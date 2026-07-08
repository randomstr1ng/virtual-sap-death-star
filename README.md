# Virtual SAP Death Star (and the Auditlog)


> [!IMPORTANT]  
> This code was developed for security research purposes on systems the author was authorized to test.
>
> Use only on systems you own or have explicit written authorization to test. If you use this to do something illegal, that is on you.
>
> This has been reported to SAP PSIRT and got rejected with the reason "Our analysis has determined that your submission is a false positive and *does not have any security impact on SAP*." [Full Statement here](https://github.com/randomstr1ng/virtual-sap-death-star#a-comment-from-the-sap-psirt) 

## What Is This

SAP NetWeaver ships with an emergency super-user mechanism called **Virtual SAP\***. It creates a temporary, fully privileged SAP\* account — with `SAP_ALL` authorizations — that lives only in process memory. No database record. Not visible in user management. No change document.

SAP intended this feature to be controlled by a profile parameter (`login/create_virtual_user_sapstar`) and to always leave an audit log entry when used.

This repository contains two tools that explore what happens when you look at those assumptions more carefully.

While playing around with the SAP Kernel Audit Log capabilities, I figured out how to selectively suppress audit events which caused me to build a second tool.

https://github.com/user-attachments/assets/6eb7c4eb-c9c3-4714-8601-5770083c8cd7

## Tools

### `vsapstar` — Virtual SAP\* without dpmon

A standalone C binary that creates a Virtual SAP\* account by injecting a function call directly into the running `disp+work` process via `ptrace`. No SAP SDK. No SAP binaries. No special privileges beyond a standard `<sid>adm` OS shell.

Capabilities:
- **Create** a Virtual SAP\* account without touching any SAP-provided tool
- **Suppress the audit log entry** — patches the two `call virtual_user_audit_log_create` sites to NOP before the call, restores them after. The Security Audit Log sees nothing.
- **Bypass `login/create_virtual_user_sapstar = 0`** — the profile parameter that is supposed to prevent this feature from being used. Patched from `JE` to `JMP`, restored after the call.
- **Extend validity to 7 days** — `dpmon` caps validity at 10–30 minutes. The underlying kernel function accepts up to 10,080 minutes. We call it directly.

```
./vsapstar -c 100 -v 10 -q

ABCDEFGHIJ1234567890ABCDEFGHIJ1234567890

./vsapstar -c 100 -v 10080 --bypass -P 2 --no-audit --no-profile-check

[+] Created successfully
user=SAP*, client=100, password=<40-char Base32>
No EUP event in audit log
login/create_virtual_user_sapstar=0 ignored
```

> [!NOTE]  
> Confirmed on SAP kernel 916 / S/4HANA 2023 and 2025.



### `sap_audit_hook` — SAP Security Audit Log Monitor

A ptrace-based tool that attaches to running `disp+work` work processes and plants INT3 breakpoints at all six audit write call sites inside `rsauwr1ex`. Intercepts audit records before they reach any sink (flat file, ring buffer, database, ETD).

Modes:
- **Monitor** (`--monitor`): print intercepted audit events to stdout
- **Suppress** (`--suppress`): silently drop matching events before they are written
- **Filter** (`--filter CLASS`): target specific event classes, e.g. `AUW,AU3,EUP`

```
./sap_audit_hook --pid 12345 --monitor
./sap_audit_hook --pid 12345 --suppress --filter EUP
```

Hook points:

| Call site | What it intercepts |
|---|---|
| 1st `call fwrite` in `rsauwr1ex` | Oldstyle audit file write (entry) |
| 2nd `call fwrite` in `rsauwr1ex` | Oldstyle audit file write (header) |
| `call write_event_to_DB` | Database audit sink |
| 1st `call EtdSenderIsActive` | ETD connector check (1) |
| 2nd `call EtdSenderIsActive` | ETD connector check (2) |
| `call EtdSendEvent` in `rsauwr1ex.cold` | ETD event delivery *(PoC/unverified)* |

Hook addresses are resolved at runtime from the binary's ELF symbol table — no hardcoded offsets, works across builds.

> [!NOTE]  
> Confirmed on SAP kernel 916 / S/4HANA 2023 and 2025.

---

## Build the binaries yourself

```bash
make           # build both tools
make vsapstar
make sap_audit_hook
make clean
```

Requirements: `gcc`, Linux. Builds static by default (no glibc version
dependency on the target — needed since dev/build box glibc is commonly
newer than the target SAP host's, e.g. SLES15 SP6 ships glibc 2.31).

---

## Usage of the tools

### `vsapstar`

```
Usage: vsapstar [OPTIONS]

  -c <client>          SAP client (3 digits)
  -v <minutes>         Validity in minutes (1–10080)
  -q                   Quiet: print only the 40-char password
  --bypass             Call create_virtual_user_internal directly (enables -P, -v >30)
  -P <purpose>         Purpose (1/2/3) — requires --bypass. Use 2 for SAP GUI login.
  --no-audit           NOP the audit log call sites (suppress EUP event)
  --no-profile-check   Bypass login/create_virtual_user_sapstar gate
  --monitor            Attach and monitor without creating anything
  --singlestep         Verbose register trace (debugging)
```

Typical usage:

```bash
# Create a 10-minute slot (standard, produces audit log entry)
./vsapstar -c 100 -v 10

# Create a 7-day slot, no audit log, profile param ignored
./vsapstar -c 100 -v 10080 --bypass -P 2 --no-audit --no-profile-check

# Get password only (for scripting)
PW=$(./vsapstar -c 100 -v 10 -q)
```

**Requires:** `<sid>adm` shell, `/proc/sys/kernel/yama/ptrace_scope` ≤ 1.

### `sap_audit_hook`

```
Usage: sap_audit_hook --pid <PID> [OPTIONS]

  --pid <PID>          Target disp+work work process PID
  --monitor            Print intercepted events (default)
  --suppress           Drop events before write
  --filter <CLASSES>   Comma-separated event classes to target, e.g. EUP,AUW
  -v / --verbose       Show hook diagnostic output (attach messages, warnings)
```

```bash
# Monitor all audit events from a work process
./sap_audit_hook --pid $(pgrep -n disp+work) --monitor

# Suppress only EUP events (Virtual SAP* creation)
./sap_audit_hook --pid 12345 --suppress --filter EUP -v
```



## A comment from the SAP PSIRT

These findings were reported to SAP PSIRT in June 2026. SAP's response, in full:

> *"Based on the information you provided, the reported scenario relies on injecting a function into the disp+work process by leveraging operating system–level privileged functionality. This requires a level of access and control over the underlying operating system that is outside the intended security boundary of the SAP application.*
>
> *Actions performed with OS-level privileges are expected to be restricted and controlled by the system operator or administrator. Once an attacker or user has obtained such privileged access, they can modify or interfere with the execution of software running on the host system, including SAP processes. Such modifications result in software behavior that is no longer representative of the SAP product as delivered and supported by SAP.*
>
> *For these reasons, it is not considered to be a security vulnerability hence this is being closed as Rejected."*

SAP is correct that `<sid>adm` OS access is a prerequisite. What the response does not address is that the feature ships with a profile parameter (`login/create_virtual_user_sapstar`) specifically intended to prevent this from working — and that parameter can be bypassed. It ships with an audit log entry specifically intended to record when this feature is used — and that entry can be suppressed. These are not properties of the underlying OS. They are properties of the SAP application.

But per SAP PSIRT: false positive.


So here we are - enjoy ;)
