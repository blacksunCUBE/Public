# WinDbg Cheatsheet for Malware Analysis & EDR Research (blacksunCUBE Edition)

> A practical, professional reference for using **WinDbg** for **malware analysis** and **EDR internals research**.
>
> Written from zero no prior WinDbg experience assumed  but presumes you already understand what malware analysis, EDR (Endpoint Detection and Response), and basic Windows internals are. Each section explains *what* a command does, *why* you would use it in offensive/defensive research, and *how* to combine it with realistic analysis workflows.
>
> **Last reviewed:** 2026, against WinDbg (modern) on Windows 11 24H2 and Windows Server 2025.

---

## Table of Contents

1. [Why WinDbg for Malware Analysis & EDR Research](#why-windbg)
2. [Installation & Initial Setup (2026)](#installation)
3. [Symbols Configuration](#symbols)
4. [WinDbg Interface & Modes](#interface)
5. [Essential Command Syntax](#syntax)
6. [Process & Thread Inspection](#process-thread)
7. [Memory Examination](#memory)
8. [Disassembly & Code Analysis](#disasm)
9. [Breakpoints  Software, Hardware, Conditional](#breakpoints)
10. [Execution Control](#execution)
11. [Stack Analysis](#stack)
12. [Modules, Symbols & Exports](#modules)
13. [Pseudo-Registers & Variables](#pseudo)
14. [Kernel Debugging Setup](#kd-setup)
15. [Kernel Structures (EPROCESS, ETHREAD, PEB, TEB)](#structures)
16. [Tokens, Privileges & Security Context](#tokens)
17. [Driver & Device Object Analysis](#drivers)
18. [Kernel Callbacks (Critical for EDR Research)](#callbacks)
19. [Detecting API Hooks & Inline Patches](#hooks)
20. [Analyzing Process Injection](#injection)
21. [Syscall & SSDT Analysis](#syscalls)
22. [Recognizing Anti-Analysis & Anti-Debug Techniques](#anti-debug)
23. [Dumping Memory, Modules & Payloads](#dumping)
24. [Crash Dump Analysis](#crash)
25. [Time Travel Debugging (TTD)](#ttd)
26. [Scripting with JavaScript & dx](#scripting)
27. [WinDbg Recipes for Malware Analysis](#analysis-recipes)
28. [WinDbg Recipes for EDR Internals Research](#edr-recipes)
29. [2026 Updates: New Features & Modern Workflows](#2026-updates)
30. [Common Pitfalls & Troubleshooting](#pitfalls)
31. [Reference Resources](#resources)

---

<a name="why-windbg"></a>
## 1. Why WinDbg for Malware Analysis & EDR Research

WinDbg is **the** debugger when you need to observe what Windows is *actually* doing  not what user-mode APIs claim is happening. This matters in two specific ways:

**For malware analysis (research perspective):**
- Observe how a sample interacts with the NTAPI layer, beyond the documented Win32 surface
- Identify unhooking attempts, indirect/direct syscalls, and APC-based injection
- Inspect PEB/TEB modifications used in process hollowing and module stomping
- Reconstruct execution flow of obfuscated or packed binaries in a controlled environment
- Dump runtime-decrypted payloads from memory for static analysis

**For EDR internals research (defensive perspective):**
- Enumerate kernel callbacks (`PsSetCreateProcessNotifyRoutineEx`, `ObRegisterCallbacks`, `CmRegisterCallbackEx`)
- Trace minifilter altitudes, IRPs, and operation flows
- Observe how the kernel routes telemetry through ETW Threat-Intelligence providers
- Analyze how vendors hook user-mode (`ntdll!*`) without touching syscall stubs
- Understand how a sensor reacts to evasion techniques in real time

The same tool serves both perspectives. For 2026-era research where samples increasingly rely on direct/indirect syscalls, hardware breakpoints, and CET (Control-flow Enforcement Technology) bypasses, mastering WinDbg is non-negotiable.

---

<a name="installation"></a>
## 2. Installation & Initial Setup (2026)

### Recommended Installation

Install **WinDbg (modern)**  the current flagship debugger  from the Microsoft Store. The legacy "WinDbg Preview" was deprecated and superseded by this package, which now ships with:

- Time Travel Debugging (TTD) with hardware-assisted recording on supported CPUs
- JavaScript & TypeScript scripting engine
- The `dx` data model for querying debugger state declaratively
- Native Dark Mode and DPI-aware UI
- Built-in support for ARM64 kernel debugging (relevant for Snapdragon X / Surface Pro 11)

Alternative for older Windows or offline analysis machines: install the **Windows SDK** and select only *Debugging Tools for Windows*. This gives you the command-line versions:

```
Tools installed:
  windbg.exe   - GUI debugger (legacy / classic)
  kd.exe       - Kernel debugger (console)
  cdb.exe      - Console user-mode debugger
  ntsd.exe     - Same as cdb.exe but spawns a window
  TTD.exe      - Command-line TTD recorder (modern)
```

### Safe Analysis Lab Setup (Mandatory)

Never analyze live malware on your host. Recommended 2026 layout:

| Component | Purpose |
|-----------|---------|
| **Host machine** | WinDbg client, symbols cache, your analysis notes (FLARE-VM is fine for static prep) |
| **Analysis VM** | VMware Workstation Pro 17+, Hyper-V, or QEMU/KVM with Windows 10/11 x64  Defender disabled, AMSI patched out for the lab, network isolated |
| **Connection** | Named pipe (VMware), KDNET network kernel debugging (Hyper-V), or VirtualKD-Redux for performance |
| **Snapshots** | Clean snapshot before every sample run; revert after each analysis session |

Always take a clean snapshot of the analysis VM **before** running any sample. This is not optional  modern malware often establishes persistence within seconds and may attempt to escape virtualization.

---

<a name="symbols"></a>
## 3. Symbols Configuration

Without symbols, WinDbg shows raw addresses (`0x7ff8a3245690`) instead of meaningful function names (`ntdll!NtCreateFile`). Configure symbols once, then forget about it.

### Set Symbol Path (Persistent  Recommended)

Open an elevated Command Prompt on the analysis machine and run:

```cmd
setx _NT_SYMBOL_PATH "srv*C:\symbols*https://msdl.microsoft.com/download/symbols"
```

**Explanation:**
- `srv*`  tells WinDbg to use a symbol server
- `C:\symbols`  local cache directory (WinDbg downloads symbols here once, then reuses)
- `https://msdl.microsoft.com/download/symbols`  Microsoft's official public symbol server

### Set Symbol Path Within WinDbg

If you prefer setting it per-session, or need to override:

```
.sympath srv*C:\symbols*https://msdl.microsoft.com/download/symbols
                                    ; sets the symbol path

.reload /f                          ; force-reload all symbols
.reload /f ntdll.dll                ; reload symbols for one module only
.reload /user                       ; (kernel debugging) reload user-mode symbols
                                    ; for the current process context

.symfix                             ; quick reset to Microsoft public symbols
.symfix+ C:\my_symbols              ; append a private symbol directory
```

### Verify Symbols Are Loaded

```
lm                                  ; list loaded modules
lm v m ntdll                        ; verbose info on ntdll, including symbol status
```

**What to look for:** if a module shows `(deferred)` next to its name, symbols have not been loaded yet  they will load on demand the first time you reference them, or when you run `.reload /f`. If a module shows `(export symbols)`, only export names are available (no PDB). If it shows `(private pdb symbols)`, you have full symbols including local variable names.

---

<a name="interface"></a>
## 4. WinDbg Interface & Modes

WinDbg has **two operational modes** with different prompts and capabilities:

| Mode | Prompt | Use Case |
|------|--------|----------|
| User-mode | `0:000>` | Debugging a single process (a sample, a service) |
| Kernel-mode | `kd>` or `lkd>` | Debugging the entire OS (drivers, callbacks, EDR sensors) |

The number before the colon is the **process index**; the number after is the **thread index**. So `0:003>` means *process #0, thread #3*. In `lkd>`, the `l` stands for "local kernel" (live debugging the same machine, limited capability).

### Attaching to a Live Process (User Mode)

From the GUI:
```
File → Attach to Process → select PID
```

Or from command line:

```cmd
windbg -p <PID>                     ; attach by PID
windbg -pn <process_name.exe>       ; attach by process name
windbg <path_to_exe>                ; launch and debug from start
windbg -o <path_to_exe>             ; also debug child processes
windbg -z <path_to_dump.dmp>        ; open a memory dump file
```

**Tip for malware analysis:** use `windbg -o <sample.exe>` so you also catch any child processes the sample spawns (a common evasion: drop a child and exit the parent).

---

<a name="syntax"></a>
## 5. Essential Command Syntax

WinDbg has three command types  learn to distinguish them:

| Prefix | Type | Examples |
|--------|------|----------|
| (none) | Standard commands | `g`, `p`, `t`, `r`, `u`, `bp`, `dq` |
| `.` | Meta-commands (debugger config) | `.reload`, `.sympath`, `.process`, `.frame` |
| `!` | Extension commands (from DLLs) | `!process`, `!analyze`, `!peb`, `!heap` |

### Number Format

By default, **all numbers are hex**. To force decimal use the `0n` prefix:

```
0:000> ? 100              ; 100 hex = 256 decimal
0:000> ? 0n100            ; 100 decimal = 64 hex
```

Forgetting this rule is the #1 source of confusion for beginners.

### Expression Evaluator

```
? <expr>                  ; evaluate MASM-style expression (default)
?? <expr>                 ; evaluate C++-style expression (works on types/structures)
dx <expr>                 ; evaluate using the data model (NatVis & JavaScript-aware)
```

**Example use:**
```
0:000> ? rax + 0x10                 ; arithmetic on register
0:000> ?? sizeof(_EPROCESS)         ; sizeof on a kernel structure
0:000> dx @$curprocess.Name         ; query the data model
```

---

<a name="process-thread"></a>
## 6. Process & Thread Inspection

### User Mode

```
|                                   ; list all debugged processes
|.                                  ; show current process
~                                   ; list all threads in current process
~.                                  ; show current thread
~*                                  ; verbose listing of all threads
~<n>s                               ; switch to thread n
~<n>k                               ; stack trace of thread n
~* k                                ; stack trace of every thread (powerful one-liner)
```

**Why this matters in malware analysis:** when a sample creates multiple threads (a common injection pattern), `~* k` gives you an instant overview of *every* thread's call stack  perfect for spotting a thread whose start address points into unbacked memory (a strong injection indicator).

### Kernel Mode

```
!process 0 0                        ; brief list of all processes
!process 0 7                        ; full detail of all processes (very long output)
!process 0 0 lsass.exe              ; find a specific process by name
!process <EPROCESS> 7               ; full detail of one specific process
!process -1 0                       ; the current process context
.process /i <EPROCESS>              ; switch to that process's VA space (invasive  needs `g` after)
.reload /user                       ; after switching context, reload user-mode symbols
!thread                             ; current thread info
!thread <ETHREAD> f                 ; verbose thread info including stack
```

**Typical workflow** when investigating a sample from the kernel debugger:

```
kd> !process 0 0 sample.exe         ; find PID and EPROCESS pointer
kd> .process /i ffffd302f0302080    ; switch context invasively
kd> g                               ; let it run so context switch completes
kd> .reload /user                   ; load user-mode symbols for sample.exe
kd> !peb                            ; inspect its Process Environment Block
```

The `/i` (invasive) flag is essential  without it, you can see the process but cannot resolve user-mode addresses correctly.

---

<a name="memory"></a>
## 7. Memory Examination

The `d` (display) command family  your most-used commands. Each shows memory in a different format.

| Command | Format | Example | When to Use |
|---------|--------|---------|-------------|
| `db` | Bytes + ASCII | `db 0x401000 L20` | Inspecting shellcode, raw data, network buffers |
| `dw` | Words (2 bytes) | `dw rsp L10` | Inspecting structures with 16-bit fields |
| `dd` | DWORDs (4 bytes) | `dd 0x401000 L4` | Reading 32-bit values, flags |
| `dq` | QWORDs (8 bytes, x64) | `dq rcx L4` | Reading 64-bit pointers, structures |
| `da` | ASCII string | `da 0x401000` | Reading C strings |
| `du` | Unicode string | `du 0x401000` | Reading Windows wide strings (most APIs use these) |
| `dps` | Pointers + nearest symbol | `dps rsp L10` | Identifying what function pointers are pointing to |
| `dpp` | Double pointer dereference | `dpp rcx L1` | Walking pointer chains |

**Length:** `L` specifies the length in items of that size. `L20` after `db` means 32 bytes (0x20 hex). After `dq`, `L4` means 4 × 8 = 32 bytes.

### Searching Memory

```
s -b <range_start> <range_end> <bytes>          ; byte pattern
s -a <range_start> <range_end> "string"         ; ASCII string
s -u <range_start> <range_end> "string"         ; Unicode string

; Practical examples:
s -a 0 L?80000000 "Mozilla"                     ; find a User-Agent-like string anywhere in user space
s -b ntdll L?ntdll "4c 8b d1 b8"                ; find every syscall stub prologue
s -u 0 L?80000000 "C2.example.com"              ; find a hardcoded C2 hostname (Unicode)
```

The `L?` syntax allows arbitrary-sized ranges (otherwise the limit is `0x10000000`).

### Editing Memory (Use With Care)

```
eb <addr> <byte>...                 ; edit bytes
ed <addr> <dword>                   ; edit DWORD
eq <addr> <qword>                   ; edit QWORD
ea <addr> "string"                  ; write ASCII string
eu <addr> "string"                  ; write Unicode string
```

**Use cases in analysis:**
- Patching out anti-analysis checks (set `BeingDebugged = 0`)
- Flipping a flag to take a different code path
- Forcing a sample down its happy path to observe its true behavior

Never edit memory without first understanding what the program will do next.

### Virtual Memory Layout

```
!address                            ; full memory map of current process
!address <addr>                     ; details for one specific address
!vad                                ; (kernel) VAD tree of current process
```

`!address` is invaluable for confirming whether an allocation is `MEM_PRIVATE` vs `MEM_IMAGE`  a key distinction since EDRs heavily flag `RWX` private memory regions (a strong indicator of shellcode or unpacked payloads).

**Output to look for:**
```
        Allocation Base:     00007ff0a0000000
        Base Address:        00007ff0a0000000
        End Address:         00007ff0a0010000
        Region Size:         00000000`00010000   (  64.000 kB)
        State:               00001000          MEM_COMMIT
        Protect:             00000040          PAGE_EXECUTE_READWRITE  ← suspicious!
        Type:                00020000          MEM_PRIVATE              ← unbacked
```

`PAGE_EXECUTE_READWRITE` + `MEM_PRIVATE` is a textbook shellcode region.

---

<a name="disasm"></a>
## 8. Disassembly & Code Analysis

```
u <addr>                            ; disassemble starting at addr (default 8 instructions)
u <addr> L<count>                   ; disassemble N instructions
uf <addr>                           ; disassemble entire function (follows branches)
uf /c <addr>                        ; show only call targets (gives you a call graph)
ub <addr>                           ; disassemble backwards (useful when you stop mid-function)
u .                                 ; disassemble at current instruction pointer
```

### Quick Hook Detection Pattern

```
u ntdll!NtCreateFile L4             ; check the first 4 instructions of an Nt* function
```

A healthy x64 NTAPI syscall stub on a modern Windows 11 looks like:

```
4C 8B D1            mov  r10, rcx
B8 55 00 00 00      mov  eax, 55h            ; syscall service number (varies per build)
F6 04 25 08 03 FE   test byte ptr [...]      ; check user-shared-data flag
   7F 01
75 03               jne  short ...
0F 05               syscall
C3                  ret
```

**If you see `E9 ?? ?? ?? ??` (a `JMP rel32`) at the function start instead of `4C 8B D1`, the function has been inline-hooked.** EDRs and AV products do this constantly to user-mode functions to intercept API calls.

Other hook signatures:
- `49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF E3`  `mov r11, imm64; jmp r11` (older AV style)
- `FF 25 ?? ?? ?? ??`  `jmp qword ptr [rip+offset]` (trampoline via IAT-style)
- `CC` at function start  INT3 breakpoint (could be a debugger or a hook framework)

---

<a name="breakpoints"></a>
## 9. Breakpoints  Software, Hardware, Conditional

### Software Breakpoints (most common)

```
bp <addr>                           ; breakpoint at address
bp <module>!<function>              ; symbolic breakpoint
bp ntdll!NtCreateFile               ; break on NtCreateFile
bu <module>!<function>              ; deferred  fires when module loads
bp /1 <addr>                        ; one-shot breakpoint (auto-deletes after first hit)
bp /p <EPROCESS> <addr>             ; (kernel) only for this process
bp /t <ETHREAD> <addr>              ; (kernel) only for this thread
```

**`bu` is essential when targeting code that isn't loaded yet.** Example: setting a breakpoint inside a DLL the sample will load reflectively. `bp` fails (address can't resolve now); `bu` defers resolution until the module loads.

### Hardware Breakpoints (Data Breakpoints / Watchpoints)

Limited to **4 simultaneous** (uses CPU debug registers DR0–DR3).

```
ba r1 <addr>                        ; break on read (1-byte watch)
ba w4 <addr>                        ; break on write (4-byte watch)
ba e1 <addr>                        ; break on execute (1-byte watch)
```

**Why hardware breakpoints matter for malware analysis:** they trigger on *any* code touching a memory location, regardless of how the access happens. Perfect for tracking who reads or modifies a specific structure (e.g., the PEB's `BeingDebugged` flag, an EDR's callback list, or a decryption key buffer).

**Caveat:** some samples specifically check `Dr0`–`Dr3` of their own threads to detect hardware breakpoints. If a sample evades your hardware breakpoint, switch to software (`bp`).

### Breakpoint Management

```
bl                                  ; list all breakpoints
bc *                                ; clear all breakpoints
bc <n>                              ; clear breakpoint #n
bd <n>                              ; disable breakpoint #n (without deleting)
be <n>                              ; re-enable disabled breakpoint
```

### Conditional Breakpoints

Break only when a condition is true. Syntax: `bp <addr> ".if (<cond>) {} .else {gc}"`

**The `gc` ("go-continue") at the end is critical**  without it, the debugger will stop on every hit and just print the condition result.

```
bp kernel32!CreateFileW ".if (poi(@rcx) == 0x5c) {} .else {gc}"
; break only when first character of filename (rcx) is '\\'

bp ntdll!NtAllocateVirtualMemory ".if (@r9 == 0x40) {} .else {gc}"
; break only when Protect parameter == PAGE_EXECUTE_READWRITE (0x40)
```

### Command Breakpoints (Auto-Execute and Continue)

Massively useful for **logging without stopping** execution. Effectively turns WinDbg into a poor-man's API monitor.

```
bp ntdll!NtCreateFile "du poi(poi(@rdx)+10); g"
; for every NtCreateFile call: dump the filename, then continue

bp kernel32!WriteProcessMemory "r rcx, rdx, r8, r9; .echo ---; gc"
; log all parameters of every WriteProcessMemory call
```

For analysis work, this lets you build behavioral profiles of a sample without manual intervention.

---

<a name="execution"></a>
## 10. Execution Control

| Command | Action | When to Use |
|---------|--------|-------------|
| `g` | Go (continue) | Resume after a breakpoint |
| `g <addr>` | Go until address | Skip ahead to a known location |
| `gu` | Go up  run until current function returns | Quickly exit a function you don't care about |
| `gh` | Go with exception handled | When sample hit an exception, mark it handled |
| `gn` | Go with exception not handled | Let the exception propagate to SEH |
| `p` | Step over (skips function calls) | Walk through code without descending into calls |
| `pc` | Step to next call | Jump to the next `call` instruction |
| `pt` | Step to next return | Jump to the next `ret` |
| `t` | Step into | Descend into a function call |
| `tc` | Trace to next call | Step-into until next `call` |
| `wt` | Watch and trace  log every function called | Detailed sub-function trace |

`wt` produces a massive but informative log  ideal for understanding what a small piece of code does internally. Run with `wt -l 2` to limit depth.

---

<a name="stack"></a>
## 11. Stack Analysis

```
k                                   ; basic call stack
kn                                  ; with frame numbers
kb                                  ; with first 3 arguments (legacy x86 convention)
kv                                  ; verbose  includes calling convention & FPO data
kp                                  ; with full parameters (requires private symbols)
kP                                  ; same as kp but on separate lines (readable)
.frame <n>                          ; switch to frame n
dv                                  ; display local variables in current frame
```

### Manually Reading x64 Function Arguments

The x64 Windows calling convention places the first four arguments in `rcx`, `rdx`, `r8`, `r9`. Stack arguments start at `[rsp+0x28]` (after the 32-byte shadow space the caller reserves).

```
0:000> r rcx, rdx, r8, r9           ; show first 4 args
0:000> dq /c1 rsp L8                ; show 8 stack slots, one per line
0:000> dq /c1 rsp+0x28 L4           ; show stack arguments 5-8
```

When you break inside a function, dump `rcx` first  it's usually the most interesting argument (handle, pointer, filename, etc.).

### Recognizing a Suspicious Stack

```
0:000> k
 # Child-SP          RetAddr           Call Site
00 000000d4`f5f7e6f8 00000000`00401234 0x000001f8`d0030000     ← unbacked memory!
01 000000d4`f5f7e700 00007ff8`a3245690 sample!main+0x42
```

A frame whose call site is **not** in any loaded module  bare `0x...`  is a classic sign of shellcode execution. Cross-reference with `!address` to confirm.

---

<a name="modules"></a>
## 12. Modules, Symbols & Exports

```
lm                                  ; list loaded modules
lm m kernel*                        ; filter by name pattern
lm a <addr>                         ; module containing this address
lm Dv m ntdll                       ; detailed verbose info about ntdll
ln <addr>                           ; nearest symbol to address  great for "where am I?"
x <module>!<pattern>                ; search symbols (wildcards supported)
x ntdll!Nt*                         ; list every Nt* function in ntdll
!dh <base_addr>                     ; parse PE headers at base address
!dh -e <module>                     ; list export table
```

### Investigating an Unknown Loaded Module

```
0:000> lm a 00007ffe`12340000       ; identify the module at this address
0:000> lmDvm <module>               ; detailed info: version, path, timestamp, signature
0:000> !dh <base>                   ; check PE headers (entry point, section flags)
```

**Catching reflectively loaded DLLs:** these typically *won't* appear in `lm` because the loader was bypassed. Use `!address` to spot anonymous private executable regions, then `!dh` on the suspected base address to verify a PE signature (`MZ` at offset 0, `PE\0\0` at the PE header offset).

---

<a name="pseudo"></a>
## 13. Pseudo-Registers & Variables

Pseudo-registers (prefixed with `@$` or `$`) are debugger-managed values that follow the current debug context.

| Pseudo-Register | Meaning |
|----------|---------|
| `$ip` | Current instruction pointer (architecture-independent: `rip` on x64, `pc` on ARM64) |
| `$exentry` | Entry point of main executable |
| `$peb` | PEB of current process |
| `$teb` | TEB of current thread |
| `$tpid` | Current process ID |
| `$tid` | Current thread ID |
| `$proc` | EPROCESS pointer (kernel mode) |
| `$thread` | ETHREAD pointer (kernel mode) |
| `$retreg` | Return value register (`rax` on x64, `x0` on ARM64) |

### User-Defined Aliases (`$t0`–`$t9`)

```
r $t0 = 0x401000                    ; store an address
bp $t0                              ; set breakpoint there
?? @$t0                             ; read it back
```

User pseudo-registers `$t0`–`$t9` are handy for keeping a target address around between commands without having to retype it.

---

<a name="kd-setup"></a>
## 14. Kernel Debugging Setup

### VMware Workstation (Recommended for Most Analysis Work)

**On the debugee VM:**

1. Power off the VM, open the `.vmx` file in a text editor, add:
   ```
   serial0.present = "TRUE"
   serial0.fileType = "pipe"
   serial0.fileName = "\\.\pipe\com_1"
   serial0.tryNoRxLoss = "FALSE"
   serial0.pipe.endPoint = "server"
   ```

2. Boot the VM and run in elevated cmd:
   ```cmd
   bcdedit /debug on
   bcdedit /dbgsettings serial debugport:1 baudrate:115200
   ```
   Then reboot.

**On the host (WinDbg):**

```
File → Start Debugging → Attach to Kernel → COM tab
  Pipe:         checked
  Reconnect:    checked
  Resets:       0
  Baud Rate:    115200
  Port:         \\.\pipe\com_1
```

### Hyper-V (KDNET  Significantly Faster)

On Hyper-V, use **network kernel debugging** instead of serial  it's dramatically faster (megabytes per second vs kilobytes).

On the debugee:
```cmd
bcdedit /debug on
bcdedit /dbgsettings net hostip:<HOST_IP> port:50000 key:<random.key.value.here>
```

The command outputs the connection key. Keep it.

On the host:
```cmd
windbg -k net:port=50000,key=<random.key.value.here>
```

### First Connection  Disable Driver Signature Enforcement (For Test Drivers)

If you're analyzing or developing a kernel driver in a research lab, disable DSE on the debugee:

```cmd
bcdedit /set testsigning on
```

Reboot. The desktop will display "Test Mode"  confirming unsigned drivers can load. **Never enable this on production systems.**

### Useful Kernel Debugger Commands

```
.reboot                             ; reboot the debugee from the debugger
.crash                              ; force a bugcheck (useful for testing crash handlers)
.dump /f C:\crash.dmp               ; capture a full kernel dump
g                                   ; let the kernel run
Ctrl+Break                          ; break in (kernel mode)
.kdtargetstate                      ; confirm connection health
```

---

<a name="structures"></a>
## 15. Kernel Structures (EPROCESS, ETHREAD, PEB, TEB)

These structures are the *core* of Windows internals  and the playground for both malware authors and EDR vendors.

### EPROCESS  The Kernel View of a Process

```
dt nt!_EPROCESS                     ; show structure layout (types only)
dt nt!_EPROCESS <addr>              ; populate with data from address
dt nt!_EPROCESS <addr> ImageFileName ; show just one field
dt nt!_EPROCESS <addr> -r           ; recursive expansion of substructures
```

Fields of highest interest:

| Field | Why It Matters |
|-------|----------------|
| `ImageFileName` | Process name (ANSI, max 15 chars  yes, truncated) |
| `UniqueProcessId` | PID |
| `Pcb.DirectoryTableBase` | CR3 value  the page-table base address |
| `Token` | Pointer to the process's security token |
| `Protection` | PPL (Protected Process Light) level + signer |
| `ObjectTable` | The process handle table |
| `Peb` | User-mode PEB pointer |
| `SectionObject` | The image section (the EXE on disk) |
| `InheritedFromUniqueProcessId` | Parent PID  used to detect parent-PID spoofing |
| `MitigationFlags` / `MitigationFlags2` | Process mitigation policy bitmask |

### ETHREAD

```
dt nt!_ETHREAD <addr>
dt nt!_KTHREAD <addr>               ; the KTHREAD substructure
```

Key fields for analysis:
- `Cid.UniqueThread`  TID
- `StartAddress`  initial thread start address as set by the kernel
- `Win32StartAddress`  the actual user-mode start address. **EDRs check this for thread injection**  a thread whose `Win32StartAddress` lies in unbacked memory is a strong injection indicator.

### PEB (Process Environment Block)

```
!peb                                ; pretty-printed PEB
dt nt!_PEB                          ; raw structure layout
dt nt!_PEB @$peb                    ; current process PEB
```

Critical fields for malware analysis:
- `Ldr` → `_PEB_LDR_DATA` → `InMemoryOrderModuleList`  malware sometimes **modifies this list to hide loaded modules**
- `BeingDebugged`  anti-debug flag; trivially patched
- `NtGlobalFlag`  anti-debug; holds debug heap creation flags
- `ProcessParameters` → `ImagePathName`, `CommandLine`, `CurrentDirectory`

### TEB (Thread Environment Block)

```
!teb                                ; current thread TEB
dt nt!_TEB @$teb
```

Critical fields:
- `NtTib.Self`  pointer to itself (used in anti-debug: code validates `gs:[0x30]` returns the same pointer)
- `LastErrorValue`  last Win32 error code
- `StackBase`, `StackLimit`  bounds of the thread's stack (EDRs use these to detect stack pivot attacks)

---

<a name="tokens"></a>
## 16. Tokens, Privileges & Security Context

Modern EDRs heavily monitor token theft and privilege escalation. These commands let you see exactly what a token contains.

```
!process <EPROCESS> 1               ; brief view, includes token pointer
!token <token_addr>                 ; verbose token info
!token -n <token_addr>              ; with full privilege names
dt nt!_TOKEN <token_addr>           ; raw token structure
```

### Common Investigation Pattern

```
kd> !process 0 0 lsass.exe          ; find LSASS
kd> dt nt!_EPROCESS <addr> Token    ; get its token pointer
kd> !token <token_addr>             ; inspect privileges
```

**Red flags:** if a non-system process (notepad.exe, mshta.exe, a browser child) suddenly holds LSASS-like privileges (`SeDebugPrivilege`, `SeTcbPrivilege`, `SeImpersonatePrivilege` enabled), you are likely looking at a **token duplication or theft** attack.

---

<a name="drivers"></a>
## 17. Driver & Device Object Analysis

For EDR research, you constantly inspect drivers, their devices, and IRP dispatch routines.

```
!drvobj <driver_name>               ; basic driver info
!drvobj <driver_name> 7             ; verbose  all dispatch routines and devices
!devobj <device_addr>               ; device object details
!devstack <device_addr>             ; full device stack (top to bottom)
!devnode 0 1                        ; device tree (PnP)
!object \Driver                     ; list all driver objects
!object \FileSystem\Filters         ; list registered minifilters
```

### Walking the Driver Dispatch Table

```
kd> !drvobj \Driver\Tcpip 2
Driver object (ffffa70d18334e30) is for:
 \Driver\Tcpip
DriverEntry:   fffff80721d12010 tcpip!GsDriverEntry
DriverStartIo: 00000000
DriverUnload:  fffff8072116b830 tcpip!TcpipUnload
AddDevice:     fffff8072116c2c0 tcpip!TcpipAddDevice

Dispatch routines:
[00] IRP_MJ_CREATE                  fffff8072116b8d0  tcpip!TcpipDispatch
[01] IRP_MJ_CREATE_NAMED_PIPE       fffff80717fa1f10  nt!IopInvalidDeviceRequest
...
```

This is essential for understanding **how an EDR driver routes IRPs** and where to set breakpoints to trace request flows.

### Minifilter Inspection

```
.load fltkd                         ; load the filter manager extension if needed
!fltkd.frame                        ; minifilter frame
!fltkd.filters                      ; list all registered minifilters
!fltkd.instances                    ; minifilter instances
!fltkd.cbs                          ; pre/post operation callbacks
!fltkd.volumes                      ; volumes being filtered
```

Output shows each filter's **altitude** (a number determining order of execution). Lower altitudes run closer to the file system; higher altitudes run closer to the user. Most EDR file-system minifilters live in altitudes 320000–329999 (Microsoft-allocated "FSFilter Anti-Virus" range).

---

<a name="callbacks"></a>
## 18. Kernel Callbacks (Critical for EDR Research)

Modern EDRs register kernel callbacks rather than (or in addition to) older SSDT hooking. WinDbg is the most reliable way to enumerate them.

### Process Creation Callbacks

```
kd> dps nt!PspCreateProcessNotifyRoutine L40
kd> dps nt!PspCreateProcessNotifyRoutineEx L40
```

Each non-null entry is a pointer (with low bits flagged) to a callback routine. Use `ln` to identify which driver registered it:

```
kd> ln poi(nt!PspCreateProcessNotifyRoutine)
```

### Thread Creation Callbacks

```
kd> dps nt!PspCreateThreadNotifyRoutine L40
```

### Image Load Callbacks

```
kd> dps nt!PspLoadImageNotifyRoutine L40
```

### Object Callbacks (`ObRegisterCallbacks`)

These are used to filter handle operations on processes and threads  for example, to prevent dumping LSASS memory.

```
kd> !object \ObjectTypes\Process
kd> dt nt!_OBJECT_TYPE <addr_from_above>
kd> dt nt!_OBJECT_TYPE <addr> CallbackList
```

Walk the `CallbackList` linked list to enumerate every registered callback. This is **exactly** how PPL-bypass and LSASS-protection research starts.

### Registry Callbacks

```
kd> dps nt!CmpCallBackVector L40
```

For each non-null entry, `ln` resolves it to the registering driver.

For **EDR research**: knowing how to enumerate, identify, and analyze every callback type is mandatory. For **malware analysis**: the same knowledge tells you exactly which sensors a sample needed to evade.

---

<a name="hooks"></a>
## 19. Detecting API Hooks & Inline Patches

User-mode hooks remain a common detection technique in 2026, especially for AMSI, NTDLL telemetry, and ETW patching.

### Quick Hook Detection

```
0:000> u ntdll!NtCreateFile L1
```

A pristine x64 stub starts with `4C 8B D1` (`mov r10, rcx`). If you see `E9 ?? ?? ?? ??` or `49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF E3`, it's hooked.

### Compare to On-Disk DLL

```
0:000> !chkimg ntdll                ; check for unexpected changes vs disk image
0:000> !chkimg -d ntdll             ; show detailed differences (each modified byte)
```

`!chkimg` reads the DLL from disk and diffs it against the in-memory copy. **Every diff is either a hook or a relocation fixup**  most fixups are in expected places (IAT, base relocations), so unexpected diffs in the `.text` section are hooks.

### Bulk Check of All Nt* Functions

```
0:000> .foreach (func {x /1 ntdll!Nt*}) { db ${func} L4 }
```

Iterates every `Nt*` export and dumps its first 4 bytes  a quick visual scan to spot all hooked functions at once. Any line whose first byte isn't `4C` is suspicious.

### Checking for AMSI Patching

```
0:000> u amsi!AmsiScanBuffer L8
```

A common evasion is to patch `AmsiScanBuffer` to return `AMSI_RESULT_CLEAN` immediately. Look for an early `mov eax, 0; ret` sequence at the start.

### Checking for ETW Patching

```
0:000> u ntdll!EtwEventWrite L4
0:000> u ntdll!NtTraceEvent L4
```

If you see an early `ret` (`C3`) or `xor eax, eax; ret`, ETW telemetry has been disabled in-process.

---

<a name="injection"></a>
## 20. Analyzing Process Injection

When analyzing samples, you frequently need to determine *if* injection occurred, *how*, and *what payload* was delivered.

### Watching for Suspicious Allocations

```
0:000> bp ntdll!NtAllocateVirtualMemory ".if (poi(@r9) == 0x40) {} .else {gc}"
; break only when Protect == PAGE_EXECUTE_READWRITE (0x40)
```

When this fires, `rcx` is the target process handle (`-1` if self), `rdx` is the base address pointer, and `r8` is a pointer to the requested size.

### Tracing Cross-Process Writes

```
0:000> bp kernel32!WriteProcessMemory "r rcx, rdx, r8, r9; gc"
; logs handle, base addr, buffer, size for every call without stopping
```

### Inspecting Remote Thread Creation

```
0:000> bp ntdll!NtCreateThreadEx
; when hit: r8 holds StartRoutine pointer
; verify it points into the target process's memory and not a backed image
```

### From the Kernel  Watching Cross-Process Activity

```
kd> bp nt!NtWriteVirtualMemory ".if (@rcx != -1) {!process @rcx 0; .echo ----; !process -1 0} .else {gc}"
```

This logs both the source and target process for every cross-process memory write  exactly the signal an EDR would tap.

### Identifying APC Injection

```
0:000> bp ntdll!NtQueueApcThread
; rcx = thread handle, rdx = ApcRoutine, r8 = NormalContext
0:000> r rcx, rdx, r8
0:000> u poi(@rdx)                  ; inspect the queued routine
```

---

<a name="syscalls"></a>
## 21. Syscall & SSDT Analysis

Direct and indirect syscalls (Hell's Gate, Halo's Gate, Tartarus Gate variants) are common evasion techniques you'll encounter in modern samples.

### Finding a Syscall Number

```
0:000> u ntdll!NtCreateFile L4
ntdll!NtCreateFile:
00007ff8`a3245690 4c8bd1          mov     r10,rcx
00007ff8`a3245693 b855000000      mov     eax,55h           ; <-- syscall number
00007ff8`a3245698 f604250803fe...
```

The `mov eax, <num>` instruction always holds the System Service Number (SSN). Tools like **SysWhispers3** and **HellsHall** extract these dynamically at runtime to call syscalls without going through the user-mode stub.

### Verifying the SSDT (Kernel View)

```
kd> dps nt!KeServiceDescriptorTable L4
kd> dd /c1 nt!KiServiceTable L100
```

On modern Windows x64, the SSDT entries are **encoded offsets**, not direct pointers. To resolve an entry:

```
kd> dd /c1 nt!KiServiceTable L1
fffff803`12234000  00b08400          ; encoded
kd> r $t0 = (0x00b08400 >> 4) + nt!KiServiceTable
kd> ln @$t0                          ; resolves to NtAccessCheck or similar
```

The right-shift by 4 strips the argument-count field embedded in the low nibble.

### Identifying the System Call Entry

The MSR `MSR_LSTAR` (0xC0000082) holds the syscall handler address:

```
kd> rdmsr 0xc0000082
msr[c0000082] = fffff803`12345670
kd> ln fffff803`12345670
(fffff803`12345670)   nt!KiSystemCall64Shadow
```

`KiSystemCall64Shadow` is the kernel's syscall entrypoint on systems with Meltdown mitigations enabled (KVA Shadow). On older systems or in VMs without the mitigation, you'll see `KiSystemCall64`.

---

<a name="anti-debug"></a>
## 22. Recognizing Anti-Analysis & Anti-Debug Techniques

You will encounter anti-debug checks in nearly every modern sample. Here's how to identify and neutralize the most common ones.

### PEB BeingDebugged

```
0:000> dt nt!_PEB @$peb BeingDebugged
   +0x002 BeingDebugged : 0x1 ''
0:000> eb @$peb+2 0                 ; clear the flag
```

### PEB NtGlobalFlag

```
0:000> dd @$peb+0xbc L1             ; offset 0xBC on x64 (was 0x70 on older builds  verify with dt)
0:000> ed @$peb+0xbc 0              ; clear it
```

**Note:** the offset of `NtGlobalFlag` has changed across Windows builds. Always confirm with `dt nt!_PEB @$peb NtGlobalFlag` before patching.

### CheckRemoteDebuggerPresent / NtQueryInformationProcess

Break at `ntdll!NtQueryInformationProcess` and check the second argument (`ProcessInformationClass`):
- `0x07` = `ProcessDebugPort`
- `0x1E` = `ProcessDebugObjectHandle`
- `0x1F` = `ProcessDebugFlags`

When the function returns, zero out the value at `r8` (the output buffer) before resuming.

### Heap Flags

```
0:000> dt nt!_HEAP @@(*((void**)(@$peb+0x30))) Flags ForceFlags
```

Debugger-allocated heaps have non-zero `Flags` (0x40000060) and `ForceFlags` (0x40000060). Patch to zero if a check uses them.

### Hardware Breakpoint Detection

Some samples check `Dr0`–`Dr3` of their own threads via `NtGetContextThread`. Counter: use **software breakpoints (`bp`)** instead of **hardware breakpoints (`ba`)** for these samples.

### Timing Checks (rdtsc, GetTickCount, QueryPerformanceCounter)

```
0:000> bp ntdll!RtlGetTickCount     ; break to inspect/tamper return value if needed
```

For `rdtsc` loops, the simplest workaround is to NOP-out the comparison after the time read, or patch the conditional jump to always take the "no-debugger" branch.

### Modern 2026 Anti-Analysis: CPU Vendor Check via CPUID

Samples increasingly use `CPUID` (leaf `0x40000000`) to detect hypervisor strings (`VMwareVMware`, `KVMKVMKVM`, `Microsoft Hv`, etc.). Patch the relevant compare instruction or change VM CPUID exposure at the hypervisor level (VMware's `cpuid.1.ecx` settings).

---

<a name="dumping"></a>
## 23. Dumping Memory, Modules & Payloads

A core analysis workflow: let the sample decrypt its payload in memory, then dump it to disk for static analysis.

```
.writemem C:\payload.bin <start> <end>          ; explicit range
.writemem C:\payload.bin <start> L?<size>       ; range by size
```

**Example  dumping a freshly decrypted payload buffer:**

```
0:000> bp ntdll!NtProtectVirtualMemory          ; break when something becomes executable
0:000> g
; when hit:
0:000> .writemem C:\decrypted.bin poi(@rdx) L?poi(@r8)
```

### Dumping a Whole Module

```
0:000> lm a 00007ff8`a3240000        ; identify the base and module
0:000> !dh 00007ff8`a3240000         ; verify it's a PE and get SizeOfImage
0:000> .writemem C:\ntdll_dump.dll 00007ff8`a3240000 L?0x200000
```

For dumped DLLs/EXEs, you'll typically need to fix the section alignment afterward (with `pe-bear`, `CFF Explorer`, or a custom script) since on-disk and in-memory layouts differ.

### Creating a Process or Kernel Dump

```
.dump /ma C:\sample.dmp              ; full memory dump  best for post-mortem analysis
.dump /mf C:\sample.dmp              ; smaller, fewer details
.dump /mp C:\sample.dmp              ; intermediate  process info + thread stacks
```

---

<a name="crash"></a>
## 24. Crash Dump Analysis

If you're analyzing a sample that crashed (or a kernel driver), `!analyze -v` is your first move.

```
windbg -z C:\Windows\MEMORY.DMP      ; open a kernel crash dump
windbg -z C:\sample.dmp              ; open a user-mode dump
```

Once open:

```
!analyze -v                          ; verbose analysis (run this first)
.bugcheck                            ; just the bugcheck code + parameters
!thread                              ; the crashing thread
kv                                   ; stack of the crashing thread
.ecxr                                ; switch to exception context for inspection
```

Common bugchecks when analyzing kernel components:
- `0xD1` (`DRIVER_IRQL_NOT_LESS_OR_EQUAL`)  touching paged memory at high IRQL
- `0x7E` (`SYSTEM_THREAD_EXCEPTION_NOT_HANDLED`)  unhandled exception
- `0xC4` (`DRIVER_VERIFIER_DETECTED_VIOLATION`)  Driver Verifier caught a violation
- `0x139` (`KERNEL_SECURITY_CHECK_FAILURE`)  stack corruption or CFG violation

**Tip:** for analysis lab work, **enable Driver Verifier** before testing drivers:

```cmd
verifier /standard /driver YourDriver.sys
```

It catches issues that won't crash on a normal system but reveal subtle bugs.

---

<a name="ttd"></a>
## 25. Time Travel Debugging (TTD)

TTD is the killer feature of modern WinDbg  it records execution and lets you step backwards.

### Recording

```
File → Launch executable (advanced) → "Record process with Time Travel Debugging"
```

Or from the command line:
```cmd
TTD.exe -out C:\trace.run target.exe
```

### Replaying

Open the `.run` file in WinDbg. Now you can:

| Command | Action |
|---------|--------|
| `g-` | Go backwards |
| `p-` | Step over backwards |
| `t-` | Step into backwards |
| `!tt <position>` | Jump to a specific time position |
| `dx @$cursession.TTD.Calls("module!func")` | Query all calls to a function |

### Why TTD Is a Game-Changer for Malware Analysis

You can record a sample's execution **once** and then explore every code path, every memory write, and every API call backwards in time. No more "I missed the breakpoint and have to restart."

**Example query**  find every `NtAllocateVirtualMemory` call and inspect the protect flag:

```
dx -g @$cursession.TTD.Calls("ntdll!NtAllocateVirtualMemory").Select(c => new { Pos = c.TimeStart, Protect = c.Parameters[3] })
```

**Find all memory writes to a specific address:**

```
dx @$cursession.TTD.Memory(0x401000, 0x401010, "w")
```

This lists every write to that range, with timestamps you can jump to.

### 2026 Update  TTD Improvements

Recent WinDbg builds added:
- Faster recording on Intel 12th-gen and newer (PT-assisted)
- Support for recording attached processes (no longer launch-only)
- TTD on ARM64 Windows 11
- TTD support for child-process recording (`-children` flag)

---

<a name="scripting"></a>
## 26. Scripting with JavaScript & dx

Modern WinDbg ships with a JavaScript engine and the `dx` (data model) command. This lets you write debugger scripts that look like real code.

### Loading a JS Script

```
.scriptload C:\scripts\myscript.js
.scriptlist                          ; show loaded scripts
.scriptunload C:\scripts\myscript.js
```

### Minimal Script Template

```javascript
"use strict";

function invokeScript() {
    var ctrl = host.namespace.Debugger.Utility.Control;
    var output = ctrl.ExecuteCommand("lm");
    for (var line of output) {
        host.diagnostics.debugLog(line + "\n");
    }
}
```

### `dx` Examples

```
dx Debugger.Sessions[0].Processes              ; list all processes in session
dx @$curprocess.Modules                         ; modules of current process
dx @$curprocess.Threads                         ; threads of current process
dx -r2 @$curprocess.Environment.EnvironmentBlock   ; PEB, depth-2 expansion
dx @$cursession.Processes.Where(p => p.Name == "lsass.exe")  ; LINQ-style filtering
```

The data model treats the debugger as a queryable object graph. For repetitive investigations (enumerating callbacks, listing handles by type, mapping every hooked Nt* export), it beats writing `.foreach` loops by a wide margin.

---

<a name="analysis-recipes"></a>
## 27. WinDbg Recipes for Malware Analysis

Concrete workflows for common analysis tasks.

### Recipe 1: Identifying an Indirect Syscall

When a sample calls a syscall directly without going through `ntdll!Nt*`:

```
0:000> bp <suspected_syscall_stub_address>
0:000> g
; when hit:
0:000> u . L6
; you'll see: mov r10,rcx / mov eax,<num> / syscall / ret
0:000> r eax                         ; the syscall number
0:000> ? eax                         ; convert to decimal if needed
; then look up the syscall number against the running Windows build's table
```

### Recipe 2: Confirming a Sample Performed Unhooking

Before suspected unhook code runs:
```
0:000> u ntdll!NtCreateFile L1
ntdll!NtCreateFile:
00007ff8`a3245690 e9d3220000      jmp ...      ; HOOKED
```

After:
```
0:000> u ntdll!NtCreateFile L1
ntdll!NtCreateFile:
00007ff8`a3245690 4c8bd1          mov r10,rcx  ; PRISTINE
```

Then run `!chkimg ntdll` to confirm there are no other differences against the on-disk image.

### Recipe 3: Catching Module Stomping

```
0:000> bp kernel32!LoadLibraryExW "du @rcx; gc"
; logs every DLL loaded into the process

0:000> bp ntdll!NtProtectVirtualMemory ".if (poi(@r9) == 0x40) {.echo RWX!; r; kv} .else {gc}"
; alerts on any transition to RWX with a stack trace
```

Module stomping typically appears as:
1. A legitimate DLL gets loaded.
2. Its `.text` section gets re-protected to `RWX`.
3. Custom code is written over the legit content.
4. Protection is restored to `RX`.

### Recipe 4: Dumping a Decrypted Payload from Memory

```
0:000> bp ntdll!NtCreateThreadEx
; when hit, r9 (or sometimes r8) holds the StartRoutine address
0:000> .writemem C:\decrypted.bin @r9 L?0x10000
```

For shellcode without a clear "start thread" trigger, set a hardware execute breakpoint on the suspected payload region:

```
0:000> ba e1 <suspected_start_addr>
```

### Recipe 5: Reconstructing C2 Configuration

Many samples decrypt their C2 configuration just before connecting. Set a breakpoint on the network functions and walk backwards:

```
0:000> bp ws2_32!WSAConnect
0:000> bp ws2_32!connect
0:000> bp wininet!InternetConnectA
0:000> bp wininet!InternetConnectW
0:000> bp winhttp!WinHttpConnect
; on hit, inspect the parameters for the host/port
```

For HTTPS, also break on `winhttp!WinHttpOpenRequest` to see the URL path.

---

<a name="edr-recipes"></a>
## 28. WinDbg Recipes for EDR Internals Research

Workflows for analyzing how a deployed EDR sensor works.

### Recipe 1: Mapping All Callbacks Installed on a System

A reconnaissance sweep:

```
kd> dps nt!PspCreateProcessNotifyRoutine L40
kd> dps nt!PspCreateProcessNotifyRoutineEx L40
kd> dps nt!PspCreateThreadNotifyRoutine L40
kd> dps nt!PspLoadImageNotifyRoutine L40
kd> dps nt!CmpCallBackVector L40
```

For each non-null entry, run `ln <addr>` to identify which driver registered it. Build a table  that's your map of installed sensors.

### Recipe 2: Enumerating ObRegisterCallbacks for the Process Object Type

```
kd> !object \ObjectTypes\Process
kd> dt nt!_OBJECT_TYPE <addr_from_above> CallbackList
kd> dt nt!_CALLBACK_ENTRY_ITEM <addr> -l Next
; walk the linked list to find every registered callback
```

Each entry includes function pointers for `PreOperation` and `PostOperation`  the routines the EDR uses to filter `OpenProcess`/`DuplicateHandle` requests against critical processes like LSASS.

### Recipe 3: Tracing IRPs Through a Minifilter

```
kd> !fltkd.filters                   ; identify your target filter
kd> !fltkd.filter <filter_addr> 4    ; verbose info with callbacks
kd> bp <filter>!<PreOperation>       ; break on pre-op
kd> bp <filter>!<PostOperation>      ; break on post-op
```

When a breakpoint hits, `rcx` holds the `PFLT_CALLBACK_DATA` pointer. Use `dt FLT_CALLBACK_DATA @rcx` to inspect the operation, target file, and parameters.

### Recipe 4: Watching ETW Threat-Intelligence (ETW-TI) Events

ETW-TI is how Defender and many EDRs receive high-fidelity kernel events. To see what fires it:

```
kd> x nt!EtwTi*
kd> bp nt!EtwTiLogReadWriteVm        ; cross-process memory access events
kd> bp nt!EtwTiLogAllocExecVm        ; RWX allocations
kd> bp nt!EtwTiLogProtectExecVm      ; RX/RWX transitions
kd> bp nt!EtwTiLogSetContextThread   ; thread-context modifications (injection)
kd> bp nt!EtwTiLogMapView            ; section mapping events
```

These are the **kernel functions that emit the highest-signal telemetry** to user-mode consumers like Defender. Every modern EDR subscribes to this provider.

### Recipe 5: Identifying PPL-Protected Processes

```
kd> !process 0 0 MsMpEng.exe         ; find MsMpEng (Defender)
kd> dt nt!_EPROCESS <addr> Protection
   +0x87a Protection : _PS_PROTECTION
kd> dt nt!_PS_PROTECTION <addr>+0x87a
   +0x000 Level            : 0x62 'b'
   +0x000 Type             : 0y010
   +0x000 Audit            : 0y0
   +0x000 Signer           : 0y0110
```

The `Type` and `Signer` fields tell you:
- **Type:** 1 = ProtectedLight (PPL), 2 = Protected (PP)
- **Signer:** 1 = Authenticode, 4 = Windows, 6 = Antimalware, 7 = LSA

A `Signer=6 Type=1` process is an Antimalware-class PPL  like Defender or a third-party AV. To even open such a process for read access, the requesting process must run at an equal or higher protection level.

### Recipe 6: Confirming an EDR's User-Mode Hook Surface

Attach to any normal process running on a system with an EDR installed, then:

```
0:000> !chkimg ntdll
; reports modified bytes  these are the EDR's inline hooks
0:000> !chkimg kernelbase
0:000> !chkimg kernel32
0:000> !chkimg amsi
```

Then for each hook location, examine the trampoline target with `u` to identify the EDR's hooking DLL.

---

<a name="2026-updates"></a>
## 29. 2026 Updates: New Features & Modern Workflows

### WinDbg Modern Highlights (Microsoft Store Build)

- **NatVis improvements**  better visualization of STL/Rust types in user-mode dumps. Useful when analyzing modern malware written in Rust (an increasingly common 2025/2026 trend).
- **JavaScript debugging**  you can now debug your own WinDbg JavaScript scripts in the same UI.
- **ARM64 support**  full kernel and user debugging on Snapdragon X / Surface Pro 11 / Copilot+ PCs.
- **Dark mode + DPI scaling**  proper readability on 4K monitors and OLED displays.
- **Hot reload of scripts**  `.scriptload` no longer requires unloading first.

### New Mitigations to Be Aware Of (Windows 11 24H2 / Server 2025)

When debugging on modern builds, expect to encounter:

- **CET (Control-flow Enforcement Technology)**  shadow stack enforcement. Most user-mode code runs with shadow stacks enabled. If a sample crashes with `STATUS_STACK_BUFFER_OVERRUN` after a ROP chain, CET caught it.
- **Hypervisor-protected Code Integrity (HVCI)**  prevents unsigned kernel code execution. Disable for driver research (`bcdedit /set hypervisorlaunchtype off` + disable Memory Integrity in Windows Security).
- **Kernel CFG / XFG**  Control Flow Guard / Xtended Flow Guard for kernel. Inspect with `!cfg <function>`.
- **VBS (Virtualization-Based Security)**  runs critical kernel components in a separate VTL (Virtual Trust Level). Some EDR data structures now live there and aren't reachable from a traditional kernel debugger session.

### Rust Malware Analysis Tips

A growing fraction of 2025/2026 samples are written in Rust. WinDbg implications:

- Rust functions follow the Microsoft x64 calling convention on Windows  registers `rcx`, `rdx`, `r8`, `r9` work as expected.
- Symbol names are heavily mangled (`_ZN...`). Use `?? <mangled_name>` and let WinDbg apply rustc demangling, or use the `rustfilt` utility offline.
- Rust panics produce `STATUS_ILLEGAL_INSTRUCTION` (UD2). Catch them with `sxe ud`.
- Strings are stored without null terminators  use `db` rather than `da`.

### Modern Anti-Analysis Trends to Watch

- **Direct syscalls with randomized SSN**  samples generate the syscall stub dynamically at runtime, randomizing register usage to evade pattern matching.
- **Hardware breakpoint abuse for control flow**  instead of normal call/ret, samples use INT1 with `Dr0`–`Dr3` to redirect execution. Counter: examine the VEH chain via `!exchain`.
- **Page Guard tricks**  samples set guard pages and use `STATUS_GUARD_PAGE_VIOLATION` exceptions to drive execution; trace with `sxe gp`.
- **Anti-VM via CPUID hypervisor leaf**  patch CPUID handling at the VM level to spoof bare-metal indicators.

---

<a name="pitfalls"></a>
## 30. Common Pitfalls & Troubleshooting

| Problem | Fix |
|---------|-----|
| `*** ERROR: Module load completed but symbols could not be loaded` | `.reload /f`. Check `.sympath`. Verify internet access to `msdl.microsoft.com`. |
| Breakpoints don't fire | The module isn't loaded yet  use `bu` (deferred) instead of `bp`. Or `sxe ld <module>` to break on module load. |
| Numbers don't match expectations | Remember: everything is hex by default. Use `0n` prefix for decimal. |
| `Source not available` | You don't have the source (normal for closed-source). Use `u` to disassemble. |
| WinDbg appears frozen | The debugee is running freely. Press Ctrl+Break (kernel) or Debug → Break (user). |
| Hooks don't show up in `lm` | Reflectively loaded DLLs aren't registered with the PE loader. Use `!address` to find unbacked private executable regions. |
| Kernel debugger disconnects after VM sleep | Reconnect with `g`; in the worst case, reboot the debugee. KDNET handles this better than serial. |
| `!process` shows weird addresses | You're not in the right process context. Use `.process /i <EPROCESS>; g; .reload /user`. |
| Symbols missing for your custom driver | Add the PDB directory to `.sympath+ C:\path\to\driver\pdb`. |
| `!chkimg` reports many spurious mismatches | Likely base-relocation differences. Use `!chkimg -d` to see exact locations and ignore IAT/relocation areas. |
| TTD recording fails on certain processes | Some PPL-protected or specific anti-tampering processes refuse TTD. Try kernel-side analysis instead. |

### General Health Checks Before Any Long Session

```
.symfix                              ; reset to Microsoft public symbols
.reload /f                           ; force-reload everything
lm                                   ; sanity-check loaded modules
version                              ; OS version + WinDbg version
.kdtargetstate                       ; (kernel) confirm connection healthy
```

---

<a name="resources"></a>
## 31. Reference Resources

**Official Microsoft documentation:**
- WinDbg overview: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
- Command reference: https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/
- Data model & `dx`: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/data-model

**Community cheatsheets worth bookmarking:**
- `repnz/windbg-cheat-sheet`  kernel-debugging focus
- `alex-ilgayev/windbg-kernel-debug-cheat-sheet`  concise kernel reference
- OALabs WinDbg-for-malware-analysis blog series  practical user-mode workflows
- Dump-GUY's malware-analysis-and-reverse-engineering repo  full kernel+user walkthroughs

**Books:**
- *Practical Malware Analysis* (Sikorski & Honig)  Chapter 10 covers WinDbg fundamentals; the rest is essential analysis methodology.
- *Windows Internals, Part 1 & 2* (Russinovich, Solomon, Yosifovich, Ionescu)  every structure you'll inspect.
- *Windows Kernel Programming* (Yosifovich)  companion for driver-level work.
- *Rootkits and Bootkits* (Matrosov, Rodionov, Bratus)  kernel-mode malware techniques.
- *The Art of Memory Forensics* (Ligh, Case, Levy, Walters)  pair with WinDbg for full memory analysis methodology.

**Online courses worth your time:**
- OpenSecurityTraining2 Windows internals courses (free, high-quality)
- Pavel Yosifovich's Windows Internals classes
- Specialized vendor training in malware analysis and EDR internals research

---

## Final Notes

This cheatsheet is meant to grow with you. As you encounter new techniques in your research, add your own recipes  a personal lab notebook is more valuable than any generic reference.

A few principles to keep in mind:

1. **Always work in an isolated, snapshotted analysis VM.** Never analyze live samples on your daily-driver machine.
2. **Symbols make or break your investigation.** Spend 10 minutes setting up `_NT_SYMBOL_PATH` properly once and you'll save days over the long run.
3. **Learn to read the x64 calling convention on sight** (`rcx`, `rdx`, `r8`, `r9` + 32-byte shadow space). It saves hours of guesswork.
4. **The data model (`dx`) and TTD are 10x productivity gains.** Invest the time to learn them  the rest of the cheatsheet becomes leverage on top of those two.
5. **Kernel debugging looks intimidating but is just user-mode with more context.** The commands are nearly identical; you simply have access to every process at once.

Good hunting  and remember, the only ethical way to use any of this is on systems you own, in dedicated research labs, or with explicit written authorization.

---
