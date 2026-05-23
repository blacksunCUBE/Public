# WinDbg Cheatsheet for Malware analysis & EDR Research

> A practical, professional reference for using **WinDbg** while studying the **Malware analysis ** and **EDR Internals **.
>
> This cheatsheet is written from zero  no prior WinDbg experience assumed  but assumes you already know what malware analysis, EDR, and basic Windows internals are. Each section explains *what* a command does, *why* you'd use it in offensive/defensive research, and *how* to combine it with real malware analysis workflows.

---

## Table of Contents

1. [Why WinDbg for blacksunCUBE & EDR Research](#why-windbg)
2. [Installation & Initial Setup](#installation)
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
18. [Kernel Callbacks (Critical for EDR)](#callbacks)
19. [Tracking API Hooks & Inline Patches](#hooks)
20. [Process Injection Analysis](#injection)
21. [Syscall & SSDT Analysis](#syscalls)
22. [Anti-Debugging Bypass Techniques](#anti-debug)
23. [Dumping Memory, Modules & Payloads](#dumping)
24. [Crash Dump Analysis](#crash)
25. [Time Travel Debugging (TTD)](#ttd)
26. [Scripting with JavaScript & dx](#scripting)
27. [WinDbg Recipes for blacksunCUBE Modules](#blacksunCUBE-recipes)
28. [WinDbg Recipes for EDR Modules](#edr-recipes)
29. [Common Pitfalls & Troubleshooting](#pitfalls)
30. [Reference Resources](#resources)

---

<a name="why-windbg"></a>
## 1. Why WinDbg for blacksunCUBE & EDR Research

WinDbg is **the** debugger when you need to see what Windows is *actually* doing  not what user-mode APIs claim is happening. For blacksunCUBE     , this matters in two specific ways:

**As a malware analisyseloper (offensive perspective):**
- Verify your payloads behave as expected at the syscall/NTAPI level
- Confirm your unhooking, indirect syscalls, and APC injection actually work
- Inspect PEB/TEB modifications during process hollowing or module stomping
- Debug your loaders without an EDR interfering (controlled environment)

**As an EDR developer/researcher (defensive perspective):**
- Inspect kernel callbacks (`PsSetCreateProcessNotifyRoutine`, `ObRegisterCallbacks`)
- Trace minifilter altitudes and IRPs
- Watch how the kernel routes telemetry through ETW providers
- Analyze how vendors hook user-mode (`ntdll!*`) without modifying syscalls

The same tool serves both sides. Mastering it is non-negotiable for serious work in either .

---

<a name="installation"></a>
## 2. Installation & Initial Setup

### Recommended Installation

Install **WinDbg (modern)** from the Microsoft Store. It is the replacement for WinDbg Preview and includes:
- Time Travel Debugging (TTD)
- JavaScript scripting
- The `dx` data model
- A modern UI with proper docking

Alternative for older Windows or offline machines: install the **Windows SDK** and select only *Debugging Tools for Windows*. This gives you `windbg.exe`, `kd.exe`, `cdb.exe`, and `ntsd.exe`.

```
Tools installed:
  windbg.exe   - GUI debugger
  kd.exe       - Kernel debugger (console)
  cdb.exe      - Console user-mode debugger
  ntsd.exe     - Same as cdb.exe but spawns a window
```

### VM Setup for Safe Malware Work

Never debug live malware on your host. Recommended layout:

| Component | Purpose |
|-----------|---------|
| **Host machine** | WinDbg client, symbols, your payload source |
| **Debugee VM** | VMware/Hyper-V Windows 10/11 x64, Defender disabled, snapshot before each test |
| **Connection** | Named pipe (VMware) or network kernel debugging (Hyper-V/KDNET) |

Always take a clean snapshot of the debugee VM **before** running any sample, so you can revert.

---

<a name="symbols"></a>
## 3. Symbols Configuration

Without symbols, WinDbg shows raw addresses instead of function names like `ntdll!NtCreateFile`. Configure them once and forget about it.

### Set Symbol Path (Persistent)

Open a Command Prompt (Admin) on the WinDbg machine:

```cmd
setx _NT_SYMBOL_PATH "srv*C:\symbols*https://msdl.microsoft.com/download/symbols"
```

This tells WinDbg to download symbols from Microsoft's symbol server on demand and cache them in `C:\symbols`.

### Set Symbol Path Within WinDbg

```
.sympath srv*C:\symbols*https://msdl.microsoft.com/download/symbols
.reload /f                          ; force reload all symbols
.reload /f ntdll.dll                ; reload symbols for a specific module
.reload /user                       ; reload user-mode symbols (kernel debugging)
```

### Verify Symbols Are Loaded

```
lm                                  ; list modules
lm v m ntdll                        ; verbose info on ntdll, including symbol status
```

If you see `(deferred)` next to a module, symbols haven't been loaded yet  they will load on demand or when you `.reload /f` it.

---

<a name="interface"></a>
## 4. WinDbg Interface & Modes

WinDbg has **two operational modes** with different prompts and capabilities:

| Mode | Prompt | Use Case |
|------|--------|----------|
| User-mode | `0:000>` | Debugging a single process (your loader, a sample) |
| Kernel-mode | `kd>` or `lkd>` | Debugging the entire OS (drivers, callbacks, EDR) |

The number before the colon is the **process ID index**; the number after is the **thread ID index**. So `0:003>` means *process #0, thread #3*.

### Attaching to a Live Process (User Mode)

```
File → Attach to Process → select PID
```

Or from command line:

```cmd
windbg -p <PID>
windbg -pn <process_name.exe>
windbg <path_to_exe>            ; launch and debug from start
```

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

By default, **all numbers are hex**. To force decimal use `0n` prefix:

```
0:000> ? 100              ; 100 hex = 256 decimal
0:000> ? 0n100            ; 100 decimal = 64 hex
```

### Expression Evaluator

```
? <expr>                  ; evaluate MASM-style expression
?? <expr>                 ; evaluate C++-style expression (works on types/structures)
dx <expr>                 ; evaluate using data model (JavaScript-aware)
```

---

<a name="process-thread"></a>
## 6. Process & Thread Inspection

### User Mode

```
|                                   ; list debugged processes
|.                                  ; show current process
~                                   ; list all threads in current process
~.                                  ; show current thread
~*                                  ; verbose listing of all threads
~<n>s                               ; switch to thread n
~<n>k                               ; stack trace of thread n
~* k                                ; stack of every thread
```

### Kernel Mode

```
!process 0 0                        ; brief list of all processes
!process 0 7                        ; full detail of all processes (long output)
!process 0 0 lsass.exe              ; find a specific process by name
!process <EPROCESS> 7               ; full detail of one process
!process -1 0                       ; the current process context
.process /i <EPROCESS>              ; switch to that process's VA space (invasive)
.reload /user                       ; after switching, reload user-mode symbols
!thread                             ; current thread info
!thread <ETHREAD> f                 ; verbose thread info with stack
```

A typical workflow when investigating malware from the kernel:

```
kd> !process 0 0 evil.exe           ; find PID and EPROCESS
kd> .process /i ffffd302f0302080    ; switch context invasively
kd> g                               ; let it resume so context switch completes
kd> .reload /user                   ; load user symbols for evil.exe
kd> !peb                            ; inspect its PEB
```

---

<a name="memory"></a>
## 7. Memory Examination

The `d` (display) family  your most-used commands. Each shows memory in a different format.

| Command | Format | Example |
|---------|--------|---------|
| `db` | Bytes + ASCII | `db 0x401000 L20` |
| `dw` | Words (2 bytes) | `dw rsp L10` |
| `dd` | DWORDs (4 bytes) | `dd 0x401000 L4` |
| `dq` | QWORDs (8 bytes, x64) | `dq rcx L4` |
| `da` | ASCII string | `da 0x401000` |
| `du` | Unicode string | `du 0x401000` |
| `dps` | Pointers + nearest symbol | `dps rsp L10` |
| `dpp` | Double pointer dereference | `dpp rcx L1` |

`L` specifies the length (in items of that size). `L20` after `db` means 32 bytes (0x20).

### Searching Memory

```
s -b <range_start> <range_end> <bytes>          ; byte pattern
s -a <range_start> <range_end> "string"         ; ASCII string
s -u <range_start> <range_end> "string"         ; Unicode string

; Examples
s -a 0 L?80000000 "Mozilla"                     ; search a Firefox-like UA across user space
s -b ntdll L?ntdll "4c 8b d1 b8"                ; classic x64 syscall stub prologue
```

### Editing Memory (Dangerous  Use Only When Necessary)

```
eb <addr> <byte>...                 ; edit bytes
ed <addr> <dword>                   ; edit DWORD
eq <addr> <qword>                   ; edit QWORD
ea <addr> "string"                  ; write ASCII
eu <addr> "string"                  ; write Unicode
```

Editing memory is useful for **patching out anti-debug checks** or **flipping a process flag** during research. Never do this without understanding the consequences.

### Virtual Memory Layout

```
!address                            ; full VAD-style memory map
!address <addr>                     ; details for a specific address (type, protection, module)
!vad                                ; (kernel) VAD tree of current process
```

`!address` is invaluable for confirming whether an allocation is `MEM_PRIVATE` vs `MEM_IMAGE`  a critical distinction when EDRs flag suspicious `RWX` private memory.

---

<a name="disasm"></a>
## 8. Disassembly & Code Analysis

```
u <addr>                            ; disassemble starting at addr (default 8 instructions)
u <addr> L<count>                   ; disassemble N instructions
uf <addr>                           ; disassemble entire function
uf /c <addr>                        ; show only call targets (call graph)
ub <addr>                           ; disassemble backwards
u .                                 ; disassemble at current instruction pointer
```

### Useful Disassembly Patterns

```
u ntdll!NtCreateFile L20            ; check the syscall stub
u ntdll!NtCreateFile L4             ; quick check: is it hooked?
```

A healthy x64 NTAPI syscall stub on a modern Windows looks like:

```
4C 8B D1            mov  r10, rcx
B8 55 00 00 00      mov  eax, 55h          ; syscall number (varies per build)
F6 04 25 ...        test byte ptr [...]    ; check user-shared-data flag
75 03               jne  short ...
0F 05               syscall
C3                  ret
```

If you see `E9 ?? ?? ?? ??` (a `JMP` rel32) at the function start instead of `4C 8B D1`, the function has been **inline-hooked**. EDRs do this constantly to user-mode functions.

---

<a name="breakpoints"></a>
## 9. Breakpoints  Software, Hardware, Conditional

### Software Breakpoints (most common)

```
bp <addr>                           ; breakpoint at address
bp <module>!<function>              ; symbolic breakpoint
bp ntdll!NtCreateFile               ; break on NtCreateFile
bu <module>!<function>              ; deferred  fires when module loads
bp /1 <addr>                        ; one-shot breakpoint (auto-deletes)
bp /p <EPROCESS> <addr>             ; (kernel) only for this process
bp /t <ETHREAD> <addr>              ; (kernel) only for this thread
```

`bu` is essential when targeting code that **isn't loaded yet**  for example, when you want to break inside a DLL that the loader will pull in after a syscall.

### Hardware Breakpoints (Data Breakpoints / Watchpoints)

Limited to 4 simultaneous (uses DR0–DR3 CPU registers).

```
ba r1 <addr>                        ; break on read (1-byte watch)
ba w4 <addr>                        ; break on write (4-byte watch)
ba e1 <addr>                        ; break on execute (1-byte watch)
```

Use these to catch *anything* touching a memory location. Indispensable when tracking how malware (or an EDR) modifies a structure.

### Breakpoint Management

```
bl                                  ; list breakpoints
bc *                                ; clear all breakpoints
bc <n>                              ; clear breakpoint #n
bd <n>                              ; disable
be <n>                              ; enable
```

### Conditional Breakpoints

Break only when a condition is met. Syntax: `bp <addr> ".if (<cond>) {} .else {gc}"`

```
bp kernel32!CreateFileW ".if (poi(@rcx) == 0x5c) {} .else {gc}"
; break only when first char of filename (rcx) is '\\'

bp ntdll!NtAllocateVirtualMemory ".if (@r9 == 0x40) {} .else {gc}"
; break only when Protect == PAGE_EXECUTE_READWRITE
```

### Command Breakpoints (Auto-Execute Then Continue)

Massively useful for logging without stopping.

```
bp ntdll!NtCreateFile "du poi(poi(@rdx)+10); g"
; log every filename passed to NtCreateFile, then continue
```

For blacksunCUBE work, this lets you turn WinDbg into a poor-man's API monitor.

---

<a name="execution"></a>
## 10. Execution Control

| Command | Action |
|---------|--------|
| `g` | Go (continue) |
| `g <addr>` | Go until address |
| `gu` | Go up  run until current function returns |
| `gh` | Go with exception handled |
| `gn` | Go with exception not handled |
| `p` | Step over (one instruction, skipping calls) |
| `pc` | Step to next call |
| `pt` | Step to next return |
| `t` | Step into |
| `tc` | Trace to next call |
| `wt` | Watch and trace  log every function called |

`wt` produces a massive but informative log  perfect for understanding what a small piece of code does internally.

---

<a name="stack"></a>
## 11. Stack Analysis

```
k                                   ; basic call stack
kn                                  ; with frame numbers
kb                                  ; with first 3 arguments
kv                                  ; verbose  includes calling conv & FPO data
kp                                  ; with full parameters (needs private symbols)
kP                                  ; same as kp but on separate lines
.frame <n>                          ; switch to frame n
dv                                  ; display local variables in current frame
```

### Manually Reading x64 Function Arguments

x64 Windows calling convention: first four args in `rcx`, `rdx`, `r8`, `r9`. Stack args start at `[rsp+0x28]` after the 32-byte shadow space.

```
0:000> r rcx, rdx, r8, r9           ; show first 4 args
0:000> dq /c1 rsp L8                ; show 8 stack slots, one per line
```

When you break inside a function, dump `rcx` first  it's usually the most interesting argument (handle, pointer, filename, etc.).

---

<a name="modules"></a>
## 12. Modules, Symbols & Exports

```
lm                                  ; list loaded modules
lm m kernel*                        ; filter by name pattern
lm a <addr>                         ; module containing this address
lm Dv m ntdll                       ; detailed verbose info about ntdll
ln <addr>                           ; nearest symbol to address  great for "where am I?"
x <module>!<pattern>                ; search symbols
x ntdll!Nt*                         ; list every Nt* function in ntdll
!dh <base_addr>                     ; parse PE headers
!dh -e <module>                     ; list export table
```

### Investigating a Loaded Module

```
lm a 00007ffe`12340000              ; identify the module
lmDvm <module>                      ; detailed info: version, path, timestamp
!dh <base>                          ; check headers (entry point, section flags)
```

Useful for catching **reflectively loaded DLLs**  they often won't appear in `lm` unless properly linked into the PEB loader list.

---

<a name="pseudo"></a>
## 13. Pseudo-Registers & Variables

Pseudo-registers (prefixed with `@$` or `$`) are debugger-managed values.

| Register | Meaning |
|----------|---------|
| `$ip` | Current instruction pointer (architecture-independent) |
| `$exentry` | Entry point of main executable |
| `$peb` | PEB of current process |
| `$teb` | TEB of current thread |
| `$tpid` | Current process ID |
| `$tid` | Current thread ID |
| `$proc` | EPROCESS pointer (kernel) |
| `$thread` | ETHREAD pointer (kernel) |
| `$retreg` | Return value register (`rax` on x64) |

### User-Defined Aliases

```
r $t0 = 0x401000                    ; store an address
bp $t0                              ; break there
?? @$t0                             ; read it back
```

`$t0`–`$t9` are user pseudo-registers  handy for keeping a target address around between commands.

---

<a name="kd-setup"></a>
## 14. Kernel Debugging Setup

### VMware Workstation (Recommended for blacksunCUBE Work)

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
File → Start Debugging → Attach to Kernel → COM
  Pipe:         checked
  Reconnect:    checked
  Resets:       0
  Baud Rate:    115200
  Port:         \\.\pipe\com_1
```

### Hyper-V (KDNET  Faster)

On Hyper-V, use **network kernel debugging** instead of serial  it's dramatically faster.

```cmd
bcdedit /debug on
bcdedit /dbgsettings net hostip:<HOST_IP> port:50000 key:<random.key.value.here>
```

Then on the host:
```
windbg -k net:port=50000,key=<random.key.value.here>
```

### First Connection  Disable Driver Signing for Test Drivers

If you're developing a custom EDR driver (or studying one), you must disable Driver Signature Enforcement on the debugee:

```cmd
bcdedit /set testsigning on
```

Reboot. The VM will show "Test Mode" on the desktop.

### Useful Commands Once Connected

```
.reboot                             ; reboot the debugee from the debugger
.crash                              ; force a bugcheck (for crash dump testing)
.dump /f C:\crash.dmp                ; capture a full kernel dump
g                                   ; let the kernel run
Ctrl+Break                          ; break in (kernel debugging)
```

---

<a name="structures"></a>
## 15. Kernel Structures (EPROCESS, ETHREAD, PEB, TEB)

These structures are the *core* of Windows internals  and the playground for both malware and EDRs.

### EPROCESS  The Kernel View of a Process

```
dt nt!_EPROCESS                     ; show structure layout (just types)
dt nt!_EPROCESS <addr>              ; populate with data from address
dt nt!_EPROCESS <addr> ImageFileName ; just one field
dt nt!_EPROCESS <addr> -r           ; recursive (expand substructures)
```

Fields of high interest:

| Field | Why It Matters |
|-------|----------------|
| `ImageFileName` | Process name (ANSI, max 15 chars) |
| `UniqueProcessId` | PID |
| `Pcb.DirectoryTableBase` | CR3 value  page table base |
| `Token` | Security token pointer |
| `Protection` | PPL level (Protected Process Light) |
| `ObjectTable` | Handle table |
| `Peb` | User-mode PEB pointer |
| `SectionObject` | Image section |
| `InheritedFromUniqueProcessId` | Parent PID  useful for parent spoofing detection |

### ETHREAD

```
dt nt!_ETHREAD <addr>
dt nt!_KTHREAD <addr>               ; the KTHREAD substructure
```

Key fields:
- `Cid.UniqueThread`  TID
- `StartAddress`  initial thread start address (kernel-set)
- `Win32StartAddress`  actual user-mode start address  **EDRs check this for thread injection**

### PEB (Process Environment Block)

```
!peb                                ; pretty-printed PEB
dt nt!_PEB                          ; raw structure layout
dt nt!_PEB @$peb                    ; current process PEB
```

Critical fields for blacksunCUBE:
- `Ldr` → `_PEB_LDR_DATA` → InMemoryOrderModuleList  **modify this for module hiding**
- `BeingDebugged`  anti-debug flag, easy to patch
- `NtGlobalFlag`  anti-debug, holds debug heap flags
- `ProcessParameters` → `ImagePathName`, `CommandLine`, `CurrentDirectory`

### TEB (Thread Environment Block)

```
!teb                                ; current thread TEB
dt nt!_TEB @$teb
```

Critical for malware:
- `NtTib.Self`  pointer to itself (anti-debug check: validate via `gs:[0x30]` on x64)
- `LastErrorValue`  last error code
- `StackBase`, `StackLimit`  for stack pivot detection

---

<a name="tokens"></a>
## 16. Tokens, Privileges & Security Context

EDRs heavily monitor token theft and privilege escalation. These commands let you see exactly what a token contains.

```
!process <EPROCESS> 1               ; brief, includes token pointer
!token <token_addr>                 ; verbose token info
!token -n <token_addr>              ; with privilege names
dt nt!_TOKEN <token_addr>           ; raw token structure
```

### Common Investigation Pattern

```
kd> !process 0 0 lsass.exe          ; find LSASS
kd> dt nt!_EPROCESS <addr> Token    ; get its token
kd> !token <token_addr>             ; inspect privileges
```

If a non-system process suddenly has LSASS-like privileges, you're likely looking at a **token theft / token duplication** attack  covered extensively in blacksunCUBE  .

---

<a name="drivers"></a>
## 17. Driver & Device Object Analysis

For EDR Internals work, you constantly need to inspect drivers, their devices, and IRP handlers.

```
!drvobj <driver_name>               ; basic driver info
!drvobj <driver_name> 7             ; verbose  shows all dispatch routines and devices
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

This is essential for understanding **how an EDR driver routes IRPs** and where to set breakpoints if you want to trace how a request flows.

### Minifilter Inspection

```
!fltkd.frame                        ; minifilter frame
!fltkd.filters                      ; list registered minifilters
!fltkd.instances                    ; minifilter instances
!fltkd.cbs                          ; pre/post operation callbacks
!fltkd.volumes                      ; volumes being filtered
```

`fltkd` is the filter manager extension  load it with `.load fltkd` if it's not active.

---

<a name="callbacks"></a>
## 18. Kernel Callbacks (Critical for EDR)

Modern EDRs register callbacks instead of (or in addition to) SSDT hooking. WinDbg is the best way to see them.

### Process Creation Callbacks

```
kd> dps nt!PspCreateProcessNotifyRoutine L40
```

Each entry is a pointer (with low bits flagged) to a callback routine. `ln` it to find which driver registered it:

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

### Object Callbacks (ObRegisterCallbacks)

These are used to filter handle operations on processes and threads  for example, to prevent dumping LSASS.

```
kd> !object \ObjectTypes\Process
kd> dt nt!_OBJECT_TYPE <addr_from_above>
kd> dt nt!_OBJECT_TYPE <addr> CallbackList
```

Walk the `CallbackList` to enumerate registered callbacks. This is *exactly* how PPL bypass research works.

### Registry Callbacks

```
kd> dps nt!CmpCallBackVector L40
kd> !reg querykey \Registry\Machine\Software
```

For **EDR Internals**   : knowing how to enumerate, identify, and analyze every callback type is mandatory. For **blacksunCUBE**   : the same knowledge tells you exactly what surface area you must evade.

---

<a name="hooks"></a>
## 19. Tracking API Hooks & Inline Patches

User-mode hooks are the bread and butter of legacy EDRs  and the focus of half the blacksunCUBE unhooking modules.

### Quick Hook Detection

```
0:000> u ntdll!NtCreateFile L1
```

A pristine x64 stub starts with `4C 8B D1` (`mov r10, rcx`). If you see `E9 ?? ?? ?? ??` or `49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF E3` (`mov r11, imm64; jmp r11`), it's hooked.

### Compare to On-Disk DLL

```
0:000> !chkimg ntdll                ; check for unexpected changes vs disk
0:000> !chkimg -d ntdll             ; detailed differences
```

`!chkimg` reads the DLL from disk and diffs it against the in-memory copy. **Every diff is a hook.**

### Scripted Bulk Check

```
0:000> .foreach (func {x /1 ntdll!Nt*}) { db ${func} L4 }
```

Iterates every `Nt*` export and dumps its first 4 bytes  a quick way to spot all hooked functions at once.

---

<a name="injection"></a>
## 20. Process Injection Analysis

Several blacksunCUBE modules cover process injection. Here's how to verify your injection actually worked.

### Watch a Suspicious Allocation

```
0:000> bp ntdll!NtAllocateVirtualMemory ".if (poi(@r9) == 0x40) {} .else {gc}"
; break only when Protect == PAGE_EXECUTE_READWRITE
```

### Trace WriteProcessMemory

```
0:000> bp kernel32!WriteProcessMemory "r rcx, rdx, r8, r9; gc"
; logs handle, base addr, buffer, size for every call
```

### Inspect Remote Thread Creation

```
0:000> bp ntdll!NtCreateThreadEx
; when hit, r9 holds StartRoutine  note it down
```

### From the Kernel  Watch Cross-Process Writes

```
kd> bp nt!NtWriteVirtualMemory ".if (@rcx != -1) {!process @rcx 0; .echo ----; !process -1 0} .else {gc}"
```

This logs both the target and the source process for every cross-process write  exactly the signal an EDR would tap.

---

<a name="syscalls"></a>
## 21. Syscall & SSDT Analysis

Indirect/direct syscalls (Hell's Gate, Halo's Gate, Tartarus Gate) are core blacksunCUBE topics.

### Find a Syscall Number

```
0:000> u ntdll!NtCreateFile L4
ntdll!NtCreateFile:
00007ff8`a3245690 4c8bd1          mov     r10,rcx
00007ff8`a3245693 b855000000      mov     eax,55h           ; <-- syscall number
00007ff8`a3245698 f604250803fe...
```

The `mov eax, <num>` instruction always holds the syscall number. This is what tools like SysWhispers extract.

### Verify SSDT (Kernel View)

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

### Watch System Call Entry

The MSR `MSR_LSTAR` (0xC0000082) holds the syscall handler address:

```
kd> rdmsr 0xc0000082
msr[c0000082] = fffff803`12345670
kd> ln fffff803`12345670
(fffff803`12345670)   nt!KiSystemCall64Shadow
```

`KiSystemCall64Shadow` is the kernel's syscall entrypoint on systems with Meltdown mitigations enabled.

---

<a name="anti-debug"></a>
## 22. Anti-Debugging Bypass Techniques

You will encounter anti-debug checks in samples (and you'll write some). Here's how to neutralize the most common ones from the debugger side.

### PEB BeingDebugged

```
0:000> eb @$peb+2 0                 ; set BeingDebugged = 0
```

### PEB NtGlobalFlag

```
0:000> dd @$peb+0x70 L1             ; check NtGlobalFlag (0x70 on x64)
0:000> ed @$peb+0x70 0              ; clear it
```

### CheckRemoteDebuggerPresent / NtQueryInformationProcess

Break at `ntdll!NtQueryInformationProcess` and check the second arg (`ProcessInformationClass`):
- `0x07` = `ProcessDebugPort`
- `0x1E` = `ProcessDebugObjectHandle`
- `0x1F` = `ProcessDebugFlags`

When you see one of these, step until the function returns and zero out the value before resuming.

### Heap Flags

```
0:000> dt nt!_HEAP @$peb!ProcessHeap Flags ForceFlags
```

Patch these to zero if a check uses them as debugger indicators.

### Hardware Breakpoint Detection (NtGetContextThread)

Some samples check `Dr0`–`Dr3` of their own threads. Counter: use software breakpoints (`bp`) instead of hardware (`ba`) for these samples.

### Time Checks (rdtsc, GetTickCount)

```
0:000> bp ntdll!RtlGetTickCount     ; break and tamper return value if needed
```

For `rdtsc` loops, sometimes the simplest fix is to NOP-out the comparison after the time read.

---

<a name="dumping"></a>
## 23. Dumping Memory, Modules & Payloads

A core blacksunCUBE workflow: decrypt a payload in memory, dump it to disk for static analysis.

```
.writemem C:\payload.bin <start> <end>          ; range
.writemem C:\payload.bin <start> L?<size>       ; with explicit size
```

Example  dumping a freshly decrypted shellcode buffer:

```
0:000> bp ntdll!NtProtectVirtualMemory          ; break when payload is being made executable
0:000> g
0:000> .writemem C:\shellcode.bin poi(@rdx) L?poi(@r8)
```

### Dumping a Whole Module

```
0:000> lm a 00007ff8`a3240000        ; identify the base + size
0:000> .writemem C:\ntdll_dump.dll 00007ff8`a3240000 L?0x200000
```

### Dumping a Process Image as a Crash Dump

```
.dump /ma C:\sample.dmp              ; full memory dump (best for post-mortem)
.dump /mf C:\sample.dmp              ; smaller, just essentials
```

---

<a name="crash"></a>
## 24. Crash Dump Analysis

If your custom driver bugchecks (and it will), `!analyze -v` is your first move.

```
windbg -z C:\Windows\MEMORY.DMP      ; open a kernel crash dump
windbg -z C:\sample.dmp              ; open a user-mode dump
```

Once open:

```
!analyze -v                          ; verbose analysis, recommended starting point
.bugcheck                            ; just the bugcheck code + parameters
!thread                              ; thread that crashed
kv                                   ; stack of the crashing thread
.ecxr                                ; switch to exception context
```

Common bugchecks when developing drivers:
- `0xD1` (`DRIVER_IRQL_NOT_LESS_OR_EQUAL`)  touching paged memory at high IRQL
- `0x7E` (`SYSTEM_THREAD_EXCEPTION_NOT_HANDLED`)  unhandled exception in your code
- `0xC4` (`DRIVER_VERIFIER_DETECTED_VIOLATION`)  Driver Verifier caught you

**Always run your driver under Driver Verifier** during analysis:

```cmd
verifier /standard /driver YourDriver.sys
```

---

<a name="ttd"></a>
## 25. Time Travel Debugging (TTD)

TTD is a killer feature of modern WinDbg  it records the execution of a process and lets you step backwards.

### Recording

```
File → Launch executable (advanced) → "Record process with Time Travel Debugging"
```

Or:
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

### Why TTD Is a Superpower for blacksunCUBE

You can record a malware execution **once** and then explore every code path, every memory write, and every API call backwards in time. No more "I missed the breakpoint and have to restart."

Query example  find every call to `NtAllocateVirtualMemory` and inspect the protect flag:

```
dx -g @$cursession.TTD.Calls("ntdll!NtAllocateVirtualMemory").Select(c => new { Pos = c.TimeStart, Protect = c.Parameters[3] })
```

---

<a name="scripting"></a>
## 26. Scripting with JavaScript & dx

Modern WinDbg ships with a JavaScript engine and the `dx` (data model) command. This lets you write debugger scripts that look like real code.

### Load a JS Script

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

### dx Examples

```
dx Debugger.Sessions[0].Processes              ; list processes
dx @$curprocess.Modules                         ; modules of current process
dx @$curprocess.Threads                         ; threads
dx -r2 @$curprocess.Environment.EnvironmentBlock
dx @$cursession.Processes.Where(p => p.Name == "lsass.exe")
```

The data model treats the debugger as a queryable object graph. For repetitive investigations (enumerating callbacks, listing handles by type, mapping every hooked Nt* export), it beats writing `.foreach` loops by a wide margin.

---

<a name="blacksunCUBE-recipes"></a>
## 27. WinDbg Recipes for blacksunCUBE Modules

Concrete workflows mapped to the kinds of techniques you'll meet in blacksunCUBE  .

### Verifying an Indirect Syscall Stub

After writing your indirect syscall code, attach WinDbg to your loader **before** the syscall fires:

```
0:000> bp <your_loader>!IndirectSyscallStub
0:000> g
; when hit:
0:000> u .
; you should see your MOV R10, RCX / MOV EAX, <num> / JMP <ntdll syscall instruction>
0:000> t                              ; single-step into the syscall instruction
; rip should now be inside ntdll, just at the syscall instruction
```

If `ln @rip` doesn't resolve into `ntdll!Nt*`, your stub is jumping to the wrong place.

### Confirming Module Unhooking

Before unhooking:
```
0:000> u ntdll!NtCreateFile L1
ntdll!NtCreateFile:
00007ff8`a3245690 e9d3220000      jmp ...      ; HOOKED
```

After your unhook code runs:
```
0:000> u ntdll!NtCreateFile L1
ntdll!NtCreateFile:
00007ff8`a3245690 4c8bd1          mov r10,rcx  ; PRISTINE
```

Then run `!chkimg ntdll` to confirm zero differences against disk.

### Watching Module Stomping

```
0:000> bp kernel32!LoadLibraryExW "du @rcx; gc"
; logs every DLL loaded into the process

0:000> bp ntdll!NtProtectVirtualMemory ".if (poi(@r9) == 0x40) {.echo RWX!; r; kv} .else {gc}"
; alerts on any RWX transition with a stack trace
```

### Verifying APC Injection (Atom Bombing, NtQueueApcThread variants)

```
0:000> bp ntdll!NtQueueApcThread
; rcx = thread handle, rdx = ApcRoutine, r8 = NormalContext
0:000> r rcx, rdx, r8
0:000> u poi(@rdx)                    ; inspect the queued routine
```

### Dumping a Decrypted Payload

```
0:000> bp ntdll!NtCreateThreadEx
; when hit, the payload buffer is usually rdx (start address)
0:000> .writemem C:\decrypted.bin @rdx L?0x10000
```

---

<a name="edr-recipes"></a>
## 28. WinDbg Recipes for EDR Modules

Workflows specific to the EDR Internals .

### Mapping All EDR Callbacks On a System

A one-shot routine to enumerate every callback type:

```
kd> dps nt!PspCreateProcessNotifyRoutine L40
kd> dps nt!PspCreateProcessNotifyRoutineEx L40
kd> dps nt!PspCreateThreadNotifyRoutine L40
kd> dps nt!PspLoadImageNotifyRoutine L40
kd> dps nt!CmpCallBackVector L40
```

For each non-null entry, `ln` it to identify which driver owns the callback. Build a table  that's your map of installed EDR/AV sensors.

### Identifying ObRegisterCallbacks Entries for Process Object

```
kd> !object \ObjectTypes\Process
kd> dt nt!_OBJECT_TYPE <addr> CallbackList
kd> dt nt!_CALLBACK_ENTRY_ITEM <addr> -l Next
; walk the linked list to find every registered callback
```

### Tracing IRP Flow Through a Minifilter

```
kd> !fltkd.filters                    ; identify your target filter
kd> !fltkd.filter <filter_addr> 4    ; verbose info, including callbacks
kd> bp <filter>!<PreOperation>        ; break on pre-op
kd> bp <filter>!<PostOperation>       ; break on post-op
```

When the breakpoint hits, `rcx` holds the `PFLT_CALLBACK_DATA` pointer. Use `dt FLT_CALLBACK_DATA @rcx` to inspect the operation, target file, parameters.

### Watching ETW-TI Events (Threat Intelligence Provider)

ETW Threat Intelligence is how Defender and many EDRs get high-fidelity events. To see what fires it:

```
kd> x nt!EtwTi*
kd> bp nt!EtwTiLogReadWriteVm        ; cross-process memory access events
kd> bp nt!EtwTiLogAllocExecVm        ; RWX allocations
kd> bp nt!EtwTiLogProtectExecVm      ; RX/RWX transitions
```

These are *exactly* the kernel functions the EDR Internals  teaches you to understand  and that malware developers learn to avoid triggering.

### Identifying PPL-Protected Processes

```
kd> !process 0 0 MsMpEng.exe
kd> dt nt!_EPROCESS <addr> Protection
   +0x87a Protection : _PS_PROTECTION
kd> dt nt!_PS_PROTECTION <addr>+0x87a
```

The `Type` and `Signer` fields tell you whether a process is PPL, full PP, and which signing authority issued the protection. Critical for understanding what you can/can't open with `OpenProcess`.

---

<a name="pitfalls"></a>
## 29. Common Pitfalls & Troubleshooting

| Problem | Fix |
|---------|-----|
| `***  ERROR: Module load completed but symbols could not be loaded` | `.reload /f`. Check `.sympath`. Verify internet access for symbol server. |
| Breakpoints don't fire | Module not loaded yet  use `bu` instead of `bp` (deferred). Or `sxe ld <module>` to break on load. |
| Numbers don't match expectations | Remember: everything is hex by default. Use `0n` prefix for decimal. |
| `Source not available` | You don't have the source code (normal for closed-source). Use `u` to disassemble. |
| `WinDbg is unresponsive` | The debugee is running freely. Press Ctrl+Break (kernel) or Debug → Break. |
| Hooks don't show up in `lm` | Reflectively loaded DLLs don't register with the PE loader. Use `!address` to find unbacked private regions. |
| Kernel debugger stops working after sleep | Reconnect with `g`, or in worst case, reboot the debugee. |
| `!process` shows weird addresses | You're not in the right process context. Use `.process /i <EPROCESS>; g; .reload /user`. |
| Symbols for your own driver missing | Add the path to your PDB to `.sympath+ C:\path\to\driver\pdb`. |

### General Health Checks

Before any long debug session:

```
.symfix                              ; reset to Microsoft public symbols
.reload /f                           ; force reload everything
lm                                   ; sanity check loaded modules
version                              ; OS version + WinDbg version
.kdtargetstate                       ; (kernel) confirm connection healthy
```

---



---

## Final Notes

This cheatsheet is meant to grow with you. 
A few principles to keep in mind throughout both s:

1. **Always work in an isolated, snapshotted VM.** Never debug live samples on your daily-driver machine.
2. **Symbols make or break your investigation.** Spend the 10 minutes to set up `_NT_SYMBOL_PATH` properly once.
3. **Learn to read x64 calling convention by sight** (rcx, rdx, r8, r9 + shadow space). It will save you hours.
4. **The data model (dx) and TTD are 10x productivity gains.** Invest the time to learn them  the rest of the cheatsheet becomes leverage on top of those two.
5. **Kernel debugging looks intimidating but is just user-mode with more context.** The commands are nearly identical; you just have access to every process, not one.

Good hunting  and remember, the only ethical way to use any of this is on systems you own or have explicit written authorization to test.

---

