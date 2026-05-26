# BYOVD, DRTM Bypass & XDR Evasion (2026 Reference)

> Focus: kernel-level tradecraft for detection engineering, purple team, and threat modeling.
> Last updated: April 2026

---

## Scope & How to Use

This document covers three intertwined areas that together represent the modern kernel-to-EDR attack surface:

| Area | What it is | Primary attacker goal |
|------|------------|----------------------|
| **BYOVD** (Bring Your Own Vulnerable Driver) | Loading a legitimately-signed but vulnerable driver to gain kernel primitives | Disable EDR, read/write kernel memory, terminate PPL processes |
| **DRTM Bypass** (Dynamic Root of Trust for Measurement) | Defeating or sidestepping Intel TXT / AMD SKINIT / Microsoft System Guard / Pluton launch-time protections | Persist below the OS, bypass measured boot, hide from TPM attestation |
| **XDR Evasion** | Defeating correlated telemetry across endpoint / identity / cloud / network | Operate without triggering multi-signal alerts |

**Reading strategy:**

- Detection engineers → start with [§1 Driver Catalog](#1-vulnerable-driver-catalog-2024-2026) and [§5 Detection Pairing](#5-detection--hunting-pairing)
- Purple team planners → start with [§2 Primitives Matrix](#2-primitive-capability-matrix) and [§6 Engagement Playbook](#6-engagement-level-playbook)
- Threat modelers → start with [§3 DRTM](#3-drtm-bypass-scaffold) and [§7 2026 Watch List](#7-2026-watch-list--research-slot)

**Maturity tags used throughout:**

- `STABLE` known-good, widely reproducible, documented in public tooling
- `EMERGING` observed in 2024–2026 campaigns or conference research, reproducible but requires tuning
- `EXPERIMENTAL` research-grade, narrow build/hardware dependencies, lab validation required before operational use

---

## Table of Contents

- [§1 Vulnerable Driver Catalog (2024–2026)](#1-vulnerable-driver-catalog-2024-2026)
- [§2 Primitive Capability Matrix](#2-primitive-capability-matrix)
- [§3 DRTM Bypass Scaffold](#3-drtm-bypass-scaffold)
- [§4 XDR Evasion](#4-xdr-evasion)
- [§5 Detection & Hunting Pairing](#5-detection--hunting-pairing)
- [§6 Engagement-Level Playbook](#6-engagement-level-playbook)
- [§7 2026 Watch List / Research Slot](#7-2026-watch-list--research-slot)
- [Appendix A: Tool Index](#appendix-a-tool-index)
- [Appendix B: Microsoft Vulnerable Driver Blocklist Notes](#appendix-b-microsoft-vulnerable-driver-blocklist-notes)

---

# §1 Vulnerable Driver Catalog (2024–2026)

**Primary data source:** [loldrivers.io](https://www.loldrivers.io/) maintain as your authoritative reference. Cross-reference with Microsoft's [recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules) (file: `SiPolicy.p7b`).

> **Operational note:** The Microsoft Vulnerable Driver Blocklist (HVCI-enforced) is updated 1–2× per year and lags newly-disclosed drivers by months. "Fresh" BYOVD candidates are almost always drivers signed after the last blocklist refresh. See [Appendix B](#appendix-b-microsoft-vulnerable-driver-blocklist-notes).

## 1.1 Still-Viable Drivers in 2025–2026 Campaigns

### RTCore64.sys (MSI Afterburner)

- **Publisher:** MICRO-STAR INTERNATIONAL CO., LTD.
- **Versions affected:** All `< 4.8.0` (vuln disclosed 2019, still seen in campaigns through 2025)
- **CVE:** CVE-2019-16098
- **Primitives:**
  - Arbitrary MSR read/write via `IOCTL 0x80002030` / `0x80002034`
  - Arbitrary physical memory read/write via `IOCTL 0x80002048` / `0x8000204C`
  - Arbitrary IN/OUT port I/O via `IOCTL 0x80002040` / `0x80002044`
- **Operational use:** Classic primitive for `EDRSandBlast`, `kdmapper`-loaded unsigned driver staging
- **Status 2026:** `STABLE` on MS blocklist, but still used when HVCI is off (common in non-managed endpoints)
- **Sample hash (SHA256):** `01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd` (v4.6.2 build)

### dbutil_2_3.sys (Dell Update)

- **Publisher:** Dell Inc.
- **CVE:** CVE-2021-21551 (5 CVEs bundled)
- **Primitives:**
  - Arbitrary kernel r/w via `IOCTL 0x9B0C1EC4` / `0x9B0C1EC8`
  - Token manipulation by chaining kernel write to `_EPROCESS.Token`
- **Operational use:** Used by Lazarus Group (FudModule rootkit), various ransomware crews
- **Status 2026:** Blocked by default MS blocklist still works when HVCI disabled
- **Replacement (by attackers):** `dbutildrv2.sys` (newer, also vulnerable CVE-2021-36276)

### gdrv.sys (Gigabyte Driver)

- **Publisher:** Gigabyte Technology Co., Ltd.
- **CVE:** CVE-2018-19320
- **Primitives:**
  - Arbitrary kernel r/w
  - MSR read/write
  - Physical memory map
- **Operational use:** RobbinHood ransomware historical; still reappears in loader chains
- **Status 2026:** Blocklisted

### viragt64.sys (Trend Micro legacy)

- **CVE:** CVE-2016-9643
- **Primitives:** Kernel r/w, process token steal
- **Status 2026:** Blocklisted; operational value low

### AsIO3.sys / AsUpIO.sys (ASUS utilities)

- **Publisher:** ASUSTeK Computer Inc.
- **Primitives:**
  - Arbitrary physical memory r/w
  - MSR read
- **Operational use:** Reported in APT41 campaigns 2023–2024
- **Status 2026:** Partially blocklisted depending on version; newer ASUS drivers periodically reveal new bugs

### procexp152.sys (Sysinternals Process Explorer)

- **Publisher:** Microsoft (yes, signed by MS)
- **Abuse vector:** Not a memory-corruption vuln the driver itself exposes `IOCTL 0x8335003C` for terminating arbitrary processes including PPL-protected ones (when loaded).
- **Operational use:**
  - "Backstab" tool chain terminate EDR userland agents
  - BYOPE (Bring Your Own Process Explorer) legitimate-looking telemetry
- **Status 2026:** `EMERGING` not traditionally in "vulnerable driver" lists but abused widely 2023–2025. Newer Process Explorer versions (17+) added mitigations; old drivers still signed and usable.

## 1.2 Recently Disclosed / Not Yet On Blocklist (EMERGING 2025–2026)

> These drivers are loaded into operational tooling but are either post-last-blocklist-refresh or have limited public revocation. Validate current status via loldrivers.io before each engagement.

### Truesight.sys (Adlice)

- **Publisher:** Adlice Software
- **Versions:** `< 3.4.0` (specifically v2.0.x–3.3.x widely abused)
- **Primitives:**
  - Kernel process termination by PID including PPL
  - Process handle manipulation
- **Operational use:**
  - SpyBoy "Terminator" tool (sold as an EDR killer since 2023)
  - Continues to appear in ransomware loaders (BlackCat, LockBit derivatives) through 2025
- **Status 2026:** Blocklisted in later MS updates BUT many versions are not, because Adlice reshuffled signing
- **Note:** Multiple versions are signed with different embedded timestamps attackers rotate versions to evade file-hash blocklists

### zamguard64.sys / zam64.sys (Zemana AntiMalware)

- **Publisher:** Zemana Ltd.
- **CVE:** CVE-2021-31728 (and follow-on)
- **Primitives:**
  - Process termination (including PPL)
  - Kernel r/w via IOCTL
  - Process handle privilege escalation
- **Status 2026:** `STABLE` widely used in `EDRSilencer`-class tooling, blocklisted but bypass via timestamp manipulation works intermittently

### iqvw64e.sys (Intel Network Adapter Diagnostic)

- **CVE:** CVE-2015-2291
- **Primitives:**
  - Kernel r/w
  - MSR read/write
- **Operational use:** Original "Slingshot" APT rootkit loader; still in some tooling
- **Status 2026:** Blocklisted

### kprocesshacker.sys / SystemInformer (formerly Process Hacker)

- **Publisher:** Winsider Seminars & Solutions
- **Abuse vector:** Legitimate driver exposing process manipulation IOCTLs
- **Primitives:**
  - Process/thread termination (non-PPL by default; PPL possible in older versions)
  - Handle duplication
- **Status 2026:** `EMERGING` newer SystemInformer versions hardened; attackers ship old driver alongside modern agent

### avg/avast anti-rootkit drivers (various)

- **Abuse vector:** Historically exposed arbitrary process termination and file operations
- **Drivers observed in campaigns:** `aswArPot.sys`, `aswSP.sys`
- **Primitives:** Process kill (including PPL), kernel file I/O
- **Notable campaign:** AvosLocker / Cuba ransomware 2022–2023; techniques replicated into 2025
- **Status 2026:** Heavily blocklisted; still works on un-updated systems

## 1.3 Very Recent / Research-Grade (2025–2026 disclosures)

> `EMERGING` to `EXPERIMENTAL`. Track via loldrivers.io PRs and security conference talks.

### Categories to monitor actively

- **Gaming anti-cheat drivers** historical BYOVD goldmine (Genshin Impact's `mhyprot2.sys` was the canonical example, CVE-2020-36603). 2025 saw continued disclosures in:
  - Various Korean/Chinese MMO anti-cheat modules
  - Kernel-mode cheat detection libraries shipped in indie games
- **PC vendor "system update" drivers** Lenovo, HP, Dell, ASUS, Gigabyte, MSI all periodically ship drivers with IOCTL-exposed primitives. Monitor vendor security advisories.
- **Legacy AV drivers post-acquisition** when AV vendors get acquired, old drivers with expired support but valid signatures accumulate (e.g., old Symantec, McAfee, Trend Micro modules).
- **Mining / overclocking utilities** HWiNFO, CPU-Z, OpenHardwareMonitor-based tooling regularly ship MSR-read drivers.

### Slot: New driver disclosed

```markdown
### <driver_name.sys>

**Publisher:** 
**Version range:** 
**CVE / disclosure:** 
**Signed timestamp range:** 
**Blocklist status (MS SiPolicy.p7b):** not-listed / listed-since-YYYY-MM
**HVCI-enforced?:** 
**Primitives:**
- 
**IOCTL codes observed:**
- 
**Public PoC:** 
**Operational notes:**
- 
```

---

# §2 Primitive Capability Matrix

Match what you need (left column) to drivers that provide it. Cross-reference with [§1](#1-vulnerable-driver-catalog-2024-2026) for versions and blocklist status.

| Capability | Example drivers | Typical use |
|------------|----------------|-------------|
| Arbitrary kernel virtual memory r/w | `dbutil_2_3.sys`, `gdrv.sys`, `iqvw64e.sys`, `zamguard64.sys` | Patch `_EPROCESS.Token`, disable callback arrays, steal tokens |
| Arbitrary physical memory r/w | `RTCore64.sys`, `AsIO3.sys`, `gdrv.sys` | Read secrets from non-paged pool, map kernel structures without direct VA access |
| MSR read/write | `RTCore64.sys`, `gdrv.sys`, `iqvw64e.sys`, HWiNFO-class | Install SMEP/SMAP flip, MSR LSTAR hijack (less useful post-KPTI), CPU feature toggling |
| Port I/O (IN/OUT) | `RTCore64.sys` | Hardware manipulation, rare in modern ops |
| Arbitrary process termination (inc. PPL) | `procexp152.sys`, `Truesight.sys`, `zamguard64.sys`, `aswArPot.sys`, `kprocesshacker.sys` (old) | Kill EDR userland agents (MsMpEng, CSFalconService, Sense, etc.) |
| Process handle w/ elevated access | `kprocesshacker.sys`, `zamguard64.sys` | Open `PROCESS_ALL_ACCESS` to protected processes |
| Kernel module load w/o signature | `kdmapper`-style manual mapping via vulnerable r/w driver | Load unsigned rootkit (final stage) |
| Callback array NULL / unhook | Any kernel r/w primitive | Disable `PsSetCreateProcessNotifyRoutineEx`, `ObRegisterCallbacks`, ETW-TI |
| ETW-TI provider disable | Any kernel r/w primitive | Blind PPL-protected ETW-Threat-Intelligence used by modern EDR |

## 2.1 Classic Attack Chain Using BYOVD

```
1. Initial access + UAC bypass (if needed) → local admin
2. Drop vulnerable driver to disk (C:\Windows\Temp\ or %TEMP%\)
3. sc create / sc start  (OR manually via NtLoadDriver with appropriate SeLoadDriverPrivilege)
4. Open handle to driver device (\\.\<DeviceName>)
5. DeviceIoControl() with target IOCTL
   5a. Primitive 1: Read _EPROCESS of target (e.g., MsMpEng.exe)
   5b. Primitive 2: Walk PsActiveProcessHead to find target
   5c. Primitive 3: Clear _EPROCESS.Protection (PS_PROTECTION structure) to defeat PPL
   5d. Primitive 4: NULL out kernel callback arrays OR patch EDR hook functions
6. Terminate EDR userland (or let it run blind)
7. Load final stage (unsigned driver via kdmapper, userland implant, etc.)
8. (Optional) Uninstall driver to reduce IOCs
```

## 2.2 EDR Blinding via Kernel Callback NULL-ing

The kernel arrays that EDR relies on are finite and well-documented. With kernel r/w, the typical sequence is:

```
1. Resolve PsSetCreateProcessNotifyRoutineEx offset → PspCreateProcessNotifyRoutine array
2. Resolve PsSetCreateThreadNotifyRoutine → PspCreateThreadNotifyRoutine array  
3. Resolve PsSetLoadImageNotifyRoutine → PspLoadImageNotifyRoutine array
4. Resolve CmRegisterCallbackEx → CallbackListHead (registry callbacks)
5. Resolve ObRegisterCallbacks → ObCallBack linked list (handle callbacks)
6. For each: walk array/list, find entry whose routine resolves to EDR-owned module, NULL it
```

**Modern defenses to be aware of:**

- **HVCI (Hypervisor-Protected Code Integrity)** callback arrays may be in VBS-protected memory; direct write fails
- **Kernel CFG** indirect calls verified, so even if you clear an entry the integrity verifier may catch changes
- **Callback list integrity checks** some EDRs (e.g., recent CrowdStrike Falcon, Defender for Endpoint) hash their own callback registrations and alert on tampering
- **ETW-TI re-registration** even if you disable it, kernel event consumers in PPL processes will notice gaps

## 2.3 Defeating PPL (Protected Process Light)

To terminate `MsMpEng.exe`, `LsaIso.exe`, `SgrmBroker.exe`, etc., you need to either:

- **Modify `_EPROCESS.Protection`** the `PS_PROTECTION` struct has `Type`, `Audit`, `Signer` fields. Overwriting to `0x00` removes PPL entirely.
- **Use a driver that doesn't check PPL** `procexp152.sys`, `zamguard64.sys`, and several anti-cheat drivers terminate by PID without regard to process protection.
- **Hijack a PPL-privileged process** much harder, typically requires exploit chain.

## 2.4 Signature & Timestamp Evasion (For the Driver Itself)

Goal: get a vulnerable driver past the MS blocklist when possible.

- **Version rotation** blocklist entries are often file-hash based. Signed versions `N-1` and `N+1` of the same driver family may evade if the blocklist only lists the specific hash from the CVE.
- **Rebuild from leaked source** some older vulnerable drivers have leaked source code; rebuilding with a different signing cert changes the hash while preserving the bug. Requires access to a valid EV code-signing cert (gray market ~$5k–$50k in 2025).
- **Certificate abuse**:
  - Expired certs are still accepted for drivers signed *before* expiry (timestamp bind)
  - Revoked-but-used certs work until the CRL is consulted (most systems cache)
  - Leaked / stolen EV certs from code-signing breaches (search loldrivers for `Certificate` field to see historically abused signers)
- **PE time-date stamp backdating** pair with a valid timestamp-authority (TSA) counter-signature from before vuln disclosure. Makes the driver appear to be a legitimate old artifact.

> **Legal:** Using stolen code-signing certificates is trivially a felony in most jurisdictions (CFAA, DMCA signing-cert abuse, equivalents in EU/UK). Purple team engagements should document authorization scope carefully.

---

# §3 DRTM Bypass Scaffold

> **Maturity warning:** DRTM bypass research in 2024–2026 is a mix of confirmed academic / conference-grade work and highly speculative techniques. This section flags each technique's maturity explicitly. Do not assume any `EXPERIMENTAL` technique works in a real environment without lab validation.

## 3.1 DRTM 101 (Context)

DRTM (Dynamic Root of Trust for Measurement) establishes a trusted execution environment *after* system boot, without trusting BIOS/UEFI. The key implementations:

- **Intel TXT** uses SENTER instruction + SINIT ACM + MLE (Measured Launch Environment). Measurements stored in TPM PCR17–22.
- **AMD SKINIT** simpler analog; uses `SKINIT` instruction + SLB (Secure Loader Block). Measurements in PCR17.
- **Microsoft System Guard Secure Launch** Windows 10/11 feature that uses DRTM (Intel TXT or AMD SKINIT) at boot to establish a measured kernel load. Pairs with HVCI and VBS.
- **Windows DRTM + Pluton** on Pluton-equipped systems (Surface Pro X, some AMD Ryzen 6000+ laptops), Pluton acts as discrete TPM and attestation anchor.

**What DRTM protects against:**
- Pre-boot rootkits (bootkits that load before OS)
- Firmware implants attempting to hide from measured boot
- DMA attacks during early OS load (paired with IOMMU / VT-d)

**What DRTM does NOT protect against:**
- Post-boot kernel compromise (BYOVD still works)
- Exploits in the MLE / Secure Launch code itself
- Attacks on the attestation path (e.g., poisoned TPM, forged quotes)

## 3.2 Confirmed / Public Techniques (STABLE → EMERGING)

### 3.2.1 SINIT ACM / MLE Exploitation `EMERGING`

- **Concept:** Bugs in the Intel Authenticated Code Module (ACM) or the MLE running under SENTER can compromise DRTM at its root.
- **Historical CVEs:**
  - CVE-2017-5715 / Spectre-v2 derivatives against DRTM academic demonstration, vendor patched via microcode
  - Academic work by Joanna Rutkowska / Invisible Things Lab (historical) established the playbook
- **2024–2025 research:** Several Black Hat / OffensiveCon talks explored side-channel leakage from DRTM launch (CPU cache state, TLB).
- **Practical status:** Not a commodity technique. Requires hardware-specific knowledge and sophisticated tooling.

### 3.2.2 TPM PCR Extension Manipulation `EMERGING`

- **Concept:** If you can write to `\\.\PhysicalMemory` or `\Device\Tpm` after DRTM has completed but before remote attestation, you may be able to:
  - Read PCR values to forge a quote
  - Exploit TPM2 command parsing bugs (historically CVE-2023-1017, CVE-2023-1018)
- **Practical status:** Useful for defeating attestation servers that trust the TPM quote; doesn't help local persistence.
- **Tooling:** `tpm2-tools`, custom WHCI callers with kernel r/w primitive.

### 3.2.3 Measured Launch Bypass via HVCI Disable Pre-Boot `STABLE`

- **Concept:** If an attacker can disable HVCI / Credential Guard / System Guard Secure Launch via BCD modification (`bcdedit /set hypervisorlaunchtype off`), the measured-launch chain fails on next boot. System continues to boot but without DRTM protection.
- **Requirements:** Admin on OS, no secure-boot-enforced BCD signing (common in enterprise).
- **Practical status:** Trivially doable when policies don't enforce BCD integrity. Detected by boot-configuration telemetry in mature orgs.

### 3.2.4 Intel SA-00086 (ME / TXT-related) Historical

- **Reference:** Intel Management Engine flaws (2017 era) had secondary effects on TXT validity on certain platforms.
- **Practical status 2026:** Patched on modern CPUs; mentioned for completeness.

### 3.2.5 AMD SKINIT / fTPM Side Channels `EMERGING`

- **Concept:** Research has shown timing side channels on AMD Platform Security Processor (PSP) and fTPM (firmware TPM) that can leak sealed secrets or influence attestation.
- **CVE examples:** CVE-2021-26311, CVE-2021-26312 (PSP)
- **Practical status:** Requires specialized knowledge; mostly academic for now.

## 3.3 Experimental / Research-Grade `EXPERIMENTAL`

> All of the following are research ideas or narrow one-off demonstrations. Validate independently before relying on them.

### 3.3.1 DRTM Resume Path Hijack

- **Hypothesis:** When a system resumes from S3/S4, the DRTM state must be re-established (or attested). Bugs in the resume path may allow injection.
- **Status:** Unconfirmed publicly; candidate area for research.

### 3.3.2 DMA After DRTM Establishment (IOMMU Bypass)

- **Hypothesis:** If IOMMU protection drops momentarily (e.g., during a device reset), a DMA-capable attacker (Thunderbolt, PCIe slot) could write to protected memory.
- **Prior art:** PCILeech, Thunderclap research (2019–2020).
- **Status 2026:** Modern systems enforce IOMMU throughout but gaps have been shown in specific device-reset scenarios.

### 3.3.3 Pluton-Specific Attacks

- **Hypothesis:** Pluton has a different attack surface than discrete TPM 2.0 firmware updates, Azure attestation channel, shared silicon with CPU.
- **Status:** No public exploits as of 2026; MS treats Pluton internals as closed. Potential research target:
  - Pluton firmware update channel abuse
  - Pluton-to-TPM command translation
  - Cross-tenant Pluton attestation quirks in shared hardware

### 3.3.4 Windows System Guard Secure Launch Callback Abuse

- **Hypothesis:** Once SGSL establishes measured launch, it installs callbacks and continues to monitor. Interfering with those callbacks (via kernel r/w) may not immediately trigger a re-measurement.
- **Status:** Requires kernel primitives (from BYOVD or similar) already; speculative.

### 3.3.5 Template: New DRTM Technique

```markdown
### <technique name>

**Maturity:** STABLE / EMERGING / EXPERIMENTAL
**Affected DRTM implementations:** Intel TXT / AMD SKINIT / Windows SGSL / Pluton
**Prerequisites:**
- 
**Primitive required:**
- 
**Detection surface:**
- 
**References:**
- 
```

## 3.4 DRTM Defensive Stance (what you'll see defenders doing)

- **Attestation-based conditional access** Azure AD / Intune check TPM attestation before granting resources. Fail-closed on mismatch.
- **BCD signing / Secure Boot enforced** prevents `bcdedit` tampering
- **Pluton-required enrollment** increasingly common for 2026 managed Windows fleets
- **Remote attestation** via Microsoft Azure Attestation Service

---

# §4 XDR Evasion

XDR differs from traditional EDR by correlating signals across **endpoint + identity + network + cloud + email**. Defeating a single agent is no longer sufficient evasion has to span the correlation surface.

## 4.1 XDR Correlation Surface (What Gets Correlated)

| Telemetry source | What it carries | Common vendors |
|------------------|-----------------|----------------|
| Endpoint (EDR) | Process, file, registry, network, kernel events | CrowdStrike, MS Defender for Endpoint, SentinelOne, Cortex XDR |
| Identity (ITDR) | AAD sign-ins, token events, risky-sign-in signals | AAD ID Protection, Defender for Identity, Falcon Identity |
| Email (EPS) | Message metadata, URL clicks, attachment detonation | Defender for Office 365, Proofpoint |
| Network (NDR) | NetFlow, DNS, HTTP/S metadata, TLS fingerprinting | Darktrace, Vectra AI, ExtraHop, Arista NDR |
| Cloud (CWPP / CNAPP) | IAM API calls, workload behavior, control-plane | Wiz, CrowdStrike Cloud, Defender for Cloud |
| SIEM (correlation layer) | All of the above | Sentinel, Splunk, Chronicle, Exabeam |

## 4.2 Single-Signal Evasion (Baseline STABLE)

These defeat *one* source but typically trigger correlation alerts in mature XDR deployments. Use as building blocks, not solutions.

- **EDR userland unhook** (NT API unhooking, direct syscalls) Hell's Gate / Halo's Gate / Tartarus Gate / Indirect Syscalls
- **ETW patch** `EtwEventWrite` patch, `EtwpEventWriteFull` patch
- **AMSI patch / bypass** `AmsiScanBuffer` patch, memory patching
- **Named pipe impersonation** avoid process creation signals by piggybacking on existing pipes
- **Kernel callback NULL-ing** (via BYOVD, see [§2.2](#22-edr-blinding-via-kernel-callback-null-ing))

**Why these alone are insufficient in 2026:** XDR no longer relies solely on EDR agent telemetry. A blinded endpoint with no outbound network beaconing is itself a signal "quiet" endpoints in historically-chatty subnets trigger anomaly alerts.

## 4.3 Multi-Signal Evasion Patterns (EMERGING)

### 4.3.1 Signal-Consistent Operation

- **Concept:** Don't blind telemetry generate telemetry that looks consistent with baseline.
- **Example:** After disabling EDR hook for a specific process, continue emitting plausible network traffic and process activity for that PID. XDR expects to see *something*.
- **Implementation:**
  - Use living-off-the-land (`rundll32`, `regsvr32`, `mshta`) that appear in baseline
  - Beacon on protocols the environment uses (HTTPS to known CDNs, not raw TCP)
  - Match beacon timing to user activity cycles (sleep during off-hours, active during work hours)

### 4.3.2 Identity-Plane Blending

- **Concept:** If you've got valid OAuth tokens (from AiTM, stealer, or consent phish), operate via legitimate APIs so that identity telemetry shows a "normal" sign-in pattern.
- **Avoid:** Impossible travel, new-device-new-country in same hour, admin operations from non-admin workstations.
- **Techniques:**
  - Use victim's residential IP via their own machine (SOCKS tunnel through the compromised host)
  - Match user-agent to victim's browser
  - Reuse existing session cookies rather than re-authenticating
  - Respect MFA cadence don't trigger MFA when victim wouldn't

### 4.3.3 Living-Off-Trusted-Cloud (LOTC)

- **Concept:** Use the victim org's own cloud tenancy for staging and exfil. Telemetry shows traffic to `*.sharepoint.com`, `*.onedrive.live.com`, `*.azureedge.net` all baseline-expected.
- **Examples:**
  - Exfil to an attacker-controlled document within the victim's SharePoint (self-hosted)
  - Use Teams message bodies as C2 (covert channel)
  - Azure Functions in attacker tenant with `*.azurewebsites.net` but user's own tenant is cleaner still if you have the foothold

### 4.3.4 Cross-Agent Gap Exploitation

- **Concept:** Different agents have different blind spots. Operate in the seams.
- **Examples:**
  - EDR often doesn't see what happens inside `svchost.exe` child threads once injected
  - NDR struggles with encrypted protocols that use perfect forward secrecy + client-pinned certs (e.g., native app traffic)
  - Cloud telemetry is strong on API calls but weak on workload-internal activity (post-compromise container behavior)
  - Email security is blind to in-app messaging (Teams, Slack DMs)

## 4.4 Correlation-Aware Tradecraft (EMERGING → EXPERIMENTAL)

### 4.4.1 Time-Sliced Operations

- Space out correlated actions beyond the XDR correlation window (typically 15min–24h)
- Example: credential theft → wait 36h → use credential from a different geo
- Trade-off: slower operation; acceptable for persistence-oriented ops, not for ransomware-timeline

### 4.4.2 Identity Laundering

- Chain: compromise A → use A to grant permission to B (guest invite) → operate as B
- Each step generates one or two signals, none of which correlate to a single actor
- Particularly effective in Azure AD B2B / cross-tenant scenarios ([§4.5 in initial-access.md](./initial-access.md#45-cloud-trust--federation-abuse))

### 4.4.3 Sensor Poisoning

- **Concept:** Generate noise that dilutes real signals. Mature XDRs tune anomaly thresholds based on baseline; shifting baseline moves thresholds.
- **Status:** `EXPERIMENTAL` ethically dubious, operationally risky (may itself be an anomaly).

### 4.4.4 Attack-the-Analyst

- **Concept:** Target the SOC's own tools and workflows rather than the endpoints
- **Examples observed 2024–2025:**
  - Compromised SIEM query results (injected via log-ingestion path)
  - Poisoned EDR dashboards via malicious asset metadata
  - Malicious false-positive flooding to induce alert fatigue
- **Status:** `EMERGING` seen in high-tier APT work

## 4.5 Specific EDR Agent Notes (2026)

> Research-level only; validate per-build. Agents update frequently.

### CrowdStrike Falcon

- **Known weak points 2024–2025:**
  - Channel file update mechanism (post-incident scrutiny after July 2024 outage not a vuln per se, but an attack surface)
  - `CSFalconService.exe` is PPL but the sensor driver surface is large
- **Tradecraft:** Unhooking doesn't disable cloud telemetry the cloud correlation is the stronger signal; focus on behavioral blending.

### Microsoft Defender for Endpoint (MDE)

- **Known weak points:**
  - Sense agent (`MsSense.exe`) runs in PPL; telemetry via ETW-TI
  - Blinding ETW-TI requires kernel r/w (BYOVD path)
  - Cloud-delivered protection (MAPS) telemetry is separate disabling local service doesn't stop cloud queries
- **Tradecraft:** "Tamper Protection" must be disabled for many local modifications; bypass requires kernel access OR policy manipulation via valid admin context.

### SentinelOne

- **Known weak points:** Agent uses behavioral AI engine unhooking is less useful than behavioral mimicry
- **Tradecraft:** Must avoid sequence-based detections (e.g., recon → creds → lateral within short time window).

### Cortex XDR (Palo Alto)

- **Known weak points:** Heavy network + cloud correlation; endpoint blinding has limited value alone.
- **Tradecraft:** Focus on blending into baseline cloud API patterns.

---

# §5 Detection & Hunting Pairing

Your blue-team-flavored flip of the document. For each offensive technique, what a mature detection engineer builds.

## 5.1 BYOVD Detection Strategies

### Kernel-level (requires kernel sensor: EDR driver, Sysmon w/ DriverLoad, WDAC)

| Signal | How to hunt |
|--------|-------------|
| Unexpected `DriverLoad` event (Sysmon Event ID 6) | Baseline known-good drivers per-host; alert on outliers. Field: `ImageLoaded` path + `Signature` + `SignatureStatus`. |
| Driver loaded from `C:\Windows\Temp\`, `%TEMP%`, user profile | Hunt: `Sysmon EventID=6 AND ImageLoaded LIKE '%\\Temp\\%'` |
| Service creation registering a driver (`sc create ... type= kernel`) | Monitor `System` EventID 7045 with `ServiceType=1` (kernel driver) |
| `NtLoadDriver` from non-standard caller | Requires kernel telemetry; ETW provider `Microsoft-Windows-Kernel-General` |
| Driver hash on vulnerable-driver blocklist (loldrivers) | Enrich DriverLoad events against loldrivers JSON feed; Sigma rule available |
| HVCI/VBS status flip | `Microsoft-Windows-CodeIntegrity/Operational` events around policy changes |

### Sigma rules (already published, known-good starting points)

- `win_driver_load_vuln.yml` loldrivers hash match
- `win_susp_sc_create_kernel.yml` service creation with kernel driver type
- `win_proc_creation_sc_create.yml` `sc.exe create` command-line anomaly
- `win_driver_load_non_c_windows.yml` driver loaded outside `C:\Windows\System32\drivers\`

### KQL (MDE / Sentinel) starter

```kql
DeviceEvents
| where ActionType == "DriverLoad"
| where FolderPath !startswith "C:\\Windows\\System32\\drivers\\"
  or FolderPath contains "\\Temp\\"
  or FolderPath contains "\\AppData\\"
| extend FileHashLookup = SHA256
| join kind=leftouter LoldriversFeed on $left.FileHashLookup == $right.SHA256
| where isnotempty(CVE)
| project Timestamp, DeviceName, FolderPath, SHA256, Signer, CVE, Primitives
```

## 5.2 PPL Tampering Detection

| Signal | How to hunt |
|--------|-------------|
| `MsMpEng.exe` / `SgrmBroker.exe` / `LsaIso.exe` abnormal exit | Correlate unexpected service stop with prior driver load |
| Sensor "gap" EDR telemetry drops for >N seconds | Heartbeat monitoring on agent; alert on gap |
| Kernel callback array integrity | Custom kernel sensor (not available in standard EDR); check notification routines periodically |

## 5.3 DRTM-Related Hunting

| Signal | How to hunt |
|--------|-------------|
| BCD modification affecting hypervisor / DRTM | `Microsoft-Windows-Bcd/Operational`; changes to `hypervisorlaunchtype`, `systemguardsecurelaunch` |
| Secure Boot / HVCI status change | `Microsoft-Windows-CodeIntegrity` EventID 3089 (policy refresh), 3099 |
| TPM PCR mismatch at attestation time | Azure Attestation Service logs; Intune device compliance fail on DRTM measurements |
| Kernel DMA Protection state change | `Microsoft-Windows-Kernel-IoTrace`; IOMMU disable is a red flag |

## 5.4 XDR / Cross-Signal Hunting

Correlation queries (conceptual):

- **Endpoint quiet + identity active** EDR telemetry gap > 10min WHILE same user has active cloud API calls
- **Identity anomaly + endpoint new binary** risky sign-in within 1h of first-seen binary on user's workstation
- **Cloud API burst + endpoint script activity** > N cloud API calls within 5min of PowerShell / script host execution
- **Quiet beaconing** outbound HTTPS to low-reputation domain at regular cadence (jitter-resistant beacon detection)

---

# §6 Engagement-Level Playbook

Sequential reference for planning a purple-team engagement involving BYOVD. All work done under explicit authorization.

## 6.1 Pre-Engagement

1. **Validate authorization scope** specifically that kernel-level modification is in scope
2. **Check target HVCI/VBS posture** `msinfo32` → "Virtualization-based security" section; shapes which drivers are viable
3. **Check MS blocklist version on target** file: `C:\Windows\System32\CodeIntegrity\SiPolicy.p7b` date; compare to [latest MS release](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)
4. **EDR identification** know your target's EDR before choosing driver+primitive combo

## 6.2 Driver Selection

Match the task to the primitive:

- **Just kill EDR userland** → process-termination drivers (`procexp152.sys`, `Truesight.sys` if not blocklisted)
- **Persistent kernel access** → kernel r/w drivers → chain to manual-map unsigned driver
- **ETW-TI blinding** → kernel r/w to patch event-provider structures
- **Token steal only** → kernel r/w → walk `_EPROCESS` → overwrite token pointer

## 6.3 Delivery & Load

- Drop driver to `%TEMP%` or `C:\Windows\Temp\` (commonly writable)
- Register via `sc create` + `sc start`, or more stealthily via `NtLoadDriver` with `SeLoadDriverPrivilege`
- For extreme stealth: use `NtLoadDriver` after directly writing to `HKLM\SYSTEM\CurrentControlSet\Services` (requires admin)

## 6.4 Operate

- Execute primitive(s)
- Maintain awareness of detection: if EDR has dropped, expect a 5–15min window before cloud-side anomaly detection
- Chain secondary payload quickly (unsigned driver load, final implant)

## 6.5 Cleanup

- `sc stop` and `sc delete` the driver service
- Delete driver file from disk
- Clear relevant event log entries IF in scope AND authorized (noisy may trigger its own alerts)

## 6.6 Reporting (purple team)

- Timeline of what was loaded when
- Hashes of all drivers used
- IOCTLs issued and primitives exercised
- Which detections fired vs. silent
- Recommendations: HVCI enablement, MS blocklist enforcement, WDAC policy hardening

---

# §7 2026 Watch List / Research Slot

Scaffold for techniques and drivers emerging this year. Populate as you encounter them via threat intel feeds, conferences (OffensiveCon, Black Hat, DEF CON, BlueHat, Recon, REcon, Insomni'hack), and loldrivers PRs.

## 7.1 BYOVD Research Priorities 2026

- **Drivers signed post-2024 that haven't hit MS blocklist yet** highest operational value; check `SignDate` field on loldrivers
- **Gaming anti-cheat drivers from emerging platforms** historically fertile ground; Korean/Chinese/Russian game publishers lag Western disclosure
- **Vendor "AI accelerator" drivers** new class of drivers shipping in 2024–2026 for NPU / Copilot+ hardware; minimal public scrutiny
- **Windows on ARM driver ecosystem** smaller driver surface, less-studied; potential for first-mover advantage
- **Signed drivers from recently-acquired companies** when a vendor is acquired, their signing certs may remain valid while maintenance lapses

## 7.2 DRTM / Firmware Research Priorities

- **Pluton firmware** as fleet penetration grows (mandatory on some Copilot+ PCs), bugs in Pluton itself become higher-value
- **SGSL (System Guard Secure Launch) on Windows 11 26H2 / Windows 12** new versions may introduce regression
- **Azure Attestation Service** the attestation endpoint is the weak link for remote-attestation-based conditional access
- **fTPM vs. discrete TPM divergence** behavioral differences between fTPM and dTPM implementations occasionally expose bugs

## 7.3 XDR Research Priorities

- **AI-in-EDR bypasses** EDRs increasingly use on-device ML (e.g., SentinelOne's Static AI, CS Falcon's ML engine). Adversarial ML against these is a 2025–2026 research frontier.
- **Copilot-assisted SOC evasion** as SOCs adopt AI-assisted triage (Security Copilot, Charlotte AI), prompt injection against the triage LLM becomes a vector. See also `initial-access.md §4.1`.
- **Cross-tenant correlation quirks** XDR products that correlate across customer tenants may have isolation bugs
- **Agent-in-agent** EDR agents increasingly extended with cloud-workload sensors (CNAPP); internal IPC / upgrade paths are attack surface

## 7.4 Entry Template

```markdown
### <name of driver/technique>

**Category:** BYOVD / DRTM / XDR
**Maturity:** STABLE / EMERGING / EXPERIMENTAL
**First observed / disclosed:** <date, source>
**Affects:** <OS/product versions>
**Prerequisites:**
- 
**Primitive(s) / capability:**
- 
**Known campaigns / actors using it:**
- 
**Public PoC / tooling:**
- 
**Blocklist / mitigation status:**
- 
**Detection surface:**
- 
**Notes:**
- 
```

---

# Appendix A: Tool Index

## A.1 BYOVD Tooling

| Tool | Purpose | URL / source |
|------|---------|--------------|
| **LOLDrivers** | Catalog of vulnerable drivers, SHA256s, CVEs, blocklist status | [loldrivers.io](https://www.loldrivers.io/) |
| **EDRSandBlast** | BYOVD + kernel callback NULL-ing, ETW-TI disable | GitHub (search; repo names change) |
| **EDRSilencer** | Disable EDR userland via BYOVD-backed filter driver abuse | GitHub |
| **Terminator / Backstab** | Process-termination via `procexp152.sys` | Public / leaked tooling |
| **kdmapper** | Manual-map unsigned driver using Intel vulnerable driver | GitHub |
| **KDU (Kernel Driver Utility)** | Swiss-army BYOVD framework; supports many drivers | hfiref0x/KDU |
| **gmer** (historical) | Rootkit detection that itself exposes driver primitives | gmer.net |
| **Process Hacker / SystemInformer** | Admin tool with kernel driver (older versions exploitable) | systeminformer.sourceforge.io |
| **Double-U** | Newer 2024 tool for ETW-TI patching via BYOVD | Research-grade |

## A.2 Analysis & Reversing

- **IDA Pro / Ghidra** driver reversing for new IOCTL discovery
- **WinDbg** kernel debugging (required for serious work)
- **HxD / 010 Editor** binary patching
- **DriverJack** (research) automated driver vulnerability fuzzing

## A.3 DRTM / TPM Tooling

- **tpm2-tools** TPM manipulation
- **Intel TXT Measured Launch Environment (tboot)** reference MLE for research
- **Microsoft Attestation client libraries** for testing attestation path

## A.4 XDR Testing

- **Atomic Red Team** pairs tests with MITRE ATT&CK; useful for telemetry validation
- **SharpHound / BloodHound** (identity-side) detect your own ID-plane footprint
- **CrowdStrike "redcanary" tool** open-source correlation emulation
- **PurpleSharp / APTSimulator** multi-signal attack simulation

---

# Appendix B: Microsoft Vulnerable Driver Blocklist Notes

## B.1 How the Blocklist Works

- File: `C:\Windows\System32\CodeIntegrity\SiPolicy.p7b`
- Enforced by **HVCI** (Hypervisor-Protected Code Integrity) when enabled
- Enforced by **Smart App Control** on Windows 11 (new installs, S mode)
- Updated via Windows Update as part of cumulative updates or out-of-band refresh

## B.2 Enforcement Gaps

- **HVCI not enabled** on older Windows 10 installs, on systems with incompatible drivers, on servers: blocklist is advisory only
- **Smart App Control not enabled** most existing Windows 11 installs (opt-in only for clean installs)
- **Partial enforcement** blocklist may catch file hash but miss renamed/repacked versions
- **Downgrade attacks** older SiPolicy.p7b can be swapped back (requires admin + no Secure Boot enforcement on the policy)

## B.3 Checking Blocklist Version on a Target

```powershell
# Check current policy file date
Get-Item C:\Windows\System32\CodeIntegrity\SiPolicy.p7b | Select-Object Name, LastWriteTime, Length

# Check HVCI status
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard | 
  Select-Object VirtualizationBasedSecurityStatus, AvailableSecurityProperties, CodeIntegrityPolicyEnforcementStatus
```

Values for `CodeIntegrityPolicyEnforcementStatus`:
- `0` Off
- `1` Audit mode (log but don't block)
- `2` Enforced

## B.4 Fresh Driver Criterion

For a vulnerable driver to be operationally useful in 2026:

- Must be signed with a valid cert (not revoked)
- Must NOT be on the current SiPolicy.p7b (OR target must not enforce HVCI)
- Ideally signed after the target's last Windows Update
- Published vulnerability research against the driver exists (else you're discovering primitives yourself)

## B.5 References

- [MS recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)
- [MS HVCI documentation](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-hvci-enablement)
- [loldrivers.io](https://www.loldrivers.io/)
- [MITRE T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [MITRE T1014 Rootkit](https://attack.mitre.org/techniques/T1014/)
- [MITRE T1562.001 Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

---

# Change Log

- **2026-04 (initial version):** BYOVD catalog with concrete drivers and IOCTLs, DRTM scaffold (confirmed + experimental), XDR evasion across correlation surfaces, detection pairing, engagement playbook, 2026 research slot.

