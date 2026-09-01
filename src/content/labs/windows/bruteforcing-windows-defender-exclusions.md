---
title: "Bruteforcing Windows Defender Exclusions"
summary: "A validated Windows lab showing how MpCmdRun.exe reveals a Defender-excluded directory through a distinctive skipped-scan response, with detection and mitigation guidance."
category: "Windows Security"
labType: "security-research"
status: "validated"
difficulty: "Intermediate"
duration: "30–45 minutes"
environment:
  - "Windows virtual machine"
  - "Microsoft Defender Antivirus"
  - "PowerShell"
  - "Isolated lab filesystem"
publishedAt: 2026-09-02T10:00:00Z
updatedAt: 2026-09-02T10:00:00Z
completedAt: 2026-09-02
tags:
  - "Microsoft Defender"
  - "MpCmdRun"
  - "AV Exclusions"
  - "Windows Security"
  - "Security Research"
  - "Detection Engineering"
  - "Living off the Land"
tools:
  - "MpCmdRun.exe"
  - "PowerShell"
  - "Windows Security"
  - "Event Viewer"
mitre:
  - "T1518.001 — Security Software Discovery"
sourceName: "Friends & Security research, demonstrated by John Hammond"
sourceUrl: "https://blog.fndsec.net/2024/10/04/uncovering-exclusion-paths-in-microsoft-defender-a-security-research-insight/"
visualLeft: "MPCMD"
visualRight: "EXCLUDE"
visualProcess: "MpCmdRun.exe"
featured: true
draft: false
---

> **Controlled lab use only.** This experiment intentionally creates a temporary Microsoft Defender exclusion. Perform it only in an isolated Windows virtual machine that you own or are explicitly authorized to test. Do not place payloads or malware in the excluded directory.

<div class="research-state validation-complete">
  <strong>Validation complete:</strong> the supplied lab evidence confirms the output difference between an excluded directory and a non-excluded control path. The low-privilege claim, automated recursion with SharpExclusionFinder and the proposed detection rule are source-backed analysis, not results independently validated in this run.
</div>

## Executive summary

Microsoft Defender exclusions are normally protected configuration data because they identify locations that Defender does not scan in the usual way. Friends & Security documented an unusual discovery primitive: a custom scan launched through <code>MpCmdRun.exe</code> can reveal whether a candidate directory is excluded by returning a different result before it rejects a deliberately invalid path.

I reproduced the core behavior in a controlled Windows lab. I configured <code>C:\Share</code> as a Defender folder exclusion and submitted two otherwise equivalent custom-scan requests:

- <code>C:\|*</code>, where the base path was not excluded, returned <code>0x80508023</code>.
- <code>C:\Share\|*</code>, where the base path was excluded, returned <code>Scanning C:\share\|* was skipped.</code>

That response difference creates a simple yes-or-no oracle for a candidate directory. The technique does not add an exclusion, disable Defender or execute code. Its security value is discovery: an attacker who already has local execution could use existing exclusions to understand where file scanning has been intentionally reduced.

| Field | Value |
| --- | --- |
| Validation state | Core output oracle reproduced |
| Test platform | Isolated Windows VM with Microsoft Defender |
| Positive control | <code>C:\Share</code> configured as a folder exclusion |
| Negative control | <code>C:\</code> not configured as an exclusion |
| Payload | None |
| Primary telemetry | <code>MpCmdRun.exe</code> process creation and command line |

## Research objective

The lab had four goals:

1. Confirm that <code>MpCmdRun.exe</code> accepts a custom scan containing the deliberately invalid <code>\|*</code> suffix.
2. Compare the result for a known excluded folder with a non-excluded path.
3. Explain why the two outputs can be used to enumerate exclusions.
4. Translate the behavior into practical detection and hardening guidance.

This is an exclusion-discovery experiment, not an antivirus-bypass test. No malicious file was created, downloaded or executed.

## Evidence boundary

The following distinctions keep the article tied to the available evidence:

| Claim | Status |
| --- | --- |
| <code>C:\Share</code> appeared in the Defender exclusion interface | Observed in the supplied screenshot |
| The excluded path returned <code>was skipped</code> | Executed and observed |
| The non-excluded path returned <code>0x80508023</code> | Executed and observed |
| The output difference can classify a tested path | Validated by the positive and negative controls |
| The same test succeeds from a low-privilege session | Reported by Friends & Security and John Hammond; session integrity was not captured in my screenshots |
| Event ID 5007 exposed the exclusion in this VM | Not tested in this run |
| SharpExclusionFinder recursively discovered the path | Not executed in this run |
| A Sigma rule generated an alert in my environment | Proposed for follow-up; not tested in this run |

The exact Windows build, Defender platform version and PowerShell integrity level were not captured, so I do not infer them from the screenshots.

## Lab environment and topology

The minimum topology is deliberately small:

<div class="attack-flow" role="img" aria-label="Defender exclusion discovery lab flow">
  <span>Isolated Windows VM with Microsoft Defender enabled</span>
  <span>Administrator creates the temporary C:\Share exclusion</span>
  <span>PowerShell launches controlled MpCmdRun custom scans</span>
  <span>The excluded and non-excluded responses are compared</span>
  <span>The exclusion is removed and the VM is restored</span>
</div>

### Prerequisites

- A disposable Windows virtual machine.
- Microsoft Defender Antivirus enabled and active.
- Administrative access only for creating and removing the temporary exclusion.
- PowerShell for launching the two controlled scan requests.
- A VM snapshot taken before changing Defender configuration.

Keep the VM disconnected from production networks and do not reuse the excluded directory for other work.

## Technical background

### Defender exclusions

Microsoft Defender supports exclusions for files, folders, file types and processes. They are sometimes required for compatibility or performance, but every exclusion reduces visibility over the affected scope. That makes exclusion paths valuable discovery data.

An administrator can view or modify exclusions through **Windows Security → Virus & threat protection → Manage settings → Exclusions**. In normal use, access to the complete preference data is restricted. The original Friends & Security research also describes Event ID <code>5007</code> as a possible source of exclusion information because the event records Defender configuration changes.

### Why the invalid suffix matters

The probe appends two characters to a candidate directory:

- The pipe character (<code>|</code>) is invalid in a Windows filename.
- The asterisk (<code>*</code>) is a wildcard.

The Friends & Security researchers explain that Defender appears to evaluate the exclusion before it reaches normal path validation. If the base directory is excluded, the scan is skipped. If it is not excluded, processing reaches the malformed path and fails.

This produces the observable branch:

~~~text
candidate base directory
├── excluded     → "was skipped"
└── not excluded → HRESULT 0x80508023
~~~

## Step 1 — Establish the positive control

I created the lab folder <code>C:\Share</code> and added it as a folder exclusion through the Windows Security interface. The screenshot below captures both the configured exclusion and the corresponding skipped-scan result.

![Microsoft Defender lists C Share as an exclusion while MpCmdRun reports that the custom scan was skipped](/images/labs/windows/bruteforcing-windows-defender-exclusions/defender-excluded-path-skipped.png)

The exclusion is the experiment's known positive control. Without a known excluded folder, a skipped response could not be validated against the Defender configuration.

## Step 2 — Run the non-excluded control

In the lab VM, <code>MpCmdRun.exe</code> was launched from the installed Windows Defender directory. The first request tested the root of <code>C:\</code>, which was not configured as an exclusion:

~~~powershell
.\MpCmdRun.exe -Scan -ScanType 3 -File "C:\|*"
~~~

The important output was:

~~~text
Scan starting...
CmdTool: Failed with hr = 0x80508023.
Check C:\Users\ADMINI~1\AppData\Local\Temp\MpCmdRun.log for more information
~~~

![MpCmdRun custom scan against a non-excluded C drive returns HRESULT 0x80508023](/images/labs/windows/bruteforcing-windows-defender-exclusions/defender-non-excluded-path-error.png)

The error is expected in this experiment. The invalid pipe character prevents the argument from referring to a real file or directory.

## Step 3 — Test the known exclusion

The second request changed only the base directory:

~~~powershell
.\MpCmdRun.exe -Scan -ScanType 3 -File "C:\Share\|*"
~~~

The observed output was:

~~~text
Scan starting...
Scan finished.
Scanning C:\share\|* was skipped.
~~~

Windows paths are case-insensitive by default, so <code>C:\Share</code> in the interface and <code>C:\share</code> in the result refer to the same directory.

### Parameter breakdown

| Argument | Purpose |
| --- | --- |
| <code>-Scan</code> | Starts a Microsoft Defender scan |
| <code>-ScanType 3</code> | Requests a custom scan |
| <code>-File</code> | Supplies the path to test |
| <code>C:\Share</code> | Candidate base directory |
| <code>\|*</code> | Deliberately malformed suffix that creates the output oracle |

The installed location of <code>MpCmdRun.exe</code> varies by Windows and Defender platform version. The supplied screenshot shows it being run from <code>C:\Program Files (x86)\Windows Defender</code>; current Microsoft documentation also describes the Defender platform directory under <code>%ProgramData%\Microsoft\Windows Defender\Platform</code> and the inbox <code>%ProgramFiles%\Windows Defender</code> fallback.

## Validation and interpretation

The positive and negative controls produced different, repeatable classes of output:

| Tested path | Defender configuration | Observed result | Interpretation |
| --- | --- | --- | --- |
| <code>C:\|*</code> | Not excluded | <code>0x80508023</code> | The malformed target reached error handling |
| <code>C:\Share\|*</code> | Excluded | <code>was skipped</code> | Defender recognized the exclusion before scanning |

This validates the core oracle. It does not prove that every Defender release behaves identically, nor does it prove the privilege level of the shell used for these screenshots. Platform updates can change parsing, logging or access-control behavior, so defenders should reproduce the test against the versions they operate.

## From one probe to brute-force discovery

Testing one known path is enough to validate the behavior. Turning it into enumeration means generating candidate directories and repeating the probe.

Friends & Security published **SharpExclusionFinder**, a C# utility that accepts a base directory and recursively tests subdirectories using this method. John Hammond's demonstration showed that this approach creates a large number of short-lived <code>MpCmdRun.exe</code> processes.

I did not execute SharpExclusionFinder in this lab. That matters because recursive enumeration adds several unanswered variables: runtime, access-denied behavior, notification volume, process count and EDR response. Those are useful follow-up measurements, not results to assume.

## Detection opportunities and defensive telemetry

The technique uses a legitimate Microsoft binary, but the command-line pattern and repetition are unusual.

### High-value process signals

Monitor for:

- <code>MpCmdRun.exe</code> launched by an interactive shell such as PowerShell or Command Prompt.
- A command line containing <code>-Scan -ScanType 3 -File</code>.
- The distinctive invalid suffix <code>\|*</code>.
- Many <code>MpCmdRun.exe</code> processes from the same user or parent process in a short interval.
- Rapid changes to the tested path while the remaining arguments stay constant.

Process-creation telemetry from an EDR or Sysmon Event ID <code>1</code> is the most direct source. Defender scan events <code>1000</code>, <code>1001</code> and <code>1002</code> may provide additional context, depending on the scan outcome and platform version.

### Experimental Sigma starting point

The following rule is a defensive hypothesis derived from the observed command and John Hammond's detection discussion. It was **not validated in this lab** and should be tested against local telemetry before deployment:

~~~yaml
title: Potential Microsoft Defender Exclusion Enumeration via MpCmdRun
id: f3ba227d-c6d3-4f2d-9c22-59bef1ea74ea
status: experimental
description: Detects a malformed custom scan pattern associated with Defender exclusion discovery.
logsource:
  category: process_creation
  product: windows
detection:
  image:
    Image|endswith: '\MpCmdRun.exe'
  arguments:
    CommandLine|contains|all:
      - ' -Scan'
      - ' -ScanType 3'
      - ' -File'
      - '\|*'
  condition: image and arguments
falsepositives:
  - Authorized Defender troubleshooting or security testing
level: high
~~~

A second correlation rule should count repeated custom scans with different <code>-File</code> values. That captures automated enumeration even if an implementation changes the malformed suffix.

### Event ID 5007

The alternative discovery surface discussed by the original research is:

~~~text
Applications and Services Logs
└── Microsoft
    └── Windows
        └── Windows Defender
            └── Operational
~~~

Event ID <code>5007</code> indicates that Defender configuration changed. It is broader than exclusion changes, so defenders must inspect the old and new values rather than alerting on the ID alone. This log path was not reviewed as part of the supplied validation.

## Defensive recommendations

1. **Minimize exclusions.** Treat each one as a reduction in coverage that requires an owner, justification and expiration review.
2. **Avoid broad paths.** Excluding a drive root, user-writable directory or shared staging folder creates unnecessary exposure.
3. **Control write access.** If an exclusion is unavoidable, restrict who can create or modify files inside it.
4. **Monitor configuration changes.** Review Defender Event ID <code>5007</code> and correlate the changed value with administrative activity.
5. **Monitor enumeration patterns.** Alert on malformed custom scans and bursts of <code>MpCmdRun.exe</code> process creation.
6. **Retest after platform updates.** The behavior depends on Defender's evaluation order and may change.
7. **Do not treat an exclusion as a trusted zone.** Application control, reputation, behavioral monitoring and EDR telemetry should still cover execution from excluded directories.

## Cleanup and rollback

After collecting the two screenshots:

1. Open **Windows Security → Virus & threat protection → Manage settings → Exclusions**.
2. Select <code>C:\Share</code> and remove the temporary exclusion.
3. Delete the empty lab directory if it is no longer required.
4. Confirm that Defender real-time protection remains enabled.
5. Revert the VM to its pre-lab snapshot if a clean baseline is required.

An administrator can verify status after cleanup:

~~~powershell
Get-MpComputerStatus |
  Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled
~~~

The screenshot proves that the exclusion existed during validation, but cleanup evidence was not supplied. The steps above are therefore the required rollback procedure rather than a claim that cleanup was observed.

## Troubleshooting and limitations

### Every request returns an error

- Confirm that the positive-control directory is visibly listed in Defender exclusions.
- Preserve the trailing <code>\|*</code> exactly.
- Verify that the same directory spelling is being tested.
- Confirm that Microsoft Defender is the active antivirus provider.

### MpCmdRun.exe is not in the documented directory

Defender platform updates can move the current binary. Check the latest directory below:

~~~text
%ProgramData%\Microsoft\Windows Defender\Platform\<platform-version>\
~~~

The inbox fallback is commonly:

~~~text
%ProgramFiles%\Windows Defender\
~~~

### A skipped-items notification appears

John Hammond observed that Defender may show a notification when a scan skips excluded content. That visible artifact is another reason this should not be described as stealthy.

### Why not use Get-MpPreference?

<code>Get-MpPreference</code> is the supported administrative view of Defender preferences. The security-research question is whether observable scan behavior discloses one exclusion decision without granting the caller the complete preference list.

## Security considerations

An exclusion is not a universal Defender or EDR bypass. It primarily affects the configured scanning scope. File creation, PowerShell activity, process execution, network connections, token activity and downstream behavior may still be visible to Defender for Endpoint, another EDR, Sysmon or centralized logging.

The experiment also demonstrates an important distinction:

~~~text
discovering a reduced-visibility path ≠ obtaining code execution
discovering a reduced-visibility path ≠ disabling Defender
discovering a reduced-visibility path ≠ evading behavioral detection
~~~

The safe research value is understanding the information leak and building telemetry around it.

## Key findings and lessons learned

- A deliberately malformed custom-scan path produced two distinct results based on whether the base directory was excluded.
- <code>C:\Share\|*</code> returned <code>was skipped</code>, while <code>C:\|*</code> returned <code>0x80508023</code>.
- The technique uses a signed Defender utility but generates a recognizable command-line pattern.
- Automated recursion is likely noisy because it repeatedly launches <code>MpCmdRun.exe</code>.
- Existing exclusions should be treated as sensitive configuration and reviewed like firewall or application-control exceptions.
- Honest validation boundaries matter: the core oracle was reproduced, while low-privilege operation, recursive automation and detection alerts remain follow-up work.

Related portfolio research:

- [LNK–HTA Polyglot Lab: Code Execution, Detection & Persistence](/labs/windows/lnk-hta-polyglot-code-execution-detection-persistence/)
- [Sliver C2 Lab: Netsh Helper DLL Persistence & Detection](/labs/red-team/sliver-netsh-helper-dll-persistence-detection/)

## References and attribution

- [Friends & Security — Peeking Behind the Curtain: Finding Defender's Exclusions](https://blog.fndsec.net/2024/10/04/uncovering-exclusion-paths-in-microsoft-defender-a-security-research-insight/)
- [Friends & Security — SharpExclusionFinder](https://github.com/Friends-Security/SharpExclusionFinder)
- [John Hammond — Bruteforcing Windows Defender Exclusions](https://www.youtube.com/watch?v=fxO1V0mzePQ)
- [Microsoft Learn — Configure and manage Microsoft Defender Antivirus with MpCmdRun](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus)
- [Microsoft Learn — Defender Antivirus scan issues and scan telemetry](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-mdav-scan-issues)
- [Microsoft Learn — Defender Antivirus event IDs and error codes](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
