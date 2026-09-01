---
title: "DNS TXT PowerShell Lab: Command Retrieval, Staging & Detection"
summary: "A controlled lab that stores a harmless PowerShell instruction in DNS TXT, retrieves and validates it from Windows, then studies DNS, process and script telemetry."
category: "Network & Windows Security"
labType: "detection-engineering"
status: "planned"
difficulty: "Intermediate"
duration: "60–90 minutes"
environment:
  - "Windows 10/11 VM"
  - "Kali Linux VM"
  - "Microsoft Defender"
  - "Owned DNS zone or isolated authoritative DNS"
publishedAt: 2026-09-01T06:00:00Z
updatedAt: 2026-09-01T06:00:00Z
tags:
  - "DNS"
  - "TXT Records"
  - "PowerShell"
  - "Detection Engineering"
  - "Script Block Logging"
  - "Sysmon"
  - "Staging"
  - "Network Telemetry"
tools:
  - "PowerShell"
  - "dig"
  - "nslookup"
  - "Resolve-DnsName"
  - "Microsoft Defender"
  - "Sysmon"
  - "Event Viewer"
mitre:
  - "T1071.004 — Application Layer Protocol: DNS"
  - "T1059.001 — Command and Scripting Interpreter: PowerShell"
  - "T1105 — Ingress Tool Transfer (theoretical staging discussion)"
sourceName: "John Hammond — PowerShell commands through DNS TXT records; original technique credited to Alh4zr3d"
sourceUrl: "https://www.linkedin.com/posts/johnhammond010_avoid-powershell-invoke-expression-with-dns-activity-6975439094512332800-3hc8"
visualLeft: "DNS"
visualRight: "TXT"
visualProcess: "PowerShell"
featured: true
draft: false
---

> **Controlled lab use only.** Use only virtual machines, DNS zones and infrastructure you own or are explicitly authorized to test. Microsoft Defender must remain enabled. This lab retrieves a harmless string and opens Notepad only after an exact allowlist match. It does not build a downloader, C2 channel, reverse shell, arbitrary remote-execution primitive or protection bypass.

<div class="research-state">
  <strong>Research status:</strong> this page documents the complete research blueprint and validation workflow. Actual resolver timings, screenshots, event records and Defender observations will be added only after the lab has been executed.
</div>

## Executive summary

DNS TXT records are designed to carry text. They are commonly used for legitimate purposes such as SPF, DKIM and domain verification, but the same mechanism can transport instructions or staged data. This lab stores the harmless PowerShell string `Start-Process notepad.exe` in a TXT record, retrieves it from Kali and Windows, validates it against an exact allowlist and maps the resulting telemetry.

The objective is to understand the transport and the defensive evidence—not to execute arbitrary content received from DNS. A negative test deliberately changes the TXT value to confirm that the allowlist rejects unexpected input.

| Field | Value |
| --- | --- |
| Validation state | Research blueprint — practical validation pending |
| Difficulty | Intermediate |
| Estimated time | 60–90 minutes |
| Primary systems | Windows 10/11 VM and Kali Linux VM |
| Benign action | Open `notepad.exe` after an exact string match |
| Detection focus | PowerShell, DNS, process, Defender and optional Sysmon telemetry |

## Learning objectives

After completing the lab, you should be able to:

- Explain DNS TXT records, TTL values, caching and propagation.
- Create and independently verify a harmless TXT record.
- Retrieve the record from Kali and Windows.
- Safely reproduce the storage → retrieval → validation → action concept.
- Explain why moving a command into DNS is not automatic evasion.
- Identify PowerShell, process, DNS and network artifacts.
- Explain staging and the practical size limits of TXT strings.
- Design detection logic that correlates several weak signals into a stronger alert.

## Technique and execution flow

The original offensive concept follows five stages:

1. Store command text in a DNS TXT record.
2. Query the record from a Windows endpoint.
3. Convert the response into a local string.
4. In an offensive chain, pass that string to an execution mechanism.
5. If the payload is too large, use the TXT value as a small stager that retrieves a second stage.

This lab intentionally replaces stages 4 and 5 with strict validation and one known local action.

<div class="attack-flow" role="img" aria-label="DNS TXT PowerShell lab flow">
  <span>Windows VM sends a DNS TXT query</span>
  <span>The recursive resolver contacts the authoritative DNS service</span>
  <span>The TXT response returns to the Windows VM</span>
  <span>PowerShell joins the returned strings and compares the exact value</span>
  <span>Only an allowlisted value causes the local Notepad action</span>
  <span>PowerShell, DNS, process and optional Sysmon telemetry are reviewed</span>
</div>

In John Hammond's demonstration, early tests used harmless applications such as Notepad and Calculator. A later PowerShell Empire payload was detected by AMSI/Microsoft Defender. A successful callback occurred only after protection was disabled; therefore, the demonstration did **not** establish an antivirus bypass. A second stage over HTTP/ngrok was required because of payload size. This lab retains the research lesson while removing the C2 and protection-disabling behavior.

## Core concepts

### DNS TXT records

TXT records carry one or more character strings. Legitimate deployments use them for email security policy, service discovery and ownership verification. From a detection perspective, the protocol is not inherently malicious; context, frequency, length, entropy, endpoint behavior and follow-on activity matter.

### TTL, caching and propagation

The Time to Live value tells recursive resolvers how long an answer may remain cached. After changing a TXT record, one resolver can continue returning the old value until its cached response expires, while another resolver may already return the new value.

This affects both the positive and negative tests. Record the TTL, the modification time and the resolver used instead of assuming that every response changes immediately.

### TXT string length and splitting

A TXT record may contain multiple strings, but each individual character string is limited to 255 octets. DNS tools can display these strings separately. PowerShell should therefore treat the result as structured data and deliberately join the returned strings in the expected order.

### Staging

A stager is a small first stage that retrieves or activates a larger second stage. In the source demonstration, DNS TXT transport was followed by HTTP/ngrok. Here, staging is analyzed only as architecture: the lab does not create a downloader or callback.

## MITRE ATT&CK mapping

- [T1071.004 — Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/) describes adversary use of DNS for command-and-control communications.
- [T1059.001 — Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/) covers PowerShell execution and related defensive visibility.
- [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) is relevant only to the theoretical second-stage discussion; this lab does not transfer a payload.

The mappings describe the behaviors being studied. A normal TXT query or an administrator using PowerShell is not malicious by itself.

## Lab architecture and prerequisites

### Required systems

- **Windows 10/11 VM:** endpoint under observation.
- **Kali Linux VM:** independent DNS verification with `dig`.
- **Microsoft Defender:** enabled throughout the experiment.
- **DNS control:** either an owned public DNS zone or an authoritative DNS server inside the isolated lab.
- **Snapshots:** one for each VM before logging or test changes.

### Network options

**Option A — Owned public DNS zone:** use NAT with only the connectivity required for DNS resolution. The TXT record is created under a subdomain you control.

**Option B — Fully isolated DNS:** run an authoritative DNS service on a lab-only network and configure both VMs to query it. This avoids public DNS propagation but requires a local zone that both systems can resolve.

The examples use `txtlab.example.com`. Replace it with a subdomain you control. Do not create records in another person's zone.

### Safe TXT value

```text
Start-Process notepad.exe
```

Do not use Base64, obfuscation, hidden PowerShell, a downloader, reverse shell or C2 payload. The research target is transport and telemetry.

## Phase 1 — Establish the Windows baseline

Take snapshots of both VMs. Open PowerShell as Administrator only for logging configuration.

### Confirm Microsoft Defender

```powershell
Get-MpComputerStatus |
  Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled
```

All three values should remain `True`. Record the output before and after the experiment.

### Enable Script Block Logging

```powershell
New-Item `
  -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
  -Force

Set-ItemProperty `
  -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
  -Name EnableScriptBlockLogging `
  -Type DWord `
  -Value 1

wevtutil sl Microsoft-Windows-PowerShell/Operational /e:true
```

Verify the log and record the experiment start time:

```powershell
Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational' |
  Select-Object LogName, IsEnabled, RecordCount

$LabStart = Get-Date
$LabStart
```

Keep this PowerShell window open so `$LabStart` remains available. In managed environments, use the organization's approved logging policy rather than changing local policy for this exercise.

## Phase 2 — Create the benign DNS TXT record

In the control panel for your owned DNS zone, create:

| Field | Value |
| --- | --- |
| Type | `TXT` |
| Name / Host | `txtlab` |
| Value | `Start-Process notepad.exe` |
| TTL | `300` seconds, or the lowest value offered by the provider |

Write down:

- The full hostname.
- The authoritative nameservers.
- The selected TTL.
- The time the record was created.

Do not proceed to the PowerShell action until the expected value is independently visible from Kali.

## Phase 3 — Verify the record from Kali

Set the hostname and query the default resolver:

```bash
LAB_FQDN='txtlab.example.com'

dig TXT "$LAB_FQDN"
dig +short TXT "$LAB_FQDN"
dig TXT "$LAB_FQDN" +noall +answer
```

Compare two public resolvers when using a public DNS zone:

```bash
dig @1.1.1.1 TXT "$LAB_FQDN"
dig @8.8.8.8 TXT "$LAB_FQDN"
```

Expected content:

```text
"Start-Process notepad.exe"
```

The quotation marks are output formatting from the DNS client. Save the answer section and note whether the resolvers return the same TTL and value.

## Phase 4 — Retrieve the record from Windows

Open a standard-user PowerShell session and set the hostname:

```powershell
$LabFqdn = 'txtlab.example.com'

nslookup -type=TXT $LabFqdn
Resolve-DnsName -Name $LabFqdn -Type TXT
```

Retrieve the record as structured objects and join any returned strings:

```powershell
$TxtRecord = Resolve-DnsName `
  -Name $LabFqdn `
  -Type TXT `
  -ErrorAction Stop |
  Where-Object Type -eq 'TXT'

$TxtValue = ($TxtRecord.Strings) -join ''
$TxtValue
```

The final value must be exactly:

```text
Start-Process notepad.exe
```

Do not pipe the returned value into `Invoke-Expression`, `cmd.exe`, a script block or any other generic execution mechanism.

## Phase 5 — Execute the allowlisted local action

The DNS value is treated as untrusted input. Only one exact, case-sensitive value is allowed, and the corresponding action is defined locally:

```powershell
$ExpectedTxt = 'Start-Process notepad.exe'

if ($TxtValue -ceq $ExpectedTxt) {
  Write-Host '[OK] TXT value matches the allowlist. Opening Notepad.'
  Start-Process notepad.exe
}
else {
  Write-Warning "Unexpected TXT value—no action was performed: $TxtValue"
}
```

Confirm the expected process:

```powershell
Get-Process notepad -ErrorAction SilentlyContinue |
  Select-Object Id, ProcessName, StartTime
```

This reproduces the essential sequence—DNS storage, retrieval, validation and a local action—without creating a remote code-execution primitive.

## Phase 6 — Negative allowlist test

Temporarily change the TXT value in your DNS zone to:

```text
Start-Process calc.exe
```

Record the modification time. Wait for the previous TTL to expire, or clear the Windows client cache before querying again:

```powershell
Clear-DnsClientCache
```

Retrieve the value again:

```powershell
$TxtRecord = Resolve-DnsName `
  -Name $LabFqdn `
  -Type TXT `
  -ErrorAction Stop |
  Where-Object Type -eq 'TXT'

$TxtValue = ($TxtRecord.Strings) -join ''
$TxtValue
```

Run the same allowlist block from Phase 5.

**Expected result:** a warning is displayed and Calculator does not open. Confirm that no new Calculator process was created:

```powershell
Get-Process CalculatorApp, Calculator -ErrorAction SilentlyContinue
```

If the original value is still returned, compare resolvers and wait for the cached TTL. Do not weaken the allowlist to make the test pass.

## Detection engineering and telemetry

### PowerShell Event ID 4104

Query Script Block Logging events from the recorded start time:

```powershell
Get-WinEvent -FilterHashtable @{
  LogName   = 'Microsoft-Windows-PowerShell/Operational'
  StartTime = $LabStart
} |
Where-Object Id -eq 4104 |
Select-Object TimeCreated, Id, Message |
Format-List
```

Target the lab-specific commands and values:

```powershell
Get-WinEvent -FilterHashtable @{
  LogName   = 'Microsoft-Windows-PowerShell/Operational'
  StartTime = $LabStart
} |
Where-Object {
  $_.Message -match 'Resolve-DnsName|TXT|Start-Process|txtlab'
} |
Select-Object TimeCreated, Id, Message
```

Record whether `Resolve-DnsName`, the returned text, the allowlist comparison and `Start-Process` appear in one or more 4104 events.

### Microsoft Defender

```powershell
Get-MpComputerStatus |
  Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled

Get-MpThreatDetection |
  Select-Object InitialDetectionTime, ThreatName, Resources, ActionSuccess
```

The benign proof of concept may reasonably produce no alert. That does not mean an offensive chain using the same transport would be invisible; the payload content and follow-on behavior are materially different.

### Windows DNS Client log

Check whether the operational log is available and enabled:

```powershell
Get-WinEvent -ListLog 'Microsoft-Windows-DNS-Client/Operational' |
  Select-Object LogName, IsEnabled, RecordCount
```

If enabled, query lab-related events:

```powershell
Get-WinEvent -FilterHashtable @{
  LogName   = 'Microsoft-Windows-DNS-Client/Operational'
  StartTime = $LabStart
} -ErrorAction SilentlyContinue |
Where-Object Message -match 'txtlab|TXT' |
Select-Object TimeCreated, Id, Message
```

### Sysmon, when already installed

Useful events are:

- Event `1` — Process Create.
- Event `3` — Network Connection.
- Event `22` — DNS Query.

```powershell
Get-WinEvent -FilterHashtable @{
  LogName   = 'Microsoft-Windows-Sysmon/Operational'
  StartTime = $LabStart
} -ErrorAction SilentlyContinue |
Where-Object Id -in 1, 3, 22 |
Where-Object Message -match 'powershell.exe|nslookup.exe|txtlab' |
Select-Object TimeCreated, Id, Message |
Format-List
```

Sysmon results depend on the installed configuration. Do not install an unknown configuration or change production logging solely for this lab.

### Defensive hypotheses

Potentially useful signals include:

- `powershell.exe` spawning `nslookup.exe`.
- TXT queries from endpoint groups that rarely request TXT records.
- Unusually long or high-entropy TXT responses.
- PowerShell converting network-derived text into executable code.
- Immediate HTTP/TLS activity following the DNS query.
- Domains associated with tunneling infrastructure or poor reputation.
- Script Block Logging, AMSI or Defender detections.
- Hidden PowerShell and unusual parent-child relationships.

The lab's structured `Resolve-DnsName` path may not create `nslookup.exe`, which makes comparison between the two retrieval methods a valuable detection exercise.

## Control and telemetry matrix

| Phase | Action | Primary evidence | Expected security outcome |
| --- | --- | --- | --- |
| A | `dig` and `nslookup` retrieve the TXT value | Resolver answer, DNS logs, optional Sysmon 22 | Query is observable; no process action |
| B | `Resolve-DnsName` retrieves and joins strings | PowerShell 4104, DNS telemetry | Structured retrieval only |
| C | Exact allowlist opens Notepad | PowerShell 4104 and process creation | Known value accepted |
| D | TXT changes to Calculator | DNS answer and PowerShell comparison | Unexpected value rejected |
| E | Theoretical second-stage discussion only | Additional DNS, HTTP/TLS and process artifacts | Not executed in this lab |

For each phase, record the timestamp, resolver, observed process tree, relevant event IDs and whether Microsoft Defender generated an alert.

## Why DNS storage is not “automatic evasion”

Moving command text from a visible command line into DNS changes the location of one artifact; it does not remove the execution chain.

| Stage | Potential evidence |
| --- | --- |
| DNS query | Resolver logs, Sysmon Event 22, EDR network telemetry |
| TXT response | Length, entropy, domain reputation and query frequency |
| PowerShell parsing | Script Block Logging, AMSI and ETW telemetry |
| Child process | Process creation and parent-child relationships |
| Second stage | HTTP/TLS, proxy, DNS, EDR and tunneling indicators |

The Empire stager in the source demonstration was detected. Disabling Defender is not a bypass; it removes a control that was successfully interrupting the chain.

## Troubleshooting

### The TXT record does not appear

Clear the Windows client cache and query again:

```powershell
Clear-DnsClientCache
Resolve-DnsName -Name $LabFqdn -Type TXT
```

Compare resolvers from Kali:

```bash
dig @1.1.1.1 TXT "$LAB_FQDN"
dig @8.8.8.8 TXT "$LAB_FQDN"
```

Then verify:

- The previous TTL has expired.
- The provider expects the host label `txtlab` rather than the complete FQDN, or vice versa.
- You edited the correct DNS zone.
- The authoritative nameserver itself returns the new value.

### The value is returned as multiple strings

Use the `Strings` property and join the elements deliberately:

```powershell
$TxtValue = ($TxtRecord.Strings) -join ''
```

### `dig` or `nslookup` displays quotation marks

The tools format TXT output with quotes. `Resolve-DnsName` returns structured objects and is preferable for programmatic parsing.

### No PowerShell telemetry appears

- Confirm that the PowerShell Operational log is enabled.
- Start a new PowerShell process after changing the policy.
- Filter with the correct `$LabStart` value from the same session.
- Remember that the Sysmon section applies only when Sysmon is already installed and configured to collect those events.

### The negative test still returns Notepad

- The resolver may still hold the previous cached value.
- Query the authoritative nameserver directly.
- Compare the TTL in the answer section.
- Do not alter the allowlist; wait for the DNS data to converge.

## Cleanup and restoration

1. Delete the `txtlab` TXT record from the DNS zone you control.
2. Clear the Windows client cache and close Notepad:

```powershell
Clear-DnsClientCache
Stop-Process -Name notepad -ErrorAction SilentlyContinue
```

3. Confirm that Defender remains enabled:

```powershell
Get-MpComputerStatus |
  Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled
```

4. Preserve only the event exports and screenshots required for the research record.
5. Revert both VMs to their snapshots if a clean baseline is required. Snapshot restoration is also the safest way to remove the temporary local logging-policy change without guessing the machine's previous configuration.

## Completion checklist

- [ ] I used only a DNS zone and VMs that I control.
- [ ] Microsoft Defender remained enabled.
- [ ] I created the harmless TXT record.
- [ ] I verified it from Kali with `dig`.
- [ ] I verified it from Windows with `nslookup` and `Resolve-DnsName`.
- [ ] The allowlist opened only Notepad.
- [ ] The negative Calculator value was rejected.
- [ ] I reviewed PowerShell, Defender and DNS telemetry.
- [ ] I reviewed Sysmon telemetry if Sysmon was already available.
- [ ] I deleted the TXT record and restored the lab.

## Findings and safe follow-up experiments

The expected research conclusions are:

- DNS can carry text, but it does not provide magical invisibility.
- Removing suspicious text from the original command line changes only one detection surface.
- Staging creates additional process and network artifacts.
- AMSI and Defender results show that content and behavior matter more than storage location.
- In red-team validation, the meaningful outcome is measured control coverage under explicit rules of engagement.

Safe extensions include:

- Compare telemetry produced by `nslookup` and `Resolve-DnsName`.
- Test different TTL values and measure caching behavior.
- Capture Sysmon Event 22 and create a defensive query.
- Test harmless TXT strings of different lengths and observe splitting.
- Extend the allowlist with a local hash or signature check.
- Draft and validate a Sigma rule for suspicious `powershell.exe → nslookup.exe` ancestry and unusual TXT queries.

## Practical validation record

These fields intentionally remain pending until the lab is executed:

| Evidence | Current value |
| --- | --- |
| Execution date | Pending |
| Windows build | Pending |
| DNS provider or isolated server | Pending |
| TXT hostname and TTL | Pending |
| Resolver propagation observations | Pending |
| PowerShell 4104 evidence | Pending |
| DNS Client/Sysmon evidence | Pending |
| Defender result | Pending |
| Negative-test result | Pending |
| What failed | Pending |
| Cleanup confirmation | Pending |

## References and attribution

- [John Hammond — PowerShell commands retrieved through DNS TXT records](https://www.linkedin.com/posts/johnhammond010_avoid-powershell-invoke-expression-with-dns-activity-6975439094512332800-3hc8). Hammond credits the original technique to Alh4zr3d. The Empire/C2 and Defender-disabling portions are intentionally excluded from this lab.
- [MITRE ATT&CK — DNS, T1071.004](https://attack.mitre.org/techniques/T1071/004/)
- [MITRE ATT&CK — PowerShell, T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Microsoft Learn — Resolve-DnsName](https://learn.microsoft.com/en-us/powershell/module/dnsclient/resolve-dnsname)
- [Microsoft Learn — PowerShell Script Block Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [Microsoft Sysinternals — Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft Defender — PowerShell and Microsoft Defender Antivirus](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-using-powershell)
