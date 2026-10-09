---
title: "Hack The Box Sherlock — Unit42"
summary: "A Sysmon EVTX investigation tracing a cloud-hosted installer through execution, file staging, timestamp changes, network activity and process exit."
platform: "Hack The Box"
contentType: "sherlock"
publicationPolicy: "retired"
sherlockCategory: "DFIR"
difficulty: "Very Easy"
solvedAt: 2026-10-09
publishedAt: 2026-10-09
tags:
  - dfir
  - sysmon
  - evtx-analysis
  - windows
  - timestomping
  - ultravnc
tools:
  - PowerShell
  - Get-WinEvent
  - Python 3
cves: []
htbUrl: "https://app.hackthebox.com/sherlocks/Unit42"
cover: "/images/writeups/hackthebox/sherlocks/dfir/unit42/unit42-cover.png"
coverAlt: "Purple Unit42 Sherlock shield with a gold VNC horse on a teal background"
featured: false
draft: false
---

> **Authorized-lab notice:** This investigation covers the **retired** Hack The Box Sherlock Unit42; the solved page identified its state as Retired on 9 October 2026. The original evidence package, task answers and any executable artifacts are not redistributed. Obtain the EVTX from your own authorized HTB account and treat it as untrusted evidence.

Browse the [write-up library](/writeups/) or the [Sherlocks archive](/writeups/sherlocks/) for related cases.

## Executive summary

Unit42 is a short Windows initial-access investigation inspired by a campaign involving a backdoored UltraVNC installer. The supplied evidence is one Sysmon Operational EVTX file. I correlated browser DNS activity, a downloaded executable, process creation, file creation and creation-time changes, a DNS query, a network connection attempt, and process termination. The key was to follow the **same process GUID** across event types and to distinguish files staged by the initial executable from files subsequently written by Windows Installer.

The logs establish a compact sequence of host activity. They do not independently establish that the UltraVNC components were backdoored or that an attacker obtained a working remote session; those claims would need the binary, network capture or additional endpoint telemetry.

## Case information and objectives

| Item | Value |
| --- | --- |
| Scenario | Initial access through a deceptive installer in a Windows user session |
| Platform | [Hack The Box Unit42 Sherlock](https://app.hackthebox.com/sherlocks/Unit42) |
| Category and difficulty | DFIR · Very Easy |
| Publication status | Retired, confirmed on the HTB solved page on 9 October 2026 |
| Evidence | One `Microsoft-Windows-Sysmon-Operational.evtx` file |
| Analysis | Windows `Get-WinEvent`, PowerShell XML extraction and Python field searches |

The questions require more than spotting one suspicious filename. A reproducible solution must establish **how many** file-create records exist, identify the executing image and likely delivery service, compare changed versus previous file-creation times, choose the correct file-creation event when a name appears twice, and link DNS/network activity to the process that exits at the end of the sequence.

## Evidence handling and integrity

The HTB download was a password-protected ZIP. The first `unzip` attempt reported `unsupported compression method 99`; an AES-capable extractor is needed. The HTB help page provides the archive password. On Windows, I used the built-in `tar.exe` against the ZIP and entered the passphrase at its prompt. A Kali reader can use `7z x` with the password supplied by HTB. Extract only the EVTX into an analysis directory; do not execute files named *inside* its events.

The SHA-1 of the downloaded ZIP matched the value published on the Sherlock page. I also calculated a SHA-256 for the extracted log:

```powershell
Get-FileHash .\unit42.zip -Algorithm SHA1
Get-FileHash .\Microsoft-Windows-Sysmon-Operational.evtx -Algorithm SHA256
```

| Artifact | Algorithm | Observed hash |
| --- | --- | --- |
| Downloaded ZIP | SHA-1 | `1D8AC45395551187EAF23793CE525056C4136D6E` |
| Extracted EVTX | SHA-256 | `447C1D3084B919244696ADEC7C541873778B60B35DAAF35C539582FE8E66287B` |

The SHA-1 check verifies that this download matches HTB's stated artifact; it is not a recommendation to use SHA-1 for new evidence. The ZIP and EVTX remain outside this public repository. The EVTX contains **169 records** in total.

## Initial triage: count and inspect the event types

Open the extracted file with **Event Viewer → Action → Open Saved Log**. `Filter Current Log` accepts a comma-separated list of event IDs. Start with `1,2,3,5,11,22`, then filter one ID at a time to see the relevant fields in **Details → XML View**. Event Viewer displays a local-time rendering in its list; the Sysmon `UtcTime` field inside each event is the consistent timestamp for this timeline.

I first grouped all events by ID with PowerShell, then exported their named XML fields for focused searches:

```powershell
$evtx = (Resolve-Path .\Microsoft-Windows-Sysmon-Operational.evtx).Path
Get-WinEvent -Path $evtx | Group-Object Id | Sort-Object Name |
  Select-Object Name, Count
```

That output tells you how many Event ID **11** records exist without counting rows by eye. If Windows denies access to a saved EVTX, rerun the read from a PowerShell session with sufficient permissions; permission failure is not evidence that the file is corrupt.

The core of my parser preserved the Sysmon field names, rather than treating the rendered message as one string:

```powershell
$records = foreach ($event in Get-WinEvent -Path $evtx -Oldest) {
  [xml]$xml = $event.ToXml()
  $fields = [ordered]@{}
  foreach ($field in $xml.Event.EventData.Data) {
    $fields[[string]$field.Name] = [string]$field.'#text'
  }
  [pscustomobject]@{
    Id = $event.Id
    RecordId = $event.RecordId
    TimeCreatedUtc = $event.TimeCreated.ToUniversalTime().ToString('o')
    Data = $fields
  }
}
$records | ConvertTo-Json -Depth 6 | Set-Content .\events.json -Encoding utf8
```

The same observations can be made in Event Viewer. The JSON simply makes repeated field searches easier. In particular, **record ID order is not a reliable incident timeline** here: some DNS and network events have later record IDs but earlier `UtcTime` values. Sort by the event's own UTC time before narrating the sequence.

## Timeline reconstruction

The date is **14 February 2024** and the times below are **UTC**. I show approximate timing where an exact value would be a task answer; inspect the referenced event's `UtcTime` for full precision.

| Time | Evidence source | Event | Significance |
| --- | --- | --- | --- |
| 03:41:25 | Sysmon 22, record 118747 | Firefox resolves a cloud file-hosting endpoint | Delivery lead; DNS alone does not prove the HTTP download URL. |
| 03:41:26 | Sysmon 11, record 118752 | Firefox creates a double-extension executable in the user's Downloads folder | Connects browser activity to a file placed on disk. |
| 03:41:56 | Sysmon 1, record 118793 | Explorer starts the downloaded executable | Establishes the initial executable's PID and Process GUID. |
| 03:41:57 | Sysmon 1, record 118813; Sysmon 22 and 3 | Windows Installer is invoked; the initial process queries a domain and initiates outbound TCP | Join these records by process GUID and parent image rather than by adjacency in the log. |
| Late in the same minute | Sysmon 11 and 2, including records 118846 and 118850 | Files are staged and several creation times are changed | Separates actual write time from the older timestamp applied to a file. |
| End of the sequence | Sysmon 5, record 118907 | The initial executable exits | Use the event's `UtcTime`, not the rounded Event Viewer list time. |

This timeline is short enough to reconstruct manually, but the **relationships** matter more than the chronology alone.

## Following the downloaded executable

The first useful cross-check is the pair of Firefox records: Event ID **22** shows the browser resolving a cloud-hosted file endpoint, and Event ID **11** shortly afterward shows Firefox creating a file under `Downloads`. The later DNS query to the same cloud service supports the delivery hypothesis. It does not show the response body or prove that this exact DNS lookup supplied the executable. A browser download history or network capture would strengthen that link.

Next, filter for Event ID **1**. Record **118793** is the unusual process creation: its `Image` lives in the user's Downloads directory, its basename has a double `.exe` extension, and `ParentImage` is `C:\Windows\explorer.exe`. The `CommandLine` gives the full path required to identify the launched process. Record the `ProcessGuid` at this stage; it is more dependable than a PID for correlation across event types.

```text
Event ID:    1
Record ID:   118793
Image:       C:\Users\<USER>\Downloads\<DOUBLE-EXTENSION-EXECUTABLE>
ParentImage: C:\Windows\explorer.exe
ProcessId:   10672
ProcessGuid: {817bddf3-3684-65cc-2d02-000000001900}
```

The event also contains a SHA-256 for the executable, but the executable itself was not in the supplied package. A hash or suspicious name can support triage; neither proves what code ran. The next event cluster is stronger behavioral evidence.

## File staging, installer handoff and timestamp changes

Event ID **1** records Windows Installer processes after the initial execution. One command line references a staged `main1.msi` and an `AI_SETUPEXEPATH` value pointing back to the downloaded executable. This ties the installer activity to the initial file. Event ID **11** then shows the initial executable writing a set of files under a per-user installer staging directory, including `once.cmd` and UltraVNC-named components. A later Event ID 11 shows `msiexec.exe` writing another copy of `once.cmd` under a shorter machine-level path.

Those two records answer **different questions**. If you need the path *created by the initial malicious file*, filter Event ID 11 by `TargetFilename` ending in `once.cmd`, then compare each matching record's `Image` field. Choose the record whose `Image` is the downloaded executable, not the one whose `Image` is `msiexec.exe`.

```text
Record 118846: Image=<INITIAL-EXECUTABLE>; TargetFilename=<USER-STAGING-PATH>\once.cmd
Record 118875: Image=C:\Windows\system32\msiexec.exe; TargetFilename=<INSTALLED-PATH>\once.cmd
```

Event ID **2** documents deliberate changes to file-creation times in the same staging tree. For the PDF-named target, compare `CreationUtcTime` with `PreviousCreationUtcTime`: the first is the **new, older value**, while the second is the value before modification. It is easy to reverse them if you only read the Event Viewer timestamp at the top of the record.

```text
Event ID:                2
Record ID:               118850
TargetFilename:          <USER-STAGING-PATH>\TempFolder\~.pdf
CreationUtcTime:         <NEW-OLDER-TIME>
PreviousCreationUtcTime: <ORIGINAL-TIME>
```

The log supports a file-time-change finding. Calling it an evasion attempt is a reasonable interpretation of the older replacement time and the surrounding suspicious activity; this EVTX does not disclose the actor's intent. When entering a timestamp into the HTB task, pay attention to the requested precision: the accepted value used **whole seconds**, even though Sysmon preserves milliseconds.

## DNS, network attempt and process exit

Two more event types share the initial process's GUID. Event ID **22** records a query to a dummy-looking domain. Event ID **3** records an initiated TCP connection to its resolved IPv4 address on port **80**. Inspect `Image` and `ProcessGuid` in both records so that Firefox's earlier cloud-service DNS activity is not mistaken for a query by the malicious process.

```text
Event 22, record 118906: Image=<INITIAL-EXECUTABLE>; QueryName=<DUMMY-DOMAIN>
Event 3,  record 118910: Image=<INITIAL-EXECUTABLE>; DestinationIp=<IP>; DestinationPort=80
```

The Event ID 3 field `Initiated=true` shows the process attempted the connection. It does not prove that an HTTP request completed, that data was exchanged or that the destination was a command-and-control server. In the scenario, the dummy-domain query is plausibly a connectivity check; that remains an inference.

Finally, Event ID **5** records the initial executable's termination under the same GUID. Use its `UtcTime` field to recover the precise exit time. In this case, the accepted task format was **date and time to the second**, without the millisecond fraction. Note that a record can appear later in the EVTX than an event whose own UTC timestamp is later; this is why I used the named time fields for the timeline.

## Attack-chain reconstruction and detection opportunities

The confirmed host-side chain is: browser resolves a cloud file host → browser writes a double-extension executable → Explorer starts it → it invokes installer components, stages files and alters creation times → it performs a DNS query and initiates a TCP connection → the initial executable exits. The presence of UltraVNC-named files is consistent with the scenario, but their backdoor behavior is **not proven** by this telemetry alone.

Useful detection ideas from this case are:

- Join **Sysmon 22 → 11 → 1** over a short window to investigate downloads that execute soon after creation. Preserve the browser process and downloaded path.
- Flag unusual **double executable extensions** in user download directories, then enrich with the process parent and hash instead of alerting on the name alone.
- Correlate **Sysmon 1, 2 and 11** by `ProcessGuid` to find newly launched installers that stage many files and immediately backdate their creation times.
- Review **two file-create records for the same basename** when one is produced by a user-run installer and another by `msiexec.exe`; the writer process determines which path answers an investigative question.
- Correlate **Sysmon 22, 3 and 5** by GUID. A short-lived process that queries a domain and initiates outbound traffic is worth triage, but Event ID 3 alone does not establish a successful session.

These are hunting leads, not production-ready detections. They need allow-listing and validation against legitimate installers and software deployment activity.

## Limits and lessons learned

Only a narrow Sysmon log was provided. There was no executable sample to reverse engineer, no packet capture or browser history to confirm the exact download transaction, and no later telemetry showing a durable UltraVNC session or persistence execution. The process's SHA-256 in Event ID 1 could be used for external enrichment, but no VirusTotal verdict is necessary to reconstruct this local sequence.

The main practical lesson is to **read the named fields of the record that performed the action**. `Image` distinguishes the initial file from its installer child; `CreationUtcTime` differs from the event timestamp; and `ProcessGuid` ties creation, file activity, DNS, network and termination together. Finally, format the submitted value exactly as the task asks. A full process path, the right creator of a duplicate file, and the requested timestamp precision mattered in this lab.

## References

- [Hack The Box Unit42 Sherlock](https://app.hackthebox.com/sherlocks/Unit42), [How to Play Sherlocks](https://help.hackthebox.com/en/articles/8570249-how-to-play-sherlocks) and [public write-up rules](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines)
- [Microsoft: Sysmon events and investigative field guidance](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [Microsoft: Sysmon configuration event-ID mapping](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files)
