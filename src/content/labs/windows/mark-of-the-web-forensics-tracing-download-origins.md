---
title: "Mark of the Web Forensics: Tracing Download Origins with NTFS Alternate Data Streams"
summary: "A practical Windows forensics blueprint for inspecting Zone.Identifier metadata, tracing download origins, testing Unblock behavior and monitoring MOTW creation."
category: "Windows Security"
labType: "security-research"
status: "planned"
difficulty: "Intermediate"
duration: "45–60 minutes"
environment:
  - "Windows 10/11 virtual machine"
  - "NTFS filesystem"
  - "Microsoft Defender SmartScreen"
  - "PowerShell 5.1 or later"
  - "Sysmon (optional)"
publishedAt: 2026-09-02
updatedAt: 2026-09-02
tags:
  - "Mark of the Web"
  - "MOTW"
  - "Zone.Identifier"
  - "NTFS ADS"
  - "Windows Forensics"
  - "SmartScreen"
  - "Digital Forensics"
tools:
  - "PowerShell"
  - "Command Prompt"
  - "Windows Explorer"
  - "Sysmon"
  - "Autopsy"
mitre:
  - "T1553.005 — Subvert Trust Controls: Mark-of-the-Web Bypass"
sourceName: "John Hammond — The Mark of the Web"
sourceUrl: "https://www.linkedin.com/posts/johnhammond010_simple-windows-forensics-with-the-mark-of-activity-7232008627673309185-VsSb"
visualLeft: "MOTW"
visualRight: "ADS"
visualProcess: "Zone.Identifier"
featured: true
draft: false
---

> **Controlled lab use only.** Perform these exercises in a Windows virtual machine that you own or are explicitly authorized to test. Use only benign files from trusted sources. Do not disable security controls on a production workstation.

<div class="research-state">
  <strong>Research status:</strong> this article is a source-backed research blueprint. The commands, expected observations and validation criteria are documented, but personal execution evidence, screenshots and captured telemetry have not yet been supplied. Results will be promoted to validated only after the lab is reproduced.
</div>

## Executive summary

Windows can attach a **Mark of the Web (MOTW)** to a file obtained from the Internet. On an NTFS volume, the mark is normally stored in a named Alternate Data Stream (ADS) called <code>Zone.Identifier</code>. The stream can record the security zone and, depending on the application that created it, the referring page and the exact download URL.

That makes MOTW useful in two directions:

- Windows and security products can use it to make trust decisions, including SmartScreen checks and Protected View.
- Investigators can use it as a forensic lead when determining how a suspicious file reached a host.

This lab safely downloads a benign file, inspects its streams, records its hash, removes the mark with <code>Unblock-File</code> and confirms whether the primary file content changed. An optional Sysmon phase examines Event ID <code>15</code>, which is designed to record named file-stream creation, including <code>Zone.Identifier</code>.

| Field | Value |
| --- | --- |
| Validation state | Research blueprint — practical validation pending |
| Primary artifact | <code>Zone.Identifier</code> NTFS Alternate Data Stream |
| Safe test object | Benign file downloaded from a trusted HTTPS source |
| Main question | Can the download zone and source URLs be recovered? |
| Detection focus | Sysmon Event ID 15 and EDR file-stream telemetry |
| Destructive action | None; Unblock removes only the selected file's zone metadata |

## Learning objectives

- Explain what the Mark of the Web is and why it depends on NTFS Alternate Data Streams.
- Enumerate file streams with Command Prompt and PowerShell.
- Read and interpret <code>ZoneId</code>, <code>ReferrerUrl</code> and <code>HostUrl</code>.
- Verify that removing MOTW does not alter the primary file content hash.
- Compare an Internet-downloaded file with a locally created negative control.
- Evaluate archive extraction and MOTW inheritance without assuming that every tool behaves identically.
- Identify defensive telemetry for named stream creation.

## Evidence boundary

The source demonstration uses PuTTY, PowerShell, Windows Explorer and a forensic CTF image. This article converts those ideas into a repeatable lab plan without claiming observations that have not been independently captured.

| Claim | Current status |
| --- | --- |
| MOTW is commonly stored in <code>Zone.Identifier</code> on NTFS | Documented by Microsoft and MITRE ATT&CK |
| <code>dir /R</code> and PowerShell can enumerate named streams | Source-backed procedure; pending personal validation |
| <code>HostUrl</code> and <code>ReferrerUrl</code> may identify the download source | Source-backed; fields are optional and application-dependent |
| Removing <code>Zone.Identifier</code> leaves the primary file hash unchanged | Expected from ADS design; this lab will validate it |
| A particular archive tool propagates MOTW to extracted files | Version- and tool-dependent; must be tested locally |
| Sysmon Event ID 15 captures the lab's stream creation | Microsoft-documented capability; local telemetry pending |

The URLs stored in MOTW are evidence leads, not cryptographic proof. Metadata can be absent, lost during transfer or deliberately modified, so investigators should corroborate it with browser history, proxy logs, DNS data, timestamps and file hashes.

## Technical background

### NTFS Alternate Data Streams

An NTFS file has a primary unnamed data stream containing the bytes normally read by applications. NTFS can also associate additional named streams with the same directory entry.

~~~text
downloaded-file.exe
├── unnamed $DATA stream          → normal file content
└── Zone.Identifier:$DATA         → zone-transfer metadata
~~~

Because the named stream is separate from the primary content, a conventional hash of the file normally covers the primary stream only. Removing <code>Zone.Identifier</code> should therefore remove the mark without changing that hash. The lab records both values to verify this rather than simply assuming it.

ADS metadata is an NTFS feature. Moving a file through a filesystem or service that does not preserve named streams can remove the artifact.

### The Zone.Identifier format

A typical stream can resemble the following:

~~~ini
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://example.org/downloads/
HostUrl=https://example.org/files/sample.exe
~~~

The exact fields vary by browser, client and Windows version. <code>ZoneId</code> is the most common field; source URLs may not always be present.

| ZoneId | Windows security zone |
| --- | --- |
| 0 | Local computer |
| 1 | Local intranet |
| 2 | Trusted sites |
| 3 | Internet |
| 4 | Restricted sites |

An Internet download is commonly marked with <code>ZoneId=3</code>. The presence of the stream can influence SmartScreen, Microsoft Office Protected View and other attachment-handling decisions.

## Lab architecture

<div class="attack-flow" role="img" aria-label="Mark of the Web forensic validation flow">
  <span>Download one benign file to an NTFS lab directory</span>
  <span>Enumerate the file's named streams</span>
  <span>Read and preserve Zone.Identifier metadata</span>
  <span>Hash, unblock and hash the primary file again</span>
  <span>Compare controls and review defensive telemetry</span>
</div>

### Prerequisites

- A disposable Windows 10 or Windows 11 virtual machine.
- A VM snapshot created before the experiment.
- A test directory on an NTFS volume.
- PowerShell and Command Prompt.
- A benign file available from a trusted HTTPS source.
- Optional: Sysmon and Event Viewer for detection validation.

Do not change Attachment Manager or SmartScreen policy for the core experiment. Those policies are part of the security baseline and are not required to inspect MOTW.

## Step 1 — Establish the lab directory and baseline

Open PowerShell and create an isolated directory:

~~~powershell
$Lab = 'C:\Lab\MOTW'
New-Item -ItemType Directory -Path $Lab -Force | Out-Null
Get-Volume -DriveLetter C | Select-Object DriveLetter, FileSystem, FileSystemLabel
~~~

The <code>FileSystem</code> result should be <code>NTFS</code>. Record the Windows build and PowerShell version alongside the future screenshots:

~~~powershell
Get-ComputerInfo |
  Select-Object WindowsProductName, WindowsVersion, OsBuildNumber

$PSVersionTable.PSVersion
~~~

## Step 2 — Create a negative control

Create a local text file that did not arrive through a browser:

~~~powershell
$LocalControl = Join-Path $Lab 'local-control.txt'
Set-Content -LiteralPath $LocalControl -Value 'Created locally for the MOTW lab.'
Get-Item -LiteralPath $LocalControl -Stream *
~~~

Expected question: does the file have only its primary <code>:$DATA</code> stream, with no <code>Zone.Identifier</code>? Record the actual result rather than forcing it to match the hypothesis.

## Step 3 — Download one benign file

Use Edge, Chrome or Firefox to download a harmless file from an HTTPS source you trust, then move it into <code>C:\Lab\MOTW</code>. In the commands below, replace the placeholder with its real name:

~~~powershell
$File = 'C:\Lab\MOTW\<DOWNLOADED_FILE>'
Get-Item -LiteralPath $File
~~~

Do not use malware, exploit code or an unknown executable. A small text document, PDF or a signed utility from its official publisher is sufficient to study the metadata.

Before modifying the file, open **Properties** in Explorer and capture whether Windows displays the security notice and **Unblock** option. The option can vary with the downloader, file type and policy.

## Step 4 — Enumerate Alternate Data Streams

Command Prompt can reveal named streams with <code>dir /R</code>:

~~~batch
cd /d C:\Lab\MOTW
dir /R
~~~

PowerShell provides a structured view:

~~~powershell
Get-Item -LiteralPath $File -Stream * |
  Select-Object FileName, Stream, Length
~~~

Look for an entry named <code>Zone.Identifier</code>. Some environments may expose other streams, but their presence and names should be documented as observations rather than treated as universal Windows behavior.

## Step 5 — Read and preserve Zone.Identifier

Read the stream without modifying it:

~~~powershell
$Zone = Get-Content -LiteralPath $File -Stream Zone.Identifier -ErrorAction Stop
$Zone
~~~

Preserve the text in a separate evidence file before using Unblock:

~~~powershell
$ZoneEvidence = Join-Path $Lab 'zone-identifier-evidence.txt'
$Zone | Set-Content -LiteralPath $ZoneEvidence
Get-FileHash -LiteralPath $ZoneEvidence -Algorithm SHA256
~~~

Document these fields if present:

- <code>ZoneId</code>: the security-zone classification.
- <code>HostUrl</code>: the URL from which the file was obtained.
- <code>ReferrerUrl</code>: the page or origin that referred the download.

Do not publish authentication tokens, private URLs, usernames or query-string secrets that may appear in captured URLs. Redact sensitive values while preserving an unredacted copy only in the authorized evidence store.

## Step 6 — Hash, unblock and compare

Record the primary file hash before removing MOTW:

~~~powershell
$Before = Get-FileHash -LiteralPath $File -Algorithm SHA256
$Before
~~~

Remove the zone metadata from this one benign file:

~~~powershell
Unblock-File -LiteralPath $File
~~~

Then enumerate the streams and hash the file again:

~~~powershell
Get-Item -LiteralPath $File -Stream *
$After = Get-FileHash -LiteralPath $File -Algorithm SHA256

[pscustomobject]@{
  Before = $Before.Hash
  After  = $After.Hash
  Match  = ($Before.Hash -eq $After.Hash)
}
~~~

Validation succeeds if the collected evidence shows both of the following:

1. <code>Zone.Identifier</code> is no longer listed after Unblock.
2. The SHA-256 hash of the primary file is identical before and after.

If either result differs, preserve the output and investigate the downloader, filesystem and any security software that may have changed the file.

## Step 7 — Optional synthetic control

This safe control demonstrates that a named stream can be attached without downloading a file. It does not reproduce browser reputation or prove that every Windows component will treat the file identically.

~~~powershell
$Synthetic = Join-Path $Lab 'synthetic-motw.txt'
Set-Content -LiteralPath $Synthetic -Value 'Benign synthetic MOTW control.'

$Motw = "[ZoneTransfer]`r`nZoneId=3"
Set-Content -LiteralPath $Synthetic -Stream Zone.Identifier -Value $Motw

Get-Item -LiteralPath $Synthetic -Stream *
Get-Content -LiteralPath $Synthetic -Stream Zone.Identifier
~~~

Remove only the test stream when finished:

~~~powershell
Remove-Item -LiteralPath $Synthetic -Stream Zone.Identifier
~~~

## Step 8 — Optional archive propagation matrix

Archive behavior has changed across Windows and extraction-tool versions. Treat propagation as an experiment, not a timeless rule.

1. Download a benign ZIP archive so the archive itself receives MOTW.
2. Record the archive's <code>Zone.Identifier</code>.
3. Extract one copy with Windows **Extract All**.
4. Extract a second copy with the current version of another authorized tool.
5. Test each extracted file for <code>Zone.Identifier</code>.
6. Record the Windows build, extractor name and exact version.

| Extraction path | Archive has MOTW | Extracted file has MOTW | Tool version |
| --- | --- | --- | --- |
| Windows Extract All | To test | To test | Record locally |
| Alternate extractor | To test | To test | Record locally |

Containers such as ZIP, ISO, VHD and VHDX are security-relevant because a failure to propagate MOTW can remove downstream trust checks. MITRE ATT&CK maps adversarial abuse of this behavior to [T1553.005 — Mark-of-the-Web Bypass](https://attack.mitre.org/techniques/T1553/005/). This lab studies the artifact and its defenses; it does not create or execute a payload.

## Forensic interpretation

### What MOTW can tell an investigator

- That a compatible application classified the file as originating from a particular Windows security zone.
- The apparent download URL when <code>HostUrl</code> is present.
- A referring page when <code>ReferrerUrl</code> is present.
- Whether a file retained zone metadata through the evidence-collection path.

### What MOTW cannot prove by itself

- That the stored URL is genuine or untouched.
- Which user intentionally initiated the download.
- That the file is malicious or benign.
- That a missing stream means the file was created locally.
- That every copy of the same file carried identical metadata.

If MOTW matters to an investigation, preserve the evidence on NTFS or in a forensic image that retains named streams. Avoid clicking **Unblock**, and do not move the only copy through FAT/exFAT, an archive format or a cloud workflow without first validating metadata preservation.

## Detection opportunities

### Sysmon Event ID 15

Microsoft documents Sysmon Event ID <code>15</code>, <code>FileCreateStreamHash</code>, as the event for named file-stream creation. Its documented purpose includes browser-created <code>Zone.Identifier</code> streams.

After installing and configuring Sysmon in the disposable VM, repeat the benign download and inspect:

~~~text
Applications and Services Logs
└── Microsoft
    └── Windows
        └── Sysmon
            └── Operational
~~~

Filter on Event ID <code>15</code> and validate whether the event includes:

- The target filename.
- The <code>Zone.Identifier</code> stream name.
- Hashes for the associated file.
- Stream content containing <code>ZoneId</code> and optional URLs.

The event can be high-volume. Production filtering should be tested against normal browser and email-client activity before alerts are enabled.

### Defensive hunting questions

- Which executables were created with <code>ZoneId=3</code> and executed shortly afterward?
- Did an Internet-origin archive produce extracted executables without zone metadata?
- Was <code>Zone.Identifier</code> removed shortly before execution?
- Do EDR, browser history and proxy logs agree with the recorded <code>HostUrl</code>?
- Are users repeatedly unblocking high-risk file types?

MOTW is context for a detection, not a verdict. Combine it with file reputation, signature state, process ancestry, user activity and network telemetry.

## Attachment Manager policy considerations

Microsoft exposes policies for preserving zone information and for showing mechanisms that let users remove it. The relevant user-policy path is:

~~~text
User Configuration
└── Administrative Templates
    └── Windows Components
        └── Attachment Manager
~~~

The underlying policy values include <code>SaveZoneInformation</code> and <code>HideZoneInfoOnProperties</code>. Microsoft notes that zone-information preservation requires NTFS and that disabling preservation prevents Windows from making the same origin-based risk assessments.

This lab deliberately does **not** provide registry-toggling steps. Enterprise policy should be changed only through an approved change process, and a research VM does not justify weakening production download protections.

## Troubleshooting

### No Zone.Identifier stream appears

- Confirm that the destination volume is NTFS.
- Confirm that the file was downloaded, not created locally.
- Check whether the downloader applies MOTW.
- Check whether the file was already unblocked.
- If it came from an archive, record the extraction tool and version.
- Review Attachment Manager policy rather than changing it immediately.

### ZoneId exists but HostUrl is absent

URL fields are optional and depend on the application that created the stream. The security zone can still be useful, but download-origin attribution needs other telemetry.

### Get-Content reports that the stream does not exist

List streams first with <code>Get-Item -Stream *</code>. If <code>Zone.Identifier</code> is absent, preserve that as the observed result and investigate the acquisition path.

### The hash changed after Unblock

Stop and preserve both files and command output. A normal ADS-only removal should not change the primary stream, so another process may have replaced or modified the file.

## Cleanup and rollback

After evidence collection:

1. Preserve only the screenshots, command output and hashes needed for the write-up.
2. Remove the synthetic <code>Zone.Identifier</code> stream if it still exists.
3. Delete <code>C:\Lab\MOTW</code> or restore the VM snapshot.
4. Do not leave altered Attachment Manager or SmartScreen policies behind.
5. If Sysmon was installed solely for the lab, restore the original VM snapshot rather than improvising production-like cleanup.

## Validation checklist

- [ ] Windows build, filesystem and PowerShell version captured.
- [ ] Locally created negative control inspected.
- [ ] Benign downloaded file and source documented.
- [ ] Explorer security notice captured, if displayed.
- [ ] <code>dir /R</code> and PowerShell stream enumeration captured.
- [ ] <code>Zone.Identifier</code> content preserved with sensitive URLs redacted for publication.
- [ ] SHA-256 recorded before and after Unblock.
- [ ] Stream removal and hash equality confirmed.
- [ ] Optional archive propagation results recorded by tool version.
- [ ] Optional Sysmon Event ID 15 captured.
- [ ] VM restored or lab files removed.

## Key findings to validate

- MOTW can provide a valuable download-origin lead without changing the file's primary content.
- <code>Zone.Identifier</code> may expose the Internet zone, referrer and direct download URL.
- The artifact is fragile: it can be removed deliberately or lost when a workflow does not preserve NTFS named streams.
- Unblock is a metadata-changing action, so investigators should capture the stream before using it.
- Sysmon Event ID 15 provides a defensive opportunity to observe named stream creation.
- Archive inheritance must be measured against current Windows and tool versions instead of relying on historical assumptions.

Related portfolio research:

- [Bruteforcing Windows Defender Exclusions](/labs/windows/bruteforcing-windows-defender-exclusions/)
- [LNK–HTA Polyglot Lab: Code Execution, Detection & Persistence](/labs/windows/lnk-hta-polyglot-code-execution-detection-persistence/)

## References and attribution

- [John Hammond — The Mark of the Web](https://www.linkedin.com/posts/johnhammond010_simple-windows-forensics-with-the-mark-of-activity-7232008627673309185-VsSb)
- [Microsoft Learn — AttachmentManager Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-attachmentmanager)
- [Microsoft Learn — Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft Learn — Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [MITRE ATT&CK — T1553.005: Mark-of-the-Web Bypass](https://attack.mitre.org/techniques/T1553/005/)
- [Outflank — Mark-of-the-Web from a Red Team's Perspective](https://www.outflank.nl/blog/2020/03/30/mark-of-the-web-from-a-red-teams-perspective/)
- [Red Canary — Why so, ISO? Mark-of-the-Web, Explained](https://redcanary.com/blog/threat-detection/iso-files/)
