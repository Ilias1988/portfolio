---
title: "Armaxis"
summary: "Armaxis chains an unbound password-reset token with Markdown image file fetching to take over the admin account and read a server-side flag as Base64."
platform: "Hack The Box"
contentType: "challenge"
publicationPolicy: "retired"
challengeCategory: "Web"
difficulty: "Very Easy"
solvedAt: 2026-10-05
publishedAt: 2026-10-05
tags:
  - web-security
  - password-reset
  - account-takeover
  - arbitrary-file-read
  - markdown
  - source-code-review
tools:
  - Chrome DevTools
  - CyberChef
cves: []
htbUrl: "https://app.hackthebox.com/challenges/Armaxis"
cover: "/images/writeups/hackthebox/challenges/shared/hackthebox-challenge-cover.webp"
coverAlt: "Abstract cybersecurity challenge medallion with terminal, puzzle and network motifs"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up covers the retired Hack The Box Armaxis challenge. The owner confirmed its retired status on 5 October 2026; the supplied HTB page screenshot also showed an available official write-up. The live flag, reset token, chosen password, temporary instance address, and original challenge archive are excluded.

Browse more [Hack The Box write-ups](/writeups/) or the [retired Challenges archive](/writeups/challenges/).

## Executive summary

Armaxis exposes a weapon-dispatch application and a separate inbox. The interesting path is a two-stage chain. First, the password-reset endpoint accepts a valid token for one account while changing the password of an independently supplied email address. A token received for the test account can therefore reset the seeded administrator account. Second, an admin-only dispatch form processes Markdown image URLs by running `curl` on the server. Supplying `file:///flag.txt` reads the local file, Base64-encodes its bytes, and places them in an HTML image `src` attribute.

The live session reached the admin dispatch form, and the final `/weapons` page exposed a `data:image/*;base64,...` attribute in Chrome DevTools. The flag was decoded during the solve but is not reproduced here. The exact reset-token value and terminal response were not preserved, so the request below is a sanitized reproduction of the confirmed transition rather than a verbatim captured transcript.

## Challenge information

| Item | Value |
| --- | --- |
| Name | Armaxis |
| Platform | Hack The Box |
| Category | Web |
| Difficulty | Very Easy |
| Status | Retired, confirmed by the owner on 5 October 2026 |
| Objective | Read the server-side flag |
| Core chain | Password-reset account takeover → admin-only Markdown file read |

The challenge provided a password-protected `Armaxis.zip` source package and two ephemeral HTTP services: the main Armaxis application and a mail inbox. The source package was inspected after the live solve. Only short relevant code excerpts appear here; the package itself is not redistributed.

## Inspecting the supplied application

The useful files in the source tree were:

```text
web_armaxis/
├── Dockerfile
├── challenge/
│   ├── database.js
│   ├── markdown.js
│   ├── routes/index.js
│   └── views/weapons.html
├── email-app/routes/index.js
└── flag.txt
```

The main application offered registration, login, a password-reset form, and a weapons page. The second service displayed an inbox for `test@email.htb`. This was not a generic mail viewer: `email-app/routes/index.js` filters messages to recipients that exactly match that address. Registering `test@email.htb` is therefore the reproducible way to receive a reset email in the visible inbox.

The database initializer seeds an administrator with a known email but a random password:

```js
await runInsertUser(
  "admin@armaxis.htb",
  `${crypto.randomBytes(69).toString("hex")}`,
  "admin",
);
```

This establishes the target account without giving us a password to guess. New registrations receive the `user` role. Both `GET` and `POST /weapons/dispatch` reject users whose authenticated role is not `admin`, so a normal account cannot directly submit a weapon note.

## Finding the password-reset mistake

Requesting a password reset creates a random token, associates it with a user ID and a one-hour expiry, then emails it to that user's address. The database table explicitly stores `user_id` alongside `token` and `expires_at`.

The final `POST /reset-password` handler retrieves a row by token, but then selects the account to update from a separate, client-controlled `email` parameter:

```js
const reset = await getPasswordReset(token);
if (!reset) return res.status(400).send("Invalid or expired token.");

const user = await getUserByEmail(email);
if (!user) return res.status(404).send("User not found.");

await updateUserPassword(user.id, newPassword);
await deletePasswordReset(token);
```

`getPasswordReset()` checks only the token and its expiry. The handler never compares `reset.user_id` with `user.id`. Consequently, possession of **any** valid reset token authorizes a password change for **any** existing email supplied in the same request. This is a broken password-recovery authorization check, not token prediction or brute force.

## Reproducing the account takeover

1. Open the main application and register `test@email.htb` with a disposable lab password.
2. Select **Forgot Password?**, request a code for `test@email.htb`, and open the separate inbox.
3. Copy the token from the password-reset email. It expires after one hour, so request a fresh one if it is rejected.
4. Send a reset request containing that token but replace the email field with the seeded administrator address.

The following command is a sanitized reproduction. Replace the placeholders with the current instance URL, a fresh token from **your** inbox, and a new lab password:

```bash
APP_URL='http://<HOST>:<APP_PORT>'
curl -sS "$APP_URL/reset-password" \
  -H 'Content-Type: application/json' \
  --data '{"token":"<YOUR_RESET_TOKEN>","newPassword":"<NEW_LAB_PASSWORD>","email":"admin@armaxis.htb"}'
```

The success response defined by the route is `Password reset successful.` The handler then deletes the token, so it is a one-use value. Log in as `admin@armaxis.htb` with the chosen new password. The server puts the account's `id` and `role` into its signed session token; the admin role unlocks **Dispatch Weapon**. The live screenshot of that form confirms this privilege transition, although the raw reset request was not captured in the retained evidence.

## Turning a Markdown image into a local file read

The dispatch handler receives `name`, `price`, `note`, and `dispatched_to`. It calls `parseMarkdown(note)` before storing the weapon. In `challenge/markdown.js`, a regular expression extracts the URL from each Markdown image and runs it through `curl`:

```js
content.replace(/\!\[.*?\]\((.*?)\)/g, (match, url) => {
    const fileContent = execSync(`curl -s ${url}`);
    const base64Content = Buffer.from(fileContent).toString('base64');
    return `<img src="data:image/*;base64,${base64Content}" alt="Embedded Image">`;
})
```

There is no URL-scheme restriction. `curl` accepts `file://` URLs, so `file:///flag.txt` reads a file in the **server container**, not on the attacker's computer. The Dockerfile places the challenge flag at `/flag.txt`.

The admin dispatch form can be completed as follows:

| Field | Value |
| --- | --- |
| Weapon Name | `Test Weapon` |
| Price | `1` |
| Note (Markdown) | `![flag](file:///flag.txt)` |
| User Email | `admin@armaxis.htb` |

Sending it to the admin account lets us read the result without changing accounts again. The application stores the parsed HTML in the weapon's `note` field. On `/weapons`, it selects records addressed to the current user's email and renders the stored note with `{{ weapon.note | safe }}`.

## Extracting and validating the result

After dispatching the weapon, open **Home** (`/weapons`). The image appears broken because text from `/flag.txt` is not an image format. That visual failure does not mean the file read failed. In Chrome DevTools, inspect the note's `<img>` element and look for an attribute shaped like:

```html
<img src="data:image/*;base64,<BASE64_DATA>" alt="Embedded Image">
```

Copy only `<BASE64_DATA>`—the text after the comma—and decode it with CyberChef's **From Base64** operation or a terminal:

```bash
printf '%s' '<BASE64_DATA>' | base64 -d
```

The screenshot from the live solve shows the Base64 data URI in the dispatched weapon's DOM, and the challenge was reported solved after decoding it. The bundled `flag.txt` contains a testing placeholder; it is not evidence of the live flag and is not reproduced here.

## Why the chain works

The two flaws cross different trust boundaries:

1. **Identity boundary:** the reset token proves control of the `test@email.htb` recovery flow, but the server applies it to an unrelated email. The stored `user_id` is ignored at the decisive point.
2. **Filesystem boundary:** an admin-supplied Markdown URL is interpreted as a server-side `curl` target. `file://` lets an otherwise ordinary image feature read local files.
3. **Output boundary:** the parser Base64-encodes arbitrary response bytes into an `<img>` tag. The weapons template marks the HTML safe, so those bytes become visible in the page source even though the browser cannot display them as an image.

The shell interpolation in ``execSync(`curl -s ${url}`)`` also creates a separate command-injection risk. The documented solve did **not** use shell metacharacters or execute an extra command: the `file://` scheme alone was sufficient. Describing this specific payload as command execution would misstate the evidence.

## Evidence limits and unneeded approaches

No brute-force attempt, token guessing, JWT forgery, or automated exploit script is supported by the retained solve record, so none is claimed. A public community walkthrough provided an early lead during the assisted solve; the mechanism, exact affected functions, flag path, and rendering behavior were subsequently checked against the supplied archive. The local code review was performed after the live flag was recovered.

## Defensive perspective

- Bind each reset token to the account it authorizes. Update the password using `reset.user_id`, or compare that value with the requested user's ID before proceeding. Consume the token in the same transaction as the update.
- Do not pass user-controlled URLs to a shell command. If remote image fetching is a requirement, use an HTTP client with an explicit `http`/`https` allowlist, destination checks, redirects policy, and size and time limits.
- Sanitize user-controlled HTML before rendering it, and avoid marking arbitrary Markdown output safe. Disabling raw HTML in Markdown is a useful defense in depth measure but does not by itself fix the server-side file read.

## Key takeaways

An unguessable recovery token is insufficient when the server fails to bind it to the intended identity. A Markdown image is also a server-side input when the application fetches it before rendering; its URL must be treated as access to the server's network and filesystem capabilities.

## References

- [Hack The Box Armaxis challenge](https://app.hackthebox.com/challenges/Armaxis)
- Supplied Armaxis source archive, inspected locally and not redistributed
- [4wayhandshake's Armaxis walkthrough](https://4wayhandshake.github.io/ctf/armaxis/), used as an initial lead; code claims above were checked against the supplied archive
