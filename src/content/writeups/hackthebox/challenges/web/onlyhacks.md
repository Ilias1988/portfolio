---
title: "Hack The Box Challenge — OnlyHacks"
summary: "OnlyHacks exposes another user's private chat through a client-controlled rid parameter. A manual IDOR test reveals the flag and shows why chat IDs need server-side authorization."
platform: "Hack The Box"
contentType: "challenge"
publicationPolicy: "retired"
challengeCategory: "Web"
difficulty: "Very Easy"
solvedAt: 2026-11-17
publishedAt: 2026-11-17
tags:
  - web-security
  - idor
  - broken-access-control
  - chat-privacy
  - html-injection
tools:
  - Web browser
  - Burp Suite
cves: []
htbUrl: "https://app.hackthebox.com/challenges/OnlyHacks"
cover: "/images/writeups/hackthebox/challenges/web/onlyhacks/cover.webp"
coverAlt: "Original illustration of dating app chat panels and an unauthorized message card unlocked across an access boundary"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up covers the retired Hack The Box Web Challenge OnlyHacks. I confirmed its presence in the **Retired** challenge list on 17 November 2026. The flag, test credentials, session cookies and temporary host addresses are omitted. No original challenge package is redistributed.

You can find more retired Hack The Box material in the [write-ups archive](/writeups/) and [Challenges archive](/writeups/challenges/).

## Executive summary

OnlyHacks is a dating-style web app with profiles, matches and private chats. The challenge asks us to identify possible impostors. My first registration attempt returned a duplicate-account message, so I considered whether that error mattered. After reaching the authenticated chat interface, I matched with Renata and sent a simple HTML tag. It rendered as markup, which showed that chat messages were not being safely displayed as text.

The decisive finding was elsewhere in the same interface: the chat URL contained a numeric `rid` parameter. My own conversation used `rid=6`. Changing it to `rid=3` opened a conversation outside my match list and displayed the flag. The verified solution was a manual **insecure direct object reference (IDOR)** test. HTML injection was observed, but JavaScript execution and session theft were not needed or performed.

## Challenge information

| Item | Value |
| --- | --- |
| Name | `OnlyHacks` |
| Category | Web |
| Difficulty | Very Easy |
| Status | Retired, checked on 17 November 2026 |
| Release date | 14 February 2025 |
| Challenge page | [Hack The Box — OnlyHacks](https://app.hackthebox.com/challenges/OnlyHacks) |
| Tested service | Ephemeral HTTP instance; host and port change when the instance restarts |

The HTB challenge page showed the description:

> Dating and matching can be exciting especially during Valentine's, but it’s important to stay vigilant for impostors. Can you help identify possible frauds?

The story is a clue to examine identity and private conversations. It does not, by itself, identify a specific vulnerable endpoint.

## Provided material and evidence boundaries

The challenge provided a live web service, not a supplied source archive in this solve. My evidence was the browser interaction, a Burp Suite registration capture, screenshots of the chat, the changed chat URL, the flag-bearing response and the HTB completion banner. The registered account's password, email, session value and the real flag are intentionally absent from this article.

There is no solver script to publish. The final exploit was a one-parameter URL change in the browser. A successful registration request was not preserved in the available transcript, so this article does not invent its HTTP response or claim that a registration bypass was necessary.

## Initial analysis: the registration error

The login page offered a sign-up link. The first captured registration request used `multipart/form-data` and included ordinary profile fields: `username`, `password`, `email`, `age`, `bio`, two gender selections and an optional `profile-picture` upload. Burp Suite recorded a `200 OK` response, but the returned HTML contained:

```html
<script>
  alert("Username or email already exists");
</script>
```

The `200` status only meant that the server returned the registration page; it did not mean the account was created. The error was consistent with a duplicate username or email, and the capture did not identify which field collided. I considered whether this was the intended vulnerability because the challenge mentions impostors, but no observed behavior connected the duplicate-account check to the flag.

Later evidence showed an authenticated Matches page, so registration was no longer the blocker. The useful lesson from this detour is to read the **response body** and subsequent browser state instead of treating a successful HTTP status as a successful application action.

## Mapping the chat interface

The Matches page listed Renata. Opening her chat gave a URL of this form:

```text
http://<HOST>:<PORT>/chat/?rid=6#last_message
```

`<HOST>:<PORT>` represents the temporary HTB instance. The `#last_message` fragment is handled by the browser and is not sent in the HTTP request. The server-relevant part is `/chat/?rid=6`.

I sent a normal `hello` message and saw a reply from Renata. Then I sent this literal message:

```html
<h1>test</h1>
```

In the chat, `test` appeared as a large heading rather than the literal characters `<h1>test</h1>`. That is direct evidence of **HTML injection**. It is not, on its own, proof that `<script>` tags execute or that another user's browser processes the message. I kept those claims separate from the verified solve.

## Identifying and exploiting the access-control weakness

The numeric `rid` looked like a reference to a chat or relationship. A community walkthrough found during research suggested checking this parameter. I then tested the idea against my own HTB instance; this was a source-assisted hypothesis followed by direct validation, not an independently discovered enumeration campaign.

While authenticated, I opened a new tab and changed only the query value:

```text
Observed conversation:  http://<HOST>:<PORT>/chat/?rid=6
Tested conversation:    http://<HOST>:<PORT>/chat/?rid=3
```

The `rid=3` page loaded a conversation that was not in my match list. Its message area contained the challenge flag, represented here as:

```text
<REDACTED_FLAG>
```

This one request crossed the relevant trust boundary. Knowing or guessing a chat identifier should not grant access to that chat. The browser was still authenticated as my own test account; only the object reference changed.

For readers reproducing the exercise, `3` was the value that worked in my instance. First record the `rid` of a chat you can legitimately open. Then try a small number of nearby values while remaining logged in. Compare the displayed participants and messages with your own Matches list. Instance data can differ, so the important technique is **changing the object ID and checking authorization**, not assuming that `3` is universal.

## Validation

The visible evidence supports the following sequence:

1. The legitimate Renata chat loaded at `rid=6` and accepted messages.
2. The `<h1>test</h1>` message rendered as a heading.
3. The manually requested `rid=3` chat loaded despite not appearing among my matches.
4. That chat displayed the flag; its value has been redacted here.
5. The HTB challenge page subsequently showed **“You have completed the OnlyHacks challenge.”**

The completion banner confirms the platform accepted the solve. The transcript does not preserve the exact flag-submission interaction, so I do not reconstruct the form request.

## What did not lead to the flag

The duplicate registration alert was a real observed response, but it was not the exploit used. Its cause was not isolated beyond the server's combined username-or-email message. Repeatedly attacking registration would have distracted from the authenticated features where the flag was stored.

The HTML rendering test was valuable because it exposed another unsafe behavior in chat. Public walkthroughs describe a stored XSS and session-hijacking route through Renata, but I did not execute JavaScript or capture anyone's cookie in this solve. Those reports informed the broader context, while the observed IDOR was sufficient to finish this instance.

## Why the IDOR works

The application accepts a client-controlled chat reference in `rid` and returns a conversation belonging to another user. From the browser evidence, the access decision appears to depend on the requested identifier without enforcing that the current user is a participant. The server-side implementation was not provided, so this is a behavioral conclusion rather than a claim about a specific line of code.

The central rule is simple: object identifiers locate data; they do not authorize access. Numeric IDs make the mistake easy to discover, but replacing them with random UUIDs would only make guessing harder. The server must check membership in the requested chat on every read and write.

The separate HTML injection observation also matters. Rendering message content as HTML can turn a private chat into a script execution surface. That risk needs output encoding or a narrowly defined sanitizer, independent of the `rid` authorization fix.

## Defensive perspective

| Observed weakness | Appropriate control |
| --- | --- |
| A user can request another chat by changing `rid` | Query the chat only after checking that the authenticated user is a participant |
| A numeric ID is treated as sufficient context | Apply object-level authorization to every chat read and message write |
| Chat text renders as HTML | Escape untrusted text at output, or sanitize against a strict allowed format |
| The registration page reports a combined duplicate error with `200 OK` | Use clear application-level success and error handling; do not infer success from HTTP status alone |

An authorization test should use two test accounts and verify that each account receives a denial when requesting the other's chat, regardless of whether the identifier is known.

## Key takeaways

- Follow the application's object references. A single query parameter can expose private data when ownership checks are missing.
- Keep evidence levels distinct: rendered HTML is not automatically proven JavaScript execution.
- Record both the failed lead and the final pivot. The duplicate-account message mattered during triage, but the verified weakness was in chat access control.
- A reproducible write-up should show the exact parameter change and observed outcome while withholding the real flag and session data.

## References

- [Hack The Box — OnlyHacks](https://app.hackthebox.com/challenges/OnlyHacks) — challenge description, category, difficulty, release date and completion status.
- [Hack The Box platform rules](https://help.hackthebox.com/en/articles/12325897-hack-the-box-platform-rules) — publication policy for retired content.
- [OnlyHacks community walkthrough by Ansh Dhingra](https://medium.com/@anshdhingra47/htb-challenge-writeup-onlyhacks-5009e218e2c0) — source-assisted `rid` hypothesis, subsequently tested in my own instance.
- [OnlyHacks walkthrough by bst04](https://bst04.hashnode.dev/htb-walkthrough-challenge-onlyhack) — alternate XSS route noted as background, not claimed as executed here.
