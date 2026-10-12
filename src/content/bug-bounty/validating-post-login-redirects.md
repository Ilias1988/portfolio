---
title: "Validating Post-Login Redirects Without Overstating Impact"
summary: "A synthetic method for checking whether a login continuation parameter sends an authenticated user to an external site, and for separating a real redirect from an unproven phishing scenario."
kind: "technique"
findingType: "Post-login open redirect"
publishedAt: 2026-10-12T09:20:00Z
tags:
  - "Bug Bounty"
  - "Open Redirect"
  - "Authentication"
  - "Evidence Validation"
tools:
  - "Browser DevTools"
  - "HTTP inspection"
visualFrom: "LOGIN"
visualTo: "EXTERNAL"
order: 6
featured: true
draft: false
---

> **Educational example.** All hosts, paths and observations below are fictional. This is a testing method, not a disclosed vulnerability report or a claim about a live program.

## The question to answer

Applications commonly remember where a user wanted to go after authentication. If an attacker can replace that destination with an external URL, a successful login might send the user away from the trusted site. The relevant evidence is the **completed authentication flow**, including the final browser destination. A parameter that merely accepts a URL before login does not prove a post-login redirect.

## Synthetic workflow

In a lab application you own, create two disposable accounts and an external destination you control, such as `https://destination.example.test/landing`. Start a clean browser session and visit a lab-only login URL:

~~~text
https://account.example.test/sign-in?continue=https%3A%2F%2Fdestination.example.test%2Flanding
~~~

Sign in with the first test account. A hypothetical vulnerable flow would produce a redirect after the server accepts authentication:

~~~http
HTTP/1.1 302 Found
Location: https://destination.example.test/landing
~~~

The browser must actually reach the controlled external page. Preserve the Network log so the response that completes login and the later navigation can be matched. The URL and response above are fabricated examples, not captured target evidence.

## Validation sequence

1. Confirm the application and accounts are within the written testing scope. Use a destination domain that you control.
2. Record the original login URL and the redirect parameter's value. Keep authentication cookies, codes and tokens out of shared evidence.
3. Complete a normal sign-in with no custom destination as a baseline.
4. Repeat from a fresh browser session with the external destination. Record the authenticated response, its `Location` header and the final browser URL.
5. Repeat with a second disposable account or clean session to rule out a stale login state. Check whether the behavior requires a specific host, path or encoding.
6. Check whether any secret appears in the external request. If none is observed, do not claim credential or token theft.

If the application blocks the external destination, or if the browser never reaches it after authentication, report that result accurately. The mere presence of a redirect parameter is not sufficient evidence.

## Impact and evidence boundary

A demonstrated result is that an authenticated user can be sent to an attacker-controlled page. That may support a social-engineering scenario, depending on how the link is presented and what the program accepts. It does not by itself show account takeover, credential capture or a bypass of authentication.

Severity should follow the program's policy and the observed flow. A useful report states the exact precondition, the final destination and any constraints. It distinguishes the verified navigation from possible downstream abuse.

## Defensive pattern

Accept relative paths for post-login destinations, or map a short server-side identifier to an approved internal route. If external destinations are necessary, validate an exact allowlist after URL parsing and reject ambiguous encodings and scheme-relative URLs. Add a regression test that completes login with an external destination and confirms the browser remains on an approved origin.
