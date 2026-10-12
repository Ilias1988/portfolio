---
title: "Tracing Password-Reset Secrets into Telemetry Requests"
summary: "A synthetic workflow for checking whether a reset token in a page URL is copied into outbound telemetry, with controls that keep observation separate from account-takeover claims."
kind: "technique"
findingType: "Recovery-token exposure / browser telemetry"
publishedAt: 2026-10-12T09:00:00Z
tags:
  - "Bug Bounty"
  - "Password Reset"
  - "Token Exposure"
  - "Browser Telemetry"
  - "Evidence Validation"
tools:
  - "Browser DevTools"
  - "HAR analysis"
  - "SHA-256"
visualFrom: "RESET"
visualTo: "METRICS"
order: 4
featured: true
draft: false
---

> **Educational example.** The application, token and network records below are fictional. This guide describes a general testing method; it is not a disclosed program report or evidence of a particular organization's vulnerability.

## The question to answer

A password-reset link often carries a bearer secret in its URL. The key question is whether the browser or application copies that secret into a request sent to a separate telemetry service before the URL is cleaned.

Finding a token in the address bar is only a starting signal. A report needs the actual outbound request, a reliable comparison of values and a clear explanation of who could access the receiving service. A successful password change or account takeover is a separate claim requiring separate proof.

## Synthetic workflow

Imagine an application you own at `https://account.example.test`. A disposable account receives this lab-only link:

~~~text
https://account.example.test/reset?token=LAB-RESET-7B3C
~~~

With the browser Network panel open and **Preserve log** enabled, the reset page is loaded once. The fictional records look like this:

~~~http
GET /reset?token=LAB-RESET-7B3C HTTP/1.1
Host: account.example.test

HTTP/1.1 200 OK
~~~

~~~http
POST /collect HTTP/1.1
Host: telemetry.example.test
Content-Type: application/json

{"page_url":"https://account.example.test/reset?token=LAB-RESET-7B3C"}
~~~

The second record would show the secret crossing from the reset application to a different recipient. The hostname and marker above are placeholders; they are not retained records from a live program.

## Validation sequence

1. Use only a disposable account that you control, within the target's written testing rules.
2. Capture the first-party reset request and all outbound requests from the same page load.
3. Search URL parameters, POST bodies and custom telemetry fields. Checking only the `Referer` header misses explicit copies of the page URL.
4. Compare the complete token value locally. A SHA-256 digest can correlate records while keeping the token out of a report. A short digest prefix is useful for presentation but is not a substitute for checking full equality during analysis.
5. Repeat with a fresh lab token in a clean browser profile. Also load a reset page without a token as a negative control.
6. Record destination host, request method, relevant field, timestamp and response status. Redact the token before attaching evidence.

If the telemetry request is produced by your own browser, that proves delivery to its configured destination. It does **not** prove that an attacker can access the telemetry account, that the token remains usable, or that the reset flow permits password modification without another check.

## Impact and evidence boundary

The direct finding would be **disclosure of a recovery secret to the telemetry recipient**. The practical severity depends on token lifetime, single-use behavior, recipient access, retention and any extra verification required before a password change.

Phrase the conclusion narrowly: “A reset token was copied into an outbound telemetry request.” Do not write “account takeover” unless a controlled end-to-end test on an owned account demonstrates that result under the program's rules.

## Defensive pattern

Exchange the URL token for a short-lived server-side reset session before loading third-party code, then redirect the browser to a clean URL. Strip sensitive query values from every telemetry field and test that a synthetic marker never reaches another origin.
