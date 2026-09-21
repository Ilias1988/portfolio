---
title: "Authenticated SMTP Test Function Exposes a Private-Network TCP Oracle"
summary: "A sanitized report showing how an authenticated SMTP test feature exposed loopback and RFC1918 connection states through timing and error-class differences."
findingType: "Blind SSRF / SMTP reachability oracle"
severity: "Low"
outcome: "Duplicate"
outcomeDetail: "Duplicate — Closed"
publishedAt: 2026-09-21T09:20:00Z
updatedAt: 2026-09-21T09:20:00Z
testedAt: 2026-09-19
tags:
  - "Bug Bounty"
  - "SMTP"
  - "Blind SSRF"
  - "Loopback"
  - "RFC1918"
tools:
  - "Strix"
  - "Python"
  - "HTTP client"
evidenceImage: "/images/bug-bounty/authenticated-smtp-private-network-oracle/report-outcome.png"
evidenceAlt: "Redacted bug bounty platform screenshot showing a low-severity report closed as duplicate"
order: 3
featured: true
draft: false
---

> **Sanitized disclosure.** The target, domain, endpoint, report identifier, project and branch identifiers, email addresses and authentication material have been removed. Only controlled loopback and RFC1918 measurements are retained.

<div class="research-state">
  <strong>Validation state:</strong> nine authenticated samples and one rejected-port control demonstrated distinct connection states. The program later linked the report to an earlier submission covering the same missing private-address validation.
</div>

## Executive summary

An authenticated SMTP test-email feature allowed a project administrator to choose an SMTP hostname while restricting the destination port to a small approved set. Host validation did not prevent loopback or private-network destinations. Timing and error details exposed whether the backend received an immediate connection refusal or waited for a timeout.

The result was a constrained internal TCP oracle. It did not provide SMTP banner content, email delivery, authentication material or access to another tenant.

| Field | Value |
| --- | --- |
| Access required | Authenticated project administrator |
| Input | SMTP hostname and an approved SMTP port |
| Allowed ports observed | `465`, `587`, `2525` |
| Observable signal | Timing plus normalized error class |
| Submitted severity | Low |
| Final program state | Duplicate — Closed |

## Affected workflow

The feature sent a test email using project-supplied SMTP configuration. The public endpoint is intentionally withheld; its sanitized request shape was equivalent to:

~~~http
POST /api/[redacted]/projects/{OWNED_PROJECT}/branches/{OWNED_BRANCH}/send-test-email
Content-Type: application/json
Authorization: Bearer [redacted]
X-CSRF-Token: [redacted]
X-Bug-Bounty: ilias1988

{
  "smtp_host": "127.0.0.1",
  "smtp_port": 2525,
  "recipient": "[researcher-owned-address]"
}
~~~

Only the researcher's own project, branch and email account were used. The request did not attempt SMTP authentication and no message was delivered through an internal service.

## Methodology

Three destination forms were chosen to test separate validation and connection paths:

1. Literal loopback address `127.0.0.1` on allowed port `2525`.
2. Public DNS hostname `127.0.0.1.nip.io`, which resolves to the same loopback address.
3. Unresponsive RFC1918 address `10.255.255.1` on the same port.
4. Port `25` as a negative control because it was outside the accepted SMTP port allowlist.

Each accepted destination was sampled exactly three times. Status code, elapsed time, normalized response body and resolved-address disclosure were recorded.

## Observed evidence

| Test case | Samples | Median | HTTP/result class |
| --- | ---: | ---: | --- |
| `127.0.0.1:2525` | 3 | **1.688 s** | HTTP 200, immediate `ECONNREFUSED` |
| `127.0.0.1.nip.io:2525` | 3 | **1.436 s** | HTTP 200, resolved to loopback, immediate refusal |
| `10.255.255.1:2525` | 3 | **11.514 s** | HTTP 500, connection timeout class |
| `127.0.0.1:25` control | 1 | Not applicable | HTTP 400 before connection handling |

The loopback variants returned quickly and disclosed that the resolved target refused the connection. The RFC1918 test waited for the network timeout. The disallowed-port control confirmed that the application performed port validation before opening a connection.

## Why this forms an oracle

The response distinguished at least two backend network states:

~~~text
selected host:port
├── immediate refusal → fast response + ECONNREFUSED class
└── no response       → delayed response + timeout class
~~~

An authenticated administrator could therefore test selected hosts on the three allowed ports and infer connection behavior from a network position unavailable to an external client.

## Security impact

The practical impact was limited internal network reconnaissance across administrator-selected SMTP ports. Error detail also revealed the post-resolution address and connection result, increasing the quality of the oracle.

<div class="evidence-boundary">
  <strong>Evidence boundary:</strong> the tests did not read SMTP banners, authenticate to a service, deliver email through an internal relay, access internal content, obtain credentials, reach metadata, modify state or create denial of service.
</div>

The requirement for project-administrator privileges and the fixed port allowlist reduced the attack surface, which is why the report was submitted as Low.

## Recommended remediation

1. Resolve the SMTP hostname and reject loopback, private, link-local, multicast, reserved and non-routable addresses for IPv4 and IPv6.
2. Validate the resolved address immediately before connection and prevent DNS rebinding between validation and use.
3. Restrict the SMTP worker's outbound network access to approved public destinations.
4. Remove resolved IPs and low-level socket errors from user-visible responses.
5. Use uniform timeout behavior and generic messages so refusal and timeout states are not distinguishable.
6. Rate-limit configuration tests and alert on repeated changes across multiple hostnames.

## Program outcome

<div class="report-outcome">
  <strong>Duplicate — Closed.</strong> An earlier report, submitted roughly ten hours before this one, had already demonstrated the same private/loopback validation gap and timing/error oracle. The program treated staging and production as the same vulnerability because they shared the same root cause.
</div>

The duplicate result does not change the technical evidence. It means the issue had already entered the program's remediation process before this submission arrived.

## Final response evidence

The screenshot below documents the final duplicate classification with the target and report identifier redacted.

<img class="report-evidence-image" src="/images/bug-bounty/authenticated-smtp-private-network-oracle/report-outcome.png" alt="Redacted bug bounty platform screenshot showing a low-severity report closed as duplicate" loading="lazy" decoding="async" />
