---
title: "Authenticated Connection Validation Exposes an Internal TCP Timing Oracle"
summary: "A sanitized bug bounty report documenting a repeatable timing oracle in an authenticated connection-validation workflow and the duplicate triage outcome."
findingType: "Blind SSRF / TCP reachability oracle"
severity: "Medium"
outcome: "Duplicate"
outcomeDetail: "Duplicate — Closed"
publishedAt: 2026-09-21T09:00:00Z
updatedAt: 2026-09-21T09:00:00Z
testedAt: 2026-09-19
tags:
  - "Bug Bounty"
  - "Blind SSRF"
  - "Timing Oracle"
  - "Internal Network"
  - "Responsible Disclosure"
tools:
  - "Strix"
  - "Python"
  - "HTTP client"
evidenceImage: "/images/bug-bounty/authenticated-connection-validation-timing-oracle/report-outcome.png"
evidenceAlt: "Redacted bug bounty platform screenshot showing a medium-severity report closed as duplicate"
order: 1
featured: true
draft: false
---

> **Sanitized disclosure.** The target name, domain, endpoint path, report identifier, tenant identifiers and authentication material have been removed. The timings and final triage state are preserved because they are the evidence relevant to this report.

<div class="research-state">
  <strong>Validation state:</strong> the timing difference was reproduced with authenticated requests and an unauthenticated negative control. The report was later closed as a duplicate of an earlier submission affecting the same underlying code path.
</div>

## Executive summary

An authenticated connection-validation feature accepted a user-controlled database connection URI and attempted to resolve and connect to its destination from the service's backend network position. Although every authenticated probe returned the same generic failure body, the response time changed consistently across destination ports.

The behavior created a limited blind SSRF primitive: a project user could infer destination-dependent TCP behavior inside the service environment. The test did **not** retrieve internal response content or demonstrate access to credentials, metadata, another tenant or a sensitive management interface.

| Field | Value |
| --- | --- |
| Access required | Authenticated project user |
| Input | User-controlled connection URI |
| Observable signal | Response-time difference |
| Verified impact | Internal DNS/TCP reachability inference |
| Submitted severity | Medium |
| Final program state | Duplicate — Closed |

## Affected workflow

The affected workflow was an authenticated migration or connection-checking function. The public path is intentionally withheld; the relevant request shape was equivalent to:

~~~http
POST /api/[redacted]/connection-validation
Content-Type: application/json
Authorization: Bearer [redacted]
X-Bug-Bounty: ilias1988

{
  "connection_uri": "postgres://test:test@[internal-service-name]:[port]/test"
}
~~~

Only an owned account and an owned test project were used. Request volume was limited to three samples per test case.

## Methodology

The validation used one stable internal service name and changed only the destination port. This minimized variables and made the timing comparison easier to interpret.

1. Authenticate with the dedicated bug bounty test account.
2. Submit the same connection-validation request three times for port `443`.
3. Repeat for ports `81` and `5432`, changing no other request fields.
4. Record HTTP status, normalized response-body hash and elapsed time.
5. Send the same request without authentication as a negative control.
6. Compare medians instead of relying on a single request.

## Observed evidence

| Destination variant | Samples | Median response time | Response class |
| --- | ---: | ---: | --- |
| Internal service, port `443` | 3 | **1.516 s** | Generic authenticated failure |
| Same service, port `81` | 3 | **2.495 s** | Same generic failure |
| Same service, port `5432` | 3 | **2.501 s** | Same generic failure |
| Unauthenticated control | 1 | Not applicable | **HTTP 401** |

All nine authenticated requests returned the same generic application-level failure body. The useful signal was the repeatable timing separation of approximately one second between port `443` and the two comparison ports.

## Security impact

The demonstrated impact was narrow but real: an authenticated user could use the backend as a timing oracle to classify destination-dependent TCP behavior that was not observable directly from the public internet.

This could assist internal service discovery when combined with a carefully selected list of hostnames and ports. However, this report did not establish:

- retrieval of internal HTTP or database content;
- access to cloud metadata or orchestration APIs;
- credentials, tokens or secrets;
- cross-tenant access;
- state-changing requests;
- denial of service or remote code execution.

<div class="evidence-boundary">
  <strong>Evidence boundary:</strong> timing differences support a reachability oracle, not a claim that a protected service was successfully authenticated to or that its response content was read.
</div>

## Recommended remediation

1. Parse the connection URI using a strict, scheme-aware parser before any DNS lookup or socket operation.
2. Resolve the hostname and reject loopback, link-local, private, carrier-grade NAT, multicast and otherwise reserved address ranges for both IPv4 and IPv6.
3. Revalidate every resolved address immediately before connection and after any redirect or resolution change.
4. Apply egress firewall rules so the validation worker can reach only the external destinations and ports required by the product.
5. Return constant, generic errors and enforce a uniform timeout to reduce timing and error-class side channels.
6. Add audit logging and rate limits for repeated connection checks across many hosts or ports.

## Program outcome

<div class="report-outcome">
  <strong>Duplicate — Closed.</strong> The program confirmed that an earlier researcher had reported the same timing-based SSRF behavior in the corresponding production workflow. Testing the staging deployment did not create a separate vulnerability because both environments shared the same root cause and underlying code.
</div>

This outcome is important professionally: the technical observation was reproducible, but bounty eligibility is determined by first valid report and root cause—not by being the first person to reproduce the issue in a different deployment.

## Final response evidence

The screenshot below records the final state while deliberately concealing the target and report identifier.

<img class="report-evidence-image" src="/images/bug-bounty/authenticated-connection-validation-timing-oracle/report-outcome.png" alt="Redacted bug bounty platform screenshot showing a medium-severity report closed as duplicate" loading="lazy" decoding="async" />
