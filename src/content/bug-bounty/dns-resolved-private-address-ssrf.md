---
title: "DNS-Resolved Private Address Bypass in a Server-Side JWKS Fetcher"
summary: "A controlled callback and timing analysis showed that a hostname resolving to RFC1918 space reached a backend fetch stage, with impact limited to blind reconnaissance."
findingType: "Blind SSRF / DNS validation bypass"
severity: "Medium"
outcome: "Informative"
outcomeDetail: "Informative — Closed"
publishedAt: 2026-09-21T09:10:00Z
updatedAt: 2026-09-21T09:10:00Z
testedAt: 2026-09-19
tags:
  - "Bug Bounty"
  - "SSRF"
  - "DNS Resolution"
  - "JWKS"
  - "Egress Validation"
tools:
  - "Strix"
  - "Controlled callback server"
  - "HTTP client"
evidenceImage: "/images/bug-bounty/dns-resolved-private-address-ssrf/report-outcome.png"
evidenceAlt: "Redacted bug bounty platform screenshot showing a medium-severity report closed as informative"
order: 2
featured: true
draft: false
---

> **Sanitized disclosure.** The organization, domain, endpoint path, report identifier, project identifiers and authentication material are withheld. The article documents only the minimum technical behavior needed to explain the finding and its triage outcome.

<div class="research-state">
  <strong>Validation state:</strong> a researcher-controlled callback confirmed a backend HTTP fetch. A comparison between a literal RFC1918 address and a hostname resolving to the same address demonstrated inconsistent destination validation.
</div>

## Executive summary

An authenticated project configuration endpoint accepted a URL for retrieving a JSON Web Key Set (JWKS). A controlled public callback proved that the application fetched this URL from the backend. Direct use of a private IPv4 literal was rejected quickly, but a public hostname resolving to the same RFC1918 address reached a later network stage and timed out after a much longer interval.

This was a resolution-aware validation bypass and a blind SSRF primitive. The confirmed impact was limited to destination reachability inference: no internal response body, credential, token, metadata document or state-changing action was obtained.

| Field | Value |
| --- | --- |
| Access required | Authenticated project user |
| Input | User-controlled JWKS URL |
| Backend request proven | Yes, through controlled callback |
| Validation difference | Literal private IP vs DNS-resolved private IP |
| Submitted severity | Medium |
| Final program state | Informative — Closed |

## Affected workflow

The feature allowed an authenticated user to configure a remote JWKS location for an owned project. The exact endpoint is omitted; the sanitized request shape was:

~~~http
POST /api/[redacted]/projects/{OWNED_PROJECT}/jwks
Content-Type: application/json
Authorization: Bearer [redacted]
X-Bug-Bounty: ilias1988

{
  "jwks_url": "https://[researcher-controlled-host]/jwks-ssrf-revalidation"
}
~~~

The callback server observed a backend `GET` request to the unique path. Headers were sanitized before evidence was retained.

## Validation sequence

### 1. Prove the server-side fetch

A unique HTTPS URL on a researcher-controlled server was submitted. The callback received the expected request, proving that the target backend—not the browser—resolved and fetched the supplied URL.

### 2. Establish the literal-IP control

The URL was changed to a literal RFC1918 address:

~~~text
https://10.255.255.1/ssrf-validation
~~~

The request failed quickly with an `invalid JWKS URL` class of response, consistent with input validation blocking a directly visible private address.

### 3. Test resolution-aware validation

The private address was represented by a public hostname that resolved to the same RFC1918 address:

~~~text
https://10.255.255.1.sslip.io/ssrf-validation
~~~

This variant produced a different error class and remained active until the backend connection timeout, indicating that validation occurred before—or without correctly evaluating—the resolved destination.

## Observed evidence

Exactly three samples were collected for each private-address variant.

| Variant | Median response time | Response class |
| --- | ---: | --- |
| Literal `10.255.255.1` | **1.486 s** | Invalid URL validation error |
| DNS hostname resolving to `10.255.255.1` | **16.283 s** | Backend fetch/timeout error |
| Difference between medians | **14.797 s** | Destination-dependent behavior |

All private-address responses used `HTTP 400`; the distinction came from normalized error class and elapsed time. No additional hosts, redirect chains, metadata endpoints or internal services were probed.

## Root cause analysis

The most plausible explanation is that the application validated the URL's textual hostname but did not apply the same policy to every resolved IP address before opening the outbound connection. A hostname can appear public at parsing time while DNS resolves it into a private or loopback range.

This is a common SSRF defense gap because secure handling must cover the complete lifecycle:

~~~text
parse URL → validate scheme → resolve DNS → validate every IP → connect only to that validated IP
~~~

Validation must also be repeated after redirects and protected against DNS rebinding or address changes between validation and connection.

## Security impact

The verified capability was an authenticated blind network oracle from the backend's network position. It could potentially help classify whether a selected internal destination caused immediate rejection or a connection timeout.

<div class="evidence-boundary">
  <strong>Evidence boundary:</strong> this research did not show internal content access, cloud metadata extraction, Kubernetes API access, credentials, authentication bypass, another tenant's data, state change, denial of service or code execution.
</div>

Because the feature required a valid project user and returned no internal response content, its practical impact remained reconnaissance-only in the submitted evidence.

## Recommended remediation

1. Allow only `https` and reject URLs containing credentials, ambiguous encodings or non-canonical host representations.
2. Resolve the hostname server-side and reject every loopback, private, link-local, multicast, reserved and non-routable IPv4/IPv6 result.
3. Connect to the validated address rather than resolving the hostname again after validation.
4. Repeat destination validation for every redirect and limit the number of redirects.
5. Enforce outbound network policy so the fetcher cannot reach metadata, orchestration, management or tenant networks.
6. Use short uniform timeouts and generic errors to reduce reachability side channels.

## Program outcome

<div class="report-outcome">
  <strong>Informative — Closed.</strong> The program acknowledged the DNS-based private-address bypass and timing behavior but required demonstrable impact beyond outbound connection attempts. Without internal data, credentials, metadata or access to a sensitive service, the blind SSRF did not meet its acceptance threshold.
</div>

The result illustrates a central bug bounty lesson: a technically valid security primitive can still be non-bounty-eligible when the program's policy requires a proven downstream consequence.

## Final response evidence

The screenshot below records the final informative classification. The target and report identifier have been manually redacted.

<img class="report-evidence-image" src="/images/bug-bounty/dns-resolved-private-address-ssrf/report-outcome.png" alt="Redacted bug bounty platform screenshot showing a medium-severity report closed as informative" loading="lazy" decoding="async" />
