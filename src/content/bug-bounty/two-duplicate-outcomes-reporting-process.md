---
title: "Two Bug Bounty Reports, Two Duplicate Outcomes"
summary: "A private-program reporting case study on evidence discipline, duplicate triage and the limits of what a public portfolio can claim."
kind: "process"
findingType: "Responsible disclosure process"
outcome: "Duplicate"
outcomeDetail: "Two reports — Duplicate (Closed)"
publishedAt: 2026-10-13T12:00:00Z
tags:
  - "Bug Bounty"
  - "Responsible Disclosure"
  - "Triage"
  - "Evidence Boundaries"
visualFrom: "REPORT"
visualTo: "TRIAGE"
order: 7
featured: true
draft: false
---

> **Publication boundary.** Both source reports are private. This case study names no company, target, domain, endpoint, report identifier, tenant or technical exploit detail. It describes the reporting process and final status only. No program-approved vulnerability disclosure is claimed.

## What I did

I investigated two separate observations during authorized bug bounty testing. For each, I checked the applicable scope, used researcher-controlled data, recorded a baseline and the changed behavior, and prepared a standalone report with reproducible evidence, limitations and a remediation recommendation. I removed credentials, tokens and personal data before submission.

The private reports contain the specific requests, responses and technical analysis. Those details are intentionally absent here because the reports have not been approved for public disclosure.

## Triage outcome

The platform closed **both submissions as Duplicate** of earlier reports. The triage response said the first matched a previously reported underlying issue. The second was also matched to an earlier report of the same underlying issue. This status means the work was not first to report. It does not establish a bounty, credit for the original discovery, or public permission to release the technical findings.

<div class="outcome-illustrations">
  <figure>
    <img src="/images/bug-bounty/duplicate-outcomes/report-a.png" alt="Anonymized illustration showing Report A closed as Duplicate" width="1852" height="849" loading="lazy" decoding="async" />
    <figcaption>Report A: Duplicate (Closed). Anonymized illustration, not the original screenshot.</figcaption>
  </figure>
  <figure>
    <img src="/images/bug-bounty/duplicate-outcomes/report-b.png" alt="Anonymized illustration showing Report B closed as Duplicate" width="1853" height="849" loading="lazy" decoding="async" />
    <figcaption>Report B: Duplicate (Closed). Anonymized illustration, not the original screenshot.</figcaption>
  </figure>
</div>

## Evidence and impact boundaries

The original evidence was gathered with low-volume checks against researcher-controlled records. The public article cannot independently demonstrate the affected behavior, its security impact or its reproduction steps without exposing private report details. I therefore make **no public severity, CVSS or CWE claim** for either submission. I did not demonstrate access to another person's data or a production business outcome.

The two graphics above are privacy-safe visual reconstructions of the closed status shown in private screenshots. They are not raw platform evidence. The status is also supported by the private triage messages retained outside this site.

## What I learned

Duplicate triage is a useful research signal, but it is a reporting outcome rather than a newly accepted finding. The practical improvement is to record a precise root cause, state exactly what the controlled test proved, and stop before extrapolating to untested impact. When several observations point to one underlying weakness, I should compare them before filing separate reports. When they are genuinely separate, each report needs its own clear reproduction path.

For future submissions I will prioritize less-explored in-scope workflows, keep evidence tied to owned accounts and check public program guidance before testing. I will continue to separate observed behavior from hypothetical impact and publish technical details only after the program authorizes disclosure.

## Remediation and disclosure

The private reports included finding-specific remediation. Those details are withheld here. In general, security fixes should be enforced at the server boundary and verified with regression tests for the affected workflow. This article records the final triage outcome accurately: **two private reports, both closed as Duplicate, no claim of bounty or original discovery**.
