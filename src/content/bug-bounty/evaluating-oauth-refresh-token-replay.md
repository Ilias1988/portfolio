---
title: "Evaluating Refresh-Token Replay in a Public OAuth Client"
summary: "A synthetic test plan for distinguishing a repeated refresh response from an independently usable token, with controls for client type, resource access and token binding."
kind: "technique"
findingType: "OAuth refresh-token replay assessment"
publishedAt: 2026-10-12T09:05:00Z
tags:
  - "Bug Bounty"
  - "OAuth"
  - "Refresh Tokens"
  - "Public Clients"
  - "Replay Testing"
tools:
  - "HTTP client"
  - "OAuth test application"
  - "Token redaction"
visualFrom: "REFRESH"
visualTo: "REPLAY"
order: 5
featured: true
draft: false
---

> **Educational example.** The client, grant and responses below are synthetic. This is a test design for an application you own or are authorized to assess, not a claim about a live program or its triage outcome.

## Establish the client model first

Refresh-token behavior depends on whether the OAuth client is public or confidential and on the protection chosen by the authorization server. A public client may have no client secret. The security question is whether a copied refresh token can be replayed by an independent holder after legitimate use.

[RFC 9700, sections 2.2.2 and 4.14.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2) describes two protections for public clients: sender-constraining the refresh token or rotating it so replay can be detected. A repeated successful response is a useful signal, but it should be assessed together with the actual client model and any sender-binding mechanism.

## Synthetic test sequence

Use a disposable account and an OAuth client you control. Request only the smallest read-only scope required for the test. After an authorization-code flow with PKCE, store the issued refresh token only in local test memory.

~~~text
Client A receives: refresh_token = LAB_REFRESH_1
Client A exchanges LAB_REFRESH_1 -> access_token = LAB_ACCESS_A
Client B exchanges LAB_REFRESH_1 -> access_token = LAB_ACCESS_B
~~~

The decisive checks happen after these exchanges:

1. Confirm that Client B is genuinely independent: separate process or device context, no shared cookie jar, client secret, certificate or proof-of-possession key.
2. Record whether the first refresh issued a replacement refresh token. If it did, test the old value rather than accidentally using the replacement.
3. Send each returned access token to a read-only resource endpoint on the **same owned account**. A token endpoint response alone does not prove that the new token authorizes API access.
4. Send an intentionally invalid refresh token as a negative control and confirm rejection.
5. If the program permits it, revoke the test grant and verify that subsequent refreshes fail. End the test and destroy local token copies.

For a real assessment, redact bearer values in every HTTP transcript. Use local hashes or stable labels to correlate requests, and state exactly which controls were and were not run.

## What the result would mean

If an independent Client B can exchange the copied token and use the resulting access token after Client A has already used it, the test supports a replay concern. The demonstrated impact is limited to the granted scopes and the API operations actually confirmed.

If both “clients” are merely new HTTP sessions in one process on the same host, the result is narrower. A server may bind tokens to a property shared by those sessions. Likewise, the test does not prove that an attacker can obtain a victim's refresh token. Token acquisition is a separate prerequisite.

Do not describe a read-only project-list response as account takeover or cross-tenant access. Those outcomes require additional, permitted evidence.

## Defensive pattern

For a public client, rotate refresh tokens with reuse detection or bind them cryptographically to a client instance. Keep scopes narrow, support revocation and expiry, and test that an old token cannot mint another usable access token after rotation.
