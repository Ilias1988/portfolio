---
title: "Hack The Box Challenge — SpeedNet"
summary: "SpeedNet chains a GraphQL profile IDOR, an exposed developer password-reset mutation and batched OTP attempts to reach an admin invoice."
platform: "Hack The Box"
contentType: "challenge"
publicationPolicy: "retired"
challengeCategory: "Web"
difficulty: "Easy"
solvedAt: 2026-11-19
publishedAt: 2026-11-19
tags:
  - web-security
  - graphql
  - idor
  - password-reset
  - two-factor-authentication
  - rate-limit-bypass
tools:
  - Web browser
  - Burp Suite
  - Python 3
cves: []
htbUrl: "https://app.hackthebox.com/challenges/SpeedNet"
cover: "/images/writeups/hackthebox/challenges/shared/hackthebox-challenge-cover.webp"
coverAlt: "Abstract cybersecurity challenge medallion with terminal, puzzle and network motifs"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents my run against the retired Hack The Box SpeedNet challenge. On 19 November 2026, its HTB page displayed **Writeup Available** and explained that write-ups unlock once content is retired. The live flag, passwords, reset tokens, OTP values, JWTs, personal account details and temporary instance address are omitted. No original challenge package is redistributed.

Browse more [Hack The Box write-ups](/writeups/) or the [retired Challenges archive](/writeups/challenges/).

## Executive summary

SpeedNet is an ISP-themed web application with registration, profiles, billing and a separate email inbox. Its browser client sends GraphQL requests to `/graphql`. After registering a test account, I found that an authenticated `userProfile(userId: Int!)` query returned another user's profile when I changed only the numeric ID. That exposed the seeded administrator's email address and showed that two-factor authentication (2FA) was enabled.

GraphQL introspection also exposed a `devForgotPassword` mutation. Unlike the normal reset flow, this developer mutation returned a valid reset token in the API response, even without an `Authorization` header. I used it to reset the administrator's password. Login then stopped at an email OTP prompt. A test inbox showed that OTPs were four digits, and later source-assisted research suggested GraphQL batching as a way to send many verification operations in one HTTP request. A Python solver performed a fresh login, tested the four-digit space in batches and used the resulting admin JWT to query invoices. The final run printed a flag-shaped value, which is redacted here.

## Challenge information and supplied service

| Item | Value |
| --- | --- |
| Name | `SpeedNet` |
| Category | Web |
| Difficulty | Easy |
| Status | Retired; checked on 19 November 2026 |
| Challenge page | [Hack The Box — SpeedNet](https://app.hackthebox.com/challenges/SpeedNet) |
| Supplied service | Ephemeral HTTP host and port, including `/emails/` |
| Test mailbox | `test@email.htb` |

The scenario directed players to find vulnerabilities in the ISP platform and retrieve a hidden flag. It explicitly supplied the `/emails/` service and `test@email.htb` address. No downloadable source package was used in this solve; the evidence came from browser pages, Burp Suite requests and responses, the test mailbox, GraphQL introspection and the final solver output. The instance address changes when the challenge restarts, so the commands below use `<HOST>:<PORT>`.

## Initial analysis: the mailbox and GraphQL traffic

I first registered using an address other than `test@email.htb`. Opening `http://<HOST>:<PORT>/emails/` showed an empty inbox headed **“Your email address is test@email.htb.”** That was expected: this inbox did not display mail for my first account. I later registered a separate test account with the designated address, and its welcome message appeared there.

On the profile page, I changed the first name to `speednet_probe_1` and clicked **Save Changes** while recording traffic in Burp Suite. The request was a GraphQL mutation:

```graphql
mutation UpdateProfile($input: ProfileInput!) {
  updateProfile(input: $input) {
    firstName
    lastName
    address
    phoneNumber
    twoFactorAuthEnabled
  }
}
```

The response returned `"firstName":"speednet_probe_1"`, confirming that `/graphql` was the active application API and that the mutation changed the profile. It did not yet identify the flag path.

## Enumerating the GraphQL schema

I sent this introspection query to `POST /graphql` in Burp Repeater:

```json
{"query":"{ __schema { queryType { fields { name } } mutationType { fields { name } } } }"}
```

The response named four queries and eight mutations:

```text
Queries:   userProfile, currentInvoice, invoiceHistory, dataUsageStats
Mutations: register, login, updateProfile, forgotPassword,
           devForgotPassword, resetPassword, verifyTwoFactor, resendOTP
```

Further introspection showed that `userProfile` requires `userId: Int!`, both password-reset request mutations require `email: String!`, and `resetPassword` requires `token: String!` and `newPassword: String!`. These signatures guided the next tests instead of relying on guessed endpoints.

## Finding the profile IDOR

The browser's ordinary profile request queried `userProfile` with `userId: 3`, the ID of my controlled test account. Using the same authenticated request in Repeater, I changed only the variable to `1`:

```json
{
  "query": "query GetUserProfile($userId: Int!) { userProfile(userId: $userId) { id email firstName lastName twoFactorAuthEnabled } }",
  "variables": { "userId": 1 }
}
```

The response returned user ID `1`, email `admin@speednet.htb` and `twoFactorAuthEnabled: true`. Without an `Authorization` header, the same query returned `Not authenticated`. The server therefore checked whether a request had a session, but did not restrict this read to the session's own user ID. This was an **insecure direct object reference (IDOR)** that supplied the administrator's email for the next stage.

## Comparing normal and developer password reset

Before creating the `test@email.htb` account, I tried the normal reset mutation for that address:

```json
{"query":"mutation { forgotPassword(email: \"test@email.htb\") }"}
```

It returned `User not found`, explaining why the mailbox had no reset mail. After I registered the test account, the normal reset flow sent a link to `/emails/`. It did not put the token directly in the GraphQL response.

The developer mutation behaved differently:

```json
{"query":"mutation { devForgotPassword(email: \"test@email.htb\") }"}
```

Its response contained:

```text
Dev only! Password reset token: <REDACTED_RESET_TOKEN>
```

I repeated this controlled-account test without the `Authorization` header and received another token. That confirmed the developer mutation was callable without a logged-in session. Using the email learned from the IDOR, I then called `devForgotPassword(email: "admin@speednet.htb")`; it returned a reset token for the admin account as well.

The reset mutation accepted that token and a new lab password:

```json
{
  "query": "mutation Reset($token: String!, $newPassword: String!) { resetPassword(token: $token, newPassword: $newPassword) }",
  "variables": {
    "token": "<REDACTED_RESET_TOKEN>",
    "newPassword": "<NEW_LAB_PASSWORD>"
  }
}
```

The server answered `Password has been reset successfully`. The actual token and password are not needed to understand the flaw; on a fresh instance, use the token returned for that instance and choose a unique lab password.

## The 2FA barrier and the tested alternatives

Logging in as `admin@speednet.htb` with the newly chosen password did not create an authenticated admin session. The GraphQL `login` response contained an error in this form:

```text
2FA_REQUIRED:<REDACTED_2FA_TOKEN>
```

The browser opened `/2fa` and asked for an OTP sent to the admin email. This value is a temporary 2FA challenge token, distinct from the password-reset token and the final JWT.

I enabled 2FA on my `test@email.htb` account, logged in again and observed a four-digit code in the supplied inbox. An OTP attempt on the admin form returned **“Verification failed: Invalid or expired OTP.”** The retained screenshot of the entered code differs from the earlier mailbox screenshot, and no matching newer email was preserved. This failed attempt therefore does **not** establish whether codes are bound to accounts or whether the entered value was simply wrong or expired.

I also inspected `ProfileInput`. It contained `firstName`, `lastName`, `address`, `phoneNumber` and `twoFactorAuthEnabled`, but no `userId` or `email`. The available schema gave no direct way to target the admin's 2FA toggle through that mutation. I did not claim a successful 2FA change.

## Batching OTP attempts

At this point I consulted two community solutions, cited below. They suggested that the GraphQL endpoint accepts an **array of operations** in one HTTP request and that this can bypass a limit applied to requests rather than individual OTP checks. This was a source-assisted lead, subsequently confirmed by the successful local solve; it was not an independently discovered server implementation detail.

The same temporary 2FA token can be supplied to several `verifyTwoFactor` operations in a JSON array. A minimal illustrative batch looks like this:

```json
[
  {"query":"mutation($token:String!,$otp:String!){verifyTwoFactor(token:$token,otp:$otp){token}}","variables":{"token":"<FRESH_2FA_TOKEN>","otp":"0000"}},
  {"query":"mutation($token:String!,$otp:String!){verifyTwoFactor(token:$token,otp:$otp){token}}","variables":{"token":"<FRESH_2FA_TOKEN>","otp":"0001"}}
]
```

The verified solver sends 200 four-digit guesses per HTTP request, waits one second between batches, and stops as soon as a response contains `data.verifyTwoFactor.token`. It covers `0000` through `9999`, including leading zeroes. It performs a fresh admin login first, so the short-lived 2FA challenge token does not have to be copied from Burp.

Download the [sanitized Python 3 solver](/files/writeups/hackthebox/challenges/web/speednet/solve_speednet.py). Edit its `URL` setting to the host and port shown in your current HTB instance, then run:

```bash
python3 solve_speednet.py
```

The script asks for the admin password using `getpass`, finds the valid OTP, keeps the resulting JWT in memory, introspects the scalar fields of the `Invoice` type, queries `currentInvoice` and `invoiceHistory`, and searches those responses for an `HTB{...}` value. It uses only Python's standard library. Do not paste the password or JWT into a public issue or write-up.

## Solver validation and the authentication-header correction

The first solver version found a valid OTP, but its subsequent invoice queries both returned `Not authenticated`. The mistake was in **my client code**: it sent `Authorization: Bearer <JWT>`. Earlier successful browser traffic showed that SpeedNet expects the raw JWT in the header:

```http
Authorization: <JWT>
```

After changing the script to send the token without the `Bearer ` prefix, I ran it again. The retained terminal output shows the decisive transitions, with temporary values and the flag redacted:

```text
Fresh admin 2FA challenge received.
Testing 0000–0199
...
Admin OTP found: <REDACTED_OTP>
Admin JWT kept in memory for the invoice query.
Flag: <REDACTED_FLAG>
```

This confirms the corrected solver reached an authenticated invoice response containing the flag. The retained output prints only the flag value, not the containing JSON field. A community solution identifies the invoice number as the field, but I do not present that field-level detail as independently observed in my terminal output. The HTB challenge page later displayed **“User Owns Flag.”**

## Why the chain works

Each stage crosses a separate boundary:

1. **Object authorization:** `userProfile(userId: 1)` exposes the admin's email to a different authenticated user. Authentication alone is not authorization for that profile.
2. **Password recovery:** `devForgotPassword` returns a valid reset token to the caller rather than delivering it only to the account owner, and it works without a session.
3. **2FA verification:** GraphQL batching lets the client submit many `verifyTwoFactor` operations per HTTP request. The successful run demonstrates that the effective limit did not prevent searching the four-digit space before the challenge expired.
4. **Session use:** A valid OTP returns a JWT. The app expects that JWT as the raw `Authorization` value; using the common `Bearer` convention caused a real failure until the request matched the application's observed format.

The profile IDOR alone did not reveal the flag, and password reset alone did not bypass 2FA. The solve required the complete chain.

## Defensive perspective

| Observed behavior | Defensive control |
| --- | --- |
| `userProfile` accepts another user's ID under a valid session | Check object ownership or an explicit admin permission for every profile read |
| `devForgotPassword` exposes reset tokens | Remove developer-only mutations from production; deliver reset links only to the verified account mailbox |
| OTP attempts can be packed into GraphQL batches | Limit verification attempts per account and challenge token, not only per HTTP request; count every operation inside a batch |
| Four-digit OTP space can be exhausted quickly | Use short expiry together with attempt limits and invalidation, rather than expiry alone |
| Client and server disagree with a standard `Bearer` assumption | Document and consistently enforce the intended authentication-header format |

The response to an invalid OTP should also avoid revealing whether a user exists or which part of authentication failed. Monitoring should count failed OTP operations, including those inside a single batched request.

## Key takeaways

- GraphQL introspection can reveal unexpected production operations, but the exploitability came from their behavior, not from introspection itself.
- An IDOR can be an information-gathering stage in a larger account-takeover chain.
- Rate limits must be applied to the underlying security action. A single HTTP request can contain many GraphQL operations.
- Preserve failed results in a write-up when they explain a pivot. Here, the initial empty inbox, the rejected 2FA attempt and the incorrect `Bearer` header all changed the next test.
- Keep the evidence boundary clear: the final solver run proved a flag in invoice data; the exact invoice field was not retained in the local output.

## References

- [Hack The Box — SpeedNet](https://app.hackthebox.com/challenges/SpeedNet) — scenario, category, difficulty, retirement indicator and completion state.
- [Hack The Box write-up and streaming guidelines](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines) — public solutions are for retired content.
- [Kholoud Ahmed's SpeedNet write-up](https://medium.com/@kholoudahmed305/htb-challenge-speednet-ddfa9cc3e7be) — source-assisted batching hypothesis and invoice-number context.
- [Sahand Babali's SpeedNet write-up](https://medium.com/@sahand.babali/htb-challenge-writeup-speednet-d6899aa4b172) and [solver repository](https://github.com/sahandbabali/Hack-The-Box---SpeedNet) — corroborating batching approach; my published Python solver was written and validated against my own run.
