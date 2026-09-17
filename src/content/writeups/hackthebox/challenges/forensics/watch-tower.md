---
title: "Hack The Box Challenge — Watch Tower"
summary: "A Modbus/TCP packet capture hides an encoded message in register addresses, demonstrating how protocol metadata can become a covert data channel."
platform: "Hack The Box"
contentType: "challenge"
publicationPolicy: "retired"
challengeCategory: "Forensics"
difficulty: "Very Easy"
solvedAt: 2026-09-17
publishedAt: 2026-09-17
tags:
  - network-forensics
  - ics-security
  - modbus-tcp
  - pcap-analysis
  - protocol-analysis
  - covert-channel
tools:
  - TShark
  - capinfos
  - awk
cves: []
htbUrl: "https://app.hackthebox.com/challenges/Watch%2520Tower"
cover: "/images/writeups/hackthebox/challenges/shared/hackthebox-challenge-cover.webp"
coverAlt: "Abstract cybersecurity challenge medallion with terminal, puzzle and network motifs"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents the retired Hack The Box Challenge Watch Tower. Its retired status was explicitly reconfirmed before publication on 17 September 2026. The flag, personal information and unrelated sensitive artifacts have been removed. The original challenge archive and packet capture are not redistributed.

The rest of my published Hack The Box material is available in the [write-ups archive](/writeups/) and the focused [Challenges archive](/writeups/challenges/).

## Executive summary

Watch Tower provides a short packet capture from an industrial-control-system network and asks what an intruder collected and altered. Protocol enumeration showed that every captured packet belonged to one Modbus/TCP conversation between a client and a server on TCP port 502. The client's requests consisted of coil reads plus two types of write operation: one Write Multiple Coils request and 57 Write Multiple Registers requests.

The register values initially looked like the obvious place to search for embedded text, but they were mostly non-printable when interpreted as character codes. The useful signal was instead the `Reference Number` field: every one of the 57 register addresses fell inside the printable ASCII range. Preserving their packet order and converting those decimal addresses to characters exposed a noise-wrapped `HTB{...}` token. The actual token is redacted below.

The challenge is officially categorized by Hack The Box as **ICS**. This site currently groups it under **Forensics** because the task is solved entirely through network-capture analysis and Forensics is the closest supported portfolio category.

## Challenge information

| Item | Value |
| --- | --- |
| Name | `Watch Tower` |
| Platform | Hack The Box |
| HTB category | ICS |
| Portfolio category | Forensics |
| Difficulty | Very Easy |
| Status | Retired, reconfirmed 17 September 2026 |
| Released | 4 August 2023 |
| Supplied evidence | `tower_logs.pcapng` inside the challenge archive |

The scenario states that infrastructure monitoring detected abnormal behavior and initiated a network capture. The investigation therefore had two linked objectives: identify what the suspicious client read and determine how it altered the industrial protocol state.

## Provided material and evidence boundaries

The supplied archive contained a single useful evidence file:

```text
tower_logs.pcapng
```

The PCAPNG and original ZIP remain local and are not included in this public repository. `capinfos` recorded the following evidence metadata:

```text
File type:           Wireshark/... - pcapng
File encapsulation:  Ethernet
Number of packets:   420
File size:           47 kB
Data size:           32 kB
Capture duration:    2.002483116 seconds
Earliest packet time: 2023-08-03 17:02:23.206826857
Latest packet time:   2023-08-03 17:02:25.209309973
SHA256:              6c3746b4ba3bff6745f5ebcf49aec25df494f369b6992fe6e04cdcaafa987d7d
Strict time order:   True
```

These details established that the capture was small, chronologically ordered and suitable for complete request-by-request inspection. The SHA-256 value identifies the analyzed evidence without redistributing it.

## Initial protocol analysis

### Enumerating the protocol hierarchy

The first useful question was whether the capture mixed several protocols or contained one narrow conversation. TShark's protocol hierarchy answered that directly:

```bash
tshark -r tower_logs.pcapng -q -z io,phs
```

The relevant output was:

```text
frame                                    frames:420 bytes:32749
  eth                                    frames:420 bytes:32749
    ip                                   frames:420 bytes:32749
      tcp                                frames:420 bytes:32749
        mbtcp                            frames:420 bytes:32749
          modbus                         frames:420 bytes:32749
```

All 420 packets were decoded as Modbus/TCP. That removed the need to hunt through unrelated DNS, HTTP or file-transfer traffic and made Modbus fields the main evidence source.

### Identifying the communicating endpoints

The IP endpoint and TCP conversation statistics were collected next:

```bash
tshark -r tower_logs.pcapng -q -z endpoints,ip
tshark -r tower_logs.pcapng -q -z conv,tcp
tshark -r tower_logs.pcapng -q -z conv,udp
```

Only two IPv4 endpoints appeared:

```text
192.168.1.150    420 packets
192.168.1.252    420 packets
```

The entire capture belonged to one TCP conversation:

```text
192.168.1.150:46608 <-> 192.168.1.252:502
420 frames, 32 kB, duration 2.0025 seconds
```

TCP port 502 identified `192.168.1.252` as the Modbus/TCP server side. The ephemeral source port `46608` and the request direction identified `192.168.1.150` as the client issuing the suspicious operations. There was no UDP traffic.

## Classifying the Modbus operations

Rather than reading all 420 packets manually, I counted the function codes sent by the client:

```bash
tshark -r tower_logs.pcapng \
  -Y 'ip.src == 192.168.1.150' \
  -T fields -e modbus.func_code |
sort | uniq -c
```

The result was concise:

```text
152 1
  1 15
 57 16
```

These codes divided the activity into collection and modification:

| Function code | Operation | Observed count | Investigative meaning |
| --- | --- | ---: | --- |
| `1` | Read Coils | 152 | The client queried coil state |
| `15` | Write Multiple Coils | 1 | The client changed multiple coil values |
| `16` | Write Multiple Registers | 57 | The client repeatedly changed holding registers |

The capture therefore matched both parts of the scenario. Function 1 represented the information-gathering activity, while Functions 15 and 16 showed state-changing operations.

To preserve chronology, I also displayed every client request with its frame number, relative timestamp and Wireshark Info column:

```bash
tshark -r tower_logs.pcapng \
  -Y 'ip.src == 192.168.1.150' \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e modbus.func_code \
  -e _ws.col.Info
```

The first request was the single Function 15 write. A sequence of Function 1 reads followed, then frames 107 through 219 contained the 57 Function 16 requests, after which the client returned to reading coils. That long, contiguous write sequence was the strongest candidate for an encoded modification.

## Inspecting the write structure

The write-only filter confirmed the relevant frames:

```bash
tshark -r tower_logs.pcapng \
  -Y 'ip.src == 192.168.1.150 && (modbus.func_code == 5 || modbus.func_code == 6 || modbus.func_code == 15 || modbus.func_code == 16)' \
  -T fields \
  -e frame.number \
  -e modbus.func_code \
  -e _ws.col.Info
```

The output began with frame 1 as `Write Multiple Coils`, followed by the Function 16 sequence beginning at frame 107.

### The initial coil modification

Verbose inspection of frame 1 showed:

```bash
tshark -r tower_logs.pcapng -Y 'frame.number == 1' -V
```

```text
Function Code: Write Multiple Coils (15)
Reference Number: 1
Bit Count: 21
Byte Count: 3
```

The request explicitly altered 21 coils beginning at reference 1. This established that the client was not merely monitoring the device, although the later register sequence carried the recoverable challenge token.

### A representative register write

I then inspected the first Function 16 request in both decoded and hexadecimal form:

```bash
tshark -r tower_logs.pcapng -Y 'frame.number == 107' -V
tshark -r tower_logs.pcapng -Y 'frame.number == 107' -x
```

The decoded Modbus section was:

```text
Function Code: Write Multiple Registers (16)
Reference Number: 52
Word Count: 1
Byte Count: 2
Register 52 (UINT16): 6
```

Every Function 16 request wrote exactly one 16-bit register. Each packet therefore contributed two values worth comparing:

- the target register address in `modbus.reference_num`;
- the written value in `modbus.regval_uint16`.

## Finding the encoded channel

The two fields were extracted from all 57 Function 16 requests while retaining capture order:

```bash
tshark -r tower_logs.pcapng \
  -Y 'ip.src == 192.168.1.150 && modbus.func_code == 16' \
  -T fields \
  -E header=y \
  -e frame.number \
  -e modbus.reference_num \
  -e modbus.regval_uint16 |
tee register_writes.tsv
```

The beginning of the table looked like this:

```text
frame.number  modbus.reference_num  modbus.regval_uint16
107           52                    6
109           76                    85
111           82                    153
113           48                    151
```

The written values ranged across printable and non-printable values and did not form useful direct ASCII. The register references were different: all 57 addresses fell between decimal 33 and 125, exactly the printable ASCII region used by punctuation, digits and letters.

That observation changed the interpretation of the sequence. The addresses were not just locations being modified; their ordered numeric values were functioning as character codes. A few isolated conversions illustrate the pattern without exposing the final token:

```text
72  -> H
84  -> T
66  -> B
123 -> {
125 -> }
```

This is the central trick in Watch Tower: the meaningful message is carried in protocol metadata rather than the register data field that attracts attention first.

## Minimal extraction pipeline

Because the TSV rows were already ordered by frame number, a short `awk` expression was sufficient. It skipped the header and printed the second column as characters:

```bash
awk 'NR > 1 {printf "%c", $2} END {print ""}' register_writes.tsv
```

The sanitized result was:

```text
<PREFIX_NOISE>-HTB{<REDACTED_FLAG>}-<SUFFIX_NOISE>
```

The random-looking prefix and suffix explain why decoding the complete stream, rather than assuming its first character began the answer, mattered. The bounded substring beginning with `HTB{` and ending at the matching `}` was the challenge answer. It is intentionally omitted from this public write-up.

No standalone solver script was necessary: TShark performed the field extraction and `awk` performed the only required decimal-to-character conversion.

## Validation

The recovered candidate was validated through several mutually reinforcing properties:

1. It appeared in chronological packet order rather than after manual rearrangement.
2. Its boundaries followed the standard `HTB{...}` challenge-token format.
3. It was surrounded by deliberate noise, consistent with an embedded message rather than an accidental ASCII coincidence.
4. The message came from all 57 consecutive Function 16 requests identified during the protocol analysis.
5. Re-running the TShark extraction and `awk` conversion produced the same sanitized structure.

The preserved solve transcript does not include a platform-side flag-submission response, so this article does not claim that such a response was captured. The deterministic decode and canonical token structure were the recorded validation evidence.

## Tooling detours and failed assumptions

### The missing `file` command

An initial attempt to run `file tower_logs.pcapng` failed because the `file` package was not installed. Installing it was unnecessary: `capinfos` already identified the capture as PCAPNG and provided much richer forensic metadata.

### Optional table formatting

The first register-extraction pipeline ended with `column -t -s,` for readability. The `column` utility was absent, and an attempted `bsdextrautils` installation returned an HTTP 404 from the Kali mirror. This did not block the investigation because table formatting was cosmetic. Removing the final pipe produced the required TSV data immediately.

### Looking at register values first

The natural first hypothesis was that `modbus.regval_uint16` held character codes. The representative value `6` and the wider set of values up to `245` did not support readable ASCII. Comparing both available fields exposed the real signal in `modbus.reference_num`. This is a useful forensic lesson: field names describe protocol semantics, not necessarily how an adversary may abuse those fields as a covert channel.

## Why the technique works

A Modbus Function 16 request needs a starting register reference and one or more values to write. In this capture, each request targeted one register, giving the sender control over both the address and the value. By choosing successive register addresses whose decimal numbers also map to printable ASCII, the sender encoded text while still producing syntactically valid Modbus write operations.

The method is visible to a protocol-aware analyst because the message spans a sequence of requests. Looking at one packet reveals only an ordinary address/value pair. Preserving time order, extracting the same field from every request and testing the numeric range reveals the higher-level structure.

This does not demonstrate a software vulnerability in the PLC implementation. It demonstrates how legitimate industrial-protocol operations can be repurposed to carry information and alter process state when a client is able to issue unauthorized read and write commands.

## Defensive perspective

Defenders monitoring Modbus/TCP should inspect semantics, not only connection metadata. Useful controls and detections include:

| Observation | Defensive action |
| --- | --- |
| New client communicating with TCP/502 | Restrict Modbus access with network segmentation and explicit client allow-lists |
| Function 15 or 16 from a monitoring workstation | Alert on write-capable function codes from read-only roles |
| Rapid writes to many unrelated references | Baseline normal address ranges and detect unusual address sequences |
| Repeated single-register writes | Correlate bursts rather than evaluating each packet independently |
| Read activity immediately surrounding writes | Build function-aware timelines that link reconnaissance to state changes |
| Address values clustering in printable ranges | Add analytics for encoded or structured patterns in protocol fields |
| Limited device-side authentication evidence | Place legacy devices behind authenticated gateways and tightly controlled management paths |

Packet capture remains valuable for incident response because Modbus function codes, addresses and values allow investigators to reconstruct what a client requested and changed. Where possible, this network evidence should be correlated with PLC logic, engineering-workstation logs and process historian data to determine operational impact.

## Key takeaways

- Begin PCAP analysis with protocol hierarchy and conversation statistics before inspecting individual packets.
- Separate read operations from write operations to reconstruct both collection and modification behavior.
- Use protocol-aware fields such as `modbus.func_code` instead of relying only on raw hex.
- Preserve packet order when testing whether repeated numeric values form an encoded stream.
- Compare metadata and payload fields; adversaries are not required to hide information in the most obvious data field.
- Treat industrial write functions as high-value detection events, especially when they come from a new or nominally read-only client.
- Record failed tooling steps honestly, but distinguish cosmetic failures from analysis blockers.

## References

- [Hack The Box — Watch Tower](https://app.hackthebox.com/challenges/Watch%2520Tower)
