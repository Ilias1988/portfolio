---
title: "Hack The Box — Delivery"
summary: "Delivery chains an osTicket email alias into Mattermost access, exposes SSH credentials, then uses a leaked MySQL account and password reuse to reach root."
platform: "Hack The Box"
contentType: "machine"
publicationPolicy: "retired"
difficulty: "Easy"
os: "Linux"
solvedAt: 2026-11-20
publishedAt: 2026-11-20
tags:
  - web-security
  - tickettrick
  - osticket
  - mattermost
  - mysql
  - password-cracking
  - password-reuse
  - privilege-escalation
tools:
  - Nmap
  - osTicket
  - Mattermost
  - SSH
  - MariaDB
  - Hashcat
cves: []
htbUrl: "https://app.hackthebox.com/machines/Delivery"
cover: "/images/writeups/hackthebox/machines/delivery/delivery.png"
coverAlt: "Hack The Box Delivery machine logo with a courier and parcel inside a green circle"
featured: false
draft: false
---

> This write-up covers an authorized Hack The Box lab. [0xdf records Delivery's retirement date as 22 May 2021](https://0xdf.gitlab.io/2021/05/22/htb-delivery.html); [Hack The Box permits public solutions for retired content](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines). Flag values, the live ticket number, email-verification token, and personal identifiers are omitted. The credentials shown below belong to this retired lab and are needed to reproduce the path.

## Executive summary

Delivery exposes osTicket on a helpdesk virtual host and Mattermost on port 8065. Opening a support ticket creates an `@delivery.htb` address. Registering that address with Mattermost sends a verification message into the ticket thread, which the ticket creator can read. An internal channel reveals SSH credentials for `maildeliverer` and a password-pattern hint. After SSH access, the Mattermost configuration file exposes MySQL credentials. A bcrypt hash for the Mattermost `root` account can be cracked with a small, targeted candidate set; the resulting password is also valid for the Linux `root` account.

## Target information

| Item | Value |
| --- | --- |
| Target | Delivery |
| Platform | Hack The Box |
| Difficulty | Easy |
| Operating system | Linux |
| Publication policy | Retired; [retirement recorded on 22 May 2021](https://0xdf.gitlab.io/2021/05/22/htb-delivery.html) |
| Main weaknesses | Ticket email alias accepted as an identity; credential disclosure; exposed database secret; password reuse |

Your HTB instance will have its own IP address. Set it once in the Kali terminal and substitute it throughout:

~~~bash
export TARGET_IP='<YOUR_HTB_TARGET_IP>'
~~~

## Enumeration

An all-port TCP scan with service and default-script detection found three reachable services:

~~~bash
nmap "$TARGET_IP" -T5 -sVC -p-
~~~

~~~text
22/tcp   open  ssh   OpenSSH 7.9p1 Debian 10+deb10u2
80/tcp   open  http  nginx 1.14.2
8065/tcp open  http  Mattermost
~~~

Nmap warned that its retransmission cap was reached during this aggressive `-T5` scan. The three positive findings were usable; if a scan misses a service on your connection, repeat it at `-T3`. Port 8065 is particularly important because it already identifies the collaboration application.

Visiting `http://<TARGET_IP>/` shows a Delivery landing page. Its **Contact Us** panel points unregistered users to a HelpDesk and says a `@delivery.htb` email address grants Mattermost access. Add the site names to Kali's hosts file so the browser resolves the virtual host:

~~~bash
printf '%s delivery.htb helpdesk.delivery.htb\n' "$TARGET_IP" | sudo tee -a /etc/hosts
~~~

Then open `http://helpdesk.delivery.htb/` and `http://delivery.htb:8065/` in separate tabs.

### Findings

| Evidence | Why it mattered |
| --- | --- |
| HelpDesk runs osTicket | A guest can open a ticket and later inspect its thread. |
| Ticket confirmation advertises an address like `<TICKET_ID>@delivery.htb` | The address can receive mail into the ticket thread. |
| Mattermost uses email verification | A verification message sent to the ticket address can be read from osTicket. |
| SSH is open | Credentials found in the internal chat can be tested directly. |

## Initial access

### Create a ticket and obtain its email alias

On the HelpDesk, select **Open a New Ticket**. Enter a name, an email address you will remember, a help topic if required, and a short subject and message. A placeholder such as `student@example.com` works for this lab. Keep the *original email* and the generated ticket number.

After submission, osTicket confirms the ticket and shows an address in this form:

~~~text
Ticket ID: <TICKET_ID>
Reply address: <TICKET_ID>@delivery.htb
~~~

The number is instance-specific. The reply address is the critical observation: mail delivered there is added to the ticket, and the person who opened the ticket can read the thread. This is the TicketTrick in Delivery.

### Verify a Mattermost account through the ticket

At `http://delivery.htb:8065/`, create a Mattermost account using `<TICKET_ID>@delivery.htb` as its email address. Choose a new username and password for this account. Mattermost sends its verification message to the ticket alias.

Return to the HelpDesk and select **Check Ticket Status**. Enter the ticket number and the *original email used to open the ticket*, not the ticket alias. Open the ticket thread and find the Mattermost registration message. Copy its **complete** `do_verify_email` URL into a new browser tab. In the lab's osTicket view, only the first part of that URL may appear as a blue hyperlink; clicking that fragment can drop the token. Copy the full URL through its final `email=...` parameter. Do not publish that URL, because it contains a live verification token.

After verification, sign in to Mattermost and join the **Internal** team. Its public channel was renamed from Town Square to **Internal**. A message from `root` gives the server credentials and warns that users reuse variants of `PleaseSubscribe!`:

~~~text
maildeliverer:Youve_G0t_Mail!
Password-pattern hint: PleaseSubscribe!
~~~

Use the disclosed account for SSH:

~~~bash
ssh maildeliverer@"$TARGET_IP"
# Password: Youve_G0t_Mail!
~~~

Confirm the account and read the user flag locally. Do not put its value in a public write-up:

~~~bash
id
ls -la ~
cat ~/user.txt
~~~

## Privilege escalation

### Recover Mattermost's database credentials

Local enumeration of the Mattermost installation reveals its configuration file. Inspect only the SQL settings:

~~~bash
grep -A8 '"SqlSettings"' /opt/mattermost/config/config.json
~~~

The `DataSource` contains a MySQL connection string for the local `mattermost` database. In this retired lab, the relevant portion is:

~~~text
mmuser:Crack_The_MM_Admin_PW@tcp(127.0.0.1:3306)/mattermost
~~~

This is a database password, not the Linux root password. Use it at the password prompt rather than placing it directly on the command line:

~~~bash
mysql -h 127.0.0.1 -u mmuser -p mattermost
~~~

Query the Mattermost user table:

~~~sql
SELECT Username, Password FROM Users WHERE Username = 'root';
~~~

The `root` row returns a hash beginning with `$2a$10$`. That prefix identifies bcrypt with cost 10. Copy the **complete** hash value to your Kali machine; it is a Mattermost password hash, so the next step is an offline candidate test.

### Test the password hint with Hashcat

On Kali, place the hash on one line in `root.hash`. The single quotes keep the dollar signs literal. Replace the placeholder with the full hash returned by your SQL query:

~~~bash
printf '%s\n' '<FULL_BCRYPT_HASH_FROM_SQL>' > root.hash
printf '%s\n' 'PleaseSubscribe!' > base.txt
~~~

Hashcat mode `3200` handles bcrypt. Hybrid attack mode `-a 6` appends a mask to each base word. Testing two decimal digits after the phrase searches just 100 candidates:

~~~bash
hashcat -m 3200 -a 6 root.hash base.txt '?d?d'
hashcat -m 3200 --show root.hash
~~~

For this machine, the recovered password is `PleaseSubscribe!21`. Hashcat may warn that the wordlist and mask are too small to fill the device's parallel capacity; that is a performance note, not a cracking failure. The observed result is `Status: Cracked`.

Back in the `maildeliverer` SSH session, test whether the password was reused for the Linux root account:

~~~bash
su - root
# Password: PleaseSubscribe!21
id
cat /root/root.txt
~~~

`id` should report `uid=0(root)`. Submit the flag to HTB without publishing its value.

## What did not work

The original `-T5` scan produced a retransmission warning, so it should not be treated as proof that every other port was absent. It still identified all three services used in this path. The osTicket-rendered verification message also linked only part of the URL in the browser; copying the full URL from the ticket text completed verification. No unrelated exploit path was needed or tested.

## Attack path

1. Enumerate SSH, nginx, Mattermost, and the helpdesk virtual host.
2. Open an osTicket ticket and obtain its `@delivery.htb` reply address.
3. Register that address with Mattermost, then read the verification message from the ticket thread.
4. Join **Internal**, recover the `maildeliverer` credential, and establish SSH access.
5. Read Mattermost's MySQL `DataSource`, query the `Users` table, and extract the `root` bcrypt hash.
6. Test the chat's password hint with a two-digit suffix mask, then use the recovered password with `su`.

## Lessons learned

- Email verification only proves control of the receiving mailbox or workflow. A ticket reply alias should not confer the same identity as a company-managed mailbox.
- Credentials posted in an internal channel become exposed when the channel's membership boundary fails. Remove shared passwords from chat and rotate them when discovered.
- A readable application configuration file can bridge a low-privilege shell into a database account. Protect configuration secrets and limit database permissions.
- Reusing a predictable password variant across an application account and Linux root turned a cracked Mattermost hash into full host control. Unique passwords and restricted root authentication break that final link.
- A short, evidence-led candidate set was enough for bcrypt. The meaningful work was identifying the phrase from the chat and the account hash from MySQL, not running a large generic wordlist.

## References

- [0xdf's Delivery retirement record](https://0xdf.gitlab.io/2021/05/22/htb-delivery.html)
- [Hack The Box write-up publication guidelines](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines)
- [osTicket: Check Ticket Status](https://docs.osticket.com/en/latest/User/Ticket/Check%20Ticket%20Status.html)
- [Mattermost authentication configuration](https://docs.mattermost.com/administration-guide/configure/authentication-configuration-settings)
- [Hashcat mask and hybrid attacks](https://hashcat.net/wiki/doku.php?id=mask_attack)
