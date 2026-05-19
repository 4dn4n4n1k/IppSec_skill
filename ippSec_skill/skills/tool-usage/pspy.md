# pspy Reference

> Linux process snooping without root. Reveals processes started by
> *other users* — critical for cron-based privesc.

## Install / use

```bash
# pre-built binary
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -O pspy64
chmod +x pspy64
./pspy64

# 32-bit variant
./pspy32

# verbose
./pspy64 -pf -i 1000

# log to file
./pspy64 -pf -i 1000 | tee pspy.log
```

## Flags

```
-i <ms>     # poll interval in ms (default 1000)
-p          # print PIDs
-f          # print filesystem events too (chmod, write)
-c          # color output
-r          # only print arguments / cmdline (no env)
```

## What you're looking for

```
2024/05/15 13:01:00 CMD: UID=0    PID=12345  /usr/bin/python /scripts/test.py
```

`UID=0` (root) running a script every minute = **cron / systemd timer
privesc candidate**.

## Output interpretation

Each event is one of:
- `CMD:` — process executed.
- `FS:` — filesystem event (with `-f`).

Pay attention to:
- High-frequency CMDs from UID you don't own.
- File touches in `/var/log`, `/tmp`, `/opt`, `/scripts` matching the
  CMD timing.

## Recipe — find writable script in a cron run

```bash
# 1. run pspy, wait 5 minutes
./pspy64 -pf -i 1000 | tee /tmp/pspy.log

# 2. find UID=0 events
grep 'UID=0' /tmp/pspy.log | head

# 3. for each script path, check writability
ls -la /scripts/test.py  # rw-r--r-- scriptmanager → writable as scriptmanager
```

## When pspy is unavailable

- Static cron read: `cat /etc/crontab`, `ls /etc/cron.{d,daily,...}`.
- Run timing: `stat <suspect-script>` — check if `Modify` cycles.
- Use bash tricks:
  ```bash
  while true; do ps -ef | grep -v "$$" | sort > /tmp/procs.now; comm -13 /tmp/procs.last /tmp/procs.now; cp /tmp/procs.now /tmp/procs.last; sleep 1; done
  ```
  (poor-man's pspy)

## Common Mistakes

- Running for less than a full cron period (60s minimum).
- Not catching short-lived processes — increase polling: `-i 100`.
- Trusting only CMDs — without `-f`, file events that imply a cron
  are missed.

## Real HTB Examples

- **Bashed** — reveals `python /scripts/test.py` running as root every
  minute.
- **Tartarsauce, Networked, Frolic** — different cron patterns; pspy
  surfaces them.
- **Postman, Cronos** — pspy reveals time-based services.

## Related

- [`linux-privesc/cron-writable-script.md`](../linux-privesc/cron-writable-script.md)
- [`linux-privesc/path-hijacking.md`](../linux-privesc/path-hijacking.md)
- [`methodology/06-linux-attack-flow.md`](../methodology/06-linux-attack-flow.md)
