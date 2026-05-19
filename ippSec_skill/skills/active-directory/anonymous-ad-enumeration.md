# Anonymous AD Enumeration

> Pre-credential discovery against an AD-joined target. The first 5 minutes
> of every AD box.

## Objective
Extract maximum AD information (users, groups, password policy, custom
attributes) without any credential.

## When To Use
- AD detected (88+389+445 cluster).
- Before attempting password spray, brute force, or AS-REPRoasting.

## Detection Indicators
- nmap `ldap-rootdse` returns base DN ⇒ AD present.
- nmap `smb-os-discovery` confirms it's a domain controller.

## Enumeration Strategy

### Layer 1 — RPC null session

```bash
rpcclient -U "" -N <ip>
> srvinfo                # OS, server type
> enumdomusers           # full user list with RIDs
> querydispinfo          # users + descriptions
> enumdomgroups          # all groups
> getdompwinfo           # password policy
> querydominfo           # domain controller info
> enumdomains            # other domains in trust
> lsaquery               # domain SID
> lookupnames Administrator   # → SID
> lookupsids S-1-5-21-...    # → name
```

`enumdomusers` and `querydispinfo` are gold. `getdompwinfo` tells you
the lockout threshold *before* you spray.

### Layer 2 — LDAP anonymous bind

```bash
# get the base DN
ldapsearch -x -H ldap://<ip> -s base namingcontexts

# then dump users
ldapsearch -x -H ldap://<ip> -b "DC=...,DC=..." \
  "(objectClass=user)" sAMAccountName cn description \
  -LLL > users.ldif

# include operational attrs to catch custom ones (Cascade pattern)
ldapsearch -x -H ldap://<ip> -b "DC=...,DC=..." \
  "(objectClass=user)" '*' '+' \
  -LLL > users-full.ldif
```

### Layer 3 — SMB anonymous

```bash
smbmap -H <ip>                     # auto-anonymous
smbmap -H <ip> -u guest -p ''
smbclient -L //<ip>/ -N
smbclient //<ip>/IPC$ -N

# null SID brute (works through IPC$)
impacket-lookupsid '<dom>/'@<ip>
```

### Layer 4 — Kerberos

```bash
# username brute via Kerberos pre-auth (works even when other channels are locked)
kerbrute userenum --dc <ip> -d <domain> users.txt
```

### Layer 5 — DNS

```bash
# zone transfer (rarely succeeds, but free)
dig axfr @<ip> <domain>
# pull domain controllers via SRV
dig SRV _ldap._tcp.dc._msdcs.<domain> @<ip>
```

## Exploitation Workflow

The output of anonymous enum drives everything else:

1. Save the **user list** → users.txt.
2. Save **password policy** → choose spray strategy.
3. Save **group memberships** → identify privileged users.
4. Save **descriptions** → grep for cleartext passwords.
5. Save **custom attributes** → look for non-default secrets.
6. Save **domain SID** → required for some impacket commands.

## Commands

```bash
# one-shot wrapper (covers RPC + LDAP + SMB)
enum4linux-ng -A <ip> -oJ enum.json

# crackmapexec sweep (anonymous)
crackmapexec smb <ip> -u '' -p '' --shares --users --groups --pass-pol

# Kerberos username brute (no creds required)
kerbrute userenum --dc <ip> -d <domain> /usr/share/seclists/Usernames/Names/names.txt
```

## Tool Usage

| Tool | Purpose |
|---|---|
| `rpcclient` | DCERPC null session enum |
| `ldapsearch` | LDAP anonymous bind |
| `smbmap` / `smbclient` | SMB anonymous enum |
| `enum4linux-ng` | All-in-one wrapper |
| `kerbrute` | Kerberos username brute |
| `impacket-lookupsid` | SID brute through IPC$ |

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Skipping `getdompwinfo` before spray | Locks accounts | Always check policy first |
| Trusting `enumdomusers` blindly | Some users hidden in OUs | Cross-check via LDAP + RPC |
| Wrong realm casing | Tools fail | Use exact realm |
| Only one tool | Each tool sees different things | Run all four (rpc, ldap, smb, kerbrute) |
| Forgetting to grep `description` for passwords | Miss free creds | Always grep |

## Decision-Making Logic

```
RPC null works (enumdomusers populated)?
  Yes → grab user list and policy
  No  → LDAP anonymous?
        Yes → grab user list + custom attrs
        No  → Kerberos username brute (kerbrute) — slower, last resort
              + try web-scraping if a public site exists
```

## Pivot Opportunities

User list ⇒ **AS-REPRoast** the whole list (cheap, frequent yield).
Password policy ⇒ choose a spray candidate within the threshold.
Description fields ⇒ grep for cleartext.
Custom attributes ⇒ `cascadeLegacyPwd`-style finds.

## OPSEC Considerations
- Anonymous queries are normally legitimate (printers, scanners do
  them).
- High volume looks like a scanner; throttle.
- Kerbrute generates Event 4768 on the DC per username; consider this
  on detection-aware engagements.

## Real HTB Examples

- **Forest** — RPC null session returns 27 users.
- **Cascade** — LDAP anonymous returns user with custom
  `cascadeLegacyPwd`.
- **Active** — SMB anonymous → Replication share → GPP.
- **Sauna** — none of these work; pivots to web username harvest.
- **Resolute** — RPC null gives users; one description holds the cleartext.

## Alternative Techniques
- **WSDL / web service enumeration** when the box exposes one.
- **NetBIOS enumeration** with `nbtscan`.
- **MS-RPRN / Print spooler null session** — modern variant.

## Automation Opportunities

```bash
enum4linux-ng -A <ip> -oA enum-out
# parses everything from RPC + LDAP + SMB into a structured report
```

## Checklist

- [ ] `rpcclient -U "" -N` — `enumdomusers`, `querydispinfo`,
      `getdompwinfo`, `enumdomgroups`
- [ ] LDAP rootDSE for base DN
- [ ] LDAP anonymous: users with `*` and `+` attributes
- [ ] SMB anonymous: smbmap, smbclient -L, IPC$
- [ ] enum4linux-ng -A as a sanity check
- [ ] Kerbrute when other channels dry up
- [ ] grep all description fields for cleartext passwords

## Related Skills

- [`enumeration/ldap-enumeration.md`](../enumeration/ldap-enumeration.md)
- [`enumeration/smb-enumeration.md`](../enumeration/smb-enumeration.md)
- [`active-directory/kerberos-username-enumeration.md`](kerberos-username-enumeration.md)
- [`active-directory/as-rep-roasting.md`](as-rep-roasting.md)
- [`methodology/07-ad-attack-chains.md`](../methodology/07-ad-attack-chains.md)
