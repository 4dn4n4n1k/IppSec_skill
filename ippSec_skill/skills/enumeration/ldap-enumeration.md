# LDAP Enumeration

> Anonymous and authenticated AD object discovery. Your single best
> source for usernames, groups, descriptions, custom attributes, and
> trust relationships.

## Objective
Pull every interesting attribute on every reachable AD object using
LDAP, with whatever credentials you have (or no credentials).

## When To Use
Whenever port 389 / 636 / 3268 / 3269 is open. LDAP often allows
anonymous bind even when SMB / RPC are locked down.

## Detection Indicators
- nmap detects LDAP via `-sV`.
- `nmap --script ldap-rootdse <ip>` returns a base DN ⇒ AD is present.
- nmap script `ldap-search` returns objects ⇒ anonymous bind allowed.

## Enumeration Strategy

### Step 1 — find the base DN

```bash
ldapsearch -x -H ldap://<ip> -s base namingcontexts
# returns: namingContexts: DC=cascade,DC=local
```

### Step 2 — anonymous user enumeration

```bash
# all users
ldapsearch -x -H ldap://<ip> -b "DC=...,DC=..." \
  "(&(objectClass=user)(sAMAccountName=*))" sAMAccountName cn description \
  -LLL > ldap-users.txt

# users with DONT_REQUIRE_PREAUTH (AS-REP candidates)
ldapsearch -x -H ldap://<ip> -b "DC=...,DC=..." \
  "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  sAMAccountName

# users with SPN (Kerberoast candidates) — requires authentication
ldapsearch -x -H ldap://<ip> -b "DC=...,DC=..." \
  "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName

# computers
ldapsearch -x -H ldap://<ip> -b "DC=...,DC=..." \
  "(objectClass=computer)" name dNSHostName operatingSystem
```

### Step 3 — pull *everything* on a specific account

```bash
ldapsearch -x -H ldap://<ip> -b "DC=...,DC=..." \
  "(sAMAccountName=<user>)" '*' '+'
```

The `*` returns standard attributes; `+` returns operational ones —
critical for spotting **custom attributes** like `cascadeLegacyPwd`.

### Step 4 — nmap LDAP scripts for one-shot

```bash
nmap -p 389 --script "ldap-search,ldap-rootdse" <ip>
```

## Exploitation Workflow

1. Pull all users → save as `users.txt`.
2. Pull all `description` fields → grep for passwords.
3. Pull `userAccountControl` flags → find AS-REP / pre-auth candidates.
4. Pull SPNs → find Kerberoastable accounts.
5. Pull custom attributes (`'*' '+'`) → find non-default secrets.
6. Pull group memberships → identify privileged groups (Domain Admins,
   Enterprise Admins, Account Operators, Server Operators, Backup
   Operators).

## Commands

```bash
# ldapsearch fundamentals
ldapsearch -x -H ldap://<ip>                        # anonymous
ldapsearch -x -H ldap://<ip> -D '<bind-dn>' -w '<p>' # simple bind w/ password
ldapsearch -x -H ldap://<ip> -D 'CN=user,CN=Users,DC=domain,DC=local' -W

# specifying scope
-s base   # only the base entry
-s one    # entries one level below base
-s sub    # whole subtree (default)

# limit attributes
ldapsearch ... 'attr1' 'attr2'

# include operational attributes (SIDs, replication metadata)
ldapsearch ... '*' '+'

# custom filters (RFC 4515)
"(objectClass=user)"
"(memberOf=CN=Domain Admins,CN=Users,DC=...)"
"(adminCount=1)"               # users marked privileged
"(servicePrincipalName=*)"      # accounts with SPN
"(userAccountControl:1.2.840.113556.1.4.803:=4194304)" # DONT_REQUIRE_PREAUTH bit
"(userAccountControl:1.2.840.113556.1.4.803:=8192)"    # SERVER_TRUST_ACCOUNT (DCs)
```

## Tool Usage

- `ldapsearch` — canonical CLI, OpenLDAP.
- `ldapdomaindump` — Python; dumps to JSON/HTML.
- `windapsearch` — friendlier; shorthand queries.
- `ldap-utils` package on Kali / Parrot.
- `nmap --script ldap-*` — quick survey.
- `bloodhound-python` (`bloodhound.py`) — LDAP-driven BloodHound
  collection, off-host.

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Wrong base DN | empty results | Get from rootDSE first |
| Anonymous bind disabled but assuming creds anyway | "Operations error" | Use `-D <user> -w <pass>` |
| Forgetting `+` for operational attrs | Miss custom attributes | Always `'*' '+'` on user dumps |
| Massive result set crash | Tool hangs | `-l <seconds>` time limit, `-z <size>` size limit |
| Searching from a non-DC LDAP | Partial / cached data | Confirm target is the DC (port 3268 = global catalog) |

## Decision-Making Logic

```
LDAP responds to anonymous? 
  Yes → enumerate users / groups / attributes immediately
  No  → try authenticated bind w/ any cred you have
        ↓
  Still no → fallback to Kerberos username brute (kerbrute)
```

If you see **non-default attributes** on a user (e.g. the Cascade
`cascadeLegacyPwd`), that's a high-signal lead — the box's author put
something there for a reason.

## Pivot Opportunities

LDAP creds enable:
- BloodHound collection.
- Pre-auth-disabled identification → AS-REPRoast.
- SPN enumeration → Kerberoast.
- ACL-edge identification (PowerView equivalent: `Get-DomainObjectAcl`).

## OPSEC Considerations
- LDAP queries are logged on the DC at high verbosity if Directory
  Service auditing is on; default at most shops is *off*.
- Anonymous LDAP queries are often legitimate (printers, scanners).
- Excessive `*` queries from one IP look like recon; throttle.

## Real HTB Examples

- **Forest** — anonymous bind reveals `svc-alfresco`.
- **Cascade** — anonymous bind reveals `r.thompson` with custom
  `cascadeLegacyPwd`.
- **Sauna** — LDAP locked down; required Kerbrute path.
- **Active** — LDAP enumeration confirms the GPP-leaked user.
- **Multimaster, Resolute, Mantis** — LDAP-driven user lists drive the
  follow-on attacks.

## Alternative Techniques

- **rpcclient null session** when LDAP is restricted — `enumdomusers`
  via DCERPC.
- **Kerberos username brute** when both LDAP and RPC are locked.
- **Web-scraping** the company website for names → permute → Kerbrute.

## Automation Opportunities

Wrap LDAP into a one-shot:
```bash
windapsearch -d <domain> --dc-ip <ip> -m all -o ldap-dump
```

```bash
ldapdomaindump -u '<domain>\\<user>' -p '<pass>' <ip> -o ldap-dump
firefox ldap-dump/domain_users.html
```

## Checklist

- [ ] rootDSE: `namingcontexts`
- [ ] All users: `(objectClass=user)` → `sAMAccountName cn description`
- [ ] AS-REP candidates: UAC flag 4194304
- [ ] SPNs: `servicePrincipalName=*`
- [ ] Computers: `(objectClass=computer)`
- [ ] Privileged: `(memberOf=CN=Domain Admins,...)`, `(adminCount=1)`
- [ ] Custom attrs sweep: `'*' '+'` on every user

## Related Skills

- [`enumeration/nmap-methodology.md`](nmap-methodology.md)
- [`active-directory/anonymous-ad-enumeration.md`](../active-directory/anonymous-ad-enumeration.md)
- [`active-directory/as-rep-roasting.md`](../active-directory/as-rep-roasting.md)
- [`active-directory/kerberoasting.md`](../active-directory/kerberoasting.md)
- [`active-directory/bloodhound-usage.md`](../active-directory/bloodhound-usage.md)
- [`methodology/07-ad-attack-chains.md`](../methodology/07-ad-attack-chains.md)
