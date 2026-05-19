# Windows Attack Flow

> Holistic flow for attacking a Windows host outside of pure AD context.
> When the host is a domain controller / domain member, branch to
> `07-ad-attack-chains.md` after foothold.

## Decision: AD or Standalone?

Look at the nmap output:

| Evidence | Likely role |
|---|---|
| 88 + 389 + 445 + 53 | Domain controller |
| 88 + 389 not present, 445 + 5985 + 3389 | Domain member or workgroup |
| Only 80/443 + 5985 | Web server, possibly domain-joined |
| 80 + 21 + 445, no 88 | Standalone Windows server |

If domain controller → see `07-ad-attack-chains.md`.

## Foothold flow (standalone Windows)

1. **Web first**: more often than not, foothold is a web app on Windows
   (Jenkins, Tomcat, IIS WebDAV, custom .NET).
2. **SMB enumeration**: `smbmap -H <ip>` for shares, `smbclient -L //<ip>/`
   for listings.
3. **WinRM (5985/5986)** if you ever obtain creds; cleaner than SMB.
4. **RDP (3389)** is rarely the foothold, but useful post-exploitation if
   you want a GUI.

## Once you have a shell

The first 90 seconds on a Windows shell:

```powershell
whoami
whoami /priv
whoami /groups
hostname
systeminfo                              # OS version, hotfixes, domain
ipconfig /all
net user
net localgroup administrators
Get-LocalUser | Select Name, Enabled, LastLogon
Get-ChildItem Env:                       # USERDOMAIN tells you AD context
```

Why each:
- `whoami /priv` — token privileges; `SeImpersonatePrivilege` and
  `SeAssignPrimaryTokenPrivilege` are immediate Potato candidates.
- `whoami /groups` — group membership; `BUILTIN\Administrators` means
  you're already there (UAC dance only).
- `systeminfo` — feeds `windows-exploit-suggester` for kernel privesc.
- `Get-ChildItem Env:` — `USERDOMAIN` ≠ `COMPUTERNAME` ⇒ domain-joined.

## Shell stabilisation on Windows

Most reverse shells from Nishang / msfvenom give you a usable prompt
immediately. Things to know:

- `cmd.exe` → run `powershell -ep bypass` for a friendlier shell.
- `cmd /c command` does not preserve directory; use full paths.
- `Ctrl+C` will kill the reverse shell; mind your fingers.
- For an interactive shell, prefer `evil-winrm` once you have creds.

## Privilege escalation on Windows

Run an enum tool first, then act on findings.

```powershell
# winPEAS — fastest broad enum
.\winPEASany.exe quiet > peas.txt

# PowerUp — focused on misconfigurations
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```

Categories of Windows privesc, in rough frequency order on HTB:

### 1. Token / privilege abuse (very common on web/svc accounts)
If `SeImpersonatePrivilege` is enabled (typical for IIS/MSSQL service
accounts):

- Older targets: `JuicyPotato.exe` (works pre-2019).
- Newer targets: `PrintSpoofer.exe`, `RoguePotato.exe`, `GodPotato.exe`.

These give SYSTEM by abusing the COM impersonation chain. See
`windows-privesc/token-impersonation.md`.

### 2. Stored credentials in files
Highest hit rate per minute spent:
```powershell
# PowerShell history
Get-Content "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"

# Unattended.xml (image-deployment leftovers)
Get-Content C:\Windows\Panther\Unattend.xml
Get-Content C:\Windows\Panther\Unattended.xml
Get-Content C:\Windows\system32\sysprep\sysprep.xml

# Web app config
Select-String -Path C:\inetpub\wwwroot\web.config -Pattern "password|connectionString"

# Registry — autologon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr /i "DefaultUserName DefaultPassword"
```

The Sauna box is built around the `winlogon` autologon registry leak.

### 3. Service misconfigurations
```powershell
# unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows" | findstr /i /v """

# weak service permissions
accesschk.exe -uwcqv "Authenticated Users" *

# weak binary perms (writable service binary)
icacls "C:\Path\To\Service.exe"
```

### 4. AlwaysInstallElevated
```powershell
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
# both 1 → msi to SYSTEM
```

### 5. DLL hijacking / PATH issues
```powershell
$env:Path -split ';'                      # check for unusual writable dirs in PATH
```

### 6. Kernel exploits (older targets)
```bash
# from systeminfo output
# https://github.com/bitsadmin/wesng
wes.py systeminfo.txt
```

Optimum's MS16-032 path is a textbook example.

### 7. Stored hashes / SAM
```powershell
# DA / Local admin already required for SAM:
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
# offline: secretsdump.py LOCAL -system system.save -sam sam.save
```

## Common credential reuse paths on Windows

1. Local admin password reused across the domain (lateral hopping with
   `crackmapexec smb <range> -u administrator -H <hash> --local-auth`).
2. Service account password in a file → use it for `evil-winrm`.
3. Logon-as-a-service password → cleartext in Unattend.xml.
4. PowerShell history with `-Password` arguments visible.

## Logging footprints (Windows)

- Most enum is logged in the Security/Application/System event logs.
- Powershell logging (Modules, ScriptBlock) captures payloads to
  `Microsoft-Windows-PowerShell/Operational`.
- `secretsdump` and `psexec` leave very loud Service Control Manager
  events (Service `RemComSvc` / `PSEXESVC`). Use WMI/WinRM where
  possible for stealth.

## See also

- [07-ad-attack-chains.md](07-ad-attack-chains.md)
- [08-privilege-escalation-heuristics.md](08-privilege-escalation-heuristics.md)
- [12-shell-stabilization.md](12-shell-stabilization.md)
- [../windows-privesc/](../windows-privesc/)
