# NTFS Alternate Data Streams (ADS)

> NTFS lets a single filename hold multiple data streams. The default
> ("`$DATA`") stream is what `type` and `cat` show; named streams are
> hidden from default directory listings.

## Objective
Read or write data hidden in named ADS streams of an NTFS file.

## When To Use
- Windows post-exploitation when the obvious flag file appears empty
  or wrong.
- Files named oddly on the desktop (Jeeves's `hm.txt`).
- During malware analysis (DFIR scenarios).

## Detection Indicators

```cmd
dir /R C:\path\to\file
```
The `/R` switch reveals named streams. Without it, ADS data is
invisible.

## Enumeration Strategy

```cmd
:: list all files with their streams
dir /R /S C:\Users\Administrator\Desktop

:: PowerShell equivalent
Get-Item -Path C:\Users\Administrator\Desktop\hm.txt -Stream *
Get-ChildItem -Recurse | ForEach-Object { Get-Item -Path $_.FullName -Stream * } | Where-Object Stream -ne ':$DATA'
```

## Exploitation Workflow

### Read an ADS

```cmd
:: classic Windows command-line trick
more < C:\Users\Administrator\Desktop\hm.txt:root.txt

:: PowerShell
Get-Content -Path C:\Users\Administrator\Desktop\hm.txt -Stream root.txt
```

### Write an ADS (often used by malware)

```cmd
type evil.exe > legitimate.txt:hidden.exe
:: launch via WMI / wmic process call create
wmic process call create '"C:\path\legitimate.txt:hidden.exe"'
```

```powershell
Set-Content -Path C:\path\legitimate.txt -Stream hidden.txt -Value "secret"
```

### Note the syntax

ADS notation: `<filename>:<stream-name>:<type>`
- `:$DATA` is the default stream (regular file content).
- A named stream is `:<name>` (like `:root.txt`).

## Commands

```cmd
:: see streams
dir /R <file>
:: read stream
more < <file>:<stream>
:: enumerate every stream on every file recursively
dir /R /A /S | findstr /V "0 File"
```

```powershell
Get-Item <file> -Stream *
Get-Content <file> -Stream <name>
```

## Tool Usage

- `dir /R` — built-in; mandatory.
- `streams.exe` (Sysinternals) — comprehensive ADS enumeration.
- `Get-Item -Stream *` — PowerShell native.
- `Out-File ... -Stream` / `Set-Content ... -Stream` — write.
- `lads` (Frank Heyne) — older legacy option.

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| `dir` without `/R` | ADS invisible | Always `/R` for post-ex flag-hunt |
| Trying `type <file>:<stream>` | "the syntax of the command is incorrect" | Use `more <` redirect form |
| Confusing stream name with filename | "file not found" | `<file>:<stream>` not `<file>/<stream>` |

## Decision-Making Logic

```
post-exploitation, can't find root.txt
  └─ dir /R Administrator's desktop → see :root.txt stream?
       Yes → more < <file>:<stream>
       No  → search other usual locations:
              - C:\Users\Public
              - C:\ProgramData
              - C:\flags (custom)
```

## Pivot Opportunities

ADS is end-of-chain on HTB; it's a flag-recovery technique.
On real engagements:
- Detect adversary persistence (malware in ADS).
- Detect data exfiltration staging.

## OPSEC Considerations
- ADS reads/writes are normal NTFS operations and aren't separately
  logged unless filesystem auditing is enabled.
- Modern EDR can flag ADS-resident executables.

## Real HTB Examples

- **Jeeves** — `hm.txt:root.txt` ADS on the Administrator desktop.
- **Minion** — same trick with a different filename.

## Alternative Techniques
- **NTFS reparse points** — junctions / symlinks for redirection.
- **Resource forks** (macOS analogue) — comparable concept on HFS+.

## Automation Opportunities

```powershell
# scan a tree for files with non-default streams
Get-ChildItem -Recurse -Force -ErrorAction SilentlyContinue |
  ForEach-Object {
    Get-Item -Path $_.FullName -Stream * -ErrorAction SilentlyContinue
  } | Where-Object Stream -ne ':$DATA' |
  Select-Object FileName, Stream, Length
```

## Checklist

- [ ] `dir /R` on every interesting directory in post-ex
- [ ] `Get-Item -Stream *` on every interesting file
- [ ] Read non-default streams via `more <file>:<stream>`

## Related Skills

- [`windows-privesc/file-hiding-techniques.md`](file-hiding-techniques.md)
- [`methodology/13-post-exploitation.md`](../methodology/13-post-exploitation.md)
