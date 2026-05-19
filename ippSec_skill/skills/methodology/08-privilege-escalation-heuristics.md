# Privilege Escalation Heuristics

> A platform-agnostic decision lattice. Use this to choose *which* privesc
> family to investigate first, given the context.

## The four privesc families

1. **Misconfiguration** — sudo rules, weak ACLs, service permissions.
2. **Stored credentials** — secrets-in-files, history files, registry,
   memory.
3. **Trust abuse** — token impersonation, group membership, ACL edges.
4. **Software vulnerability** — kernel exploits, sudo CVEs, DLL hijack.

In rough HTB frequency: 1 ≫ 2 > 3 > 4. Real engagements may shift the
distribution.

## The 5-minute decision rule

Within 5 minutes of getting any new shell, you should have answers to:

| Question | Linux | Windows |
|---|---|---|
| Who am I? | `id` | `whoami /all` |
| What can I run as someone else? | `sudo -l` | `whoami /priv`; `whoami /groups` |
| What's the OS? | `uname -a; cat /etc/os-release` | `systeminfo` |
| Where are obvious creds? | `~/.bash_history`; `find / -name "*.conf" 2>/dev/null` | PSReadline history; `Unattend.xml`; `web.config` |
| Anything custom on this box? | `find /opt /scripts /usr/local -type f -mtime -90 2>/dev/null` | non-default scheduled tasks; non-default services |

If those answers don't yield a path, *then* run linpeas/winPEAS.

## Heuristic 1 — context tells you the family

| Context | First family to suspect |
|---|---|
| Web app shell (`www-data`, `apache`, `iis apppool\xxx`) | Token abuse (Linux: usually nothing; Windows: SeImpersonate) or stored creds |
| Service account (`mssql$`, `svc_*`) | Stored creds or token abuse |
| Standard user (`john`, `bob`) on a multi-user box | Misconfiguration (sudo, cron) |
| Local admin or domain user on a member server | Lateral / credential hunting |
| A shell on a DC | DCSync, NTDS.dit, AD object abuse |

## Heuristic 2 — recent files are special

```bash
# Linux
find / -mmin -60 -type f 2>/dev/null | grep -v -E "^/proc|^/sys|^/run|^/var/log"
find /opt /home /root /tmp /var/spool/cron -type f 2>/dev/null
```
```powershell
# Windows
Get-ChildItem C:\ -Recurse -Force -ErrorAction SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } |
  Select FullName, LastWriteTime
```
Files modified by the box's authors (within the last few weeks) frequently
contain the privesc.

## Heuristic 3 — non-default processes / services

```bash
ps -ef | grep -v "^root" | grep -v "^USER" | sort -u    # processes by other users
ss -tlnp; netstat -tlnp                                  # local-only services
```
Services bound to `127.0.0.1` are often there because the box's author
added them — and they tend to be the privesc target.

```powershell
Get-Process -IncludeUserName | Where-Object { $_.UserName -ne $null -and $_.UserName -ne $env:USERDOMAIN+"\"+$env:USERNAME }
Get-Service | Where-Object { $_.Status -eq 'Running' -and $_.DisplayName -notlike "Microsoft*" -and $_.DisplayName -notlike "Windows*" }
```

## Heuristic 4 — multi-user box implies pivoting

If `/home/` has multiple users or `Get-LocalUser` shows multiple, the
intended path likely chains through one of them before root/SYSTEM.
- Search every user's home for files readable by you.
- Watch processes running as those users — they may load files you can
  influence.

OpenAdmin: `www-data` → `jimmy` → `joanna` → root. Never skip user-to-user.

## Heuristic 5 — credentials reuse aggressively

Every credential you discover, try against:
- All users on this box.
- All services on this box (mysql, ssh, mssql, web admin).
- All other boxes on the network.

This is the OpenAdmin (DB password = system password) and many AD
patterns at once.

## Heuristic 6 — check what runs as root *in the future*

`pspy` on Linux, scheduled tasks on Windows. Cron jobs running every
minute are dropped on the box for a reason; the privesc is usually
related.

```bash
./pspy64 -pf -i 1000 | tee pspy.log
```
```powershell
schtasks /query /fo LIST /v | findstr /i /b /c:"TaskName" /c:"Run As User"
```

## Heuristic 7 — Read the script first

Boxes often place a custom script in `/opt`, `/scripts`, `/usr/local/bin`,
or `C:\Scripts\`. Read every one — they almost always contain or reference
credentials, or run something exploitable.

```bash
find /opt /scripts /srv 2>/dev/null
ls -la /usr/local/bin/ | head -50
```
```powershell
Get-ChildItem C:\Scripts, C:\Tools, C:\Users\Public -Recurse -ErrorAction SilentlyContinue
```

## Heuristic 8 — known software ⇒ known abuse

When `winPEAS` / `linpeas` flags installed software, the privesc question
becomes: *what does this software do that I can hijack?*
- Backup software → arbitrary file read/write (e.g., NetBackup, Veeam).
- AV / endpoint agents → DLL injection, scheduled scan abuse.
- Splunk Universal Forwarder → forwarder API RCE.
- MSSQL → `xp_cmdshell` if `sa` known.
- Tomcat manager → app deployment to RCE.

## Heuristic 9 — kernel exploits are the last resort

Kernel exploits are loud, often unreliable, and frequently panic the
host. Try every other family first. When you do reach for them:
1. Identify the exact kernel: `uname -a; cat /etc/os-release`.
2. Identify candidate CVEs: `linux-exploit-suggester.sh`, `wesng`.
3. Compile *off-target* against a matching kernel; transfer the binary.
4. Test in a way that you can recover (background, log output).

## Heuristic 10 — Don't chase chrome

Some classes of "vulnerability" are noise on HTB:
- World-writable `/etc/hosts` or `/etc/resolv.conf` rarely exploitable in
  a standalone context.
- Outdated browser / desktop software in a server box.
- Vulnerable libraries that no service on the box uses.

Filter linpeas output for *running services / used software*, not
*installed software*.

## Recovery when stuck

If 30 minutes of privesc effort yields nothing:

1. **Re-enumerate as the current user.** Tools see different things at
   different times of day (cron-driven file changes).
2. **Try every harvested credential** as every other user.
3. **Look for connections you've missed**: open files, listening
   sockets, mounted filesystems.
4. **Read the box's purpose** — what is this software for? The privesc
   is usually thematic.
5. **Re-check `sudo -l` / `whoami /priv`** — sometimes you missed a line.

## See also

- [09-credential-hunting.md](09-credential-hunting.md)
- [13-post-exploitation.md](13-post-exploitation.md)
- [../linux-privesc/](../linux-privesc/)
- [../windows-privesc/](../windows-privesc/)
- [../privilege-escalation-checklists/](../privilege-escalation-checklists/)
