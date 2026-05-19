# Nmap Methodology

> Two-pass scanning, banner extraction, scripting category selection.

## Objective
Map the target's exposed services completely and quickly without
wasting cycles or triggering rate limits.

## When To Use
Always. Nmap is the first tool against any new target. Re-run as your
network position changes (post-pivot, new VLAN reachable).

## Detection Indicators
This is *the* detection tool. Indicators come from its output, not from
external evidence.

## Enumeration Strategy
The two-pass model:

1. **Discover all open ports fast**:
   ```bash
   sudo nmap -p- --min-rate=10000 -T4 -oA nmap/all-tcp <ip>
   ```

2. **Detail-scan only those ports**:
   ```bash
   ports=$(grep ^[0-9] nmap/all-tcp.gnmap | awk -F'/' '/open/{print $1}' \
           | tr -s ' ' | sed 's/^.* //' | tr '\n' ',' | sed 's/,$//')
   sudo nmap -sV -sC -p $ports -oA nmap/tcp-detail <ip>
   ```

UDP is selective:
```bash
sudo nmap -sU --top-ports 50 -oA nmap/udp-top <ip>
```

## Exploitation Workflow
Nmap is foundational; "exploitation" here means leveraging the scan
output for downstream tools.

```bash
# Extract just the open ports for piping
grep ^[0-9] nmap/all-tcp.gnmap | awk -F'/' '/open/{print $1}'

# Build /etc/hosts entries from cert data
nmap -p443 --script ssl-cert <ip> | grep -oE "DNS:[a-zA-Z0-9.-]+" | cut -d':' -f2

# Pull SMB / LDAP version specifics
nmap -p445 --script "smb-protocols,smb-security-mode,smb2-security-mode" <ip>
nmap -p389 --script "ldap-rootdse" <ip>
```

## Commands

```bash
# Fastest possible host discovery (one-shot)
sudo nmap -sn 10.10.10.0/24 -oA nmap/sweep

# Aggressive single-host (versions + scripts + traceroute + OS)
sudo nmap -A -T4 -p- --min-rate=10000 -oA nmap/aggressive <ip>

# Avoid pinging (firewalls that drop ICMP)
sudo nmap -Pn ...

# Avoid DNS resolution noise
sudo nmap -n ...

# Vuln scripts (loud)
sudo nmap --script vuln <ip>

# Specific script categories
sudo nmap --script "default,safe,auth"  -p <ports> <ip>
sudo nmap --script "discovery and not intrusive" -p <ports> <ip>

# Save all formats (normal, grepable, XML)
-oA <basename>

# Read targets from a file
nmap -iL targets.txt
```

## Tool Usage

- `-sV` — service version probing (TCP connect probe-driven).
- `-sC` — equivalent to `--script default`.
- `--script <name>` — run a specific NSE script. Find scripts in
  `/usr/share/nmap/scripts/`.
- `--script-help <name>` — explain what a script does.
- `--reason` — show *why* a port was classified open/closed/filtered.
- `--open` — show only open ports (cleaner output).

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Running `-sV -sC` on all 65535 ports first | Scan takes 30+ minutes | Two-pass: ports first, scripts after |
| Using `-T4` against fragile services | Crashes IoT / appliances | `-T3` on live engagements |
| Forgetting `sudo` for SYN scan | Falls back to TCP connect (slower, easier to detect) | Always `sudo nmap` |
| `-p-` with low `--min-rate` | Times out on flaky networks | `--min-rate=5000` minimum |
| Trusting `closed` vs `filtered` blindly | Misreads firewalls | Use `--reason` to interpret |

## Decision-Making Logic

| Observed | Implication | Next |
|---|---|---|
| Many odd high ports | RPC ephemeral / Win EPMAP | Run `nmap --script msrpc-enum -p 135 <ip>` |
| 88+389+445 cluster | Domain Controller | Pivot to AD enum (`07-ad-attack-chains.md`) |
| Only 80 / 443 | Web-only foothold | Skip to web flow (`04-web-attack-flow.md`) |
| 22 + 80 + nothing else (Linux) | Common easy box | Web first, SSH after creds |
| 80 + 50000 | Likely Jenkins | Hit `/script` first |
| Nothing except weird high port | Custom service | `nc` raw probe; `--script banner` |
| 21 anon banner | FTP anon | `mget *`; check for keys/configs |

## Pivot Opportunities
After foothold, run nmap *from* the foothold to enumerate internal
networks (with chisel/proxychains).

## OPSEC Considerations
- Default nmap is loud. `T4` and `--min-rate` raise this further.
- TCP SYN scan looks like aggressive recon to any IDS.
- For real engagements, `-T2` and a small port set, with timing
  jitter, is recommended.
- `--script vuln` writes a lot of probes; many of them are signatured
  by IDS as scanner activity.

## Real HTB Examples

- **Forest**: nmap reveals AD cluster, kicks off LDAP/RPC enum.
- **Sauna**: `-sC` `ldap-rootdse` gives `EGOTISTICAL-BANK.LOCAL`.
- **Optimum**: nmap banner `HFS 2.3` is the entire foothold trigger.
- **Sense**: nmap `--script ssl-cert` confirms pfSense.
- **Jeeves**: nmap finds port 50000 (Jenkins) — easy to miss without `-p-`.

## Alternative Techniques

- `rustscan` — much faster port discovery; pipes results to nmap for
  versioning.
- `masscan` — internet-scale; useful for `-p- --rate=100000`.
- `naabu` — alternative fast scanner.
- For UDP, `unicornscan` is faster than nmap-sU but less accurate.

## Automation Opportunities

```bash
# rustscan + nmap combo (faster than 2-pass nmap)
rustscan -a <ip> -t 5000 -- -A -sC -sV -oA nmap/rscan
```

## Checklist

- [ ] Full TCP port scan (`-p-`)
- [ ] Detail scan (`-sV -sC`) on open ports
- [ ] UDP top-50 if AD/SNMP/DNS hints
- [ ] `/etc/hosts` updated with hostname(s) from certs
- [ ] Output saved in three formats (`-oA`)

## Related Skills

- [`enumeration/smb-enumeration.md`](smb-enumeration.md)
- [`enumeration/ldap-enumeration.md`](ldap-enumeration.md)
- [`enumeration/web-content-discovery.md`](web-content-discovery.md)
- [`methodology/01-initial-foothold.md`](../methodology/01-initial-foothold.md)
- [`methodology/03-service-prioritization.md`](../methodology/03-service-prioritization.md)
