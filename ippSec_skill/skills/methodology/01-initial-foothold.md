# Initial Foothold Methodology

> The first 30 minutes of every box. The goal of this phase is not to "get
> in" — it is to **identify the right surface to get in through**.

## Phase 0: Pre-flight

```bash
mkdir -p ~/htb/<box>/{nmap,scans,loot,exploit}
cd ~/htb/<box>
echo "<ip>  <box>.htb" | sudo tee -a /etc/hosts   # update vhost as you learn it
```

Add a hostname to `/etc/hosts` immediately because:
1. Many web apps redirect to a hostname they expect.
2. SMB/Kerberos/LDAP often demand the right name.
3. Virtual host routing won't return the same content with the IP.

## Phase 1: TCP discovery (always)

Two-pass nmap:

```bash
# Pass 1 — fast, all 65535 ports, just open/closed
sudo nmap -p- --min-rate=10000 -T4 -oA nmap/all-tcp <ip>

# Pass 2 — versions + scripts on the open ports only
ports=$(grep ^[0-9] nmap/all-tcp.gnmap | awk -F'/' '/open/{print $1}' \
        | tr -s ' ' | sed 's/^.* //' | tr '\n' ',' | sed 's/,$//')
sudo nmap -sV -sC -p $ports -oA nmap/tcp-detail <ip>
```

**Why two passes**: pass 1 is dumb-fast and reliable. Pass 2 is slow but
narrow; running scripts against 65k ports is wasted time.

**IppSec frequently pre-runs the slow scan and starts enumerating the most
obvious port (typically 80 or 445) while detail finishes.** That is the
parallel-tracks rule from `00-operator-mindset.md`.

## Phase 2: UDP triage (when AD or specific services hint)

UDP scans are slow. Don't run a full UDP scan on every box. Run it when:
- You see Kerberos / LDAP and want to confirm DNS (UDP 53), Kerberos (UDP 88), or NTP/DC (UDP 123).
- You see SNMP candidates (UDP 161 — SNMP often gives huge wins on appliances).
- The TCP picture is suspiciously empty.

```bash
sudo nmap -sU --top-ports 50 -oA nmap/udp-top <ip>
```

## Phase 3: Build a service inventory

For every open port, record:

| Port | Service | Version | Banner / hostname / cert names |
|---|---|---|---|
| 80 | nginx 1.18 | — | `Server: nginx/1.18` |
| 88 | Kerberos | — | realm `htb.local` |
| 389 | LDAP | — | DC=htb,DC=local |

Cert and AD names matter:
- Nmap shows TLS cert subjects. Those are *real hostnames* — add them to
  `/etc/hosts`.
- AD realms exposed by Kerberos / LDAP are *the domain name* — required
  for impacket commands.

## Phase 4: Decide the foothold class

Four pure foothold classes; the box is almost always one of them:

| Class | Trigger | First move |
|---|---|---|
| **Web** | Port 80/443/8080/8000/8443 | Browse, gobuster, view source |
| **AD** | Ports 88+389+445 cluster | LDAP anon bind, RPC null session, Kerbrute |
| **File-share** | Port 445 *without* AD | smbmap, smbclient |
| **Service-specific exploit** | Banner of known-vulnerable software (HFS, Drupal, Jenkins, Tomcat, etc.) | searchsploit |

The cheap-shot priority order from `00-operator-mindset.md` applies within
each class.

## Phase 5: Web foothold flow (when applicable)

```bash
# Always look at the page in a browser; many CTFs hide hints in the visible
# page or comments
curl -s -o page.html http://<ip>/ && grep -iE "powered|version|admin|@|login" page.html

# Directory & file fuzzing — pick a list that matches the platform
gobuster dir -u http://<ip> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -x php,html,txt -t 50 -o scans/gobuster.txt

# Virtual-host fuzzing if a hostname is hinted
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -u http://<ip> -H "Host: FUZZ.<box>.htb" -fs <baseline-size>
```

Then move to `04-web-attack-flow.md` for the post-discovery decision tree.

## Phase 6: AD foothold flow (when applicable)

```bash
# Anonymous LDAP — gives you usernames if NotebookOps allows
ldapsearch -x -H ldap://<ip> -s base namingcontexts
ldapsearch -x -H ldap://<ip> -b "DC=htb,DC=local" "(objectClass=user)" sAMAccountName

# RPC null session — gives you the user list on a vulnerable DC
rpcclient -U "" -N <ip>
> enumdomusers
> querydispinfo

# Kerberos username brute — when LDAP/RPC are locked down but 88 is open
kerbrute userenum --dc <ip> -d <domain> users.txt
```

Then move to `07-ad-attack-chains.md`.

## Phase 7: SMB foothold flow

```bash
smbmap -H <ip>                     # what shares exist, what perms
smbmap -H <ip> -u guest -p ''      # try guest
smbmap -H <ip> -u '' -p ''         # try null
smbclient -L //<ip>/ -N            # list shares
smbclient //<ip>/<share> -N        # connect to readable share
```

Inside readable shares, *recursively download everything*:
```bash
smbclient //<ip>/<share> -N -c "prompt OFF; recurse ON; mget *"
```

Then locally:
```bash
grep -RinE "password|passwd|pwd|secret|cred|key" .
strings *.bin *.exe 2>/dev/null | grep -iE "password|cpassword"
```

This is exactly the Active box pattern (`Groups.xml` → `cpassword`).

## Phase 8: Service-specific exploit flow

If a banner gives you an exact product+version:

```bash
searchsploit <product> <version>
searchsploit -m <id>           # copy locally
# Read the exploit before running it
cat <id>.{py,rb,c}
```

**Always read the exploit before running it.** IppSec consistently
demonstrates this. Reasons:
- The exploit may target a different OS / arch.
- Default callback IPs / ports are baked in.
- The "exploit" may be a vulnerability writeup with no payload.
- Some Exploit-DB scripts are deliberately broken or weaponised.

## Foothold dead-ends and recovery

| Symptom | Likely cause | Recovery |
|---|---|---|
| Every login form 401s | Wrong creds (obvious) | Look for username sources you missed |
| Webshell uploads but doesn't execute | Path is outside docroot | Find the docroot; check upload path |
| Reverse shell connects then dies | Stabilisation needed (see `12-shell-stabilization.md`) | TTY upgrade, or migrate to nc -e |
| Exploit returns 200 but no shell | Egress filtering | Reverse port range — try 80, 443, 53 |
| nmap shows a port closed but other tools see it open | UDP / RST blocked / firewall | `nmap -Pn`, raw TCP probes |

## See also

- [02-enumeration-first.md](02-enumeration-first.md)
- [03-service-prioritization.md](03-service-prioritization.md)
- [04-web-attack-flow.md](04-web-attack-flow.md)
- [07-ad-attack-chains.md](07-ad-attack-chains.md)
