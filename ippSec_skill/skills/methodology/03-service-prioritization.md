# Service Prioritization

> Given a list of open ports, decide which to attack first. Order matters
> because each service has a different cost-to-payoff ratio.

## Default priority order (use unless evidence says otherwise)

1. **Anonymous-friendly enumeration sources** (LDAP 389, SMB 445, RPC 135,
   SNMP 161, FTP 21) — very low cost, often yield credentials directly.
2. **Web (80, 443, 8080, 8000, 8443, 3000, 5000)** — highest payload of
   attack surface per port; fingerprint, then drill in.
3. **Banner-fingerprinted vulnerable software** (anything where nmap or curl
   tells you "Server: Tomcat 7.0.27" → searchsploit immediately).
4. **AD ecosystem** (88 + 389 + 445 cluster) — once anon enum produces a
   user list, switch to AS-REPRoasting / Kerbrute.
5. **Database services** (1433 MSSQL, 3306 MySQL, 5432 Postgres, 27017
   Mongo, 6379 Redis) — try defaults; rarely directly exploitable from the
   outside.
6. **Mail (25, 110, 143, 993, 995)** — `vrfy`/`expn` for usernames; rarely
   the foothold.
7. **Remote management (22 SSH, 3389 RDP, 5985 WinRM)** — enumerate, do not
   brute force, except when explicitly directed by other context (a
   credential leak).
8. **DNS (53)** — zone transfer attempt; rarely fruitful but cheap.
9. **Esoteric / niche services** (rsync 873, NFS 2049, IPMI 623, Cassandra
   7000, etc.) — handle ad-hoc.

## Port-by-port quick reference

### 21 — FTP
- Always try `anonymous:''`.
- If logged in, recursively `mget *` and grep for creds.
- Look for `.bak`, `.config`, `web.config`, `id_rsa`.

### 22 — SSH
- Don't brute force unless you have a known username and a custom wordlist.
- Note the SSH banner — fingerprint OS / distribution.
- If you have a private key from elsewhere, try it here as every harvested
  user.

### 25 / 110 / 143 / 465 / 587 / 993 / 995 — Mail
- `nmap --script smtp-enum-users` on 25.
- VRFY / EXPN if SMTP allows.
- IMAP/POP3 with creds from elsewhere often yields email-stored secrets.

### 53 — DNS
- `dig axfr @<ip> <domain>` (zone transfer; rarely succeeds but is cheap).
- `nmap --script dns-zone-transfer`.
- If domain unknown, look at AD context.

### 80 / 443 / 8080 / 8443 — HTTP(S)
- See `04-web-attack-flow.md`.
- Fingerprint with `whatweb`, view-source, `Wappalyzer`.
- Always check `/robots.txt`, `/sitemap.xml`, `/.git/HEAD`, `/.env`,
  `/admin`, `/login`.
- Always check both IP and any hostname; vhost separation is common.

### 88 — Kerberos
- Confirm the realm: `nmap --script krb5-enum-users` (needs userlist).
- `kerbrute userenum --dc <ip> -d <domain> users.txt`.
- If 88 is open, also expect 389 (LDAP) and 445 (SMB).

### 111 — RPCBind / portmapper
- `rpcinfo -p <ip>` to enumerate exported services.
- If NFS is exported (2049), `showmount -e <ip>` and try mounting writable
  shares.

### 135 / 139 / 445 — Windows RPC / NetBIOS / SMB
- `rpcclient -U "" -N <ip>` for null session.
- `smbclient -L //<ip>/ -N` and `smbmap -H <ip>`.
- `enum4linux -a <ip>` as a one-shot.
- Pay attention to SMB versions — SMBv1 + Windows XP/2003 ⇒ EternalBlue.

### 161 — SNMP
- Public community string is the default: `snmpwalk -c public -v1 <ip>`.
- SNMP frequently exposes routing tables, processes, installed software,
  user accounts, and even cleartext credentials in legacy gear.

### 389 / 636 / 3268 — LDAP / LDAPS / Global Catalog
- Anonymous bind: `ldapsearch -x -H ldap://<ip> -s base namingcontexts`.
- Once you have base DN, enumerate users:
  `ldapsearch -x -b "DC=..." "(objectClass=user)" sAMAccountName`.

### 1433 — MSSQL
- Try `sa:` with a blank, `sa:sa`, `sa:Password1`, `sa:<box>`.
- If creds work, `xp_cmdshell` is the fast win when configured.

### 3306 — MySQL
- Anonymous / weak creds. Read users with `SELECT user,authentication_string FROM mysql.user;`.

### 5985 / 5986 — WinRM
- `evil-winrm -i <ip> -u <user> -p <pass>` (or `-H <hash>` for pass-the-hash).

### 5432 — Postgres
- Try `postgres:postgres` and `postgres:postgres123`.

### 6379 — Redis
- Frequently unauthenticated.
- Abuse `CONFIG SET dir` + write `authorized_keys` for SSH.

### 27017 — MongoDB
- Frequently unauthenticated.
- `mongo` shell, dump every collection.

## When the priority changes

The default priority is a *prior*. Update it when:

- **Box is themed**: A pfSense banner means try defaults first (Sense).
- **Banner shouts a CVE**: HFS 2.x means try CVE-2014-6287 first (Optimum).
- **AD with no anonymous channels**: jump to Kerberos username brute via
  Kerbrute (Sauna pattern).
- **Web behind cloud / WAF**: focus on parameter / vhost fuzzing rather
  than scanner-driven attacks.
- **Single port open**: that port is the foothold; do not get distracted.

## Time-boxing rules

| Service | Time-box for foothold attempt |
|---|---|
| Anonymous enum (SMB/LDAP/RPC) | 15 min total |
| Web fingerprint | 10 min |
| Web content discovery | 30 min initial; iterate as you learn |
| Banner-fingerprinted CVE attempt | 30 min (read exploit, run it) |
| Brute force | Avoid; cap at 15 min if necessary |

When you exceed the box, switch services. **Never delete progress** — keep
the running scans in a separate tmux window.

## See also

- [02-enumeration-first.md](02-enumeration-first.md)
- [04-web-attack-flow.md](04-web-attack-flow.md)
- [07-ad-attack-chains.md](07-ad-attack-chains.md)
- [../enumeration/](../enumeration/)
