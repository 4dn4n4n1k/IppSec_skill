# Default Credentials

> The cheapest possible foothold check. Most appliances ship with
> documented defaults; many remain in production years after deployment.

## Objective
Authenticate against any service or web app using documented vendor
defaults before considering more involved attacks.

## When To Use
*Always*, as the first credentialed-step attempt. Try defaults before
brute force, before SQLi, before kernel exploits.

## Detection Indicators
The service banner identifies the vendor; vendor docs provide the
defaults.

## Common defaults (priority list)

### Web appliances

| Product | User | Password |
|---|---|---|
| pfSense | `admin` | `pfsense` |
| OPNsense | `root` | `opnsense` |
| Tomcat manager | `tomcat` | `tomcat` / `s3cret` / `admin` |
| Tomcat manager (Kali pentest target) | `manager` | `manager` |
| Jenkins (older) | `admin` | `admin` |
| GitLab | `root` | (set on first login; check `/help`) |
| Splunk | `admin` | `changeme` |
| Cisco IOS | `cisco` | `cisco` |
| Cisco SDM | `cisco` | `cisco` |
| Mikrotik | `admin` | (blank) |
| WatchGuard | `admin` | `readwrite` |
| Fortinet | `admin` | (blank) |
| Juniper SSG | `netscreen` | `netscreen` |
| F5 BIG-IP | `admin` | `admin` |
| ManageEngine ServiceDesk | `administrator` | `administrator` |
| ManageEngine ADAudit | `admin` | `admin` |
| Zabbix | `Admin` | `zabbix` |
| Nagios | `nagiosadmin` | `nagiosadmin` |
| Grafana | `admin` | `admin` |
| Solr / Elastic | (no auth) | n/a |
| RabbitMQ | `guest` | `guest` |
| Redis | (no auth) | n/a |
| Kibana | (no auth or `kibana:kibana`) | n/a |
| Wordpress (fresh) | `admin` | `password` |
| Drupal install | `admin` | (set during install — try `admin`/`admin`) |

### Databases

| Product | User | Password |
|---|---|---|
| MySQL | `root` | (blank) / `root` / `mysql` |
| Postgres | `postgres` | `postgres` |
| MSSQL | `sa` | (blank) / `sa` |
| Oracle | `system` | `manager` / `oracle` |
| MongoDB | (no auth) | n/a |

### Embedded / IoT

| Product | User | Password |
|---|---|---|
| HP iLO | `admin` | (printed on physical tag; on virtual: `admin`) |
| Dell iDRAC | `root` | `calvin` |
| Supermicro IPMI | `ADMIN` | `ADMIN` |
| Various NVRs | `admin` | `888888` / `12345` / blank |

## Enumeration Strategy

```bash
# fingerprint to identify product
whatweb http://<ip>/
curl -sI http://<ip>/

# read product docs:
# - search "<product> default credentials"
# - search "/help" or "/manual" on the box itself
```

## Exploitation Workflow

1. Fingerprint the product *and* the version.
2. Look up the default for that version (defaults sometimes change
   between major versions).
3. Try the documented default *before* any other attack.
4. If multiple defaults exist (e.g., multiple admin accounts), try all
   of them.

## Commands

```bash
# generic web auth attempt
curl -sI -u admin:admin http://<ip>/

# basic-auth file
echo "admin:admin" > creds.txt
hydra -C creds.txt http-get://<ip>/

# tomcat manager
curl -s -u tomcat:tomcat http://<ip>:8080/manager/html

# pfSense (form-based)
curl -k -L -c c.txt -b c.txt -d "usernamefld=admin&passwordfld=pfsense&login=Login" \
  https://<ip>/index.php
```

## Tool Usage

- `whatweb` — fingerprint.
- `wpscan --enumerate` — WordPress-specific.
- `nuclei` with `default-logins` templates — automated check.
- `default-creds` (Nuclei community) — broad coverage.

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Skipping the default attempt | Wasted time on harder paths | Always try first |
| Wrong product version | Defaults don't apply | Read banner / version disclosure |
| Caps / typos | "Authentication failed" for actual default | Verify exact casing |
| Trying after lockout policy triggered | Account locked | Defaults first, brute force later |

## Decision-Making Logic

```
new web service identified
  └─ product known? → try documented default(s) first
       └─ no? → look up vendor docs / security advisories
       └─ default works? → done
       └─ default rejected? → check for "first-run" install state
                              (often grants admin without auth)
       └─ still nothing → move to disclosed-files / CVE / brute force
```

## Pivot Opportunities
A working default usually grants admin to the underlying app, which
in turn enables:
- Authenticated CVE exploitation (e.g., pfSense's RCE in Sense).
- Configuration disclosure → other credentials.
- File upload / RCE features intended for admins.

## OPSEC Considerations
- Trying defaults generates a 401/302 entry per attempt; quiet.
- Hitting the wrong default 5–15 times triggers product-level lockout
  (pfSense locks for 24h after 15 attempts!). Always check policy
  *before* spraying.

## Real HTB Examples

- **Sense** — `rohit:pfsense` (the version's documented default).
- **Sneakymailer, Beep, Bastard** — multiple appliances with default
  creds.
- **Mantis** — MSSQL `sa` default.
- **Querier, Giddy** — MSSQL `sa` patterns.
- **Tabby** — Tomcat manager attempted with defaults before any
  upload exploit.

## Alternative Techniques

- **Disclosed credentials** in `changelog.txt` / `system-users.txt`
  (Sense — both default-creds AND disclosed-file vectors).
- **Source code config disclosure** for non-default-but-still-leaked
  creds.
- **Brute force** as a last resort.

## Automation Opportunities

```bash
# nuclei default-logins template
nuclei -u http://<ip>/ -t default-logins/ -severity high
```

## Checklist

- [ ] Product identified
- [ ] Version captured
- [ ] Documented default(s) tried first
- [ ] Tried in the order: vendor → admin/admin → admin/password →
      admin/<product>
- [ ] Lockout policy understood before further brute force

## Related Skills

- [`web/disclosed-files.md`](disclosed-files.md)
- [`enumeration/web-content-discovery.md`](../enumeration/web-content-discovery.md)
- [`linux-privesc/credential-reuse.md`](../linux-privesc/credential-reuse.md)
- [`methodology/04-web-attack-flow.md`](../methodology/04-web-attack-flow.md)
