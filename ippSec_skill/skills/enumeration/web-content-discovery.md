# Web Content Discovery

> Find every URL, file, parameter, and vhost the application exposes,
> beyond what is linked from the homepage.

## Objective
Discover hidden directories, backup files, admin panels, vhosts, and
parameters using wordlist-driven fuzzing.

## When To Use
After fingerprinting a web service. Before exploiting any web vector.

## Detection Indicators
- A web port is open.
- The visible site is a single page or login.
- Search engines or robots.txt hint at unknown paths.

## Enumeration Strategy

### Layer 1 — directory & file fuzz

```bash
gobuster dir -u http://<ip>/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -x php,html,txt,bak,old,zip,tar.gz \
  -t 50 -o gobuster.txt
```

Wordlist by stack:
- `raft-medium-words.txt` — generic, balanced.
- `raft-large-words.txt` — when easy yields nothing.
- `directory-list-2.3-medium.txt` — DirBuster classic.
- `quickhits.txt` — appliance recon (favicon/version paths).
- `common-php-files.txt` — PHP applications.
- `IIS.fuzz.txt` — IIS / .NET targets.
- `ColdFusion`, `Tomcat`, `Joomla`, `WordPress` — product-specific
  lists in seclists.

### Layer 2 — extensions tailored to fingerprint

```bash
# generic
-x php,html,txt,bak,old,zip,tar.gz,sql

# .NET / IIS
-x asp,aspx,ashx,asmx,svc,xml,config

# Java
-x jsp,do,action,war

# ColdFusion
-x cfm,cfc

# add backup variants always
-x bak,old,1,~,swp
```

### Layer 3 — vhost fuzz

```bash
# baseline content-length
curl -s http://<ip>/ | wc -c   # e.g., 5821

ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -u http://<ip>/ \
  -H "Host: FUZZ.<box>.htb" \
  -fs 5821                       # filter-size matches default page
```

When you discover a vhost, add it to `/etc/hosts` and re-fuzz the
content of each.

### Layer 4 — recursive / deep fuzz

```bash
feroxbuster -u http://<ip>/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -x php,html,txt -t 50 -d 3 \
  -o ferox.txt
```

`feroxbuster` automatically recurses into directories it finds.

### Layer 5 — parameter fuzz

```bash
# discover GET parameters that change responses
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u "http://<ip>/page.php?FUZZ=test" \
  -fs <baseline-size>

# wfuzz alternative
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  --hh <baseline-size> "http://<ip>/page.php?FUZZ=test"

# Arjun — purpose-built parameter discovery
arjun -u http://<ip>/page.php
```

## Exploitation Workflow

1. Fuzz directories with raft-medium + appropriate extensions.
2. Manually browse each interesting hit; view source.
3. For redirects, follow the redirect target and fuzz *that* path.
4. For login pages, try defaults; capture session cookies.
5. For admin interfaces, fingerprint product+version.
6. Backup-file extensions (`-x bak,old,~,swp,1`) frequently leak
   source code on PHP/JSP apps.
7. Vhost fuzz when the cert SAN list or any page hints at hostnames.

## Commands

```bash
# Gobuster — fast, simple
gobuster dir -u <url> -w <wordlist> -x <exts> -t 50 -o output.txt
gobuster vhost -u http://<ip>/ -w <subdomains.txt>          # vhost mode
gobuster dns -d <domain> -w <subdomains.txt>                # DNS subdomain

# ffuf — flexible; supports multiple wordlists, response filters
ffuf -w <wordlist>:WORD,<extlist>:EXT -u http://<ip>/WORD.EXT
ffuf -w <list> -u http://<ip>/FUZZ -fc 404 -ac     # auto-calibrate
ffuf -w <list> -u http://<ip>/FUZZ -mc 200,401,403 # match codes

# feroxbuster — recursive
feroxbuster -u http://<ip>/ -w <wordlist> -x php,html -d 3

# wfuzz — older but powerful
wfuzz -c -z file,<wordlist> --hh <size> http://<ip>/FUZZ

# nikto — vuln/file scanner
nikto -h http://<ip> -o nikto.txt
```

## Tool Usage

| Tool | Strength | Weakness |
|---|---|---|
| `gobuster` | Fast, simple, stable | No recursion (mode dir); single-list per run |
| `ffuf` | Flexible, multi-list, filtering | Filter calibration learning curve |
| `feroxbuster` | Recursive by default | Can hammer a server |
| `wfuzz` | Historic standard | Slower than ffuf |
| `dirsearch` | Python; nice TUI | Slower than gobuster |
| `nikto` | One-shot common-vuln check | Loud; signatured |

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Default 10 threads | Scan takes hours | `-t 50` (or 100 for fast labs) |
| Ignoring redirects | Miss real content | Follow with `--follow-redirect` (gobuster) or check the redirect target |
| Wrong wordlist for stack | Miss obvious paths | Pick the stack-specific list |
| Single extension | Miss `.bak`, `.old`, `.swp` | Always include backup exts |
| No vhost fuzzing | Miss split-content sites | Always vhost-fuzz when cert/page hints at a hostname |
| Treating `403` as dead | Sometimes 403 indicates existence | Investigate; try with auth |

## Decision-Making Logic

```
gobuster baseline scan →
  if results sparse:
    expand wordlist (raft-large)
    add extensions (.bak, .old, .config)
    try vhost fuzzing
    try dirsearch (different default settings)
    try a recursive scanner (feroxbuster)
  if a redirect appears:
    follow + fuzz the target path
  if rate-limited (429):
    reduce threads to 5
    add jitter (-p)
    consider using a proxy chain
```

## Pivot Opportunities
Found content drives the next attack:
- `/admin/` → default-creds attempt.
- `/.git/` → `git-dumper` for source.
- `/uploads/` → upload-bypass attempts.
- `/backup.zip` → free credential leak.
- `phpinfo.php` → environment / paths disclosed.

## OPSEC Considerations

- Default user-agents (`gobuster/3.x`) shout "scanner". Customise:
  ```bash
  gobuster dir -u <url> -H "User-Agent: Mozilla/5.0 ..." ...
  ```
- 50+ threads will trigger many WAFs.
- Fuzzing for backup files (`/.env`, `/.git/HEAD`) is highly signatured.

## Real HTB Examples

- **Bashed** — gobuster finds `/dev/phpbash.php`.
- **OpenAdmin** — gobuster reveals `/music/` → redirect → `/ona/`.
- **Sense** — gobuster reveals `/changelog.txt` and `/system-users.txt`.
- **Jeeves** — gobuster on port 50000 finds Jenkins paths.
- **Mantis** — vhost discovery is the entire foothold step.

## Alternative Techniques

- Search engines (`site:`, `inurl:`) for real targets — irrelevant on HTB.
- Wayback Machine for historical paths — irrelevant on HTB.
- Burp Suite spider for *interactive* discovery — useful when gobuster
  paths return interactive apps.

## Automation Opportunities

A workflow:
```bash
URL=http://<ip>
gobuster dir -u $URL -w raft-medium-words.txt -x php,html,txt -t 50 -o p1.txt
# check redirects in p1.txt; recurse manually
# also run a vhost fuzz if you have a hostname hint
```

## Checklist

- [ ] Directory fuzz with raft-medium + extensions
- [ ] Recurse into every 200/301 result manually
- [ ] Backup file extensions (`bak,old,~,swp,1`) included
- [ ] Vhost fuzz performed when a hostname is hinted
- [ ] Parameter fuzz on PHP / dynamic endpoints
- [ ] `nikto` run as a one-shot sanity check
- [ ] All output saved to disk for cross-reference

## Related Skills

- [`enumeration/nmap-methodology.md`](nmap-methodology.md)
- [`web/disclosed-files.md`](../web/disclosed-files.md)
- [`web/upload-bypass.md`](../web/upload-bypass.md)
- [`tool-usage/gobuster.md`](../tool-usage/gobuster.md)
- [`tool-usage/ffuf.md`](../tool-usage/ffuf.md)
- [`methodology/04-web-attack-flow.md`](../methodology/04-web-attack-flow.md)
