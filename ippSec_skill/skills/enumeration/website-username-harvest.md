# Website Username Harvest

> When LDAP/RPC/SMB are locked down, the public website is the username
> source. This is the Sauna pattern.

## Objective
Convert real names visible on a public web property into AD username
candidates that can then be validated via Kerberos.

## When To Use
- AD detected (88+389+445).
- Anonymous LDAP/RPC/SMB return nothing.
- The box runs a website that lists employees or contributors.

## Detection Indicators
- "About us", "Our Team", "Contact" pages with photos and names.
- Email addresses in the form `first.last@domain` or `flast@domain`.
- Author/by-line metadata on blog posts.
- Image alt-text containing names.

## Enumeration Strategy

### Step 1 — extract names from web pages

```bash
# basic curl + python
curl -s http://<ip>/ -o page.html
curl -s http://<ip>/about | tee -a page.html
curl -s http://<ip>/team -o -| tee -a page.html

# regex sweep for First Last patterns
python3 -c '
import sys, re
html = open("page.html").read()
for m in re.finditer(r"\b([A-Z][a-z]{1,15})\s+([A-Z][a-z]{1,15})\b", html):
    print(f"{m.group(1)} {m.group(2)}")
' | sort -u > names.txt
```

### Step 2 — username permutation

Tools that generate `flast`, `first.last`, `lfirst`, `firstl`, etc.:

```bash
git clone https://github.com/urbanadventurer/username-anarchy
./username-anarchy/username-anarchy -i names.txt > users.txt

# alternative: namemash
git clone https://gist.github.com/superkojiman/.../namemash.py
python3 namemash.py names.txt > users.txt
```

Inspect `users.txt`:
```
fsmith
fergus.smith
smith.fergus
fergusS
fsmith01
...
```

### Step 3 — validate via Kerberos pre-auth

```bash
./kerbrute userenum --dc <dc-ip> -d <domain> users.txt
# valid users return KDC_ERR_PREAUTH_REQUIRED
# invalid users return KDC_ERR_C_PRINCIPAL_UNKNOWN
```

The output lists `[+] <user>@<domain> is valid` for each existing
account.

## Exploitation Workflow

1. Identify a website on the AD target.
2. Pull every page with personal names (about, team, blog, contact).
3. Add real names from email addresses if they appear.
4. Permute with `username-anarchy` or equivalent.
5. Validate via `kerbrute userenum`.
6. AS-REPRoast the validated list.
7. Spray a common password if AS-REP yields nothing.

## Commands

```bash
# scrape every linked page on a small site
curl -s http://<ip>/sitemap.xml | grep -oE "https?://[^<]+" > urls.txt
# (or wget --recursive --level=2 ...)

# extract emails/users from arbitrary HTML
grep -oiE '[a-z0-9._]+@[a-z0-9.-]+\.[a-z]{2,}' page.html | sort -u

# extract names — beware of false positives
grep -oE '\b[A-Z][a-z]{1,15}\s+[A-Z][a-z]{1,15}\b' page.html | sort -u
```

## Tool Usage

- `curl` / `wget` — page download.
- `linkedin2username` — for real engagements (LinkedIn → username).
- `cewl` — extract custom wordlists from a site, *also* names.
- `username-anarchy` — name → username permutations.
- `kerbrute userenum` — Kerberos boolean oracle.

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Using the wrong realm casing | Kerbrute "no valid users" | Realm is usually UPPERCASE: `EGOTISTICAL-BANK.LOCAL` |
| Forgetting `--dc <dc-ip>` | Kerbrute can't reach DC | Always specify `--dc` |
| Permuting too aggressively | Wordlist too long → slow | Start with `flast`, `firstlast`, `flast1`, then expand |
| Not adding usernames from emails | Miss obvious answers | If `j.smith@bank.com` appears on a page, add `j.smith` and `jsmith` |

## Decision-Making Logic

```
AD detected, anonymous channels closed
  └─ scrape website → names list
       └─ permute → users.txt
            └─ kerbrute userenum
                 ├─ at least one valid user found:
                 │    AS-REPRoast it (free)
                 │    if no AS-REP, password-spray (cautiously)
                 └─ nothing valid:
                      try larger wordlist
                      try email harvesting
                      try LinkedIn / Hunter.io OSINT (real engagements)
```

## Pivot Opportunities
Validated usernames feed into:
- AS-REPRoasting (`active-directory/as-rep-roasting.md`).
- Password spraying (`password-attacks/password-spraying.md`).
- Targeted social engineering (real engagements).

## OPSEC Considerations

- Kerbrute pre-auth checks **do not lock accounts** because they don't
  attempt authentication. They are not in the SMB lockout policy path.
- They **do** generate event ID 4768 (Kerberos TGT requested) on the DC.
- Web scraping is local to your box — only the page fetches are
  visible.

## Real HTB Examples

- **Sauna** — entire foothold built on this pattern (web →
  username-anarchy → kerbrute → AS-REP).
- **Sniper** — partial: usernames from web feed back into spray.
- **Multimaster** — names from comments seed username brute.
- **Mantis** — username discovery via NetBIOS / SMB equivalent.

## Alternative Techniques

- LDAP anon (Forest, Cascade) — when anonymous bind is allowed.
- RPC null session (`enumdomusers`) — when RPC null is allowed.
- LinkedIn for real engagements (`linkedin2username`).
- Document metadata (`exiftool`) on PDFs, DOCXs from the site.

## Automation Opportunities

```bash
# one-shot wrapper
curl -s http://<ip>/about.html | grep -oE '\b[A-Z][a-z]+\s+[A-Z][a-z]+\b' \
  | sort -u > names.txt

./username-anarchy -i names.txt > users.txt

./kerbrute userenum --dc <ip> -d <domain> users.txt 2>/dev/null \
  | grep '\[+\]' | awk '{print $5}' | cut -d'@' -f1 > valid-users.txt
```

## Checklist

- [ ] Scrape the public site for names
- [ ] Add names from any email address visible
- [ ] Permute with username-anarchy (or namemash)
- [ ] Validate with kerbrute userenum
- [ ] AS-REPRoast valid users
- [ ] Cautious spray if AS-REP empty

## Related Skills

- [`active-directory/kerberos-username-enumeration.md`](../active-directory/kerberos-username-enumeration.md)
- [`active-directory/as-rep-roasting.md`](../active-directory/as-rep-roasting.md)
- [`password-attacks/password-spraying.md`](../password-attacks/password-spraying.md)
- [`tool-usage/kerbrute.md`](../tool-usage/kerbrute.md)
- [`methodology/07-ad-attack-chains.md`](../methodology/07-ad-attack-chains.md)
