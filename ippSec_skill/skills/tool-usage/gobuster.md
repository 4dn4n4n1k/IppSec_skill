# Gobuster Reference

> Fast directory / vhost / DNS brute force.

## Modes

```bash
# directory / file fuzz
gobuster dir -u http://<ip>/ -w <wordlist> -x php,html,txt -t 50 -o out.txt

# vhost discovery (HTTP Host: header)
gobuster vhost -u http://<ip>/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# DNS subdomain brute (real engagement; rare on HTB)
gobuster dns -d <domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 50

# S3 bucket discovery
gobuster s3 -w bucket-names.txt
```

## Useful flags

```bash
-x php,html,txt,bak,old,zip                  # extensions
-t 50                                         # threads
-s 200,204,301,302,401,403                    # match statuses
-b 404,500                                    # blacklist statuses
-k                                            # ignore TLS errors (HTTPS)
-c <cookie>                                   # session cookie for auth fuzz
-H "User-Agent: Mozilla/5.0"                  # custom header
-r                                            # follow redirects (default off)
-o out.txt                                    # output file
-z                                            # quiet (less noise)
```

## Recommended wordlists

```
/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt          # default
/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt           # if medium fails
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  # DirBuster classic
/usr/share/seclists/Discovery/Web-Content/quickhits.txt                  # appliances
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt       # vhosts
```

## Decision-Making

```
fuzz with raft-medium + .php,.html,.txt
  ├─ sparse hits → also try .bak,.old,.zip,.config
  ├─ all 200s identical-size (catch-all) → use -s and content-length filter
  ├─ found redirects → manually follow + fuzz target path
  └─ no hits at all → try ffuf with different wordlist / parameter fuzzing
```

## Common Mistakes

- Default `-t 10` → very slow.
- Forgetting `-x` extensions.
- Missing `-k` on HTTPS targets.
- Misreading the redirect target.

## Real HTB Examples

- **Bashed** — finds `/dev/`.
- **OpenAdmin** — finds `/music/` (redirects to `/ona/`).
- **Sense** — finds `/changelog.txt`, `/system-users.txt`.
- **Jeeves** — finds Jenkins paths on port 50000.

## Related

- [`enumeration/web-content-discovery.md`](../enumeration/web-content-discovery.md)
- [`tool-usage/ffuf.md`](ffuf.md)
- [`web/disclosed-files.md`](../web/disclosed-files.md)
