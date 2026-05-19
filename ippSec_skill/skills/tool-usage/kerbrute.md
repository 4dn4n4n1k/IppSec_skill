# Kerbrute Reference

> Fast, multithreaded Kerberos username/password brute-forcer. The
> tool of choice for AD username discovery without LDAP/RPC.

## Install

```bash
wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 -O kerbrute
chmod +x kerbrute
```

## Modes

```bash
# username enumeration — does NOT lock accounts
./kerbrute userenum --dc <dc-ip> -d <DOMAIN> users.txt

# password spray (one password vs many users) — careful, locks accounts
./kerbrute passwordspray --dc <dc-ip> -d <DOMAIN> users.txt 'Welcome1!'

# bruteforce one user with many passwords
./kerbrute bruteuser --dc <dc-ip> -d <DOMAIN> passwords.txt <user>

# combination userlist (`user:pass` per line)
./kerbrute bruteforce --dc <dc-ip> -d <DOMAIN> combo.txt
```

## Threads / output

```bash
./kerbrute userenum --dc <ip> -d <DOMAIN> users.txt -t 30 -o results.txt
```

`-o` saves matches; `-t` is thread count (default 10).

## Common Mistakes

- Forget `--dc` — tool can't reach the KDC.
- Realm casing — typically UPPERCASE.
- Wordlist contains domain suffix (`@DOMAIN`) — strip it.
- Password spray during business hours / aggressive threads → lockouts.

## Real HTB Examples

- **Sauna** — userenum after web-scrape username permutation.
- **Forest** — userenum used as fallback (RPC null worked).
- **Multimaster, Resolute, Sniper** — userenum plus targeted spray.

## Related

- [`active-directory/kerberos-username-enumeration.md`](../active-directory/kerberos-username-enumeration.md)
- [`enumeration/website-username-harvest.md`](../enumeration/website-username-harvest.md)
- [`active-directory/as-rep-roasting.md`](../active-directory/as-rep-roasting.md)
