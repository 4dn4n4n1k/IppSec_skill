# Hashcat Reference

> The dominant offline cracker. GPU-accelerated; supports >300 hash
> modes.

## Modes you'll actually use

| Mode | Hash | Source |
|---|---|---|
| 0 | MD5 | weakly-hashed creds |
| 100 | SHA1 | also weak; appears in legacy apps |
| 1000 | NTLM | Windows local + domain hashes |
| 1100 | Domain Cached Credentials (mscash) | Win XP/2003 |
| 2100 | Domain Cached Credentials 2 (mscash2) | Win 7+ |
| 5500 | NetNTLMv1 | responder/old SMB |
| 5600 | NetNTLMv2 | responder modern |
| 7500 | Kerberos AS-REQ Pre-Auth (krb5pa-md5) | rare |
| 13100 | Kerberos 5 TGS-REP etype 23 (Kerberoast) | service tickets |
| 18200 | Kerberos 5 AS-REP etype 23 (AS-REP roast) | pre-auth disabled |
| 1800 | sha512crypt $6$ | `/etc/shadow` modern |
| 500 | md5crypt $1$ | older `/etc/shadow` |
| 3200 | bcrypt $2*$ | Apache htpasswd, modern apps |
| 22000 | WPA-PMKID/EAPOL | wifi |
| 22921 | OpenSSH private key (passphrase) | `ssh2john` output |
| 13400 | KeePass 1/2 | KDBX databases |
| 17200 | PKZIP | zip archives |
| 12500 | RAR3-hp | RAR archives |
| 13600 | 7-Zip | 7z |
| 10000 | Django (PBKDF2-SHA256) | Django apps |
| 1410 | sha256(salt+pass) | apps that prefix-salt |
| 1420 | sha256(pass+salt) | apps that suffix-salt |

If unsure, run `hashid <hash>` or `hash-identifier`.

## Basic syntax

```bash
hashcat -m <mode> <hashfile> <wordlist> [rules]
```

## First-attempt recipes

```bash
# always try rockyou + best64 first
hashcat -m <mode> hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# expand to dive2012 / d3ad0ne / OneRuleToRuleThemAll if best64 fails
hashcat -m <mode> hashes.txt /usr/share/wordlists/rockyou.txt -r OneRuleToRuleThemAll.rule

# bigger wordlists if rockyou+rules failed
hashcat -m <mode> hashes.txt /usr/share/wordlists/SecLists/Passwords/Leaked-Databases/rockyou-75.txt
hashcat -m <mode> hashes.txt /usr/share/wordlists/Hashes.org-2019/Hashes_org_passwords-found_2019.txt
```

## Mask attacks (for derived patterns)

```bash
# 8-character lowercase + digit
hashcat -m <mode> hashes.txt -a 3 ?l?l?l?l?l?l?l?d

# season+year+!  (Spring2024! pattern)
hashcat -m <mode> hashes.txt -a 3 'Spring202?d!'

# capital + 7 lowercase (BankAccount style)
hashcat -m <mode> hashes.txt -a 3 ?u?l?l?l?l?l?l?l
```

Charsets:
- `?l` lowercase, `?u` uppercase, `?d` digit, `?s` symbol, `?a` all,
  `?h` hex lower, `?H` hex upper, `?b` byte.

## Combination

```bash
# wordlist + wordlist (e.g., word + 4-digit year)
hashcat -m <mode> hashes.txt -a 1 wordlist1.txt wordlist2.txt
```

## Show / restore

```bash
# show cracked hashes from previous run
hashcat -m <mode> hashes.txt --show

# resume an interrupted session
hashcat --restore --session=mysession

# new session
hashcat -m 1000 hashes.txt rockyou.txt --session=mysession
```

## Performance flags

```bash
-O                # optimised kernel (assumes pass < 32 chars)
-w 3              # workload profile (3 = high; 4 = nightmare)
--force           # ignore device warnings (for VMs)
--status          # print status updates
-d 1              # use device 1 (for multi-GPU)
```

## Rule files (Kali defaults)

```
/usr/share/hashcat/rules/
  best64.rule
  d3ad0ne.rule
  generated2.rule
  T0XlC.rule
  rockyou-30000.rule
  Incisive-leetspeak.rule
  combinator.rule
  toggles*.rule
```

Recommended progression: `best64` → `d3ad0ne` → `OneRuleToRuleThemAll` →
custom mask.

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Wrong mode | "No hashes loaded" | Run `hashid` first |
| GPU not used | Slow CPU run | `--device-info`; ensure CUDA / OpenCL drivers |
| Extra whitespace in hashfile | "Salt-value exception" | `dos2unix; sed -i 's/[[:space:]]*$//'` |
| `--show` shows nothing | Output file mismatch | Re-run with `-o cracked.txt` then `cat` |
| Hash with leading `:` | NTLM-only | Strip `aad3...:`, keep just NTLM |

## Decision-making

```
got hash → hashid → mode known → 
  rockyou + best64 (~10-30 min)
    cracked? done.
    not cracked? rockyou + d3ad0ne / OneRule
      cracked? done.
      not cracked? larger wordlist (Hashes.org, KaonashI 2020)
        cracked? done.
        not cracked? mask attack (derive pattern from clues)
          cracked? done.
          give up cracking, try pass-the-hash etc.
```

## Real HTB Examples

- **Forest** — `-m 18200` AS-REP → `s3rvice`.
- **Sauna** — `-m 18200` AS-REP → `Thestrokes23`.
- **Active** — `-m 13100` Kerberoast → `Ticketmaster1968`.
- **Jeeves** — `-m 13400` KeePass → `moonshine1`.
- **OpenAdmin** — `-m 100` SHA1 → `Revealed`.
- **Bashed** — usually no cracking; `sudo -u` skips it.

## Related Skills

- [`password-attacks/hash-identification.md`](../password-attacks/hash-identification.md)
- [`tool-usage/john.md`](john.md)
- [`active-directory/as-rep-roasting.md`](../active-directory/as-rep-roasting.md)
- [`active-directory/kerberoasting.md`](../active-directory/kerberoasting.md)
- [`methodology/09-credential-hunting.md`](../methodology/09-credential-hunting.md)
