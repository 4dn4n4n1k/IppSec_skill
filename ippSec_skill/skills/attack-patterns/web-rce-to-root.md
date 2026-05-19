# Attack Pattern — Web RCE → Password Reuse → Lateral User → Root

> The canonical Linux multi-user-box chain. The OpenAdmin pattern.

## Signature

```
nmap → 80 / 443
  → fingerprint app + version → CVE / default-cred / disclosed-files
       → web RCE → www-data shell
            → app config files leak credentials
                 → reuse cred for system account → user shell
                      → repeat enumeration as new user → next pivot
                           → eventually sudo / cron / suid → root
```

## Step-by-step

### 1. Foothold via web RCE

- App fingerprint: `whatweb`, page footer, headers.
- Find exploit: `searchsploit <app>`.
- Adapt payload: see `methodology/11-exploit-adaptation.md` and
  `web/url-encoding-bypass.md`.
- Listener + reverse shell.

### 2. www-data enumeration

```bash
# universal first 60 seconds
id
hostname
uname -a
sudo -l
ls -la ~ /home/* /root 2>/dev/null
```

### 3. Find the app's config

```bash
# common locations
find / -iname "wp-config.php" -o -iname "config.php" \
       -o -iname "database*.inc.php" -o -iname "*.env" \
       -o -iname "settings.py" -o -iname "appsettings*.json" \
       2>/dev/null

cat /opt/<app>/*/config/*
cat /var/www/html/wp-config.php
```

### 4. Try the cred against system accounts

```bash
# enumerate non-system users
cat /etc/passwd | grep /bash | cut -d: -f1 > users.txt
# cred reuse — `su` for each
for u in $(cat users.txt); do echo "$u:"; echo "<pass>" | timeout 3 su -c id "$u" 2>&1; done
```

### 5. Pivot

```bash
su - <user>
Password: <reused-pass>
```

### 6. Re-enumerate as the new user

`sudo -l` first. Then look for:
- Internal services (`ss -tlnp`).
- Files only readable by this user (logs, ssh keys, app data).
- Group-based privilege (e.g., `docker`, `lxd`).

### 7. Repeat until root

The pivot may chain across multiple users. OpenAdmin is
`www-data → jimmy → joanna → root` via three different mechanisms.

## Real HTB Examples

- **OpenAdmin** — full template:
  ONA RCE → `www-data` → DB password in `database_settings.inc.php`
  → reused for `jimmy` → internal `:52846` PHP app prints SSH key
  → crack passphrase → `joanna` → sudo nano → root.

- **Magic** — SQL injection upload → `www-data` → DB cred reuse.

- **Postman** — Redis foothold → SSH key drop → cred reuse.

- **Curling** — disclosed user.txt → password file → password reuse.

- **Networked** — upload bypass → www-data → wildcard cron + arg
  injection.

- **Tabby** — Tomcat manager → war upload → cred from /var/lib/tomcat
  → reuse for SSH.

## Common Mistakes

- Cracking creds you already have plaintext for (no need; reuse first).
- Skipping `ss -tlnp` after pivoting users — internal services
  emerge per-user.
- Trying kernel exploits before `sudo -l`.
- Forgetting `find / -iname "*.conf" 2>/dev/null` for config files.

## Decision-tree

```
new user shell
  └─ sudo -l → endgame?
       Yes → GTFOBins escape → root → done
       No  → enumerate:
            ├─ SUID find / -perm -4000
            ├─ getcap -r /
            ├─ ss -tlnp (new user might see new services)
            ├─ ls -la /home/* /root (readable now?)
            ├─ pspy → cron jobs running as another user
            └─ grep config files for next cred → another pivot
```

## Why this works

In real organisations, developers reuse passwords for development
convenience: the database root password ends up as the system root
password ends up as the SSH passphrase. CTF authors mirror this.

## Related Skills

- [`web/opennetadmin-rce.md`](../web/opennetadmin-rce.md)
- [`web/url-encoding-bypass.md`](../web/url-encoding-bypass.md)
- [`linux-privesc/credential-reuse.md`](../linux-privesc/credential-reuse.md)
- [`linux-privesc/sudo-gtfobins.md`](../linux-privesc/sudo-gtfobins.md)
- [`methodology/06-linux-attack-flow.md`](../methodology/06-linux-attack-flow.md)
- [`methodology/09-credential-hunting.md`](../methodology/09-credential-hunting.md)
