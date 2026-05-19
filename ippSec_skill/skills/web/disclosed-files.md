# Disclosed Files / Information Leakage

> Files left in the docroot or accessible to anonymous users that
> reveal credentials, version info, or attack-surface clues. Often
> the entire foothold on appliance and easy-difficulty boxes.

## Objective
Discover and read files in webroots, FTP servers, and SMB shares that
the box's authors (or original developers) left behind.

## When To Use
- After any web fingerprint shows an unusual product or version.
- After any FTP / SMB anonymous channel becomes available.
- Before attempting any complex exploit chain — disclosed files
  frequently *are* the chain.

## Detection Indicators
- gobuster returns `200 OK` for files like `changelog.txt`,
  `readme.txt`, `notes.txt`, `users.txt`, `db_backup.sql`,
  `config.php.bak`, `web.config.old`.
- An FTP / SMB share contains a backup directory.
- A page references a file (`see notes.txt`) without restricting it.

## Common high-value files

| Filename pattern | Why interesting |
|---|---|
| `changelog.txt`, `CHANGELOG.md` | Version + recent fixes (Sense) |
| `readme.txt`, `README.md` | Setup notes, sometimes default creds |
| `notes.txt`, `todo.txt` | Developer/admin reminders, often credentials |
| `system-users.txt` | Username + sometimes password (Sense) |
| `users.csv`, `users.txt` | User list |
| `passwords.txt`, `creds.txt` | Literally credentials |
| `*.bak`, `*.old`, `*.orig`, `*.swp`, `*.~`, `*.1`, `*.save` | Backup of config / source |
| `config.php`, `wp-config.php`, `web.config`, `appsettings.json`, `.env` | Application config with DB creds |
| `database.sql`, `dump.sql`, `*.sql.gz` | Database dump → user/passwords |
| `id_rsa`, `id_dsa`, `*.ppk`, `*.pem` | Private keys |
| `.git/HEAD`, `.svn/entries` | Source code repo exposure |
| `phpinfo.php`, `info.php` | Environment, paths, versions |
| `robots.txt` | Hidden paths |
| `sitemap.xml` | Page enumeration |
| `web.config.bak`, `*.config.old` | IIS / .NET config |
| `Unattend.xml`, `unattended.xml` | Windows deployment creds |
| `Groups.xml`, `Services.xml`, `ScheduledTasks.xml` | GPP cpassword |
| `*.kdbx` | KeePass database |
| `*.vhd`, `*.vmdk` | Virtual disk → mount → SAM |
| `*.pst`, `*.ost` | Outlook data |

## Enumeration Strategy

### Web

```bash
gobuster dir -u http://<ip>/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -x txt,bak,old,zip,sql,cfg,conf,ini,xml,json \
  -t 50 -o gobuster.txt
```

Pay attention to:
- 200 OK responses with very short bodies (often means a tiny but
  important file, like `system-users.txt`).
- 200 OK responses to *any* `.bak`/`.old` request.

### FTP

```bash
ftp <ip>
> user anonymous
> pass <blank>
> ls -la
> recurse on
> mget *
```

### SMB

```bash
smbmap -H <ip>
smbmap -H <ip> -u guest -p ''
smbclient //<ip>/<share> -N -c 'recurse ON; prompt OFF; mget *'
```

## Exploitation Workflow

1. Run baseline gobuster / smbmap / FTP-anon checks.
2. Read every text file in returned hits.
3. For binary backups (`*.bak`, `*.zip`), extract and grep for creds.
4. For DB dumps, look for users / passwords tables.
5. For config files, follow connection strings to other services.

## Commands

```bash
# Grep harvested files
grep -RinE "(pass|pwd|secret|key|cpassword|connection)\s*[:=]" .

# Common one-liners
curl -s http://<ip>/changelog.txt
curl -s http://<ip>/system-users.txt
curl -s http://<ip>/.git/HEAD              # 200 → use git-dumper
curl -s http://<ip>/.env
curl -s http://<ip>/web.config
curl -s http://<ip>/wp-config.php          # often not served literal — try .bak
curl -s http://<ip>/config.php.bak
```

## Tool Usage

- `gobuster` / `feroxbuster` — discovery.
- `git-dumper` — extract `.git/` → full source.
- `wget --mirror --no-parent <url>` — bulk archive of an exposed dir.
- `binwalk` / `strings` — extract from binary backups.
- `7z l <file>` — list archives without extracting.

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Forgetting `.bak`/`.old` extensions | Miss obvious backup | Include them in gobuster `-x` |
| Not reading text files | Skip the answer | Read every TXT/MD/INI hit |
| Not following connection strings | Cred leak ignored | DB user + DB pass = pivot opportunity |
| Treating `.git/HEAD` as just a 200 | Miss the entire source | `git-dumper` to extract |

## Decision-Making Logic

```
gobuster output review:
  ├─ changelog/version → fingerprint version → CVE?
  ├─ users/system-users → username (try default password / spray)
  ├─ *.bak / *.old → download → strings/grep
  ├─ .git/HEAD → git-dumper → full source
  ├─ phpinfo → server paths, env, modules → LFI/RFI feasibility
  ├─ DB backup → extract users/passwords table
  └─ leftover Unattend.xml / Groups.xml → cleartext / cpassword
```

## Pivot Opportunities

Disclosed file content commonly enables:
- Default-credentials login (Sense).
- Auth-bypass of a "secured" admin panel.
- Source code review → vulnerability identification (Cascade analogue).
- Backup file → extracted creds → SSH / SMB pivot.

## OPSEC Considerations
- Reading public files is benign noise on a scan.
- `git-dumper` makes thousands of small requests; rate-limit on real
  engagements.

## Real HTB Examples

- **Sense** — `/changelog.txt` and `/system-users.txt` disclose
  version and `rohit:pfsense`.
- **Bashed** — `/dev/phpbash.php` is a left-behind interactive shell.
- **Curling** — `/user.txt` (literally the flag) accessible.
- **Tally, Networked, Bitlab, Magic** — config files with creds.
- **Bastion** — VHD backup in SMB share → mount → SAM.
- **Bitlab** — `.git/` exposure → source review → pivot.
- **Nineveh** — phpLiteAdmin disclosed.

## Alternative Techniques

- **LFI** to read files outside the docroot (when discovery alone
  doesn't expose them).
- **Source code review** when you find a partial leak (often a config
  file references another file you can request).
- **Wayback Machine** — for real engagements.

## Automation Opportunities

```bash
# baseline appliance recon
URL=http://<ip>
for path in changelog.txt CHANGELOG.md system-users.txt users.txt notes.txt todo.txt readme.txt README.md \
            config.php.bak web.config.bak wp-config.php.bak .env .git/HEAD .svn/entries phpinfo.php \
            backup.zip db.sql; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" $URL/$path)
  [ "$CODE" = "200" ] && echo "$URL/$path  ($CODE)"
done
```

## Checklist

- [ ] gobuster with backup extensions
- [ ] FTP-anon and SMB-anon check
- [ ] Read every text file
- [ ] Extract and grep every binary backup
- [ ] Extract `.git/` if exposed
- [ ] Follow connection strings to other services

## Related Skills

- [`enumeration/web-content-discovery.md`](../enumeration/web-content-discovery.md)
- [`web/default-credentials.md`](default-credentials.md)
- [`active-directory/gpp-cpassword.md`](../active-directory/gpp-cpassword.md)
- [`linux-privesc/credential-reuse.md`](../linux-privesc/credential-reuse.md)
- [`methodology/09-credential-hunting.md`](../methodology/09-credential-hunting.md)
