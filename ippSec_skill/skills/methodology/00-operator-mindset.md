# Operator Mindset (IppSec Methodology Synthesis)

> The single most valuable artifact in this corpus. Everything else is a
> specialisation of these heuristics.

Synthesised from cross-cutting patterns observed across the IppSec channel.
Phrased as imperatives the LLM should internalise.

---

## 1. Always read the box, never guess it

You should never be more than one observation away from your next decision.
If you find yourself asking "what should I try next?" the answer is almost
always **enumerate more, not exploit harder**.

> "If your gut says brute force, your enumeration was incomplete." — recurring
> IppSec maxim

Operationally:
- Before launching an exploit, ask: *what specific evidence makes me think
  this exploit applies?* If you cannot name the evidence, stop and enumerate.
- Before brute-forcing creds, ask: *did I check every page, every header,
  every comment, every file share, every LDAP attribute for an existing
  cred?*

## 2. Enumeration is iterative, not linear

Enumeration is not a checklist you complete once. It is a loop:

```
scan → notice anomaly → form hypothesis → targeted scan → repeat
```

Every credential you obtain restarts enumeration with new privileges. Every
shell you obtain restarts enumeration as a new user. Every machine you
compromise restarts enumeration of the network.

## 3. The "cheap shot" priority order

When facing a new service, try things in this order. Each step is roughly
10× cheaper than the next:

1. **Default credentials** (admin/admin, root/root, the vendor default for
   that exact appliance, e.g. `pfSense:pfsense` for Sense)
2. **Anonymous / unauthenticated functions** (SMB null session, FTP
   anonymous, unauthenticated API endpoints, `/etc/passwd` style file reads)
3. **Public exploits matching the exact version** (searchsploit, GitHub)
4. **Configuration disclosure** (`.git`, backup files, `robots.txt`,
   `/sitemap.xml`, exposed admin panels)
5. **Logical flaws** (parameter manipulation, IDOR, race conditions)
6. **Brute force** (always last, often unnecessary, frequently the wrong
   answer in CTF contexts)

## 4. The "name pop-up" rule

Whenever a name, username, hostname, version, path, or string is shown in a
banner, page, comment, or error, **write it down immediately**. CTFs and
real engagements share this property: tiny scraps of identity become
critical inputs three steps later.

Specific patterns where the name matters:
- HTTP `Server:` and `X-Powered-By:` headers
- HTML page footers ("Powered by ...")
- Default usernames in login pages (`admin`, the product's vendor)
- File metadata (`exiftool`, PDF authors)
- Error stack traces (database paths, framework versions)
- LDAP and RPC attributes (`description`, `info`, `comment`)
- AD organisational unit names — they hint at services
- Outlook contact lists scraped from a website (used to seed Kerbrute)

## 5. Three layers of identity

Every machine has three identity layers, and a successful chain almost
always crosses all three:

| Layer | Examples |
|---|---|
| **Public surface** | Banners, page metadata, public comments |
| **Authenticated surface** | Files in shares, app data, internal config |
| **Privileged surface** | Process tokens, registry, SAM, NTDS.dit |

A scrap of evidence at one layer often unlocks the next. *"This password
appears in a `.bak` file → reuse for SSH → process running as another user
→ steal token."*

## 6. Adversarial caching

Catalogue everything as you go, even if it looks unrelated. The discipline
of writing down the unimportant means the important is already there when
you need it. IppSec demonstrates this with Cherrytree and a notes file.

```
notes/<box>/
  recon.md          ← every port, banner, version
  creds.md          ← every username and password ever seen
  paths.md          ← every interesting path on disk
  hashes.md         ← every hash extracted (with format)
  todo.md           ← things to come back to
```

## 7. Read the error messages

Every error tells you the next step. A 200 with "Login failed" tells you the
endpoint exists and accepts your input. A 403 tells you the endpoint exists
but blocks unauthenticated access. A 500 with a stack trace gives you the
framework and probably a file path. A redirect to `/login` tells you the
endpoint is auth-gated.

## 8. Consider the box's purpose

What is the box *for*? An AD server is for AD; treat web only as a
fingerprinting source for usernames. A pfSense box is for filtering, so
default creds are likely the only intended path. A Jenkins instance is for
running arbitrary code on behalf of authenticated users — therefore
unauthenticated access *is* RCE.

## 9. CTF-specific shortcuts

- Easy boxes have a single intended path; if you are deep in a complex
  chain on an easy box, you are probably wrong.
- Insane boxes never have a single intended path; expect 2–4 chained
  primitives.
- The "obvious thing" works on easy boxes and is a red herring on hard
  boxes.
- Old boxes (CVE 2014–2016 era) reward kernel exploits and trivial RCEs;
  new boxes reward ACL abuse and protocol confusion.

## 10. Time-management heuristics

- 30 minutes stuck on enumeration ⇒ change recon angle (different tool,
  different protocol, different verbosity).
- 30 minutes stuck on exploitation ⇒ stop exploiting, return to
  enumeration. The missing input is almost always a misread piece of
  evidence.
- 30 minutes stuck on privesc ⇒ run `linpeas`/`winpeas` again with the
  current shell context (sometimes new permissions appear after token
  changes), then enumerate users you haven't tried becoming yet.

## 11. Always have two parallel tracks

While a long-running scan completes, work on something else. IppSec
characteristically pre-runs nmap before recording, then continues
enumeration of one service while another scan finishes. Concretely:

- nmap full TCP scan in tmux pane 1
- Service-specific enum (gobuster, smbclient, ldapsearch) in pane 2
- Local exploit research / reading source code in pane 3

## 12. Verify, don't trust

When something looks like it worked, prove it worked.
- After uploading a webshell, request it explicitly to confirm execution.
- After a "successful" auth, browse to a known-protected resource to
  confirm session validity.
- After "rooting", run `id` *and* read `/etc/shadow` *and* read
  `/root/root.txt`.

## 13. Don't fight the process; understand it

The most common stuck-state in IppSec videos is "the exploit didn't fire".
The fix is almost never a different exploit; it is reading the exploit's
source to understand what input it actually expects. Read tools and
exploits as if they were written by someone who didn't anticipate your
exact target.

---

## See also

- [01-initial-foothold.md](01-initial-foothold.md)
- [02-enumeration-first.md](02-enumeration-first.md)
- [03-service-prioritization.md](03-service-prioritization.md)
- [11-exploit-adaptation.md](11-exploit-adaptation.md)
