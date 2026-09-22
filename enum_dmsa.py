#!/usr/bin/env python3
"""
Enumerate DMSA objects and their security-relevant attributes via LDAP.
Handles LDAP signing requirements on Server 2025.

Usage:
  python3 enum_dmsa_ldap.py                          # Use defaults
  python3 enum_dmsa_ldap.py -u bob.marley -p 'P@ssw0rd!'  # Low-priv enum
  python3 enum_dmsa_ldap.py -u administrator -p 'pass'     # Full enum with ACLs
"""

import argparse
import ssl
import struct
import sys
from binascii import hexlify

from ldap3 import (Server, Connection, ALL, NTLM, SUBTREE, BASE, Tls)
from ldap3.protocol.microsoft import security_descriptor_control


DC_IP = '192.168.15.171'
DOMAIN = 'cve.local'


WELL_KNOWN_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-5-10": "SELF",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "SYSTEM",
    "S-1-3-0": "CREATOR OWNER",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-548": "Account Operators",
}

WELL_KNOWN_RIDS = {
    500: 'Administrator', 502: 'krbtgt',
    512: 'Domain Admins', 513: 'Domain Users',
    515: 'Domain Computers', 516: 'Domain Controllers',
    518: 'Schema Admins', 519: 'Enterprise Admins',
}


def format_sid(sid_bytes):
    if not sid_bytes or len(sid_bytes) < 8:
        return "INVALID"
    rev = sid_bytes[0]
    sub_count = sid_bytes[1]
    auth = int.from_bytes(sid_bytes[2:8], 'big')
    subs = []
    for i in range(sub_count):
        off = 8 + i * 4
        if off + 4 > len(sid_bytes):
            break
        subs.append(struct.unpack_from('<L', sid_bytes, off)[0])
    return "S-%d-%d-%s" % (rev, auth, "-".join(str(s) for s in subs))


def resolve_sid(conn, domain_dn, domain_sid, sid_str):
    if sid_str in WELL_KNOWN_SIDS:
        return WELL_KNOWN_SIDS[sid_str]
    if domain_sid and sid_str.startswith(domain_sid + '-'):
        rid = int(sid_str.split('-')[-1])
        if rid in WELL_KNOWN_RIDS:
            return WELL_KNOWN_RIDS[rid]
        conn.search(domain_dn, '(objectSid=%s)' % sid_str, SUBTREE,
                    attributes=['sAMAccountName'])
        if conn.entries:
            return conn.entries[0]['sAMAccountName'].value
    return sid_str


def parse_sd_aces(sd_bytes, conn, domain_dn, domain_sid):
    """Parse a security descriptor and return ACE details."""
    if not sd_bytes or len(sd_bytes) < 20:
        return []

    revision = sd_bytes[0]
    control = struct.unpack_from('<H', sd_bytes, 2)[0]
    offset_owner = struct.unpack_from('<L', sd_bytes, 4)[0]
    offset_group = struct.unpack_from('<L', sd_bytes, 8)[0]
    offset_sacl = struct.unpack_from('<L', sd_bytes, 12)[0]
    offset_dacl = struct.unpack_from('<L', sd_bytes, 16)[0]

    aces = []

    if offset_owner and offset_owner < len(sd_bytes):
        owner_sid = format_sid(sd_bytes[offset_owner:])
        owner_name = resolve_sid(conn, domain_dn, domain_sid, owner_sid)
        aces.append(('OWNER', owner_name, owner_sid, ''))

    if not offset_dacl or offset_dacl >= len(sd_bytes):
        aces.append(('NO_DACL', '', '', 'No DACL = ALLOW ALL'))
        return aces

    dacl_rev = sd_bytes[offset_dacl]
    dacl_size = struct.unpack_from('<H', sd_bytes, offset_dacl + 2)[0]
    ace_count = struct.unpack_from('<H', sd_bytes, offset_dacl + 4)[0]

    pos = offset_dacl + 8
    for _ in range(ace_count):
        if pos + 4 > len(sd_bytes):
            break
        ace_type = sd_bytes[pos]
        ace_flags = sd_bytes[pos + 1]
        ace_size = struct.unpack_from('<H', sd_bytes, pos + 2)[0]

        if ace_type == 0:  # ACCESS_ALLOWED_ACE
            mask = struct.unpack_from('<L', sd_bytes, pos + 4)[0]
            sid = format_sid(sd_bytes[pos + 8:pos + ace_size])
            name = resolve_sid(conn, domain_dn, domain_sid, sid)
            rights = []
            if mask & 0x10000000: rights.append('GENERIC_ALL')
            if mask & 0x80000000: rights.append('GENERIC_READ')
            if mask & 0x40000000: rights.append('GENERIC_WRITE')
            if mask & 0x20000000: rights.append('GENERIC_EXECUTE')
            if mask & 0x10: rights.append('READ_PROP')
            if mask & 0x20: rights.append('WRITE_PROP')
            if mask & 0x1F01FF: rights.append('FULL_CONTROL')
            aces.append(('ALLOW', name, sid, '|'.join(rights) if rights else '0x%x' % mask))

        elif ace_type == 5:  # ACCESS_ALLOWED_OBJECT_ACE
            mask = struct.unpack_from('<L', sd_bytes, pos + 4)[0]
            obj_flags = struct.unpack_from('<L', sd_bytes, pos + 8)[0]
            guid_offset = pos + 12
            if obj_flags & 1:
                guid_offset += 16
            if obj_flags & 2:
                guid_offset += 16
            sid = format_sid(sd_bytes[guid_offset:pos + ace_size])
            name = resolve_sid(conn, domain_dn, domain_sid, sid)
            aces.append(('ALLOW_OBJ', name, sid, '0x%x' % mask))

        pos += ace_size

    return aces


def connect_ldap(dc_ip, domain, username, password):
    """Connect via LDAPS (handles Server 2025 signing requirement)."""
    tls_config = Tls(validate=ssl.CERT_NONE)

    # Try LDAPS first (Server 2025 enforces signing)
    try:
        s = Server('ldaps://%s:636' % dc_ip, get_info=ALL, tls=tls_config)
        c = Connection(s, user='%s\\%s' % (domain, username), password=password,
                       authentication=NTLM, auto_bind=True)
        print('[+] Connected via LDAPS (636)')
        return c
    except Exception as e:
        print('[*] LDAPS failed: %s' % str(e)[:60])

    # Fall back to LDAP
    try:
        s = Server('ldap://%s:389' % dc_ip, get_info=ALL)
        c = Connection(s, user='%s\\%s' % (domain, username), password=password,
                       authentication=NTLM, auto_bind=True)
        print('[+] Connected via LDAP (389)')
        return c
    except Exception as e:
        print('[-] LDAP failed: %s' % str(e)[:60])
        return None


def get_domain_sid(conn, domain_dn):
    conn.search(domain_dn, '(objectClass=domain)', BASE, attributes=['objectSid'])
    if conn.entries:
        return format_sid(conn.entries[0]['objectSid'].raw_values[0])
    return None


def enum_dmsa(conn, domain_dn, domain_sid, verbose=False):
    """Enumerate all DMSA objects."""
    print('\n' + '=' * 70)
    print('  DMSA ENUMERATION')
    print('=' * 70)

    # Search for DMSAs by objectClass
    dmsa_filter = '(objectClass=msDS-DelegatedManagedServiceAccount)'
    dmsa_attrs = [
        'cn', 'sAMAccountName', 'distinguishedName', 'objectClass', 'objectSid',
        'userAccountControl', 'dNSHostName',
        'msDS-DelegatedMSAState',
        'msDS-ManagedAccountPrecededByLink',
        'msDS-GroupMSAMembership',
        'msDS-ManagedPasswordId',
        'msDS-ManagedPasswordInterval',
        'msDS-SupportedEncryptionTypes',
        'servicePrincipalName',
        'whenCreated', 'whenChanged',
    ]

    conn.search(domain_dn, dmsa_filter, SUBTREE, attributes=dmsa_attrs,
                controls=security_descriptor_control(sdflags=0x07))
    dmsas = list(conn.entries)

    if not dmsas:
        print('\n  No DMSA objects found.')
        print('  Filter used: %s' % dmsa_filter)

        # Try alternate: search for objects with DelegatedMSAState attribute
        alt_filter = '(msDS-DelegatedMSAState=*)'
        conn.search(domain_dn, alt_filter, SUBTREE, attributes=dmsa_attrs)
        dmsas = list(conn.entries)
        if dmsas:
            print('  Found %d objects with msDS-DelegatedMSAState (alternate filter)' % len(dmsas))
        else:
            print('  No objects with msDS-DelegatedMSAState either.')
            return []

    print('\n  Found %d DMSA(s):\n' % len(dmsas))

    results = []
    for entry in dmsas:
        print('  ' + '-' * 60)
        sam = entry['sAMAccountName'].value if 'sAMAccountName' in entry else '?'
        dn = entry.entry_dn
        sid = format_sid(entry['objectSid'].raw_values[0]) if 'objectSid' in entry and entry['objectSid'].raw_values else '?'
        state = entry['msDS-DelegatedMSAState'].value if 'msDS-DelegatedMSAState' in entry else 'N/A'
        preceded = entry['msDS-ManagedAccountPrecededByLink'].value if 'msDS-ManagedAccountPrecededByLink' in entry else 'N/A'
        uac = entry['userAccountControl'].value if 'userAccountControl' in entry else 'N/A'
        dns_host = entry['dNSHostName'].value if 'dNSHostName' in entry else 'N/A'
        pw_interval = entry['msDS-ManagedPasswordInterval'].value if 'msDS-ManagedPasswordInterval' in entry else 'N/A'
        enc_types = entry['msDS-SupportedEncryptionTypes'].value if 'msDS-SupportedEncryptionTypes' in entry else 'N/A'
        created = entry['whenCreated'].value if 'whenCreated' in entry else 'N/A'
        changed = entry['whenChanged'].value if 'whenChanged' in entry else 'N/A'
        has_pw_id = bool(entry['msDS-ManagedPasswordId'].raw_values) if 'msDS-ManagedPasswordId' in entry else False
        spns = entry['servicePrincipalName'].values if 'servicePrincipalName' in entry else []
        obj_classes = entry['objectClass'].values if 'objectClass' in entry else []

        state_names = {0: 'NotConfigured', 1: 'Pending', 2: 'Started', 3: 'Completed'}
        state_str = state_names.get(int(state), str(state)) if state != 'N/A' else 'N/A'

        enabled = 'Yes' if uac != 'N/A' and not (int(uac) & 2) else 'No/Unknown'

        print('  sAMAccountName:         %s' % sam)
        print('  DN:                     %s' % dn)
        print('  SID:                    %s' % sid)
        print('  objectClass:            %s' % ' → '.join(obj_classes))
        print('  DelegatedMSAState:      %s (%s)' % (state, state_str))
        print('  PrecededByLink:         %s' % preceded)
        print('  Enabled:                %s (UAC: %s)' % (enabled, uac))
        print('  DNS Hostname:           %s' % dns_host)
        print('  ManagedPasswordId:      %s' % ('SET' if has_pw_id else 'NOT SET'))
        print('  ManagedPasswordInterval: %s days' % pw_interval)
        print('  EncryptionTypes:        %s' % enc_types)
        print('  SPNs:                   %s' % (', '.join(spns) if spns else 'None'))
        print('  Created:                %s' % created)
        print('  Changed:                %s' % changed)

        # Check superseded account
        if preceded and preceded != 'N/A':
            print('\n  SUPERSEDED ACCOUNT:')
            target_filter = '(distinguishedName=%s)' % preceded
            conn.search(domain_dn, target_filter, SUBTREE,
                        attributes=['sAMAccountName', 'objectSid', 'memberOf',
                                    'userAccountControl',
                                    'msDS-SupersededManagedAccountLink'])
            if conn.entries:
                target = conn.entries[0]
                t_sam = target['sAMAccountName'].value
                t_sid = format_sid(target['objectSid'].raw_values[0])
                t_uac = target['userAccountControl'].value if 'userAccountControl' in target else 'N/A'
                t_enabled = 'Yes' if t_uac != 'N/A' and not (int(t_uac) & 2) else 'No'
                t_groups = target['memberOf'].values if 'memberOf' in target else []

                print('    Account:     %s (%s)' % (t_sam, t_sid))
                print('    Enabled:     %s' % t_enabled)
                print('    Groups:      %s' % (', '.join(g.split(',')[0].replace('CN=', '') for g in t_groups) if t_groups else 'None'))

                # Check reverse link
                try:
                    succeeded = target['msDS-SupersededManagedAccountLink'].values
                    has_reverse = any(sam.rstrip('$') in str(v) for v in succeeded)
                    print('    ReverseLink: %s (SucceededManagedAccountLink)' % succeeded)
                    print('    BIDIRECTIONAL: %s' % ('YES' if has_reverse else 'NO — UNILATERAL!'))
                except:
                    print('    ReverseLink: NOT SET — UNILATERAL LINK!')

                # Check if superseded account is privileged
                priv_groups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins',
                               'Administrators']
                is_priv = any(any(pg in g for pg in priv_groups) for g in t_groups)
                rid = int(t_sid.split('-')[-1])
                if rid == 500:
                    is_priv = True
                if is_priv:
                    print('    [!!!] SUPERSEDED ACCOUNT IS PRIVILEGED')
                    print('    [!!!] DMSA S4U will inherit admin group SIDs')

        # Parse GroupMSAMembership SD
        if 'msDS-GroupMSAMembership' in entry and entry['msDS-GroupMSAMembership'].raw_values:
            gmsa_sd = entry['msDS-GroupMSAMembership'].raw_values[0]
            print('\n  GroupMSAMembership (who can read DMSA password):')
            aces = parse_sd_aces(gmsa_sd, conn, domain_dn, domain_sid)
            for ace_type, name, sid, rights in aces:
                if ace_type == 'OWNER':
                    print('    Owner: %s (%s)' % (name, sid))
                elif ace_type == 'NO_DACL':
                    print('    [!!!] NO DACL — ANYONE CAN ACCESS!')
                else:
                    print('    %s: %s (%s) — %s' % (ace_type, name, sid, rights))
        else:
            print('\n  GroupMSAMembership: NOT SET')
            print('  [!] Empty SD — check KDC behavior (null SD may allow or deny all)')

        results.append({
            'sam': sam, 'dn': dn, 'sid': sid, 'state': state,
            'preceded_by': preceded, 'enabled': enabled,
        })
        print()

    return results


def enum_superseded(conn, domain_dn):
    """Find accounts that have a SucceededByLink (are superseded by a DMSA)."""
    print('\n' + '=' * 70)
    print('  ACCOUNTS WITH SucceededManagedAccountLink (superseded by a DMSA)')
    print('=' * 70)

    conn.search(domain_dn, '(msDS-SupersededManagedAccountLink=*)', SUBTREE,
                attributes=['sAMAccountName', 'objectSid', 'userAccountControl',
                            'memberOf', 'msDS-SupersededManagedAccountLink'])

    if not conn.entries:
        # Try the reverse: look at PrecededByLink targets
        print('\n  No accounts with SucceededManagedAccountLink found.')
        print('  (The link may be computed/backlink rather than stored.)')
        return

    for entry in conn.entries:
        sam = entry['sAMAccountName'].value
        link = entry['msDS-SupersededManagedAccountLink'].values
        print('\n  %s — superseded by: %s' % (sam, link))


def enum_msa_container(conn, domain_dn, domain_sid):
    """Check permissions on the Managed Service Accounts container."""
    print('\n' + '=' * 70)
    print('  MANAGED SERVICE ACCOUNTS CONTAINER ACL')
    print('=' * 70)

    msa_dn = 'CN=Managed Service Accounts,%s' % domain_dn
    conn.search(msa_dn, '(objectClass=*)', BASE,
                attributes=['nTSecurityDescriptor', 'cn'],
                controls=security_descriptor_control(sdflags=0x07))

    if not conn.entries:
        print('\n  Container not found or not accessible.')
        return

    sd_raw = conn.entries[0]['nTSecurityDescriptor'].raw_values[0]
    print('\n  DN: %s' % msa_dn)
    print('  ACEs:')
    aces = parse_sd_aces(sd_raw, conn, domain_dn, domain_sid)
    for ace_type, name, sid, rights in aces:
        print('    %s: %s (%s) — %s' % (ace_type, name, sid, rights))


def check_maq(conn, domain_dn):
    """Check MachineAccountQuota."""
    print('\n' + '=' * 70)
    print('  MachineAccountQuota')
    print('=' * 70)

    conn.search(domain_dn, '(objectClass=domain)', BASE,
                attributes=['ms-DS-MachineAccountQuota'])
    if conn.entries:
        maq = conn.entries[0]['ms-DS-MachineAccountQuota'].value
        print('\n  ms-DS-MachineAccountQuota: %s' % maq)
        if maq and int(maq) > 0:
            print('  [!] Any domain user can create up to %s computer accounts' % maq)
            print('  [!] If computer → DMSA conversion is possible, this is Any User → DA')
    else:
        print('\n  Could not read MachineAccountQuota')


def main():
    parser = argparse.ArgumentParser(description='Enumerate DMSA objects via LDAP')
    parser.add_argument('-u', '--username', default='bob.marley')
    parser.add_argument('-p', '--password', default='P@ssw0rd!')
    parser.add_argument('--dc-ip', default=DC_IP)
    parser.add_argument('--domain', default=DOMAIN)
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    domain_dn = ','.join('DC=%s' % p for p in args.domain.split('.'))

    print('DMSA LDAP Enumeration')
    print('DC: %s, User: %s\\%s' % (args.dc_ip, args.domain, args.username))

    conn = connect_ldap(args.dc_ip, args.domain, args.username, args.password)
    if not conn:
        print('[-] Could not connect to LDAP')
        sys.exit(1)

    domain_sid = get_domain_sid(conn, domain_dn)
    print('[+] Domain SID: %s' % domain_sid)

    enum_dmsa(conn, domain_dn, domain_sid, args.verbose)
    enum_superseded(conn, domain_dn)
    enum_msa_container(conn, domain_dn, domain_sid)
    check_maq(conn, domain_dn)

    conn.unbind()

    print('\n' + '=' * 70)
    print('  BLOODHOUND NOTE')
    print('=' * 70)
    print("""
  BloodHound does NOT natively support DMSAs (Server 2025 feature).
  SharpHound and bloodhound-python collectors do not collect:
    - msDS-DelegatedManagedServiceAccount objectClass
    - msDS-DelegatedMSAState
    - msDS-ManagedAccountPrecededByLink
    - msDS-GroupMSAMembership (for DMSAs)

  To add DMSA visibility to BloodHound, you would need to:
    1. Add a custom node type for DMSAs
    2. Add edges for GroupMSAMembership (CanRetrieveDMSAPassword)
    3. Add edges for PrecededByLink (Supersedes)
    4. Mark the escalation path: CanRetrieveDMSAPassword + Supersedes → DA

  For now, use this script or raw LDAP queries:
    # Find all DMSAs:
    (objectClass=msDS-DelegatedManagedServiceAccount)

    # Find DMSAs superseding specific accounts:
    (msDS-ManagedAccountPrecededByLink=CN=Administrator,CN=Users,DC=cve,DC=local)

    # Find DMSAs in a specific state:
    (msDS-DelegatedMSAState=2)   # Started
    (msDS-DelegatedMSAState=3)   # Completed
""")


if __name__ == '__main__':
    main()
