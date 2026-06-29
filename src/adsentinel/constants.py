"""Well-known constants for Active Directory security assessment."""

# ============================================================================
# User Account Control (UAC) Flags
# ============================================================================
UAC_ACCOUNTDISABLE = 0x0002
UAC_LOCKOUT = 0x0010
UAC_PASSWD_NOTREQD = 0x0020
UAC_PASSWD_CANT_CHANGE = 0x0040
UAC_ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080
UAC_NORMAL_ACCOUNT = 0x0200
UAC_DONT_EXPIRE_PASSWD = 0x10000
UAC_SMARTCARD_REQUIRED = 0x40000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_NOT_DELEGATED = 0x100000
UAC_USE_DES_KEY_ONLY = 0x200000
UAC_DONT_REQ_PREAUTH = 0x400000
UAC_PASSWORD_EXPIRED = 0x800000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
UAC_NO_AUTH_DATA_REQUIRED = 0x2000000

# ============================================================================
# Well-Known SIDs
# ============================================================================
WELL_KNOWN_SIDS = {
    "S-1-0-0": "Nobody",
    "S-1-1-0": "Everyone",
    "S-1-5-7": "Anonymous Logon",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "SYSTEM",
    "S-1-5-19": "LOCAL SERVICE",
    "S-1-5-20": "NETWORK SERVICE",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-552": "BUILTIN\\Replicator",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
}

# Domain-relative RIDs for privileged groups
RID_DOMAIN_ADMINS = 512
RID_DOMAIN_USERS = 513
RID_DOMAIN_COMPUTERS = 515
RID_DOMAIN_CONTROLLERS = 516
RID_SCHEMA_ADMINS = 518
RID_ENTERPRISE_ADMINS = 519
RID_GROUP_POLICY_CREATOR_OWNERS = 520
RID_PROTECTED_USERS = 525
RID_KEY_ADMINS = 526
RID_ENTERPRISE_KEY_ADMINS = 527
RID_KRBTGT = 502
RID_ADMINISTRATOR = 500

PRIVILEGED_GROUP_RIDS = {
    RID_DOMAIN_ADMINS,
    RID_SCHEMA_ADMINS,
    RID_ENTERPRISE_ADMINS,
    RID_GROUP_POLICY_CREATOR_OWNERS,
    RID_KEY_ADMINS,
    RID_ENTERPRISE_KEY_ADMINS,
}

# ============================================================================
# Well-Known GUIDs (AD Schema Rights)
# ============================================================================
GUID_DS_REPL_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPL_GET_CHANGES_IN_FILTERED_SET = "89e95b76-444d-4c62-991a-0facbeda640c"
GUID_USER_FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
GUID_WRITE_MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"
GUID_SELF_MEMBERSHIP = "bf9679c0-0de6-11d0-a285-00aa003049e2"
GUID_VALIDATED_WRITE_TO_SPN = "f3a64788-5306-11d1-a9c5-0000f80367c1"
GUID_VALIDATED_WRITE_TO_DNS = "72e39547-7b18-11d1-adef-00c04fd8d5cd"
GUID_MS_DS_KEY_CREDENTIAL_LINK = "5b47d60f-6090-40b2-9f37-2a4de88f3063"
GUID_USER_ACCOUNT_RESTRICTIONS = "4c164200-20c0-11d0-a768-00aa006e0529"

# ============================================================================
# Access Mask Constants
# ============================================================================
ADS_RIGHT_GENERIC_ALL = 0x10000000
ADS_RIGHT_GENERIC_WRITE = 0x40000000
ADS_RIGHT_GENERIC_READ = 0x80000000
ADS_RIGHT_WRITE_DAC = 0x00040000
ADS_RIGHT_WRITE_OWNER = 0x00080000
ADS_RIGHT_DS_CREATE_CHILD = 0x00000001
ADS_RIGHT_DS_DELETE_CHILD = 0x00000002
ADS_RIGHT_DS_READ_PROP = 0x00000010
ADS_RIGHT_DS_WRITE_PROP = 0x00000020
ADS_RIGHT_DS_SELF = 0x00000008
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100

# Dangerous permissions that enable privilege escalation
DANGEROUS_PERMISSIONS = {
    ADS_RIGHT_GENERIC_ALL: "GenericAll",
    ADS_RIGHT_GENERIC_WRITE: "GenericWrite",
    ADS_RIGHT_WRITE_DAC: "WriteDACL",
    ADS_RIGHT_WRITE_OWNER: "WriteOwner",
}

# ============================================================================
# Domain Functional Levels
# ============================================================================
FUNCTIONAL_LEVELS = {
    0: "Windows 2000",
    1: "Windows Server 2003 Mixed",
    2: "Windows Server 2003",
    3: "Windows Server 2008",
    4: "Windows Server 2008 R2",
    5: "Windows Server 2012",
    6: "Windows Server 2012 R2",
    7: "Windows Server 2016",
    8: "Windows Server 2019",
    9: "Windows Server 2022",
    10: "Windows Server 2025",
}

# ============================================================================
# Certificate Template / AD CS Constants
# ============================================================================
# Certificate Name Flags
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000

# Private Key Flags (msPKI-Private-Key-Flag)
CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL = 0x00000010  # ESC12: CA must archive the private key

# Enrollment Flags
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002
CT_FLAG_AUTO_ENROLLMENT = 0x00000020

# Extended Key Usage OIDs
EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_SMART_CARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
EKU_ANY_PURPOSE = "2.5.29.37.0"
EKU_CERTIFICATE_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
EKU_PKIX_KP_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"

# CA Flags
EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
IF_ENFORCEENCRYPTICERTREQUEST = 0x00000200

# ============================================================================
# MITRE ATT&CK Technique IDs (commonly referenced)
# ============================================================================
MITRE_KERBEROASTING = "T1558.003"
MITRE_ASREP_ROASTING = "T1558.004"
MITRE_GOLDEN_TICKET = "T1558.001"
MITRE_SILVER_TICKET = "T1558.002"
MITRE_DCSYNC = "T1003.006"
MITRE_PASS_THE_HASH = "T1550.002"
MITRE_PASS_THE_TICKET = "T1550.003"
MITRE_UNCONSTRAINED_DELEGATION = "T1558"
MITRE_FORCED_AUTH = "T1187"
MITRE_STEAL_OR_FORGE_CERTS = "T1649"
MITRE_ACCOUNT_MANIPULATION = "T1098"
MITRE_GROUP_POLICY_MODIFICATION = "T1484.001"
MITRE_PERMISSION_GROUPS_DISCOVERY = "T1069.002"
MITRE_BRUTE_FORCE = "T1110"
MITRE_PASSWORD_SPRAYING = "T1110.003"
MITRE_NTLM_RELAY = "T1557.001"

# ============================================================================
# Default Thresholds
# ============================================================================
DEFAULT_PASSWORD_MIN_LENGTH = 14
DEFAULT_LOCKOUT_THRESHOLD = 5
DEFAULT_PASSWORD_HISTORY = 24
DEFAULT_MAX_PASSWORD_AGE_DAYS = 90
DEFAULT_KRBTGT_MAX_AGE_DAYS = 180
DEFAULT_STALE_DAYS = 90
DEFAULT_MACHINE_ACCOUNT_QUOTA = 0  # Best practice is 0
