import logging
import os
from pathlib import Path
from typing import ClassVar
from asn1crypto import x509 as asn1_x509
from epa_core.runtime_config.data.konnektor_tls_mode import KonnektorTlsMode
from epa_core.runtime_config.epa_env import EpaEnvs, EpaEnvConfig
from epa_core.runtime_config.logging import setup_logging

# DiGA professionOID - all other OIDs are treated as LE (Leistungserbringer)
# See: gemSpec_OID Tab_PKI_403 (oid_diga = DiGA-Hersteller und -Anbieter)
#   https://gemspec.gematik.de/docs/gemSpec/gemSpec_OID/latest/#polarion___2
DIGA_PROFESSION_OID = '1.2.276.0.76.4.282'

# Mapping of SMC-B professionOID to healthcareFacilityTypeCode
# ProfessionOIDs: gemSpec_OID V3.23.0 Tab_PKI_403 (OID-Festlegung Institutionen im X.509-Zertifikat der SMC-B)
#   https://gemspec.gematik.de/docs/gemSpec/gemSpec_OID/latest/#polarion___2
# FacilityTypeCodes: https://wiki.hl7.de/index.php?title=IG:Value_Sets_f%C3%BCr_XDS#DocumentEntry.healthcareFacilityTypeCode
PROFESSION_OID_TO_FACILITY = {
    '1.2.276.0.76.4.50': 'PRA',   # Betriebsstätte Arzt
    '1.2.276.0.76.4.51': 'PRA',   # Zahnarztpraxis
    '1.2.276.0.76.4.52': 'PRA',   # Betriebsstätte Psychotherapeut
    '1.2.276.0.76.4.53': 'KHS',   # Krankenhaus
    '1.2.276.0.76.4.54': 'APO',   # Öffentliche Apotheke
    '1.2.276.0.76.4.55': 'APO',   # Krankenhausapotheke
    '1.2.276.0.76.4.56': 'APO',   # Bundeswehrapotheke
    '1.2.276.0.76.4.282': 'PAT',  # DiGA-Hersteller und -Anbieter
}

# --- DiGA author/institution generation ---
def is_le() -> bool:
    """Check if the current SMC-B card belongs to a Leistungserbringer (non-DiGA)."""
    return os.getenv('OID_DIGA', DIGA_PROFESSION_OID) != DIGA_PROFESSION_OID

def generate_author() -> str:
    telematik_id = os.getenv('TELEMATIK_ID')
    diga_name = os.getenv('DIGA_NAME')
    diga_manufacturer = os.getenv('DIGA_MANUFACTURER')
    sw_addition_1 = os.getenv('SW_ADDITION_1', '')
    sw_addition_2 = os.getenv('SW_ADDITION_2', '')
    sw_addition_3 = os.getenv('SW_ADDITION_3', '')
    oid_diga = os.getenv('OID_DIGA')

    author = f"{telematik_id}^{diga_name}^{diga_manufacturer}^{sw_addition_1}^{sw_addition_2}^{sw_addition_3}^^^&{oid_diga}&ISO"
    return author

def generate_institution() -> str:
    telematik_id = os.getenv('TELEMATIK_ID')
    diga_manufacturer = os.getenv('DIGA_MANUFACTURER')
    oid_diga = os.getenv('OID_DIGA')

    institution = f"{diga_manufacturer}^^^^^&1.2.276.0.76.4.188&ISO^^^^{telematik_id}"
    return institution

# --- Leistungserbringer (doctor) author/institution generation ---

def generate_author_le() -> str:
    # XCN format per IHE ITI TF-3 §4.2.3.1.7 / gemSpec A_14763-03
    # surName/givenName/title only available in KBV-sector SMC-B certs (Arztpraxis)
    lanr = os.getenv('LANR', '')
    surname = os.getenv('AUTHOR_SURNAME', '') or os.getenv('CERT_SURNAME', '')
    given_name = os.getenv('AUTHOR_GIVEN_NAME', '') or os.getenv('CERT_GIVEN_NAME', '')
    title = os.getenv('AUTHOR_TITLE', '') or os.getenv('CERT_TITLE', '')
    # Assigning authority (LANR registry OID) - only include when LANR is set
    if lanr:
        assigning_authority = "&1.2.276.0.76.4.16&ISO"
    else:
        assigning_authority = ''
    if not surname:
        surname = os.getenv('ORG_NAME', '')
    author = f"{lanr}^{surname}^{given_name}^^^{title}^^^{assigning_authority}"
    return author

def generate_institution_le() -> str:
    # XON format per IHE ITI TF-3 §4.2.3.1.7
    # Assigning authority OID 1.2.276.0.76.4.188 = Telematik-ID domain
    telematik_id = os.getenv('TELEMATIK_ID')
    org_name = os.getenv('ORG_NAME', '')
    institution = f"{org_name}^^^^^&1.2.276.0.76.4.188&ISO^^^^{telematik_id}"
    return institution

def set_telematik_id(telematik_id: str, ):
    os.environ['TELEMATIK_ID'] = telematik_id

def set_cert_author_fields(cert_data):
    """Extract actor type, facility type, and author fields from SMC-B certificate.
    Sets OID_DIGA, HEALTHCARE_FACILITY_TYPE_CODE, ORG_NAME, and CERT_* env vars."""
    # Set professionOID
    profession_oid = cert_data.read_profession_oid()
    os.environ['OID_DIGA'] = profession_oid

    # Map professionOID to healthcareFacilityTypeCode
    facility_code = PROFESSION_OID_TO_FACILITY.get(profession_oid, 'PRA')
    os.environ['HEALTHCARE_FACILITY_TYPE_CODE'] = facility_code
    Config.logger.info(f"SMC-B professionOID: {profession_oid} → mode: {'le' if is_le() else 'diga'}, facility: {facility_code}")

    # LE-specific: extract org name and author fields from certificate
    if is_le():
        try:
            if not os.getenv('ORG_NAME'):
                os.environ['ORG_NAME'] = cert_data.read_organization_name()
        except ValueError:
            Config.logger.warning("Could not read organization name from certificate.")
        for field, env_key in [('read_surname', 'CERT_SURNAME'), ('read_given_name', 'CERT_GIVEN_NAME'), ('read_title', 'CERT_TITLE')]:
            try:
                value = getattr(cert_data, field)()
                if value:
                    os.environ[env_key] = value
            except (AttributeError, ValueError):
                pass

def set_author():
    if 'TELEMATIK_ID' not in os.environ:
        raise ValueError("TELEMATIK_ID not set")
    if is_le():
        os.environ['AUTHOR'] = generate_author_le()
    else:
        if 'DIGA_NAME' not in os.environ:
            raise ValueError("DIGA_NAME not set")
        os.environ['AUTHOR'] = generate_author()

def set_institution():
    if 'TELEMATIK_ID' not in os.environ:
        raise ValueError("TELEMATIK_ID not set")
    if is_le():
        os.environ['INSTITUTION'] = generate_institution_le()
    else:
        if 'DIGA_MANUFACTURER' not in os.environ:
            raise ValueError("DIGA_MANUFACTURER not set")
        os.environ['INSTITUTION'] = generate_institution()

def get_telematik_id() -> str | None:
    if 'TELEMATIK_ID' not in os.environ:
        raise ValueError("TELEMATIK_ID not set")
    return os.getenv('TELEMATIK_ID')

def get_oid_diga() -> str | None:
    if 'OID_DIGA' not in os.environ:
        raise ValueError("OID_DIGA not set")
    return os.getenv('OID_DIGA')

def get_author() -> str | None:
    set_author()
    return os.getenv('AUTHOR')

def get_institution() -> str | None:
    set_institution()
    return os.getenv('INSTITUTION')

def get_author_role() -> str:
    """Return the authorRole slot value based on SMC-B type.
    DiGA: role 12 (dokumentierendes Gerät), LE: role 4 (Durchführender/performer).
    Value set: 1.3.6.1.4.1.19376.3.276.1.5.13 (Prozessrollen für Autoren)
    See: gemILF_PS_ePA §3.12.3 / Anhang B Tab.41
    https://gemspec.gematik.de/docs/gemILF/gemILF_PS_ePA/latest/#A_15621-02
    """
    if is_le():
        return "4^^^&1.3.6.1.4.1.19376.3.276.1.5.13&ISO"
    return "12^^^&1.3.6.1.4.1.19376.3.276.1.5.13&ISO"

def get_as_url(epa_env: EpaEnvConfig, provider_id: str) -> str:
    return epa_env.get_as_url(provider_id)

class Config:
    EPA_ENVIRONMENT: ClassVar[str] = 'RT'

    USER_AGENT: ClassVar[str] = ''

    DIGA_NAME: ClassVar[str] = ''
    DIGA_MANUFACTURER: ClassVar[str] = ''
    SW_ADDITION_1: ClassVar[str] = ''
    SW_ADDITION_2: ClassVar[str] = ''
    SW_ADDITION_3: ClassVar[str] = ''

    MANDANT_ID: ClassVar[str] =''
    CLIENT_SYSTEM_ID: ClassVar[str] = ''
    WORKPLACE_ID: ClassVar[str] = ''
    USER_ID: ClassVar[str] = ''

    KONNEKTOR_CERT_PW: ClassVar[str] = ''
    HTTPS_TIMEOUT: ClassVar[int] = 30

    IDP_AUTH_PATH: ClassVar[str] = "/auth"

    KONNEKTOR_URL: ClassVar[str] = ''
    TI_CA_BUNDLE: ClassVar[str] = ''

    KONNEKTOR_TLS_MODE: ClassVar[str] = KonnektorTlsMode.SMC_K.value
    KONNEKTOR_TLS_HOSTNAME: ClassVar[str | None] = None

    KONNEKTOR_IP: ClassVar[str | None] = None
    KONNEKTOR_CA_BUNDLE: ClassVar[str | None] = None

    TI_PKI_ROOTS_DIR: ClassVar[str] = ''
    TI_TRUST_ROOTS: ClassVar[list[asn1_x509.Certificate]] = []

    USER_CONFIG_DIR: ClassVar[Path] = Path()
    TEMP_DIR: ClassVar[Path] = Path()
    DATA_DIR: ClassVar[Path] = Path()

    LOG_LEVEL: ClassVar[str] = 'INFO'

    logger: ClassVar[logging.Logger] = logging.getLogger()

    @classmethod
    def init(cls, USER_CONFIG_DIR: Path, TEMP_DIR: Path, DATA_DIR: Path):
        from epa_core.truststores.ti.ti_truststore import TI_Truststore
        from epa_core.vau.validator import _load_ti_trust_roots

        cls.USER_CONFIG_DIR = USER_CONFIG_DIR
        cls.TEMP_DIR = TEMP_DIR
        cls.DATA_DIR = DATA_DIR

        # Load environment variables
        cls.LOG_LEVEL = os.getenv("LOG_LEVEL", cls.LOG_LEVEL).upper()
        cls.logger = setup_logging(cls.LOG_LEVEL)


        # Dynamically load RECORD_PROVIDER_X variables from the environment
        cls.RECORD_PROVIDER_MAPPING: dict[str, int] = {}
        for key, value in os.environ.items():
            if key.startswith("RECORD_PROVIDER_"):
                provider_name = value.strip()
                provider_id = key.split("_")[-1]  # Extract the number from the variable name
                cls.RECORD_PROVIDER_MAPPING[provider_name] = int(provider_id)

        cls.EPA_ENVIRONMENT = os.getenv('EPA_ENVIRONMENT', cls.EPA_ENVIRONMENT).upper()
        if cls.EPA_ENVIRONMENT not in EpaEnvs.available_envs():
            raise ValueError(f"Invalid EPA_ENVIRONMENT: {cls.EPA_ENVIRONMENT}. (Available environments are: {', '.join(EpaEnvs.available_envs())})")

        epa_env = EpaEnvs.get(cls.EPA_ENVIRONMENT)

        cls.DEFAULT_EPA_PROVIDER_ID = os.getenv('DEFAULT_EPA_PROVIDER_ID', '2')
        cls.DEFAULT_AS_URL = get_as_url(epa_env, str(cls.DEFAULT_EPA_PROVIDER_ID))
        cls.IDP_URL = epa_env.get_idp_url()

        cls.USER_AGENT = os.getenv('USER_AGENT', cls.USER_AGENT)

        cls.DIGA_NAME = os.getenv('DIGA_NAME', cls.DIGA_NAME)
        cls.DIGA_MANUFACTURER = os.getenv('DIGA_MANUFACTURER', cls.DIGA_MANUFACTURER)
        cls.SW_ADDITION_1 = os.getenv('SW_ADDITION_1', cls.SW_ADDITION_1)
        cls.SW_ADDITION_2 = os.getenv('SW_ADDITION_2', cls.SW_ADDITION_2)
        cls.SW_ADDITION_3 = os.getenv('SW_ADDITION_3', cls.SW_ADDITION_3)

        cls.MANDANT_ID = os.getenv('MANDANT_ID', cls.MANDANT_ID)
        cls.CLIENT_SYSTEM_ID = os.getenv('CLIENT_SYSTEM_ID', cls.CLIENT_SYSTEM_ID)
        cls.WORKPLACE_ID = os.getenv('WORKPLACE_ID', cls.WORKPLACE_ID)
        cls.USER_ID = os.getenv('USER_ID', cls.USER_ID)

        cls.KONNEKTOR_CERT_PW = os.getenv('KONNEKTOR_CERT_PW', cls.KONNEKTOR_CERT_PW)

        cls.HTTPS_TIMEOUT = int(os.getenv('HTTPS_TIMEOUT', cls.HTTPS_TIMEOUT))

        cls.KONNEKTOR_URL = os.getenv('KONNEKTOR_URL', cls.KONNEKTOR_URL)

        if cls.KONNEKTOR_CERT_PW is None:
            raise ValueError("KONNEKTOR_CERT_PW is not set. Please set it in your .env file.")
        if not cls.KONNEKTOR_URL:
            raise ValueError("KONNEKTOR_URL is not set. Please set it in your .env file.")

        # === Loading CA-Bundles from truststores ===
        ti_ts = TI_Truststore(
            ca_path=os.getenv('TI_CA_BUNDLE_PATH', str(cls.TEMP_DIR / 'ti-ca')),
            epa_envs=epa_env,
            provider_mapping=cls.RECORD_PROVIDER_MAPPING,
            https_timeout=cls.HTTPS_TIMEOUT,
        )

        cls.TI_CA_BUNDLE = ti_ts.build_ca_bundle()

        cls.KONNEKTOR_TLS_MODE = os.getenv("KONNEKTOR_TLS_MODE", KonnektorTlsMode.SMC_K.value).lower()
        if cls.KONNEKTOR_TLS_MODE not in [mode.value for mode in KonnektorTlsMode]:
            raise ValueError(f"Invalid KONNEKTOR_TLS_MODE: {cls.KONNEKTOR_TLS_MODE}. Must be one of {[mode.value for mode in KonnektorTlsMode]}.")

        cls.KONNEKTOR_URL = os.getenv('KONNEKTOR_URL', '')
        cls.KONNEKTOR_IP = cls.KONNEKTOR_URL.split("//")[-1].split("/")[0].split(":")[0]  # Extract hostname or IP from URL
        cls.KONNEKTOR_TLS_HOSTNAME = None  # Default: use IP for both connection and TLS verification

        match cls.KONNEKTOR_TLS_MODE:
            case KonnektorTlsMode.ALTERNATIVE.value:
                cls.KONNEKTOR_CA_BUNDLE = os.path.join(cls.USER_CONFIG_DIR, "ssl", "konnektor", "cert.pem")
                if not os.path.isfile(cls.KONNEKTOR_CA_BUNDLE):
                    Config.logger.error(f"KONNEKTOR_TLS_MODE=alternative is set, but the alternative certificate bundle does not exist at {cls.KONNEKTOR_CA_BUNDLE}.")
                    raise FileNotFoundError(f"Alternative certificate bundle not found at {cls.KONNEKTOR_CA_BUNDLE}.")
                Config.logger.warning(
                    f"Konnektor identity verification is ENABLED using existing certificate bundle at {cls.KONNEKTOR_CA_BUNDLE}\n"
                    "To enable automatic refresh via ti-tls, set KONNEKTOR_TLS_MODE to \"smc_k\".\n" 
                    "For that: Be sure to set \"Zertifikat für die Authentisierung\" to \"gSMC-K Zertifikat (ECC)\"."
                )
            case KonnektorTlsMode.SMC_K.value:
                cls.KONNEKTOR_CA_BUNDLE = cls.TI_CA_BUNDLE
                cls.KONNEKTOR_TLS_HOSTNAME = "konnektor.konlan"
                cls.KONNEKTOR_URL = f"https://{cls.KONNEKTOR_TLS_HOSTNAME}"
                Config.logger.info(
                    "Konnektor identity verification is ENABLED using SMC-K certificate bundle."
                )
            case KonnektorTlsMode.INSECURE.value:
                cls.KONNEKTOR_CA_BUNDLE = None
                Config.logger.error(
                    "Konnektor identity verification is EXPLICITLY DISABLED via KONNEKTOR_TLS_MODE=insecure. The service cannot confirm it is talking to the real Konnektor. "
                    "This is insecure and NOT recommended for production use."
                )

        cls.TI_PKI_ROOTS_DIR = ti_ts.get_root_ca_path()

        # Load pinned TI roots once; these are the only certificates we trust as root of trust for chain validation.
        cls.TI_TRUST_ROOTS = _load_ti_trust_roots()

        Config.logger.info(f"""
        Constants loaded:
        EPA_ENVIRONMENT: {cls.EPA_ENVIRONMENT}
        DEFAULT_AS_URL: {cls.DEFAULT_AS_URL}
        USER_AGENT: {cls.USER_AGENT}
        IDP_URL: {cls.IDP_URL}
        KONNEKTOR_URL: {cls.KONNEKTOR_URL}
        LOG_LEVEL: {cls.LOG_LEVEL}
        RECORD_PROVIDER_MAPPING: {cls.RECORD_PROVIDER_MAPPING}
        """)
