import os

from app import USER_CONFIG_DIR, TEMP_DIR
from app.runtime_config.logging import logger, LOG_LEVEL
from app.runtime_config.epa_env import EpaEnvs
from app.truststores.ti.ti_truststore import TI_Truststore
from app.konnektor.pkcs12adapter import find_p12
from app.runtime_config.data.konnektor_tls_mode import KonnektorTlsMode

# Dynamically load RECORD_PROVIDER_X variables from the environment
RECORD_PROVIDER_MAPPING: dict[str, int] = {}
for key, value in os.environ.items():
    if key.startswith("RECORD_PROVIDER_"):
        provider_name = value.strip()
        provider_id = key.split("_")[-1]  # Extract the number from the variable name
        RECORD_PROVIDER_MAPPING[provider_name] = int(provider_id)


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

def is_le() -> bool:
    """Check if the current SMC-B card belongs to a Leistungserbringer (non-DiGA)."""
    return os.getenv('OID_DIGA', DIGA_PROFESSION_OID) != DIGA_PROFESSION_OID

# --- DiGA author/institution generation ---

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
    logger.info(f"SMC-B professionOID: {profession_oid} → mode: {'le' if is_le() else 'diga'}, facility: {facility_code}")

    # LE-specific: extract org name and author fields from certificate
    if is_le():
        try:
            if not os.getenv('ORG_NAME'):
                os.environ['ORG_NAME'] = cert_data.read_organization_name()
        except ValueError:
            logger.warning("Could not read organization name from certificate.")
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

EPA_ENVIRONMENT = os.getenv('EPA_ENVIRONMENT', 'RT').upper()
if EPA_ENVIRONMENT not in EpaEnvs.available_envs():
    raise ValueError(f"Invalid EPA_ENVIRONMENT: {EPA_ENVIRONMENT}. (Available environments are: {', '.join(EpaEnvs.available_envs())})")

epa_envs = EpaEnvs.get(EPA_ENVIRONMENT)

def get_as_url(provider_id: str) -> str:
    return epa_envs.get_as_url(provider_id)

DEFAULT_EPA_PROVIDER_ID = os.getenv('DEFAULT_EPA_PROVIDER_ID', '2')
DEFAULT_AS_URL = get_as_url(str(DEFAULT_EPA_PROVIDER_ID))
IDP_URL = epa_envs.get_idp_url()

USER_AGENT = os.getenv('USER_AGENT')

DIGA_NAME = os.getenv('DIGA_NAME')
DIGA_MANUFACTURER = os.getenv('DIGA_MANUFACTURER')
SW_ADDITION_1 = os.getenv('SW_ADDITION_1')
SW_ADDITION_2 = os.getenv('SW_ADDITION_2')
SW_ADDITION_3 = os.getenv('SW_ADDITION_3')

MANDANT_ID = os.getenv('MANDANT_ID')
CLIENT_SYSTEM_ID = os.getenv('CLIENT_SYSTEM_ID')
WORKPLACE_ID = os.getenv('WORKPLACE_ID')
USER_ID = os.getenv('USER_ID')

KONNEKTOR_CERT_PW = os.getenv('KONNEKTOR_CERT_PW')

# Insecure override: only use insecure mode if no valid CA bundle is available.
ENABLE_SMC_K_TLS_VERIFICATION = os.getenv("ENABLE_SMC_K_TLS_VERIFICATION", "false").lower() == "true"

KONNEKTOR_TLS_MODE = os.getenv("KONNEKTOR_TLS_MODE", KonnektorTlsMode.SMC_K.value).lower()

HTTPS_TIMEOUT = int(os.getenv('HTTPS_TIMEOUT', '30'))

IDP_AUTH_PATH = "/auth"
KONNEKTOR_URL = os.getenv('KONNEKTOR_URL')

if KONNEKTOR_CERT_PW is None:
    raise ValueError("KONNEKTOR_CERT_PW is not set. Please set it in your .env file.")
if not KONNEKTOR_URL:
    raise ValueError("KONNEKTOR_URL is not set. Please set it in your .env file.")

# === Loading CA-Bundles from truststores ===
ti_ts = TI_Truststore(
    ca_path=os.getenv('TI_CA_BUNDLE_PATH', str(TEMP_DIR / 'ti-ca')),
    epa_envs=epa_envs,
    provider_mapping=RECORD_PROVIDER_MAPPING,
    https_timeout=HTTPS_TIMEOUT,
)

TI_CA_BUNDLE = ti_ts.build_ca_bundle()

KONNEKTOR_TLS_MODE = os.getenv("KONNEKTOR_TLS_MODE", "alternative").lower()
if KONNEKTOR_TLS_MODE not in [mode.value for mode in KonnektorTlsMode]:
    raise ValueError(f"Invalid KONNEKTOR_TLS_MODE: {KONNEKTOR_TLS_MODE}. Must be one of {[mode.value for mode in KonnektorTlsMode]}.")


KONNEKTOR_URL = os.getenv('KONNEKTOR_URL', '')
KONNEKTOR_IP = KONNEKTOR_URL.split("//")[-1].split("/")[0].split(":")[0]  # Extract hostname or IP from URL
KONNEKTOR_TLS_HOSTNAME = None  # Default: use IP for both connection and TLS verification

match KONNEKTOR_TLS_MODE:
    case KonnektorTlsMode.ALTERNATIVE.value:
        KONNEKTOR_CA_BUNDLE = os.path.join(USER_CONFIG_DIR, "ssl", "konnektor", "cert.pem")
        if not os.path.isfile(KONNEKTOR_CA_BUNDLE):
            logger.error(f"KONNEKTOR_TLS_MODE=alternative is set, but the alternative certificate bundle does not exist at {KONNEKTOR_CA_BUNDLE}.")
            raise FileNotFoundError(f"Alternative certificate bundle not found at {KONNEKTOR_CA_BUNDLE}.")
        logger.warning(
            f"Konnektor identity verification is ENABLED using existing certificate bundle at {KONNEKTOR_CA_BUNDLE}\n"
            "To enable automatic refresh via ti-tls, set KONNEKTOR_TLS_MODE to \"smc_k\".\n" 
            "For that: Be sure to set \"Zertifikat für die Authentisierung\" to \"gSMC-K Zertifikat (ECC)\"."
        )
    case KonnektorTlsMode.SMC_K.value:
        KONNEKTOR_CA_BUNDLE = TI_CA_BUNDLE
        KONNEKTOR_TLS_HOSTNAME = "konnektor.konlan"
        KONNEKTOR_URL = f"https://{KONNEKTOR_TLS_HOSTNAME}"
        logger.info(
            "Konnektor identity verification is ENABLED using SMC-K certificate bundle."
        )
    case KonnektorTlsMode.INSECURE.value:
        KONNEKTOR_CA_BUNDLE = None
        logger.error(
            "Konnektor identity verification is EXPLICITLY DISABLED via KONNEKTOR_TLS_MODE=insecure. The service cannot confirm it is talking to the real Konnektor. "
            "This is insecure and NOT recommended for production use."
        )


TI_PKI_ROOTS_DIR = ti_ts.get_root_ca_path()

logger.info(f"""
Constants loaded:
EPA_ENVIRONMENT: {EPA_ENVIRONMENT}
DEFAULT_AS_URL: {DEFAULT_AS_URL}
USER_AGENT: {USER_AGENT}
IDP_URL: {IDP_URL}
KONNEKTOR_URL: {KONNEKTOR_URL}
LOG_LEVEL: {LOG_LEVEL}
RECORD_PROVIDER_MAPPING: {RECORD_PROVIDER_MAPPING}
""")
