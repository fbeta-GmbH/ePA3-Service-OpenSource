import os

from app.runtime_config.bootstrap import _APP_ROOT, USER_CONFIG_DIR, load_env
from app.logging_config import logger
from app.runtime_config.epa_env import EpaEnvs
from app.truststores.ti.ti_truststore import TI_Truststore
from app.truststores.konnektor.konnektor_truststore import Konnektor_Truststore
from app.konnektor.pkcs12adapter import find_p12

load_env()
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logger.info(f"Loading constants using config from /{os.path.relpath(USER_CONFIG_DIR, _APP_ROOT)}")

# Dynamically load RECORD_PROVIDER_X variables from the environment
RECORD_PROVIDER_MAPPING: dict[str, int] = {}
for key, value in os.environ.items():
    if key.startswith("RECORD_PROVIDER_"):
        provider_name = value.strip()
        provider_id = key.split("_")[-1]  # Extract the number from the variable name
        RECORD_PROVIDER_MAPPING[provider_name] = int(provider_id)



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

def set_telematik_id(telematik_id: str, ):
    os.environ['TELEMATIK_ID'] = telematik_id

def set_oid_diga(oid_diga: str):
    os.environ['OID_DIGA'] = oid_diga

def set_author():
    if 'TELEMATIK_ID' not in os.environ:
        raise ValueError("TELEMATIK_ID not set")
    if 'DIGA_NAME' not in os.environ:
        raise ValueError("DIGA_NAME not set")
    os.environ['AUTHOR'] = generate_author()

def set_institution():
    if 'TELEMATIK_ID' not in os.environ:
        raise ValueError("TELEMATIK_ID not set")
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
"""
URL to a JWS file published by the Konnektor provider, containing trusted server certificates, used to verify the identity of the Konnektor. 
If empty, TLS server verification is disabled (verify=False) in all Konnektor requests.
"""
KONNEKTOR_JWS_URL = os.getenv("KONNEKTOR_JWS_URL", "")

HTTPS_TIMEOUT = int(os.getenv('HTTPS_TIMEOUT', '30'))

IDP_AUTH_PATH = "/auth"
KONNEKTOR_URL = os.getenv('KONNEKTOR_URL')

if KONNEKTOR_CERT_PW is None:
    raise ValueError("KONNEKTOR_CERT_PW is not set. Please set it in your .env file.")
if not KONNEKTOR_URL:
    raise ValueError("KONNEKTOR_URL is not set. Please set it in your .env file.")


# === Loading CA-Bundles from truststores ===
ti_ts = TI_Truststore(
    ca_path=os.getenv('TI_CA_BUNDLE_PATH', os.path.join(_APP_ROOT, 'app', 'tmp', 'ti-ca')),
    epa_envs=epa_envs,
    provider_mapping=RECORD_PROVIDER_MAPPING,
    https_timeout=HTTPS_TIMEOUT,
)

TI_CA_BUNDLE = ti_ts.build_ca_bundle()

# Build the Konnektor CA bundle from the JWS-provided server certificates.
kon_ts = Konnektor_Truststore(
    ca_bundle_path=os.getenv('KONNEKTOR_CA_BUNDLE', os.path.join(_APP_ROOT, 'app', 'tmp', 'konnektor-ca')),
    epa_envs=epa_envs,
    konnektor_url=KONNEKTOR_URL,
    konnektor_jws_url=KONNEKTOR_JWS_URL,
    p12_path=find_p12(USER_CONFIG_DIR),
    p12_password=KONNEKTOR_CERT_PW,
    https_timeout=HTTPS_TIMEOUT,
)
KONNEKTOR_CA_BUNDLE = kon_ts.build_ca_bundle()


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