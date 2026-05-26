from dataclasses import dataclass
import os
import dotenv

dotenv.load_dotenv()
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

from app.logging_config import logger  # noqa: E402

logger.info("Loading constants")

# Dynamically load RECORD_PROVIDER_X variables from the environment
RECORD_PROVIDER_MAPPING = {}
for key, value in os.environ.items():
    if key.startswith("RECORD_PROVIDER_"):
        provider_name = value.strip()
        provider_id = key.split("_")[-1]  # Extract the number from the variable name
        RECORD_PROVIDER_MAPPING[provider_name] = int(provider_id)

@dataclass
class EpaEnvConfig:
    """See: https://gemspec.gematik.de/docs/gemSpec/gemSpec_Aktensystem_ePAfueralle/latest/#A_24592-02"""
    id: str
    name: str
    subdomain : str
    idp_subdomain: str
    
    prefix_as = "epa-as"
    prefix_asisa = "epa-asisa"
    domain = "epa4all.de"

    def get_as_url(self, provider_id: str) -> str:
        return f"https://{self.prefix_as}-{provider_id}.{self.subdomain}.{self.domain}/"
    
    def get_idp_url(self) -> str:
        return f"https://{self.idp_subdomain}.zentral.idp.splitdns.ti-dienste.de"

class EpaEnvs:
    RU = EpaEnvConfig(
        id="RU",
        name="RU1 / RU_ref", 
        subdomain="ref",
        idp_subdomain="idp-ref"
    )
    RT = EpaEnvConfig(
        id="RT",
        name="RU2 / RU_dev", 
        subdomain="dev",
        idp_subdomain="idp-ref"
    )
    PROD = EpaEnvConfig(
        id="PROD",
        name="PROD", 
        subdomain="prod",
        idp_subdomain="idp"
    )

    @classmethod
    def available_envs(cls) -> list[str]:
        return [env.id for env in vars(cls).values() if isinstance(env, EpaEnvConfig)]

    @classmethod
    def get(cls, env_name: str) -> EpaEnvConfig:
        return getattr(cls, env_name)


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

def get_as_url(provider_id: str) -> str:
    return EpaEnvs.get(EPA_ENVIRONMENT).get_as_url(provider_id)


DEFAULT_EPA_PROVIDER_ID = os.getenv('DEFAULT_EPA_PROVIDER_ID', '2')
DEFAULT_AS_URL = get_as_url(str(DEFAULT_EPA_PROVIDER_ID))
IDP_URL = EpaEnvs.get(EPA_ENVIRONMENT).get_idp_url()

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

HTTPS_TIMEOUT = int(os.getenv('HTTPS_TIMEOUT', '30'))

IDP_AUTH_PATH = "/auth"
KONNEKTOR_URL = os.getenv('KONNEKTOR_URL') 

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