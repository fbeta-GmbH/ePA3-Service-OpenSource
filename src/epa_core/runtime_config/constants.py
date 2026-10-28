from dataclasses import dataclass, field
import logging
import os
from pathlib import Path
from typing import ClassVar
from urllib.parse import urlsplit
from types import MappingProxyType
from asn1crypto import x509 as asn1_x509
from collections.abc import Mapping
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

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


RECORD_PROVIDER_PREFIX = "RECORD_PROVIDER_"

class EnvironmentSettings(BaseSettings):
    """
    All user-configurable environment variables.

    Fields without defaults are required.
    Fields with defaults are optional.

    Field names correspond directly to environment variable names.
    """

    model_config = SettingsConfigDict(case_sensitive=True, extra="ignore", frozen=True)

    # -- Konnektor ---------------------------------

    KONNEKTOR_URL: str = Field(description="URL used to reach the Konnektor.", min_length=1)
    KONNEKTOR_CERT_PW: str = Field(description="Password for the Konnektor client certificate.", repr=False)
    KONNEKTOR_TLS_MODE: KonnektorTlsMode = Field(
        default=KonnektorTlsMode.SMC_K,
        description=("Konnektor TLS verification mode: smc_k, alternative, or insecure.")
    )

    MANDANT_ID: str = Field(description="Konnektor Mandant ID.")
    CLIENT_SYSTEM_ID: str = Field(description="Konnektor ClientSystem ID.")
    WORKPLACE_ID: str = Field(description="Konnektor Workplace ID.")
    USER_ID: str = Field(default="", description="Optional Konnektor User ID.")

    # -- EPA ---------------------------------------

    EPA_ENVIRONMENT: str = Field(default="RT", description="Target EPA environment.")
    DEFAULT_EPA_PROVIDER_ID: str = Field(default="2", description="Default EPA provider ID.")

    USER_AGENT: str = Field(description="User-Agent sent with HTTP requests.")

    # -- DiGA --------------------------------------

    DIGA_NAME: str = Field(description="Name of the DiGA.")
    DIGA_MANUFACTURER: str = Field(description="Manufacturer of the DiGA.")
    SW_ADDITION_1: str = Field(default="", description="Optional software addition 1.")
    SW_ADDITION_2: str = Field(default="", description="Optional software addition 2.")
    SW_ADDITION_3: str = Field(default="", description="Optional software addition 3.")

    # -- Network / Certificates --------------------

    HTTPS_TIMEOUT: int = Field(default=30, gt=0, description="HTTPS timeout in seconds.")

    TI_CA_BUNDLE_PATH: Path | None = Field(
        default=None,
        description=("Directory for the TI CA bundle. Defaults to <TEMP_DIR>/ti-ca."),
    )

    # -- Logging -----------------------------------

    LOG_LEVEL: str = Field(default="INFO", description="Application log level.")

    # -- Validation --------------------------------

    @field_validator("KONNEKTOR_TLS_MODE", mode="before")
    @classmethod
    def validate_tls_mode(cls, value):
        if isinstance(value, str):
            return value.lower()
        return value

    @field_validator("EPA_ENVIRONMENT")
    @classmethod
    def validate_epa_environment(cls, value: str) -> str:
        available = EpaEnvs.available_envs()
        if value not in available:
            raise ValueError(f"Invalid EPA_ENVIRONMENT: {value!r}. Available options: {available}")
        return value

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        value = value.upper()
        if value not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            raise ValueError(f"Invalid LOG_LEVEL: {value!r}")
        return value

    # -- Dynamic environment variables ------------

    @staticmethod
    def load_provider_mapping(environ: Mapping[str, str] | None = None) -> dict[str, int]:
        """
        Parse RECORD_PROVIDER_<ID>=<NAME> variables.

        Returns:
            Mapping from provider name to numeric provider ID.
        """
        if environ is None:
            environ = os.environ

        mapping: dict[str, int] = {}

        for key, raw_name in environ.items():
            if not key.startswith(RECORD_PROVIDER_PREFIX):
                continue

            raw_id = key.removeprefix(RECORD_PROVIDER_PREFIX)

            if not raw_id or not raw_id.isascii() or not raw_id.isdecimal():
                raise ValueError(
                    f"Invalid provider environment variable: {key!r}. "
                    "Expected RECORD_PROVIDER_<numeric ID>."
                )

            provider_name = raw_name.strip()
            provider_id = int(raw_id)

            if not provider_name:
                raise ValueError(f"{key} must not be empty.")

            if provider_name in mapping:
                raise ValueError(f"Duplicate provider name: {provider_name!r}")

            mapping[provider_name] = provider_id

        return mapping


@dataclass(frozen=True, slots=True)
class KonnektorConnection:
    url: str
    connection_host: str
    tls_hostname: str | None
    ca_bundle: str | None
    verify_certificate: bool


def resolve_konnektor_connection(
    settings: EnvironmentSettings,
    user_config_dir: Path,
    ti_ca_bundle: str,
    logger: logging.Logger,
) -> KonnektorConnection:
    """
    Resolve the Konnektor connection for the selected TLS mode.
    """

    parsed = urlsplit(settings.KONNEKTOR_URL)

    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Invalid KONNEKTOR_URL scheme: {settings.KONNEKTOR_URL!r}")

    try:
        connection_host = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid KONNEKTOR_URL: {settings.KONNEKTOR_URL!r}") from exc

    if not connection_host:
        raise ValueError(f"Invalid KONNEKTOR_URL: {settings.KONNEKTOR_URL!r}")

    match settings.KONNEKTOR_TLS_MODE:
        case KonnektorTlsMode.ALTERNATIVE:
            if parsed.scheme != "https":
                raise ValueError("KONNEKTOR_TLS_MODE=alternative requires an HTTPS URL.")

            bundle = user_config_dir / "ssl" / "konnektor" / "cert.pem"

            if not bundle.is_file():
                raise FileNotFoundError(f"Alternative certificate bundle not found: {bundle}")

            logger.warning(
                "Konnektor identity verification is ENABLED "
                "using the alternative CA bundle at %s. "
                "For automatic refresh via ti-tls, use "
                "KONNEKTOR_TLS_MODE=smc_k and configure "
                "the gSMC-K ECC authentication certificate.",
                bundle,
            )

            return KonnektorConnection(
                url=settings.KONNEKTOR_URL,
                connection_host=connection_host,
                tls_hostname=None,
                ca_bundle=str(bundle),
                verify_certificate=True,
            )

        case KonnektorTlsMode.SMC_K:
            hostname = "konnektor.konlan"

            logger.info(
                "Konnektor identity verification is ENABLED "
                "using the SMC-K certificate bundle."
            )

            return KonnektorConnection(
                url=f"https://{hostname}",
                connection_host=connection_host,
                tls_hostname=hostname,
                ca_bundle=ti_ca_bundle,
                verify_certificate=True,
            )

        case KonnektorTlsMode.INSECURE:
            logger.error(
                "Konnektor identity verification is EXPLICITLY "
                "DISABLED. This is not recommended "
                "for production use."
            )

            return KonnektorConnection(
                url=settings.KONNEKTOR_URL,
                connection_host=connection_host,
                tls_hostname=None,
                ca_bundle=None,
                verify_certificate=False,
            )


@dataclass(frozen=True, slots=True, repr=False)
class KonnektorConfig:
    configured_url: str
    cert_password: str = field(repr=False)
    tls_mode: KonnektorTlsMode
    mandant_id: str
    client_system_id: str
    workplace_id: str
    user_id: str
    url: str
    connection_host: str
    tls_hostname: str | None
    ca_bundle: str | None
    verify_certificate: bool


@dataclass(frozen=True, slots=True)
class EpaConfig:
    environment: str
    default_provider_id: str
    default_as_url: str
    idp_url: str
    idp_auth_path: str = "/auth"


@dataclass(frozen=True, slots=True)
class DigaConfig:
    name: str
    manufacturer: str
    sw_addition_1: str
    sw_addition_2: str
    sw_addition_3: str


@dataclass(frozen=True, slots=True)
class NetworkConfig:
    https_timeout: int
    user_agent: str


@dataclass(frozen=True, slots=True)
class PathConfig:
    user_config_dir: Path
    temp_dir: Path
    data_dir: Path


@dataclass(frozen=True, slots=True)
class TruststoreConfig:
    ca_bundle_path: Path
    ti_ca_bundle: str
    ti_pki_roots_dir: str
    ti_trust_roots: tuple[asn1_x509.Certificate, ...]
    provider_mapping: Mapping[str, int]


class Config:
    """Global application configuration.

    Call init_config() exactly once before using fields other than logger.
    """

    _initialized: ClassVar[bool] = False

    konnektor: ClassVar[KonnektorConfig]
    epa: ClassVar[EpaConfig]
    diga: ClassVar[DigaConfig]
    network: ClassVar[NetworkConfig]
    truststore: ClassVar[TruststoreConfig]
    paths: ClassVar[PathConfig]

    logger: ClassVar[logging.Logger] = logging.getLogger("epa_core")

    @classmethod
    def assert_initialized(cls) -> None:
        if not cls._initialized:
            raise RuntimeError(
                "Config is not initialized. Call bootstrap_environment() first."
            )


def init_config(user_config_dir: Path, temp_dir: Path, data_dir: Path) -> None:
    """Load settings, build the truststore, and publish configuration once.

    The caller is responsible for loading .env and setting OPENSSL_CONF
    before calling this function or importing OpenSSL-dependent modules.
    """
    if Config._initialized:
        raise RuntimeError("Config is already initialized")
    from epa_core.truststores.ti.ti_truststore import TI_Truststore
    from epa_core.vau.validator import _load_ti_trust_roots

    user_config_dir = Path(user_config_dir)
    temp_dir = Path(temp_dir)
    data_dir = Path(data_dir)

    # Load environment variables
    env = EnvironmentSettings()  # pyright: ignore[reportCallIssue]
    provider_mapping = env.load_provider_mapping()

    # Initialize logging
    logger = setup_logging(log_level=env.LOG_LEVEL)
    Config.logger = logger

    # Resolve EPA environment
    epa_env = EpaEnvs.get(env.EPA_ENVIRONMENT)
    default_as_url = get_as_url(epa_env, env.DEFAULT_EPA_PROVIDER_ID)
    idp_url = epa_env.get_idp_url()

    # Initialize truststore
    ti_ca_bundle_path = env.TI_CA_BUNDLE_PATH or temp_dir / "ti-ca"
    truststore = TI_Truststore(
        ca_path=str(ti_ca_bundle_path),
        epa_envs=epa_env,
        provider_mapping=provider_mapping,
        https_timeout=env.HTTPS_TIMEOUT,
    )
    ti_ca_bundle = truststore.build_ca_bundle()
    if ti_ca_bundle is None:
        raise RuntimeError("TI truststore did not produce a CA bundle")

    # Resolve Konnektor connection
    connection = resolve_konnektor_connection(
        settings=env,
        user_config_dir=user_config_dir,
        ti_ca_bundle=ti_ca_bundle,
        logger=logger,
    )

    # Trust roots
    ti_pki_roots_dir = truststore.get_root_ca_path()
    ti_trust_roots = tuple(_load_ti_trust_roots(ti_pki_roots_dir, logger))

    # Publish the configuration to the global Config object
    Config.konnektor = KonnektorConfig(
        configured_url=env.KONNEKTOR_URL,
        cert_password=env.KONNEKTOR_CERT_PW,
        tls_mode=env.KONNEKTOR_TLS_MODE,
        mandant_id=env.MANDANT_ID,
        client_system_id=env.CLIENT_SYSTEM_ID,
        workplace_id=env.WORKPLACE_ID,
        user_id=env.USER_ID,
        url=connection.url,
        connection_host=connection.connection_host,
        tls_hostname=connection.tls_hostname,
        ca_bundle=connection.ca_bundle,
        verify_certificate=connection.verify_certificate,
    )
    Config.epa = EpaConfig(
        environment=env.EPA_ENVIRONMENT,
        default_provider_id=env.DEFAULT_EPA_PROVIDER_ID,
        default_as_url=default_as_url,
        idp_url=idp_url,
    )
    Config.diga = DigaConfig(
        name=env.DIGA_NAME,
        manufacturer=env.DIGA_MANUFACTURER,
        sw_addition_1=env.SW_ADDITION_1,
        sw_addition_2=env.SW_ADDITION_2,
        sw_addition_3=env.SW_ADDITION_3,
    )
    Config.network = NetworkConfig(
        https_timeout=env.HTTPS_TIMEOUT, user_agent=env.USER_AGENT
    )
    Config.paths = PathConfig(
        user_config_dir=user_config_dir, temp_dir=temp_dir, data_dir=data_dir
    )
    Config.truststore = TruststoreConfig(
        ca_bundle_path=ti_ca_bundle_path,
        ti_ca_bundle=ti_ca_bundle,
        ti_pki_roots_dir=ti_pki_roots_dir,
        ti_trust_roots=ti_trust_roots,
        provider_mapping=MappingProxyType(dict(provider_mapping)),
    )
    Config._initialized = True

    logger.info(
        "Configuration initialized: EPA_ENVIRONMENT=%s, KONNEKTOR_TLS_MODE=%s, LOG_LEVEL=%s",
        env.EPA_ENVIRONMENT,
        env.KONNEKTOR_TLS_MODE.value,
        env.LOG_LEVEL,
    )
