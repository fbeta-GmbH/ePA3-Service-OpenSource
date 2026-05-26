"""EPA environment configuration.

Defines the per-environment URL/host scheme for the gematik ePA backends
(RU, RT, PROD).

Kept import-free of `app.runtime_config.constants` to avoid circular imports.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class EpaEnvConfig:
    """See: https://gemspec.gematik.de/docs/gemSpec/gemSpec_Aktensystem_ePAfueralle/latest/#A_24592-02"""
    id: str
    name: str
    subdomain: str
    idp_subdomain: str
    tls_subdomain: str
    ti_root_certs: str

    prefix_as = "epa-as"
    prefix_asisa = "epa-asisa"
    domain = "epa4all.de"

    def get_as_url(self, provider_id: str) -> str:
        return f"https://{self.prefix_as}-{provider_id}.{self.subdomain}.{self.domain}/"

    def get_idp_url(self) -> str:
        return f"https://{self.idp_subdomain}.zentral.idp.splitdns.ti-dienste.de"

    def get_tsl_dist_url(self) -> str:
        return f"https://{self.tls_subdomain}.tsl.ti-dienste.de"

    def get_root_ca_url(self) -> str:
        return f"{self.get_tsl_dist_url()}/ECC/ROOT-CA/"

    def get_sub_ca_url(self) -> str:
        return f"{self.get_tsl_dist_url()}/ECC/SUB-CA/"

    def get_tsl_url(self) -> str:
        if self.tls_subdomain == EpaEnvs.RT.tls_subdomain:
            return f"{self.get_tsl_dist_url()}/ECC/ECC-RSA_TSL-ref.xml"
        return f"{self.get_tsl_dist_url()}/ECC/TSL.xml"


class EpaEnvs:
    RU = EpaEnvConfig(
        id="RU",
        name="RU1 / RU_ref",
        subdomain="ref",
        idp_subdomain="idp-ref",
        tls_subdomain="download-ref",
        ti_root_certs="ref"
    )
    RT = EpaEnvConfig(
        id="RT",
        name="RU2 / RU_dev",
        subdomain="dev",
        idp_subdomain="idp-ref",
        tls_subdomain="download-ref",
        ti_root_certs="test"
    )
    PROD = EpaEnvConfig(
        id="PROD",
        name="PROD",
        subdomain="prod",
        idp_subdomain="idp",
        tls_subdomain="download",
        ti_root_certs="prod"

    )

    @classmethod
    def available_envs(cls) -> list[str]:
        return [env.id for env in vars(cls).values() if isinstance(env, EpaEnvConfig)]

    @classmethod
    def get(cls, env_name: str) -> EpaEnvConfig:
        return getattr(cls, env_name)
