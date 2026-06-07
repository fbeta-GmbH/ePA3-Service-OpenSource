import asyncio
import concurrent.futures
import hashlib
import logging
import os
import re
from abc import ABC
from datetime import datetime, timedelta, timezone
from email.message import Message
from typing import Never, cast
from urllib.parse import urljoin

import cbor2
import oqs
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509 import ocsp as crypto_ocsp
from cryptography.x509.oid import ExtensionOID, NameOID
from fastapi import status
from pydantic import ValidationError as PydanticValidationError
from pyhanko_certvalidator import CertificateValidator, ValidationContext
from pyhanko_certvalidator.errors import (
    CRLValidationError,
    OCSPValidationError,
    PathError,
    ValidationError,
)
from pyhanko_certvalidator.policy_decl import (
    CertRevTrustPolicy,
    FreshnessReqType,
    RevocationCheckingPolicy,
    RevocationCheckingRule,
)

# from app.constants import HTTPS_TIMEOUT, TI_PKI_ROOTS_DIR, USER_AGENT
from app.runtime_config.constants import HTTPS_TIMEOUT, TI_PKI_ROOTS_DIR, USER_AGENT
from app.exceptions import ErrorCodes, VAUException
from app.runtime_config.logging import logger
from app.vau.vau_models import (
    AUT_VAU_CertData,
    ECDHPublicKey,
    SignedVauServerPubKeys,
    VAUPublicKeyBundle,
)


# TODO: Implement TSL option for VAU trust basis as per A_24958: https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.48.0/#A_24958
# - fetch and validate TSL from TI TSL endpoint (https://download.tsl.ti-dienste.de/)
# - extract CA certs
# - use them as trust anchors without age filter. 

def _load_ti_trust_roots() -> list[asn1_x509.Certificate]:
    """
    Load locally configured TI root certificates (trust anchors).
    Only chains ending in one of these roots are accepted as valid during certificate path validation.

    A_24958: Each root certificate must have a notBefore date at least 2 years in the past.
    Roots that do not satisfy this age requirement are excluded.

    Returns:
        list[asn1_x509.Certificate]: A list of TI root certificates loaded in a format that pyHanko can use.

    Raises:
        VAUException: If the root certificate directory is missing, or if no usable root certificates were found.
    """
    if not os.path.isdir(TI_PKI_ROOTS_DIR):
        raise VAUException(
            message=f"TI PKI root certificate directory does not exist: {TI_PKI_ROOTS_DIR}",
            error_code=ErrorCodes.VAU_INIT_FAILED,
            status_code=500,
        )

    # A_24958: root must be at least 2 years old (based on notBefore).
    min_age = timedelta(days=2 * 365)
    now = datetime.now(timezone.utc)

    # Collect all usable root certs from the configured directory.
    ti_trust_roots: list[asn1_x509.Certificate] = []
    for root_cert_filename in sorted(os.listdir(TI_PKI_ROOTS_DIR)):
        # Only DER certificate files are considered.
        if not root_cert_filename.endswith(".der"):
            continue
        root_cert_path = os.path.join(TI_PKI_ROOTS_DIR, root_cert_filename)
        try:
            with open(root_cert_path, "rb") as f:
                root_cert_der = f.read()
            # Validate file as X.509 DER.
            cert = x509.load_der_x509_certificate(root_cert_der, default_backend())

            # A_24958: skip roots whose notBefore is less than 2 years ago.
            cert_age = now - cert.not_valid_before_utc
            if cert_age < min_age:
                logger.debug(f"Skipping TI root {root_cert_filename}: not yet 2 years old (notBefore={cert.not_valid_before_utc.isoformat()}, age={cert_age.days} days)")
                continue

            # Convert to asn1crypto type expected by pyHanko.
            ti_trust_roots.append(asn1_x509.Certificate.load(root_cert_der))
        except Exception as e:
            logger.error(f"Failed to load TI PKI trust root {root_cert_path}: {str(e)}")

    if not ti_trust_roots:
        raise VAUException(
            message=f"No valid TI PKI trust roots loaded from {TI_PKI_ROOTS_DIR}",
            error_code=ErrorCodes.VAU_INIT_FAILED,
            status_code=500,
        )

    loaded_filenames = [cert.subject.native.get("common_name", "?") for cert in ti_trust_roots]
    logger.debug(f"Loaded {len(ti_trust_roots)} TI PKI trust root(s) ({os.path.basename(TI_PKI_ROOTS_DIR)}): {loaded_filenames}")
    logger.debug(f"TI PKI trust root details: {ti_trust_roots[0].subject.human_friendly}")

    return ti_trust_roots

# Load pinned TI roots once; these are the only certificates we trust as root of trust for chain validation.
TI_TRUST_ROOTS: list[asn1_x509.Certificate] = _load_ti_trust_roots()

# A_24958: CertData cache keyed by "<cert_hash_hex>-<cdv>". Retained indefinitely per spec.
_cert_data_cache: dict[str, AUT_VAU_CertData] = {}

def _evict_cert_data_cache(signed_vau_server_pub_keys: SignedVauServerPubKeys|None) -> None:
    """Evict a specific entry from the CertData cache based on cert hash and CDV. This is used to force re-fetching of CertData on the next validation attempt after a failure."""
    if not signed_vau_server_pub_keys:
        return
    cache_key = f"{signed_vau_server_pub_keys.cert_hash.hex()}-{signed_vau_server_pub_keys.cdv}"
    if cache_key in _cert_data_cache:
        logger.debug(f"Evicting CertData cache for {cache_key}")
        _cert_data_cache.pop(cache_key, None)

def raise_validation_failure(details: str, reference: str) -> Never:
    """
    Raise a standardized validation error and abort the VAU handshake.
    Per protocol, any failed required check must result in an immediate handshake abortion.

    Args:
        details (str): Detailed error message describing the specific validation failure.
        reference (str): Reference to the specific validation step or component. This helps to identify which part of the validation process failed, for example "A_24624-01#3" for step #3 of A_24624-01.
    """
    raise VAUException(
        message=f"VAU validation failed at {reference}: {details}",
        error_code=ErrorCodes.VAU_CERT_VALIDATION_FAILED,
        status_code=status.HTTP_502_BAD_GATEWAY,
    )


class VAUCertificateValidator:
    def __init__(self, AS_URL: str, https_session):
        self.AS_URL = AS_URL
        self.https_session = https_session
        self.ti_trust_roots = TI_TRUST_ROOTS

    def fetch_cert_data(self, cert_hash: bytes, cdv: int) -> AUT_VAU_CertData:
        """
        Fetch CertData referenced by `cert_hash` and `cdv`.
        A_24958: consults the local cache first; on miss fetches via HTTP and caches indefinitely.
        The `cdv` (Certificate Data Version) distinguishes corrected versions of the same cert hash.

        Args:
            cert_hash (bytes): SHA-256 fingerprint of the AUT-VAU certificate.
            cdv (int): Certificate Data Version. This is part of the endpoint name.

        Returns:
            AUT_VAU_CertData: object containing `AUT-VAU certificate`, `issuing CA certificate`, and optional `RCA/cross-certificate chain material` needed for validation.
        """
        # Endpoint expects hash as lowercase hex.
        cert_hash_hex = cert_hash.hex()
        cache_key = f"{cert_hash_hex}-{cdv}"

        # A_24958: check local cache before issuing the GET request.
        if cache_key in _cert_data_cache:
            logger.debug(f"CertData cache hit for {cache_key}")
            return _cert_data_cache[cache_key]

        logger.debug(f"CertData cache miss for {cache_key}, fetching from server")

        # Endpoint pattern: /CertData.<cert_hash_hex>-<cdv>
        cert_endpoint = urljoin(self.AS_URL, f"/CertData.{cert_hash_hex}-{cdv}")

        # Request CertData
        # TODO: Remove `verify=False`
        cert_data_response = self.https_session.get(
            cert_endpoint,
            verify=False,
            headers={"x-useragent": USER_AGENT},
            timeout=HTTPS_TIMEOUT
        )

        logger.info(f"Requested CertData from {cert_endpoint}, status code: {cert_data_response.status_code}")
        logger.debug(f"CertData response headers: {cert_data_response.headers}")

        # Abort on any non-200 responses
        if cert_data_response.status_code != status.HTTP_200_OK:
            logger.error(f"Failed to retrieve CertData: {cert_data_response.text}")
            raise_validation_failure(f"Failed to retrieve CertData: {cert_data_response.text}", "A_24957")

        # Validate that Content-Type header is `application/cbor` as described in A_24957.
        content_type = cert_data_response.headers.get("Content-Type", "")
        content_type_message = Message()
        content_type_message["content-type"] = content_type

        if content_type_message.get_content_type() != "application/cbor":
            raise_validation_failure(
                f"CertData response Content-Type must be application/cbor, got {content_type!r}", "A_24957"
            )

        # Decode the CBOR response and validate that it matches the expected CertData structure.
        try:
            cert_data = AUT_VAU_CertData.model_validate(cbor2.loads(cert_data_response.content))
        except Exception as e:
            raise_validation_failure(f"Invalid CertData body: {type(e).__name__}: {e}", "A_24957")

        # A_24958: cache indefinitely.
        _cert_data_cache[cache_key] = cert_data
        return cert_data

    def validate(self, signed_vau_server_pub_keys_dict: dict) -> None:
        """
        Validate the signed VAU server public keys according to A_24624-01.
        Flow: parse payload -> fetch CertData -> validate cert/OCSP/trust checks -> verify signed server keys.

        Any required-check failure aborts the handshake.

        See: https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.48.0/#A_24624-01

        Args:
            signed_vau_server_pub_keys_dict (dict): Raw dictionary containing the fields like `cert_hash`, `cdv`, `signature-ES256`, `signed_pub_keys`, and `ocsp_response` as received from the VAU handshake.

        Raises:
            VAUException: If validation fails at any implemented step.
        """
        signed_vau_server_pub_keys: SignedVauServerPubKeys|None = None
        try:
            # Parse and normalize incoming payload shape.
            try:
                signed_vau_server_pub_keys = SignedVauServerPubKeys.model_validate(signed_vau_server_pub_keys_dict)
            except Exception as e:
                raise_validation_failure(
                    f"Invalid signed VAU server public keys: {type(e).__name__}: {e}", "A_24624-01#0"
                )

            # Fetch certificate data needed for validation based on the cert hash and CDV provided by the server in the handshake.
            # ======== Preparation: A_24957 ==========
            # Fetch the AUT-VAU certificate and helper chain certificates from the CertData endpoint. This is needed for all subsequent validation steps.
            aut_vau_cert_data = self.fetch_cert_data(
                cert_hash=signed_vau_server_pub_keys.cert_hash,
                cdv=signed_vau_server_pub_keys.cdv,
            )

            # Load AUT-VAU certificate used for signature verification.
            cert = x509.load_der_x509_certificate(aut_vau_cert_data.cert, default_backend())
            logger.debug(f"Loaded AUT-VAU certificate: Subject={cert.subject}, Issuer={cert.issuer}, NotBefore={cert.not_valid_before_utc}, NotAfter={cert.not_valid_after_utc}")

            # ======== A_24624-01#1 ===========
            # Step #1: check that `cert_hash` matches the fetched cert.
            logger.debug("Running VAU certificate validation for A_24624-01#1")
            Step1.validate_cert_hash(
                cert_data=aut_vau_cert_data, expected_cert_hash=signed_vau_server_pub_keys.cert_hash
            )

            # ======== A_24624-01#1/#2 (overlap) ===========
            # Step #1/#2: Combined OCSP + path validation shared by steps #1 and #2.
            logger.debug("Running overlapping VAU certificate checks for A_24624-01#1/#2")
            Step1_2.validate_cert_path_with_ocsp(
                aut_vau_cert_data=aut_vau_cert_data,
                ocsp_response_der=signed_vau_server_pub_keys.ocsp_response,
                ti_trust_roots=self.ti_trust_roots,
            )

            # ======== A_24624-01#2 ===========
            # Step #2 remainder: certificate time validity.
            logger.debug("Running VAU certificate validation for A_24624-01#2")
            Step2.validate_cert_time_validity(aut_vau_cert=cert)

            # ======== A_24624-01#3 ===========
            # Step #3: Check Komponenten-PKI and role OID `oid_epa_vau`.
            logger.debug("Running VAU certificate validation for A_24624-01#3")
            Step3.validate_komponenten_pki(aut_vau_cert=cert, issuing_ca_der=aut_vau_cert_data.ca)
            Step3.validate_oid_epa_vau(aut_vau_cert=cert)

            # ======== A_24624-01#4 ===========
            # Step #4: Signature check for `signed_pub_keys` using AUT-VAU cert key.
            logger.debug("Running VAU cert check A_24624-01#4")
            Step4.validate_signed_pub_keys_signature(
                aut_vau_cert=cert,
                signature_es256=signed_vau_server_pub_keys.signature_es256,
                signed_pub_keys=signed_vau_server_pub_keys.signed_pub_keys,
            )

            # ======== A_24624-01#5 ===========
            # Step #5: Decode the signed key bundle (VAU_Keys_encoded) and validate key material.
            try:
                decoded_signed_pub_keys_payload = cbor2.loads(signed_vau_server_pub_keys.signed_pub_keys)
            except Exception as e:
                raise_validation_failure(f"signed_pub_keys is not valid CBOR: {type(e).__name__}: {e}", "A_24624-01#5")

            try:
                decoded_signed_pub_keys = VAUPublicKeyBundle.model_validate(decoded_signed_pub_keys_payload)
            except PydanticValidationError as e:
                raise_validation_failure(
                    f"signed_pub_keys CBOR payload is invalid for VAUPublicKeyBundle: {type(e).__name__}: {e}", "A_24624-01#5",
                )

            logger.debug("Running VAU certificate validation for A_24624-01#5")
            Step5.validate_ecdh_p256_key(ecdh_public_key=decoded_signed_pub_keys.ECDH_PK)
            Step5.validate_kyber768_key(kyber_public_key=decoded_signed_pub_keys.Kyber768_PK)

            # ======== A_24624-01#6 ===========
            # Step #6: Validate expiry in the signed key bundle.
            logger.debug("Running VAU certificate validation for A_24624-01#6")
            Step6.validate_signed_pub_keys_expiry(exp=decoded_signed_pub_keys.exp)

            # ======= All steps passed =======
            logger.info("VAU server key validation successful")

        except VAUException:
            _evict_cert_data_cache(signed_vau_server_pub_keys)
            raise

        except Exception as e:
            _evict_cert_data_cache(signed_vau_server_pub_keys)
            logger.error(f"✗ Certificate validation failed: {str(e)}")
            raise VAUException(
                message=f"Certificate validation failed: {str(e)}",
                error_code=ErrorCodes.VAU_CERT_VALIDATION_FAILED,
                status_code=status.HTTP_502_BAD_GATEWAY,
            )


class ValidationStep(ABC):
    """
    Base class for individual validation steps. Each step implements a specific part of the overall validation process as defined in A_24624-01 and related specifications.
    """

    _step_number: str

    @classmethod
    def _raise_failure(cls, details: str) -> Never:
        """
        Helper method to raise a standardized validation failure for this specific step.

        Args:
            details (str): Detailed error message describing the specific validation failure.
        """
        raise_validation_failure(details, f"A_24624-01#{cls._step_number}")


class Step1(ValidationStep):
    """
    Executes checks from A_24624-01#1.

    Prüfung des TI-Zertifikats, das den Hashwert aus dem "cert_hash"-Datenfeld besitzt (Bezug des Zertifikats vgl. A_24957-*), u. a. unter der Verwendung der OCSP-Response aus "ocsp_response" für die Prüfung des Sperrstatus (Prüfung ob "good"). Die OCSP-Response darf dabei nicht älter als 24 Stunden sein.

    See: https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.48.0/#A_24624-01
    """

    _step_number = "1"

    @classmethod
    def validate_cert_hash(cls, cert_data: AUT_VAU_CertData, expected_cert_hash: bytes) -> None:
        """
        Verify that downloaded AUT-VAU certificate bytes match the expected SHA-256 hash provided in the signed key bundle. This ensures we are working with the correct certificate that the server claims to use for signing.

        Args:
            cert_data (CertData): Certificate data downloaded from the CertData endpoint. Contains the AUT-VAU certificate and helper certificates for chain validation.
            expected_cert_hash (bytes): The expected SHA-256 hash of the AUT-VAU certificate, as provided in the signed key bundle.
        """
        actual_cert_hash = hashlib.sha256(cert_data.cert).digest()

        if actual_cert_hash != expected_cert_hash:
            logger.error(
                f"Certificate hash mismatch: expected {expected_cert_hash.hex()}, got {actual_cert_hash.hex()}"
            )
            cls._raise_failure("Certificate hash does not match expected value")


class Step1_2(ValidationStep):
    """
    Executes overlapping checks from A_24624-01#1 and A_24624-01#2.

    Prüfung des TI-Zertifikats, das den Hashwert aus dem "cert_hash"-Datenfeld besitzt (Bezug des Zertifikats vgl. A_24957-*), u. a. unter der Verwendung der OCSP-Response aus "ocsp_response" für die Prüfung des Sperrstatus (Prüfung ob "good"). Die OCSP-Response darf dabei nicht älter als 24 Stunden sein.

    Das VAU/TI-Zertifikat MUSS zeitlich gültig sein. Es MUSS kryptographisch in einer Zertifikats-/Signaturprüfungskette rückführbar auf eine X.509-Root-Version der TI-PKI sein.

    See: https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.48.0/#A_24624-01
    """

    _step_number = "1/2"

    @classmethod
    def validate_cert_path_with_ocsp(
        cls,
        aut_vau_cert_data: AUT_VAU_CertData,
        ocsp_response_der: bytes,
        ti_trust_roots: list[asn1_x509.Certificate],
    ) -> None:
        """
        Validate AUT-VAU trust and revocation status in one run by combining the overlapping checks from A_24624-01#1 and A_24624-01#2.

        OCSP validation (#1) and certificate path validation (#2) both depend on the same CertData chain material
        and pinned TI roots and can be done together in a single validation run.

        Step mapping:
        - Step #1 (OCSP / revocation):
            - require an OCSP response for the AUT-VAU end-entity certificate,
            - verify OCSP response integrity and responder signature,
            - require certificate status GOOD (not revoked / not unknown),
            - enforce OCSP freshness: response age must be <= 24 hours.
        - Step #2 (certificate path):
            - build the AUT-VAU path from cert via ca and optional rca_chain,
            - require that path to terminate at one pinned TI trust root.


        Args:
            aut_vau_cert_data (AUT_VAU_CertData): Certificate data downloaded from CertData, containing AUT-VAU certificate and helper chain certificates.
            ocsp_response_der (bytes): DER-encoded OCSP response from the handshake for AUT-VAU revocation/freshness validation.
            ti_trust_roots (list[asn1_x509.Certificate]): Locally pinned TI root certificates used as trust anchors.
        """
        try:
            # Load AUT-VAU certificate (end-entity cert whose private key was used to sign signed_pub_keys
            # and whose public key is used for the verification of that signature).
            aut_vau_cert = asn1_x509.Certificate.load(aut_vau_cert_data.cert)

            # Load helper chain from CertData that links AUT-VAU cert to pinned TI roots.
            untrusted_chain_certs = cls._build_untrusted_chain_certs(aut_vau_cert_data)

            if logger.isEnabledFor(logging.DEBUG):
                _resp = crypto_ocsp.load_der_ocsp_response(ocsp_response_der)
                logger.debug(f"Parsed OCSP response: status={_resp.response_status}, cert_status={_resp.certificate_status}, this_update={_resp.this_update_utc}, next_update={_resp.next_update_utc}")

            # --- A_24624-01#1: Explicit OCSP time checks (thisUpdate, nextUpdate, 24h age) ---
            cls._validate_ocsp_time_constraints(ocsp_response_der)

            # --- A_24624-01#2: Certificate path + OCSP signature/status validation ---
            certificate_revocation_policy = CertRevTrustPolicy(
                revocation_checking_policy=RevocationCheckingPolicy(
                    # AUT-VAU certificate must have valid OCSP status.
                    ee_certificate_rule=RevocationCheckingRule.OCSP_REQUIRED,
                    # Intermediates are not revocation-checked here.
                    intermediate_ca_cert_rule=RevocationCheckingRule.NO_CHECK,
                ),
                freshness_req_type=FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION,
                freshness=timedelta(hours=24),
            )

            # Validation context: pinned roots + provided helper chain-certs/OCSP, no network fetching.
            validation_context = ValidationContext(
                trust_roots=ti_trust_roots,
                other_certs=untrusted_chain_certs,
                ocsps=[ocsp_response_der],
                allow_fetching=False,
                moment=datetime.now(timezone.utc),
                revinfo_policy=certificate_revocation_policy,
            )

            # Perform combined certificate path validation and OCSP signature/status checks in one run. This ensures that the OCSP response is correctly linked to the certificate being validated and that the certificate chain is valid up to a trusted TI root.
            cert_validator = CertificateValidator(
                end_entity_cert=aut_vau_cert,
                intermediate_certs=untrusted_chain_certs,
                validation_context=validation_context,
            )

            # Require certificate usage compatible with signature verification.
            async_certificate_validation = cert_validator.async_validate_usage(
                key_usage={"digital_signature"},
                extended_key_usage=None,
                extended_optional=True,
            )
            # Run in separate thread to avoid blocking the event loop
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                validated_path = pool.submit(asyncio.run, async_certificate_validation).result()

            # Enforce that the direct issuer selected by path validation is exactly the certificate provided in CertData `ca`.
            validated_chain = list(validated_path.iter_certs(include_root=True))
            if len(validated_chain) < 2:
                cls._raise_failure(
                    "Certificate path validation failed: validated path is too short to determine direct issuer"
                )

            direct_issuer_der = validated_chain[-2].dump()
            if hashlib.sha256(direct_issuer_der).digest() != hashlib.sha256(aut_vau_cert_data.ca).digest():
                cls._raise_failure("CertData CA certificate is not the direct issuer of the AUT-VAU certificate")

            logger.info("✓ AUT-VAU certificate OCSP and chain validation successful")

        except VAUException:
            raise
        except (PathError, ValidationError, OCSPValidationError, CRLValidationError) as e:
            cls._raise_failure(f"Certificate OCSP/path validation failed: {e}")
        except Exception as e:
            cls._raise_failure(f"Certificate OCSP/path validation failed: {type(e).__name__}: {e}")

    @classmethod
    def _validate_ocsp_time_constraints(cls, ocsp_response_der: bytes) -> None:
        """
        Explicit OCSP time validation for A_24624-01#1:
        - thisUpdate must not be in the future
        - nextUpdate (if present) must not be in the past
        - OCSP response age (now - thisUpdate) must be <= 24 hours
        """
        try:
            ocsp_response = crypto_ocsp.load_der_ocsp_response(ocsp_response_der)
        except Exception as e:
            cls._raise_failure(f"Could not parse OCSP response: {type(e).__name__}: {e}")

        this_update = ocsp_response.this_update_utc
        next_update = ocsp_response.next_update_utc

        if this_update is None:
            cls._raise_failure("OCSP response does not contain a thisUpdate field")

        now = datetime.now(timezone.utc)

        # thisUpdate must not be in the future.
        if this_update > now:
            cls._raise_failure(f"OCSP response thisUpdate is in the future: {this_update.isoformat()}")

        # nextUpdate must not be in the past (if present).
        if next_update is not None and next_update < now:
            cls._raise_failure(f"OCSP response nextUpdate is in the past: {next_update.isoformat()}")

        # A_24624-01#1: "Die OCSP-Response darf dabei nicht älter als 24 Stunden sein."
        max_age = timedelta(hours=24)
        age = now - this_update
        if age > max_age:
            cls._raise_failure(
                f"OCSP response is too old: thisUpdate={this_update.isoformat()}, age={age}, max_age={max_age}"
            )

    @classmethod
    def _build_untrusted_chain_certs(cls, cert_data: AUT_VAU_CertData) -> list[asn1_x509.Certificate]:
        """
        Build the list of untrusted chain certificates needed for OCSP/path validation from the provided CertData.
        """
        # Load the CA certificate from CertData that issued the AUT-VAU certificate. (helper certificate; trusted only if it links to a pinned TI root).
        issuing_ca_cert = asn1_x509.Certificate.load(cert_data.ca)

        # Normalize optional chain extension to list form.
        rca_chain_list = cert_data.rca_chain
        if not isinstance(rca_chain_list, list):
            rca_chain_list = [rca_chain_list] if rca_chain_list else []

        # Parse additional helper chain-certificates sent by the server for linking the AUT-VAU certificate up to a pinned TI root
        rca_chain_certs = [asn1_x509.Certificate.load(cross_cert_der) for cross_cert_der in rca_chain_list]

        # Combine CA cert and optional RCA/cross-certs into a single list of untrusted chain certificates
        return [issuing_ca_cert, *rca_chain_certs]


class Step2(ValidationStep):
    """
    Executes checks from A_24624-01#2.

    Das VAU/TI-Zertifikat MUSS zeitlich gültig sein. Es MUSS kryptographisch in einer Zertifikats-/Signaturprüfungskette rückführbar auf eine X.509-Root-Version der TI-PKI sein.

    See: https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.48.0/#A_24624-01
    """

    _step_number = "2"

    @classmethod
    def validate_cert_time_validity(cls, aut_vau_cert: x509.Certificate) -> None:
        """
        Check that the current time is within the `notBefore` and `notAfter` validity period of the AUT-VAU certificate. This ensures that the certificate is currently valid and not expired or not yet valid.

        Args:
            cert (x509.Certificate): AUT-VAU certificate.

        """
        now = datetime.now(timezone.utc)

        if now < aut_vau_cert.not_valid_before_utc:
            cls._raise_failure("AUT-VAU certificate is not yet valid")

        if now > aut_vau_cert.not_valid_after_utc:
            cls._raise_failure("AUT-VAU certificate is expired")


class Step3(ValidationStep):
    """
    Executes checks from A_24624-01#3.

    Das TI-Zertifikat MUSS aus der Komponenten-PKI der TI stammt (vgl. Implementierungshinweis A_25192-*#Punkt-2) und die Rollen-OID "oid_epa_vau" besitzt.

    See: https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.48.0/#A_24624-01
    """

    _step_number = "3"

    OID_EPA_VAU = x509.ObjectIdentifier("1.2.276.0.76.4.209")
    """
    Object Identifier (OID) for the VAU role (ProfessionOID), which must be present in the AUT-VAU certificate to confirm its intended use for VAU operations.

    See: https://gemspec.gematik.de/docs/gemF/gemF_Personalisierung_HSM/gemF_Personalisierung_HSM_V1.0.0/#GS-A_4446-12
    """

    KOMP_CA_CN_RE = re.compile(r"^GEM\.KOMP-CA[1-9][0-9]*(?:\s|$)")
    """
    Regular expression to validate that the Common Name (CN) of the issuing CA certificate follows the expected pattern for TI Komponenten-PKI CAs:
    - Starts with "GEM.KOMP-CA"
    - Followed by a natural number (1, 2, 3, ...)
    - Optionally followed by a whitespace-separated suffix, e.g. "GEM.KOMP-CA56 TEST-ONLY"
    """

    @classmethod
    def validate_komponenten_pki(cls, aut_vau_cert: x509.Certificate, issuing_ca_der: bytes) -> None:
        """
        Verify that the AUT-VAU certificate was issued by a TI Komponenten-PKI CA.

        A_25192 implementation hint:
        - CA certificate CommonName starts with "GEM.KOMP-CA" followed by a natural number.
        - CA certificate is child of a TI-PKI root. (=> Already covered by A_24624-01#1/2 checks)

        See: https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.48.0/#A_25192-02
        """
        # Load issuing CA certificate from DER bytes provided in CertData. This is the certificate that directly issued the AUT-VAU certificate and must be a TI Komponenten-PKI CA.
        try:
            issuing_ca_cert = x509.load_der_x509_certificate(issuing_ca_der, default_backend())
        except Exception as e:
            cls._raise_failure(f"Could not parse issuing CA certificate: {type(e).__name__}: {e}")

        logger.debug(f"Issuing CA certificate: Subject={issuing_ca_cert.subject}, Issuer={issuing_ca_cert.issuer}, NotBefore={issuing_ca_cert.not_valid_before_utc}, NotAfter={issuing_ca_cert.not_valid_after_utc}") 
        # Verify that the issuing CA certificate is the direct issuer of the AUT-VAU certificate by comparing the issuer and subject fields.
        if aut_vau_cert.issuer != issuing_ca_cert.subject:
            cls._raise_failure("CertData CA certificate is not the direct issuer of the AUT-VAU certificate")

        # Find the Common Name (CN) attributes in the issuing CA certificate's subject
        common_name_attributes = issuing_ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_names = [cast(str, attr.value) for attr in common_name_attributes]

        if not common_names:
            cls._raise_failure("Issuing CA certificate does not contain a CommonName")

        # Check if any of the Common Names matches the expected pattern for TI Komponenten-PKI CAs.
        if not any(cls.KOMP_CA_CN_RE.match(cn) for cn in common_names):
            cls._raise_failure(
                f"Issuing CA certificate is not a TI Komponenten-PKI CA: expected CommonName starting with {cls.KOMP_CA_CN_RE.pattern!r}, got {common_names!r}"
            )

    @classmethod
    def validate_oid_epa_vau(cls, aut_vau_cert: x509.Certificate) -> None:
        """
        Verify that the certificate contains the role OID oid_epa_vau.
        The role OID is expected in the Admission extension: ExtensionOID.ADMISSIONS / 1.3.36.8.3.3

        Args:
            aut_vau_cert (x509.Certificate): AUT-VAU certificate.
        """

        # Extract the Admission extension from the certificate.
        # See: https://gemspec.gematik.de/prereleases/ePAfueralle/gemILF_PS_ePA_V3.0.0_CC/#A_20657
        try:
            admissions_ext = aut_vau_cert.extensions.get_extension_for_oid(ExtensionOID.ADMISSIONS)
        except x509.ExtensionNotFound:
            cls._raise_failure("AUT-VAU certificate does not contain the Admission extension")

        try:
            admissions = cast(x509.Admissions, admissions_ext.value)
        except Exception as e:
            cls._raise_failure(f"Failed to cast Admission extension: {e}")

        # Check if any of the ProfessionOIDs in the Admission extension matches the expected OID for VAU role.
        found_oids: list[str] = []
        for admission in admissions._admissions:
            for profession_info in admission.profession_infos:
                profession_oids = profession_info.profession_oids or []
                for oid in profession_oids:
                    found_oids.append(oid.dotted_string)

                    if oid == cls.OID_EPA_VAU:
                        return

        logger.error(
            f"Did not find required oid_epa_vau in certificate Admission extension. Found ProfessionOIDs: {', '.join(found_oids)}"
        )
        cls._raise_failure(
            f"AUT-VAU certificate does not contain role OID oid_epa_vau ({cls.OID_EPA_VAU.dotted_string}); found ProfessionOIDs: {', '.join(found_oids)}"
        )


class Step4(ValidationStep):
    """
    Executes checks from A_24624-01#4.

    Die Signatur im "signature-ES256"-Datenfeld MUSS eine valide Signatur für die Daten im Datenfeld "signed_pub_keys" (Signaturprüfung ergibt "valid/accept") sein, unter Verwendung des öffentlichen Signatur-Schlüssels aus dem VAU/TI-Zertifikats bei der Signaturprüfung.

    See: https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.48.0/#A_24624-01
    """

    _step_number = "4"

    @classmethod
    def validate_signed_pub_keys_signature(
        cls,
        aut_vau_cert: x509.Certificate,
        signature_es256: bytes,
        signed_pub_keys: bytes,
    ) -> None:
        """
        Execute protocol step #4 (A_24624-01):
        Verify that `signature-ES256` is a valid signature over `signed_pub_keys` using the public key from the validated AUT-VAU certificate.

        Args:
            aut_vau_cert (x509.Certificate): AUT-VAU certificate. Its public key is used to verify the signature.
            signature_es256 (bytes): Raw 64-byte ES256 signature from the `signature-ES256` field.
            signed_pub_keys (bytes): The exact bytes that were signed by the server.

        Raises:
            VAUException: If the certificate public key is not usable, the curve is unsupported, the signature has the wrong format, or the signature is invalid.
        """
        try:
            # Extract certificate public key for signature verification.
            public_key = aut_vau_cert.public_key()

            # ES256 requires an EC public key.
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                logger.error("Certificate public key is not an EC key")
                cls._raise_failure("Certificate public key is not an EC key")

            # Cast to specific type for better type checking
            public_key = cast(ec.EllipticCurvePublicKey, public_key)

            # Accept only protocol-allowed curves.
            # See:
            #   https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.48.0/#polarion_54
            #   https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.48.0/#GS-A_4359-02
            #   https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.48.0/#A_23139
            if not isinstance(public_key.curve, (ec.BrainpoolP256R1, ec.SECP256R1)):
                logger.error(
                    "Certificate EC key uses unsupported curve: %s",
                    public_key.curve.name,
                )
                cls._raise_failure(
                    f"Certificate EC curve must be brainpoolP256r1 or P-256, got {public_key.curve.name}"
                )

            # Expected raw ES256 signature format: 64 bytes R||S.
            if len(signature_es256) != 64:
                logger.error("signature-ES256 must be exactly 64 bytes")
                cls._raise_failure(f"signature-ES256 must be exactly 64 bytes, got {len(signature_es256)}")

            # Split raw signature into R and S integers.
            r = int.from_bytes(signature_es256[:32], byteorder="big")
            s = int.from_bytes(signature_es256[32:], byteorder="big")

            # Convert raw R||S to DER, which `cryptography` expects.
            signature_der = encode_dss_signature(r, s)

            # Verify integrity/origin of the signed key bundle. This checks if `signature_der` correctly signs `signed_pub_keys` using the public key from the AUT-VAU certificate.
            public_key.verify(
                signature_der,
                signed_pub_keys,
                ec.ECDSA(hashes.SHA256()),
            )

            logger.info("✓ Signature verification successful")

        except InvalidSignature:
            logger.error("✗ Invalid signature on signed public keys")
            cls._raise_failure("Invalid signature on signed public keys")


class Step5(ValidationStep):
    """
    Executes checks from A_24624-01#5.

    Der ECC-Schlüssel in signed_pub_keys (vgl. Erzeugung bei A_24425) MUSS ein gültiger Punkt der Kurve P-256 [FIPS-186-5] sein. Der öffentliche Schlüssel in "Kyber768_PK"-Datenfeld MUSS ein gültiger Kyber-768-Schlüssel [IEFT-Kyber] (should probably be "IETF-Kyber") sein.

    See: https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.48.0/#A_24624-01
    """

    _step_number = "5"

    _VAU_KYBER768_OQS_ALGORITHM = "Kyber768"
    """
    The OQS algorithm name for the Kyber-768 (field name: Kyber768_PK) mechanism used in the VAU protocol. 
    See:
        - https://www.ietf.org/archive/id/draft-cfrg-schwabe-kyber-04.html
        - https://openquantumsafe.org/liboqs/algorithms/kem/kyber#parameter-set-summary
    """

    @classmethod
    def validate_ecdh_p256_key(cls, ecdh_public_key: ECDHPublicKey) -> None:
        """
        Check that the ECDH public key provided in `signed_pub_keys` is a valid point on the P-256 curve.

        See: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf

        Args:
            ecdh_public_key (ECDHPublicKey): The ECDH public key to validate.
        """
        try:
            # Construct an EllipticCurvePublicNumbers object from the raw x and y coordinates, specifying the P-256 curve.
            ec_public_numbers = ec.EllipticCurvePublicNumbers(
                int.from_bytes(ecdh_public_key.x, byteorder="big", signed=False),
                int.from_bytes(ecdh_public_key.y, byteorder="big", signed=False),
                ec.SECP256R1(),
            )
            # The points are not validated until a call to public_key() is made.
            ec_public_numbers.public_key()
        except ValueError as e:
            cls._raise_failure(f"ECDH_PK is not a valid P-256 public key: {e}")

    @classmethod
    def validate_kyber768_key(cls, kyber_public_key: bytes) -> None:
        """
        Check that the Kyber-768 public key provided in `signed_pub_keys` is structurally usable as a Kyber768 public key.

        Args:
            kyber_public_key (bytes): The Kyber-768 public key to validate.
        """
        try:
            with oqs.KeyEncapsulation(cls._VAU_KYBER768_OQS_ALGORITHM) as kem:
                expected_len = kem.details["length_public_key"]

                if len(kyber_public_key) != expected_len:
                    cls._raise_failure(f"Kyber768_PK must be {expected_len} bytes, got {len(kyber_public_key)}")

                # Attempt to use the provided key in an encapsulation operation to verify that it is structurally valid.
                kem.encap_secret(kyber_public_key)
        except VAUException:
            raise
        except Exception as e:
            cls._raise_failure(f"Invalid Kyber768_PK: {type(e).__name__}: {e}")


class Step6(ValidationStep):
    """
    Executes checks from A_24624-01#6.

    Die Zeit in "signed_pub_keys.exp" MUSS größer als die aktuelle Systemzeit (Seconds since epoch) sein, d. h. die beiden Schlüssel (ECDH_PK und Kyber768_PK) sind noch zeitlich gültig.

    See: https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.48.0/#A_24624-01
    """

    _step_number = "6"

    @classmethod
    def validate_signed_pub_keys_expiry(cls, exp: int) -> None:
        """
        Check that the `exp` field in `signed_pub_keys` contains a time in the future, ensuring that the provided keys (ECDH_PK and Kyber768_PK) are still valid for use.

        Args:
            exp (int): The expiration time to check.
        """
        now = int(datetime.now(timezone.utc).timestamp())

        if exp <= now:
            cls._raise_failure(f"signed_pub_keys.exp must be greater than current system time: exp={exp}, now={now}")
