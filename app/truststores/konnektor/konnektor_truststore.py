import os

import requests
import json
import base64

from app.runtime_config.epa_env import EpaEnvConfig
from app.konnektor.pkcs12adapter import PinnedPkcs12Adapter
from app.truststores.builder_lock import Builder_Locker
from cryptography import x509
from cryptography.hazmat.primitives import serialization   

from requests import Session
from requests.adapters import HTTPAdapter

from app.logging_config import logger

import ssl


class Konnektor_Truststore():
    """Class to manage the Konnektor truststore, including downloading and verifying the CA bundle."""
    
    def __init__(self, ca_bundle_path: str, epa_envs: EpaEnvConfig, konnektor_url: str, konnektor_jws_url: str, p12_path: str, p12_password: str, https_timeout: int):
        self.ca_bundle_path = os.path.join(ca_bundle_path, epa_envs.ti_root_certs)
        self.konnektor_url = konnektor_url
        self.konnektor_jws_url = konnektor_jws_url
        self.p12_path = p12_path
        self.p12_password = p12_password
        
        self.https_timeout = https_timeout
        
        self.pem_path = os.path.join(self.ca_bundle_path, "bundles", "konnektor_cert.pem")
        self.builder_locker = Builder_Locker("konnektor_truststore_builder")
        
        os.makedirs(self.ca_bundle_path, exist_ok=True)
        os.makedirs(os.path.dirname(self.pem_path), exist_ok=True)

    
    def build_ca_bundle(self):
        """
        Builds the CA bundle by downloading and validating root and sub-CA certificates, and combining them into a PEM file.

        Returns:
            str: Path to the combined PEM file if successful, None otherwise.
        """
        try:
            if not os.path.exists(self.pem_path):
                logger.info("Initializing Konnektor CA bundle. Building bundle.")
                return self.refresh_ca_bundle()
            else:
                logger.info("Konnektor CA bundle already exists. Using existing bundle.")
                return self.pem_path
        except Exception as e:
            logger.error(f"Error initial building Konnektor CA bundle: {e}")
            return None
    
    def refresh_ca_bundle(self) -> str | None:
        """Downloads the latest Konnektor certificates, saves them to the CA bundle path, and verifies the bundle.
        Returns:
            str: The path to the updated CA bundle if successful, None otherwise.
        """
        if self.konnektor_jws_url == "":
            if os.path.exists(self.pem_path):
                logger.info("KONNEKTOR_JWS_URL is not set. Using existing Konnektor CA bundle (automatic refresh is not available).")
                return self.pem_path
            logger.error("KONNEKTOR_JWS_URL is not set and no existing certificate bundle was found.")
            return None

        is_builder = False
        try:
            is_builder = self.builder_locker.lock_for_builder()
            
            if is_builder:
                self._download_certs(self.pem_path)
                if self.verify_bundle():
                    logger.info("Konnektor CA bundle verified successfully.")
                    return self.pem_path
                else:
                    logger.error("Failed to verify Konnektor with the new CA bundle. Please check the logs for details.")
                    raise ssl.SSLCertVerificationError("Failed to verify Konnektor with the new CA bundle.")  
            else:
                if os.path.exists(self.pem_path):
                    logger.info("Konnektor CA bundle is being updated by another process. Using existing bundle.")
                    return self.pem_path
                else:
                    logger.warning("Konnektor CA bundle is being updated by another process, but no existing bundle found. Waiting for update to complete.")
                    raise FileNotFoundError("Konnektor CA bundle not found while waiting for builder to update it.")
        except TimeoutError as e:
            logger.error(f"Timeout while waiting for builder lock: {e}")
            raise
        finally:
            if is_builder:
                self.builder_locker.unlock_for_builder()

        
        
    def _download_certs(self, output_path: str) -> str:
        """Downloads the latest Konnektor certificates from the provider-published JWS file and saves them to the specified output path.
        
        JWS format: header.payload.signature
        Cert path in payload: data -> v1 -> kon -> [base64-encoded DER certs]
        
        Returns:
            str: The path to the saved CA bundle file.
        """
        
        output_file = output_path
        
        response = requests.get(self.konnektor_jws_url, timeout=self.https_timeout)
        response.raise_for_status()
        
        # split JWS into header, payload, signature
        header, payload, signature = response.text.split('.')
        
        # Decode payload from base64
        decoded_payload = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)).decode())
        
        logger.debug(f"Decoded JWS payload: {json.dumps(decoded_payload, indent=2)}")
        
        data = json.loads(base64.urlsafe_b64decode(decoded_payload.get("data", "") + '=' * (-len(decoded_payload.get("data", "")) % 4)).decode())
        
        logger.debug(f"Decoded 'data' field from JWS payload: {json.dumps(data, indent=2)}")
        
        kons = data.get("v1", {}).get("kon", [])
                
        pems = []
                
        for kon in kons:
            cert = x509.load_der_x509_certificate(base64.b64decode(kon))
            # Convert to PEM format
            pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
            pems.append(pem)
        
        with open(output_file, "wb") as pem_file:
            for pem in pems:
                pem_file.write(pem if pem.endswith(b"\n") else pem + b"\n")
        
        return output_file
        
    
    def verify_bundle(self):
        """Verifies the Konnektor CA bundle by attempting to connect to the Konnektor endpoint.

        Returns:
            bool: True if the bundle is valid and the Konnektor is reachable, False otherwise.
        """
        bundle = self.pem_path
        url = self.konnektor_url.rstrip("/") + "/connector.sds"

        try:
            s = Session()
            s.mount(
                "https://",
                PinnedPkcs12Adapter(
                    pkcs12_filename=self.p12_path,
                    pkcs12_password=self.p12_password,
                    ca_bundle=bundle,
                ),
            )
            s.mount("http://", HTTPAdapter(max_retries=2))
            s.verify = bundle

            response = s.get(url, timeout=self.https_timeout)
            logger.info(f"Konnektor reachable: {response.status_code}")
            return True
        except requests.exceptions.SSLError as e:
            logger.warning(f"SSL error: {e}")
            return False
        except requests.RequestException as e:
            logger.warning(f"Request error: {e}")
            return False