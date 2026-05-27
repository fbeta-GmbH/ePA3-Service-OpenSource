"""
Configurable Truststore class for the Telematics Infrastructure (TI) of gematik.
This class enables downloading and managing root and sub-CA certificates as well as the root.json from the respective URLs.
It provides functions to update the truststore based on a configurable time interval and stores the certificates
in a specified directory, as well as creating a combined PEM truststore for TLS connections.
"""

import base64
import json
import os
import re
from urllib.parse import urljoin
import requests
import hashlib

from app.truststores.ti.utils import ROOT_FILE_RE, SUB_FILE_RE

from app.runtime_config.epa_env import EpaEnvConfig
from app.logging_config import logger
from app.truststores.builder_lock import Builder_Locker

from cryptography import x509
from cryptography.hazmat.primitives import serialization
import certifi
from lxml import etree 
import ssl

class TI_Truststore:
    """
    A class to manage and update the truststore for the Telematics Infrastructure.

    Attributes:
        ca_path (str): Path to store the certificates.
        epa_envs (EpaEnvConfig): Environment configurations for the application.
        provider_mapping (dict[str, int]): Mapping of providers to their identifiers.
        http_timeout (int): Timeout for HTTP requests.
    """

    def __init__(self, ca_path: str, epa_envs: EpaEnvConfig, provider_mapping: dict[str, int], https_timeout: int = 30):
        """
        Initializes the TI_Truststore instance.

        Args:
            ca_path (str): Path to store the certificates.
            epa_envs (EpaEnvConfig): Environment configurations for the application.
            provider_mapping (dict[str, int]): Mapping of providers to their identifiers.
            https_timeout (int): Timeout for HTTPS requests.
        """
        self.ca_path = os.path.join(ca_path, epa_envs.ti_root_certs)
        self.epa_envs = epa_envs
        self.https_timeout = https_timeout
        
        self.provider_mapping = provider_mapping
                
        self.ca_base_url = self.epa_envs.get_root_ca_url()   
        self.sub_ca_base_url = self.epa_envs.get_sub_ca_url() 
        
        # Paths for root CA certificates and root.json
        self.ca_path_roots = os.path.join(self.ca_path, "roots")
        self.ca_path_root_json = os.path.join(self.ca_path, "roots.json")
        self.ca_base_url_root_json = urljoin(self.ca_base_url, "roots.json")
        
        # Paths for sub-CA certificates and TSL XML
        self.ca_path_sub = os.path.join(self.ca_path, "subs")
        self.ca_tsl_xml_url = self.epa_envs.get_tsl_url()
        self.ca_tsl_xml_path = os.path.join(self.ca_path, "tsl.xml")
        
        self.pem_path = os.path.join(self.ca_path, "bundles", "ti.pem")
        
        self.builder_locker = Builder_Locker(lock_file="ti_truststore_builder")
        
        os.makedirs(self.ca_path_roots, exist_ok=True)
        os.makedirs(self.ca_path_sub, exist_ok=True)
        os.makedirs(os.path.dirname(self.pem_path), exist_ok=True)
        
        
    
    def build_ca_bundle(self):
        """
        Builds the CA bundle by downloading and validating root and sub-CA certificates, and combining them into a PEM file.

        Returns:
            str: Path to the combined PEM file if successful, None otherwise.
        """
        try:
            if not os.path.exists(self.pem_path):
                logger.info("Initializing TI CA bundle. Building bundle.")
                return self.refresh_ca_bundle()
            else:
                logger.info("TI CA bundle already exists. Using existing bundle.")
                return self.pem_path
        except Exception as e:
            logger.error(f"Error initial building TI CA bundle: {e}")
            raise

    
    def refresh_ca_bundle(self):
        """
        Updates the CA bundle by downloading root and sub-CA certificates from the configured URLs
        and saving them in a combined PEM format. Checks if the certificates need to be updated
        based on the last update time and the configured interval.

        Returns:
            str: Path to the updated CA bundle if successful, None otherwise.
        """
        
        is_builder = False
        try:
            is_builder = self.builder_locker.lock_for_builder()
            
            if is_builder:    
            
                logger.info("Refreshing CA bundle...")
                
                root_json = self._get_root_json(self.ca_base_url_root_json, self.ca_path_root_json, force_refresh=True)
                sub_tsl_xml = self._get_sub_tsl_xml(self.ca_tsl_xml_url, self.ca_tsl_xml_path, force_refresh=True)
                
                fingerprint_map = self._map_root_cn_to_expected_fingerprint(root_json)
                sub_fingerprint_set = self._map_sub_cert_fingerprints(sub_tsl_xml)
                
                root_ca_name_list = self._list_files(self.ca_base_url, ROOT_FILE_RE[self.epa_envs.id])
                sub_ca_name_list = self._list_files(self.sub_ca_base_url, SUB_FILE_RE[self.epa_envs.id])

                file_paths = self._load_root_certificates(root_ca_name_list, fingerprint_map, self.ca_base_url, force_download=True)
                file_paths += self._load_sub_certificates(sub_ca_name_list, sub_fingerprint_set, self.sub_ca_base_url, force_download=True)
                        
                ca_bundle_path = self._combine_certs_to_pem(cert_paths=file_paths, output_path=self.pem_path)
                
                if self.verify_bundle(ca_bundle_path):
                    logger.info("CA bundle refreshed successfully.")  
                    return ca_bundle_path

                raise ssl.SSLCertVerificationError("Failed to verify TI CA bundle.")
            else:
                if os.path.exists(self.pem_path):
                    return self.pem_path
                else:
                    raise FileNotFoundError("No existing CA bundle found.")
            
        except TimeoutError as e:
            logger.error(f"Timeout while waiting for builder lock: {e}")
            raise
        finally:
            if is_builder:
                self.builder_locker.unlock_for_builder()
        
    # === Root CA ===
        
    def _load_root_certificates(self, cert_name_list: list[str], fingerprint_map: dict, base_url: str, force_download: bool = False) -> list[str]:
        """
        Loads root CA certificates and validates them against fingerprints from root.json.

        Args:
            cert_name_list (list[str]): List of certificate names.
            fingerprint_map (dict): Mapping of certificate names to expected fingerprints.
            base_url (str): Base URL for downloading certificates.

        Returns:
            list[str]: List of file paths to the downloaded and validated certificates.
        """
        file_paths = []
        
        for file_name in cert_name_list:
            logger.info(f"Downloading Root CA: {file_name}...")
            save_path = os.path.join(self.ca_path_roots, file_name)
            self._download_file(url=base_url + file_name, save_path=save_path, force_download=force_download)
            
            expected_fingerprint = fingerprint_map.get(file_name.replace(".der", "").replace("_", " ").lower())
            if not expected_fingerprint:
                logger.warning(f"No fingerprint found for {file_name}. Skipping.")
                continue
            
            if not self._check_integrity(file_path=save_path, expected_fingerprint=expected_fingerprint):
                logger.warning(f"File {file_name} failed integrity check.")
                continue
            
            logger.debug(f"File {file_name} passed integrity check.")
            file_paths.append(save_path)
        
        return file_paths
    
    def _get_root_json(self, base_url_root_json: str, root_json_path: str, force_refresh: bool = False) -> list[dict]:
        """
        Checks if a root.json file exists. If not, downloads the corresponding root.json.
        Loads the root.json as a dictionary.

        Args:
            base_url_root_json (str): URL to download the root.json file.
            root_json_path (str): Path to save the root.json file.

        Returns:
            list[dict]: root.json as a list of dictionaries.
        """
        if os.path.exists(root_json_path) and not force_refresh:
            with open(root_json_path, "r") as f:
                root_json = json.load(f)
        else:
            response = requests.get(base_url_root_json, timeout=self.https_timeout)
            response.raise_for_status()
            root_json = response.json()
            with open (root_json_path, "w") as f:
                json.dump(root_json, f)
        return root_json

        
    def _map_root_cn_to_expected_fingerprint(self, root_json: list[dict]) -> dict[str, str]:
        """
        Extracts fingerprints from root.json, indexed by CN.

        Args:
            root_json (list[dict]): List of dictionaries from root.json.

        Returns:
            dict[str, str]: Mapping of CNs to their respective fingerprints.
        """
        hashes_by_cn: dict[str, str] = {}
        
        for entry in root_json:
            cn = entry.get("cn")
            cert_b64 = entry.get("cert")
            
            if not cn or not cert_b64:
                continue
            
            cn = cn.lower()
            cert_der = base64.b64decode(cert_b64)
            digest = hashlib.sha256(cert_der).hexdigest().lower()
            hashes_by_cn[cn] = digest
        
        return hashes_by_cn
    
    # === Sub-CA ===
    
    def _load_sub_certificates(self, cert_name_list: list[str], fingerprint_set: set[str], base_url: str, force_download: bool = False) -> list[str]:
        """
        Loads sub-CA certificates and validates them.

        Args:
            cert_name_list (list[str]): List of certificate names.
            fingerprint_set (set[str]): Set of valid fingerprints.
            base_url (str): Base URL for downloading certificates.

        Returns:
            list[str]: List of file paths to the downloaded and validated certificates.
        """
        file_paths = []

        for file_name in cert_name_list:
            logger.info(f"Downloading Sub-CA: {file_name}...")
            save_path = os.path.join(self.ca_path_sub, file_name)
            self._download_file(url=base_url + file_name, save_path=save_path, force_download=force_download)

            actual_fingerprint = self._get_sha256_fingerprint(save_path)
            if actual_fingerprint not in fingerprint_set:
                logger.warning(f"Sub-CA {file_name} not in TSL fingerprint list. Skipping.")
                continue

            logger.debug(f"Sub-CA {file_name} validation passed.")
            file_paths.append(save_path)

        return file_paths
    
    def _get_sub_tsl_xml(self, tsl_url: str, tsl_path: str, force_refresh: bool = False) -> str:
        """
        Retrieves the TSL XML file. If it exists locally, loads it; otherwise, downloads it.

        Args:
            tsl_url (str): URL to download the TSL XML file.
            tsl_path (str): Path to save the TSL XML file.

        Returns:
            str: Content of the TSL XML file.
        """
        if os.path.exists(tsl_path) and not force_refresh:
            with open(tsl_path, "r") as f:
                tsl_xml = f.read()
        else:
            response = requests.get(tsl_url, timeout=self.https_timeout)
            response.raise_for_status()
            tsl_xml = response.text
            with open(tsl_path, "w") as f:
                f.write(tsl_xml)
        return tsl_xml
    
    
    def _map_sub_cert_fingerprints(self, tsl_xml: str) -> set[str]:
        """
        Extracts all certificate fingerprints from the TSL.

        Args:
            tsl_xml (str): Content of the TSL XML file.

        Returns:
            set[str]: Set of extracted fingerprints.
        """
        tree = etree.fromstring(tsl_xml.encode('utf-8'))
        fingerprints: set[str] = set()
        
        for el in tree.iterfind(".//tsl:X509Certificate", {"tsl": "http://uri.etsi.org/02231/v2#"}):
            if not el.text:
                continue
            
            try:
                der = base64.b64decode("".join(el.text.split()))
                fp = hashlib.sha256(der).hexdigest().lower()
                fingerprints.add(fp)
            except Exception as e:
                logger.warning(f"Failed to extract fingerprint from TSL certificate: {e}")
                continue
        
        return fingerprints
    

    # === Helper Functions ===
    
    def verify_bundle(self, ca_bundle_path: str) -> bool:
        """
        Ensures the CA bundle is present and up-to-date. If the bundle is missing or outdated,
        it will be updated. Returns the path to the current CA bundle.

        Args:
            ca_bundle_path (str): Path to the CA bundle.

        Returns:
            bool: True if the bundle is valid, False otherwise.
        """
    
        if not self.provider_mapping:
            logger.warning("No providers configured. Cannot verify CA bundle.")
            return False
        as_url = None
        try:
            for provider_name, provider_id in self.provider_mapping.items():
                as_url = self.epa_envs.get_as_url(str(provider_id))
                response = requests.get(as_url, timeout=self.https_timeout, verify=ca_bundle_path)
                logger.info(f"AS URL {as_url} is reachable with status code {response.status_code}.")
            return True
        except requests.exceptions.SSLError as e:
            logger.warning(f"SSL error when connecting to AS URL {as_url}: {e}. Attempting to refresh CA bundle.")
            return False
        except requests.RequestException as e:
            logger.error(f"Error when connecting to AS URL {as_url}: {e}.")
            return False
    
    
    def _list_files(self, url:str, regex: re.Pattern) -> list[str]:
        """
        Lists files from a given URL matching a regex pattern.

        Args:
            url (str): URL to fetch the file list from.
            regex (re.Pattern): Regular expression to match file names.

        Returns:
            list[str]: List of file names matching the regex.
        """
        response = requests.get(url, timeout=self.https_timeout)
        response.raise_for_status()
        
        file_name_list = set(regex.findall(response.text))
        
        return list(file_name_list)
    
    
    def _download_file(self, url:str, save_path: str, force_download: bool = False) -> None:
        """
        Downloads a file from the specified URL and saves it to the given path.

        Args:
            url (str): URL of the file to download.
            save_path (str): Path to save the downloaded file.
        """
        if os.path.exists(save_path) and not force_download:
            logger.info(f"File {save_path} already exists. Skipping download.")
            return
        if os.path.exists(save_path) and force_download:
            logger.info(f"Refreshing existing file: {save_path}")
        
        response = requests.get(url, timeout=self.https_timeout)
        response.raise_for_status()
        
        with open(save_path, "wb") as f:
            f.write(response.content)
       
            
    def _check_integrity(self, file_path: str, expected_fingerprint: str) -> bool:
        """
        Checks the integrity of a file by comparing its SHA-256 fingerprint with the expected fingerprint.

        Args:
            file_path (str): Path to the file to check.
            expected_fingerprint (str): Expected SHA-256 fingerprint.

        Returns:
            bool: True if the fingerprints match, False otherwise.
        """
        actual_fingerprint = self._get_sha256_fingerprint(file_path)
        return actual_fingerprint == expected_fingerprint  
     
            
    def _get_sha256_fingerprint(self, cert_path: str) -> str:
        """
        Computes the SHA-256 fingerprint of a certificate file.

        Args:
            cert_path (str): Path to the certificate file.

        Returns:
            str: SHA-256 fingerprint of the certificate.
        """
        with open(cert_path, "rb") as f:
            cert_data = f.read()
            return hashlib.sha256(cert_data).hexdigest()
            
            
    def _combine_certs_to_pem(self, cert_paths: list[str], output_path: str) -> str:
        """
        Combines multiple certificates into a single PEM file.

        Args:
            cert_paths (list[str]): List of paths to certificate files.
            output_path (str): Path to save the combined PEM file.

        Returns:
            str: Path to the combined PEM file.
        """
        with open(output_path, "wb") as pem_file:
            for cert_path in cert_paths:
                with open(cert_path, "rb") as cert_file:
                    cert = x509.load_der_x509_certificate(cert_file.read())
                    pem = cert.public_bytes(serialization.Encoding.PEM)
                    
                    pem_file.write(pem if pem.endswith(b"\n") else pem + b"\n")
            
            with open(certifi.where(), "rb") as certifi_file:
                pem_file.write(b"\n")
                pem_file.write(certifi_file.read())
                    
        return output_path
    
    # === Getters ===
    
    def get_root_ca_path(self) -> str:
        return self.ca_path_roots


