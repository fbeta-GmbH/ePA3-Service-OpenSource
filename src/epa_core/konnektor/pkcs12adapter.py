import requests_pkcs12
import os
import glob
import ssl
import socket
import urllib3.util.connection


from epa_core.http_status import status

from epa_core.exceptions import ErrorCodes, KonnektorException
from epa_core.runtime_config.logging import logger


class PinnedPkcs12Adapter(requests_pkcs12.Pkcs12Adapter):
    """Pkcs12Adapter mit PARTIAL_CHAIN-Flag für Leaf-Pinning und optionalem IP-Override."""

    def __init__(self, *args, ca_bundle: str | None = None, target_ip: str | None = None, 
                 tls_hostname: str | None = None, **kwargs):
        
        self.target_ip = target_ip
        self.tls_hostname = tls_hostname
        
        super().__init__(*args, **kwargs)
        
        if ca_bundle:
            ctx = self.ssl_context
            ctx.load_verify_locations(cafile=ca_bundle)
            # Allow pinning against JWS-provided certs without requiring a full chain to a system root.
            ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

    def init_poolmanager(self, *args, **kwargs):
        """
        init_poolmanager ist eine Funktion zum Initialisieren des PoolManagers für die Pkcs12Adapter-Klasse.
        Diese wird bei der __init__-Methode des Pkcs12Adapters aufgerufen, um die Verbindungspools für HTTPS-Verbindungen zu initialisieren.
        init_poolmanager erstellt einen PoolManager, welcher HTTPSConnectionsPools erstellt und verwaltet.
        Im HTTPSConnectionPool können dann HTTPS-Verbindungen konfiguriert werden.
        
        In dieser überladenen Funktion wird diese eigenart genutzt um die Verbindung zu einem bestimmten Ziel-IP-Adresse umzuleiten, 
        während der TLS-Handshake weiterhin den Hostnamen verwendet.
        
        Während des TLS-Handshakes wird der Hostname (tls_hostname) verwendet, um das Zertifikat zu validieren,
        während die Verbindung tatsächlich zu einer angegebenen IP-Adresse (target_ip) hergestellt wird.
        
        Aus diesem Grund muss im zweiten SChritt die create_connection-Funktion von urllib3.util.connection überladen werden, 
        um die Verbindung zu der target_ip herzustellen (Monkey-Patching).

        """
        if self.target_ip and self.tls_hostname:
            kwargs['assert_hostname'] = self.tls_hostname
            kwargs['server_hostname'] = self.tls_hostname
            
            original_create_connection = urllib3.util.connection.create_connection
            target_ip = self.target_ip
            
            def custom_create_connection(address, *args, **kwargs):
                """
                Funktion um die create_connection-Funktion von urllib3.util.connection zu überladen (Monkey Patching).
                Hier sollen Verbindungen die an die tls_hostname gehen, auf die target_ip umgeleitet werden.
                Falls die Verbindung nicht an den tls_hostname geht, wird die originale create_connection-Funktion aufgerufen.
                """
                host, port = address
                if host == self.tls_hostname:
                    logger.debug(f"Redirecting connection from {host}:{port} to {target_ip}:{port}")
                    return original_create_connection((target_ip, port), *args, **kwargs)
                else:
                    return original_create_connection(address, *args, **kwargs)
            
            # Monkey-Patching der create_connection-Funktion von urllib3.util.connection
            urllib3.util.connection.create_connection = custom_create_connection
            
        return super().init_poolmanager(*args, **kwargs)
            

def find_p12(user_config_dir: str) -> str:
    """
    Initialize the API on startup - search for a .p12 file in the config directory
    and handle it as the cert_path.

    Args:
        user_config_dir (str): The directory to search for the .p12 file.
    Returns:
        str: The path to the .p12 file if found.
    Raises:
        KonnektorException: If the directory does not exist or if no .p12 file is found.
    """
    try:
        # Search for .p12 files in the config directory
        p12_files = glob.glob(os.path.join(user_config_dir, "*.p12"))
        if not p12_files:
            raise Exception("No .p12 certificate file found in the config directory.")

        # Use the first .p12 file found
        if len(p12_files) > 1:
            p12_files.sort(key=lambda x: os.path.basename(x).lower())  # Sort alphabetically by filename
            logger.warning(
                f"Multiple .p12 files found. Using the first one (alphabetically): {os.path.basename(p12_files[0])}"
            )

        cert_path = p12_files[0]

        logger.info(f"Found .p12 certificate file: {os.path.abspath(cert_path)}")
        return cert_path
    except Exception as e:
        logger.error("Certificate file not found")
        raise KonnektorException(
            message="Certificate file not found",
            error_code=ErrorCodes.KONNEKTOR_INIT_FAILED,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "path": user_config_dir,
                "resolution": "Please ensure the certificate exists in the config directory and is named with a .p12 extension.",
            },
        )
