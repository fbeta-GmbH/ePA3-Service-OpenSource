import requests_pkcs12
import os
import glob
import ssl

from http import HTTPStatus as status

from app.exceptions import ErrorCodes, KonnektorException
from app.logging_config import logger


class PinnedPkcs12Adapter(requests_pkcs12.Pkcs12Adapter):
    """Pkcs12Adapter mit PARTIAL_CHAIN-Flag für Leaf-Pinning."""

    def __init__(self, *args, ca_bundle: str | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        if ca_bundle:
            ctx = self.ssl_context
            ctx.load_verify_locations(cafile=ca_bundle)
            # Allow pinning against JWS-provided certs without requiring a full chain to a system root.
            ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            
            

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
            status_code=status.INTERNAL_SERVER_ERROR,
            detail={
                "path": user_config_dir,
                "resolution": "Please ensure the certificate exists in the config directory and is named with a .p12 extension.",
            },
        )
