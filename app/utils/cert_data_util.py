from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
import base64



from app.runtime_config.logging import logger

class ReadCertData:
    def __init__(self, cert_base64: str):
        try:
            # Base64-dekodieren und als DER-Zertifikat laden
            cert_bytes = base64.b64decode(cert_base64)
            self.cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
            # Definiere die OID für die Admission-Extension
            ADMISSION_IDENTIFIER_ID = "1.3.36.8.3.3"
            ADMISSION_OID = x509.ObjectIdentifier(ADMISSION_IDENTIFIER_ID)

            try:
                admission_extension = self.cert.extensions.get_extension_for_oid(ADMISSION_OID)
                admission_values = admission_extension.value
                
                if admission_values:
                    first_admission_value = admission_values[0]
                    if hasattr(first_admission_value, "profession_infos") and first_admission_value.profession_infos:
                        profession_info = first_admission_value.profession_infos[0]
                        self.profession_info = profession_info

            except x509.ExtensionNotFound:
                logger.error("Admission Extension not found in certificate.")

        except Exception as e:
            logger.error(f"Error during reading certificate: {e}")

    def read_telematik_id(self) -> str:
        try:
            if hasattr(self.profession_info, "registration_number"):
                registration_number = self.profession_info.registration_number
                logger.debug(f"Telematik-ID found in certificate: {registration_number}")        
                return registration_number

        except x509.ExtensionNotFound:
                logger.error("Admission Extension not found in certificate.")

        raise ValueError("Telematik-ID not found.")
    
    def read_profession_oid(self) -> str:
        try:
            if hasattr(self.profession_info, "profession_oids"):
                profession_oids = self.profession_info.profession_oids           
                for profession_oid in profession_oids:
                    if profession_oid.dotted_string:
                        logger.debug(f"Profession OIDs found in certificate: {profession_oid.dotted_string}")
                        return profession_oid.dotted_string

        except x509.ExtensionNotFound:
            logger.error("Admission Extension not found in certificate.")

        raise ValueError("Profession OIDs not found.")

    def read_organization_name(self) -> str:
        try:
            org_names = self.cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
            if org_names:
                logger.debug(f"Organization name found in certificate: {org_names[0].value}")
                return str(org_names[0].value)
        except Exception as e:
            logger.error(f"Error reading organization name: {e}")
        raise ValueError("Organization name not found in certificate.")

    def read_common_name(self) -> str:
        try:
            common_name_attributes = self.cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if common_name_attributes:
                logger.debug(f"Common name found in certificate: {common_name_attributes[0].value}")
                return str(common_name_attributes[0].value)
        except Exception as e:
            logger.error(f"Error reading common name: {e}")
        raise ValueError("Common name not found in certificate.")

    def read_surname(self) -> str | None:
        """Read surName from cert Subject DN (optional, KBV-sector SMC-B only)."""
        surname_attributes = self.cert.subject.get_attributes_for_oid(x509.oid.NameOID.SURNAME)
        return str(surname_attributes[0].value) if surname_attributes else None

    def read_given_name(self) -> str | None:
        """Read givenName from cert Subject DN (optional, KBV-sector SMC-B only)."""
        given_name_attributes = self.cert.subject.get_attributes_for_oid(x509.oid.NameOID.GIVEN_NAME)
        return str(given_name_attributes[0].value) if given_name_attributes else None

    def read_title(self) -> str | None:
        """Read title from cert Subject DN (optional, KBV-sector SMC-B only)."""
        title_attributes = self.cert.subject.get_attributes_for_oid(x509.oid.NameOID.TITLE)
        return str(title_attributes[0].value) if title_attributes else None
