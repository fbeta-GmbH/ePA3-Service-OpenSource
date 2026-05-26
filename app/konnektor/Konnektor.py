from typing import Optional, Tuple
import requests
import requests_pkcs12
import base64
import hashlib
import datetime
import json
import sqlite3
import os

from fastapi import status
from requests import Session
from requests.adapters import HTTPAdapter

from app.logging_config import logger

from app.utils.utils import convert_der_ecdsa_to_concated_x962
from app.constants import MANDANT_ID, CLIENT_SYSTEM_ID, USER_AGENT, WORKPLACE_ID, HTTPS_TIMEOUT, USER_ID, DIGA_NAME, DIGA_MANUFACTURER, KONNEKTOR_URL, KONNEKTOR_CERT_PW

from app.exceptions import KonnektorException, CardException, ErrorCodes

from app.xml_service.soap_client import SoapClient



class Konnektor:
    def __init__(self, path_to_p12:str, test_conn: bool = True)->None:
        """
        Initialize a new instance of the Konnektor class.
        
        Args:
            path_to_p12 (str): Path to the PKCS#12 (.p12) certificate file
        """
        logger.info("Initializing Konnektor with p12 certificate: %s", path_to_p12)
        self.path_to_p12 = path_to_p12
        self.cert_password = KONNEKTOR_CERT_PW

        self.session = Session()

        pkcs12_adapter = requests_pkcs12.Pkcs12Adapter(
            pkcs12_filename=self.path_to_p12,
            pkcs12_password=self.cert_password
        )

        self.session.mount("https://", pkcs12_adapter)
        self.session.mount("http://", HTTPAdapter(max_retries=2))
        self.session.headers.update({
            'Content-Type': 'application/xml',
        })
        self.session.verify = False

        self.db = self.init_db()
        
        try:
            if test_conn:
                self.test_connection()
        except KonnektorException as e:
            logger.error("Failed to initialize Konnektor connection: %s", str(e))
            raise
    


    def init_db(self)->sqlite3.Connection:
        """
        Initialize the SQLite database for storing card data.
        Creates a table 'card_data' with columns for id, card handle, and certificate.
        """
        db = sqlite3.connect(os.getenv('SQLITE_DB_PATH', 'card_data.db'))
        c = db.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS card_data
                    (id INTEGER PRIMARY KEY, card TEXT, card_certificate TEXT)''')
        db.commit()
        return db
    
    def test_connection(self)->bool:
        """
        Test the connection to the Konnektor by sending a simple GET request.

        Returns:
            bool: True if the connection is successful, False otherwise.
        """
        try:
            response = self.session.get(f'{KONNEKTOR_URL}/connector.sds', timeout=HTTPS_TIMEOUT)
            if response.status_code == status.HTTP_200_OK:
                logger.info("Konnektor connection test successful")
                return True
            else:
                logger.error("Konnektor connection test failed with status code: %d", response.status_code)
                return False     
        except requests.exceptions.RequestException as e:

            raise KonnektorException(
                message=f"Konnektor initialization failed due to connection error: {e}",
                error_code=ErrorCodes.KONNEKTOR_INIT_FAILED)
            
            


    def store_card_data(self, card:Optional[str]=None, card_certificate:Optional[str]=None)->None:
        """
        Set card data in enviroments.
        
        Args:
            card (str): Card handle to store
            card_certificate (str): Card's certificate data to store
        """
        if card is None and card_certificate is None:
            raise ValueError("Both card and card_certificate are not provided")
        if card:
            os.environ["CARD"] = card
        if card_certificate:
            os.environ["CARD_CERTIFICATE"] = card_certificate
        
        c = self.db.cursor()
        c.execute("INSERT INTO card_data (card, card_certificate) VALUES (?, ?)", (card, card_certificate))
        self.db.commit()


    def clear_card_data(self)->None:
        """
        Clear card data from enviroments and database.
        """
        card_env = os.environ.pop("CARD", None)
        cert_env = os.environ.pop("CARD_CERTIFICATE", None)
        if card_env:
            logger.debug("Cleared card handle from environment variables.")
        if cert_env:
            logger.debug("Cleared card certificate from environment variables.")

        c = self.db.cursor()
        c.execute("SELECT card, card_certificate FROM card_data")
        rows = c.fetchall()
        if rows:
            logger.debug(f"Clearing {len(rows)} entries of card data from database.")
        
        c.execute("DELETE FROM card_data")
        self.db.commit()


    def get_card_data(self)->tuple:
        """
        Retrieve card data from the enviroments.
        
        Returns:
            tuple: (card_handle, card_certificate) pair or None if no data exists
        """
        card = os.getenv("CARD")
        card_certificate = os.getenv("CARD_CERTIFICATE")
        if card is None or card_certificate is None:
            c = self.db.cursor()
            c.execute("SELECT card, card_certificate FROM card_data ORDER BY id DESC LIMIT 1")
            row = c.fetchone()
            return row if row else (None, None)
        return card, card_certificate


    def get_cards(self)->str:
        """
        Query the Konnektor for available cards and retrieve the SMC-B card handle.
        
        Returns:
            str: Handle of the SMC-B card
            
        Raises:
            ValueError: If no SMC-B card is found
            requests.exceptions.RequestException: If the Konnektor request fails
        """
        try:
            logger.info("Getting cards")

            soap_request = SoapClient.generate_xml(
                SoapClient.Services.EventService.EventServicePort.GetCards, 
                params={
                    "Context": {
                        "MandantId": MANDANT_ID,
                        "ClientSystemId": CLIENT_SYSTEM_ID,
                        "WorkplaceId": WORKPLACE_ID,
                    }
                }
            )

            response = self.session.post(
                f'{KONNEKTOR_URL}/webservices/eventservice',
                data=soap_request,
                timeout=HTTPS_TIMEOUT,
            )

            # Evaluate the response using zeep
            parsed_response = SoapClient.parse_xml_response(response, SoapClient.Services.EventService.EventServicePort.GetCards)

            if parsed_response.get('Cards') is None:
                raise CardException(
                    message="No card available. Is the connection to the Konnektor and the terminal established?",
                    error_code=ErrorCodes.CARD_NOT_FOUND,
                )
            
            # Extract the SMC-B card handle
            if parsed_response.get('Cards') is not None:
                for card in parsed_response.get('Cards', {}).get('Card', []):
                    if card['CardType'] == "SMC-B":
                        card_handle = card['CardHandle']
                        logger.debug("CardHandle: %s", card_handle)
                        if card_handle is not None:
                            return card_handle

            raise CardException(
                message="No SMC-B card found. Is the card inserted and the connection to the terminal established?",
                error_code=ErrorCodes.CARD_NOT_FOUND,
            )
        
        except requests.exceptions.RequestException as e:
            raise KonnektorException(
                message=f"Failed to communicate with Konnektor: {e}",
                error_code=ErrorCodes.KONNEKTOR_REQUEST_FAILED
                )
        except Exception as e:
            raise KonnektorException(
                message=f"Error during card retrieval: {str(e)}",
                error_code=ErrorCodes.UNEXPECTED_ERROR,
                )


    def read_card_certificate(self, card_handle: str) -> str:
        """
        Read the C.AUT certificate from a card using its handle.

        Args:
            card_handle (str): Handle of the card to read from

        Returns:
            str: Base64-encoded card certificate

        Raises:
            ValueError: If no certificate is found
            requests.exceptions.RequestException: If the certificate service request fails
        """
        try:
            logger.info("Reading card certificate for card handle: %s", card_handle)
            soap_request = SoapClient.generate_xml(
                SoapClient.Services.CertificateService.CertificateServicePort.ReadCardCertificate,
                params={
                    "CardHandle": card_handle,
                    "Context": {
                        "MandantId": MANDANT_ID,
                        "ClientSystemId": CLIENT_SYSTEM_ID,
                        "WorkplaceId": WORKPLACE_ID,
                    },
                    "CertRefList": ["C.AUT"],
                    "Crypt": "ECC"
                }
            )

            response = self.session.post(
                f'{KONNEKTOR_URL}/webservices/certificateservice',
                data=soap_request,
                timeout=HTTPS_TIMEOUT
            )

            # Evaluate the response using zeep
            parsed_response = SoapClient.parse_xml_response(
                response,
                SoapClient.Services.CertificateService.CertificateServicePort.ReadCardCertificate
            )

            # Extract the certificate
            certificate_bytes = parsed_response.get('X509DataInfoList', {}).get('X509DataInfo', [{}])[0].get('X509Data', {}).get('X509Certificate', None)
            if not certificate_bytes:
                raise KonnektorException(
                    message="No certificate found",
                    error_code=ErrorCodes.CARD_CERTIFICATE_ERROR
                    )

            # Encode the certificate in Base64
            certificate_base64 = base64.b64encode(certificate_bytes).decode('utf-8')
            return certificate_base64
        
        except requests.exceptions.RequestException as e:
            raise KonnektorException(
                message=f"Failed to read card certificate: {str(e)}",
                error_code=ErrorCodes.CARD_CERTIFICATE_ERROR
                )
        except Exception as e:
            raise KonnektorException(
                message=f"Error processing certificate: {str(e)}",
                error_code=ErrorCodes.CARD_CERTIFICATE_ERROR
            )

    def is_card_pin_verified(self, card_handle: str) -> bool:
        """
        Check if the PIN of the card is verified.

        Args:
            card_handle (str): Handle of the card to check.

        Returns:
            bool: True if the PIN is verified, False otherwise.

        Raises:
            CardException: If the card is not detected or if an error occurs during the request.
        """
        try:
            logger.info("Getting PIN status for card handle: %s", card_handle)
            soap_request = SoapClient.generate_xml(
                SoapClient.Services.CardService.CardServicePort.GetPinStatus,
                params={
                    "CardHandle": card_handle,
                    "Context": {
                        "MandantId": MANDANT_ID,
                        "ClientSystemId": CLIENT_SYSTEM_ID,
                        "WorkplaceId": WORKPLACE_ID,
                    },
                    "PinTyp": "PIN.SMC", 
                }
            )
            
            response = self.session.post(
                f'{KONNEKTOR_URL}/webservices/cardservice',
                data=soap_request,
                timeout=HTTPS_TIMEOUT
            )

            parsed_response = SoapClient.parse_xml_response(
                response,
                SoapClient.Services.CardService.CardServicePort.GetPinStatus,
            )

            if parsed_response['Status']['Result'] != 'OK' or parsed_response['Status']['Error'] != None: 
                if parsed_response['Status']['Error'] == "Karte nicht als gesteckt identifiziert":
                    raise CardException(
                        message=f"{parsed_response['Status']['Error']}", 
                        error_code=ErrorCodes.CARD_NOT_FOUND)
                raise CardException(
                    message=f"{parsed_response['Status']['Error']}",
                    error_code=ErrorCodes.CARD_OPERATION_ERROR)
            
            # Parse the XML response to check the PIN status
            pin_status = parsed_response.get('PinStatus')

            if pin_status == 'VERIFIABLE':
                logger.info(f"PIN not verified for card handle: {card_handle}")
                return False
            elif pin_status == 'VERIFIED':
                logger.info(f"PIN verified for card handle: {card_handle}")
                return True
            else:
                raise CardException(
                    message=f"Unexpected PIN status '{pin_status}'",
                    error_code=ErrorCodes.UNEXPECTED_ERROR
                    )
        except requests.exceptions.RequestException as e:
            raise CardException(
                message=f"Failed to call GetPinStatus: {str(e)}", 
                error_code=ErrorCodes.KONNEKTOR_REQUEST_FAILED
                )
        except CardException as e:
            raise CardException(
                message=f"Error during GetPinStatus: {str(e)}", 
                error_code=e.error_code
                )
        except Exception as e:
            raise CardException(
                message=f"Unexpected Error during GetPinStatus: {str(e)}",
                error_code=ErrorCodes.UNEXPECTED_ERROR
                )


    def create_signed_attest_jwt(self, nonce:str, card_handle:str, card_certificate:str)->str:
        """
        Create a signed JWT attestation using the card's certificate.
        
        Args:
            nonce (str): Nonce value to include in the JWT
            card_handle (str): Handle of the card for signing
            card_certificate (str): Certificate to include in the JWT header
            
        Returns:
            str: Complete signed JWT string in format header.payload.signature
        """
        # https://github.com/gematik/app-asforepa
        logger.info("Creating signed attest JWT")
        # Encode the JWT header and payload
        jwt_header = {
            "typ": "JWT",
            "alg": "ES256",
            "x5c": [card_certificate]
        }
        
        iat = int((datetime.datetime.now()).timestamp())
        exp = iat + 1200  

        jwt_body = {
            "nonce": nonce,
            "iat": iat,
            "exp": exp
        }

        # Create the client attest string
        client_attest = f"{base64.urlsafe_b64encode(json.dumps(jwt_header).encode()).decode().replace("=",'')}.{base64.urlsafe_b64encode(json.dumps(jwt_body).encode()).decode().replace("=",'')}"

        logger.debug("Client attest: %s", client_attest)

        # Hash the client attest string with SHA256
        binary_string = hashlib.sha256(client_attest.encode('utf-8')).digest()
        binary_hex = binary_string.hex()
        binary_string_base64 = base64.b64encode(bytes.fromhex(binary_hex)).decode('utf-8')

        logger.debug("Binary string (base64): %s", binary_string_base64)

        # Sign the hash using ExternalAuthenticate
        signature = self.external_authenticate(card_handle, binary_string_base64, signature_type="urn:bsi:tr:03111:ecdsa")

        # Make the signature URL-safe
        urlsafe_signature = signature.replace('+', '-').replace('/', '_').replace("=",'')
        logger.debug("Signature: %s", signature)

        final_jwt = f"{client_attest}.{urlsafe_signature}"

        logger.debug("Final JWT: %s", final_jwt)

        return final_jwt


    def get_challenge_token_signature(self, header_payload_challenge_string:str, card_handle:str)->str:
        """
        Sign a challenge token using the SMC-B card's ID.HCI.AUT identity.
        
        Uses the Konnektor's ExternalAuthenticate operation according to 
        [gemSpec_Kon#4.1.13.4] and [gemILF_PS#4.4.6.1] specifications.
        
        Args:
            header_payload_challenge_string (str): Challenge token to sign
            card_handle (str): Handle of the SMC-B card
            
        Returns:
            str: Base64-encoded ECDSA signature
        """
        logger.info("Signing challenge token")

        logger.debug("Header payload challenge string: %s", header_payload_challenge_string)
        binary_string = hashlib.sha256(header_payload_challenge_string.encode('utf-8')).digest()
        logger.debug("Binary string: %s", binary_string)
        binary_hex = binary_string.hex()
        logger.debug("Binary string (hex): %s", binary_hex)
        binary_string_base64 = base64.b64encode(bytes.fromhex(binary_hex)).decode('utf-8')
        logger.debug("Binary string (base64): %s", binary_string_base64)
        challenge_signature = self.external_authenticate(card_handle, binary_string_base64, signature_type="urn:bsi:tr:03111:ecdsa")

        logger.debug("Signature: %s", challenge_signature)

        return challenge_signature


    def external_authenticate(self, card_handle:str, challenge:str, signature_type:str="urn:ietf:rfc:3447")->str:
        """
        Perform external authentication using the card's signing capabilities.
        
        Args:
            card_handle (str): Handle of the card to use
            challenge (str): Base64-encoded challenge string to sign
            signature_type (str, optional): Signature algorithm URI. Defaults to "urn:ietf:rfc:3447"
            
        Returns:
            str: Base64-encoded signature
            
        Raises:
            RuntimeError: If authentication fails
            ValueError: If no signature is produced
        """
        try:
            logger.info("Performing ExternalAuthenticate for card handle: %s", card_handle)

            soap_request = SoapClient.generate_xml(
                SoapClient.Services.AuthSignatureService.AuthSignatureServicePort.ExternalAuthenticate,
                params={
                    "CardHandle": card_handle,
                    "Context": {
                        "MandantId": MANDANT_ID,
                        "ClientSystemId": CLIENT_SYSTEM_ID,
                        "WorkplaceId": WORKPLACE_ID,
                    },
                    "OptionalInputs": {
                        "SignatureType": signature_type,
                        "SignatureSchemes": "RSASSA-PSS" if signature_type == "urn:ietf:rfc:3447" else None
                    },
                    "BinaryString": {
                        "Base64Data": {
                            "_value_1": challenge,
                            "MimeType": "application/octet-stream"
                        }
                    }
                }
            )

            response = self.session.post(
                f'{KONNEKTOR_URL}/webservices/authsignatureservice',
                data=soap_request,
                headers={
                    'SOAPAction': '"http://ws.gematik.de/conn/SignatureService/v7.4#ExternalAuthenticate"'
                },
                timeout=HTTPS_TIMEOUT,
                allow_redirects=False,
            )

            logger.debug("ExternalAuthenticate Response: %s", response.text)
            parsed_response = SoapClient.parse_xml_response(response, SoapClient.Services.AuthSignatureService.AuthSignatureServicePort.ExternalAuthenticate)

            if parsed_response['Status']['Result'] != 'OK' or parsed_response['Status']['Error'] != None:
                if parsed_response['Status']['Error'] == "Karte nicht als gesteckt identifiziert":
                    raise CardException(
                        message=f"{parsed_response['Status']['Error']}", 
                        error_code=ErrorCodes.CARD_NOT_FOUND
                        )
                else:
                    logger.error("Error during ExternalAuthenticate: %s", parsed_response['Status'])
                    raise KonnektorException(
                        message=f"Error during ExternalAuthenticate: {parsed_response['Status']}",
                        error_code=ErrorCodes.KONNEKTOR_REQUEST_FAILED
                        )
            
            type_is_ecdas = parsed_response.get('SignatureObject', {}).get('Base64Signature', {}).get('Type') == 'urn:bsi:tr:03111:ecdsa'
            base64_signature = parsed_response.get('SignatureObject', {}).get('Base64Signature', {}).get('_value_1')
            
            if base64_signature is None:
                raise KonnektorException(
                    message="No Base64Signature found",
                    error_code=ErrorCodes.SIGNATURE_MISSING)
            
            if type_is_ecdas and base64_signature:
                try:        
                    logger.debug("Before convert signature to X962: %s", base64.urlsafe_b64encode(base64_signature))
                    base64_signature = convert_der_ecdsa_to_concated_x962(base64_signature)
                    logger.debug("Converted signature to X962: %s", base64_signature)
                except Exception as e:
                    raise KonnektorException(
                        message=f"Error processing signature:  {e}",
                        error_code=ErrorCodes.SIGNATURE_PROCESSING_ERROR
                        )
            
            logger.debug("Base64Signature: %s", base64_signature)
            return base64_signature
        
        except requests.exceptions.RequestException as e:
            raise KonnektorException(
                message=f"Failed to authenticate with Konnektor: {str(e)}",
                error_code=ErrorCodes.KONNEKTOR_REQUEST_FAILED
                )
        except CardException as e:
            raise e
        except Exception as e:
            raise KonnektorException(
                message=f"Authentication error: {str(e)}",
                error_code=ErrorCodes.UNEXPECTED_ERROR,
                )

