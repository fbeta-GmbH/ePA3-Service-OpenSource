
from typing import Optional, Tuple
import requests
import base64
import hashlib
import datetime
import json
import sqlite3
import os

from requests import Session
from requests.adapters import HTTPAdapter

from app.logging_config import logger

from app.utils.utils import convert_der_ecdsa_to_concated_x962
from app.constants import MANDANT_ID, CLIENT_SYSTEM_ID, USER_AGENT, WORKPLACE_ID, USER_ID, DIGA_NAME, DIGA_MANUFACTURER, KONNEKTOR_URL

from app.exceptions import KonnektorException, CardException

from app.xml_service.soap_client import SoapClient



class Konnektor:
    def __init__(self, path_to_cert:str, path_to_key:str)->None:
        """
        Initialize a new instance of the Konnektor class.
        
        Args:
            path_to_cert (str): Path to the certificate file
            path_to_key (str): Path to the private key file
        """
        logger.info("Initializing Konnektor with cert: %s and key: %s", path_to_cert, path_to_key)
        self.cert = path_to_cert
        self.key = path_to_key

        self.session = Session()
        self.session.mount("https://", HTTPAdapter(max_retries=2))
        self.session.mount("http://", HTTPAdapter(max_retries=2))
        self.session.headers.update({
            'Content-Type': 'application/xml',
        })
        self.session.verify = False
        self.session.cert = (self.cert, self.key)

        self.db = self.init_db()


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
                timeout=15,
            )

            # Provide more detailed log ouput
            logger.debug(response.text)

            # Evaluate the response using zeep
            parsed_response = SoapClient.parse_xml_response(response, SoapClient.Services.EventService.EventServicePort.GetCards)

            if parsed_response.get('Cards') is None:
                raise CardException("No card available. Is the connection to the Konnektor and the terminal established?")
            
            # Extract the SMC-B card handle
            if parsed_response.get('Cards') is not None:
                for card in parsed_response.get('Cards', {}).get('Card', []):
                    if card['CardType'] == "SMC-B":
                        card_handle = card['CardHandle']
                        logger.debug("CardHandle: %s", card_handle)
                        if card_handle is not None:
                            return card_handle

            raise CardException("No SMC-B card found. Is the card inserted and the connection to the terminal established?")
        
        except requests.exceptions.RequestException as e:
            raise KonnektorException(f"Failed to communicate with Konnektor: {e}")
        except Exception as e:
            raise KonnektorException(f"Error during card retrieval: {str(e)}")


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
                timeout=15
            )

            # Evaluate the response using zeep
            parsed_response = SoapClient.parse_xml_response(
                response,
                SoapClient.Services.CertificateService.CertificateServicePort.ReadCardCertificate
            )

            # Extract the certificate
            certificate_bytes = parsed_response.get('X509DataInfoList', {}).get('X509DataInfo', [{}])[0].get('X509Data', {}).get('X509Certificate', None)
            if not certificate_bytes:
                raise KonnektorException("No certificate found")

            # Encode the certificate in Base64
            certificate_base64 = base64.b64encode(certificate_bytes).decode('utf-8')
            return certificate_base64
        
        except requests.exceptions.RequestException as e:
            raise KonnektorException(f"Failed to read card certificate: {str(e)}")
        except Exception as e:
            raise KonnektorException(f"Error processing certificate: {str(e)}")

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
                timeout=15
            )

            # Provide more detailed log ouput
            logger.debug(response.text)

            parsed_response = SoapClient.parse_xml_response(
                response,
                SoapClient.Services.CardService.CardServicePort.GetPinStatus,
            )

            if parsed_response['Status']['Result'] != 'OK' or parsed_response['Status']['Error'] != None: 
                if parsed_response['Status']['Error'] == "Karte nicht als gesteckt identifiziert":
                    raise CardException(f"{parsed_response['Status']['Error']}", error_code='CARD_NOT_FOUND')
                raise CardException(f"{parsed_response['Status']['Error']}")
            
            # Parse the XML response to check the PIN status
            pin_status = parsed_response.get('PinStatus')

            if pin_status == 'VERIFIABLE':
                logger.info(f"PIN not verified for card handle: {card_handle}")
                return False
            elif pin_status == 'VERIFIED':
                logger.info(f"PIN verified for card handle: {card_handle}")
                return True
            else:
                raise CardException(f"Unexpected PIN status '{pin_status}'")
        except requests.exceptions.RequestException as e:
            raise CardException(f"Failed to call GetPinStatus: {str(e)}", error_code='REQUEST_FAILED')
        except CardException as e:
            raise CardException(f"Error during GetPinStatus: {str(e)}", error_code=e.error_code)
        except Exception as e:
            raise CardException(f"Unexpected Error during GetPinStatus: {str(e)}")


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
                timeout=15
            )

            logger.debug("ExternalAuthenticate Response: %s", response.text)
            parsed_response = SoapClient.parse_xml_response(response, SoapClient.Services.AuthSignatureService.AuthSignatureServicePort.ExternalAuthenticate)

            if parsed_response['Status']['Result'] != 'OK' or parsed_response['Status']['Error'] != None:
                if parsed_response['Status']['Error'] == "Karte nicht als gesteckt identifiziert":
                    raise CardException(f"{parsed_response['Status']['Error']}", error_code='CARD_NOT_FOUND')
                else:
                    logger.error("Error during ExternalAuthenticate: %s", parsed_response['Status'])
                    raise KonnektorException(f"Error during ExternalAuthenticate: {parsed_response['Status']}")
            
            type_is_ecdas = parsed_response.get('SignatureObject', {}).get('Base64Signature', {}).get('Type') == 'urn:bsi:tr:03111:ecdsa'
            base64_signature = parsed_response.get('SignatureObject', {}).get('Base64Signature', {}).get('_value_1')
            
            if base64_signature is None:
                raise ValueError("No Base64Signature found")
            
            if type_is_ecdas and base64_signature:
                try:        
                    logger.debug("Before convert signature to X962: %s", base64.urlsafe_b64encode(base64_signature))
                    base64_signature = convert_der_ecdsa_to_concated_x962(base64_signature)
                    logger.debug("Converted signature to X962: %s", base64_signature)
                except Exception as e:
                    raise ValueError("Error processing signature:  %s" % e)
            
            logger.debug("Base64Signature: %s", base64_signature)
            return base64_signature
        
        except requests.exceptions.RequestException as e:
            raise KonnektorException(f"Failed to authenticate with Konnektor: {str(e)}")
        except CardException as e:
            raise e
        except Exception as e:
            raise KonnektorException(f"Authentication error: {str(e)}")


    def get_record_status(self, insurantId: str, endpoint: str) -> Tuple[bool, int, Tuple[int, str]]:
        """
        Perform the getRecordStatus operation for the given KVNR at the specified endpoint.
        See: https://github.com/gematik/ePA-Basic/blob/ePA-3.0.5/src/openapi/I_Information_Service.yaml

        Args:
            insurantId (str): The insured person's KVNR.
            endpoint (str): The service endpoint to query.

        Returns:
            bool: True if the health record exists and is in state ACTIVATED, False otherwise.
            int: Retry interval in minutes.
            Tuple[int, str]: Tuple containing the HTTP status code and message.
        Raises:
            KonnektorException: If an unexpected response is received.
            requests.exceptions.RequestException: If the request fails.
        """
        try:
            response = self.session.get(
                f"{endpoint}/information/api/v1/ehr",
                headers={
                    "x-insurantid": insurantId,
                    "x-useragent": USER_AGENT,
                    "content-type": "application/json",
                    "accept": "*/*"
                },
                timeout=30
            )
            logger.info(f"getRecordStatus response: {response.status_code}, {response.text}")

            if response.status_code == 204:
                logger.info(f"Ok: Health record exists and is in state ACTIVATED")
                return True, 24 * 60, (204, "OK")
            if response.status_code == 404 and response.json().get("errorCode") == "noHealthRecord":
                logger.info(f"Not found: Health record does not exist (UNKNOWN) or is in state INITIALIZED")
                return False, 24 * 60, (404, "NOT_FOUND")
            if response.status_code == 400 and response.json().get("errorCode") == "malformedRequest":
                # Request does not match schema
                logger.error(f"Bad Request: Malformed request: {response.status_code}, {response.text}")
                return False, 24 * 60, (400, "BAD_REQUEST")
            if response.status_code == 409 and response.json().get("errorCode") == "statusMismatch":
                # Retry Interval: approx. 24 hours
                # raise KonnektorException("Conflict", error_code="STATUS_MISMATCH")
                logger.warning(f"Conflict: Health record is not in state ACTIVATED (i.e. is in state SUSPENDED): {response.status_code}, {response.text}")
                return False, 24 * 60, (409, "CONFLICT")
            if response.status_code == 500 and response.json().get("errorCode") == "internalError":
                # Any other error
                # Retry Interval: approx. 10 minutes
                logger.warning(f"Internal Server Error: {response.status_code}, {response.text}")
                return False, 10, (500, "INTERNAL_SERVER_ERROR")

            raise KonnektorException(f"Unexpected response: {response.status_code}, {response.text}")
        except requests.exceptions.RequestException as e:
            raise KonnektorException(f"Error querying getRecordStatus:{e}")
        except KonnektorException as e:
            raise e
        except Exception as e:
            raise KonnektorException(f"Unexpected error during getRecordStatus: {str(e)}")

