"""
Initializes the VAUKanal instance and performs the initial key exchange with the AS_URL.

Parameters:
AS_URL (str): The URL of the authentication server, must start with 'http://' or 'https://' and end with '/'.
"""

import cbor2
import hashlib
import requests
import secrets
import json
from urllib import parse
from icecream import ic
from jwcrypto import jwe
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from urllib.parse import urljoin

from app.logging_config import logger

from app.vau import kemvau
from app.constants import USER_AGENT

from app.exceptions import VAUException, AuthenticationException

from app.xml_service.soap_client import SoapClient


class VAUKanal:

    def __init__(self, AS_URL: str):
        """
            Initializes the VAUProtokoll instance and establishes a VAU channel with the specified AS_URL.
            
            Args:
                            AS_URL (str): The URL of the authorization server (AS). Must start with "http://" or "https://".
            
            Raises:
                            AssertionError: If AS_URL is not specified or does not start with "http://" or "https://".
            
            The initialization process includes the following steps:
            1. Generates ECDH and Kyber key pairs and sends them in VauMessage 1 to the server.
            2. Receives the server's response (VauMessage 2) containing the server's public keys and shared secrets,
            as well as the VAU-CID which is needed for further communication.
            3. Derives shared secrets and keys (KdfKey1 and KdfKey2) from the received data.
            4. Sends VauMessage 3 to the server containing the shared secrets and key confirmation from the client.
            5. Receives the final response from the server (VauMessage 4) to complete the handshake and establish the VAU channel.
            
            Note:
                            The VAU channel is established over HTTPS, but communication within the VAU channel occurs over HTTP.
        """
        self.AS_URL = AS_URL
        logger.info("=== Initializing VAUKanal with AS_URL: %s ===", self.AS_URL)
        try:

            self.encryption_counter = 0
            self.request_counter = 0

            assert self.AS_URL
            assert self.AS_URL.startswith("http://") or self.AS_URL.startswith("https://")

            AS_URL_START_VAU = self.AS_URL + "/VAU"

            self.host = parse.urlparse(self.AS_URL).netloc

            self.https_session = requests.Session()

            # VauMessage 1:
            # Der Client erzeugt die ECDH und Kyber KeyPairs und packt sie in Message 1:
            client_schluessel_1 = kemvau.gen_keypairs()

            nachricht_1 = {
                "MessageType"   : "M1",
                "ECDH_PK"       : client_schluessel_1["ECDH"]["pub_key"],
                "Kyber768_PK"   : client_schluessel_1["Kyber768"]["pub_key"],
            }

            nachricht_1_encoded = cbor2.dumps(nachricht_1)
            transscript_client = nachricht_1_encoded

            try:
                http_response = self.https_session.post(
                    AS_URL_START_VAU,
                    headers={
                        "Content-Type": "application/cbor",
                        "x-useragent": USER_AGENT,
                    },
                    data=nachricht_1_encoded,
                    timeout=60,
                    # Um ein VAU-Kanal zu https://epa-as-2.dev.epa4all.de/ aufzubauen muss verify auf False gesetzt werden, da es sich um ein self-signed Zertifikat handelt
                    verify=False,
                )
            except Exception as e:
                raise VAUException(
                    message=f"VAU-Kanal Failed at VAU-Message 1 : {e}",
                    error_code="VAU_AUTH_FAILED",
                )

            logger.debug("VauMessage 1 sent, response: %s", http_response.content)
            logger.debug("HTTP Status Code: %s", http_response.status_code)

            """VauMessage 2:
                        Der Server nimmt die VauMessage 1 entgegen. Die PublicKeys des Clients und seinen eigenen PrivateKeys nutzt er, 
                        um die ECDH und Kyber Shared Secrets mitsamt Ciphertexts (KdfMessage) zu erstellen. Daraus erstellt er den ersten 
                        Schlüssel KdfKey1. Diesen nutzt er, um seine signierten PublicKeys zu verschlüsseln. In VauMessage 2 werden die Ciphertexts 
                        der Shared Secrets sowie die verschlüsselten signierten PublicKeys gespeichert und diese Nachricht wird zurück zum Client geschickt."""

            assert http_response.status_code == requests.codes.ok
            assert http_response.headers["Content-Type"] == "application/cbor"
            assert "VAU-CID" in http_response.headers

            self.vau_cid = http_response.headers["VAU-CID"]

            self.as_url_plus_vau_cid = self.AS_URL + self.vau_cid

            nachricht_2_encoded = http_response.content
            # xxx, len>0 ?
            transscript_client += nachricht_2_encoded

            nachricht_2 = cbor2.loads(nachricht_2_encoded)

            """Client: nachricht-3 VAUClientKEM+KeyConfirmation

                        VauMessage 3:
                        Der Client erhält VauMessage 2. Mithilfe der Ciphertexts des Servers und den eigenen PrivateKey 
                        erstellt er seine eigenen Shared Secrets, mit welchen er den gleichen KdfKey1 wie der Server herleitet. 
                        Damit entschlüsselt er die signierten PublicKeys des Servers. Mit diesen PublicKeys und den eigenen PrivateKeys 
                        erstellt der Client weitere Shared Secrets mit zugehörigen Ciphertexts. Mit den Shared Secrets aus beiden 
                        Vorgängen wird nun ein KdfKey2 generiert, welcher für das Ver-/Entschlüsseln zwischen Client und Server nach dem 
                        Handshake genutzt wird. Die Ciphertexts für den KdfKey2 werden mit dem KdfKey1 verschlüsselt. Ein Transcript, 
                        was aus den bisherigen codierten Nachrichten besteht, wird in SHA-256 (=Hash) und dann mit dem KdfKey2 
                        verschlüsselt (=Ciphertext-KeyConfirmation). Die VauMessage 3 besteht aus den Ciphertexts und der Ciphertext-KeyConfirmation. 
                        Diese wird zum Server zurückgeschickt."""

            client_kem_result_1 = kemvau.decapsulation(nachricht_2, client_schluessel_1)
            ic("Schlüsselableitung für die K1-Schlüssel")
            (c_k1_c2s, c_k1_s2c) = kemvau.kem_kdf(client_kem_result_1)
            transfered_signed_vau_server_pub_keys = kemvau.aead_dec(
                c_k1_s2c, nachricht_2["AEAD_ct"]
            )
            # Im Produktivcode try-Umgebung, weil daten noch nicht authentisiert
            signed_vau_server_pub_keys = cbor2.loads(transfered_signed_vau_server_pub_keys)

            logger.info(signed_vau_server_pub_keys)

            self.vau_cert_validation(signed_vau_server_pub_keys)

            pub_keys = cbor2.loads(signed_vau_server_pub_keys["signed_pub_keys"])

            client_kem_result_2 = kemvau.encapsulation(pub_keys)

            nachricht_3_inner_layer = {
                "ECDH_ct": client_kem_result_2["ECDH_ct"],
                "Kyber768_ct": client_kem_result_2["Kyber768_ct"],
                "ERP": False,
                "ESO": False,
            }
            nachricht_3_inner_layer_encoded = cbor2.dumps(nachricht_3_inner_layer)
            aead_ciphertext_msg_3 = kemvau.aead_enc(c_k1_c2s, nachricht_3_inner_layer_encoded)
            transscript_client_to_send = transscript_client + aead_ciphertext_msg_3

            ic("Schlüsselableitung für die K2-Schlüssel")
            (
                c_k2_c2s_key_confirmation,
                self.c_k2_c2s_app_data,
                c_k2_s2c_key_confirmation,
                self.c_k2_s2c_app_data,
                self.c_key_id,
            ) = kemvau.kem_kdf(client_kem_result_1, client_kem_result_2)
            transscript_client_hash = hashlib.sha256(transscript_client_to_send).digest()
            aead_ciphertext_msg_3_key_confirmation = kemvau.aead_enc(
                c_k2_c2s_key_confirmation, transscript_client_hash
            )

            nachricht_3 = {
                "MessageType"   : "M3",
                "AEAD_ct"       : aead_ciphertext_msg_3,
                "AEAD_ct_key_confirmation": aead_ciphertext_msg_3_key_confirmation,
            }

            nachricht_3_encoded = cbor2.dumps(nachricht_3)
            transscript_client += nachricht_3_encoded

            try:
                http_response = self.https_session.post(
                    self.as_url_plus_vau_cid,
                    headers={
                        "Content-Type": "application/cbor",
                        "x-useragent": USER_AGENT,
                    },
                    data=nachricht_3_encoded,
                    timeout=34,
                    # Um ein VAU-Kanal zu https://epa-as-2.dev.epa4all.de/ aufzubauen muss verify auf False gesetzt werden, da es sich um ein self-signed Zertifikat handelt
                    verify=False,
                )
            except Exception as e:
                raise VAUException(
                    message=f"VAU-Kanal Failed at VAU-Message 3 : {e}",
                    error_code="VAU_AUTH_FAILED",
                )

            logger.debug("VauMessage 3 sent, response: %s", http_response.content)

            """VauMessage 4:
                        Der Server öffnet VauMessage 4 und erhält mit seinem KdfKey1 die Ciphertexts. 
                        Mit diesen kann er nun seinen eigenen Shared Secrets erstellen. Mit allen Shared Secrets 
                        leitet er, wie der Client zuvor, den KdfKey2 her. Um den Vorgang zu validieren, überprüft 
                        der Server die Hash des Clients: Er entschlüsselt die Ciphertext-KeyConfirmation mit dem KdfKey2 
                        und erhält den Client-Hash. Diese vergleicht er mit dem SHA-256 verschlüsselten eigenen Transcript. 
                        Den eigenen Hash verschlüsselt er mit dem KdfKey2 (=Ciphertext-KeyConfirmation). 
                        Diese wird in VauMessage 4 gespeichert und zurück zum Client geschickt.
                        """
            ic(http_response.status_code)
            # ic(http_response.content)
            logger.info("Status code: %s", http_response.status_code)
            assert http_response.status_code == requests.codes.ok
            assert http_response.headers["Content-Type"] == "application/cbor"

            nachricht_4_encoded = http_response.content

            logger.info("----------------------VAU-KANAL ERFOLGREICH AUFGEBAUT----------------------")
        except Exception as e:
            logger.error("Unexpected error during building of VAU-Kanal: %s", str(e))
            raise VAUException(
                message=f"Building VAU-Kanal Failed: {str(e)}",
                error_code="VAU_AUTH_FAILED",
            )

    def vau_cert_validation(self, signed_vau_server_pub_keys: dict) -> bool:
        """
        Validates the VAU server's signed public keys by verifying the signature using the server certificate.
        It retrieves certificate data from the server, loads and validates the certificate chain,
        and uses the public key to verify the signature on the signed public keys.

        Args:
                signed_vau_server_pub_keys (dict): Dictionary containing cert_hash, cdv, signature and signed public keys

        Returns:
                bool: True if validation succeeds, False otherwise

        Raises:
                Various exceptions during certificate validation or signature verification
        """

        logger.info(signed_vau_server_pub_keys["cert_hash"])

        cert_hash = signed_vau_server_pub_keys["cert_hash"]

        logger.info(f"Cert hash 64: {cert_hash}")

        cert_hash_hex = cert_hash.hex()

        logger.info(f"Cert hash hex: {cert_hash_hex}")

        cdv = signed_vau_server_pub_keys["cdv"]

        # Request CertData from server

        cert_endpoint = urljoin(self.AS_URL, f"/CertData.{cert_hash_hex}-{cdv}")

        cert_data_response = self.https_session.get(
            cert_endpoint,
            verify=False,
            headers={"x-useragent": USER_AGENT},
        )

        if cert_data_response.status_code != 200:
            logger.error(f"Failed to retrieve CertData: {cert_data_response.text}")
            return False

        try:
            # Parse CBOR response
            cert_data = cbor2.loads(cert_data_response.content)

            # Validate structure
            required_fields = ["cert", "ca", "rca_chain"]
            if not all(field in cert_data for field in required_fields):
                logger.error("Missing required fields in CertData")
                return False

            try:
                # Load the end-entity certificate
                cert = x509.load_der_x509_certificate(
                    cert_data["cert"], default_backend()
                )

                # Get the public key from the certificate
                public_key = cert.public_key()

                if not isinstance(public_key, ec.EllipticCurvePublicKey):
                    logger.error("Certificate public key is not an EC key")
                    return False

                r = int.from_bytes(
                    signed_vau_server_pub_keys["signature-ES256"][:32], byteorder="big"
                )
                s = int.from_bytes(
                    signed_vau_server_pub_keys["signature-ES256"][32:], byteorder="big"
                )
                # Encode to DER format
                signature_der = encode_dss_signature(r, s)

                # Verify the signature
                public_key.verify(
                    signature_der,
                    signed_vau_server_pub_keys["signed_pub_keys"],
                    ec.ECDSA(hashes.SHA256()),
                )

                logger.info("✓ Signature verification successful")
                return True

            except InvalidSignature:

                logger.error("✗ Invalid signature on signed public keys")
                raise VAUException(
                    message="Invalid signature on signed public keys",
                    error_code="VAU_CERT_VALIDATION_FAILED",
                )
            except Exception as e:
                logger.error(f"✗ Error during signature verification: {str(e)}")
                raise VAUException(
                    message=f"Error during signature verification: {str(e)}",
                    error_code="VAU_CERT_VALIDATION_FAILED",
                )

        except Exception as e:
            logger.error(f"✗ Certificate validation failed: {str(e)}")
            raise VAUException(
                message=f"Certificate validation failed: {str(e)}",
                error_code="VAU_CERT_VALIDATION_FAILED",
            )

    def parse_inner_http_response(self, response: bytes) -> dict:
        logger.debug("Parsing inner HTTP response")
        """
                Parses an HTTP response in bytes and formats it into its components.
                
                Args:
                        response (bytes): The HTTP response in bytes.
                
                Returns:
                        dict: A dictionary containing 'http_status', 'headers', and 'body'.
                """
        # 1. Bytes zu String dekodieren
        decoded_response = response.decode("utf-8")

        # 2. Header und Body trennen
        header_part, body_part = decoded_response.split("\r\n\r\n", 1)

        # 3. Header aufschlüsseln
        headers = header_part.split("\r\n")
        http_status = headers[0]  # Erster Header enthält HTTP-Status
        header_dict = {}

        for header in headers[1:]:
            key, value = header.split(": ", 1)
            header_dict[key] = value

        # 4. JSON-Body parsen
        try:
            body_json = json.loads(body_part)
        except json.JSONDecodeError:
            body_json = body_part  # Fallback: Raw body, falls kein JSON vorliegt
        except Exception as e:
            raise VAUException(
                message=f"Error parsing HTTP response body: {str(e)}",
                error_code="VAU_PARSE_ERROR",
            )

        result = {"http_status": http_status, "headers": header_dict, "body": body_json}
        logger.debug("Parsed response: %s", json.dumps(result, indent=4))
        return result

    def send_vau_message(self, inner_request: bytes, vau_np=None) -> bytes:
        logger.info("Sending VAU message")
        """
                Sends an inner HTTP request through the VAU channel and processes the response.

                Args:
                        inner_request (bytes): The inner HTTP request to be sent as a byte array.
                        vau_np (str, optional): The VAU-NP header value if available. Defaults to None.
                
                Raises:
                        ValueError: If the response is too short, contains invalid header fields, or decryption fails.
                
                Returns:
                        bytes: The decrypted response as a byte array.
                """
        try:
            self.encryption_counter += 1
            random_4_bytes = secrets.token_bytes(4)
            iv = random_4_bytes + self.encryption_counter.to_bytes(8, "big")

            header = bytearray()
            header.append(0x02)  # Version
            header.append(0x00)  # nonPU
            header.append(0x01)  # Request
            header.extend(self.request_counter.to_bytes(8, "big"))  # Request counter
            header.extend(self.c_key_id)  # KeyID from handshake

            # Encrypt with AES-GCM using header as AAD
            aead_ciphertext = kemvau.aead_enc_message(
                self.c_k2_c2s_app_data, inner_request, header, iv
            )

            # Construct complete message
            message = header + aead_ciphertext

            # Send request
            headers = {
                "Content-Type": "application/octet-stream",
                "x-useragent": USER_AGENT,
            }
            if vau_np is not None:
                headers["VAU-NP"] = vau_np

            http_response = self.https_session.post(
                self.as_url_plus_vau_cid,
                headers=headers,
                data=message,
                timeout=34,
                verify=False,
            )

            # Get response data
            response_data = http_response.content

            logger.info("HTTP Status Code: %s", http_response.status_code)
            logger.info(
                "HTTP Response Headers: %s",
                json.dumps(dict(http_response.headers), indent=4),
            )

            # Verify response length >= 72 bytes
            if len(response_data) < 72:
                raise ValueError("Response too short")

            # Parse response header
            resp_version = response_data[0]
            resp_pu = response_data[1]
            resp_type = response_data[2]
            resp_counter = int.from_bytes(response_data[3:11], "big")
            resp_keyid = response_data[11:43]

            # Verify header fields
            if resp_pu != 0x00:
                raise VAUException(
                    message="Invalid PU/nonPU byte in VAU response",
                    error_code="VAU_INVALID_RESPONSE",
                )
            if resp_type != 0x02:
                raise VAUException(
                    message="Invalid response type in VAU response",
                    error_code="VAU_INVALID_RESPONSE",
                )
            if resp_counter != self.request_counter:
                raise VAUException(
                    message="Invalid response counter in VAU response",
                    error_code="VAU_INVALID_RESPONSE",
                )
            if resp_keyid != self.c_key_id:
                raise VAUException(
                    message="Unknown KeyID in VAU response",
                    error_code="VAU_INVALID_RESPONSE",
                )

            resp_cipher = response_data[43:]
            resp_aad = response_data[:43]
            # Decrypt response
            decrypted_resp = kemvau.aead_dec_message(
                self.c_k2_s2c_app_data, resp_cipher, resp_aad
            )

            logger.debug("Response data: %s", response_data)
            logger.debug("Decrypted response: %s", decrypted_resp)

            return decrypted_resp

        except Exception as e:
            logger.error("Error sending VAU message: %s", str(e))
            raise VAUException(
                message=f"Error sending VAU message: {str(e)}",
                error_code="VAU_MESSAGE_ERROR",
            )

    def get_nonce(self, insurant_id: str) -> str:
        logger.info("=== Getting Nonce ===")
        """
                This function sends an HTTP request to obtain a nonce.
                The function creates an inner HTTP request to the endpoint '/epa/authz/v1/getNonce' 
                and sends this request via the 'send_vau_message' method. The response is decrypted 
                and parsed to extract the nonce from the response body.
                
                Returns:
                        str: The nonce extracted from the response.
                """
        try:
            inner_request = "GET /epa/authz/v1/getNonce HTTP/1.1\r\n"
            inner_request += f"Host: {self.host}\r\n"
            inner_request += "Accept: application/json\r\n"
            inner_request += "Content-Type: application/json\r\n"
            inner_request += f"x-useragent: {USER_AGENT}\r\n"
            inner_request += f"x-insurantid: {insurant_id}\r\n"
            inner_request += "\r\n"

            inner_request = inner_request.encode("utf-8")

            decrypted_resp = self.send_vau_message(inner_request)
            parsed_decrypted_resp = self.parse_inner_http_response(decrypted_resp)
            logger.debug("Nonce received: %s", parsed_decrypted_resp["body"]["nonce"])
            return parsed_decrypted_resp["body"]["nonce"]

        except Exception as e:
            logger.error("Error getting Nonce from ePA-Authz-Service: %s", str(e))
            raise AuthenticationException(
                message=f"Error getting Nonce from ePA-Authz-Service: {str(e)}",
                error_code="EPA_AUTHZ_ERROR",
            )

    def send_authorization_request_sc(self, insurant_id: str) -> tuple:
        """
        Sends an authorization request to the Smartcard (SC) and processes the response.
        This method constructs an HTTP GET request to the specified endpoint for sending an authorization request.
        It then sends this request using the VAU (Virtual Authentication Unit) message protocol, parses the response,
        and sends a follow-up GET request to the Identity Provider (IDP) to retrieve the authorization challenge.
        Returns:
                tuple: A tuple containing the challenge token and user consent information.
        Raises:
                Exception: If there is an error in sending the request or processing the response.
        """
        try:
            logger.info("=== Sending authorization request SC ===")
            inner_request = (
                "GET /epa/authz/v1/send_authorization_request_sc HTTP/1.1\r\n"
            )
            inner_request += f"Host: {self.host}\r\n"
            inner_request += "Accept: application/json\r\n"
            inner_request += "Content-Type: application/json\r\n"
            inner_request += f"x-useragent: {USER_AGENT}\r\n"
            inner_request += f"x-insurantid: {insurant_id}\r\n"
            inner_request += "\r\n"

            inner_request = inner_request.encode("utf-8")

            decrypted_resp = self.send_vau_message(inner_request)
            parsed_decrypted_resp = self.parse_inner_http_response(decrypted_resp)

            logger.info("RESPONSE SEND_AUTH_REQUEST_SC")
            logger.debug(json.dumps(parsed_decrypted_resp, indent=4))
            location_uri_parameters: dict = {
                k: v[0]
                for k, v in dict(parse.parse_qs(parse.urlsplit(parsed_decrypted_resp["headers"]["Location"]).query)).items()
            }
            logger.debug(
                "Location URI parameters: %s",
                json.dumps(location_uri_parameters, indent=4),
            )

            logger.info(
                "Sending GET authorization request to IDP: %s",
                parsed_decrypted_resp["headers"]["Location"],
            )
            new_uri = parsed_decrypted_resp["headers"]["Location"]

            http_response = self.https_session.get(
                new_uri,
                headers={
                    "Content-Type": "application/octet-stream",
                    "x-useragent": USER_AGENT,
                },
                timeout=34,
                verify=False,
            )

            logger.debug("HTTP Content: %s", http_response.content)

            # Decode the byte string to a JSON string
            json_response = http_response.content.decode("utf-8")

            # Parse the JSON string
            response_data = json.loads(json_response)

            logger.debug("Response data: %s", json.dumps(response_data, indent=4))

            # Extract the challenge value
            challenge = response_data.get("challenge")
            user_consent = response_data.get("user_consent")

            logger.debug("Challenge token received: %s", challenge)

            return challenge, user_consent

        except Exception as e:
            logger.error("Error sending a authorization request to ePA-Authz-Service: %s", str(e))
            raise AuthenticationException(
                message=f"Error sending a authorization request to ePA-Authz-Service: {str(e)}",
                error_code="EPA_AUTHZ_ERROR",
            )

    def send_authcode_sc(
        self, authcode: str, client_attest_jwt: str, insurant_id: str
    ) -> str:
        """
        Sends an authorization code (which is a JWT) and client attestation JWT to the server.
        This method constructs an HTTP POST request with the provided authorization code
        and client attestation JWT, sends it to the server, and processes the response.
        Args:
                authcode (str): The authorization code to be sent.
                client_attest_jwt (str): The client attestation JWT to be sent.
        Returns:
                str: The VAU-NP value extracted from the server's response.
        Raises:
                Exception: If there is an error in sending the VAU message or parsing the response.
        """

        try:
            logger.info("Sending authcode SC")
            # Define the POST body
            body = {"authorizationCode": authcode, "clientAttest": client_attest_jwt}

            # Convert the body to a JSON string
            body_json = json.dumps(body)

            # Construct the POST request
            inner_request = "POST /epa/authz/v1/send_authcode_sc HTTP/1.1\r\n"
            inner_request += f"Host: {self.host}\r\n"
            inner_request += "Accept: application/json\r\n"
            inner_request += "Content-Type: application/json\r\n"
            inner_request += f"Content-Length: {len(body_json)}\r\n"
            inner_request += f"x-useragent: {USER_AGENT}\r\n"
            inner_request += f"x-insurantid: {insurant_id}\r\n"
            inner_request += "\r\n"
            inner_request += f"{body_json}"

            inner_request = inner_request.encode("utf-8")

            logger.debug("Inner HTTP request: %s", inner_request)

            decrypted_resp = self.send_vau_message(inner_request)
            parsed_decrypted_resp = self.parse_inner_http_response(decrypted_resp)
            logger.debug("Authcode SC response: %s", json.dumps(parsed_decrypted_resp, indent=4))

            vau_np = parsed_decrypted_resp["body"]["vau-np"]
            logger.debug("VAU-NP: %s", vau_np)
            return vau_np

        except Exception as e:
            logger.error("Error sending a authorization to ePA-Authz-Service: %s", str(e))
            raise AuthenticationException(
                message=f"Error sending a authorization to ePA-Authz-Service: {str(e)}",
                error_code="EPA_AUTHZ_ERROR",
            )

    def upload_document(
        self, vau_np: str, soap_message: bytes, boundary_string: str, insurant_id: str
    ) -> dict:
        """
        Uploads a document to the specified endpoint using a SOAP message.
        Args:
                vau_np (str): The VAU-NP Token.
                soap_message (str): The SOAP message to be sent in the request body.
                boundary_string (str): The boundary string for the multipart content type.
        Returns:
                dict: The parsed response from the server.
        Raises:
                Any exceptions raised by the `send_vau_message` or `parse_inner_http_response` methods.

        """

        try:

            logger.info("Uploading document")

            content_type = f'multipart/related;start-info="application/soap+xml";type="application/xop+xml";action="urn:ihe:iti:2007:ProvideAndRegisterDocumentSet-b";boundary={boundary_string}'

            body = soap_message

            # Construct the POST request
            inner_request = (
                "POST /epa/xds-document/api/I_Document_Management HTTP/1.1\r\n"
            )
            inner_request += f"Host: {self.host}\r\n"
            inner_request += f"Content-Type: {content_type}\r\n"
            inner_request += f"Content-Length: {len(body)}\r\n"
            inner_request += f"x-useragent: {USER_AGENT}\r\n"
            inner_request += f"x-insurantid:{insurant_id}\r\n"
            inner_request += "\r\n"
            
            inner_request = inner_request.encode("utf-8") + body

            # Read and store the soap message log content
            # with open("soap_message_log.txt", "wb") as file:
            #     file.write(inner_request)

            logger.debug("Inner HTTP request: %s", inner_request)

            decrypted_resp = self.send_vau_message(inner_request, vau_np=vau_np)

            # with open("soap_response_log.txt", "w", encoding="utf-8") as file:
            #         file.write(decrypted_resp.decode("utf-8"))

            parsed_decrypted_resp = self.parse_inner_http_response(decrypted_resp)
            logger.debug(
                "Upload document response: %s",
                json.dumps(parsed_decrypted_resp, indent=4),
            )

            # Parse the decrypted response with zeep
            response_obj = requests.Response()
            response_obj._content = parsed_decrypted_resp["body"].encode("utf-8")
            response_obj.status_code = int(
                parsed_decrypted_resp["http_status"].split(" ")[1]
            )
            response_obj.encoding = "utf-8"
            response_obj.headers = parsed_decrypted_resp["headers"]

            parsed_decrypted_resp["body"] = SoapClient.parse_xml_response(
                response_obj,
                SoapClient.Services.DocumentService.I_Document_Management.DocumentRepository_ProvideAndRegisterDocumentSet_b,
            )

            return parsed_decrypted_resp
        except Exception as e:
            raise VAUException(
                message=f"Error when sending a document to the ePA: {str(e)}",
                error_code="EPA_SEND_ERROR",
            )
