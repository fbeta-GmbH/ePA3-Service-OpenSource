"""
Initializes the VAUKanal instance and performs the initial key exchange with the AS_URL.

Parameters:
AS_URL (str): The authorization-server base URL. A trailing slash is accepted and normalized.
"""

import hashlib
import json
import secrets
from base64 import b64encode
from ssl import SSLCertVerificationError
from typing import Optional
from urllib import parse

import cbor2
import requests
from epa_core.http_status import status

from epa_core.exceptions import AuthenticationException, AuthorizationException, ErrorCodes, VAUException
from epa_core.runtime_config.constants import Config, EpaEnvs
from epa_core.vau import kemvau, utils, validator
from epa_core.vau.http import InnerHttpRequest, InnerHttpResponse


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
        self.AS_URL = AS_URL.rstrip('/')
        Config.logger.info("=== Initializing VAUKanal with AS_URL: %s ===", self.AS_URL)
        try:

            self.encryption_counter = 0
            self.request_counter = 0
            self.last_response_counter = 0  

            assert self.AS_URL
            assert self.AS_URL.startswith("http://") or self.AS_URL.startswith("https://")

            AS_URL_START_VAU = f"{self.AS_URL}/VAU"

            self.host = parse.urlparse(self.AS_URL).netloc

            self.https_session = requests.Session()
            self.https_session.verify = Config.TI_CA_BUNDLE
            self.vau_cert_validator = validator.VAUCertificateValidator(AS_URL=self.AS_URL, https_session=self.https_session)

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
                        "x-useragent": Config.USER_AGENT,
                    },
                    data=nachricht_1_encoded,
                    timeout=Config.HTTPS_TIMEOUT*2,
                )
            except (requests.exceptions.SSLError, SSLCertVerificationError):
                raise
            except Exception as e:
                raise VAUException(
                    message=f"VAU-Kanal Failed at VAU-Message 1 : {e}",
                    error_code=ErrorCodes.VAU_AUTH_FAILED,
                    status_code=status.HTTP_401_UNAUTHORIZED
                )

            Config.logger.debug("VauMessage 1 sent, response: %s", http_response.content)
            Config.logger.debug("HTTP Status Code: %s", http_response.status_code)
            Config.logger.debug("HTTP Response Headers: %s", http_response.headers)

            """VauMessage 2:
                        Der Server nimmt die VauMessage 1 entgegen. Die PublicKeys des Clients und seinen eigenen PrivateKeys nutzt er, 
                        um die ECDH und Kyber Shared Secrets mitsamt Ciphertexts (KdfMessage) zu erstellen. Daraus erstellt er den ersten 
                        Schlüssel KdfKey1. Diesen nutzt er, um seine signierten PublicKeys zu verschlüsseln. In VauMessage 2 werden die Ciphertexts 
                        der Shared Secrets sowie die verschlüsselten signierten PublicKeys gespeichert und diese Nachricht wird zurück zum Client geschickt."""

            assert http_response.status_code == requests.codes.ok
            assert http_response.headers["Content-Type"] == "application/cbor"
            assert "VAU-CID" in http_response.headers

            self.vau_cid = http_response.headers["VAU-CID"]

            self.as_url_plus_vau_cid = f"{self.AS_URL}/{self.vau_cid.lstrip('/')}"

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
            Config.logger.debug("Schlüsselableitung für die K1-Schlüssel")
            (c_k1_c2s, c_k1_s2c) = kemvau.kem_kdf(client_kem_result_1)
            transfered_signed_vau_server_pub_keys = kemvau.aead_dec(
                c_k1_s2c, nachricht_2["AEAD_ct"]
            )
            # Im Produktivcode try-Umgebung, weil daten noch nicht authentisiert
            signed_vau_server_pub_keys = cbor2.loads(transfered_signed_vau_server_pub_keys)

            Config.logger.debug(signed_vau_server_pub_keys)

            # Enforce A_24624-01 certificate validation here; violations raise VAUException directly.
            self.vau_cert_validator.validate(signed_vau_server_pub_keys)

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

            Config.logger.debug("Schlüsselableitung für die K2-Schlüssel")
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
                        "x-useragent": Config.USER_AGENT,
                    },
                    data=nachricht_3_encoded,
                    timeout=Config.HTTPS_TIMEOUT,
                )
            except (requests.exceptions.SSLError, SSLCertVerificationError):
                raise
            except Exception as e:
                raise VAUException(
                    message=f"VAU-Kanal Failed at VAU-Message 3 : {e}",
                    error_code=ErrorCodes.VAU_AUTH_FAILED,
                    status_code=status.HTTP_502_BAD_GATEWAY
                )

            Config.logger.debug("VauMessage 3 sent, response: %s", http_response.content)
            Config.logger.debug("HTTP Response Headers: %s", http_response.headers)

            """VauMessage 4:
                        Der Server öffnet VauMessage 4 und erhält mit seinem KdfKey1 die Ciphertexts. 
                        Mit diesen kann er nun seinen eigenen Shared Secrets erstellen. Mit allen Shared Secrets 
                        leitet er, wie der Client zuvor, den KdfKey2 her. Um den Vorgang zu validieren, überprüft 
                        der Server die Hash des Clients: Er entschlüsselt die Ciphertext-KeyConfirmation mit dem KdfKey2 
                        und erhält den Client-Hash. Diese vergleicht er mit dem SHA-256 verschlüsselten eigenen Transcript. 
                        Den eigenen Hash verschlüsselt er mit dem KdfKey2 (=Ciphertext-KeyConfirmation). 
                        Diese wird in VauMessage 4 gespeichert und zurück zum Client geschickt.
                        """
            Config.logger.debug(http_response.status_code)
            # ic(http_response.content)
            Config.logger.info("Status code: %s", http_response.status_code)
            assert http_response.status_code == requests.codes.ok
            assert http_response.headers["Content-Type"] == "application/cbor"

            nachricht_4_encoded = http_response.content

            Config.logger.info("----------------------VAU-KANAL ERFOLGREICH AUFGEBAUT----------------------") 
        except (requests.exceptions.SSLError, SSLCertVerificationError):
            raise
        except VAUException:
            raise
        except Exception as e:
            Config.logger.exception("Unexpected error during building of VAU-Kanal (%s)", type(e).__name__)
            raise VAUException(
                message=f"Building VAU-Kanal Failed: {str(e)}",
                error_code=ErrorCodes.VAU_AUTH_FAILED,
                status_code=status.HTTP_502_BAD_GATEWAY
            )


    def parse_inner_http_response(self, response: bytes) -> dict:
        Config.logger.debug("Parsing inner HTTP response")
        """
                Parses an HTTP response in bytes and formats it into its components.
                
                Args:
                        response (bytes): The HTTP response in bytes.
                
                Returns:
                        dict: A dictionary containing 'http_status', 'headers', and 'body'.
                """
        # 1. Header und Body trennen
        header_bytes, body_bytes = response.split(b"\r\n\r\n", 1)

        # 2. Header dekodieren
        header_part = header_bytes.decode("utf-8")

        # 3. Header aufschlüsseln
        headers = header_part.split("\r\n")
        http_status = headers[0]  # Erster Header enthält HTTP-Status
        header_dict = {}

        for header in headers[1:]:
            key, value = header.split(": ", 1)
            header_dict[key] = value

        # 4. Body parsen (JSON oder String oder Bytes-Fallback)
        try:
            body_json = json.loads(body_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError):
            try:
                body_json = body_bytes.decode("utf-8")
            except UnicodeDecodeError:
                body_json = body_bytes  # Fallback: Raw bytes für binary MTOM-Responses
        except Exception as e:
            raise VAUException(
                message=f"Error parsing HTTP response body: {str(e)}",
                error_code=ErrorCodes.VAU_COMMUNICATION_ERROR,
                status_code=status.HTTP_502_BAD_GATEWAY
            )

        result = {"http_status": http_status, "headers": header_dict, "body": body_json}
        Config.logger.debug("Parsed response: %s", json.dumps(result, indent=4, default=str))
        return result

    def send_vau_message(self, inner_request: bytes, vau_np=None) -> bytes:
        Config.logger.info("Sending VAU message")
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
        http_response = None
        try:
            self.encryption_counter += 1
            self.request_counter += 1
            
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
                "x-useragent": Config.USER_AGENT,
            }

            # If not PU, then add VAU-nonPU-Tracing in Header
            if Config.EPA_ENVIRONMENT != EpaEnvs.PROD.id:
                k2_c2s_b64 = b64encode(self.c_k2_c2s_app_data).decode('ascii')
                k2_s2c_b64 = b64encode(self.c_k2_s2c_app_data).decode('ascii')
                headers["VAU-nonPU-Tracing"] = f"{k2_c2s_b64} {k2_s2c_b64}"



            if vau_np is not None:
                headers["VAU-NP"] = vau_np

            Config.logger.debug("Sending VAU message with headers: %s", headers)

            http_response = self.https_session.post(
                self.as_url_plus_vau_cid,
                headers=headers,
                data=message,
                timeout=Config.HTTPS_TIMEOUT,
            )

            # Get response data
            response_data = http_response.content

            Config.logger.info("HTTP Status Code: %s", http_response.status_code)
            Config.logger.info(
                "HTTP Response Headers: %s",
                json.dumps(dict(http_response.headers), indent=4),
            )
            Config.logger.debug("HTTP Response Content: %s", http_response.content)
            Config.logger.debug(f"Performed on Endpoint {self.as_url_plus_vau_cid} ")
            
            if http_response.status_code != status.HTTP_200_OK and http_response.headers.get("Content-Type") == "application/cbor":
                # See: https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.45.0/#6.6
                Config.logger.error(f"Received non-200 HTTP status code: {http_response.status_code}")
                error_response = cbor2.loads(response_data)
                Config.logger.error(f"Decoded error response: {error_response}")
                error_code = error_response.get("ErrorCode", "Unknown")
                error_message = error_response.get("ErrorMessage", "No message provided")
                error_description = error_response.get("Description", "No description provided")
                error_details = error_response.get("Details", "No details provided")
                raise VAUException(
                    message=f"Received HTTP {http_response.status_code} with error code {error_code}: {error_message}. Description: {error_description}. Details: {error_details}",
                    error_code=ErrorCodes.VAU_COMMUNICATION_ERROR,
                    status_code=status.HTTP_502_BAD_GATEWAY
                )
            elif len(response_data) < 72:
                raise VAUException(
                    
                    message=f"Vau-Message response is too short: {len(response_data)}<72 bytes",
                    error_code=ErrorCodes.VAU_COMMUNICATION_ERROR,
                    status_code=status.HTTP_502_BAD_GATEWAY
                    )

            # Parse response header
            resp_version = response_data[0]
            resp_pu = response_data[1]
            resp_type = response_data[2]
            resp_counter = int.from_bytes(response_data[3:11], "big")
            resp_keyid = response_data[11:43]

            if resp_pu != 0x00:
                raise VAUException(
                    message="Invalid PU/nonPU byte in VAU response",
                    error_code=ErrorCodes.VAU_COMMUNICATION_ERROR,
                    status_code=status.HTTP_502_BAD_GATEWAY
                )
            if resp_type != 0x02:
                raise VAUException(
                    message="Invalid response type in VAU response",
                    error_code=ErrorCodes.VAU_COMMUNICATION_ERROR,
                    status_code=status.HTTP_502_BAD_GATEWAY
                )
            if resp_counter <= self.last_response_counter:
                raise VAUException(
                    message=f"Non-monotonic response counter (got {resp_counter}, expected > {self.last_response_counter})",
                    error_code=ErrorCodes.VAU_COMMUNICATION_ERROR,
                    status_code=status.HTTP_502_BAD_GATEWAY
                )
            self.last_response_counter = resp_counter
            
            if resp_keyid != self.c_key_id:
                raise VAUException(
                    message="Unknown KeyID in VAU response",
                    error_code=ErrorCodes.VAU_COMMUNICATION_ERROR,
                    status_code=status.HTTP_502_BAD_GATEWAY
                )

            resp_cipher = response_data[43:]
            resp_aad = response_data[:43]
            # Decrypt response
            decrypted_resp = kemvau.aead_dec_message(
                self.c_k2_s2c_app_data, resp_cipher, resp_aad
            )

            Config.logger.debug("Response data: %s", response_data)
            Config.logger.debug("Decrypted response: %s", decrypted_resp)

            return decrypted_resp

        except (requests.exceptions.SSLError, SSLCertVerificationError):
            raise
        except Exception as e:
            if http_response is not None:
                Config.logger.error("Error sending VAU message on endpoint %s, with %s : %s", self.as_url_plus_vau_cid, http_response.status_code, str(e))
                raise VAUException(
                    message=f"Error sending VAU message on endpoint {self.as_url_plus_vau_cid}, with Response-Status {http_response.status_code}: {str(e)}",
                    error_code=ErrorCodes.VAU_COMMUNICATION_ERROR,
                    status_code=status.HTTP_502_BAD_GATEWAY
                )
            else:
                Config.logger.error("Error sending VAU message on endpoint %s: %s", self.as_url_plus_vau_cid, str(e))
                raise VAUException(
                    message=f"Error sending VAU message on endpoint {self.as_url_plus_vau_cid}: {str(e)}",
                    error_code=ErrorCodes.VAU_COMMUNICATION_ERROR,
                    status_code=status.HTTP_502_BAD_GATEWAY
                )

    def build_inner_header(
            self, 
            uri: str, 
            insurant_id: str,
            accept_type: Optional[str] = "application/json",
            content_type: Optional[str] = "application/json",
            content_length: Optional[int] = None,
        ) -> str:
        """
        Builds the inner HTTP header for a VAU message.
        """
        Config.logger.info("=== Building inner HTTP header ===")
        try:
            utils.validate_insurant_id(insurant_id)
            inner_header = (
                f"{utils.sanitize_header_value(uri)} HTTP/1.1\r\n"
                f"Host: {utils.sanitize_header_value(self.host)}\r\n" +
                (f"Accept: {utils.sanitize_header_value(accept_type)}\r\n" if accept_type is not None else "") +
                (f"Content-Type: {utils.sanitize_header_value(content_type)}\r\n" if content_type is not None else "") +
                (f"Content-Length: {utils.sanitize_header_value(str(content_length))}\r\n" if content_length is not None else "") +
                f"x-useragent: {utils.sanitize_header_value(Config.USER_AGENT)}\r\n"
                f"x-insurantid: {utils.sanitize_header_value(utils.validate_insurant_id(insurant_id))}\r\n"
                "\r\n"
            )
            return inner_header 
        except ValueError as e:
            Config.logger.error("Error building inner HTTP header: %s", str(e))
            raise VAUException(
                message=f"Error building inner HTTP header: {str(e)}",
                error_code=ErrorCodes.VAU_COMMUNICATION_ERROR,
                status_code=status.HTTP_400_BAD_REQUEST
            )


    def execute(self, request: InnerHttpRequest, *, vau_np: str | None = None) -> InnerHttpResponse:
        """Send an arbitrary inner HTTP request over the established VAU channel."""
        body = request.body or b""
        normalized_headers = {str(k).lower(): str(v) for k, v in request.headers.items()}
        accept = normalized_headers.pop("accept", None)
        content_type = normalized_headers.pop("content-type", None)
        header = self.build_inner_header(
            f"{request.method.upper()} {request.path}",
            insurant_id=request.insurant_id,
            accept_type=accept,
            content_type=content_type,
            content_length=len(body) if body else None,
        )
        if normalized_headers:
            extra = "".join(f"{key}: {value}\r\n" for key, value in normalized_headers.items())
            header = header.replace("\r\n\r\n", f"\r\n{extra}\r\n", 1)
        raw_response = self.send_vau_message(header.encode("utf-8") + body, vau_np=vau_np)
        parsed = self.parse_inner_http_response(raw_response)
        status_line = str(parsed["http_status"])
        status_parts = status_line.split(" ", 2)
        try:
            status_code = int(status_parts[1])
        except (IndexError, ValueError) as exc:
            raise VAUException(
                message=f"Invalid inner HTTP status line: {status_line}",
                error_code=ErrorCodes.VAU_COMMUNICATION_ERROR,
                status_code=status.HTTP_502_BAD_GATEWAY,
            ) from exc
        return InnerHttpResponse(
            status_code=status_code,
            headers=parsed["headers"],
            body=parsed["body"],
            status_line=status_line,
        )

    def get_nonce(self, insurant_id: str) -> str:
        Config.logger.info("=== Getting Nonce ===")
        """
                This function sends an HTTP request to obtain a nonce.
                The function creates an inner HTTP request to the endpoint '/epa/authz/v1/getNonce' 
                and sends this request via the 'send_vau_message' method. The response is decrypted 
                and parsed to extract the nonce from the response body.
                
                Returns:
                        str: The nonce extracted from the response.
                """
        try:
            inner_request = self.build_inner_header(
                "GET /epa/authz/v1/getNonce",
                insurant_id,
            )
            Config.logger.debug("Inner HTTP request: %s", inner_request)
            inner_request = inner_request.encode("utf-8")

            decrypted_resp = self.send_vau_message(inner_request)
            parsed_decrypted_resp = self.parse_inner_http_response(decrypted_resp)

            utils.check_upload_response_for_errors(parsed_decrypted_resp)

            if parsed_decrypted_resp["body"].get("nonce") is None:
                raise ValueError(f"Nonce not found in response body: {parsed_decrypted_resp['body']}")
            Config.logger.debug("Nonce received: %s", parsed_decrypted_resp["body"]["nonce"])
            return parsed_decrypted_resp["body"]["nonce"]
        
        except (VAUException, AuthorizationException):
            raise
        except (requests.exceptions.SSLError, SSLCertVerificationError):
            raise
        except Exception as e:
            Config.logger.error("Error getting Nonce from ePA-Authz-Service: %s", str(e))
            raise AuthenticationException(
                message=f"Error getting Nonce from ePA-Authz-Service: {str(e)}",
                error_code=ErrorCodes.EPA_GETNONCE_ERROR,
                status_code=status.HTTP_401_UNAUTHORIZED
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
            Config.logger.info("=== Sending authorization request SC ===")

            inner_request = self.build_inner_header(
                "GET /epa/authz/v1/send_authorization_request_sc",
                insurant_id,
            )

            inner_request = inner_request.encode("utf-8")

            decrypted_resp = self.send_vau_message(inner_request)
            parsed_decrypted_resp = self.parse_inner_http_response(decrypted_resp)

            Config.logger.info("RESPONSE SEND_AUTH_REQUEST_SC")
            Config.logger.debug(json.dumps(parsed_decrypted_resp, indent=4))
            
            utils.check_upload_response_for_errors(parsed_decrypted_resp)
            
            location_uri_parameters: dict = {
                k: v[0]
                for k, v in dict(parse.parse_qs(parse.urlsplit(parsed_decrypted_resp["headers"]["Location"]).query)).items()
            }
            Config.logger.debug(
                "Location URI parameters: %s",
                json.dumps(location_uri_parameters, indent=4),
            )

            Config.logger.info(
                "Sending GET authorization request to IDP: %s",
                parsed_decrypted_resp["headers"]["Location"],
            )
            new_uri = parsed_decrypted_resp["headers"]["Location"]

            http_response = self.https_session.get(
                new_uri,
                headers={
                    "Content-Type": "application/octet-stream",
                    "x-useragent": Config.USER_AGENT,
                },
                timeout=Config.HTTPS_TIMEOUT,
            )

            Config.logger.debug("HTTP Content: %s", http_response.content)
            Config.logger.debug("HTTP Status Code: %s", http_response.status_code)
            Config.logger.debug("HTTP Response Headers: %s", http_response.headers)

            # Decode the byte string to a JSON string
            json_response = http_response.content.decode("utf-8")

            # Parse the JSON string
            response_data = json.loads(json_response)

            Config.logger.debug("Response data: %s", json.dumps(response_data, indent=4))

            # Extract the challenge value
            challenge = response_data.get("challenge")
            user_consent = response_data.get("user_consent")

            Config.logger.debug("Challenge token received: %s", challenge)

            return challenge, user_consent

        except AuthorizationException:
            raise
        except (requests.exceptions.SSLError, SSLCertVerificationError):
            raise
        except Exception as e:
            Config.logger.error("Error sending a authorization request to ePA-Authz-Service: %s", str(e))
            raise AuthenticationException(
                message=f"Error sending a authorization request to ePA-Authz-Service: {str(e)}",
                error_code=ErrorCodes.EPA_AUTHZ_ERROR,
                status_code=status.HTTP_401_UNAUTHORIZED
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
            Config.logger.info("Sending authcode SC")
            # Define the POST body
            body = {"authorizationCode": authcode, "clientAttest": client_attest_jwt}

            # Convert the body to a JSON string
            body_json = json.dumps(body)

            inner_request = self.build_inner_header(
                "POST /epa/authz/v1/send_authcode_sc",
                insurant_id,
                content_length=len(body_json),
            )
            inner_request += body_json

            inner_request = inner_request.encode("utf-8")

            Config.logger.debug("Inner HTTP request: %s", inner_request)

            decrypted_resp = self.send_vau_message(inner_request)
            parsed_decrypted_resp = self.parse_inner_http_response(decrypted_resp)
            Config.logger.debug("Authcode SC response: %s", json.dumps(parsed_decrypted_resp, indent=4))

            vau_np = parsed_decrypted_resp["body"]["vau-np"]
            Config.logger.debug("VAU-NP: %s", vau_np)
            return vau_np

        except (requests.exceptions.SSLError, SSLCertVerificationError):
            raise
        except Exception as e:
            Config.logger.error("Error sending a authorization to ePA-Authz-Service: %s", str(e))
            raise AuthenticationException(
                message=f"Error sending a authorization to ePA-Authz-Service: {str(e)}",
                error_code=ErrorCodes.EPA_AUTHZ_ERROR,
                status_code=status.HTTP_401_UNAUTHORIZED
            )

    def to_bytes(self) -> bytes:
        """Convert VAUKanal instance to bytes for Redis storage"""
        data = {
            "vau_cid": self.vau_cid,
            "as_url_plus_vau_cid": self.as_url_plus_vau_cid,
            "c_key_id": self.c_key_id,
            "c_k2_c2s_app_data": self.c_k2_c2s_app_data,
            "c_k2_s2c_app_data": self.c_k2_s2c_app_data,
            "encryption_counter": self.encryption_counter,
            "request_counter": self.request_counter,
            "last_response_counter": self.last_response_counter,
            "host": self.host,
        }
        return cbor2.dumps(data)

    @classmethod
    def from_bytes(cls, data_bytes: bytes) -> "VAUKanal":
        """Create VAUKanal instance from bytes stored in Redis"""
        # Skips __init__ method and directly creates an instance of the class
        instance = cls.__new__(cls)

        data = cbor2.loads(data_bytes)

        instance.vau_cid = data["vau_cid"]
        instance.as_url_plus_vau_cid = data["as_url_plus_vau_cid"]
        instance.c_key_id = data["c_key_id"]
        instance.c_k2_c2s_app_data = data["c_k2_c2s_app_data"]
        instance.c_k2_s2c_app_data = data["c_k2_s2c_app_data"]
        instance.encryption_counter = data["encryption_counter"]
        instance.request_counter = data["request_counter"]
        instance.last_response_counter = data.get("last_response_counter", 0)  # Default to 0 if not present
        instance.host = data["host"]

        instance.https_session = requests.Session()
        instance.https_session.verify = Config.TI_CA_BUNDLE

        return instance
