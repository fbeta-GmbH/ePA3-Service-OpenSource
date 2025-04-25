import base64
import hashlib
import json
import urllib.parse

import ecdsa
import requests
from jwcrypto import common, jwe, jwk, jws

from app.logging_config import logger

from app.constants import IDP_URL

from app.exceptions import IdentitiyProviderException
class IdentitiProvider:
    def __init__(self):
        """
        Initialize a new instance of the IdentitiProvider class.
        Uses the IDP_URL constant for API endpoint configuration.
        """
        logger.info("Initializing IdentitiProvider with URL: %s", IDP_URL)
        self.puk_idp_enc_url, self.puk_idp_sig_url = self.get_discovery()

    def get_certs(self) -> json:
        """
        Retrieve all certificates from the identity provider.
        
        Returns:
            json: JSON object containing all available certificates
            
        Raises:
            requests.exceptions.RequestException: If the certificates cannot be retrieved
        """
        try:
            logger.info("Getting certificates")
            response = requests.get(IDP_URL + '/certs', timeout=30)
            logger.debug("Certificates: %s", json.dumps(response.json(), indent=4))
            return response.json()
        except requests.exceptions.RequestException as e:
            raise IdentitiyProviderException(f"Failed to retrieve certificates: {str(e)}")


    def get_openid_configuration(self) -> dict:
        """
        Retrieve the OpenID Connect configuration from the well-known endpoint.
        
        Returns:
            dict: Dictionary containing the OpenID configuration headers
            
        Raises:
            requests.exceptions.RequestException: If the configuration cannot be retrieved
        """
        logger.info("Getting OpenID configuration")
        response = requests.get(IDP_URL + '/.well-known/openid-configuration', timeout=30)
        logger.debug("OpenID configuration: %s", json.dumps(dict(response.headers), indent=4))
        return dict(response.headers)
    

    #puk_idp_sig - öffentlicher Schlüssel und Zertifikat zur Validierung der vom IDP-Dienst ausgestellten Signaturen
    def get_puk_idp_sig(self) -> str:
        """
        Retrieve the public key and certificate for validating IDP signatures.
        
        This key (PUK_IDP_SIG) is used to validate signatures issued by the IDP service.
        
        Returns:
            dict: Dictionary containing the public key and certificate
            
        Raises:
            requests.exceptions.RequestException: If the key cannot be retrieved
        """
        logger.info("Getting PUK IDP SIG")
        response = requests.get(self.puk_idp_sig_url, timeout=30)
        logger.debug("PUK IDP SIG: %s", json.dumps(response.json(), indent=4))
        return response.text
    

    #puk_idp_enc - öffentlicher Schlüssel zum Verschlüsseln von für den IDP-Dienst bestimmten Daten
    #wird zum verschlüsseln der inneren JWT in NJWT verwendet
    def get_puk_idp_enc(self) -> str:
        """
        Retrieve the public key for encrypting data intended for the IDP.
        
        This key (PUK_IDP_ENC) is used to encrypt the inner JWT in NJWT format.
        
        Returns:
            dict: Dictionary containing the encryption public key
            
        Raises:
            requests.exceptions.RequestException: If the key cannot be retrieved
        """
        logger.info("Getting PUK IDP ENC")
        response = requests.get(self.puk_idp_enc_url, timeout=30)
        logger.debug("PUK IDP ENC: %s", json.dumps(response.json(), indent=4))
        return response.text


    #puk_idp_sig_sek -  öffentlicher Schlüssel des IDP-Dienst zur Authentisierung gegenüber sektoralen Identity Providern.
    def get_puk_idp_sek(self) -> str:
        """
        Retrieve the IDP's public key for authentication to sectoral identity providers.
        
        This key (PUK_IDP_SEK) is used for authentication between identity providers.
        
        Returns:
            dict: Dictionary containing the sectoral authentication public key
            
        Raises:
            requests.exceptions.RequestException: If the key cannot be retrieved
        """
        logger.info("Getting PUK IDP SEK")
        response = requests.get(IDP_URL + '/certs/puk_idp_sek', timeout=30)
        logger.debug("PUK IDP SEK: %s", json.dumps(response.json(), indent=4))
        return response.text
    
    def get_discovery(self) -> tuple[str, str]:
        """
        Retrieve the well-known configuration from the IDP.
        
        Returns:
            tuple[str, str]: Tuple containing the URI for the encryption and signature keys
            
        Raises:
            requests.exceptions.RequestException: If the configuration cannot be retrieved
        """
        logger.info("Getting discovery configuration")
        try:
            response = requests.get(IDP_URL + '/.well-known/openid-configuration', timeout=30)
            response.raise_for_status()

            try:
                # Split JWT into header, payload, signature
                header, payload, signature = response.text.split('.')
                # Decode payload from base64
                decoded_payload = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)).decode())
                
                uri_puk_idp_enc = decoded_payload['uri_puk_idp_enc']
                uri_puk_idp_sig = decoded_payload['uri_puk_idp_sig']
                
                return uri_puk_idp_enc, uri_puk_idp_sig
            
            except (ValueError, KeyError) as e:
                raise IdentitiyProviderException(f"Failed to parse discovery endpoint: {str(e)}")
        except requests.exceptions.RequestException as e:
            raise IdentitiyProviderException(f"Failed to retrieve discovery endpoint: {str(e)}")
            

    

    def verify_challenge_token(self, challenge_token: str) -> bool:
        """
        Verify the signature of a challenge token using the IDP's public key.
        
        According to gemSpec_PS_ePA specification section A_20663-01, the primary system 
        must verify the challenge token signature against the current PUK_IDP_SIG public key.
        If the key is not available, it must be retrieved using the 'puk_idp_sig' key ID
        from the Discovery Document.
        
        Args:
            challenge_token (str): The challenge token to verify
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        logger.info("Verifying challenge token")
        if not challenge_token:
            logger.error("Challenge token is None")
            raise IdentitiyProviderException("Challenge token cannot be None")
        
        # Decode challenge token
        challenge_token_jws = jws.JWS()
        challenge_token_jws.deserialize(challenge_token)
        logger.debug("Challenge token decoded (without signature): %s", challenge_token_jws)

        # Get public key from IDP (PUK_IDP_SIG)
        public_key_json = json.loads(self.get_puk_idp_sig())
        public_key_jwk = jwk.JWK(**public_key_json)

        # create a verifying key with correct signature algorithm and hash function from the given public key
        verifying_key = ecdsa.VerifyingKey.from_pem(public_key_jwk.export_to_pem(), hashfunc=hashlib.sha256)

        # Split challenge token into data and signature parts
        header, payload, signature = challenge_token.split('.')

        data_bytes =  (header + '.' + payload).encode()
        signature_bytes = common.base64url_decode(signature)

        logger.debug("Data bytes: %s", data_bytes)
        logger.debug("Signature bytes: %s", signature_bytes)
        
        # use the verifying key to verify the signature with the data 
        try:
            verifying_key.verify(signature_bytes, data_bytes)
            logger.info("Challenge token signature verified successfully")
            return True
        except ecdsa.BadSignatureError:
            logger.error("Challenge token signature verification failed")
            return False
        
    def auth_build_inner_header_payload(self, challenge_token: str, card_cert: str) -> str:
        """
        Build the inner header and payload for the nested JWT (NJWT) authentication token.
        
        Args:
            challenge_token (str): The challenge token to include in the payload
            card_cert (str): The card certificate to include in the header
            
        Returns:
            str: Concatenated base64url-encoded header and payload string
        """
        inner_headers = {
            "typ" : "JWT",
            "cty": "NJWT",
            "alg": "BP256R1",
            "x5c": [card_cert]
        }

        
        inner_payload = {
            "njwt": challenge_token
        }

        header_payload_challenge_string = f"{base64.urlsafe_b64encode(json.dumps(inner_headers).encode()).decode()}.{base64.urlsafe_b64encode(json.dumps(inner_payload).encode()).decode()}"

        return header_payload_challenge_string

        
    def auth_build_njwt(self, header_payload_challenge_string: str, signature: str, exp: str) -> str:
        """
        Build and encrypt a Nested JSON Web Token (NJWT) for authentication.
        
        Creates an outer JWE (JSON Web Encryption) that contains an inner signed JWS
        (JSON Web Signature). The inner JWS contains the challenge response.
        
        Args:
            header_payload_challenge_string (str): The header and payload string to sign
            signature (str): The signature of the challenge
            exp (str): The expiration time for the outer token
            
        Returns:
            str: The authorization code received from the IDP
            
        Raises:
            requests.exceptions.RequestException: If the authentication request fails
        """
        logger.info("Building auth NJWT")
        logger.debug("Signature: %s", signature)
        urlsafe_signature = signature.replace('+', '-').replace('/', '_')
        logger.debug("Signature urlsafe: %s", urlsafe_signature)
        inner_signed_jws = f"{header_payload_challenge_string}.{urlsafe_signature}"

        logger.debug("Inner signed JWS: %s", inner_signed_jws)

        outer_header = {
            "alg" : "ECDH-ES",
            "enc" : "A256GCM",
            "cty" : "NJWT",
            "exp" : exp
        }

        outer_payload = {
            'njwt': inner_signed_jws
        }

        puk_idp_enc= self.get_puk_idp_enc()

        key = jwk.JWK.from_json(puk_idp_enc)

        jwe_token = jwe.JWE(json.dumps(outer_payload).encode('utf-8'),
                     recipient=key,
                     protected=outer_header)
        
        encrypted_njwt = jwe_token.serialize(compact=True)

        logger.debug("Encrypted NJWT: %s", encrypted_njwt)

        data = {
            'signed_challenge': encrypted_njwt
        }

        response = requests.post(IDP_URL + '/auth', data=data, timeout=30, allow_redirects=False)
        logger.debug("Auth NJWT response: %s", response.headers)
        logger.debug("Auth NJWT response body: %s", response.text)

        parsed_location_url = urllib.parse.urlparse(response.headers['Location'])
        response_queries = urllib.parse.parse_qs(parsed_location_url.query)
        logger.debug("Auth NJWT response queries: %s", response_queries)

        auth_code = response_queries['code'][0]

        return auth_code

