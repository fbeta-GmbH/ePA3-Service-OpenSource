import ecdsa
from hashlib import sha256
import base64
import time
import requests

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

import json

from jwcrypto import jwt


def convert_der_ecdsa_to_concated_x962(der_signature: bytes) -> str:
    """
    Converts a DER-encoded ECDSA signature to a concatenated X9.62 format and returns it as a base64url-encoded string.
    This function takes a DER-encoded signature, decodes it into its r and s components, 
    and concatenates them in X9.62 format (r || s), where each component is exactly 32 bytes.
    Args:
        der_signature (bytes): The DER-encoded ECDSA signature to convert.
    Returns:
        str: The base64url-encoded concatenated signature in X9.62 format.
    Raises:
        ValueError: If the signature components cannot be properly decoded or if r or s values are too large for 32-byte representation.
    """

    r, s = decode_dss_signature(der_signature)
    r_bytes = r.to_bytes(32, 'big')
    s_bytes = s.to_bytes(32, 'big')
    return base64.urlsafe_b64encode(r_bytes + s_bytes).decode('utf-8')


def read_keyless_jwt(keyless_jwt:str)->dict:
    """
    Reads and decodes a keyless JWT (JSON Web Token) and returns its claims.

    This function takes a JWT string that doesn't require a key for verification
    and extracts the payload claims using the BP256R1 algorithm.

    Args:
        keyless_jwt (str): The JWT string to be decoded

    Returns:
        dict: The decoded claims from the JWT payload

    Raises:
        jwt.JWTError: If the JWT is invalid or cannot be decoded
        json.JSONDecodeError: If the payload is not valid JSON
    """
    jwt_challenge = jwt.JWT(key=None, jwt=keyless_jwt, algs=['BP256R1'])
    claims = json.loads(jwt_challenge.token.objects['payload'])
    return claims


def deep_merge_dicts(dict1, dict2) -> dict:
    """
    Recursively merge two dictionaries.
    """
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value
    return result