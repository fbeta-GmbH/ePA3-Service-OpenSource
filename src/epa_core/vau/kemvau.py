from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from epa_core.runtime_config.logging import logger

import secrets

import oqs
import oqs.rand as oqsrand

from binascii import hexlify
# nur fürs pretty-Printing das json-modul
import json

from typing import TypedDict

ecc_pk_dict = TypedDict("ecc_pk_dict", { "crv": str, "x": bytes, "y": bytes})

def encode_ecc_pub_key(ecc_public_key: ec.EllipticCurvePublicKey) -> dict:
    """
    Encode an ECC public key into a dictionary format.
    
    Note: In ECDH context, an ECC point = public key = ciphertext.
    
    Args:
        ecc_public_key (ec.EllipticCurvePublicKey): The ECC public key to encode
        
    Returns:
        dict: Dictionary containing curve type and x,y coordinates as bytes
    """

    pub_numbers = ecc_public_key.public_numbers()
    ecdh_ct = {"crv": "P-256",
               "x"  : pub_numbers.x.to_bytes(length=32, byteorder='big', signed=False),
               "y"  : pub_numbers.y.to_bytes(length=32, byteorder='big', signed=False)
              }

    return ecdh_ct


def decode_ecc_pub_key(data: ecc_pk_dict) -> ec.EllipticCurvePublicKey:
    """
    Decode a dictionary format ECC public key back into a cryptography.io key object.
    
    Args:
        data (ecc_pk_dict): Dictionary containing curve type and x,y coordinates
        
    Returns:
        ec.EllipticCurvePublicKey: The decoded public key
        
    Raises:
        AssertionError: If curve type is not P-256 or coordinate lengths are invalid
    """
    # Im Produktiv-Code muss das in einer try-Umgebung laufen,
    # ... invalid encoding etc.

    assert data["crv"] == "P-256"
    assert len(data["x"])==32
    assert len(data["y"])==32

    public_numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(data["x"], byteorder='big', signed=False),
            int.from_bytes(data["y"], byteorder='big', signed=False),
            ec.SECP256R1())
    result = public_numbers.public_key()

    return result

def gen_keypairs() -> dict:
    """
    Generate hybrid keypairs for ECDH and Kyber768.
    
    Returns:
        dict: Dictionary containing both ECDH and Kyber768 key pairs with structure:
            {
                "ECDH": {"pub_key": dict, "priv_key": EllipticCurvePrivateKey},
                "Kyber768": {"pub_key": bytes, "priv_key": bytes}
            }
    """

    ecdh_private_key = ec.generate_private_key(ec.SECP256R1())
    ecdh_public_key = ecdh_private_key.public_key()
    ecdh_public_key_encoded = encode_ecc_pub_key(ecdh_public_key)

    with oqs.KeyEncapsulation("Kyber768") as pqc_client:

        pqc_public_key = pqc_client.generate_keypair()

        result = { "ECDH"     : {"pub_key"  : ecdh_public_key_encoded,
                                 "priv_key" : ecdh_private_key},
                   "Kyber768" : {"pub_key"  : pqc_public_key,
                                 "priv_key" : pqc_client.export_secret_key()}
                 }

    return result

def encapsulation(pk_keys: dict) -> dict:
    """
    Perform key encapsulation using both ECDH and Kyber768.
    
    Args:
        pk_keys (dict): Dictionary containing remote public keys for both algorithms
        
    Returns:
        dict: Dictionary containing ciphertexts and shared secrets with structure:
            {
                "ecdh_ct": dict,
                "ecdh_shared_secret": bytes,
                "Kyber768_ct": bytes,
                "Kyber768_shared_secret": bytes
            }
    """

    remote_ecc_public_key = decode_ecc_pub_key(pk_keys["ECDH_PK"])
    tmp_private_key = ec.generate_private_key(ec.SECP256R1())
    ecdh_ct = encode_ecc_pub_key(tmp_private_key.public_key())
    ecdh_shared_secret = tmp_private_key.exchange(ec.ECDH(), remote_ecc_public_key)


    with oqs.KeyEncapsulation("Kyber768") as server:
        kyber768_ct, kyber768_shared_secret = server.encap_secret(pk_keys["Kyber768_PK"])

    return {
        "ECDH_ct": ecdh_ct,
        "ECDH_ss": ecdh_shared_secret,
        "Kyber768_ct": kyber768_ct,
        "Kyber768_ss": kyber768_shared_secret
    }

def kem_kdf(kem_result_1: dict, kem_result_2: dict = None) -> list:
    """
    Perform key derivation function on KEM results.
    
    Args:
        kem_result_1 (dict): First KEM result containing ECDH and Kyber768 shared secrets
        kem_result_2 (dict, optional): Second KEM result for additional entropy. Defaults to None
        
    Returns:
        list: List of derived keys (32 bytes each)
        
    Raises:
        AssertionError: If shared secrets are empty
    """

    assert len(kem_result_1["ECDH_ss"])>0
    assert len(kem_result_1["Kyber768_ss"])>0

    if kem_result_2:
        shared_secret = kem_result_1["ECDH_ss"] + \
                        kem_result_1["Kyber768_ss"] + \
                        kem_result_2["ECDH_ss"] + \
                        kem_result_2["Kyber768_ss"]
        target_len = 5*32 # 4 256-Bit-AES-Schlüssel + ein 256-Bit KeyID
    else:
        shared_secret = kem_result_1["ECDH_ss"] + kem_result_1["Kyber768_ss"]
        target_len = 2*32 # 2 256-Bit-AES-Schlüssel

    tmp = HKDF(algorithm=hashes.SHA256(), length=target_len, salt=None,
               info=b'').derive(shared_secret)

    result = []
    for i in range(0, len(tmp) >> 5):
        result.append(tmp[i*32:(i+1)*32])

    return result

def aead_enc(key: bytes, plaintext: bytes) -> bytes:
    """
    Perform authenticated encryption with associated data (AEAD).
    
    Args:
        key (bytes): 32-byte encryption key
        plaintext (bytes): Data to encrypt
        
    Returns:
        bytes: Concatenated IV and ciphertext
        
    Raises:
        AssertionError: If key length is not 32 bytes or plaintext is empty
    """
    assert len(key)==32
    assert len(plaintext)>0

    iv = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(iv, plaintext, associated_data=None)

    return iv + ciphertext

def aead_enc_message(key: bytes, plaintext: bytes, associated_data: bytes, iv: bytes) -> bytes:
    """
    Perform AEAD encryption with custom IV and associated data.
    
    Args:
        key (bytes): 32-byte encryption key
        plaintext (bytes): Data to encrypt
        associated_data (bytes): Additional authenticated data
        iv (bytes): Initialization vector
        
    Returns:
        bytes: Concatenated IV and ciphertext
        
    Raises:
        AssertionError: If key length is not 32 bytes or plaintext is empty
    """
    assert len(key)==32
    assert len(plaintext)>0

    ciphertext = AESGCM(key).encrypt(iv, plaintext, associated_data=associated_data)

    return iv + ciphertext

def aead_dec(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt AEAD encrypted data.
    
    Args:
        key (bytes): 32-byte decryption key
        ciphertext (bytes): Concatenated IV and encrypted data
        
    Returns:
        bytes: Decrypted plaintext
        
    Raises:
        AssertionError: If key length is not 32 bytes or ciphertext is empty
    """
    assert len(key)==32
    assert len(ciphertext)>0

    iv = ciphertext[:12]
    ct = ciphertext[12:]
    # Im Code für eine Produktiv-Umgebung muss man die Entschlüsselung
    # in einer try-Umgebung (exceptions) durchführen.
    plaintext = AESGCM(key).decrypt(iv, ct, associated_data=None)

    return plaintext

def aead_dec_message(key: bytes, ciphertext: bytes, assosiated_data: bytes) -> bytes:
    """
    Decrypt AEAD encrypted data with associated data.
    
    Args:
        key (bytes): 32-byte decryption key
        ciphertext (bytes): Concatenated IV and encrypted data
        assosiated_data (bytes): Additional authenticated data
        
    Returns:
        bytes: Decrypted plaintext
        
    Raises:
        AssertionError: If key length is not 32 bytes or ciphertext is empty
    """
    assert len(key)==32
    assert len(ciphertext)>0

    iv = ciphertext[:12]
    ct = ciphertext[12:]
    # Im Code für eine Produktiv-Umgebung muss man die Entschlüsselung
    # in einer try-Umgebung (exceptions) durchführen.
    plaintext = AESGCM(key).decrypt(iv, ct, associated_data=assosiated_data)

    return plaintext

def decapsulation(ciphertexts: dict, priv_keys: dict) -> dict:
    """
    Perform key decapsulation using both ECDH and Kyber768.
    
    Args:
        ciphertexts (dict): Dictionary containing ECDH and Kyber768 ciphertexts
        priv_keys (dict): Dictionary containing private keys for both algorithms
        
    Returns:
        dict: Dictionary containing derived shared secrets with structure:
            {
                "ECDH_ss": bytes,
                "Kyber768_ss": bytes
            }
            
    Raises:
        AssertionError: If input parameters are not dictionaries
    """
    assert isinstance(ciphertexts, dict)
    assert isinstance(priv_keys, dict)

    ecc_public_key_sender = decode_ecc_pub_key(ciphertexts["ECDH_ct"])
    ecdh_shared_secret = priv_keys["ECDH"]["priv_key"].exchange(ec.ECDH(), ecc_public_key_sender)


    with oqs.KeyEncapsulation("Kyber768", priv_keys["Kyber768"]["priv_key"]) as client:
        shared_secret_client = client.decap_secret(ciphertexts["Kyber768_ct"])

    return {"ECDH_ss" : ecdh_shared_secret,
            "Kyber768_ss" : shared_secret_client}