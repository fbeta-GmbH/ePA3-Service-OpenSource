from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

class SignedVauServerPubKeys(BaseModel):
    """
    The content of the "signierte öffentliche VAU-Schlüssel" structure, containing the signed public keys and related metadata for the VAU protocol key agreement. 
    Received from the server in VAU Message 2. 
    
    See: https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.48.0/#A_24425-01
    """
    model_config = ConfigDict(validate_by_name=True)

    signature_es256: bytes = Field(alias="signature-ES256", min_length=64, max_length=64)
    """
    "signature-ES256": ECDSA-Signatur-SHA-256-analog-RFC-7515 (R||S => 64 Byte) binär

    Signature over `signed_pub_keys` (ES256 = ECDSA + SHA-256).
    Used to prove origin and integrity of the server key bundle.
    Protocol format is raw R||S (64 bytes: 32 + 32), not DER.
    """

    cert_hash: bytes = Field(min_length=32, max_length=32)
    """
    SHA-256-Wert des "signierenden" AUT-VAU-Zertifikats

    SHA-256 fingerprint of the AUT-VAU signing certificate.
    This links the signed key bundle to the exact certificate that must be fetched and validated.
    """

    ocsp_response: bytes = Field(min_length=1)
    """
    OCSP-Response-für-das-VAU-Signaturzertifikat-nicht-älter-als-24-Stunden-DER-Kodierung

    OCSP response (DER) for that AUT-VAU certificate.
    Used during chain validation to ensure certificate status is GOOD and fresh (max 24h).
    """

    signed_pub_keys: bytes = Field(min_length=1)
    """
    VAU_Keys_encoded payload: signed server public keys used to encrypt VAU traffic.

    CBOR-encoded bundle containing at least ECDH/Kyber keys and metadata (for example `exp`).
    These exact bytes are covered by `signature_es256`.
    This value is not trusted by itself; trust comes from validating `signature_es256`
    with the public key from the validated AUT-VAU certificate (including cert status checks).
    """

    cdv: int = Field(ge=1)
    """
    Cert-Data-Version (natürliche Zahl, beginnend mit 1, vgl. A_24957-*)

    CertData version used to resolve the certificate endpoint.
    Must be >= 1.
    """

class AUT_VAU_CertData(BaseModel):
    """
    The content of the CertData file fetched from the /CertData.<hash>-<version> endpoint, containing the AUT-VAU certificate and its chain of trust certificates for validation.
    
    See: https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.48.0/#A_24957
    """

    cert: bytes
    """
    DER-kodiertes-AUT-VAU-Zertifikat

    AUT-VAU end-entity certificate (DER).
    Its public key verifies the signature over `signed_pub_keys` in SignedVauServerPubKeys.
    """

    ca: bytes
    """
    In "rca_chain" MÜSSEN alle Cross-Zertifikate in chronologischer Ordnung von RCA5 ausgehend aufgeführt werden, bis die Root-Schlüssel (Cross-Zertifikat) erreicht werden, mit denen das "ca"-Zertifikat bestätigt (signiert) wurde; d. h., sozusagen eine einfach verkettete Liste von Cross-Zertifikaten chronologisch aufsteigend.
    Prüfkette
    DER-kodiertes-Komponenten-PKI-CA-aus-dem-"cert"-kommt,

    Issuing CA certificate (DER) for `cert`.
    Sent by the server as helper data to prove `cert` links to one of our pinned TI root certificates.
    This means there must be a valid signature chain: `cert` was signed by `ca`, and `ca` was signed by the next cert in `rca_chain` (if any), and so on up to a pinned TI root.
    None of these are trusted on their own; only the full chain up to a pinned TI root is trusted.
    """

    rca_chain: bytes | list[bytes]
    """
    [Cross-Zertifikat-1, ..., Cross-Zertifikat-n],

    Optional cross/RCA certificates (single value or list).
    Additional helper certificates that continue the link from `ca` up to a pinned TI root.
    Each next certificate must cryptographically verify the previous one.
    These are also not trusted on their own.
    """


class ECDHPublicKey(BaseModel):
    """
    Representation of an ECDH public key for curve P-256, containing the x and y coordinates as 32-byte big-endian binary values.

    See: https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.48.0/#A_24425-01
    """
    crv: Literal["P-256"]
    """The curve type. Must be "P-256"."""

    x: bytes = Field(min_length=32, max_length=32)
    """Binärwert-x-Koordinate-32-Byte-big-endian (256 Bit)"""

    y: bytes = Field(min_length=32, max_length=32)
    """Binärwert-y-Koordinate-32-Byte-big-endian (256 Bit)"""

class VAUPublicKeyBundle(BaseModel):
    """
    The decoded content of the `signed_pub_keys` field after CBOR decoding, containing the actual public keys and metadata that the client will use for encrypting VAU traffic after validation.

    See: https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.48.0/#A_24425-01
    """

    ECDH_PK: ECDHPublicKey
    """
    ECDH-Public-Key for curve P-256, containing the x and y coordinates as 32-byte big-endian binary values.
    """

    Kyber768_PK: bytes = Field(min_length=1184, max_length=1184)
    """
    Binärwert-öffentlicher-Schlüssel-nach-keygen-Spec-Kyber768

    Public key bytes for Kyber768 as specified in the Kyber768 key generation spec.
    """

    iat: int = Field(ge=0)
    """
    Erzeugungszeits-Sekunden-Since-Epoch (integer)

    Timestamp (seconds since epoch) of when the server generated this key bundle.
    """

    exp: int = Field(ge=0)
    """
    Nicht-mehr-Verwendbar-nach (integer)

    Timestamp (seconds since epoch) after which the keys must no longer be used.
    """

    comment: str
    """
    Erzeugt bei VAU-Instanz xyz, Meta-Info abcd

    Free-form comment field that can contain any text data.
    """
