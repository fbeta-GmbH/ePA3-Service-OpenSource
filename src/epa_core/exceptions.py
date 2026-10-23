from __future__ import annotations
from epa_core.http_status import status
from epa_core.runtime_config.logging import logger


class ErrorCodes:
    """Centralized error codes grouped by subsystem."""

    # SSL errors
    SSL_ERROR = "SSL_ERROR"

    # VAU errors
    VAU_INIT_FAILED = "VAU_INIT_FAILED"
    VAU_AUTH_FAILED = "VAU_AUTH_FAILED"
    VAU_CERT_VALIDATION_FAILED = "VAU_CERT_VALIDATION_FAILED"
    VAU_COMMUNICATION_ERROR = "VAU_COMMUNICATION_ERROR"

    # ePA service errors
    EPA_GETNONCE_ERROR = "EPA_GETNONCE_ERROR"
    EPA_AUTHZ_ERROR = "EPA_AUTHZ_ERROR"
    EPA_NOT_ENTITLED = "EPA_NOT_ENTITLED"
    EPA_SEND_ERROR = "EPA_SEND_ERROR"

    # Konnektor errors
    KONNEKTOR_INIT_FAILED = "KONNEKTOR_INIT_FAILED"
    KONNEKTOR_REQUEST_FAILED = "KONNEKTOR_REQUEST_FAILED"
    KONNEKTOR_ENDPOINT_NOTREACHABLE = "KONNEKTOR_ENDPOINT_NOTREACHABLE"
    KONNEKTOR_MALFORMED_REQUEST = "KONNEKTOR_MALFORMED_REQUEST"

    # Card errors
    CARD_NOT_FOUND = "CARD_NOT_FOUND"
    CARD_CERTIFICATE_ERROR = "CARD_CERTIFICATE_ERROR"
    CARD_PIN_NOT_VERIFIED = "CARD_PIN_NOT_VERIFIED"
    CARD_OPERATION_ERROR = "CARD_OPERATION_ERROR"

    # Document errors
    DOC_DECODE_ERROR = "DOC_DECODE_ERROR"
    DOC_MISSING_DATA = "DOC_MISSING_DATA"
    DOC_UPLOAD_ERROR = "DOC_UPLOAD_ERROR"
    DOC_UPLOAD_DUPLICATE = "DOC_UPLOAD_DUPLICATE"
    DOC_REPLACE_UUID_ERROR = "DOC_REPLACE_UUID_ERROR"

    # Identity Provider errors
    IDP_VERIFICATION_ERROR = "IDP_VERIFICATION_ERROR"
    IDP_REQUEST_ERROR = "IDP_REQUEST_ERROR"

    # Signature errors
    SIGNATURE_MISSING = "SIGNATURE_MISSING"
    SIGNATURE_PROCESSING_ERROR = "SIGNATURE_PROCESSING_ERROR"

    # General errors
    UNEXPECTED_ERROR = "UNEXPECTED_ERROR"
    INTERNAL_SERVER_ERROR = "INTERNAL_SERVER_ERROR"

    # Record status errors
    RECORD_EXISTS_AND_ACTIVATED = "RECORD_EXISTS_AND_ACTIVATED"
    RECORD_NOT_FOUND = "RECORD_NOT_FOUND"
    RECORD_STATUS_CONFLICT = "RECORD_STATUS_CONFLICT"


class EPABaseException(Exception):
    def __init__(self, message: str, error_code: str | None = None,
                 status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
                 detail: dict | None = None):
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.detail = detail
        super().__init__(message)


class VAUException(EPABaseException):
    pass

class KonnektorException(EPABaseException):
    def __init__(self, message: str, error_code: str | None = None,
                 status_code: int = status.HTTP_503_SERVICE_UNAVAILABLE,
                 detail: dict | None = None):
        super().__init__(message, error_code, status_code, detail)

class CardException(KonnektorException):
    pass

class IdentityProviderException(EPABaseException):
    def __init__(self, message: str, error_code: str | None = None,
                 status_code: int = status.HTTP_502_BAD_GATEWAY,
                 detail: dict | None = None):
        super().__init__(message, error_code, status_code, detail)

class AuthenticationException(EPABaseException):
    def __init__(self, message: str, error_code: str | None = None,
                 status_code: int = status.HTTP_401_UNAUTHORIZED,
                 detail: dict | None = None):
        super().__init__(message, error_code, status_code, detail)

class AuthorizationException(EPABaseException):
    def __init__(self, message: str, error_code: str | None = None,
                 status_code: int = status.HTTP_403_FORBIDDEN,
                 detail: dict | None = None):
        super().__init__(message, error_code, status_code, detail)

class DocumentException(EPABaseException):
    def __init__(self, message: str, error_code: str | None = None,
                 status_code: int = status.HTTP_422_UNPROCESSABLE_CONTENT,
                 detail: dict | None = None):
        super().__init__(message, error_code, status_code, detail)
