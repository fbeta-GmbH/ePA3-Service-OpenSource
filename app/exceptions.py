from http import HTTPStatus

from app.runtime_config.logging import logger

class ErrorCodes:
    """Centralized error codes for better consistency and documentation"""
    # VAU errors
    VAU_INIT_FAILED = "VAU_INIT_FAILED"
    VAU_AUTH_FAILED = "VAU_AUTH_FAILED"
    VAU_CERT_VALIDATION_FAILED = "VAU_CERT_VALIDATION_FAILED"
    VAU_COMMUNICATION_ERROR = "VAU_COMMUNICATION_ERROR"
    
    # EPA service errors
    EPA_GETNONCE_ERROR = "EPA_GETNONCE_ERROR"
    EPA_AUTHZ_ERROR = "EPA_AUTHZ_ERROR"
    EPA_NOT_ENTITLED = "EPA_NOT_ENTITLED"
    EPA_SEND_ERROR = "EPA_SEND_ERROR"
    
    # Konnektor errors
    KONNEKTOR_INIT_FAILED = "KONNEKTOR_INIT_FAILED"
    KONNEKTOR_REQUEST_FAILED = "KONNEKTOR_REQUEST_FAILED"
    KONNEKTOR_ENDPOINT_NOTREACHABLE= "KONNEKTOR_ENDPOINT_NOTREACHABLE"
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

    # Value errors
    SIGNATURE_MISSING = "SIGNATURE_MISSING"
    SIGNATURE_PROCESSING_ERROR = "SIGNATURE_PROCESSING_ERROR"

    
    # Session errors
    SESSION_EXPIRED = "SESSION_EXPIRED"
    SESSION_INVALID = "SESSION_INVALID"
    SESSION_DESERIALIZATION_ERROR = "SESSION_DESERIALIZATION_ERROR"
    
    # General errors
    UNEXPECTED_ERROR = "UNEXPECTED_ERROR"
    INTERNAL_SERVER_ERROR = "INTERNAL_SERVER_ERROR"
    
    # Error codes for getRecordStatus
    RECORD_EXISTS_AND_ACTIVATED = "RECORD_EXISTS_AND_ACTIVATED"
    RECORD_NOT_FOUND = "RECORD_NOT_FOUND"
    RECORD_STATUS_CONFLICT = "RECORD_STATUS_CONFLICT"



class EPABaseException(Exception):
    """Base exception class for all ePA-related exceptions"""
    def __init__(self, message: str, error_code: str = None, status_code: int = HTTPStatus.INTERNAL_SERVER_ERROR):
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        logger.error("%s: %s (Error code: %s, Status code: %d)", 
                    self.__class__.__name__, 
                    message, 
                    error_code or 'None',
                    status_code)
        super().__init__(self.message)

class VAUException(EPABaseException):
    """Exceptions related to VAU channel operations"""
    def __init__(self, message: str, error_code: str = None, status_code: int = HTTPStatus.INTERNAL_SERVER_ERROR):
        super().__init__(message, error_code, status_code)

class KonnektorException(EPABaseException):
    """Exceptions related to Konnektor operations"""
    def __init__(self, message: str, error_code: str = None, status_code: int = HTTPStatus.INTERNAL_SERVER_ERROR):
        super().__init__(message, error_code, status_code)

class CardException(EPABaseException):
    """Exceptions related to Card operations"""
    def __init__(self, message: str, error_code: str = None, status_code: int = HTTPStatus.INTERNAL_SERVER_ERROR):
        super().__init__(message, error_code, status_code)

class IdentityProviderException(EPABaseException):
    """Exceptions related to IDP operations"""
    def __init__(self, message: str, error_code: str = None, status_code: int = HTTPStatus.INTERNAL_SERVER_ERROR):
        super().__init__(message, error_code, status_code)

class AuthenticationException(EPABaseException):
    """Exceptions related to authentication processes"""
    def __init__(self, message: str, error_code: str = None, status_code: int = HTTPStatus.INTERNAL_SERVER_ERROR):
        super().__init__(message, error_code, status_code)

class AuthorizationException(EPABaseException):
    """Exceptions related to authorization and permissions"""
    def __init__(self, message: str, error_code: str = None, status_code: int = HTTPStatus.INTERNAL_SERVER_ERROR):
        super().__init__(message, error_code, status_code)

class DocumentException(EPABaseException):
    """Exceptions related to document handling"""
    def __init__(self, message: str, error_code: str = None, status_code: int = HTTPStatus.INTERNAL_SERVER_ERROR):
        super().__init__(message, error_code, status_code)

class SessionException(EPABaseException):
    """Exceptions related to session management"""
    def __init__(self, message: str, error_code: str = None, status_code: int = HTTPStatus.INTERNAL_SERVER_ERROR):
        super().__init__(message, error_code, status_code)

class LocalizationException(EPABaseException):
    """Exceptions related to record localization"""
    def __init__(self, message: str, error_code: str = None, status_code: int = HTTPStatus.INTERNAL_SERVER_ERROR):
        super().__init__(message, error_code, status_code)