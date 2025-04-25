from http import HTTPStatus

from app.logging_config import logger

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
    def __init__(self, message: str, error_code: str = None):
        super().__init__(message, error_code, HTTPStatus.SERVICE_UNAVAILABLE)

class KonnektorException(EPABaseException):
    """Exceptions related to Konnektor operations"""
    def __init__(self, message: str, error_code: str = None):
        super().__init__(message, error_code, HTTPStatus.SERVICE_UNAVAILABLE)

class CardException(EPABaseException):
    """Exceptions related to Card operations"""
    def __init__(self, message: str, error_code: str = None):
        super().__init__(message, error_code, HTTPStatus.SERVICE_UNAVAILABLE)

class IdentitiyProviderException(EPABaseException):
    """Exceptions related to IDP operations"""
    def __init__(self, message: str, error_code: str = None):
        super().__init__(message, error_code, HTTPStatus.SERVICE_UNAVAILABLE)

class AuthenticationException(EPABaseException):
    """Exceptions related to authentication processes"""
    def __init__(self, message: str, error_code: str = None):
        super().__init__(message, error_code, HTTPStatus.UNAUTHORIZED)

class DocumentException(EPABaseException):
    """Exceptions related to document handling"""
    def __init__(self, message: str, error_code: str = None):
        super().__init__(message, error_code, HTTPStatus.BAD_REQUEST)

class SessionException(EPABaseException):
    """Exceptions related to session management"""
    def __init__(self, message: str, error_code: str = None):
        super().__init__(message, error_code, HTTPStatus.SERVICE_UNAVAILABLE)