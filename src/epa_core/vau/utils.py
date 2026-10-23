import re
import json
from epa_core.exceptions import ErrorCodes, DocumentException, AuthorizationException, VAUException
from epa_core.http_status import status

def sanitize_header_value(value: str) -> str:
    if '\r' in value or '\n' in value or '\x00' in value:
        raise ValueError("Invalid header value: contains CRLF or NUL characters")
    return value

def validate_insurant_id(insurant_id: str) -> str:
    if not re.match(r'^[A-Z]\d{9}$', insurant_id):
        raise ValueError(f"Invalid Insurant ID format: {insurant_id}")
    return insurant_id

def check_upload_response_for_errors(response_body:dict) -> None:
    """
    Checks the response of the upload document request for errors.
    Args:
        response_json (json): The JSON response from the upload document request.
    """
    response_str = json.dumps(response_body)
    
    
    if "NotEntitled" in response_str:
        raise AuthorizationException(
            "Not entitled by target InsurantId to perform this action",
            ErrorCodes.EPA_NOT_ENTITLED, 
            status_code=status.HTTP_403_FORBIDDEN,
            detail=response_body
            )
    
    if "XDSDuplicateDocument" in response_str:
        raise DocumentException(
            "Document upload failed: Duplicate document. Hashvalue of the document already exists in target record", 
            ErrorCodes.DOC_UPLOAD_DUPLICATE, 
            status_code=status.HTTP_409_CONFLICT,
            detail=response_body
            )
    
    # The vau kanal was established (earlier) with a different telematik id
    if "Telematik-ID does not match" in response_str:
        raise VAUException(
            "VAU channel established with different Telematik-ID.",
            ErrorCodes.VAU_INIT_FAILED, 
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=response_body
            )
    
    if "Invalid target ID" in response_str and "RPLC association"  in response_str:
        raise DocumentException(
            "Document upload failed: Invalid target oldEntryUUID", 
            ErrorCodes.DOC_REPLACE_UUID_ERROR, 
            status_code=status.HTTP_404_NOT_FOUND,
            detail=response_body
            )

    
    else: 
        return
    
