import json
from app.exceptions import ErrorCodes, DocumentException, AuthorizationException
from fastapi import status


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
            status_code=status.HTTP_403_FORBIDDEN
            )
    
    if "XDSDuplicateDocument" in response_str:
        raise DocumentException(
            "Document upload failed: Duplicate document. Hashvalue of the document already exists in target record", 
            ErrorCodes.DOC_UPLOAD_DUPLICATE, 
            status_code=status.HTTP_409_CONFLICT
            )
    
    if "Invalid target ID" in response_str and "RPLC association"  in response_str:
        raise DocumentException(
            "Document upload failed: Invalid target oldEntryUUID", 
            ErrorCodes.DOC_REPLACE_UUID_ERROR, 
            status_code=status.HTTP_404_NOT_FOUND
            )

    
    else: 
        return
    
