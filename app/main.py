import os
import uuid
import tempfile
import secrets
from contextlib import asynccontextmanager
from typing import Optional, Annotated

import sentry_sdk
from fastapi import FastAPI, HTTPException, status, UploadFile, File, Form, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

from app.logging_config import logger
from app.app.client import send_document_to_epa


sentry_dsn = os.getenv("SENTRY_DSN")
if sentry_dsn:
    sentry_sdk.init(
        dsn=sentry_dsn,
        traces_sample_rate=1.0,
        profiles_sample_rate=1.0,
        environment=os.getenv("EPA_ENVIRONMENT", "RT"),
    )
    logger.info("Sentry initialized")
else:
    logger.warning("SENTRY_DSN not set, Sentry will not be initialized")


# HTTP Basic Authentication setup
security = HTTPBasic()
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "changeme")


def verify_credentials(credentials: Annotated[HTTPBasicCredentials, Depends(security)]) -> str:
    """Verify HTTP Basic Auth credentials"""
    correct_username = secrets.compare_digest(credentials.username.encode("utf8"), ADMIN_USERNAME.encode("utf8"))
    correct_password = secrets.compare_digest(credentials.password.encode("utf8"), ADMIN_PASSWORD.encode("utf8"))

    if not (correct_username and correct_password):
        logger.warning(f"Failed authentication attempt for username: {credentials.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    return credentials.username


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting ePA FastAPI service")
    yield
    logger.info("Shutting down ePA FastAPI service")


app = FastAPI(
    title="ePA 3.0 Document Service",
    description="Service for uploading documents to ePA 3.0",
    version="1.0.0",
    lifespan=lifespan
)


class DocumentEntryRequest(BaseModel):
    creationTime: str = Field(..., description="Creation time in format YYYYMMDDHHMMSS")
    title: str = Field(..., description="Document title")
    URI: str = Field(..., description="Document URI/filename")
    entryUUID: str = Field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}", description="Unique document entry UUID")
    old_entry_uuid: str | None = Field(None, description="Optional: UUID of document to replace")


class DocumentUploadRequest(BaseModel):
    kvnr: str = Field(..., description="Patient insurance number (Krankenversichertennummer)")
    documentEntry: DocumentEntryRequest
    document_file_name: str = Field(..., description="Name of the document file to upload from data directory")


class DocumentResponse(BaseModel):
    id: str


class DocumentCreatedResponse(BaseModel):
    document: DocumentResponse


class ErrorResponse(BaseModel):
    error: str


@app.post(
    "/epa/3.0/documents",
    status_code=status.HTTP_201_CREATED,
    response_model=DocumentCreatedResponse,
    responses={
        201: {"model": DocumentCreatedResponse, "description": "Document created successfully"},
        400: {"model": ErrorResponse, "description": "Bad request - validation or upload error"},
        401: {"description": "Unauthorized - invalid credentials"}
    }
)
async def upload_document(
    username: Annotated[str, Depends(verify_credentials)],
    kvnr: str = Form(..., description="Patient insurance number (Krankenversichertennummer)"),
    title: str = Form(..., description="Document title"),
    creation_time: str = Form(..., description="Creation time in format YYYYMMDDHHMMSS"),
    file: UploadFile = File(..., description="Document file to upload"),
    entry_uuid: Optional[str] = Form(None, description="Optional: Unique document entry UUID"),
    old_entry_uuid: Optional[str] = Form(None, description="Optional: UUID of document to replace")
):
    temp_file_path = None
    try:
        logger.info(f"Received document upload request for KVNR: {kvnr}")

        if not entry_uuid:
            entry_uuid = f"urn:uuid:{uuid.uuid4()}"

        with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{file.filename}") as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_file_path = temp_file.name
            logger.info(f"Saved uploaded file to temporary location: {temp_file_path}")

        metadata = {
            "insurantId": kvnr,
            "documentEntry": {
                "creationTime": creation_time,
                "title": title,
                "URI": file.filename,
                "entryUUID": entry_uuid
            }
        }

        if old_entry_uuid:
            metadata["documentEntry"]["old_entry_uuid"] = old_entry_uuid

        data_dir = os.path.join(os.path.dirname(__file__), 'data')
        os.makedirs(data_dir, exist_ok=True)

        final_file_path = os.path.join(data_dir, file.filename)
        os.replace(temp_file_path, final_file_path)
        temp_file_path = None

        try:
            send_document_to_epa(
                metadata=metadata,
                document_file_name=file.filename
            )
        finally:
            if os.path.exists(final_file_path):
                try:
                    os.unlink(final_file_path)
                    logger.info(f"Cleaned up uploaded file: {final_file_path}")
                except Exception as e:
                    logger.warning(f"Failed to clean up uploaded file {final_file_path}: {str(e)}")

        logger.info(f"Document uploaded successfully for KVNR: {kvnr}")

        return DocumentCreatedResponse(
            document=DocumentResponse(id=entry_uuid)
        )

    except ValueError as e:
        logger.error(f"Validation error during document upload: {str(e)}", exc_info=True)
        sentry_sdk.capture_exception(e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": str(e)}
        )
    except FileNotFoundError as e:
        logger.error(f"Document file not found: {str(e)}", exc_info=True)
        sentry_sdk.capture_exception(e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": f"Document file not found: {str(e)}"}
        )
    except Exception as e:
        logger.error(f"Unexpected error during document upload: {str(e)}", exc_info=True)
        sentry_sdk.capture_exception(e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": f"Document upload failed: {str(e)}"}
        )
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.unlink(temp_file_path)
                logger.info(f"Cleaned up temporary file: {temp_file_path}")
            except Exception as e:
                logger.warning(f"Failed to clean up temporary file {temp_file_path}: {str(e)}")


@app.get("/health")
async def health_check():
    return {"status": "healthy"}
