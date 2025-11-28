import os
import sys
import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
from fastapi.testclient import TestClient

# Add the parent directory to the path so we can import app
sys.path.insert(0, str(Path(__file__).parent.parent))

# Set environment variables before any imports
os.environ.update({
    'EPA_ENVIRONMENT': 'RT',
    'KONNEKTOR_URL': 'https://test-konnektor.example.com',
    'DIGA_NAME': 'Test DiGA',
    'DIGA_MANUFACTURER': 'Test Manufacturer',
    'MANDANT_ID': 'test_mandant',
    'CLIENT_SYSTEM_ID': 'test_client',
    'WORKPLACE_ID': 'test_workplace',
    'USER_ID': 'test_user',
    'DEFAULT_EPA_PROVIDER_ID': '2',
    'LOG_LEVEL': 'INFO',
    'USER_AGENT': 'test-agent/1.0.0',
    'ADMIN_USERNAME': 'testuser',
    'ADMIN_PASSWORD': 'testpass'
})

# Mock the send_document_to_epa function before importing anything
mock_send_func = MagicMock(return_value=None)
sys.modules['app.app.client'] = MagicMock(send_document_to_epa=mock_send_func)


@pytest.fixture
def mock_env():
    """Test-level environment fixture"""
    yield


@pytest.fixture
def mock_send_document_to_epa(mock_env):
    # Reset the mock for each test
    mock_send_func.reset_mock()
    mock_send_func.side_effect = None
    mock_send_func.return_value = None
    yield mock_send_func


@pytest.fixture
def client(mock_send_document_to_epa):
    import app.main
    with TestClient(app.main.app) as test_client:
        yield test_client


@pytest.fixture
def sample_xml_content():
    return b'''<?xml version="1.0" encoding="UTF-8"?>
<Bundle xmlns="http://hl7.org/fhir">
    <id value="test-bundle"/>
    <type value="document"/>
</Bundle>'''


@pytest.fixture
def auth_headers():
    """HTTP Basic Auth headers for testing"""
    import base64
    credentials = base64.b64encode(b"testuser:testpass").decode("ascii")
    return {"Authorization": f"Basic {credentials}"}
