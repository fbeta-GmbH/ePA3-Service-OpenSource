import pytest
import io
from datetime import datetime
from unittest.mock import patch, MagicMock


class TestDocumentUpload:

    def test_health_check(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

    def test_upload_document_success(self, client, mock_send_document_to_epa, sample_xml_content, auth_headers):
        mock_send_document_to_epa.return_value = None

        files = {
            'file': ('test_document.xml', io.BytesIO(sample_xml_content), 'application/xml')
        }
        data = {
            'kvnr': 'X110591068',
            'title': 'Test Document',
            'creation_time': '20230609115053'
        }

        response = client.post('/epa/3.0/documents', files=files, data=data, headers=auth_headers)

        assert response.status_code == 201
        json_response = response.json()
        assert 'document' in json_response
        assert 'id' in json_response['document']
        assert json_response['document']['id'].startswith('urn:uuid:')

        mock_send_document_to_epa.assert_called_once()
        call_args = mock_send_document_to_epa.call_args
        assert call_args[1]['metadata']['insurantId'] == 'X110591068'
        assert call_args[1]['metadata']['documentEntry']['title'] == 'Test Document'
        assert call_args[1]['metadata']['documentEntry']['creationTime'] == '20230609115053'

    def test_upload_document_with_custom_uuid(self, client, mock_send_document_to_epa, sample_xml_content, auth_headers):
        mock_send_document_to_epa.return_value = None

        custom_uuid = 'urn:uuid:12345678-1234-1234-1234-123456789abc'

        files = {
            'file': ('test_document.xml', io.BytesIO(sample_xml_content), 'application/xml')
        }
        data = {
            'kvnr': 'X110591068',
            'title': 'Test Document',
            'creation_time': '20230609115053',
            'entry_uuid': custom_uuid
        }

        response = client.post('/epa/3.0/documents', files=files, data=data, headers=auth_headers)

        assert response.status_code == 201
        json_response = response.json()
        assert json_response['document']['id'] == custom_uuid

    def test_upload_document_with_old_uuid(self, client, mock_send_document_to_epa, sample_xml_content, auth_headers):
        mock_send_document_to_epa.return_value = None

        old_uuid = 'urn:uuid:old-document-id'

        files = {
            'file': ('test_document.xml', io.BytesIO(sample_xml_content), 'application/xml')
        }
        data = {
            'kvnr': 'X110591068',
            'title': 'Updated Document',
            'creation_time': '20230609115053',
            'old_entry_uuid': old_uuid
        }

        response = client.post('/epa/3.0/documents', files=files, data=data, headers=auth_headers)

        assert response.status_code == 201

        call_args = mock_send_document_to_epa.call_args
        assert call_args[1]['metadata']['documentEntry']['old_entry_uuid'] == old_uuid

    def test_upload_document_missing_kvnr(self, client, sample_xml_content, auth_headers):
        files = {
            'file': ('test_document.xml', io.BytesIO(sample_xml_content), 'application/xml')
        }
        data = {
            'title': 'Test Document',
            'creation_time': '20230609115053'
        }

        response = client.post('/epa/3.0/documents', files=files, data=data, headers=auth_headers)

        assert response.status_code == 422

    def test_upload_document_missing_title(self, client, sample_xml_content, auth_headers):
        files = {
            'file': ('test_document.xml', io.BytesIO(sample_xml_content), 'application/xml')
        }
        data = {
            'kvnr': 'X110591068',
            'creation_time': '20230609115053'
        }

        response = client.post('/epa/3.0/documents', files=files, data=data, headers=auth_headers)

        assert response.status_code == 422

    def test_upload_document_missing_creation_time(self, client, sample_xml_content, auth_headers):
        files = {
            'file': ('test_document.xml', io.BytesIO(sample_xml_content), 'application/xml')
        }
        data = {
            'kvnr': 'X110591068',
            'title': 'Test Document'
        }

        response = client.post('/epa/3.0/documents', files=files, data=data, headers=auth_headers)

        assert response.status_code == 422

    def test_upload_document_missing_file(self, client, auth_headers):
        data = {
            'kvnr': 'X110591068',
            'title': 'Test Document',
            'creation_time': '20230609115053'
        }

        response = client.post('/epa/3.0/documents', data=data, headers=auth_headers)

        assert response.status_code == 422

    def test_upload_document_epa_service_error(self, client, mock_send_document_to_epa, sample_xml_content, auth_headers):
        mock_send_document_to_epa.side_effect = ValueError("ePA service error: Invalid document format")

        files = {
            'file': ('test_document.xml', io.BytesIO(sample_xml_content), 'application/xml')
        }
        data = {
            'kvnr': 'X110591068',
            'title': 'Test Document',
            'creation_time': '20230609115053'
        }

        response = client.post('/epa/3.0/documents', files=files, data=data, headers=auth_headers)

        assert response.status_code == 400
        json_response = response.json()
        assert 'detail' in json_response
        assert 'error' in json_response['detail']
        assert 'Invalid document format' in json_response['detail']['error']

    def test_upload_document_file_not_found_error(self, client, mock_send_document_to_epa, sample_xml_content, auth_headers):
        mock_send_document_to_epa.side_effect = FileNotFoundError("Document file not found")

        files = {
            'file': ('test_document.xml', io.BytesIO(sample_xml_content), 'application/xml')
        }
        data = {
            'kvnr': 'X110591068',
            'title': 'Test Document',
            'creation_time': '20230609115053'
        }

        response = client.post('/epa/3.0/documents', files=files, data=data, headers=auth_headers)

        assert response.status_code == 400
        json_response = response.json()
        assert 'detail' in json_response
        assert 'error' in json_response['detail']
        assert 'not found' in json_response['detail']['error'].lower()

    def test_upload_document_unexpected_error(self, client, mock_send_document_to_epa, sample_xml_content, auth_headers):
        mock_send_document_to_epa.side_effect = Exception("Unexpected error occurred")

        files = {
            'file': ('test_document.xml', io.BytesIO(sample_xml_content), 'application/xml')
        }
        data = {
            'kvnr': 'X110591068',
            'title': 'Test Document',
            'creation_time': '20230609115053'
        }

        response = client.post('/epa/3.0/documents', files=files, data=data, headers=auth_headers)

        assert response.status_code == 400
        json_response = response.json()
        assert 'detail' in json_response
        assert 'error' in json_response['detail']

    @patch('app.main.sentry_sdk')
    def test_sentry_error_reporting(self, mock_sentry, client, mock_send_document_to_epa, sample_xml_content, auth_headers):
        error = ValueError("Test error for Sentry")
        mock_send_document_to_epa.side_effect = error

        files = {
            'file': ('test_document.xml', io.BytesIO(sample_xml_content), 'application/xml')
        }
        data = {
            'kvnr': 'X110591068',
            'title': 'Test Document',
            'creation_time': '20230609115053'
        }

        response = client.post('/epa/3.0/documents', files=files, data=data, headers=auth_headers)

        assert response.status_code == 400
        mock_sentry.capture_exception.assert_called_once_with(error)

    def test_upload_large_document(self, client, mock_send_document_to_epa, auth_headers):
        mock_send_document_to_epa.reset_mock()
        mock_send_document_to_epa.side_effect = None
        mock_send_document_to_epa.return_value = None

        large_content = b'<xml>' + b'x' * (1024 * 1024) + b'</xml>'

        files = {
            'file': ('large_document.xml', io.BytesIO(large_content), 'application/xml')
        }
        data = {
            'kvnr': 'X110591068',
            'title': 'Large Document',
            'creation_time': '20230609115053'
        }

        response = client.post('/epa/3.0/documents', files=files, data=data, headers=auth_headers)

        assert response.status_code == 201

    def test_upload_multiple_documents_sequentially(self, client, mock_send_document_to_epa, sample_xml_content, auth_headers):
        mock_send_document_to_epa.reset_mock()
        mock_send_document_to_epa.side_effect = None
        mock_send_document_to_epa.return_value = None

        for i in range(3):
            files = {
                'file': (f'test_document_{i}.xml', io.BytesIO(sample_xml_content), 'application/xml')
            }
            data = {
                'kvnr': 'X110591068',
                'title': f'Test Document {i}',
                'creation_time': '20230609115053'
            }

            response = client.post('/epa/3.0/documents', files=files, data=data, headers=auth_headers)

            assert response.status_code == 201

        assert mock_send_document_to_epa.call_count == 3

    def test_upload_document_special_characters_in_title(self, client, mock_send_document_to_epa, sample_xml_content, auth_headers):
        mock_send_document_to_epa.reset_mock()
        mock_send_document_to_epa.side_effect = None
        mock_send_document_to_epa.return_value = None

        files = {
            'file': ('test_document.xml', io.BytesIO(sample_xml_content), 'application/xml')
        }
        data = {
            'kvnr': 'X110591068',
            'title': 'Test Document with äöü & special <chars>',
            'creation_time': '20230609115053'
        }

        response = client.post('/epa/3.0/documents', files=files, data=data, headers=auth_headers)

        assert response.status_code == 201

        call_args = mock_send_document_to_epa.call_args
        assert call_args[1]['metadata']['documentEntry']['title'] == 'Test Document with äöü & special <chars>'

    def test_upload_document_without_auth(self, client, sample_xml_content):
        """Test that requests without authentication are rejected"""
        files = {
            'file': ('test_document.xml', io.BytesIO(sample_xml_content), 'application/xml')
        }
        data = {
            'kvnr': 'X110591068',
            'title': 'Test Document',
            'creation_time': '20230609115053'
        }

        response = client.post('/epa/3.0/documents', files=files, data=data)

        assert response.status_code == 401
        assert response.json()['detail'] == 'Not authenticated'

    def test_upload_document_with_invalid_credentials(self, client, sample_xml_content):
        """Test that requests with invalid credentials are rejected"""
        import base64
        invalid_credentials = base64.b64encode(b"wrong:password").decode("ascii")
        invalid_auth_headers = {"Authorization": f"Basic {invalid_credentials}"}

        files = {
            'file': ('test_document.xml', io.BytesIO(sample_xml_content), 'application/xml')
        }
        data = {
            'kvnr': 'X110591068',
            'title': 'Test Document',
            'creation_time': '20230609115053'
        }

        response = client.post('/epa/3.0/documents', files=files, data=data, headers=invalid_auth_headers)

        assert response.status_code == 401
        assert response.json()['detail'] == 'Invalid credentials'
