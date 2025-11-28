# ePA 3.0 Document Upload Examples

This directory contains examples for using the ePA 3.0 Document Upload API.

## Table of Contents

- [Quick Start](#quick-start)
- [Upload Script](#upload-script)
- [API Documentation](#api-documentation)
- [Examples](#examples)

## Quick Start

### 1. Start the Service

Using Docker Compose:

```bash
# From the project root
docker-compose up --build
```

The API will be available at `http://localhost:8000`

View the interactive API documentation at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### 2. Upload a Document

```bash
cd examples
./upload.sh -f /path/to/your/document.xml
```

## Upload Script

The `upload.sh` script provides a convenient way to upload documents to the ePA service.

### Usage

```bash
./upload.sh [OPTIONS]
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-h, --help` | Show help message | - |
| `-u, --url URL` | API URL | `http://localhost:8000` |
| `-k, --kvnr KVNR` | Patient insurance number | `X110591068` |
| `-t, --title TITLE` | Document title | `Test Document` |
| `-c, --creation-time TIME` | Creation time (YYYYMMDDHHMMSS) | Current time |
| `-f, --file FILE` | Path to document file | **Required** |
| `-e, --entry-uuid UUID` | Document entry UUID | Auto-generated |
| `-o, --old-uuid UUID` | UUID of document to replace | - |

### Environment Variables

You can also configure the script using environment variables:

- `API_URL` - API endpoint URL
- `KVNR` - Patient insurance number
- `TITLE` - Document title
- `CREATION_TIME` - Document creation time
- `DOCUMENT_FILE` - Path to document file
- `ADMIN_USERNAME` - HTTP Basic Auth username (default: admin)
- `ADMIN_PASSWORD` - HTTP Basic Auth password (default: changeme)

## API Documentation

### Endpoint

**POST** `/epa/3.0/documents`

Upload a document to the ePA 3.0 service.

### Authentication

The API uses HTTP Basic Authentication. You must provide valid credentials in the request:

```bash
curl -u username:password ...
```

Default credentials (change these for production!):
- Username: `admin`
- Password: `changeme`

Set custom credentials using environment variables:
- `ADMIN_USERNAME` - Set the admin username
- `ADMIN_PASSWORD` - Set the admin password

### Request

**Content-Type:** `multipart/form-data`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `kvnr` | string | Yes | Patient insurance number (Krankenversichertennummer) |
| `title` | string | Yes | Document title |
| `creation_time` | string | Yes | Creation time in format `YYYYMMDDHHMMSS` |
| `file` | file | Yes | Document file to upload |
| `entry_uuid` | string | No | Unique document entry UUID (auto-generated if not provided) |
| `old_entry_uuid` | string | No | UUID of document to replace |

### Response

#### Success (201 Created)

```json
{
  "document": {
    "id": "urn:uuid:8b7a4223-ce93-49fa-9a9b-3ba2e55279ca"
  }
}
```

#### Error (400 Bad Request)

```json
{
  "error": "Error message describing what went wrong"
}
```

## Examples

### Example 1: Basic Upload

Upload a document with default settings:

```bash
./upload.sh -f ../app/data/REAL_EXAMPLE_1_KBV_PR_MIO_DIGA_Bundle.xml
```

### Example 2: Upload with Custom Title and KVNR

```bash
./upload.sh \
  -f mydocument.xml \
  -k X110591068 \
  -t "Medical Report - Blood Test Results"
```

### Example 3: Replace Existing Document

```bash
./upload.sh \
  -f updated_document.xml \
  -o "urn:uuid:old-document-uuid-here"
```

### Example 4: Upload with Custom Creation Time

```bash
./upload.sh \
  -f mydocument.xml \
  -c 20230609115053 \
  -t "Historical Document"
```

### Example 5: Using cURL Directly

```bash
curl -X POST http://localhost:8000/epa/3.0/documents \
  -F "kvnr=X110591068" \
  -F "title=Test Document" \
  -F "creation_time=$(date +%Y%m%d%H%M%S)" \
  -F "file=@mydocument.xml"
```

### Example 6: Using Environment Variables

```bash
export API_URL=http://localhost:8000
export KVNR=X110591068
export TITLE="Lab Results"
export DOCUMENT_FILE=lab_results.xml

./upload.sh
```

### Example 7: Upload to Remote Server

```bash
./upload.sh \
  -u https://epa.example.com \
  -f mydocument.xml \
  -k X110591068
```

## Testing

To verify the service is running:

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy"
}
```

## Error Handling

The API returns appropriate error messages for common issues:

- **Missing required fields**: Returns 422 validation error
- **File not found**: Returns 400 with error details
- **ePA upload failure**: Returns 400 with error message
- **Invalid KVNR format**: Returns 400 with validation error

All errors are automatically reported to Sentry if `SENTRY_DSN` is configured.

## Configuration

### Environment Variables

Make sure to configure your environment variables in `app/.env`:

```bash
# Required
EPA_ENVIRONMENT=RT
KONNEKTOR_URL=https://konnektor.ru.tiaas.rise-ti.de
DIGA_NAME=Your DiGA Name
DIGA_MANUFACTURER=Your Company
MANDANT_ID=your_mandant_id
CLIENT_SYSTEM_ID=your_client_system_id
WORKPLACE_ID=your_workplace_id

# Optional
SENTRY_DSN=https://your-sentry-dsn@sentry.io/project-id
DEFAULT_EPA_PROVIDER_ID=2
LOG_LEVEL=INFO
```

## Troubleshooting

### Issue: Connection refused

**Solution**: Make sure the service is running:
```bash
docker-compose up
```

### Issue: 400 Bad Request

**Solution**: Check the error message in the response. Common causes:
- Invalid KVNR format
- Missing required fields
- File format not supported
- ePA service configuration issues

### Issue: File upload fails

**Solution**:
- Verify the file exists and is readable
- Check file format (should be XML for ePA documents)
- Ensure file size is within limits

## Support

For issues or questions:
1. Check the API documentation at `http://localhost:8000/docs`
2. Review the logs: `docker-compose logs -f epa-service`
3. Verify environment configuration in `app/.env`
