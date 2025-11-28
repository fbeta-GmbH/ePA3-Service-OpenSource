#!/bin/bash

set -e

API_URL="${API_URL:-http://localhost:8000}"
KVNR="${KVNR:-X110591068}"
TITLE="${TITLE:-Test Document}"
CREATION_TIME="${CREATION_TIME:-$(date +%Y%m%d%H%M%S)}"
DOCUMENT_FILE="${DOCUMENT_FILE:-}"

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Upload a document to ePA 3.0 service

OPTIONS:
    -h, --help              Show this help message
    -u, --url URL          API URL (default: http://localhost:8000)
    -k, --kvnr KVNR        Patient insurance number (default: X110591068)
    -t, --title TITLE      Document title (default: Test Document)
    -c, --creation-time    Creation time in YYYYMMDDHHMMSS format (default: current time)
    -f, --file FILE        Path to document file (required)
    -e, --entry-uuid UUID  Optional: Document entry UUID
    -o, --old-uuid UUID    Optional: UUID of document to replace

ENVIRONMENT VARIABLES:
    API_URL                API endpoint URL
    KVNR                   Patient insurance number
    TITLE                  Document title
    CREATION_TIME          Document creation time
    DOCUMENT_FILE          Path to document file

EXAMPLES:
    # Basic upload
    $0 -f mydocument.xml

    # Upload with custom title and KVNR
    $0 -f mydocument.xml -k X110591068 -t "Medical Report"

    # Upload to replace existing document
    $0 -f mydocument.xml -o "urn:uuid:old-document-id"

    # Upload using environment variables
    export KVNR=X110591068
    export DOCUMENT_FILE=mydocument.xml
    $0
EOF
}

ENTRY_UUID=""
OLD_UUID=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -u|--url)
            API_URL="$2"
            shift 2
            ;;
        -k|--kvnr)
            KVNR="$2"
            shift 2
            ;;
        -t|--title)
            TITLE="$2"
            shift 2
            ;;
        -c|--creation-time)
            CREATION_TIME="$2"
            shift 2
            ;;
        -f|--file)
            DOCUMENT_FILE="$2"
            shift 2
            ;;
        -e|--entry-uuid)
            ENTRY_UUID="$2"
            shift 2
            ;;
        -o|--old-uuid)
            OLD_UUID="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

if [ -z "$DOCUMENT_FILE" ]; then
    echo "Error: Document file is required"
    echo ""
    usage
    exit 1
fi

if [ ! -f "$DOCUMENT_FILE" ]; then
    echo "Error: File not found: $DOCUMENT_FILE"
    exit 1
fi

echo "Uploading document to ePA..."
echo "  API URL: $API_URL"
echo "  KVNR: $KVNR"
echo "  Title: $TITLE"
echo "  Creation Time: $CREATION_TIME"
echo "  File: $DOCUMENT_FILE"

CURL_ARGS=(
    -X POST
    "$API_URL/epa/3.0/documents"
    -F "kvnr=$KVNR"
    -F "title=$TITLE"
    -F "creation_time=$CREATION_TIME"
    -F "file=@$DOCUMENT_FILE"
)

if [ -n "$ENTRY_UUID" ]; then
    CURL_ARGS+=(-F "entry_uuid=$ENTRY_UUID")
    echo "  Entry UUID: $ENTRY_UUID"
fi

if [ -n "$OLD_UUID" ]; then
    CURL_ARGS+=(-F "old_entry_uuid=$OLD_UUID")
    echo "  Old UUID (replacing): $OLD_UUID"
fi

echo ""
echo "Sending request..."

RESPONSE=$(curl -s -w "\n%{http_code}" "${CURL_ARGS[@]}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo ""
echo "Response (HTTP $HTTP_CODE):"
echo "$BODY" | jq '.' 2>/dev/null || echo "$BODY"

if [ "$HTTP_CODE" = "201" ]; then
    echo ""
    echo "✓ Document uploaded successfully!"
    exit 0
else
    echo ""
    echo "✗ Upload failed with HTTP $HTTP_CODE"
    exit 1
fi
