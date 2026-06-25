#!/bin/bash
# ==============================================================================
# Script: generate_qkview.sh
# Purpose: Generate F5 QKView diagnostics and upload to Transit Server API
# Target: F5 BIG-IP (v17.5.1.6 compatible)
# Path on F5: /shared/scripts/generate_qkview.sh
# ==============================================================================

# Configuration
TEMP_DIR="/var/tmp"
LOG_TAG="F5_DIAG_UPLOAD"
TRANSIT_API_URL="https://your-transit-server.com/api/upload"
TRANSIT_TOKEN="your_secure_transit_token"

log_message() {
    local level=$1
    local msg=$2
    echo "[$level] $msg"
    logger -p "local0.${level}" -t "${LOG_TAG}" "$msg"
}

log_message "info" "Starting QKView diagnostic generation."

# 1. Generate QKView
HOSTNAME=$(hostname)
if [ -z "$HOSTNAME" ]; then
    HOSTNAME="bigip"
fi
TIMESTAMP=$(date +%Y-%m-%d_%H%M%S)
FILENAME="${HOSTNAME}_${TIMESTAMP}.qkview"
FILEPATH="${TEMP_DIR}/${FILENAME}"

log_message "info" "Generating QKView archive: $FILENAME"

# Run F5 QKView utility
# -f specifies output file
/usr/bin/qkview -f "$FILEPATH" > /dev/null 2>&1
STATUS=$?

if [ $STATUS -ne 0 ]; then
    log_message "err" "Failed to generate QKView (exit code: $STATUS)"
    exit 1
fi

log_message "info" "QKView generated successfully at $FILEPATH. File size: $(du -sh "$FILEPATH" | cut -f1)"

# 2. Upload to Transit Server API
log_message "info" "Uploading QKView to Transit Server at $TRANSIT_API_URL..."

# Upload using curl POST
# Using full path for curl
/usr/bin/curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "Authorization: Bearer $TRANSIT_TOKEN" \
  -F "file=@$FILEPATH" \
  "$TRANSIT_API_URL" > /var/tmp/upload_status.txt

HTTP_CODE=$(cat /var/tmp/upload_status.txt)
rm -f /var/tmp/upload_status.txt

if [ "$HTTP_CODE" -eq 200 ] || [ "$HTTP_CODE" -eq 201 ]; then
    log_message "info" "QKView uploaded successfully to Transit Server (HTTP $HTTP_CODE)."
else
    log_message "err" "Failed to upload QKView. Transit Server responded with HTTP code $HTTP_CODE."
fi

# 3. Cleanup local QKView file to prevent filling up storage
log_message "info" "Cleaning up local QKView archive..."
rm -f "$FILEPATH"

log_message "info" "Diagnostic process finished."
