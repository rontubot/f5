#!/bin/bash
# ==============================================================================
# Script: backup_ucs.sh
# Purpose: Generate automatic UCS backups and keep only the latest 5.
# Target: F5 BIG-IP (v17.5.1.6 compatible)
# Path on F5: /shared/scripts/backup_ucs.sh
# ==============================================================================

# Configuration
BACKUP_DIR="/var/local/ucs"
PREFIX="auto_backup_"
MAX_BACKUPS=5
LOG_TAG="F5_AUTO_BACKUP"

# Function to log messages to syslog and stdout
log_message() {
    local level=$1
    local msg=$2
    echo "[$level] $msg"
    logger -p "local0.${level}" -t "${LOG_TAG}" "$msg"
}

log_message "info" "Starting automatic UCS backup process."

# 1. Ensure backup directory exists
if [ ! -d "$BACKUP_DIR" ]; then
    log_message "err" "Backup directory $BACKUP_DIR does not exist."
    exit 1
fi

# 2. Generate filename using hostname and timestamp
HOSTNAME=$(hostname)
if [ -z "$HOSTNAME" ]; then
    HOSTNAME="bigip"
fi
TIMESTAMP=$(date +%Y-%m-%d_%H%M%S)
FILENAME="${PREFIX}${HOSTNAME}_${TIMESTAMP}.ucs"
FILEPATH="${BACKUP_DIR}/${FILENAME}"

log_message "info" "Generating UCS backup: $FILENAME"

# 3. Save UCS using tmsh
# We run it using the full path of tmsh for execution safety in restricted cron/icall environments
/usr/bin/tmsh save /sys ucs "$FILEPATH" > /dev/null 2>&1
SAVE_STATUS=$?

if [ $SAVE_STATUS -ne 0 ]; then
    log_message "err" "Failed to save UCS backup to $FILEPATH (exit code: $SAVE_STATUS)"
    exit 1
fi

log_message "info" "UCS backup saved successfully."

# 4. Rotate old backups (Keep only the 5 most recent ones)
# Find all files matching the prefix and extension, sorted by modification time (oldest first)
# Read files into an array safely (works in bash 3.x and 4.x)
BACKUP_FILES=()
while IFS= read -r line; do
    if [ -n "$line" ]; then
        BACKUP_FILES+=("$line")
    fi
done < <(ls -1tr "${BACKUP_DIR}/${PREFIX}"*.ucs 2>/dev/null)

NUM_FILES=${#BACKUP_FILES[@]}

log_message "info" "Found $NUM_FILES automatic backups in $BACKUP_DIR."

if [ "$NUM_FILES" -gt "$MAX_BACKUPS" ]; then
    NUM_TO_DELETE=$((NUM_FILES - MAX_BACKUPS))
    log_message "info" "Max backups limit ($MAX_BACKUPS) exceeded. Deleting $NUM_TO_DELETE oldest backup(s)."
    
    for ((i=0; i<NUM_TO_DELETE; i++)); do
        FILE_TO_DELETE="${BACKUP_FILES[i]}"
        if [ -f "$FILE_TO_DELETE" ]; then
            log_message "info" "Deleting old backup: $FILE_TO_DELETE"
            rm -f "$FILE_TO_DELETE"
            if [ $? -ne 0 ]; then
                log_message "err" "Failed to delete $FILE_TO_DELETE"
            fi
        fi
    done
else
    log_message "info" "No cleanup required. Current backup count ($NUM_FILES) is within limit ($MAX_BACKUPS)."
fi

log_message "info" "Backup rotation finished."
