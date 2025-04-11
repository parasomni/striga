#!/bin/bash
if [ -z "$1" ] || [ "$1" == "-h" ]; then
    echo "Search files for possible passwords in a directory."
    echo "Usage: $0 <directory>"
    exit 1
fi

FOLDER="$1"

RED=$(tput setaf 1)
RESET=$(tput sgr0)

echo "[+] Searching for 'password', 'passwd' and 'pwd' in: $FOLDER"

grep -RiI --color=always -E 'password|passwd|pwd' "$FOLDER" 2>/dev/null | \
    sed -E "s/(password|passwd|pwd)/${RED}\1${RESET}/g"
