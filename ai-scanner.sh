#!/bin/bash
# AI Security Scanner - Shell Wrapper for macOS/Linux
# 
# Usage:
#   ./ai-scanner.sh -d /path/to/scan
#   ./ai-scanner.sh --watch --interval 60
#   ./ai-scanner.sh --ci -f json -o report.json
#
# Requirements:
#   - Python 3.8+
#   - No additional dependencies (uses only standard library)

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Detect Python
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    echo "Error: Python 3 is required but not found."
    echo "Install it with: brew install python3 (macOS) or apt-get install python3 (Linux)"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$($PYTHON_CMD -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_VERSION="3.8"
if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "Error: Python 3.8+ is required. Found: $PYTHON_VERSION"
    exit 1
fi

# Run the scanner
exec $PYTHON_CMD "$SCRIPT_DIR/ai-scanner.py "$@"
