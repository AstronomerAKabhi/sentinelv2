#!/bin/bash
PYTHON_BIN="/opt/homebrew/Caskroom/miniconda/base/bin/python3"
CLI_SCRIPT="$HOME/sentinel_v2/cli_app/sentinel.py"

echo "=== TEST 1: URL SCAN ==="
"$PYTHON_BIN" "$CLI_SCRIPT" scan-url "http://phishing-test.com"

echo -e "\n=== TEST 2: FILE SCAN ==="
"$PYTHON_BIN" "$CLI_SCRIPT" scan-file "/etc/passwd"
