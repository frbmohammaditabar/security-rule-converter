#!/bin/bash
set -e

echo "[*] Running Security Rule Converter..."
python -m converter.main
echo "[+] Done! Check converted_rules/ folder."
