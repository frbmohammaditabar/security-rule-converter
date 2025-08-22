#!/usr/bin/env python3
"""
Security Rule Converter
=======================

Converts files from 'new_input_files/' into multiple security rule formats
(e.g., YARA, Sigma).

Author: Fariba Mohammaditabar
"""

import re
from pathlib import Path

INPUT_DIR = Path("new_input_files")
OUTPUT_DIR = Path("converted_rules")

OUTPUT_DIR.mkdir(exist_ok=True)


def load_input_files():
    """Load all files from the input directory"""
    files = []
    for file in INPUT_DIR.glob("*"):
        if file.is_file():
            with open(file, "r", encoding="utf-8") as f:
                files.append((file.stem, f.read()))
    return files


def convert_to_yara(filename: str, content: str) -> str:
    """Convert file content into a simple YARA rule"""
    rule_name = re.sub(r'\W+', '_', filename)
    snippet = content[:20].replace('"', '\\"')
    yara_rule = f"""
rule {rule_name}
{{
    strings:
        $a = "{snippet}"
    condition:
        $a
}}
"""
    return yara_rule.strip()


def convert_to_sigma(filename: str, content: str) -> str:
    """Convert file content into a very basic Sigma rule"""
    rule_name = re.sub(r'\W+', '_', filename)
    sigma_rule = f"""
title: Detect {rule_name}
id: {rule_name}-rule
status: experimental
description: Auto-generated Sigma rule
logsource:
  category: file_event
detection:
  keywords:
    - "{content[:20]}"
  condition: keywords
level: medium
"""
    return sigma_rule.strip()


def save_rule(rule_text: str, filename: str, extension: str):
    """Save rule text into the output directory"""
    out_file = OUTPUT_DIR / f"{filename}.{extension}"
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(rule_text)
    return out_file


def main():
    files = load_input_files()
    for fname, content in files:
        yara_rule = convert_to_yara(fname, content)
        sigma_rule = convert_to_sigma(fname, content)

        save_rule(yara_rule, fname, "yara")
        save_rule(sigma_rule, fname, "yaml")

    print(f"Converted {len(files)} files into security rules.")


if __name__ == "__main__":
    main()
