#!/usr/bin/env python3
"""
Main execution script for ASR Rules Generator
"""

import sys
from main import main

if __name__ == "__main__":
    try:
        main()
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
