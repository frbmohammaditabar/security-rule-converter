#!/usr/bin/env python3
"""
Rule Generator - Fixed version
"""

import hashlib
import json
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

class RuleGenerator:
    def __init__(self):
        self.metadata = {
            "author": "Fariba Mohammaditabar",
            "created": datetime.now().isoformat(),
            "version": "1.0",
            "description": "Automatically generated security rules"
        }
    
    def generate_rules(self, filename: str, analysis: Dict[str, Any], file_path) -> Dict[str, str]:
        """Generate multiple security rules from file analysis"""
        file_hash = self._calculate_file_hash(file_path)
        
        # Handle different file types differently
        if filename.endswith('.csv'):
            return self._generate_rules_from_csv(filename, analysis, file_path, file_hash)
        else:
            return self._generate_rules_from_text(filename, analysis, file_path, file_hash)
    
    def _generate_rules_from_text(self, filename: str, analysis: Dict[str, Any], file_path, file_hash: str) -> Dict[str, str]:
        """Generate rules from text files"""
        try:
            # Read file content to extract patterns
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Extract potential indicators from content
            indicators = self._extract_indicators_from_content(content)
            
            return {
                'yara': self._generate_yara_rule(filename, analysis, file_hash, indicators),
                'sigma': self._generate_sigma_rule(filename, analysis, file_hash),
                'metadata': self._generate_metadata(filename, analysis, file_hash, indicators)
            }
        except Exception as e:
            print(f"Error processing text file {filename}: {e}")
            return self._generate_basic_rules(filename, analysis, file_hash)
    
    def _generate_rules_from_csv(self, filename: str, analysis: Dict[str, Any], file_path, file_hash: str) -> Dict[str, str]:
        """Generate rules from CSV files"""
        try:
            return {
                'yara': self._generate_csv_yara_rule(filename, file_hash),
                'sigma': self._generate_sigma_rule(filename, analysis, file_hash),
                'metadata': self._generate_metadata(filename, analysis, file_hash, [])
            }
        except Exception as e:
            print(f"Error processing CSV file {filename}: {e}")
            return self._generate_basic_rules(filename, analysis, file_hash)
    
    def _generate_basic_rules(self, filename: str, analysis: Dict[str, Any], file_hash: str) -> Dict[str, str]:
        """Generate basic rules as fallback"""
        return {
            'yara': self._generate_basic_yara_rule(filename, file_hash),
            'sigma': self._generate_sigma_rule(filename, analysis, file_hash),
            'metadata': self._generate_metadata(filename, analysis, file_hash, [])
        }
    
    def _extract_indicators_from_content(self, content: str) -> list:
        """Extract potential indicators from file content"""
        indicators = []
        
        # Simple pattern matching for common IOCs
        patterns = [
            ('http://', 'URL'),
            ('https://', 'URL'),
            ('.exe', 'Executable'),
            ('.dll', 'Library'),
            ('malware', 'Malware reference'),
            ('virus', 'Virus reference'),
            ('trojan', 'Trojan reference'),
            ('backdoor', 'Backdoor reference'),
            ('adware', 'Adware reference'),
            ('spyware', 'Spyware reference')
        ]
        
        for pattern, indicator_type in patterns:
            if pattern in content.lower():
                indicators.append(f"{indicator_type}: {pattern}")
        
        return indicators[:5]  # Limit to 5 indicators
    
    def _generate_yara_rule(self, filename: str, analysis: Dict[str, Any], file_hash: str, indicators: list) -> str:
        """Generate YARA rule from file analysis"""
        rule_name = f"Rule_{filename.replace('.', '_').replace(' ', '_')}"
        
        # Create strings section based on indicators
        strings_section = self._create_strings_section(filename, file_hash, indicators)
        
        yara_rule = f"""rule {rule_name}
{{
    meta:
        author = "{self.metadata['author']}"
        date = "{self.metadata['created']}"
        description = "Generated from {filename}"
        file_type = "{analysis.get('file_type', 'unknown')}"
        file_size = {analysis.get('file_size', 0)}
        md5 = "{file_hash}"

    strings:
{strings_section}
        
    condition:
        any of them
}}
"""
        return yara_rule
    
    def _create_strings_section(self, filename: str, file_hash: str, indicators: list) -> str:
        """Create the strings section for YARA rule"""
        strings = []
        
        # Add filename as string
        strings.append(f'        $file_name = "{filename}" wide ascii')
        
        # Add file hash
        strings.append(f'        $hash = "{file_hash}"')
        
        # Add indicators from content
        for i, indicator in enumerate(indicators[:3]):  # Limit to 3 indicators
            indicator_text = indicator.split(':')[-1].strip()
            strings.append(f'        $indicator_{i+1} = "{indicator_text}" nocase')
        
        return '\n'.join(strings)
    
    def _generate_csv_yara_rule(self, filename: str, file_hash: str) -> str:
        """Generate basic YARA rule for CSV files"""
        rule_name = f"CSV_Rule_{filename.replace('.', '_').replace(' ', '_')}"
        
        return f"""rule {rule_name}
{{
    meta:
        author = "{self.metadata['author']}"
        date = "{self.metadata['created']}"
        description = "Basic rule for CSV file: {filename}"
        file_type = "text/csv"

    strings:
        $file_name = "{filename}" wide ascii
        $hash = "{file_hash}"
        
    condition:
        any of them
}}
"""
    
    def _generate_basic_yara_rule(self, filename: str, file_hash: str) -> str:
        """Generate basic YARA rule as fallback"""
        rule_name = f"Basic_Rule_{filename.replace('.', '_').replace(' ', '_')}"
        
        return f"""rule {rule_name}
{{
    meta:
        author = "{self.metadata['author']}"
        date = "{self.metadata['created']}"
        description = "Basic rule for {filename}"

    strings:
        $file_name = "{filename}" wide ascii
        $hash = "{file_hash}"
        
    condition:
        any of them
}}
"""
    
    def _generate_sigma_rule(self, filename: str, analysis: Dict[str, Any], file_hash: str) -> str:
        """Generate Sigma rule"""
        sigma_rule = f"""title: Suspicious File - {filename}
id: {hashlib.md5(filename.encode()).hexdigest()}
status: experimental
description: Detects presence of {filename}
author: {self.metadata['author']}
date: {self.metadata['created']}
logsource:
    category: file_event
detection:
    selection:
        FileName|endswith: '{filename}'
    condition: selection
falsepositives:
    - Unknown
level: medium
"""
        return sigma_rule
    
    def _generate_metadata(self, filename: str, analysis: Dict[str, Any], file_hash: str, indicators: list) -> Dict[str, Any]:
        """Generate metadata for the rules"""
        return {
            **self.metadata,
            "source_file": filename,
            "file_size": analysis.get('file_size', 0),
            "file_type": analysis.get('file_type', 'unknown'),
            "analysis_date": datetime.now().isoformat(),
            "file_hash": file_hash,
            "indicators_found": indicators,
            "status": "generated"
        }
    
    def _calculate_file_hash(self, file_path) -> str:
        """Calculate MD5 hash of file"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except:
            return "hash_calculation_failed"
