#!/usr/bin/env python3
"""
ASR Rules Generator - Main Script
Converts input files to security rules (YARA, Sigma, etc.)
"""

import os
import json
import logging
from pathlib import Path
from rule_generator import RuleGenerator
from file_processor import FileProcessor

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('asr_generator.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class ASRGenerator:
    def __init__(self, input_dir: str, output_dir: str):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.rule_generator = RuleGenerator()
        self.file_processor = FileProcessor()
    
    def process_files(self):
        """Process all files in input directory"""
        if not self.input_dir.exists():
            raise FileNotFoundError(f"Input directory not found: {self.input_dir}")
        
        logger.info(f"Processing files from: {self.input_dir}")
        
        # Process each file
        for file_path in self.input_dir.glob('*'):
            if file_path.is_file():
                try:
                    self._process_single_file(file_path)
                except Exception as e:
                    logger.error(f"Error processing {file_path}: {e}")
    
    def _process_single_file(self, file_path: Path):
        """Process a single file and generate rules"""
        logger.info(f"Processing file: {file_path.name}")
        
        # Analyze file content
        analysis_result = self.file_processor.analyze_file(file_path)
        
        # Generate rules based on analysis
        rules = self.rule_generator.generate_rules(
            file_path.name,
            analysis_result,
            file_path
        )
        
        # Save rules
        self._save_rules(rules, file_path.stem)
    
    def _save_rules(self, rules: dict, base_name: str):
        """Save generated rules to output directory"""
        # Save YARA rules
        if rules.get('yara'):
            yara_path = self.output_dir / f"{base_name}_rules.yar"
            with open(yara_path, 'w', encoding='utf-8') as f:
                f.write(rules['yara'])
            logger.info(f"YARA rules saved: {yara_path}")
        
        # Save Sigma rules (optional)
        if rules.get('sigma'):
            sigma_path = self.output_dir / f"{base_name}_sigma.yml"
            with open(sigma_path, 'w', encoding='utf-8') as f:
                f.write(rules['sigma'])
            logger.info(f"Sigma rules saved: {sigma_path}")
        
        # Save metadata
        meta_path = self.output_dir / f"{base_name}_metadata.json"
        with open(meta_path, 'w', encoding='utf-8') as f:
            json.dump(rules.get('metadata', {}), f, indent=2)
        logger.info(f"Metadata saved: {meta_path}")

def main():
    """Main execution function"""
    try:
        # Configuration
        input_dir = "new_input_files"
        output_dir = "output_rules"
        
        # Initialize and run generator
        generator = ASRGenerator(input_dir, output_dir)
        generator.process_files()
        
        logger.info("Rule generation completed successfully!")
        
    except Exception as e:
        logger.error(f"Error in main execution: {e}")
        raise

if __name__ == "__main__":
    main()
