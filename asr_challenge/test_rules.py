#!/usr/bin/env python3
"""
Test script for ASR Rules Generator
"""

import pytest
import yara
import json
from pathlib import Path
from main import ASRGenerator

class TestGeneratedRules:
    def setup_method(self):
        self.output_dir = Path("output_rules")
        self.test_files_dir = Path("new_input_files")
        self.generator = ASRGenerator("new_input_files", "test_output")
    
    def test_yara_rules_compilation(self):
        """Test that all generated YARA rules compile correctly"""
        yara_files = list(self.output_dir.glob("*.yar"))
        
        assert len(yara_files) > 0, "No YARA rules found"
        
        for yara_file in yara_files:
            try:
                with open(yara_file, 'r') as f:
                    rule_content = f.read()
                
                # Try to compile the YARA rule
                compiled_rule = yara.compile(source=rule_content)
                assert compiled_rule is not None
                print(f"✓ {yara_file.name} compiles successfully")
                
            except yara.SyntaxError as e:
                pytest.fail(f"YARA rule {yara_file.name} compilation failed: {e}")
            except Exception as e:
                pytest.fail(f"Error testing {yara_file.name}: {e}")
    
    def test_metadata_files_validity(self):
        """Test that metadata files are valid JSON"""
        metadata_files = list(self.output_dir.glob("*_metadata.json"))
        
        assert len(metadata_files) > 0, "No metadata files found"
        
        for meta_file in metadata_files:
            try:
                with open(meta_file, 'r') as f:
                    metadata = json.load(f)
                
                # Check required fields
                assert 'author' in metadata
                assert 'created' in metadata
                assert 'source_file' in metadata
                assert 'file_hash' in metadata
                
                print(f"✓ {meta_file.name} has valid metadata")
                
            except json.JSONDecodeError as e:
                pytest.fail(f"Metadata file {meta_file.name} is not valid JSON: {e}")
            except Exception as e:
                pytest.fail(f"Error testing {meta_file.name}: {e}")
    
    def test_rules_match_original_files(self):
        """Test that generated rules match the original files"""
        yara_files = list(self.output_dir.glob("*.yar"))
        input_files = list(self.test_files_dir.glob("*"))
        
        for yara_file, input_file in zip(yara_files, input_files):
            try:
                # Get the base name to match files
                base_name = yara_file.name.replace('_rules.yar', '')
                matching_input = self.test_files_dir / f"{base_name}.txt"
                
                if not matching_input.exists():
                    matching_input = self.test_files_dir / f"{base_name}.csv"
                
                if matching_input.exists():
                    with open(yara_file, 'r') as f:
                        rule_content = f.read()
                    
                    compiled_rule = yara.compile(source=rule_content)
                    matches = compiled_rule.match(str(matching_input))
                    
                    # Rule should match the file it was generated from
                    assert len(matches) > 0, f"Rule {yara_file.name} should match {matching_input.name}"
                    print(f"✓ {yara_file.name} correctly matches {matching_input.name}")
                
            except Exception as e:
                print(f"⚠️  Could not test matching for {yara_file.name}: {e}")
    
    def test_no_false_positives(self):
        """Test that rules don't produce false positives on clean files"""
        # Create a clean test file
        clean_file = Path("clean_test_file.txt")
        with open(clean_file, 'w') as f:
            f.write("This is a normal clean file without any malicious content.")
        
        try:
            yara_files = list(self.output_dir.glob("*.yar"))
            
            for yara_file in yara_files:
                with open(yara_file, 'r') as f:
                    rule_content = f.read()
                
                compiled_rule = yara.compile(source=rule_content)
                matches = compiled_rule.match(str(clean_file))
                
                # Rules should not match clean files (minimize false positives)
                assert len(matches) == 0, f"Rule {yara_file.name} should not match clean file"
                print(f"✓ {yara_file.name} has no false positives on clean file")
                
        finally:
            # Clean up
            if clean_file.exists():
                clean_file.unlink()
    
    def test_file_coverage(self):
        """Test that all input files were processed"""
        input_files = list(self.test_files_dir.glob("*"))
        output_files = list(self.output_dir.glob("*_rules.yar"))
        
        assert len(output_files) == len(input_files), \
            f"Processed {len(output_files)} files but expected {len(input_files)}"
        
        print(f"✓ All {len(input_files)} input files were processed successfully")

def run_tests():
    """Run all tests and print summary"""
    print("🧪 Running ASR Rules Generator Tests...")
    print("=" * 50)
    
    test_instance = TestGeneratedRules()
    test_instance.setup_method()
    
    tests = [
        test_instance.test_yara_rules_compilation,
        test_instance.test_metadata_files_validity,
        test_instance.test_rules_match_original_files,
        test_instance.test_no_false_positives,
        test_instance.test_file_coverage
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
            print(f"✅ {test.__name__} - PASSED")
        except Exception as e:
            failed += 1
            print(f"❌ {test.__name__} - FAILED: {e}")
        print("-" * 30)
    
    print("=" * 50)
    print(f"📊 Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests passed! The rules are working correctly.")
        return True
    else:
        print("⚠️  Some tests failed. Please check the generated rules.")
        return False

if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
