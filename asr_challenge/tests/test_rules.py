import pytest
import yara
from pathlib import Path
from src.rule_generator import RuleGenerator
from src.file_processor import FileProcessor

class TestRuleGeneration:
    def setup_method(self):
        self.rule_generator = RuleGenerator()
        self.file_processor = FileProcessor()
        self.test_dir = Path("tests/test_data")
    
    def test_yara_rule_compilation(self):
        """Test that generated YARA rules compile correctly"""
        # Create a simple test file
        test_file = self.test_dir / "positive" / "test_file.txt"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(test_file, 'w') as f:
            f.write("test content for rule generation")
        
        # Generate rules
        analysis = self.file_processor.analyze_file(test_file)
        rules = self.rule_generator.generate_rules("test_file.txt", analysis, test_file)
        
        # Test that YARA rule compiles
        try:
            compiled_rule = yara.compile(source=rules['yara'])
            assert compiled_rule is not None
        except yara.SyntaxError as e:
            pytest.fail(f"YARA rule compilation failed: {e}")
    
    def test_rule_matches_positive(self):
        """Test that rules match positive cases"""
        test_file = self.test_dir / "positive" / "malicious.exe"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Create a test file with specific content
        with open(test_file, 'wb') as f:
            f.write(b"malicious content http://bad.com/test.exe")
        
        analysis = self.file_processor.analyze_file(test_file)
        rules = self.rule_generator.generate_rules("malicious.exe", analysis, test_file)
        
        # Compile and test the rule
        compiled_rule = yara.compile(source=rules['yara'])
        matches = compiled_rule.match(str(test_file))
        
        assert len(matches) > 0, "Rule should match malicious file"
    
    def test_rule_no_false_positive(self):
        """Test that rules don't produce false positives"""
        clean_file = self.test_dir / "negative" / "clean_file.txt"
        clean_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(clean_file, 'w') as f:
            f.write("normal system file content")
        
        analysis = self.file_processor.analyze_file(clean_file)
        rules = self.rule_generator.generate_rules("clean_file.txt", analysis, clean_file)
        
        compiled_rule = yara.compile(source=rules['yara'])
        matches = compiled_rule.match(str(clean_file))
        
        assert len(matches) == 0, "Rule should not match clean file"
