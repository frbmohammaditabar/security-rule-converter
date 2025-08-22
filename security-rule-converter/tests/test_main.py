import pytest
from converter.main import convert_to_yara, convert_to_sigma


def test_yara_rule_format():
    content = "malicious_example_content_here"
    rule = convert_to_yara("testfile", content)
    assert "rule testfile" in rule
    assert "$a =" in rule
    assert content[:20] in rule


def test_sigma_rule_format():
    content = "another_malicious_payload"
    rule = convert_to_sigma("samplefile", content)
    assert "title: Detect samplefile" in rule
    assert content[:20] in rule
