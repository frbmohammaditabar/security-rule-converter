# ASR Rules Generator Solution

## Description
A comprehensive security rule generator that converts various file types into YARA rules, Sigma rules, and metadata. Developed as a solution for ndaal's coding challenge.

## Features
- Converts text files to YARA rules with extracted indicators
- Generates Sigma rules for SIEM integration
- Creates comprehensive JSON metadata
- Includes complete quality assurance test suite
- Follows PEP8 standards and Python best practices
- Handles different file types (text, CSV) appropriately

## Technical Stack
- Python 3.12
- yara-python for rule compilation
- pytest for testing
- magic for file type detection

## Installation
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate    # Windows

# Install dependencies
pip install -r requirements.txt
Usage
Place input files in new_input_files/ directory

Run the main generator:


python run.py
Run quality assurance tests:


python test_rules.py
## Project Structure
text
asr_challenge/
├── main.py                 # Main application logic
├── rule_generator.py       # Rule generation engine
├── file_processor.py       # File analysis and processing
├── test_rules.py          # Comprehensive test suite
├── run.py                 # Execution script
├── requirements.txt       # Dependencies
├── README.md              # Documentation
├── new_input_files/       # Input files from ndaal
├── output_rules/          # Generated rules and metadata
└── test_cases/           # Positive/negative test cases

## Quality Assurance
The solution includes comprehensive tests:

YARA rule compilation validation

Metadata integrity checks

False positive testing

File coverage verification

Positive/Negative test cases

## Author
Fariba Mohammaditabar
Security Developer

## License
MIT License

## Contact
For questions about this solution, please contact the author.
