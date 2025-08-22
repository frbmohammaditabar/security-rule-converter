# Security Rule Converter

This project converts files from `new_input_files/` into multiple 
security-related rule formats (e.g., YARA and Sigma).

## 🚀 How to Run

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the converter
python -m converter.main


Output will be saved into the converted_rules/ folder.

🧪 Testing
pytest -v

🛠️ Notes
Currently supports YARA and Sigma rule generation.

Easily extendable to other formats (e.g., Snort, Suricata).

Code follows PEP8 best practices.
