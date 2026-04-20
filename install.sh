# install.sh  (Linux/Mac)
#!/bin/bash
echo "Installing YARA-Sleuth dependencies..."
pip install yara-python colorama tabulate
echo "Done! Run: python3 yara_sleuth.py --target ./sample_files"