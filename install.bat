:: install.bat  (Windows)
@echo off
echo Installing YARA-Sleuth dependencies...

:: Try pre-built binary first
pip install yara-python --only-binary=:all:

:: If that fails, try specific version
if %errorlevel% neq 0 (
    echo Trying alternative install...
    pip install yara-python==4.3.1 --only-binary=:all:
)

pip install colorama tabulate
echo.
echo Installation complete! Run: python yara_sleuth.py --target ./sample_files
pause