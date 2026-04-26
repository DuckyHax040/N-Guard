@echo off
SETLOCAL EnableDelayedExpansion

echo ==========================================
echo Python Requirements Setup for Windows
echo ==========================================

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python and try again.
    pause
    exit /b 1
)

echo [INFO] Updating pip...
python -m pip install --upgrade pip

echo [INFO] Installing requirements...

set "reqs=yara-python pefile watchdog pyzipper psutil requests python-dotenv scikit-learn numpy joblib flask"

set "win_reqs=python-magic-bin pywin32"

echo [INFO] Installing common packages: %reqs%
python -m pip install %reqs%

echo [INFO] Installing Windows specific packages: %win_reqs%
python -m pip install %win_reqs%

if %errorlevel% equ 0 (
    echo [SUCCESS] All requirements installed successfully!
) else (
    echo [ERROR] Some packages failed to install.
)

pause
