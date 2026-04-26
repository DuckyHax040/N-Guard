#!/bin/bash

echo "=========================================="
echo "Python Requirements Setup for Linux"
echo "=========================================="

if ! command -v python3 &> /dev/null
then
    echo "[ERROR] Python3 could not be found. Please install it."
    exit 1
fi

echo "[INFO] Updating pip..."
python3 -m pip install --upgrade pip

COMMON_REQS="yara-python pefile watchdog pyzipper psutil requests python-dotenv scikit-learn numpy joblib flask"
LINUX_REQS="python-magic"

echo "[INFO] Installing common packages..."
python3 -m pip install $COMMON_REQS

echo "[INFO] Installing Linux specific packages..."
python3 -m pip install $LINUX_REQS

if [ $? -eq 0 ]; then
    echo "[SUCCESS] All requirements installed successfully!"
else
    echo "[ERROR] Some packages failed to install."
fi
