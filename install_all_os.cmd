:; echo "Detecting OS: Linux/macOS"
:; python3 -m pip install --upgrade pip
:; python3 -m pip install yara-python pefile watchdog pyzipper psutil requests python-dotenv scikit-learn numpy joblib flask python-magic
:; exit $?

@echo off
echo Detecting OS: Windows
python -m pip install --upgrade pip
python -m pip install yara-python pefile watchdog pyzipper psutil requests python-dotenv scikit-learn numpy joblib flask python-magic-bin pywin32
pause
