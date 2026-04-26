Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Python Requirements Setup (PowerShell)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

try {
    $pythonVersion = python --version
    Write-Host "[INFO] Found $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Python is not installed or not in PATH." -ForegroundColor Red
    exit 1
}

Write-Host "[INFO] Updating pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip

$commonReqs = @(
    "yara-python", "pefile", "watchdog", "pyzipper", 
    "psutil", "requests", "python-dotenv", 
    "scikit-learn", "numpy", "joblib", "flask"
)

Write-Host "[INFO] Installing common packages..." -ForegroundColor Yellow
foreach ($pkg in $commonReqs) {
    Write-Host "Installing $pkg..."
    python -m pip install $pkg
}

if ($IsWindows) {
    Write-Host "[INFO] Detected Windows. Installing specific packages..." -ForegroundColor Cyan
    python -m pip install python-magic-bin pywin32
} else {
    Write-Host "[INFO] Detected Non-Windows (Linux/macOS). Installing specific packages..." -ForegroundColor Cyan
    python -m pip install python-magic
}

if ($LASTEXITCODE -eq 0) {
    Write-Host "[SUCCESS] All requirements installed successfully!" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Some packages failed to install." -ForegroundColor Red
}
