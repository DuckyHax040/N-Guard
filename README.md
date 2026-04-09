# 🛡️ N-Guard v1.0 Advanced EDR-Ready Malware Defense Toolkit

**N-Guard v1.0** is an enterprise-grade **Endpoint Detection and Response (EDR)** toolkit designed to protect Windows systems from modern cyber threats. It combines **static analysis**, **behavioral monitoring**, **machine learning**, **cloud intelligence**, and **real‑time response** to detect, analyze, and neutralize malware, ransomware, and network attacks.

> **⚠️ Important**   
> This tool is intended for **security professionals**, **system administrators**, and **researchers**. It requires **administrator privileges** for full functionality (ETW, registry monitoring, firewall blocking).

---

## ✨ Key Features

| Category | Features |
|----------|----------|
| **🔍 Static Analysis** | – Hash calculation (MD5, SHA1, SHA256)<br>– File type detection via magic bytes<br>– Deep PE analysis (suspicious imports, entropy, packers, entry point anomalies, timestamp checks)<br>– String extraction (with size limits) & heuristic pattern matching (URLs, PowerShell, base64, ransomware keywords)<br>– **YARA rule scanning** (hot‑reload support) |
| **🧠 Machine Learning** | – Random Forest classifier trained on file features (size, entropy, suspicious imports, packed status, digital signature)<br>– Real‑time probability scoring integrated into threat scoring engine |
| **☁️ Cloud Intelligence** | – **VirusTotal** hash lookup (with optional file upload, size‑limited to 32 MB)<br>– **AbuseIPDB** IP reputation check for outbound connections |
| **📊 Behavioral Monitoring** | – **File system** (watchdog) – monitors file creation/modification in watched directories<br>– **Process** (psutil) – detects new processes, network connections, file access, suspicious command lines<br>– **Network** – detects port scans (SYN‑sent tracking) and automatically blocks offending IPs via Windows Firewall<br>– **ETW (Windows)** – monitors security events (process creation) – needs admin<br>– **Registry** – monitors persistence locations (Run, RunOnce, Services) |
| **⚖️ Threat Scoring** | Weighted scoring from all detectors, producing a verdict:<br>– **CLEAN** (0‑4)<br>– **SUSPICIOUS** (5‑9)<br>– **MALICIOUS** (10‑14)<br>– **CRITICAL** (15+) |
| **🚨 Response Actions** | – Automatic **quarantine** (AES‑256 encrypted ZIP with password)<br>– **Sandbox execution** via Sandboxie‑Plus (if installed)<br>– **Process termination** (whitelist‑protected)<br>– Interactive prompts for user decisions<br>– All events logged to **SQLite** database and shown in **real‑time web dashboard** |
| **🌐 Web Dashboard** | Built with **Flask** – live alerts, system stats, easy monitoring at `http://localhost:5000` |

---

## 📦 Requirements

- **Python 3.8+**
- **Windows** (for full EDR capabilities; some features work on Linux, but ETW, registry, and firewall blocking are Windows‑only)
- **Administrator privileges** (for ETW, firewall blocking, and some registry monitoring)

### Python Libraries

Install all dependencies with `pip` (see [Installation](#installation)):

```
yara-python, requests, pefile, psutil, watchdog, python-magic, python-dotenv,
pyzipper, joblib, scikit-learn, numpy, flask, pywin32
```

---

## 🔧 Installation

### 1. Clone the repository

```bash
git clone https://github.com/DuckyHax040/N-Guard.git
cd N-Guard
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv venv
venv\Scripts\activate   # On Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

If `requirements.txt` is not provided, install manually:

```bash
pip install yara-python requests pefile psutil watchdog python-magic python-dotenv pyzipper joblib scikit-learn numpy flask pywin32
```

> **Note for `python-magic` on Windows**:  
> Install `python-magic-bin` instead:  
> `pip install python-magic-bin`

---

## ⚙️ Configuration

### API Keys (optional but recommended)

Create a `.env` file in the project root:

```ini
VT_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
```

- **VirusTotal API key**: Get one from [virustotal.com](https://www.virustotal.com) (free tier available).
- **AbuseIPDB API key**: Register at [abuseipdb.com](https://www.abuseipdb.com).

If no keys are provided, cloud features will be disabled.

### YARA Rules

Place your YARA rule files (`.yar` or `.yara`) inside the `rules/` directory. The tool automatically loads all rules and **hot‑reloads** them when changes are detected.

Example rules are provided in the repository.

### Monitored Directories

By default, the tool monitors its own base directory. You can change this by editing `Config.MONITORED_DIRS` in the code or by adding your own configuration mechanism (not yet exposed via CLI).

---

## 🚀 Usage

N-Guard v1.0provides three operation modes:

### 1️⃣ Interactive CLI

Run the tool without arguments to enter an interactive menu:

```bash
python n-guard.py
```

You will see:
```
Options:
1. Scan file
2. Scan directory
3. Start monitoring
4. Show recent alerts
5. Exit
```

### 2️⃣ Command‑line scanning

```bash
# Scan a single file
python n-guard.py scan path/to/file.exe

# Scan all files in a directory recursively
python n-guard.py scan path/to/directory
```

### 3️⃣ Real‑time monitoring

```bash
python n-guard.py monitor
```

This starts all enabled monitors (file, process, network, ETW, registry). The web dashboard becomes available at [http://localhost:5000](http://localhost:5000). Press `Ctrl+C` to stop.

---

## 🌐 Web Dashboard

When monitoring mode is active, open your browser and go to `http://localhost:5000`. The dashboard shows:

- **Recent alerts** with timestamp, source, target, score, and verdict.
- **System statistics** (number of processes, CPU, memory usage).

The dashboard auto‑refreshes every 2 seconds.

---

## 📁 Project Structure

```
N-Guard/
├── n-guard.py          # Main application
├── .env                    # API keys (create this file)
├── requirements.txt        # Python dependencies
├── rules/                  # YARA rules directory (hot‑reload enabled)
├── quarantine/             # Quarantined files (AES‑encrypted ZIPs)
├── logs/                   # Log files (N-Guard v1.0.log)
├── db/                     # SQLite database (reputation.db)
└── models/                 # ML model storage (classifier.pkl)
```

---

## 🧪 Example Walkthrough

1. **First scan** of `suspicious.exe`:
   - Hashes calculated.
   - YARA matches detected → score +3.
   - PE analysis shows packed section → score +2.
   - VT lookup returns "Not found", user prompted to upload.
   - Total score = 5 → **SUSPICIOUS**.
   - User chooses to quarantine.

2. **Second scan** of the same file (after quarantine):
   - Cache hit: file already in database with score 5 → result returned instantly.

3. **Monitoring mode**:
   - A new file `malware.exe` is created in the watched directory.
   - FileMonitorHandler triggers a scan.
   - ProcessMonitor detects a new process connecting to a suspicious IP.
   - IP checked against AbuseIPDB → score 80 → alert generated.
   - Firewall rule added to block that IP.

---

## 🛠 Advanced Topics

### Customizing Scoring Weights

Edit the `SCORE_*` constants in the `Config` class inside `n-guard.py`.

### Adding New Detectors

The tool is designed with extensibility in mind. You can add new monitoring or analysis classes and integrate them into `N-Guard v1.0Core`.

### Running as a Windows Service

To run N-Guard v1.0as a background service, you can use **NSSM** (Non‑Sucking Service Manager) or wrap it with `pythonw.exe` and a batch script.

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/amazing-feature`).
3. Commit your changes (`git commit -m 'Add some amazing feature'`).
4. Push to the branch (`git push origin feature/amazing-feature`).
5. Open a Pull Request.

---

## 📄 License

This project is licensed under the MIT License.  
You can view the full license here: https://github.com/DuckyHax040/N-Guard/blob/main/LICENSE.md

---

## ⚠️ Disclaimer

**N-Guard v1.0 Pro** is provided for educational and defensive purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before monitoring or scanning systems you do not own.

---

## 📬 Contact

If you have any questions, suggestions, or encounter issues, feel free to open an issue on GitHub or reach out to the maintainer on Telegram: https://t.me/hovercs

---

**Stay safe. Stay secure.** 🛡️
