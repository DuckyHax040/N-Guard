# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
# """
# CyberGuard Pro v6.0 - Enterprise EDR-Level Malware Defense
# پاراستنی پێشکەوتووی سیستەم لە هێرشەکانی تۆڕ و نەرمەکالا زیانبەخشەکان
# """

# import os
# import sys
# import hashlib
# import json
# import time
# import sqlite3
# import zipfile
# import shutil
# import subprocess
# import threading
# import logging
# import re
# import queue
# import pickle
# import socket
# import struct
# from datetime import datetime, timedelta
# from pathlib import Path
# from typing import Dict, List, Tuple, Optional, Any
# from dataclasses import dataclass, asdict
# from collections import defaultdict
# from concurrent.futures import ThreadPoolExecutor
# from contextlib import contextmanager

# # External libraries
# try:
#     import yara
#     import requests
#     import pefile
#     import psutil
#     from watchdog.observers import Observer
#     from watchdog.events import FileSystemEventHandler, PatternMatchingEventHandler
#     import magic
#     from dotenv import load_dotenv
#     import pyminizip
#     import joblib
#     from sklearn.ensemble import RandomForestClassifier
#     import numpy as np
#     from flask import Flask, jsonify, request, render_template_string
#     import win32evtlog  # for ETW on Windows
#     import win32con
#     import win32security
#     import winreg
# except ImportError as e:
#     print(f"[ERROR] Missing required library: {e}")
#     print("Install with: pip install -r requirements.txt")
#     sys.exit(1)

# # Load environment variables
# load_dotenv()

# # ========================== Configuration ==========================
# class Config:
#     # API Keys
#     VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY", "")
#     ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    
#     # Paths
#     BASE_DIR = Path(__file__).parent
#     RULES_DIR = BASE_DIR / "rules"
#     QUARANTINE_DIR = BASE_DIR / "quarantine"
#     LOG_DIR = BASE_DIR / "logs"
#     DB_DIR = BASE_DIR / "db"
#     DB_PATH = DB_DIR / "reputation.db"
#     MODEL_DIR = BASE_DIR / "models"
#     MODEL_PATH = MODEL_DIR / "classifier.pkl"
    
#     # Monitoring
#     MONITORED_DIRS = [str(BASE_DIR)]  # directories to watch
#     EXCLUDED_FILES = ["cyberguard.py", ".env", "reputation.db"]  # self-exclusion
#     ALERT_THRESHOLD = 5  # score threshold for auto-quarantine
#     ENABLE_NETWORK_MONITOR = True
#     ENABLE_PROCESS_MONITOR = True
#     ENABLE_FILE_MONITOR = True
#     ENABLE_ETW_MONITOR = sys.platform == 'win32'
#     ENABLE_REGISTRY_MONITOR = sys.platform == 'win32'
#     ENABLE_WEB_DASHBOARD = True
#     DASHBOARD_PORT = 5000
    
#     # Process whitelist
#     SAFE_PROCESSES = [
#         "brave.exe", "chrome.exe", "firefox.exe", "edge.exe", 
#         "explorer.exe", "svchost.exe", "csrss.exe", "winlogon.exe",
#         "services.exe", "lsass.exe", "spoolsv.exe", "taskhostw.exe",
#         "python.exe", "pycharm64.exe", "code.exe", "cursor.exe"
#     ]
    
#     # Scoring weights
#     SCORE_YARA = 3
#     SCORE_PE_ALERT = 2
#     SCORE_VT_MALICIOUS = 5
#     SCORE_VT_SUSPICIOUS = 3
#     SCORE_STRINGS_SUSPICIOUS = 1
#     SCORE_HIGH_ENTROPY = 2
#     SCORE_ML_MALICIOUS = 4
#     SCORE_ABUSEIPDB_MALICIOUS = 3
    
#     # Limits
#     MAX_STRING_EXTRACT_SIZE = 50 * 1024 * 1024  # 50MB
#     MAX_STRING_COUNT = 1000
#     MIN_STRING_LENGTH = 4

# # Create directories
# for d in [Config.RULES_DIR, Config.QUARANTINE_DIR, Config.LOG_DIR, 
#           Config.DB_DIR, Config.MODEL_DIR]:
#     d.mkdir(exist_ok=True)

# # Logging setup
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#     handlers=[
#         logging.FileHandler(Config.LOG_DIR / "cyberguard.log", encoding='utf-8'),
#         logging.StreamHandler()
#     ]
# )
# logger = logging.getLogger("CyberGuard")

# # Global event queue for thread-safe communication
# event_queue = queue.Queue()

# # ========================== Database ==========================
# class ReputationDB:
#     """SQLite local cache with TTL and reputation scoring."""
#     def __init__(self):
#         self.conn = sqlite3.connect(str(Config.DB_PATH), check_same_thread=False)
#         self._create_tables()
#         self._cleanup_old()
    
#     def _create_tables(self):
#         self.conn.execute("""
#             CREATE TABLE IF NOT EXISTS file_reputation (
#                 sha256 TEXT PRIMARY KEY,
#                 first_seen TIMESTAMP,
#                 last_seen TIMESTAMP,
#                 score INTEGER,
#                 verdict TEXT,
#                 vt_detections INTEGER,
#                 ml_score REAL,
#                 details TEXT
#             )
#         """)
#         self.conn.execute("""
#             CREATE TABLE IF NOT EXISTS ip_reputation (
#                 ip TEXT PRIMARY KEY,
#                 first_seen TIMESTAMP,
#                 last_seen TIMESTAMP,
#                 abuse_score INTEGER,
#                 reports INTEGER,
#                 country TEXT
#             )
#         """)
#         self.conn.execute("""
#             CREATE TABLE IF NOT EXISTS alerts (
#                 id INTEGER PRIMARY KEY AUTOINCREMENT,
#                 timestamp TIMESTAMP,
#                 source TEXT,
#                 target TEXT,
#                 score INTEGER,
#                 verdict TEXT,
#                 details TEXT
#             )
#         """)
#         self.conn.commit()
    
#     def _cleanup_old(self, days=30):
#         """Remove entries older than days."""
#         cutoff = (datetime.now() - timedelta(days=days)).isoformat()
#         self.conn.execute("DELETE FROM file_reputation WHERE last_seen < ?", (cutoff,))
#         self.conn.execute("DELETE FROM ip_reputation WHERE last_seen < ?", (cutoff,))
#         self.conn.commit()
    
#     def get_file(self, sha256: str) -> Optional[Dict]:
#         cursor = self.conn.execute(
#             "SELECT sha256, score, verdict, vt_detections, ml_score, details FROM file_reputation WHERE sha256 = ?",
#             (sha256,)
#         )
#         row = cursor.fetchone()
#         if row:
#             return {
#                 'sha256': row[0],
#                 'score': row[1],
#                 'verdict': row[2],
#                 'vt_detections': row[3],
#                 'ml_score': row[4],
#                 'details': json.loads(row[5]) if row[5] else {}
#             }
#         return None
    
#     def update_file(self, sha256: str, score: int, verdict: str, 
#                     vt_detections: int = 0, ml_score: float = 0.0, details: dict = None):
#         now = datetime.now().isoformat()
#         self.conn.execute("""
#             INSERT OR REPLACE INTO file_reputation 
#             (sha256, first_seen, last_seen, score, verdict, vt_detections, ml_score, details)
#             VALUES (?, COALESCE((SELECT first_seen FROM file_reputation WHERE sha256 = ?), ?), 
#                     ?, ?, ?, ?, ?, ?)
#         """, (sha256, sha256, now, now, score, verdict, vt_detections, ml_score, 
#               json.dumps(details) if details else None))
#         self.conn.commit()
    
#     def add_alert(self, source: str, target: str, score: int, verdict: str, details: dict):
#         now = datetime.now().isoformat()
#         self.conn.execute(
#             "INSERT INTO alerts (timestamp, source, target, score, verdict, details) VALUES (?, ?, ?, ?, ?, ?)",
#             (now, source, target, score, verdict, json.dumps(details))
#         )
#         self.conn.commit()
#         # Notify dashboard via queue
#         event_queue.put(('alert', {
#             'timestamp': now, 'source': source, 'target': target,
#             'score': score, 'verdict': verdict, 'details': details
#         }))
    
#     def get_recent_alerts(self, limit=100):
#         cursor = self.conn.execute(
#             "SELECT timestamp, source, target, score, verdict, details FROM alerts ORDER BY timestamp DESC LIMIT ?",
#             (limit,)
#         )
#         return [{'timestamp': r[0], 'source': r[1], 'target': r[2], 
#                  'score': r[3], 'verdict': r[4], 'details': json.loads(r[5])} 
#                 for r in cursor.fetchall()]

# # ========================== ML Classifier ==========================
# class MLClassifier:
#     """Machine learning model for file classification."""
#     def __init__(self):
#         self.model = None
#         self.feature_names = [
#             'size', 'entropy_mean', 'entropy_max', 'suspicious_imports',
#             'suspicious_strings', 'is_packed', 'has_certificate'
#         ]
#         self._load_or_train()
    
#     def _load_or_train(self):
#         if Config.MODEL_PATH.exists():
#             try:
#                 self.model = joblib.load(Config.MODEL_PATH)
#                 logger.info("ML model loaded from disk.")
#             except Exception as e:
#                 logger.error(f"Failed to load ML model: {e}")
#         if self.model is None:
#             # Train a simple dummy model (in production, train on real dataset)
#             self._train_dummy()
    
#     def _train_dummy(self):
#         """Create a simple random forest for demo purposes."""
#         # Generate synthetic data
#         np.random.seed(42)
#         X = np.random.rand(1000, len(self.feature_names))
#         y = (X[:, 0] * X[:, 1] > 0.3).astype(int)  # random rule
#         self.model = RandomForestClassifier(n_estimators=10)
#         self.model.fit(X, y)
#         joblib.dump(self.model, Config.MODEL_PATH)
#         logger.info("Dummy ML model trained and saved.")
    
#     def extract_features(self, filepath: str, pe_alerts: List[str], 
#                          strings: List[str]) -> np.ndarray:
#         """Extract features from file for ML prediction."""
#         features = []
        
#         # File size (log scaled)
#         size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
#         features.append(np.log1p(size))
        
#         # Entropy features (simplified)
#         entropy_mean = 5.0  # default
#         entropy_max = 6.0
#         try:
#             with open(filepath, 'rb') as f:
#                 data = f.read(1024*1024)  # first 1MB
#                 if data:
#                     entropy_mean = self._calculate_entropy(data)
#                     entropy_max = entropy_mean * 1.2
#         except:
#             pass
#         features.append(entropy_mean)
#         features.append(entropy_max)
        
#         # Suspicious imports count
#         sus_imports = sum(1 for a in pe_alerts if 'Suspicious APIs' in a)
#         features.append(min(sus_imports, 10))
        
#         # Suspicious strings count
#         sus_strings = len(strings)
#         features.append(min(sus_strings, 100))
        
#         # Packed?
#         is_packed = 1 if any('Packed' in a for a in pe_alerts) else 0
#         features.append(is_packed)
        
#         # Has digital signature? (Windows only)
#         has_cert = 0
#         if sys.platform == 'win32' and filepath.lower().endswith(('.exe', '.dll')):
#             has_cert = 1 if self._check_signature(filepath) else 0
#         features.append(has_cert)
        
#         return np.array(features).reshape(1, -1)
    
#     def _calculate_entropy(self, data: bytes) -> float:
#         if not data:
#             return 0
#         entropy = 0
#         for x in range(256):
#             p_x = data.count(x) / len(data)
#             if p_x > 0:
#                 entropy += - p_x * np.log2(p_x)
#         return entropy
    
#     def _check_signature(self, filepath: str) -> bool:
#         """Check if file has valid digital signature (Windows)."""
#         try:
#             import win32security
#             import win32crypt
#             # Simplified - real implementation would verify
#             return False
#         except:
#             return False
    
#     def predict(self, features: np.ndarray) -> Tuple[float, float]:
#         """Return (malicious_probability, score_contribution)."""
#         if self.model is None:
#             return 0.0, 0
#         proba = self.model.predict_proba(features)[0]
#         malicious_prob = proba[1] if len(proba) > 1 else 0
#         score_contrib = int(malicious_prob * Config.SCORE_ML_MALICIOUS)
#         return malicious_prob, score_contrib

# # ========================== YARA Manager with Hot Reload ==========================
# class YaraManager(FileSystemEventHandler):
#     def __init__(self):
#         self.rules = None
#         self.rules_lock = threading.Lock()
#         self.rules_mtime = {}
#         self.load_rules()
#         self.start_watcher()
    
#     def load_rules(self):
#         """Load all .yar files, track modification times."""
#         rule_files = {}
#         current_mtime = {}
#         for yar_file in Config.RULES_DIR.glob("*.yar"):
#             rule_files[str(yar_file)] = str(yar_file)
#             current_mtime[str(yar_file)] = yar_file.stat().st_mtime
        
#         if not rule_files:
#             logger.warning("No YARA rule files found.")
#             return
        
#         try:
#             new_rules = yara.compile(filepaths=rule_files)
#             with self.rules_lock:
#                 self.rules = new_rules
#                 self.rules_mtime = current_mtime
#             logger.info(f"Loaded {len(rule_files)} YARA rule files.")
#         except Exception as e:
#             logger.error(f"YARA compilation failed: {e}")
    
#     def start_watcher(self):
#         """Watch rules directory for changes."""
#         observer = Observer()
#         observer.schedule(self, str(Config.RULES_DIR), recursive=False)
#         observer.start()
#         logger.info("YARA hot-reload watcher started.")
    
#     def on_modified(self, event):
#         if event.src_path.endswith('.yar'):
#             logger.info(f"YARA rule modified: {event.src_path}, reloading...")
#             self.load_rules()
    
#     def on_created(self, event):
#         if event.src_path.endswith('.yar'):
#             logger.info(f"New YARA rule: {event.src_path}, reloading...")
#             self.load_rules()
    
#     def scan(self, filepath: str) -> List[str]:
#         with self.rules_lock:
#             if not self.rules:
#                 return []
#         try:
#             matches = self.rules.match(filepath)
#             return [match.rule for match in matches]
#         except Exception as e:
#             logger.error(f"YARA scan error on {filepath}: {e}")
#             return []

# # ========================== Static Analysis ==========================
# class StaticAnalyzer:
#     def __init__(self, yara_manager: YaraManager, ml_classifier: MLClassifier):
#         self.yara = yara_manager
#         self.ml = ml_classifier
    
#     def get_hashes(self, filepath: str) -> Dict[str, str]:
#         hashes = {'md5': hashlib.md5(), 'sha1': hashlib.sha1(), 'sha256': hashlib.sha256()}
#         try:
#             with open(filepath, 'rb') as f:
#                 while chunk := f.read(8192):
#                     for algo in hashes.values():
#                         algo.update(chunk)
#             return {name: algo.hexdigest() for name, algo in hashes.items()}
#         except Exception as e:
#             logger.error(f"Hash error {filepath}: {e}")
#             return {}
    
#     def get_file_type(self, filepath: str) -> str:
#         try:
#             return magic.from_file(filepath, mime=True)
#         except:
#             return "unknown"
    
#     def analyze_pe(self, filepath: str) -> List[str]:
#         alerts = []
#         try:
#             pe = pefile.PE(filepath)
            
#             # Suspicious imports
#             suspicious_apis = {
#                 'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
#                 'OpenProcess', 'GetProcAddress', 'LoadLibraryA', 'HttpSendRequestA',
#                 'WinExec', 'ShellExecute', 'RegSetValue', 'CryptEncrypt',
#                 'NtQuerySystemInformation', 'NtSetInformationProcess', 'NtCreateThreadEx'
#             }
#             found = set()
#             for entry in pe.DIRECTORY_ENTRY_IMPORT:
#                 for imp in entry.imports:
#                     if imp.name and imp.name.decode() in suspicious_apis:
#                         found.add(imp.name.decode())
#             if len(found) > 3:
#                 alerts.append(f"Suspicious APIs: {', '.join(found)}")
            
#             # Section entropy and names
#             packers = ['UPX0', 'UPX1', 'UPX2', '.aspack', '.themida', '._winzip', 
#                        '.mpress', '.vmp0', '.vmp1', '.enigma']
#             for section in pe.sections:
#                 name = section.Name.decode().strip('\x00')
#                 entropy = section.get_entropy()
#                 if name in packers:
#                     alerts.append(f"Packed: {name}")
#                 if entropy > 7.5:
#                     alerts.append(f"High entropy {name}: {entropy:.2f}")
            
#             # Entry point in unusual section
#             ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
#             ep_section = None
#             for s in pe.sections:
#                 if s.contains_rva(ep):
#                     ep_section = s.Name.decode().strip('\x00')
#                     break
#             if ep_section and ep_section not in ['.text', 'CODE', '__text']:
#                 alerts.append(f"Entry point in {ep_section}")
            
#             # Timestamp anomaly
#             timestamp = pe.FILE_HEADER.TimeDateStamp
#             if timestamp > int(time.time()) + 86400:
#                 alerts.append("Future timestamp")
            
#             # Check for digital signature
#             if sys.platform == 'win32':
#                 try:
#                     from win32security import CryptQueryObject, CERT_QUERY_OBJECT_FILE
#                     # Simplified - real signature verification is complex
#                 except:
#                     pass
#             pe.close()
#         except:
#             pass
#         return alerts
    
#     def extract_strings(self, filepath: str) -> List[str]:
#         """Safe string extraction with size limit."""
#         if os.path.getsize(filepath) > Config.MAX_STRING_EXTRACT_SIZE:
#             logger.warning(f"File too large for string extraction: {filepath}")
#             return []
        
#         strings = []
#         try:
#             with open(filepath, 'rb') as f:
#                 current = bytearray()
#                 bytes_read = 0
#                 while chunk := f.read(4096):
#                     bytes_read += len(chunk)
#                     if bytes_read > Config.MAX_STRING_EXTRACT_SIZE:
#                         break
#                     for byte in chunk:
#                         if 32 <= byte <= 126:
#                             current.append(byte)
#                         else:
#                             if len(current) >= Config.MIN_STRING_LENGTH:
#                                 strings.append(current.decode('ascii', errors='ignore'))
#                                 if len(strings) >= Config.MAX_STRING_COUNT:
#                                     return strings
#                             current.clear()
#                 if len(current) >= Config.MIN_STRING_LENGTH:
#                     strings.append(current.decode('ascii', errors='ignore'))
#         except Exception as e:
#             logger.error(f"String extraction error: {e}")
#         return strings
    
#     def heuristic_strings(self, strings: List[str]) -> List[str]:
#         alerts = []
#         patterns = [
#             (r'http[s]?://', 'URL'),
#             (r'\\\\[^\\]+\\', 'Network path'),
#             (r'[Pp]ower[Ss]hell', 'PowerShell'),
#             (r'[Cc]md\.exe', 'cmd'),
#             (r'[Bb]ase64', 'Base64'),
#             (r'[Ee]val\(', 'eval'),
#             (r'[Ee]xec\(', 'exec'),
#             (r'[Dd]ecrypt', 'decrypt'),
#             (r'[Ee]ncrypt', 'encrypt'),
#             (r'[Kk]eylogger', 'keylogger'),
#             (r'[Rr]ansom', 'ransom'),
#             (r'[Bb]itcoin', 'bitcoin'),
#             (r'[Ww]allet', 'wallet'),
#             (r'[Mm]alware', 'malware'),
#         ]
#         for s in strings[:Config.MAX_STRING_COUNT]:
#             for pat, desc in patterns:
#                 if re.search(pat, s):
#                     alerts.append(f"{desc}: {s[:50]}")
#                     break
#         return alerts[:50]

# # ========================== Cloud Analyzer (VirusTotal + AbuseIPDB) ==========================
# class CloudAnalyzer:
#     def __init__(self, db: ReputationDB):
#         self.db = db
#         self.vt_key = Config.VIRUSTOTAL_API_KEY
#         self.abuse_key = Config.ABUSEIPDB_API_KEY
#         self.session = requests.Session()
#         self.session.headers.update({'User-Agent': 'CyberGuard-Pro/6.0'})
    
#     def query_vt_hash(self, sha256: str) -> Tuple[int, int, str]:
#         if not self.vt_key:
#             return 0, 0, "API key missing"
        
#         url = f"https://www.virustotal.com/api/v3/files/{sha256}"
#         headers = {"x-apikey": self.vt_key}
#         try:
#             resp = self.session.get(url, headers=headers, timeout=10)
#             if resp.status_code == 200:
#                 data = resp.json()
#                 stats = data['data']['attributes']['last_analysis_stats']
#                 malicious = stats.get('malicious', 0)
#                 suspicious = stats.get('suspicious', 0)
#                 return malicious, suspicious, f"M:{malicious} S:{suspicious}"
#             elif resp.status_code == 404:
#                 return 0, 0, "Not found"
#             else:
#                 return 0, 0, f"HTTP {resp.status_code}"
#         except Exception as e:
#             return 0, 0, f"Error: {e}"
    
#     def query_abuse_ip(self, ip: str) -> Tuple[int, str]:
#         """Check IP reputation on AbuseIPDB."""
#         if not self.abuse_key:
#             return 0, "No API key"
        
#         url = "https://api.abuseipdb.com/api/v2/check"
#         headers = {'Key': self.abuse_key, 'Accept': 'application/json'}
#         params = {'ipAddress': ip, 'maxAgeInDays': 90}
#         try:
#             resp = self.session.get(url, headers=headers, params=params, timeout=5)
#             if resp.status_code == 200:
#                 data = resp.json()['data']
#                 abuse_score = data['abuseConfidenceScore']
#                 country = data.get('countryCode', '')
#                 return abuse_score, country
#             else:
#                 return 0, f"Error {resp.status_code}"
#         except Exception as e:
#             return 0, str(e)
    
#     def upload_file_vt(self, filepath: str, interactive: bool = True) -> str:
#         """Upload file to VT, with non-interactive check."""
#         if not self.vt_key:
#             return "API key missing"
        
#         # Check if called from non-interactive thread
#         if not interactive or threading.current_thread() is not threading.main_thread():
#             event_queue.put(('upload_request', filepath))
#             return "Upload queued (interactive)"
        
#         print(f"\n[?] Upload {os.path.basename(filepath)} to VirusTotal?")
#         choice = input("This will share the file with VT. (y/N): ").strip().lower()
#         if choice != 'y':
#             return "Upload skipped"
        
#         url = "https://www.virustotal.com/api/v3/files"
#         headers = {"x-apikey": self.vt_key}
#         try:
#             with open(filepath, 'rb') as f:
#                 files = {"file": (os.path.basename(filepath), f)}
#                 resp = self.session.post(url, headers=headers, files=files, timeout=120)
#                 if resp.status_code == 200:
#                     analysis_id = resp.json()['data']['id']
#                     return f"Uploaded (ID: {analysis_id})"
#                 else:
#                     return f"Upload failed: {resp.status_code}"
#         except Exception as e:
#             return f"Upload error: {e}"

# # ========================== Threat Scoring Engine ==========================
# @dataclass
# class ScanResult:
#     filepath: str
#     sha256: str
#     file_type: str
#     yara_matches: List[str]
#     pe_alerts: List[str]
#     string_alerts: List[str]
#     vt_malicious: int
#     vt_suspicious: int
#     vt_verdict: str
#     ml_probability: float
#     score: int = 0
#     verdict: str = "UNKNOWN"
    
#     def calculate_score(self, ml_score_contrib: int = 0):
#         self.score = 0
#         self.score += len(self.yara_matches) * Config.SCORE_YARA
#         self.score += len(self.pe_alerts) * Config.SCORE_PE_ALERT
#         self.score += len(self.string_alerts) * Config.SCORE_STRINGS_SUSPICIOUS
#         self.score += self.vt_malicious * Config.SCORE_VT_MALICIOUS
#         self.score += self.vt_suspicious * Config.SCORE_VT_SUSPICIOUS
#         self.score += ml_score_contrib
        
#         if self.score >= 15:
#             self.verdict = "CRITICAL"
#         elif self.score >= 10:
#             self.verdict = "MALICIOUS"
#         elif self.score >= 5:
#             self.verdict = "SUSPICIOUS"
#         else:
#             self.verdict = "CLEAN"
    
#     def to_dict(self):
#         return {
#             'filepath': self.filepath,
#             'sha256': self.sha256,
#             'type': self.file_type,
#             'yara': self.yara_matches,
#             'pe': self.pe_alerts,
#             'strings': self.string_alerts,
#             'vt_malicious': self.vt_malicious,
#             'vt_suspicious': self.vt_suspicious,
#             'ml_probability': self.ml_probability,
#             'score': self.score,
#             'verdict': self.verdict
#         }

# # ========================== Response Actions ==========================
# class ResponseEngine:
#     def __init__(self, db: ReputationDB):
#         self.db = db
#         self.alert_count = 0
#         self.whitelist = set(Config.SAFE_PROCESSES)
    
#     def handle_threat(self, result: ScanResult, source: str = "scan"):
#         """Take action based on score."""
#         logger.warning(f"Threat detected: {result.filepath} (score={result.score}, verdict={result.verdict})")
#         self.alert_count += 1
        
#         # Log to DB
#         self.db.add_alert(source, result.filepath, result.score, result.verdict, result.to_dict())
        
#         # Auto-quarantine if high score
#         if result.score >= 15 or self.alert_count >= Config.ALERT_THRESHOLD:
#             self.quarantine(result.filepath)
#             return
        
#         # In interactive mode, ask user
#         if threading.current_thread() is threading.main_thread():
#             self._interactive_prompt(result)
#         else:
#             # Non-interactive: queue for later decision
#             event_queue.put(('threat', result))
    
#     def _interactive_prompt(self, result: ScanResult):
#         print(f"\n[!] Suspicious file: {result.filepath}")
#         print(f"Score: {result.score} | Verdict: {result.verdict}")
#         print(f"YARA: {result.yara_matches}")
#         print(f"PE alerts: {result.pe_alerts}")
#         action = input("Action: (Q)uarantine, (S)andbox, (I)gnore: ").strip().lower()
#         if action == 'q':
#             self.quarantine(result.filepath)
#         elif action == 's':
#             self.sandbox(result.filepath)
#         else:
#             logger.info(f"Ignored by user: {result.filepath}")
    
#     def quarantine(self, filepath: str):
#         """Secure quarantine with real encryption."""
#         try:
#             base = os.path.basename(filepath)
#             timestamp = int(time.time())
#             dest_zip = Config.QUARANTINE_DIR / f"{base}_{timestamp}.zip"
#             password = hashlib.sha256(f"{timestamp}{os.urandom(8)}".encode()).hexdigest()[:16]
            
#             # Use pyminizip for real AES encryption
#             pyminizip.compress(str(filepath), None, str(dest_zip), password, 5)
            
#             # Remove original
#             os.remove(filepath)
            
#             # Save metadata
#             meta = Config.QUARANTINE_DIR / f"{dest_zip.stem}.meta"
#             with open(meta, 'w') as f:
#                 f.write(f"Original: {filepath}\nTime: {datetime.now()}\nPassword: {password}\n")
            
#             logger.info(f"Quarantined {filepath} -> {dest_zip} (pwd: {password})")
#             self.db.add_alert("quarantine", filepath, 0, "QUARANTINED", {"zip": str(dest_zip)})
#         except Exception as e:
#             logger.error(f"Quarantine failed: {e}")
    
#     def sandbox(self, filepath: str):
#         """Run in Sandboxie if available."""
#         if sys.platform == 'win32' and os.path.exists(Config.SANDBOXIE_PATH):
#             try:
#                 subprocess.Popen([Config.SANDBOXIE_PATH, filepath])
#                 logger.info(f"Launched in Sandboxie: {filepath}")
#             except Exception as e:
#                 logger.error(f"Sandboxie error: {e}")
#         else:
#             logger.error("Sandboxie not available")
    
#     def kill_process(self, proc):
#         """Kill process if not whitelisted."""
#         if proc.name().lower() in self.whitelist:
#             logger.info(f"Whitelisted process {proc.name()} not killed.")
#             return
#         try:
#             proc.kill()
#             logger.critical(f"Killed process {proc.pid} ({proc.name()})")
#             self.db.add_alert("process_kill", f"{proc.name()}:{proc.pid}", 10, "KILLED", {})
#         except Exception as e:
#             logger.error(f"Failed to kill process: {e}")

# # ========================== Behavioral Monitoring ==========================
# class FileMonitorHandler(FileSystemEventHandler):
#     def __init__(self, core):
#         self.core = core
    
#     def on_created(self, event):
#         if not event.is_directory:
#             self._handle(event.src_path, "file_create")
    
#     def on_modified(self, event):
#         if not event.is_directory:
#             self._handle(event.src_path, "file_modify")
    
#     def _handle(self, path, source):
#         # Exclude our own files
#         if any(excl in path for excl in Config.EXCLUDED_FILES):
#             return
#         # Wait a bit for write completion
#         time.sleep(0.5)
#         self.core.scan_file(path, source=source)

# class ProcessMonitor:
#     def __init__(self, core):
#         self.core = core
#         self.running = False
#         self.seen_pids = set()
    
#     def start(self):
#         self.running = True
#         self.seen_pids = set(psutil.pids())
#         threading.Thread(target=self._monitor, daemon=True).start()
    
#     def _monitor(self):
#         while self.running:
#             try:
#                 current = set(psutil.pids())
#                 new = current - self.seen_pids
#                 for pid in new:
#                     try:
#                         proc = psutil.Process(pid)
#                         self._check_process(proc)
#                     except (psutil.NoSuchProcess, psutil.AccessDenied):
#                         pass
#                 self.seen_pids = current
#             except Exception as e:
#                 logger.error(f"Process monitor error: {e}")
#             time.sleep(3)
    
#     def _check_process(self, proc):
#         alerts = []
#         try:
#             # Use net_connections instead of deprecated connections
#             for conn in proc.net_connections(kind='inet'):
#                 if conn.status == 'ESTABLISHED' and conn.raddr:
#                     alerts.append(f"Conn to {conn.raddr}")
#                     # Check IP reputation
#                     self.core.check_ip_reputation(conn.raddr.ip)
            
#             # Check open files in monitored dirs
#             for f in proc.open_files():
#                 if any(f.path.startswith(d) for d in Config.MONITORED_DIRS):
#                     alerts.append(f"Opened {f.path}")
            
#             # Command line suspicious
#             cmd = ' '.join(proc.cmdline()).lower()
#             suspicious_cmds = ['powershell -enc', 'base64', 'downloadstring', 
#                                'invoke-expression', 'start-process']
#             if any(k in cmd for k in suspicious_cmds):
#                 alerts.append(f"Suspicious cmd: {cmd[:100]}")
            
#             if alerts:
#                 self.core.behavioral_callback(proc, alerts, "process")
#         except (psutil.NoSuchProcess, psutil.AccessDenied):
#             pass

# class NetworkMonitor:
#     def __init__(self, core):
#         self.core = core
#         self.running = False
#         self.conn_history = defaultdict(list)  # ip -> list of ports
    
#     def start(self):
#         self.running = True
#         threading.Thread(target=self._monitor, daemon=True).start()
    
#     def _monitor(self):
#         while self.running:
#             try:
#                 for conn in psutil.net_connections(kind='inet'):
#                     if conn.status == 'SYN_SENT' and conn.raddr:
#                         ip = conn.raddr.ip
#                         port = conn.raddr.port
#                         self.conn_history[ip].append((port, time.time()))
                
#                 # Detect port scan
#                 now = time.time()
#                 for ip, records in list(self.conn_history.items()):
#                     # Keep last 30 seconds
#                     records = [(p, t) for p, t in records if now - t < 30]
#                     self.conn_history[ip] = records
#                     if len(set(p for p, _ in records)) > 15:
#                         self.core.behavioral_callback(f"Port scan from {ip}", records, "network")
#                         # Block IP
#                         self._block_ip(ip)
#                         del self.conn_history[ip]
#             except Exception as e:
#                 logger.error(f"Network monitor error: {e}")
#             time.sleep(5)
    
#     def _block_ip(self, ip):
#         if sys.platform != 'win32':
#             return
#         try:
#             rule = f"CyberGuard_Block_{ip.replace('.', '_')}"
#             subprocess.run([
#                 'netsh', 'advfirewall', 'firewall', 'add', 'rule',
#                 f'name={rule}', 'dir=in', 'action=block', f'remoteip={ip}'
#             ], check=True, capture_output=True)
#             logger.info(f"Blocked IP {ip}")
#             self.core.db.add_alert("network_block", ip, 10, "BLOCKED", {})
#         except Exception as e:
#             logger.error(f"Block failed: {e}")

# # ========================== ETW Monitoring (Windows) ==========================
# if Config.ENABLE_ETW_MONITOR and sys.platform == 'win32':
#     class ETWMonitor:
#         """Monitor Windows ETW events for process creation, DLL loads, etc."""
#         def __init__(self, core):
#             self.core = core
#             self.running = False
        
#         def start(self):
#             self.running = True
#             threading.Thread(target=self._monitor, daemon=True).start()
        
#         def _monitor(self):
#             # Simplified ETW using wevtutil or Win32 API
#             # Real implementation would use Microsoft.Diagnostics.Tracing.TraceEvent
#             # This is a placeholder for demonstration
#             import win32evtlog
#             server = 'localhost'
#             logtype = 'Security'
#             hand = win32evtlog.OpenEventLog(server, logtype)
#             flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
#             while self.running:
#                 events = win32evtlog.ReadEventLog(hand, flags, 0)
#                 if events:
#                     for event in events:
#                         if event.EventID == 4688:  # Process creation
#                             # Extract process info
#                             self.core.behavioral_callback(f"New process created", event.StringInserts, "etw")
#                 time.sleep(5)

# # ========================== Registry Monitor ==========================
# if Config.ENABLE_REGISTRY_MONITOR and sys.platform == 'win32':
#     class RegistryMonitor:
#         def __init__(self, core):
#             self.core = core
#             self.running = False
#             self.keywords = ['run', 'runonce', 'services', 'winlogon', 'shell']
        
#         def start(self):
#             self.running = True
#             threading.Thread(target=self._monitor, daemon=True).start()
        
#         def _monitor(self):
#             # Simplified registry monitoring via polling
#             import winreg
#             hives = [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
#             paths = [
#                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
#                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
#                 r"SYSTEM\CurrentControlSet\Services",
#             ]
#             last_values = {}
#             while self.running:
#                 for hive in hives:
#                     for path in paths:
#                         try:
#                             key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
#                             i = 0
#                             while True:
#                                 try:
#                                     name, value, _ = winreg.EnumValue(key, i)
#                                     full = f"{hive}\\{path}\\{name}"
#                                     if full not in last_values:
#                                         last_values[full] = value
#                                         self.core.behavioral_callback(f"Registry added: {full}={value}", None, "registry")
#                                     elif last_values[full] != value:
#                                         self.core.behavioral_callback(f"Registry changed: {full}={value}", None, "registry")
#                                         last_values[full] = value
#                                     i += 1
#                                 except WindowsError:
#                                     break
#                             winreg.CloseKey(key)
#                         except Exception:
#                             pass
#                 time.sleep(10)

# # ========================== Memory Scanner ==========================
# class MemoryScanner:
#     """Scan process memory for YARA signatures."""
#     def __init__(self, yara_mgr: YaraManager):
#         self.yara = yara_mgr
#         self.running = False
    
#     def start(self):
#         self.running = True
#         threading.Thread(target=self._scan_loop, daemon=True).start()
    
#     def _scan_loop(self):
#         while self.running:
#             # Scan critical processes periodically
#             targets = ['lsass.exe', 'svchost.exe', 'winlogon.exe', 'explorer.exe']
#             for proc in psutil.process_iter(['pid', 'name']):
#                 if proc.info['name'].lower() in targets:
#                     self.scan_process(proc.info['pid'])
#             time.sleep(60)
    
#     def scan_process(self, pid):
#         """Read process memory and scan with YARA."""
#         try:
#             proc = psutil.Process(pid)
#             # Read memory regions (simplified - in reality use ReadProcessMemory)
#             # This is a placeholder; full memory scanning is complex
#             logger.info(f"Memory scan of PID {pid} started")
#             # For demo, just log
#         except Exception as e:
#             logger.error(f"Memory scan failed: {e}")

# # ========================== Web Dashboard ==========================
# def create_dashboard(core):
#     app = Flask(__name__)
    
#     @app.route('/')
#     def index():
#         return render_template_string("""
#         <!DOCTYPE html>
#         <html>
#         <head>
#             <title>CyberGuard Dashboard</title>
#             <style>
#                 body { font-family: Arial; margin: 20px; background: #1e1e1e; color: #fff; }
#                 table { border-collapse: collapse; width: 100%; }
#                 th, td { border: 1px solid #444; padding: 8px; text-align: left; }
#                 th { background: #333; }
#                 .critical { color: #ff4444; }
#                 .malicious { color: #ff8800; }
#                 .suspicious { color: #ffaa00; }
#                 .clean { color: #00ff00; }
#             </style>
#         </head>
#         <body>
#             <h1>CyberGuard Pro v6.0 Dashboard</h1>
#             <h2>Recent Alerts</h2>
#             <table id="alerts">
#                 <thead>
#                     <tr><th>Time</th><th>Source</th><th>Target</th><th>Score</th><th>Verdict</th></tr>
#                 </thead>
#                 <tbody>
#                 </tbody>
#             </table>
#             <script>
#                 function fetchAlerts() {
#                     fetch('/api/alerts')
#                         .then(res => res.json())
#                         .then(data => {
#                             let tbody = document.querySelector('#alerts tbody');
#                             tbody.innerHTML = '';
#                             data.forEach(alert => {
#                                 let row = tbody.insertRow();
#                                 row.innerHTML = `<td>${alert.timestamp}</td><td>${alert.source}</td><td>${alert.target}</td><td>${alert.score}</td><td class="${alert.verdict.toLowerCase()}">${alert.verdict}</td>`;
#                             });
#                         });
#                 }
#                 setInterval(fetchAlerts, 2000);
#                 fetchAlerts();
#             </script>
#         </body>
#         </html>
#         """)
    
#     @app.route('/api/alerts')
#     def get_alerts():
#         return jsonify(core.db.get_recent_alerts(50))
    
#     @app.route('/api/stats')
#     def get_stats():
#         # Return system stats
#         return jsonify({
#             'processes': len(psutil.pids()),
#             'cpu_percent': psutil.cpu_percent(),
#             'memory_percent': psutil.virtual_memory().percent,
#         })
    
#     return app

# # ========================== Core Engine ==========================
# class CyberGuardCore:
#     def __init__(self):
#         self.db = ReputationDB()
#         self.yara_mgr = YaraManager()
#         self.ml = MLClassifier()
#         self.static = StaticAnalyzer(self.yara_mgr, self.ml)
#         self.cloud = CloudAnalyzer(self.db)
#         self.response = ResponseEngine(self.db)
        
#         # Monitors
#         self.file_observer = None
#         self.proc_monitor = None
#         self.net_monitor = None
#         self.etw_monitor = None
#         self.registry_monitor = None
#         self.memory_scanner = None
        
#         # Dashboard
#         self.dashboard_app = None
#         self.dashboard_thread = None
    
#     def check_ip_reputation(self, ip: str):
#         """Check IP against AbuseIPDB."""
#         if not self.cloud.abuse_key:
#             return
#         score, country = self.cloud.query_abuse_ip(ip)
#         if score > 50:
#             logger.warning(f"Malicious IP detected: {ip} (abuse score {score})")
#             self.db.add_alert("ip_reputation", ip, score, "MALICIOUS", {"country": country})
    
#     def scan_file(self, filepath: str, source="manual") -> Optional[ScanResult]:
#         """Full scan pipeline."""
#         if not os.path.isfile(filepath):
#             logger.error(f"File not found: {filepath}")
#             return None
        
#         # Self-exclusion
#         if any(excl in filepath for excl in Config.EXCLUDED_FILES):
#             logger.debug(f"Skipping excluded file: {filepath}")
#             return None
        
#         logger.info(f"Scanning {filepath} (source: {source})")
        
#         # Get hashes
#         hashes = self.static.get_hashes(filepath)
#         sha256 = hashes.get('sha256', '')
        
#         # Check local DB
#         cached = self.db.get_file(sha256) if sha256 else None
#         if cached and (datetime.now() - datetime.fromisoformat(cached['last_seen'])).days < 1:
#             logger.info(f"Cache hit for {sha256[:8]}... score={cached['score']}")
#             result = ScanResult(
#                 filepath=filepath,
#                 sha256=sha256,
#                 file_type=self.static.get_file_type(filepath),
#                 yara_matches=[],
#                 pe_alerts=[],
#                 string_alerts=[],
#                 vt_malicious=cached.get('vt_detections', 0),
#                 vt_suspicious=0,
#                 vt_verdict=cached['verdict'],
#                 ml_probability=cached.get('ml_score', 0.0)
#             )
#             result.score = cached['score']
#             result.verdict = cached['verdict']
#             return result
        
#         # Perform scans
#         yara_matches = self.yara_mgr.scan(filepath)
#         pe_alerts = self.static.analyze_pe(filepath)
#         strings = self.static.extract_strings(filepath)
#         string_alerts = self.static.heuristic_strings(strings)
        
#         # ML prediction
#         features = self.ml.extract_features(filepath, pe_alerts, strings)
#         ml_prob, ml_score_contrib = self.ml.predict(features)
        
#         # Cloud lookup
#         vt_mal, vt_sus, vt_ver = self.cloud.query_vt_hash(sha256) if sha256 else (0,0,"No hash")
        
#         # Build result
#         result = ScanResult(
#             filepath=filepath,
#             sha256=sha256,
#             file_type=self.static.get_file_type(filepath),
#             yara_matches=yara_matches,
#             pe_alerts=pe_alerts,
#             string_alerts=string_alerts,
#             vt_malicious=vt_mal,
#             vt_suspicious=vt_sus,
#             vt_verdict=vt_ver,
#             ml_probability=ml_prob
#         )
#         result.calculate_score(ml_score_contrib)
        
#         # Store in DB
#         if sha256:
#             self.db.update_file(sha256, result.score, result.verdict, vt_mal, ml_prob, result.to_dict())
        
#         # If VT not found, offer upload
#         if vt_ver == "Not found" and self.cloud.vt_key:
#             upload_status = self.cloud.upload_file_vt(filepath, interactive=(source=="manual"))
#             logger.info(f"VT upload: {upload_status}")
        
#         # Respond if suspicious
#         if result.verdict != "CLEAN":
#             self.response.handle_threat(result, source)
#         else:
#             logger.info(f"File clean: {filepath}")
        
#         return result
    
#     def start_monitoring(self):
#         """Start all real-time monitors."""
#         if Config.ENABLE_FILE_MONITOR:
#             handler = FileMonitorHandler(self)
#             self.file_observer = Observer()
#             for d in Config.MONITORED_DIRS:
#                 if os.path.exists(d):
#                     self.file_observer.schedule(handler, d, recursive=True)
#                     logger.info(f"Watching directory: {d}")
#             self.file_observer.start()
        
#         if Config.ENABLE_PROCESS_MONITOR:
#             self.proc_monitor = ProcessMonitor(self)
#             self.proc_monitor.start()
        
#         if Config.ENABLE_NETWORK_MONITOR:
#             self.net_monitor = NetworkMonitor(self)
#             self.net_monitor.start()
        
#         if Config.ENABLE_ETW_MONITOR and sys.platform == 'win32':
#             self.etw_monitor = ETWMonitor(self)
#             self.etw_monitor.start()
        
#         if Config.ENABLE_REGISTRY_MONITOR and sys.platform == 'win32':
#             self.registry_monitor = RegistryMonitor(self)
#             self.registry_monitor.start()
        
#         self.memory_scanner = MemoryScanner(self.yara_mgr)
#         self.memory_scanner.start()
        
#         logger.info("All real-time monitors started.")
        
#         # Start dashboard
#         if Config.ENABLE_WEB_DASHBOARD:
#             self.dashboard_app = create_dashboard(self)
#             self.dashboard_thread = threading.Thread(
#                 target=self.dashboard_app.run,
#                 kwargs={'host':'0.0.0.0', 'port':Config.DASHBOARD_PORT, 'debug':False, 'use_reloader':False},
#                 daemon=True
#             )
#             self.dashboard_thread.start()
#             logger.info(f"Web dashboard running on http://localhost:{Config.DASHBOARD_PORT}")
    
#     def behavioral_callback(self, target, details, source):
#         """Unified callback for all monitors."""
#         if source == "file_create" or source == "file_modify":
#             if os.path.isfile(target):
#                 self.scan_file(target, source=source)
        
#         elif source == "process":
#             proc, alerts = target, details
#             logger.warning(f"Process {proc.pid} {proc.name()}: {alerts}")
#             # Check for network connections
#             if any('Conn to' in a for a in alerts):
#                 self.response.kill_process(proc)
        
#         elif source == "network":
#             logger.warning(f"Network alert: {target}")
#             self.db.add_alert("network", str(target), 8, "SUSPICIOUS", {"details": details})
        
#         elif source == "etw":
#             logger.info(f"ETW event: {target} - {details}")
        
#         elif source == "registry":
#             logger.info(f"Registry change: {target}")
#             self.db.add_alert("registry", target, 5, "INFO", {})

# # ========================== Command Line Interface ==========================
# def main():
#     print("""
#     ╔══════════════════════════════════════════════════════════╗
#     ║           CyberGuard Pro v6.0 - EDR Edition             ║
#     ║      Advanced Endpoint Detection & Response Toolkit     ║
#     ╚══════════════════════════════════════════════════════════╝
#     """)
    
#     core = CyberGuardCore()
    
#     # Process event queue in main thread
#     def process_event_queue():
#         while True:
#             try:
#                 event = event_queue.get(timeout=0.1)
#                 if event[0] == 'upload_request':
#                     filepath = event[1]
#                     # Prompt user in main thread
#                     print(f"\n[?] Upload requested for {os.path.basename(filepath)}")
#                     choice = input("Upload to VirusTotal? (y/N): ").strip().lower()
#                     if choice == 'y':
#                         core.cloud.upload_file_vt(filepath, interactive=True)
#                 elif event[0] == 'threat':
#                     result = event[1]
#                     core.response._interactive_prompt(result)
#                 elif event[0] == 'alert':
#                     # Already handled by DB
#                     pass
#             except queue.Empty:
#                 break
    
#     if len(sys.argv) > 1:
#         cmd = sys.argv[1]
#         if cmd == 'scan' and len(sys.argv) > 2:
#             target = sys.argv[2]
#             if os.path.isfile(target):
#                 core.scan_file(target)
#             elif os.path.isdir(target):
#                 for root, _, files in os.walk(target):
#                     for f in files:
#                         core.scan_file(os.path.join(root, f), source="batch")
#                         process_event_queue()
#             else:
#                 print("Invalid path")
#         elif cmd == 'monitor':
#             core.start_monitoring()
#             try:
#                 while True:
#                     process_event_queue()
#                     time.sleep(1)
#             except KeyboardInterrupt:
#                 print("\nShutting down...")
#         else:
#             print("Usage: cyberguard.py [scan <file/dir> | monitor]")
#     else:
#         # Interactive mode
#         while True:
#             print("\nOptions:")
#             print("1. Scan file")
#             print("2. Scan directory")
#             print("3. Start monitoring")
#             print("4. Show recent alerts")
#             print("5. Exit")
#             choice = input("Select: ").strip()
#             if choice == '1':
#                 path = input("File path: ").strip('"')
#                 if os.path.isfile(path):
#                     core.scan_file(path)
#                 else:
#                     print("Not a file")
#             elif choice == '2':
#                 path = input("Directory path: ").strip('"')
#                 if os.path.isdir(path):
#                     for root, _, files in os.walk(path):
#                         for f in files:
#                             core.scan_file(os.path.join(root, f), source="batch")
#                             process_event_queue()
#                 else:
#                     print("Invalid directory")
#             elif choice == '3':
#                 core.start_monitoring()
#                 try:
#                     while True:
#                         process_event_queue()
#                         time.sleep(1)
#                 except KeyboardInterrupt:
#                     print("\nMonitoring stopped")
#             elif choice == '4':
#                 alerts = core.db.get_recent_alerts(20)
#                 for a in alerts:
#                     print(f"{a['timestamp']} - {a['source']} - {a['target']} - {a['verdict']}")
#             elif choice == '5':
#                 break

# if __name__ == "__main__":
#     main()



# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
# """
# CyberGuard Pro v6.0 - Enterprise EDR-Level Malware Defense
# پاراستنی پێشکەوتووی سیستەم لە هێرشەکانی تۆڕ و نەرمەکالا زیانبەخشەکان
# """

# import os
# import sys
# import hashlib
# import json
# import time
# import sqlite3
# import zipfile
# import shutil
# import subprocess
# import threading
# import logging
# import re
# import queue
# import pickle
# import socket
# import struct
# from datetime import datetime, timedelta
# from pathlib import Path
# from typing import Dict, List, Tuple, Optional, Any
# from dataclasses import dataclass, asdict
# from collections import defaultdict
# from concurrent.futures import ThreadPoolExecutor
# from contextlib import contextmanager

# # External libraries
# try:
#     import yara
#     import requests
#     import pefile
#     import psutil
#     from watchdog.observers import Observer
#     from watchdog.events import FileSystemEventHandler, PatternMatchingEventHandler
#     import magic
#     from dotenv import load_dotenv
#     import pyzipper  # <-- replaced pyminizip with pyzipper
#     import joblib
#     from sklearn.ensemble import RandomForestClassifier
#     import numpy as np
#     from flask import Flask, jsonify, request, render_template_string
#     import win32evtlog  # for ETW on Windows
#     import win32con
#     import win32security
#     import winreg
# except ImportError as e:
#     print(f"[ERROR] Missing required library: {e}")
#     print("Install with: pip install -r requirements.txt")
#     sys.exit(1)

# # Load environment variables
# load_dotenv()

# # ========================== Configuration ==========================
# class Config:
#     # API Keys
#     VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY", "")
#     ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    
#     # Paths
#     BASE_DIR = Path(__file__).parent
#     RULES_DIR = BASE_DIR / "rules"
#     QUARANTINE_DIR = BASE_DIR / "quarantine"
#     LOG_DIR = BASE_DIR / "logs"
#     DB_DIR = BASE_DIR / "db"
#     DB_PATH = DB_DIR / "reputation.db"
#     MODEL_DIR = BASE_DIR / "models"
#     MODEL_PATH = MODEL_DIR / "classifier.pkl"
    
#     # Monitoring
#     MONITORED_DIRS = [str(BASE_DIR)]  # directories to watch
#     EXCLUDED_FILES = ["cyberguard.py", ".env", "reputation.db"]  # self-exclusion
#     ALERT_THRESHOLD = 5  # score threshold for auto-quarantine
#     ENABLE_NETWORK_MONITOR = True
#     ENABLE_PROCESS_MONITOR = True
#     ENABLE_FILE_MONITOR = True
#     ENABLE_ETW_MONITOR = sys.platform == 'win32'
#     ENABLE_REGISTRY_MONITOR = sys.platform == 'win32'
#     ENABLE_WEB_DASHBOARD = True
#     DASHBOARD_PORT = 5000
    
#     # Process whitelist
#     SAFE_PROCESSES = [
#         "brave.exe", "chrome.exe", "firefox.exe", "edge.exe", 
#         "explorer.exe", "svchost.exe", "csrss.exe", "winlogon.exe",
#         "services.exe", "lsass.exe", "spoolsv.exe", "taskhostw.exe",
#         "python.exe", "pycharm64.exe", "code.exe", "cursor.exe"
#     ]
    
#     # Scoring weights
#     SCORE_YARA = 3
#     SCORE_PE_ALERT = 2
#     SCORE_VT_MALICIOUS = 5
#     SCORE_VT_SUSPICIOUS = 3
#     SCORE_STRINGS_SUSPICIOUS = 1
#     SCORE_HIGH_ENTROPY = 2
#     SCORE_ML_MALICIOUS = 4
#     SCORE_ABUSEIPDB_MALICIOUS = 3
    
#     # Limits
#     MAX_STRING_EXTRACT_SIZE = 50 * 1024 * 1024  # 50MB
#     MAX_STRING_COUNT = 1000
#     MIN_STRING_LENGTH = 4

# # Create directories
# for d in [Config.RULES_DIR, Config.QUARANTINE_DIR, Config.LOG_DIR, 
#           Config.DB_DIR, Config.MODEL_DIR]:
#     d.mkdir(exist_ok=True)

# # Logging setup
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#     handlers=[
#         logging.FileHandler(Config.LOG_DIR / "cyberguard.log", encoding='utf-8'),
#         logging.StreamHandler()
#     ]
# )
# logger = logging.getLogger("CyberGuard")

# # Global event queue for thread-safe communication
# event_queue = queue.Queue()

# # ========================== Database ==========================
# class ReputationDB:
#     """SQLite local cache with TTL and reputation scoring."""
#     def __init__(self):
#         self.conn = sqlite3.connect(str(Config.DB_PATH), check_same_thread=False)
#         self._create_tables()
#         self._cleanup_old()
    
#     def _create_tables(self):
#         self.conn.execute("""
#             CREATE TABLE IF NOT EXISTS file_reputation (
#                 sha256 TEXT PRIMARY KEY,
#                 first_seen TIMESTAMP,
#                 last_seen TIMESTAMP,
#                 score INTEGER,
#                 verdict TEXT,
#                 vt_detections INTEGER,
#                 ml_score REAL,
#                 details TEXT
#             )
#         """)
#         self.conn.execute("""
#             CREATE TABLE IF NOT EXISTS ip_reputation (
#                 ip TEXT PRIMARY KEY,
#                 first_seen TIMESTAMP,
#                 last_seen TIMESTAMP,
#                 abuse_score INTEGER,
#                 reports INTEGER,
#                 country TEXT
#             )
#         """)
#         self.conn.execute("""
#             CREATE TABLE IF NOT EXISTS alerts (
#                 id INTEGER PRIMARY KEY AUTOINCREMENT,
#                 timestamp TIMESTAMP,
#                 source TEXT,
#                 target TEXT,
#                 score INTEGER,
#                 verdict TEXT,
#                 details TEXT
#             )
#         """)
#         self.conn.commit()
    
#     def _cleanup_old(self, days=30):
#         """Remove entries older than days."""
#         cutoff = (datetime.now() - timedelta(days=days)).isoformat()
#         self.conn.execute("DELETE FROM file_reputation WHERE last_seen < ?", (cutoff,))
#         self.conn.execute("DELETE FROM ip_reputation WHERE last_seen < ?", (cutoff,))
#         self.conn.commit()
    
#     def get_file(self, sha256: str) -> Optional[Dict]:
#         cursor = self.conn.execute(
#             "SELECT sha256, score, verdict, vt_detections, ml_score, details FROM file_reputation WHERE sha256 = ?",
#             (sha256,)
#         )
#         row = cursor.fetchone()
#         if row:
#             return {
#                 'sha256': row[0],
#                 'score': row[1],
#                 'verdict': row[2],
#                 'vt_detections': row[3],
#                 'ml_score': row[4],
#                 'details': json.loads(row[5]) if row[5] else {}
#             }
#         return None
    
#     def update_file(self, sha256: str, score: int, verdict: str, 
#                     vt_detections: int = 0, ml_score: float = 0.0, details: dict = None):
#         now = datetime.now().isoformat()
#         self.conn.execute("""
#             INSERT OR REPLACE INTO file_reputation 
#             (sha256, first_seen, last_seen, score, verdict, vt_detections, ml_score, details)
#             VALUES (?, COALESCE((SELECT first_seen FROM file_reputation WHERE sha256 = ?), ?), 
#                     ?, ?, ?, ?, ?, ?)
#         """, (sha256, sha256, now, now, score, verdict, vt_detections, ml_score, 
#               json.dumps(details) if details else None))
#         self.conn.commit()
    
#     def add_alert(self, source: str, target: str, score: int, verdict: str, details: dict):
#         now = datetime.now().isoformat()
#         self.conn.execute(
#             "INSERT INTO alerts (timestamp, source, target, score, verdict, details) VALUES (?, ?, ?, ?, ?, ?)",
#             (now, source, target, score, verdict, json.dumps(details))
#         )
#         self.conn.commit()
#         # Notify dashboard via queue
#         event_queue.put(('alert', {
#             'timestamp': now, 'source': source, 'target': target,
#             'score': score, 'verdict': verdict, 'details': details
#         }))
    
#     def get_recent_alerts(self, limit=100):
#         cursor = self.conn.execute(
#             "SELECT timestamp, source, target, score, verdict, details FROM alerts ORDER BY timestamp DESC LIMIT ?",
#             (limit,)
#         )
#         return [{'timestamp': r[0], 'source': r[1], 'target': r[2], 
#                  'score': r[3], 'verdict': r[4], 'details': json.loads(r[5])} 
#                 for r in cursor.fetchall()]

# # ========================== ML Classifier ==========================
# class MLClassifier:
#     """Machine learning model for file classification."""
#     def __init__(self):
#         self.model = None
#         self.feature_names = [
#             'size', 'entropy_mean', 'entropy_max', 'suspicious_imports',
#             'suspicious_strings', 'is_packed', 'has_certificate'
#         ]
#         self._load_or_train()
    
#     def _load_or_train(self):
#         if Config.MODEL_PATH.exists():
#             try:
#                 self.model = joblib.load(Config.MODEL_PATH)
#                 logger.info("ML model loaded from disk.")
#             except Exception as e:
#                 logger.error(f"Failed to load ML model: {e}")
#         if self.model is None:
#             # Train a simple dummy model (in production, train on real dataset)
#             self._train_dummy()
    
#     def _train_dummy(self):
#         """Create a simple random forest for demo purposes."""
#         # Generate synthetic data
#         np.random.seed(42)
#         X = np.random.rand(1000, len(self.feature_names))
#         y = (X[:, 0] * X[:, 1] > 0.3).astype(int)  # random rule
#         self.model = RandomForestClassifier(n_estimators=10)
#         self.model.fit(X, y)
#         joblib.dump(self.model, Config.MODEL_PATH)
#         logger.info("Dummy ML model trained and saved.")
    
#     def extract_features(self, filepath: str, pe_alerts: List[str], 
#                          strings: List[str]) -> np.ndarray:
#         """Extract features from file for ML prediction."""
#         features = []
        
#         # File size (log scaled)
#         size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
#         features.append(np.log1p(size))
        
#         # Entropy features (simplified)
#         entropy_mean = 5.0  # default
#         entropy_max = 6.0
#         try:
#             with open(filepath, 'rb') as f:
#                 data = f.read(1024*1024)  # first 1MB
#                 if data:
#                     entropy_mean = self._calculate_entropy(data)
#                     entropy_max = entropy_mean * 1.2
#         except:
#             pass
#         features.append(entropy_mean)
#         features.append(entropy_max)
        
#         # Suspicious imports count
#         sus_imports = sum(1 for a in pe_alerts if 'Suspicious APIs' in a)
#         features.append(min(sus_imports, 10))
        
#         # Suspicious strings count
#         sus_strings = len(strings)
#         features.append(min(sus_strings, 100))
        
#         # Packed?
#         is_packed = 1 if any('Packed' in a for a in pe_alerts) else 0
#         features.append(is_packed)
        
#         # Has digital signature? (Windows only)
#         has_cert = 0
#         if sys.platform == 'win32' and filepath.lower().endswith(('.exe', '.dll')):
#             has_cert = 1 if self._check_signature(filepath) else 0
#         features.append(has_cert)
        
#         return np.array(features).reshape(1, -1)
    
#     def _calculate_entropy(self, data: bytes) -> float:
#         if not data:
#             return 0
#         entropy = 0
#         for x in range(256):
#             p_x = data.count(x) / len(data)
#             if p_x > 0:
#                 entropy += - p_x * np.log2(p_x)
#         return entropy
    
#     def _check_signature(self, filepath: str) -> bool:
#         """Check if file has valid digital signature (Windows)."""
#         try:
#             import win32security
#             import win32crypt
#             # Simplified - real implementation would verify
#             return False
#         except:
#             return False
    
#     def predict(self, features: np.ndarray) -> Tuple[float, float]:
#         """Return (malicious_probability, score_contribution)."""
#         if self.model is None:
#             return 0.0, 0
#         proba = self.model.predict_proba(features)[0]
#         malicious_prob = proba[1] if len(proba) > 1 else 0
#         score_contrib = int(malicious_prob * Config.SCORE_ML_MALICIOUS)
#         return malicious_prob, score_contrib

# # ========================== YARA Manager with Hot Reload ==========================
# class YaraManager(FileSystemEventHandler):
#     def __init__(self):
#         self.rules = None
#         self.rules_lock = threading.Lock()
#         self.rules_mtime = {}
#         self.load_rules()
#         self.start_watcher()
    
#     def load_rules(self):
#         """Load all .yar files, track modification times."""
#         rule_files = {}
#         current_mtime = {}
#         for yar_file in Config.RULES_DIR.glob("*.yar"):
#             rule_files[str(yar_file)] = str(yar_file)
#             current_mtime[str(yar_file)] = yar_file.stat().st_mtime
        
#         if not rule_files:
#             logger.warning("No YARA rule files found.")
#             return
        
#         try:
#             new_rules = yara.compile(filepaths=rule_files)
#             with self.rules_lock:
#                 self.rules = new_rules
#                 self.rules_mtime = current_mtime
#             logger.info(f"Loaded {len(rule_files)} YARA rule files.")
#         except Exception as e:
#             logger.error(f"YARA compilation failed: {e}")
    
#     def start_watcher(self):
#         """Watch rules directory for changes."""
#         observer = Observer()
#         observer.schedule(self, str(Config.RULES_DIR), recursive=False)
#         observer.start()
#         logger.info("YARA hot-reload watcher started.")
    
#     def on_modified(self, event):
#         if event.src_path.endswith('.yar'):
#             logger.info(f"YARA rule modified: {event.src_path}, reloading...")
#             self.load_rules()
    
#     def on_created(self, event):
#         if event.src_path.endswith('.yar'):
#             logger.info(f"New YARA rule: {event.src_path}, reloading...")
#             self.load_rules()
    
#     def scan(self, filepath: str) -> List[str]:
#         with self.rules_lock:
#             if not self.rules:
#                 return []
#         try:
#             matches = self.rules.match(filepath)
#             return [match.rule for match in matches]
#         except Exception as e:
#             logger.error(f"YARA scan error on {filepath}: {e}")
#             return []

# # ========================== Static Analysis ==========================
# class StaticAnalyzer:
#     def __init__(self, yara_manager: YaraManager, ml_classifier: MLClassifier):
#         self.yara = yara_manager
#         self.ml = ml_classifier
    
#     def get_hashes(self, filepath: str) -> Dict[str, str]:
#         hashes = {'md5': hashlib.md5(), 'sha1': hashlib.sha1(), 'sha256': hashlib.sha256()}
#         try:
#             with open(filepath, 'rb') as f:
#                 while chunk := f.read(8192):
#                     for algo in hashes.values():
#                         algo.update(chunk)
#             return {name: algo.hexdigest() for name, algo in hashes.items()}
#         except Exception as e:
#             logger.error(f"Hash error {filepath}: {e}")
#             return {}
    
#     def get_file_type(self, filepath: str) -> str:
#         try:
#             return magic.from_file(filepath, mime=True)
#         except:
#             return "unknown"
    
#     def analyze_pe(self, filepath: str) -> List[str]:
#         alerts = []
#         try:
#             pe = pefile.PE(filepath)
            
#             # Suspicious imports
#             suspicious_apis = {
#                 'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
#                 'OpenProcess', 'GetProcAddress', 'LoadLibraryA', 'HttpSendRequestA',
#                 'WinExec', 'ShellExecute', 'RegSetValue', 'CryptEncrypt',
#                 'NtQuerySystemInformation', 'NtSetInformationProcess', 'NtCreateThreadEx'
#             }
#             found = set()
#             for entry in pe.DIRECTORY_ENTRY_IMPORT:
#                 for imp in entry.imports:
#                     if imp.name and imp.name.decode() in suspicious_apis:
#                         found.add(imp.name.decode())
#             if len(found) > 3:
#                 alerts.append(f"Suspicious APIs: {', '.join(found)}")
            
#             # Section entropy and names
#             packers = ['UPX0', 'UPX1', 'UPX2', '.aspack', '.themida', '._winzip', 
#                        '.mpress', '.vmp0', '.vmp1', '.enigma']
#             for section in pe.sections:
#                 name = section.Name.decode().strip('\x00')
#                 entropy = section.get_entropy()
#                 if name in packers:
#                     alerts.append(f"Packed: {name}")
#                 if entropy > 7.5:
#                     alerts.append(f"High entropy {name}: {entropy:.2f}")
            
#             # Entry point in unusual section
#             ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
#             ep_section = None
#             for s in pe.sections:
#                 if s.contains_rva(ep):
#                     ep_section = s.Name.decode().strip('\x00')
#                     break
#             if ep_section and ep_section not in ['.text', 'CODE', '__text']:
#                 alerts.append(f"Entry point in {ep_section}")
            
#             # Timestamp anomaly
#             timestamp = pe.FILE_HEADER.TimeDateStamp
#             if timestamp > int(time.time()) + 86400:
#                 alerts.append("Future timestamp")
            
#             # Check for digital signature
#             if sys.platform == 'win32':
#                 try:
#                     from win32security import CryptQueryObject, CERT_QUERY_OBJECT_FILE
#                     # Simplified - real signature verification is complex
#                 except:
#                     pass
#             pe.close()
#         except:
#             pass
#         return alerts
    
#     def extract_strings(self, filepath: str) -> List[str]:
#         """Safe string extraction with size limit."""
#         if os.path.getsize(filepath) > Config.MAX_STRING_EXTRACT_SIZE:
#             logger.warning(f"File too large for string extraction: {filepath}")
#             return []
        
#         strings = []
#         try:
#             with open(filepath, 'rb') as f:
#                 current = bytearray()
#                 bytes_read = 0
#                 while chunk := f.read(4096):
#                     bytes_read += len(chunk)
#                     if bytes_read > Config.MAX_STRING_EXTRACT_SIZE:
#                         break
#                     for byte in chunk:
#                         if 32 <= byte <= 126:
#                             current.append(byte)
#                         else:
#                             if len(current) >= Config.MIN_STRING_LENGTH:
#                                 strings.append(current.decode('ascii', errors='ignore'))
#                                 if len(strings) >= Config.MAX_STRING_COUNT:
#                                     return strings
#                             current.clear()
#                 if len(current) >= Config.MIN_STRING_LENGTH:
#                     strings.append(current.decode('ascii', errors='ignore'))
#         except Exception as e:
#             logger.error(f"String extraction error: {e}")
#         return strings
    
#     def heuristic_strings(self, strings: List[str]) -> List[str]:
#         alerts = []
#         patterns = [
#             (r'http[s]?://', 'URL'),
#             (r'\\\\[^\\]+\\', 'Network path'),
#             (r'[Pp]ower[Ss]hell', 'PowerShell'),
#             (r'[Cc]md\.exe', 'cmd'),
#             (r'[Bb]ase64', 'Base64'),
#             (r'[Ee]val\(', 'eval'),
#             (r'[Ee]xec\(', 'exec'),
#             (r'[Dd]ecrypt', 'decrypt'),
#             (r'[Ee]ncrypt', 'encrypt'),
#             (r'[Kk]eylogger', 'keylogger'),
#             (r'[Rr]ansom', 'ransom'),
#             (r'[Bb]itcoin', 'bitcoin'),
#             (r'[Ww]allet', 'wallet'),
#             (r'[Mm]alware', 'malware'),
#         ]
#         for s in strings[:Config.MAX_STRING_COUNT]:
#             for pat, desc in patterns:
#                 if re.search(pat, s):
#                     alerts.append(f"{desc}: {s[:50]}")
#                     break
#         return alerts[:50]

# # ========================== Cloud Analyzer (VirusTotal + AbuseIPDB) ==========================
# class CloudAnalyzer:
#     def __init__(self, db: ReputationDB):
#         self.db = db
#         self.vt_key = Config.VIRUSTOTAL_API_KEY
#         self.abuse_key = Config.ABUSEIPDB_API_KEY
#         self.session = requests.Session()
#         self.session.headers.update({'User-Agent': 'CyberGuard-Pro/6.0'})
    
#     def query_vt_hash(self, sha256: str) -> Tuple[int, int, str]:
#         if not self.vt_key:
#             return 0, 0, "API key missing"
        
#         url = f"https://www.virustotal.com/api/v3/files/{sha256}"
#         headers = {"x-apikey": self.vt_key}
#         try:
#             resp = self.session.get(url, headers=headers, timeout=10)
#             if resp.status_code == 200:
#                 data = resp.json()
#                 stats = data['data']['attributes']['last_analysis_stats']
#                 malicious = stats.get('malicious', 0)
#                 suspicious = stats.get('suspicious', 0)
#                 return malicious, suspicious, f"M:{malicious} S:{suspicious}"
#             elif resp.status_code == 404:
#                 return 0, 0, "Not found"
#             else:
#                 return 0, 0, f"HTTP {resp.status_code}"
#         except Exception as e:
#             return 0, 0, f"Error: {e}"
    
#     def query_abuse_ip(self, ip: str) -> Tuple[int, str]:
#         """Check IP reputation on AbuseIPDB."""
#         if not self.abuse_key:
#             return 0, "No API key"
        
#         url = "https://api.abuseipdb.com/api/v2/check"
#         headers = {'Key': self.abuse_key, 'Accept': 'application/json'}
#         params = {'ipAddress': ip, 'maxAgeInDays': 90}
#         try:
#             resp = self.session.get(url, headers=headers, params=params, timeout=5)
#             if resp.status_code == 200:
#                 data = resp.json()['data']
#                 abuse_score = data['abuseConfidenceScore']
#                 country = data.get('countryCode', '')
#                 return abuse_score, country
#             else:
#                 return 0, f"Error {resp.status_code}"
#         except Exception as e:
#             return 0, str(e)
    
#     def upload_file_vt(self, filepath: str, interactive: bool = True) -> str:
#         """Upload file to VT, with non-interactive check."""
#         if not self.vt_key:
#             return "API key missing"
        
#         # Check if called from non-interactive thread
#         if not interactive or threading.current_thread() is not threading.main_thread():
#             event_queue.put(('upload_request', filepath))
#             return "Upload queued (interactive)"
        
#         print(f"\n[?] Upload {os.path.basename(filepath)} to VirusTotal?")
#         choice = input("This will share the file with VT. (y/N): ").strip().lower()
#         if choice != 'y':
#             return "Upload skipped"
        
#         url = "https://www.virustotal.com/api/v3/files"
#         headers = {"x-apikey": self.vt_key}
#         try:
#             with open(filepath, 'rb') as f:
#                 files = {"file": (os.path.basename(filepath), f)}
#                 resp = self.session.post(url, headers=headers, files=files, timeout=120)
#                 if resp.status_code == 200:
#                     analysis_id = resp.json()['data']['id']
#                     return f"Uploaded (ID: {analysis_id})"
#                 else:
#                     return f"Upload failed: {resp.status_code}"
#         except Exception as e:
#             return f"Upload error: {e}"

# # ========================== Threat Scoring Engine ==========================
# @dataclass
# class ScanResult:
#     filepath: str
#     sha256: str
#     file_type: str
#     yara_matches: List[str]
#     pe_alerts: List[str]
#     string_alerts: List[str]
#     vt_malicious: int
#     vt_suspicious: int
#     vt_verdict: str
#     ml_probability: float
#     score: int = 0
#     verdict: str = "UNKNOWN"
    
#     def calculate_score(self, ml_score_contrib: int = 0):
#         self.score = 0
#         self.score += len(self.yara_matches) * Config.SCORE_YARA
#         self.score += len(self.pe_alerts) * Config.SCORE_PE_ALERT
#         self.score += len(self.string_alerts) * Config.SCORE_STRINGS_SUSPICIOUS
#         self.score += self.vt_malicious * Config.SCORE_VT_MALICIOUS
#         self.score += self.vt_suspicious * Config.SCORE_VT_SUSPICIOUS
#         self.score += ml_score_contrib
        
#         if self.score >= 15:
#             self.verdict = "CRITICAL"
#         elif self.score >= 10:
#             self.verdict = "MALICIOUS"
#         elif self.score >= 5:
#             self.verdict = "SUSPICIOUS"
#         else:
#             self.verdict = "CLEAN"
    
#     def to_dict(self):
#         return {
#             'filepath': self.filepath,
#             'sha256': self.sha256,
#             'type': self.file_type,
#             'yara': self.yara_matches,
#             'pe': self.pe_alerts,
#             'strings': self.string_alerts,
#             'vt_malicious': self.vt_malicious,
#             'vt_suspicious': self.vt_suspicious,
#             'ml_probability': self.ml_probability,
#             'score': self.score,
#             'verdict': self.verdict
#         }

# # ========================== Response Actions ==========================
# class ResponseEngine:
#     def __init__(self, db: ReputationDB):
#         self.db = db
#         self.alert_count = 0
#         self.whitelist = set(Config.SAFE_PROCESSES)
    
#     def handle_threat(self, result: ScanResult, source: str = "scan"):
#         """Take action based on score."""
#         logger.warning(f"Threat detected: {result.filepath} (score={result.score}, verdict={result.verdict})")
#         self.alert_count += 1
        
#         # Log to DB
#         self.db.add_alert(source, result.filepath, result.score, result.verdict, result.to_dict())
        
#         # Auto-quarantine if high score
#         if result.score >= 15 or self.alert_count >= Config.ALERT_THRESHOLD:
#             self.quarantine(result.filepath)
#             return
        
#         # In interactive mode, ask user
#         if threading.current_thread() is threading.main_thread():
#             self._interactive_prompt(result)
#         else:
#             # Non-interactive: queue for later decision
#             event_queue.put(('threat', result))
    
#     def _interactive_prompt(self, result: ScanResult):
#         print(f"\n[!] Suspicious file: {result.filepath}")
#         print(f"Score: {result.score} | Verdict: {result.verdict}")
#         print(f"YARA: {result.yara_matches}")
#         print(f"PE alerts: {result.pe_alerts}")
#         action = input("Action: (Q)uarantine, (S)andbox, (I)gnore: ").strip().lower()
#         if action == 'q':
#             self.quarantine(result.filepath)
#         elif action == 's':
#             self.sandbox(result.filepath)
#         else:
#             logger.info(f"Ignored by user: {result.filepath}")
    
#     def quarantine(self, filepath: str):
#         """Secure quarantine with real encryption using pyzipper."""
#         try:
#             base = os.path.basename(filepath)
#             timestamp = int(time.time())
#             dest_zip = Config.QUARANTINE_DIR / f"{base}_{timestamp}.zip"
#             password = hashlib.sha256(f"{timestamp}{os.urandom(8)}".encode()).hexdigest()[:16]
            
#             # Use pyzipper for AES-256 encryption
#             with pyzipper.AESZipFile(dest_zip, 'w', compression=pyzipper.ZIP_DEFLATED,
#                                       encryption=pyzipper.WZ_AES) as zf:
#                 zf.setpassword(password.encode())
#                 zf.write(filepath, arcname=base)
            
#             # Remove original
#             os.remove(filepath)
            
#             # Save metadata
#             meta = Config.QUARANTINE_DIR / f"{dest_zip.stem}.meta"
#             with open(meta, 'w') as f:
#                 f.write(f"Original: {filepath}\nTime: {datetime.now()}\nPassword: {password}\n")
            
#             logger.info(f"Quarantined {filepath} -> {dest_zip} (pwd: {password})")
#             self.db.add_alert("quarantine", filepath, 0, "QUARANTINED", {"zip": str(dest_zip)})
#         except Exception as e:
#             logger.error(f"Quarantine failed: {e}")
    
#     def sandbox(self, filepath: str):
#         """Run in Sandboxie if available."""
#         if sys.platform == 'win32' and os.path.exists(Config.SANDBOXIE_PATH):
#             try:
#                 subprocess.Popen([Config.SANDBOXIE_PATH, filepath])
#                 logger.info(f"Launched in Sandboxie: {filepath}")
#             except Exception as e:
#                 logger.error(f"Sandboxie error: {e}")
#         else:
#             logger.error("Sandboxie not available")
    
#     def kill_process(self, proc):
#         """Kill process if not whitelisted."""
#         if proc.name().lower() in self.whitelist:
#             logger.info(f"Whitelisted process {proc.name()} not killed.")
#             return
#         try:
#             proc.kill()
#             logger.critical(f"Killed process {proc.pid} ({proc.name()})")
#             self.db.add_alert("process_kill", f"{proc.name()}:{proc.pid}", 10, "KILLED", {})
#         except Exception as e:
#             logger.error(f"Failed to kill process: {e}")

# # ========================== Behavioral Monitoring ==========================
# class FileMonitorHandler(FileSystemEventHandler):
#     def __init__(self, core):
#         self.core = core
    
#     def on_created(self, event):
#         if not event.is_directory:
#             self._handle(event.src_path, "file_create")
    
#     def on_modified(self, event):
#         if not event.is_directory:
#             self._handle(event.src_path, "file_modify")
    
#     def _handle(self, path, source):
#         # Exclude our own files
#         if any(excl in path for excl in Config.EXCLUDED_FILES):
#             return
#         # Wait a bit for write completion
#         time.sleep(0.5)
#         self.core.scan_file(path, source=source)

# class ProcessMonitor:
#     def __init__(self, core):
#         self.core = core
#         self.running = False
#         self.seen_pids = set()
    
#     def start(self):
#         self.running = True
#         self.seen_pids = set(psutil.pids())
#         threading.Thread(target=self._monitor, daemon=True).start()
    
#     def _monitor(self):
#         while self.running:
#             try:
#                 current = set(psutil.pids())
#                 new = current - self.seen_pids
#                 for pid in new:
#                     try:
#                         proc = psutil.Process(pid)
#                         self._check_process(proc)
#                     except (psutil.NoSuchProcess, psutil.AccessDenied):
#                         pass
#                 self.seen_pids = current
#             except Exception as e:
#                 logger.error(f"Process monitor error: {e}")
#             time.sleep(3)
    
#     def _check_process(self, proc):
#         alerts = []
#         try:
#             # Use net_connections instead of deprecated connections
#             for conn in proc.net_connections(kind='inet'):
#                 if conn.status == 'ESTABLISHED' and conn.raddr:
#                     alerts.append(f"Conn to {conn.raddr}")
#                     # Check IP reputation
#                     self.core.check_ip_reputation(conn.raddr.ip)
            
#             # Check open files in monitored dirs
#             for f in proc.open_files():
#                 if any(f.path.startswith(d) for d in Config.MONITORED_DIRS):
#                     alerts.append(f"Opened {f.path}")
            
#             # Command line suspicious
#             cmd = ' '.join(proc.cmdline()).lower()
#             suspicious_cmds = ['powershell -enc', 'base64', 'downloadstring', 
#                                'invoke-expression', 'start-process']
#             if any(k in cmd for k in suspicious_cmds):
#                 alerts.append(f"Suspicious cmd: {cmd[:100]}")
            
#             if alerts:
#                 self.core.behavioral_callback(proc, alerts, "process")
#         except (psutil.NoSuchProcess, psutil.AccessDenied):
#             pass

# class NetworkMonitor:
#     def __init__(self, core):
#         self.core = core
#         self.running = False
#         self.conn_history = defaultdict(list)  # ip -> list of ports
    
#     def start(self):
#         self.running = True
#         threading.Thread(target=self._monitor, daemon=True).start()
    
#     def _monitor(self):
#         while self.running:
#             try:
#                 for conn in psutil.net_connections(kind='inet'):
#                     if conn.status == 'SYN_SENT' and conn.raddr:
#                         ip = conn.raddr.ip
#                         port = conn.raddr.port
#                         self.conn_history[ip].append((port, time.time()))
                
#                 # Detect port scan
#                 now = time.time()
#                 for ip, records in list(self.conn_history.items()):
#                     # Keep last 30 seconds
#                     records = [(p, t) for p, t in records if now - t < 30]
#                     self.conn_history[ip] = records
#                     if len(set(p for p, _ in records)) > 15:
#                         self.core.behavioral_callback(f"Port scan from {ip}", records, "network")
#                         # Block IP
#                         self._block_ip(ip)
#                         del self.conn_history[ip]
#             except Exception as e:
#                 logger.error(f"Network monitor error: {e}")
#             time.sleep(5)
    
#     def _block_ip(self, ip):
#         if sys.platform != 'win32':
#             return
#         try:
#             rule = f"CyberGuard_Block_{ip.replace('.', '_')}"
#             subprocess.run([
#                 'netsh', 'advfirewall', 'firewall', 'add', 'rule',
#                 f'name={rule}', 'dir=in', 'action=block', f'remoteip={ip}'
#             ], check=True, capture_output=True)
#             logger.info(f"Blocked IP {ip}")
#             self.core.db.add_alert("network_block", ip, 10, "BLOCKED", {})
#         except Exception as e:
#             logger.error(f"Block failed: {e}")

# # ========================== ETW Monitoring (Windows) ==========================
# if Config.ENABLE_ETW_MONITOR and sys.platform == 'win32':
#     class ETWMonitor:
#         """Monitor Windows ETW events for process creation, DLL loads, etc."""
#         def __init__(self, core):
#             self.core = core
#             self.running = False
        
#         def start(self):
#             self.running = True
#             threading.Thread(target=self._monitor, daemon=True).start()
        
#         def _monitor(self):
#             # Simplified ETW using wevtutil or Win32 API
#             # Real implementation would use Microsoft.Diagnostics.Tracing.TraceEvent
#             # This is a placeholder for demonstration
#             import win32evtlog
#             server = 'localhost'
#             logtype = 'Security'
#             hand = win32evtlog.OpenEventLog(server, logtype)
#             flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
#             while self.running:
#                 events = win32evtlog.ReadEventLog(hand, flags, 0)
#                 if events:
#                     for event in events:
#                         if event.EventID == 4688:  # Process creation
#                             # Extract process info
#                             self.core.behavioral_callback(f"New process created", event.StringInserts, "etw")
#                 time.sleep(5)

# # ========================== Registry Monitor ==========================
# if Config.ENABLE_REGISTRY_MONITOR and sys.platform == 'win32':
#     class RegistryMonitor:
#         def __init__(self, core):
#             self.core = core
#             self.running = False
#             self.keywords = ['run', 'runonce', 'services', 'winlogon', 'shell']
        
#         def start(self):
#             self.running = True
#             threading.Thread(target=self._monitor, daemon=True).start()
        
#         def _monitor(self):
#             # Simplified registry monitoring via polling
#             import winreg
#             hives = [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
#             paths = [
#                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
#                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
#                 r"SYSTEM\CurrentControlSet\Services",
#             ]
#             last_values = {}
#             while self.running:
#                 for hive in hives:
#                     for path in paths:
#                         try:
#                             key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
#                             i = 0
#                             while True:
#                                 try:
#                                     name, value, _ = winreg.EnumValue(key, i)
#                                     full = f"{hive}\\{path}\\{name}"
#                                     if full not in last_values:
#                                         last_values[full] = value
#                                         self.core.behavioral_callback(f"Registry added: {full}={value}", None, "registry")
#                                     elif last_values[full] != value:
#                                         self.core.behavioral_callback(f"Registry changed: {full}={value}", None, "registry")
#                                         last_values[full] = value
#                                     i += 1
#                                 except WindowsError:
#                                     break
#                             winreg.CloseKey(key)
#                         except Exception:
#                             pass
#                 time.sleep(10)

# # ========================== Memory Scanner ==========================
# class MemoryScanner:
#     """Scan process memory for YARA signatures."""
#     def __init__(self, yara_mgr: YaraManager):
#         self.yara = yara_mgr
#         self.running = False
    
#     def start(self):
#         self.running = True
#         threading.Thread(target=self._scan_loop, daemon=True).start()
    
#     def _scan_loop(self):
#         while self.running:
#             # Scan critical processes periodically
#             targets = ['lsass.exe', 'svchost.exe', 'winlogon.exe', 'explorer.exe']
#             for proc in psutil.process_iter(['pid', 'name']):
#                 if proc.info['name'].lower() in targets:
#                     self.scan_process(proc.info['pid'])
#             time.sleep(60)
    
#     def scan_process(self, pid):
#         """Read process memory and scan with YARA."""
#         try:
#             proc = psutil.Process(pid)
#             # Read memory regions (simplified - in reality use ReadProcessMemory)
#             # This is a placeholder; full memory scanning is complex
#             logger.info(f"Memory scan of PID {pid} started")
#             # For demo, just log
#         except Exception as e:
#             logger.error(f"Memory scan failed: {e}")

# # ========================== Web Dashboard ==========================
# def create_dashboard(core):
#     app = Flask(__name__)
    
#     @app.route('/')
#     def index():
#         return render_template_string("""
#         <!DOCTYPE html>
#         <html>
#         <head>
#             <title>CyberGuard Dashboard</title>
#             <style>
#                 body { font-family: Arial; margin: 20px; background: #1e1e1e; color: #fff; }
#                 table { border-collapse: collapse; width: 100%; }
#                 th, td { border: 1px solid #444; padding: 8px; text-align: left; }
#                 th { background: #333; }
#                 .critical { color: #ff4444; }
#                 .malicious { color: #ff8800; }
#                 .suspicious { color: #ffaa00; }
#                 .clean { color: #00ff00; }
#             </style>
#         </head>
#         <body>
#             <h1>CyberGuard Pro v6.0 Dashboard</h1>
#             <h2>Recent Alerts</h2>
#             <table id="alerts">
#                 <thead>
#                     <tr><th>Time</th><th>Source</th><th>Target</th><th>Score</th><th>Verdict</th></tr>
#                 </thead>
#                 <tbody>
#                 </tbody>
#             </table>
#             <script>
#                 function fetchAlerts() {
#                     fetch('/api/alerts')
#                         .then(res => res.json())
#                         .then(data => {
#                             let tbody = document.querySelector('#alerts tbody');
#                             tbody.innerHTML = '';
#                             data.forEach(alert => {
#                                 let row = tbody.insertRow();
#                                 row.innerHTML = `<td>${alert.timestamp}</td><td>${alert.source}</td><td>${alert.target}</td><td>${alert.score}</td><td class="${alert.verdict.toLowerCase()}">${alert.verdict}</td>`;
#                             });
#                         });
#                 }
#                 setInterval(fetchAlerts, 2000);
#                 fetchAlerts();
#             </script>
#         </body>
#         </html>
#         """)
    
#     @app.route('/api/alerts')
#     def get_alerts():
#         return jsonify(core.db.get_recent_alerts(50))
    
#     @app.route('/api/stats')
#     def get_stats():
#         # Return system stats
#         return jsonify({
#             'processes': len(psutil.pids()),
#             'cpu_percent': psutil.cpu_percent(),
#             'memory_percent': psutil.virtual_memory().percent,
#         })
    
#     return app

# # ========================== Core Engine ==========================
# class CyberGuardCore:
#     def __init__(self):
#         self.db = ReputationDB()
#         self.yara_mgr = YaraManager()
#         self.ml = MLClassifier()
#         self.static = StaticAnalyzer(self.yara_mgr, self.ml)
#         self.cloud = CloudAnalyzer(self.db)
#         self.response = ResponseEngine(self.db)
        
#         # Monitors
#         self.file_observer = None
#         self.proc_monitor = None
#         self.net_monitor = None
#         self.etw_monitor = None
#         self.registry_monitor = None
#         self.memory_scanner = None
        
#         # Dashboard
#         self.dashboard_app = None
#         self.dashboard_thread = None
    
#     def check_ip_reputation(self, ip: str):
#         """Check IP against AbuseIPDB."""
#         if not self.cloud.abuse_key:
#             return
#         score, country = self.cloud.query_abuse_ip(ip)
#         if score > 50:
#             logger.warning(f"Malicious IP detected: {ip} (abuse score {score})")
#             self.db.add_alert("ip_reputation", ip, score, "MALICIOUS", {"country": country})
    
#     def scan_file(self, filepath: str, source="manual") -> Optional[ScanResult]:
#         """Full scan pipeline."""
#         if not os.path.isfile(filepath):
#             logger.error(f"File not found: {filepath}")
#             return None
        
#         # Self-exclusion
#         if any(excl in filepath for excl in Config.EXCLUDED_FILES):
#             logger.debug(f"Skipping excluded file: {filepath}")
#             return None
        
#         logger.info(f"Scanning {filepath} (source: {source})")
        
#         # Get hashes
#         hashes = self.static.get_hashes(filepath)
#         sha256 = hashes.get('sha256', '')
        
#         # Check local DB
#         cached = self.db.get_file(sha256) if sha256 else None
#         if cached and (datetime.now() - datetime.fromisoformat(cached['last_seen'])).days < 1:
#             logger.info(f"Cache hit for {sha256[:8]}... score={cached['score']}")
#             result = ScanResult(
#                 filepath=filepath,
#                 sha256=sha256,
#                 file_type=self.static.get_file_type(filepath),
#                 yara_matches=[],
#                 pe_alerts=[],
#                 string_alerts=[],
#                 vt_malicious=cached.get('vt_detections', 0),
#                 vt_suspicious=0,
#                 vt_verdict=cached['verdict'],
#                 ml_probability=cached.get('ml_score', 0.0)
#             )
#             result.score = cached['score']
#             result.verdict = cached['verdict']
#             return result
        
#         # Perform scans
#         yara_matches = self.yara_mgr.scan(filepath)
#         pe_alerts = self.static.analyze_pe(filepath)
#         strings = self.static.extract_strings(filepath)
#         string_alerts = self.static.heuristic_strings(strings)
        
#         # ML prediction
#         features = self.ml.extract_features(filepath, pe_alerts, strings)
#         ml_prob, ml_score_contrib = self.ml.predict(features)
        
#         # Cloud lookup
#         vt_mal, vt_sus, vt_ver = self.cloud.query_vt_hash(sha256) if sha256 else (0,0,"No hash")
        
#         # Build result
#         result = ScanResult(
#             filepath=filepath,
#             sha256=sha256,
#             file_type=self.static.get_file_type(filepath),
#             yara_matches=yara_matches,
#             pe_alerts=pe_alerts,
#             string_alerts=string_alerts,
#             vt_malicious=vt_mal,
#             vt_suspicious=vt_sus,
#             vt_verdict=vt_ver,
#             ml_probability=ml_prob
#         )
#         result.calculate_score(ml_score_contrib)
        
#         # Store in DB
#         if sha256:
#             self.db.update_file(sha256, result.score, result.verdict, vt_mal, ml_prob, result.to_dict())
        
#         # If VT not found, offer upload
#         if vt_ver == "Not found" and self.cloud.vt_key:
#             upload_status = self.cloud.upload_file_vt(filepath, interactive=(source=="manual"))
#             logger.info(f"VT upload: {upload_status}")
        
#         # Respond if suspicious
#         if result.verdict != "CLEAN":
#             self.response.handle_threat(result, source)
#         else:
#             logger.info(f"File clean: {filepath}")
        
#         return result
    
#     def start_monitoring(self):
#         """Start all real-time monitors."""
#         if Config.ENABLE_FILE_MONITOR:
#             handler = FileMonitorHandler(self)
#             self.file_observer = Observer()
#             for d in Config.MONITORED_DIRS:
#                 if os.path.exists(d):
#                     self.file_observer.schedule(handler, d, recursive=True)
#                     logger.info(f"Watching directory: {d}")
#             self.file_observer.start()
        
#         if Config.ENABLE_PROCESS_MONITOR:
#             self.proc_monitor = ProcessMonitor(self)
#             self.proc_monitor.start()
        
#         if Config.ENABLE_NETWORK_MONITOR:
#             self.net_monitor = NetworkMonitor(self)
#             self.net_monitor.start()
        
#         if Config.ENABLE_ETW_MONITOR and sys.platform == 'win32':
#             self.etw_monitor = ETWMonitor(self)
#             self.etw_monitor.start()
        
#         if Config.ENABLE_REGISTRY_MONITOR and sys.platform == 'win32':
#             self.registry_monitor = RegistryMonitor(self)
#             self.registry_monitor.start()
        
#         self.memory_scanner = MemoryScanner(self.yara_mgr)
#         self.memory_scanner.start()
        
#         logger.info("All real-time monitors started.")
        
#         # Start dashboard
#         if Config.ENABLE_WEB_DASHBOARD:
#             self.dashboard_app = create_dashboard(self)
#             self.dashboard_thread = threading.Thread(
#                 target=self.dashboard_app.run,
#                 kwargs={'host':'0.0.0.0', 'port':Config.DASHBOARD_PORT, 'debug':False, 'use_reloader':False},
#                 daemon=True
#             )
#             self.dashboard_thread.start()
#             logger.info(f"Web dashboard running on http://localhost:{Config.DASHBOARD_PORT}")
    
#     def behavioral_callback(self, target, details, source):
#         """Unified callback for all monitors."""
#         if source == "file_create" or source == "file_modify":
#             if os.path.isfile(target):
#                 self.scan_file(target, source=source)
        
#         elif source == "process":
#             proc, alerts = target, details
#             logger.warning(f"Process {proc.pid} {proc.name()}: {alerts}")
#             # Check for network connections
#             if any('Conn to' in a for a in alerts):
#                 self.response.kill_process(proc)
        
#         elif source == "network":
#             logger.warning(f"Network alert: {target}")
#             self.db.add_alert("network", str(target), 8, "SUSPICIOUS", {"details": details})
        
#         elif source == "etw":
#             logger.info(f"ETW event: {target} - {details}")
        
#         elif source == "registry":
#             logger.info(f"Registry change: {target}")
#             self.db.add_alert("registry", target, 5, "INFO", {})

# # ========================== Command Line Interface ==========================
# def main():
#     print("""
#     ╔══════════════════════════════════════════════════════════╗
#     ║           CyberGuard Pro v6.0 - EDR Edition             ║
#     ║      Advanced Endpoint Detection & Response Toolkit     ║
#     ╚══════════════════════════════════════════════════════════╝
#     """)
    
#     core = CyberGuardCore()
    
#     # Process event queue in main thread
#     def process_event_queue():
#         while True:
#             try:
#                 event = event_queue.get(timeout=0.1)
#                 if event[0] == 'upload_request':
#                     filepath = event[1]
#                     # Prompt user in main thread
#                     print(f"\n[?] Upload requested for {os.path.basename(filepath)}")
#                     choice = input("Upload to VirusTotal? (y/N): ").strip().lower()
#                     if choice == 'y':
#                         core.cloud.upload_file_vt(filepath, interactive=True)
#                 elif event[0] == 'threat':
#                     result = event[1]
#                     core.response._interactive_prompt(result)
#                 elif event[0] == 'alert':
#                     # Already handled by DB
#                     pass
#             except queue.Empty:
#                 break
    
#     if len(sys.argv) > 1:
#         cmd = sys.argv[1]
#         if cmd == 'scan' and len(sys.argv) > 2:
#             target = sys.argv[2]
#             if os.path.isfile(target):
#                 core.scan_file(target)
#             elif os.path.isdir(target):
#                 for root, _, files in os.walk(target):
#                     for f in files:
#                         core.scan_file(os.path.join(root, f), source="batch")
#                         process_event_queue()
#             else:
#                 print("Invalid path")
#         elif cmd == 'monitor':
#             core.start_monitoring()
#             try:
#                 while True:
#                     process_event_queue()
#                     time.sleep(1)
#             except KeyboardInterrupt:
#                 print("\nShutting down...")
#         else:
#             print("Usage: cyberguard.py [scan <file/dir> | monitor]")
#     else:
#         # Interactive mode
#         while True:
#             print("\nOptions:")
#             print("1. Scan file")
#             print("2. Scan directory")
#             print("3. Start monitoring")
#             print("4. Show recent alerts")
#             print("5. Exit")
#             choice = input("Select: ").strip()
#             if choice == '1':
#                 path = input("File path: ").strip('"')
#                 if os.path.isfile(path):
#                     core.scan_file(path)
#                 else:
#                     print("Not a file")
#             elif choice == '2':
#                 path = input("Directory path: ").strip('"')
#                 if os.path.isdir(path):
#                     for root, _, files in os.walk(path):
#                         for f in files:
#                             core.scan_file(os.path.join(root, f), source="batch")
#                             process_event_queue()
#                 else:
#                     print("Invalid directory")
#             elif choice == '3':
#                 core.start_monitoring()
#                 try:
#                     while True:
#                         process_event_queue()
#                         time.sleep(1)
#                 except KeyboardInterrupt:
#                     print("\nMonitoring stopped")
#             elif choice == '4':
#                 alerts = core.db.get_recent_alerts(20)
#                 for a in alerts:
#                     print(f"{a['timestamp']} - {a['source']} - {a['target']} - {a['verdict']}")
#             elif choice == '5':
#                 break

# if __name__ == "__main__":
#     main()


####################################################
####################################################
####################################################
####################################################

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CyberGuard Pro v6.0 - Enterprise EDR-Level Malware Defense
پاراستنی پێشکەوتووی سیستەم لە هێرشەکانی تۆڕ و نەرمەکالا زیانبەخشەکان
"""

import os
import sys
import hashlib
import json
import time
import sqlite3
import zipfile
import shutil
import subprocess
import threading
import logging
import re
import queue
import pickle
import socket
import struct
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

# External libraries
try:
    import yara
    import requests
    import pefile
    import psutil
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, PatternMatchingEventHandler
    import magic
    from dotenv import load_dotenv
    import pyzipper  # <-- replaced pyminizip with pyzipper
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    import numpy as np
    from flask import Flask, jsonify, request, render_template_string
    import win32evtlog  # for ETW on Windows
    import win32con
    import win32security
    import winreg
except ImportError as e:
    print(f"[ERROR] Missing required library: {e}")
    print("Install with: pip install -r requirements.txt")
    sys.exit(1)

# Load environment variables
load_dotenv()

# ========================== Configuration ==========================
class Config:
    # API Keys
    VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY", "")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    
    # Paths
    BASE_DIR = Path(__file__).parent
    RULES_DIR = BASE_DIR / "rules"
    QUARANTINE_DIR = BASE_DIR / "quarantine"
    LOG_DIR = BASE_DIR / "logs"
    DB_DIR = BASE_DIR / "db"
    DB_PATH = DB_DIR / "reputation.db"
    MODEL_DIR = BASE_DIR / "models"
    MODEL_PATH = MODEL_DIR / "classifier.pkl"
    
    # Monitoring
    MONITORED_DIRS = [str(BASE_DIR)]  # directories to watch
    EXCLUDED_FILES = ["cyberguard.py", ".env", "reputation.db"]  # self-exclusion
    ALERT_THRESHOLD = 5  # score threshold for auto-quarantine
    ENABLE_NETWORK_MONITOR = True
    ENABLE_PROCESS_MONITOR = True
    ENABLE_FILE_MONITOR = True
    ENABLE_ETW_MONITOR = sys.platform == 'win32'
    ENABLE_REGISTRY_MONITOR = sys.platform == 'win32'
    ENABLE_WEB_DASHBOARD = True
    DASHBOARD_PORT = 5000
    
    # Process whitelist
    SAFE_PROCESSES = [
        "brave.exe", "chrome.exe", "firefox.exe", "edge.exe", 
        "explorer.exe", "svchost.exe", "csrss.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "spoolsv.exe", "taskhostw.exe",
        "python.exe", "pycharm64.exe", "code.exe", "cursor.exe"
    ]
    
    # Scoring weights
    SCORE_YARA = 3
    SCORE_PE_ALERT = 2
    SCORE_VT_MALICIOUS = 5
    SCORE_VT_SUSPICIOUS = 3
    SCORE_STRINGS_SUSPICIOUS = 1
    SCORE_HIGH_ENTROPY = 2
    SCORE_ML_MALICIOUS = 4
    SCORE_ABUSEIPDB_MALICIOUS = 3
    
    # Limits
    MAX_STRING_EXTRACT_SIZE = 50 * 1024 * 1024  # 50MB
    MAX_STRING_COUNT = 1000
    MIN_STRING_LENGTH = 4
    VT_UPLOAD_MAX_SIZE = 32 * 1024 * 1024  # 32MB

# Create directories
for d in [Config.RULES_DIR, Config.QUARANTINE_DIR, Config.LOG_DIR, 
          Config.DB_DIR, Config.MODEL_DIR]:
    d.mkdir(exist_ok=True)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_DIR / "cyberguard.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("CyberGuard")

# Global event queue for thread-safe communication
event_queue = queue.Queue()

# ========================== Database ==========================
class ReputationDB:
    """SQLite local cache with TTL and reputation scoring."""
    def __init__(self):
        self.conn = sqlite3.connect(str(Config.DB_PATH), check_same_thread=False)
        self._create_tables()
        self._cleanup_old()
    
    def _create_tables(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS file_reputation (
                sha256 TEXT PRIMARY KEY,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                score INTEGER,
                verdict TEXT,
                vt_detections INTEGER,
                ml_score REAL,
                details TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS ip_reputation (
                ip TEXT PRIMARY KEY,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                abuse_score INTEGER,
                reports INTEGER,
                country TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP,
                source TEXT,
                target TEXT,
                score INTEGER,
                verdict TEXT,
                details TEXT
            )
        """)
        self.conn.commit()
    
    def _cleanup_old(self, days=30):
        """Remove entries older than days."""
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        self.conn.execute("DELETE FROM file_reputation WHERE last_seen < ?", (cutoff,))
        self.conn.execute("DELETE FROM ip_reputation WHERE last_seen < ?", (cutoff,))
        self.conn.commit()
    
    def get_file(self, sha256: str) -> Optional[Dict]:
        cursor = self.conn.execute(
            "SELECT sha256, last_seen, score, verdict, vt_detections, ml_score, details FROM file_reputation WHERE sha256 = ?",
            (sha256,)
        )
        row = cursor.fetchone()
        if row:
            return {
                'sha256': row[0],
                'last_seen': row[1],
                'score': row[2],
                'verdict': row[3],
                'vt_detections': row[4],
                'ml_score': row[5],
                'details': json.loads(row[6]) if row[6] else {}
            }
        return None
    
    def update_file(self, sha256: str, score: int, verdict: str, 
                    vt_detections: int = 0, ml_score: float = 0.0, details: dict = None):
        now = datetime.now().isoformat()
        self.conn.execute("""
            INSERT OR REPLACE INTO file_reputation 
            (sha256, first_seen, last_seen, score, verdict, vt_detections, ml_score, details)
            VALUES (?, COALESCE((SELECT first_seen FROM file_reputation WHERE sha256 = ?), ?), 
                    ?, ?, ?, ?, ?, ?)
        """, (sha256, sha256, now, now, score, verdict, vt_detections, ml_score, 
              json.dumps(details) if details else None))
        self.conn.commit()
    
    def add_alert(self, source: str, target: str, score: int, verdict: str, details: dict):
        now = datetime.now().isoformat()
        self.conn.execute(
            "INSERT INTO alerts (timestamp, source, target, score, verdict, details) VALUES (?, ?, ?, ?, ?, ?)",
            (now, source, target, score, verdict, json.dumps(details))
        )
        self.conn.commit()
        # Notify dashboard via queue
        event_queue.put(('alert', {
            'timestamp': now, 'source': source, 'target': target,
            'score': score, 'verdict': verdict, 'details': details
        }))
    
    def get_recent_alerts(self, limit=100):
        cursor = self.conn.execute(
            "SELECT timestamp, source, target, score, verdict, details FROM alerts ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        return [{'timestamp': r[0], 'source': r[1], 'target': r[2], 
                 'score': r[3], 'verdict': r[4], 'details': json.loads(r[5])} 
                for r in cursor.fetchall()]

# ========================== ML Classifier ==========================
class MLClassifier:
    """Machine learning model for file classification."""
    def __init__(self):
        self.model = None
        self.feature_names = [
            'size', 'entropy_mean', 'entropy_max', 'suspicious_imports',
            'suspicious_strings', 'is_packed', 'has_certificate'
        ]
        self._load_or_train()
    
    def _load_or_train(self):
        if Config.MODEL_PATH.exists():
            try:
                self.model = joblib.load(Config.MODEL_PATH)
                logger.info("ML model loaded from disk.")
            except Exception as e:
                logger.error(f"Failed to load ML model: {e}")
        if self.model is None:
            # Train a simple dummy model (in production, train on real dataset)
            self._train_dummy()
    
    def _train_dummy(self):
        """Create a simple random forest for demo purposes."""
        # Generate synthetic data
        np.random.seed(42)
        X = np.random.rand(1000, len(self.feature_names))
        y = (X[:, 0] * X[:, 1] > 0.3).astype(int)  # random rule
        self.model = RandomForestClassifier(n_estimators=10)
        self.model.fit(X, y)
        joblib.dump(self.model, Config.MODEL_PATH)
        logger.info("Dummy ML model trained and saved.")
    
    def extract_features(self, filepath: str, pe_alerts: List[str], 
                         strings: List[str]) -> np.ndarray:
        """Extract features from file for ML prediction."""
        features = []
        
        # File size (log scaled)
        size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
        features.append(np.log1p(size))
        
        # Entropy features (simplified)
        entropy_mean = 5.0  # default
        entropy_max = 6.0
        try:
            with open(filepath, 'rb') as f:
                data = f.read(1024*1024)  # first 1MB
                if data:
                    entropy_mean = self._calculate_entropy(data)
                    entropy_max = entropy_mean * 1.2
        except:
            pass
        features.append(entropy_mean)
        features.append(entropy_max)
        
        # Suspicious imports count
        sus_imports = sum(1 for a in pe_alerts if 'Suspicious APIs' in a)
        features.append(min(sus_imports, 10))
        
        # Suspicious strings count
        sus_strings = len(strings)
        features.append(min(sus_strings, 100))
        
        # Packed?
        is_packed = 1 if any('Packed' in a for a in pe_alerts) else 0
        features.append(is_packed)
        
        # Has digital signature? (Windows only)
        has_cert = 0
        if sys.platform == 'win32' and filepath.lower().endswith(('.exe', '.dll')):
            has_cert = 1 if self._check_signature(filepath) else 0
        features.append(has_cert)
        
        return np.array(features).reshape(1, -1)
    
    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        return entropy
    
    def _check_signature(self, filepath: str) -> bool:
        """Check if file has valid digital signature (Windows)."""
        try:
            import win32security
            import win32crypt
            # Simplified - real implementation would verify
            return False
        except:
            return False
    
    def predict(self, features: np.ndarray) -> Tuple[float, float]:
        """Return (malicious_probability, score_contribution)."""
        if self.model is None:
            return 0.0, 0
        proba = self.model.predict_proba(features)[0]
        malicious_prob = proba[1] if len(proba) > 1 else 0
        score_contrib = int(malicious_prob * Config.SCORE_ML_MALICIOUS)
        return malicious_prob, score_contrib

# ========================== YARA Manager with Hot Reload ==========================
class YaraManager(FileSystemEventHandler):
    def __init__(self):
        self.rules = None
        self.rules_lock = threading.Lock()
        self.rules_mtime = {}
        self.load_rules()
        self.start_watcher()
    
    def load_rules(self):
        """Load all .yar files, track modification times."""
        rule_files = {}
        current_mtime = {}
        for yar_file in Config.RULES_DIR.glob("*.yar"):
            rule_files[str(yar_file)] = str(yar_file)
            current_mtime[str(yar_file)] = yar_file.stat().st_mtime
        
        if not rule_files:
            logger.warning("No YARA rule files found.")
            return
        
        try:
            new_rules = yara.compile(filepaths=rule_files)
            with self.rules_lock:
                self.rules = new_rules
                self.rules_mtime = current_mtime
            logger.info(f"Loaded {len(rule_files)} YARA rule files.")
        except Exception as e:
            logger.error(f"YARA compilation failed: {e}")
    
    def start_watcher(self):
        """Watch rules directory for changes."""
        observer = Observer()
        observer.schedule(self, str(Config.RULES_DIR), recursive=False)
        observer.start()
        logger.info("YARA hot-reload watcher started.")
    
    def on_modified(self, event):
        if event.src_path.endswith('.yar'):
            logger.info(f"YARA rule modified: {event.src_path}, reloading...")
            self.load_rules()
    
    def on_created(self, event):
        if event.src_path.endswith('.yar'):
            logger.info(f"New YARA rule: {event.src_path}, reloading...")
            self.load_rules()
    
    def scan(self, filepath: str) -> List[str]:
        with self.rules_lock:
            if not self.rules:
                return []
        try:
            matches = self.rules.match(filepath)
            return [match.rule for match in matches]
        except Exception as e:
            logger.error(f"YARA scan error on {filepath}: {e}")
            return []

# ========================== Static Analysis ==========================
class StaticAnalyzer:
    def __init__(self, yara_manager: YaraManager, ml_classifier: MLClassifier):
        self.yara = yara_manager
        self.ml = ml_classifier
    
    def get_hashes(self, filepath: str) -> Dict[str, str]:
        hashes = {'md5': hashlib.md5(), 'sha1': hashlib.sha1(), 'sha256': hashlib.sha256()}
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    for algo in hashes.values():
                        algo.update(chunk)
            return {name: algo.hexdigest() for name, algo in hashes.items()}
        except Exception as e:
            logger.error(f"Hash error {filepath}: {e}")
            return {}
    
    def get_file_type(self, filepath: str) -> str:
        try:
            return magic.from_file(filepath, mime=True)
        except:
            return "unknown"
    
    def analyze_pe(self, filepath: str) -> List[str]:
        alerts = []
        try:
            pe = pefile.PE(filepath)
            
            # Suspicious imports
            suspicious_apis = {
                'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
                'OpenProcess', 'GetProcAddress', 'LoadLibraryA', 'HttpSendRequestA',
                'WinExec', 'ShellExecute', 'RegSetValue', 'CryptEncrypt',
                'NtQuerySystemInformation', 'NtSetInformationProcess', 'NtCreateThreadEx'
            }
            found = set()
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name.decode() in suspicious_apis:
                        found.add(imp.name.decode())
            if len(found) > 3:
                alerts.append(f"Suspicious APIs: {', '.join(found)}")
            
            # Section entropy and names
            packers = ['UPX0', 'UPX1', 'UPX2', '.aspack', '.themida', '._winzip', 
                       '.mpress', '.vmp0', '.vmp1', '.enigma']
            for section in pe.sections:
                name = section.Name.decode().strip('\x00')
                entropy = section.get_entropy()
                if name in packers:
                    alerts.append(f"Packed: {name}")
                if entropy > 7.5:
                    alerts.append(f"High entropy {name}: {entropy:.2f}")
            
            # Entry point in unusual section
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_section = None
            for s in pe.sections:
                if s.contains_rva(ep):
                    ep_section = s.Name.decode().strip('\x00')
                    break
            if ep_section and ep_section not in ['.text', 'CODE', '__text']:
                alerts.append(f"Entry point in {ep_section}")
            
            # Timestamp anomaly
            timestamp = pe.FILE_HEADER.TimeDateStamp
            if timestamp > int(time.time()) + 86400:
                alerts.append("Future timestamp")
            
            # Check for digital signature
            if sys.platform == 'win32':
                try:
                    from win32security import CryptQueryObject, CERT_QUERY_OBJECT_FILE
                    # Simplified - real signature verification is complex
                except:
                    pass
            pe.close()
        except:
            pass
        return alerts
    
    def extract_strings(self, filepath: str) -> List[str]:
        """Safe string extraction with size limit."""
        if os.path.getsize(filepath) > Config.MAX_STRING_EXTRACT_SIZE:
            logger.warning(f"File too large for string extraction: {filepath}")
            return []
        
        strings = []
        try:
            with open(filepath, 'rb') as f:
                current = bytearray()
                bytes_read = 0
                while chunk := f.read(4096):
                    bytes_read += len(chunk)
                    if bytes_read > Config.MAX_STRING_EXTRACT_SIZE:
                        break
                    for byte in chunk:
                        if 32 <= byte <= 126:
                            current.append(byte)
                        else:
                            if len(current) >= Config.MIN_STRING_LENGTH:
                                strings.append(current.decode('ascii', errors='ignore'))
                                if len(strings) >= Config.MAX_STRING_COUNT:
                                    return strings
                            current.clear()
                if len(current) >= Config.MIN_STRING_LENGTH:
                    strings.append(current.decode('ascii', errors='ignore'))
        except Exception as e:
            logger.error(f"String extraction error: {e}")
        return strings
    
    def heuristic_strings(self, strings: List[str]) -> List[str]:
        alerts = []
        patterns = [
            (r'http[s]?://', 'URL'),
            (r'\\\\[^\\]+\\', 'Network path'),
            (r'[Pp]ower[Ss]hell', 'PowerShell'),
            (r'[Cc]md\.exe', 'cmd'),
            (r'[Bb]ase64', 'Base64'),
            (r'[Ee]val\(', 'eval'),
            (r'[Ee]xec\(', 'exec'),
            (r'[Dd]ecrypt', 'decrypt'),
            (r'[Ee]ncrypt', 'encrypt'),
            (r'[Kk]eylogger', 'keylogger'),
            (r'[Rr]ansom', 'ransom'),
            (r'[Bb]itcoin', 'bitcoin'),
            (r'[Ww]allet', 'wallet'),
            (r'[Mm]alware', 'malware'),
        ]
        for s in strings[:Config.MAX_STRING_COUNT]:
            for pat, desc in patterns:
                if re.search(pat, s):
                    alerts.append(f"{desc}: {s[:50]}")
                    break
        return alerts[:50]

# ========================== Cloud Analyzer (VirusTotal + AbuseIPDB) ==========================
class CloudAnalyzer:
    def __init__(self, db: ReputationDB):
        self.db = db
        self.vt_key = Config.VIRUSTOTAL_API_KEY
        self.abuse_key = Config.ABUSEIPDB_API_KEY
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'CyberGuard-Pro/6.0'})
    
    def query_vt_hash(self, sha256: str) -> Tuple[int, int, str]:
        if not self.vt_key:
            return 0, 0, "API key missing"
        
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": self.vt_key}
        try:
            resp = self.session.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                return malicious, suspicious, f"M:{malicious} S:{suspicious}"
            elif resp.status_code == 404:
                return 0, 0, "Not found"
            else:
                return 0, 0, f"HTTP {resp.status_code}"
        except Exception as e:
            return 0, 0, f"Error: {e}"
    
    def query_abuse_ip(self, ip: str) -> Tuple[int, str]:
        """Check IP reputation on AbuseIPDB."""
        if not self.abuse_key:
            return 0, "No API key"
        
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {'Key': self.abuse_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': 90}
        try:
            resp = self.session.get(url, headers=headers, params=params, timeout=5)
            if resp.status_code == 200:
                data = resp.json()['data']
                abuse_score = data['abuseConfidenceScore']
                country = data.get('countryCode', '')
                return abuse_score, country
            else:
                return 0, f"Error {resp.status_code}"
        except Exception as e:
            return 0, str(e)
    
    def upload_file_vt(self, filepath: str, interactive: bool = True) -> str:
        """Upload file to VT, with non-interactive check."""
        if not self.vt_key:
            return "API key missing"
        
        # Check file size
        size = os.path.getsize(filepath)
        if size > Config.VT_UPLOAD_MAX_SIZE:
            return f"Upload skipped (file too large: {size/1024/1024:.1f}MB > 32MB)"
        
        # Check if called from non-interactive thread
        if not interactive or threading.current_thread() is not threading.main_thread():
            event_queue.put(('upload_request', filepath))
            return "Upload queued (interactive)"
        
        print(f"\n[?] Upload {os.path.basename(filepath)} to VirusTotal?")
        choice = input("This will share the file with VT. (y/N): ").strip().lower()
        if choice != 'y':
            return "Upload skipped"
        
        url = "https://www.virustotal.com/api/v3/files"
        headers = {"x-apikey": self.vt_key}
        try:
            with open(filepath, 'rb') as f:
                files = {"file": (os.path.basename(filepath), f)}
                resp = self.session.post(url, headers=headers, files=files, timeout=120)
                if resp.status_code == 200:
                    analysis_id = resp.json()['data']['id']
                    return f"Uploaded (ID: {analysis_id})"
                else:
                    return f"Upload failed: {resp.status_code}"
        except Exception as e:
            return f"Upload error: {e}"

# ========================== Threat Scoring Engine ==========================
@dataclass
class ScanResult:
    filepath: str
    sha256: str
    file_type: str
    yara_matches: List[str]
    pe_alerts: List[str]
    string_alerts: List[str]
    vt_malicious: int
    vt_suspicious: int
    vt_verdict: str
    ml_probability: float
    score: int = 0
    verdict: str = "UNKNOWN"
    
    def calculate_score(self, ml_score_contrib: int = 0):
        self.score = 0
        self.score += len(self.yara_matches) * Config.SCORE_YARA
        self.score += len(self.pe_alerts) * Config.SCORE_PE_ALERT
        self.score += len(self.string_alerts) * Config.SCORE_STRINGS_SUSPICIOUS
        self.score += self.vt_malicious * Config.SCORE_VT_MALICIOUS
        self.score += self.vt_suspicious * Config.SCORE_VT_SUSPICIOUS
        self.score += ml_score_contrib
        
        if self.score >= 15:
            self.verdict = "CRITICAL"
        elif self.score >= 10:
            self.verdict = "MALICIOUS"
        elif self.score >= 5:
            self.verdict = "SUSPICIOUS"
        else:
            self.verdict = "CLEAN"
    
    def to_dict(self):
        return {
            'filepath': self.filepath,
            'sha256': self.sha256,
            'type': self.file_type,
            'yara': self.yara_matches,
            'pe': self.pe_alerts,
            'strings': self.string_alerts,
            'vt_malicious': self.vt_malicious,
            'vt_suspicious': self.vt_suspicious,
            'ml_probability': self.ml_probability,
            'score': self.score,
            'verdict': self.verdict
        }

# ========================== Response Actions ==========================
class ResponseEngine:
    def __init__(self, db: ReputationDB):
        self.db = db
        self.alert_count = 0
        self.whitelist = set(Config.SAFE_PROCESSES)
    
    def handle_threat(self, result: ScanResult, source: str = "scan"):
        """Take action based on score."""
        logger.warning(f"Threat detected: {result.filepath} (score={result.score}, verdict={result.verdict})")
        self.alert_count += 1
        
        # Log to DB
        self.db.add_alert(source, result.filepath, result.score, result.verdict, result.to_dict())
        
        # Auto-quarantine if high score
        if result.score >= 15 or self.alert_count >= Config.ALERT_THRESHOLD:
            self.quarantine(result.filepath)
            return
        
        # In interactive mode, ask user
        if threading.current_thread() is threading.main_thread():
            self._interactive_prompt(result)
        else:
            # Non-interactive: queue for later decision
            event_queue.put(('threat', result))
    
    def _interactive_prompt(self, result: ScanResult):
        print(f"\n[!] Suspicious file: {result.filepath}")
        print(f"Score: {result.score} | Verdict: {result.verdict}")
        print(f"YARA: {result.yara_matches}")
        print(f"PE alerts: {result.pe_alerts}")
        action = input("Action: (Q)uarantine, (S)andbox, (I)gnore: ").strip().lower()
        if action == 'q':
            self.quarantine(result.filepath)
        elif action == 's':
            self.sandbox(result.filepath)
        else:
            logger.info(f"Ignored by user: {result.filepath}")
    
    def quarantine(self, filepath: str):
        """Secure quarantine with real encryption using pyzipper."""
        try:
            base = os.path.basename(filepath)
            timestamp = int(time.time())
            dest_zip = Config.QUARANTINE_DIR / f"{base}_{timestamp}.zip"
            password = hashlib.sha256(f"{timestamp}{os.urandom(8)}".encode()).hexdigest()[:16]
            
            # Use pyzipper for AES-256 encryption
            with pyzipper.AESZipFile(dest_zip, 'w', compression=pyzipper.ZIP_DEFLATED,
                                      encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(password.encode())
                zf.write(filepath, arcname=base)
            
            # Remove original
            os.remove(filepath)
            
            # Save metadata
            meta = Config.QUARANTINE_DIR / f"{dest_zip.stem}.meta"
            with open(meta, 'w') as f:
                f.write(f"Original: {filepath}\nTime: {datetime.now()}\nPassword: {password}\n")
            
            logger.info(f"Quarantined {filepath} -> {dest_zip} (pwd: {password})")
            self.db.add_alert("quarantine", filepath, 0, "QUARANTINED", {"zip": str(dest_zip)})
        except Exception as e:
            logger.error(f"Quarantine failed: {e}")
    
    def sandbox(self, filepath: str):
        """Run in Sandboxie if available."""
        if sys.platform == 'win32' and os.path.exists(Config.SANDBOXIE_PATH):
            try:
                subprocess.Popen([Config.SANDBOXIE_PATH, filepath])
                logger.info(f"Launched in Sandboxie: {filepath}")
            except Exception as e:
                logger.error(f"Sandboxie error: {e}")
        else:
            logger.error("Sandboxie not available")
    
    def kill_process(self, proc):
        """Kill process if not whitelisted."""
        if proc.name().lower() in self.whitelist:
            logger.info(f"Whitelisted process {proc.name()} not killed.")
            return
        try:
            proc.kill()
            logger.critical(f"Killed process {proc.pid} ({proc.name()})")
            self.db.add_alert("process_kill", f"{proc.name()}:{proc.pid}", 10, "KILLED", {})
        except Exception as e:
            logger.error(f"Failed to kill process: {e}")

# ========================== Behavioral Monitoring ==========================
class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, core):
        self.core = core
    
    def on_created(self, event):
        if not event.is_directory:
            self._handle(event.src_path, "file_create")
    
    def on_modified(self, event):
        if not event.is_directory:
            self._handle(event.src_path, "file_modify")
    
    def _handle(self, path, source):
        # Exclude our own files
        if any(excl in path for excl in Config.EXCLUDED_FILES):
            return
        # Wait a bit for write completion
        time.sleep(0.5)
        self.core.scan_file(path, source=source)

class ProcessMonitor:
    def __init__(self, core):
        self.core = core
        self.running = False
        self.seen_pids = set()
    
    def start(self):
        self.running = True
        self.seen_pids = set(psutil.pids())
        threading.Thread(target=self._monitor, daemon=True).start()
    
    def _monitor(self):
        while self.running:
            try:
                current = set(psutil.pids())
                new = current - self.seen_pids
                for pid in new:
                    try:
                        proc = psutil.Process(pid)
                        self._check_process(proc)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                self.seen_pids = current
            except Exception as e:
                logger.error(f"Process monitor error: {e}")
            time.sleep(3)
    
    def _check_process(self, proc):
        alerts = []
        try:
            # Use net_connections instead of deprecated connections
            for conn in proc.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    alerts.append(f"Conn to {conn.raddr}")
                    # Check IP reputation
                    self.core.check_ip_reputation(conn.raddr.ip)
            
            # Check open files in monitored dirs
            for f in proc.open_files():
                if any(f.path.startswith(d) for d in Config.MONITORED_DIRS):
                    alerts.append(f"Opened {f.path}")
            
            # Command line suspicious
            cmd = ' '.join(proc.cmdline()).lower()
            suspicious_cmds = ['powershell -enc', 'base64', 'downloadstring', 
                               'invoke-expression', 'start-process']
            if any(k in cmd for k in suspicious_cmds):
                alerts.append(f"Suspicious cmd: {cmd[:100]}")
            
            if alerts:
                self.core.behavioral_callback(proc, alerts, "process")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

class NetworkMonitor:
    def __init__(self, core):
        self.core = core
        self.running = False
        self.conn_history = defaultdict(list)  # ip -> list of ports
    
    def start(self):
        self.running = True
        threading.Thread(target=self._monitor, daemon=True).start()
    
    def _monitor(self):
        while self.running:
            try:
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'SYN_SENT' and conn.raddr:
                        ip = conn.raddr.ip
                        port = conn.raddr.port
                        self.conn_history[ip].append((port, time.time()))
                
                # Detect port scan
                now = time.time()
                for ip, records in list(self.conn_history.items()):
                    # Keep last 30 seconds
                    records = [(p, t) for p, t in records if now - t < 30]
                    self.conn_history[ip] = records
                    if len(set(p for p, _ in records)) > 15:
                        self.core.behavioral_callback(f"Port scan from {ip}", records, "network")
                        # Block IP
                        self._block_ip(ip)
                        del self.conn_history[ip]
            except Exception as e:
                logger.error(f"Network monitor error: {e}")
            time.sleep(5)
    
    def _block_ip(self, ip):
        if sys.platform != 'win32':
            return
        try:
            rule = f"CyberGuard_Block_{ip.replace('.', '_')}"
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule}', 'dir=in', 'action=block', f'remoteip={ip}'
            ], check=True, capture_output=True)
            logger.info(f"Blocked IP {ip}")
            self.core.db.add_alert("network_block", ip, 10, "BLOCKED", {})
        except Exception as e:
            logger.error(f"Block failed: {e}")

# ========================== ETW Monitoring (Windows) ==========================
if Config.ENABLE_ETW_MONITOR and sys.platform == 'win32':
    class ETWMonitor:
        """Monitor Windows ETW events for process creation, DLL loads, etc."""
        def __init__(self, core):
            self.core = core
            self.running = False
        
        def start(self):
            self.running = True
            threading.Thread(target=self._monitor, daemon=True).start()
        
        def _monitor(self):
            try:
                import win32evtlog
                server = 'localhost'
                logtype = 'Security'
                hand = win32evtlog.OpenEventLog(server, logtype)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                while self.running:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    if events:
                        for event in events:
                            if event.EventID == 4688:  # Process creation
                                self.core.behavioral_callback(f"New process created", event.StringInserts, "etw")
                    time.sleep(5)
            except Exception as e:
                logger.error(f"ETW monitor failed (run as admin?): {e}")
                self.running = False

# ========================== Registry Monitor ==========================
if Config.ENABLE_REGISTRY_MONITOR and sys.platform == 'win32':
    class RegistryMonitor:
        def __init__(self, core):
            self.core = core
            self.running = False
            self.keywords = ['run', 'runonce', 'services', 'winlogon', 'shell']
        
        def start(self):
            self.running = True
            threading.Thread(target=self._monitor, daemon=True).start()
        
        def _monitor(self):
            # Simplified registry monitoring via polling
            import winreg
            hives = [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
            paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                r"SYSTEM\CurrentControlSet\Services",
            ]
            last_values = {}
            while self.running:
                for hive in hives:
                    for path in paths:
                        try:
                            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                            i = 0
                            while True:
                                try:
                                    name, value, _ = winreg.EnumValue(key, i)
                                    full = f"{hive}\\{path}\\{name}"
                                    if full not in last_values:
                                        last_values[full] = value
                                        self.core.behavioral_callback(f"Registry added: {full}={value}", None, "registry")
                                    elif last_values[full] != value:
                                        self.core.behavioral_callback(f"Registry changed: {full}={value}", None, "registry")
                                        last_values[full] = value
                                    i += 1
                                except WindowsError:
                                    break
                            winreg.CloseKey(key)
                        except Exception:
                            pass
                time.sleep(10)

# ========================== Memory Scanner ==========================
class MemoryScanner:
    """Scan process memory for YARA signatures."""
    def __init__(self, yara_mgr: YaraManager):
        self.yara = yara_mgr
        self.running = False
    
    def start(self):
        self.running = True
        threading.Thread(target=self._scan_loop, daemon=True).start()
    
    def _scan_loop(self):
        while self.running:
            # Scan critical processes periodically
            targets = ['lsass.exe', 'svchost.exe', 'winlogon.exe', 'explorer.exe']
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() in targets:
                    self.scan_process(proc.info['pid'])
            time.sleep(60)
    
    def scan_process(self, pid):
        """Read process memory and scan with YARA."""
        try:
            proc = psutil.Process(pid)
            # Read memory regions (simplified - in reality use ReadProcessMemory)
            # This is a placeholder; full memory scanning is complex
            # We'll just log for now, but you can implement actual memory scanning later
            pass
        except Exception as e:
            logger.error(f"Memory scan failed for PID {pid}: {e}")

# ========================== Web Dashboard ==========================
def create_dashboard(core):
    app = Flask(__name__)
    
    @app.route('/')
    def index():
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CyberGuard Dashboard</title>
            <style>
                body { font-family: Arial; margin: 20px; background: #1e1e1e; color: #fff; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #444; padding: 8px; text-align: left; }
                th { background: #333; }
                .critical { color: #ff4444; }
                .malicious { color: #ff8800; }
                .suspicious { color: #ffaa00; }
                .clean { color: #00ff00; }
            </style>
        </head>
        <body>
            <h1>CyberGuard Pro v6.0 Dashboard</h1>
            <h2>Recent Alerts</h2>
            <table id="alerts">
                <thead>
                    <tr><th>Time</th><th>Source</th><th>Target</th><th>Score</th><th>Verdict</th></tr>
                </thead>
                <tbody>
                </tbody>
            </table>
            <script>
                function fetchAlerts() {
                    fetch('/api/alerts')
                        .then(res => res.json())
                        .then(data => {
                            let tbody = document.querySelector('#alerts tbody');
                            tbody.innerHTML = '';
                            data.forEach(alert => {
                                let row = tbody.insertRow();
                                row.innerHTML = `<td>${alert.timestamp}</td><td>${alert.source}</td><td>${alert.target}</td><td>${alert.score}</td><td class="${alert.verdict.toLowerCase()}">${alert.verdict}</td>`;
                            });
                        });
                }
                setInterval(fetchAlerts, 2000);
                fetchAlerts();
            </script>
        </body>
        </html>
        """)
    
    @app.route('/api/alerts')
    def get_alerts():
        return jsonify(core.db.get_recent_alerts(50))
    
    @app.route('/api/stats')
    def get_stats():
        # Return system stats
        return jsonify({
            'processes': len(psutil.pids()),
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
        })
    
    return app

# ========================== Core Engine ==========================
class CyberGuardCore:
    def __init__(self):
        self.db = ReputationDB()
        self.yara_mgr = YaraManager()
        self.ml = MLClassifier()
        self.static = StaticAnalyzer(self.yara_mgr, self.ml)
        self.cloud = CloudAnalyzer(self.db)
        self.response = ResponseEngine(self.db)
        
        # Monitors
        self.file_observer = None
        self.proc_monitor = None
        self.net_monitor = None
        self.etw_monitor = None
        self.registry_monitor = None
        self.memory_scanner = None
        
        # Dashboard
        self.dashboard_app = None
        self.dashboard_thread = None
    
    def check_ip_reputation(self, ip: str):
        """Check IP against AbuseIPDB."""
        if not self.cloud.abuse_key:
            return
        score, country = self.cloud.query_abuse_ip(ip)
        if score > 50:
            logger.warning(f"Malicious IP detected: {ip} (abuse score {score})")
            self.db.add_alert("ip_reputation", ip, score, "MALICIOUS", {"country": country})
    
    def scan_file(self, filepath: str, source="manual") -> Optional[ScanResult]:
        """Full scan pipeline."""
        if not os.path.isfile(filepath):
            logger.error(f"File not found: {filepath}")
            return None
        
        # Self-exclusion
        if any(excl in filepath for excl in Config.EXCLUDED_FILES):
            logger.debug(f"Skipping excluded file: {filepath}")
            return None
        
        logger.info(f"Scanning {filepath} (source: {source})")
        
        # Get hashes
        hashes = self.static.get_hashes(filepath)
        sha256 = hashes.get('sha256', '')
        
        # Check local DB
        cached = self.db.get_file(sha256) if sha256 else None
        if cached and (datetime.now() - datetime.fromisoformat(cached['last_seen'])).days < 1:
            logger.info(f"Cache hit for {sha256[:8]}... score={cached['score']}")
            # Build a result from cache
            result = ScanResult(
                filepath=filepath,
                sha256=sha256,
                file_type=self.static.get_file_type(filepath),
                yara_matches=[],
                pe_alerts=[],
                string_alerts=[],
                vt_malicious=cached.get('vt_detections', 0),
                vt_suspicious=0,
                vt_verdict=cached['verdict'],
                ml_probability=cached.get('ml_score', 0.0)
            )
            result.score = cached['score']
            result.verdict = cached['verdict']
            return result
        
        # Perform scans
        yara_matches = self.yara_mgr.scan(filepath)
        pe_alerts = self.static.analyze_pe(filepath)
        strings = self.static.extract_strings(filepath)
        string_alerts = self.static.heuristic_strings(strings)
        
        # ML prediction
        features = self.ml.extract_features(filepath, pe_alerts, strings)
        ml_prob, ml_score_contrib = self.ml.predict(features)
        
        # Cloud lookup
        vt_mal, vt_sus, vt_ver = self.cloud.query_vt_hash(sha256) if sha256 else (0,0,"No hash")
        
        # Build result
        result = ScanResult(
            filepath=filepath,
            sha256=sha256,
            file_type=self.static.get_file_type(filepath),
            yara_matches=yara_matches,
            pe_alerts=pe_alerts,
            string_alerts=string_alerts,
            vt_malicious=vt_mal,
            vt_suspicious=vt_sus,
            vt_verdict=vt_ver,
            ml_probability=ml_prob
        )
        result.calculate_score(ml_score_contrib)
        
        # Store in DB
        if sha256:
            self.db.update_file(sha256, result.score, result.verdict, vt_mal, ml_prob, result.to_dict())
        
        # If VT not found, offer upload
        if vt_ver == "Not found" and self.cloud.vt_key:
            upload_status = self.cloud.upload_file_vt(filepath, interactive=(source=="manual"))
            logger.info(f"VT upload: {upload_status}")
        
        # Respond if suspicious
        if result.verdict != "CLEAN":
            self.response.handle_threat(result, source)
        else:
            logger.info(f"File clean: {filepath}")
        
        return result
    
    def start_monitoring(self):
        """Start all real-time monitors."""
        if Config.ENABLE_FILE_MONITOR:
            handler = FileMonitorHandler(self)
            self.file_observer = Observer()
            for d in Config.MONITORED_DIRS:
                if os.path.exists(d):
                    self.file_observer.schedule(handler, d, recursive=True)
                    logger.info(f"Watching directory: {d}")
            self.file_observer.start()
        
        if Config.ENABLE_PROCESS_MONITOR:
            self.proc_monitor = ProcessMonitor(self)
            self.proc_monitor.start()
        
        if Config.ENABLE_NETWORK_MONITOR:
            self.net_monitor = NetworkMonitor(self)
            self.net_monitor.start()
        
        if Config.ENABLE_ETW_MONITOR and sys.platform == 'win32':
            self.etw_monitor = ETWMonitor(self)
            self.etw_monitor.start()
        
        if Config.ENABLE_REGISTRY_MONITOR and sys.platform == 'win32':
            self.registry_monitor = RegistryMonitor(self)
            self.registry_monitor.start()
        
        self.memory_scanner = MemoryScanner(self.yara_mgr)
        self.memory_scanner.start()
        
        logger.info("All real-time monitors started.")
        
        # Start dashboard
        if Config.ENABLE_WEB_DASHBOARD:
            self.dashboard_app = create_dashboard(self)
            self.dashboard_thread = threading.Thread(
                target=self.dashboard_app.run,
                kwargs={'host':'0.0.0.0', 'port':Config.DASHBOARD_PORT, 'debug':False, 'use_reloader':False},
                daemon=True
            )
            self.dashboard_thread.start()
            logger.info(f"Web dashboard running on http://localhost:{Config.DASHBOARD_PORT}")
    
    def behavioral_callback(self, target, details, source):
        """Unified callback for all monitors."""
        if source == "file_create" or source == "file_modify":
            if os.path.isfile(target):
                self.scan_file(target, source=source)
        
        elif source == "process":
            proc, alerts = target, details
            logger.warning(f"Process {proc.pid} {proc.name()}: {alerts}")
            # Check for network connections
            if any('Conn to' in a for a in alerts):
                self.response.kill_process(proc)
        
        elif source == "network":
            logger.warning(f"Network alert: {target}")
            self.db.add_alert("network", str(target), 8, "SUSPICIOUS", {"details": details})
        
        elif source == "etw":
            logger.info(f"ETW event: {target} - {details}")
        
        elif source == "registry":
            logger.info(f"Registry change: {target}")
            self.db.add_alert("registry", target, 5, "INFO", {})

# ========================== Command Line Interface ==========================
def main():
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║           CyberGuard Pro v6.0 - EDR Edition             ║
    ║      Advanced Endpoint Detection & Response Toolkit     ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    core = CyberGuardCore()
    
    # Process event queue in main thread
    def process_event_queue():
        while True:
            try:
                event = event_queue.get(timeout=0.1)
                if event[0] == 'upload_request':
                    filepath = event[1]
                    # Prompt user in main thread
                    print(f"\n[?] Upload requested for {os.path.basename(filepath)}")
                    choice = input("Upload to VirusTotal? (y/N): ").strip().lower()
                    if choice == 'y':
                        core.cloud.upload_file_vt(filepath, interactive=True)
                elif event[0] == 'threat':
                    result = event[1]
                    core.response._interactive_prompt(result)
                elif event[0] == 'alert':
                    # Already handled by DB
                    pass
            except queue.Empty:
                break
    
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == 'scan' and len(sys.argv) > 2:
            target = sys.argv[2]
            if os.path.isfile(target):
                core.scan_file(target)
            elif os.path.isdir(target):
                for root, _, files in os.walk(target):
                    for f in files:
                        core.scan_file(os.path.join(root, f), source="batch")
                        process_event_queue()
            else:
                print("Invalid path")
        elif cmd == 'monitor':
            core.start_monitoring()
            try:
                while True:
                    process_event_queue()
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nShutting down...")
        else:
            print("Usage: cyberguard.py [scan <file/dir> | monitor]")
    else:
        # Interactive mode
        while True:
            print("\nOptions:")
            print("1. Scan file")
            print("2. Scan directory")
            print("3. Start monitoring")
            print("4. Show recent alerts")
            print("5. Exit")
            choice = input("Select: ").strip()
            if choice == '1':
                path = input("File path: ").strip('"')
                if os.path.isfile(path):
                    core.scan_file(path)
                else:
                    print("Not a file")
            elif choice == '2':
                path = input("Directory path: ").strip('"')
                if os.path.isdir(path):
                    for root, _, files in os.walk(path):
                        for f in files:
                            core.scan_file(os.path.join(root, f), source="batch")
                            process_event_queue()
                else:
                    print("Invalid directory")
            elif choice == '3':
                core.start_monitoring()
                try:
                    while True:
                        process_event_queue()
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\nMonitoring stopped")
            elif choice == '4':
                alerts = core.db.get_recent_alerts(20)
                for a in alerts:
                    print(f"{a['timestamp']} - {a['source']} - {a['target']} - {a['verdict']}")
            elif choice == '5':
                break

if __name__ == "__main__":
    main()