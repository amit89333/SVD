# SDV Cybersecurity Management Platform

A simulated **Software-Defined Vehicle (SDV) Cybersecurity Management Platform** featuring real-time CAN bus intrusion detection with Machine Learning (Random Forest & SHAP explainability), Software Bill of Materials (SBOM) CVE threat intelligence correlation, automated Secure Gateway zone isolation, Ed25519 secure OTA updates, a SHA-256 hash-chained audit ledger, and a SOC Command Dashboard.

---

## 🚀 Key Features & Architecture

1. **Virtual Vehicle Simulator (`vehicle-sim/`)**: Simulates continuous CAN telemetry (Engine RPM, Speed, Brake Pressure, Infotainment door/HVAC status, and Gateway heartbeats).
2. **Attack Injector (`attack-injector/`)**: Injects DoS floods, fuzzing payload mutations, brake spoofing, and frame replay attacks via CLI or UI controls.
3. **ML Intrusion Detection Engine (`ids-engine/`)**: Real-time feature extraction (inter-arrival time, payload entropy, burst rate, bitwise Hamming distance) with Random Forest classification and SHAP explainability.
4. **SBOM & Threat Intelligence (`sbom-threat-intel/`)**: Correlates vehicle software manifests against automotive CVE feeds.
5. **Secure Gateway Zone Isolation (`secure-gateway/`)**: Automatically isolates compromised arbitration IDs on High/Critical alerts.
6. **Ed25519 Secure OTA Manager (`ota-manager/`)**: Cryptographically signs and verifies firmware packages and delta patches.
7. **Hash-Chained Audit Ledger (`audit-log/`)**: SHA-256 cryptographic append-only event ledger with chain integrity verification.
8. **Real-time SOC Dashboard (`dashboard/`, `backend-api/`)**: Live web dashboard with WebSockets, interactive attack sandbox, telemetry charts, and zone controls.
9. **ISO/SAE 21434 & UNECE R155 TARA Report Generator (`compliance/`)**: Auto-generates compliance threat analysis reports.

---

## 🛠️ Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Launch Backend & Dashboard
```bash
python -m uvicorn backend-api.main:app --host 127.0.0.1 --port 8000
```
Open **`http://localhost:8000`** in your browser.

### 3. Run Attack Injector CLI
```bash
python attack-injector/inject.py --attack spoofing --duration 5
```

---

## 📜 Standards & Compliance
- **ISO/SAE 21434:2021**: Road vehicles cybersecurity engineering standard
- **UNECE R155 / R156**: Cybersecurity & Software Update Management Systems (SUMS)
