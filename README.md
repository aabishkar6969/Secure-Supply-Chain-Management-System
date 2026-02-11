# 🔐 Secure Supply Chain Management System

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Cryptography](https://img.shields.io/badge/Cryptography-RSA--2048%20%7C%20AES--256--GCM-orange.svg)
![Flask](https://img.shields.io/badge/Framework-Flask-red.svg)
![ST6051CEM](https://img.shields.io/badge/Module-ST6051CEM-purple.svg)

> A PKI-based open-source cryptographic toolkit that guarantees the authenticity, integrity, and non-repudiation of supply chain data using industry-standard cryptography — without the complexity of blockchain.

---

## 📋 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Cryptographic Design](#cryptographic-design)
- [Installation](#installation)
- [Usage](#usage)
- [Web Dashboard](#web-dashboard)
- [Testing](#testing)
- [Real-World Use Cases](#real-world-use-cases)
- [Project Structure](#project-structure)
- [License](#license)

---

## 🌐 Overview

The **Secure Supply Chain Management System** addresses critical vulnerabilities in modern logistics and distribution networks. Traditional supply chain systems rely on implicit trust and paper documentation — leaving them exposed to:

- ❌ Data tampering and record falsification
- ❌ Identity spoofing and impersonation
- ❌ Man-in-the-Middle interception
- ❌ Replay attacks using captured signatures
- ❌ Private key theft and brute-force attacks

This system replaces implicit trust with **mathematical cryptographic proof** — every shipment record is digitally signed, every participant identity is CA-verified, and every payload is authenticated-encrypted.

---

## ✨ Features

| Feature | Implementation |
|---|---|
| Certificate Authority | X.509 v3, RSA-2048, SHA-256 |
| Digital Signatures | RSA-PSS + SHA-256 + MAX_LENGTH salt |
| Payload Encryption | AES-256-GCM + RSA-OAEP hybrid |
| Key Storage | PKCS#12 + AES-256-CBC + PBKDF2-HMAC-SHA256 |
| CLI Interface | Click-based command line tool |
| Web Dashboard | Flask web application |
| Offline Verification | No internet required |

---

## 🏗️ System Architecture
```
┌─────────────────────────────────────────┐
│           INTERFACE LAYER               │
│  ┌─────────────┐    ┌─────────────────┐ │
│  │ CLI         │    │ Web Dashboard   │ │
│  │ cli/main.py │    │ web/app.py      │ │
│  └──────┬──────┘    └────────┬────────┘ │
└─────────┼───────────────────┼──────────┘
          │       calls       │
┌─────────▼───────────────────▼──────────┐
│         CRYPTOGRAPHIC CORE             │
│  ┌──────────┐ ┌──────────┐ ┌────────┐  │
│  │ core/    │ │ core/    │ │ core/  │  │
│  │ ca.py    │ │ crypto   │ │supply  │  │
│  │ CA+X.509 │ │ RSA+AES  │ │chain   │  │
│  └──────────┘ └──────────┘ └────────┘  │
└─────────────────────────────────────────┘
          │
┌─────────▼───────────────────────────────┐
│           STORAGE LAYER                 │
│  ca.key  ca.crt  participant.p12        │
│  participant.crt  event.json  event.sig │
└─────────────────────────────────────────┘
```

---

## 🔐 Cryptographic Design

### Asymmetric Cryptography
- **RSA-2048** — key generation for CA and all participants
- **RSA-PSS + SHA-256** — digital signatures with MAX_LENGTH salt
- **RSA-OAEP** — session key encapsulation in hybrid encryption
- **X.509 v3** — certificate format with proper KeyUsage extensions

### Symmetric Cryptography
- **AES-256-GCM** — authenticated payload encryption (confidentiality + integrity)
- **AES-256-CBC + PBKDF2-HMAC-SHA256** — PKCS#12 keystore protection

### Key Management
- Private keys never stored in plaintext
- PKCS#12 keystores with password-based encryption
- Keys decrypted in memory only during signing operations

---

## ⚙️ Installation

**Clone the repository:**
```bash
git clone https://github.com/aabishkar6969/Secure-Supply-Chain-Management-System
cd Secure-Supply-Chain-Management-System
```

**Install dependencies:**
```bash
pip install -r requirements.txt
```

---

## 🖥️ Usage

### Step 1 — Initialise Certificate Authority
```bash
python main.py ca init --name "SupplyChainCA"
```
Produces: `ca.key` + `ca.crt`

### Step 2 — Register a Participant
```bash
python main.py register --name "Manufacturer" --password yourpassword
```
Produces: `Manufacturer.p12` + `Manufacturer.crt`

### Step 3 — Sign a Shipment Event
```bash
python main.py sign --p12 Manufacturer.p12 --password yourpassword --event event.json
```
Produces: `event.sig`

### Step 4 — Verify a Signature
```bash
python main.py verify --crt Manufacturer.crt --sig event.sig --event event.json
```

**Success output:**
```
✅ Verification successful — data integrity confirmed
```

**Tamper detection:**
```
❌ Signature invalid — data tampered or wrong certificate
```

---

## 🌐 Web Dashboard
```bash
python web/app.py
```

Open browser at `http://127.0.0.1:5000`

| Route | Function |
|---|---|
| `/register` | Register new supply chain participant |
| `/sign` | Sign shipment event JSON |
| `/verify` | Verify signature and confirm integrity |

---

## 🧪 Testing

**Run full test suite:**
```bash
pytest
```

**Run with coverage:**
```bash
pytest --tb=short -v
```

**Test categories:**
- ✅ Functional tests — CA, registration, signing, verification
- ✅ Attack simulation — tampering, impersonation, wrong password
- ✅ Multi-user simulation — 5 participants with impersonation test

---

## 🌍 Real-World Use Cases

### 💊 Pharmaceutical Supply Chain
Prevents counterfeit medicines — WHO estimates 1 in 10 medicines in developing markets are falsified. Every batch record is cryptographically signed and verified offline.

### 🎓 Academic Credential Verification
Prevents certificate fraud — RSA-PSS signature detects any modification to grades, degree class, or personal details instantly.

### 🌡️ Food Safety Cold Chain
Ensures temperature logs cannot be falsified — IoT gateway signs records every 60 minutes, creating a tamper-evident audit trail from farm to supermarket.

---

## 📁 Project Structure
```
Secure-Supply-Chain-Management-System/
├── core/
│   ├── ca.py              # Certificate Authority
│   ├── crypto.py          # RSA-PSS, AES-GCM, PKCS#12
│   └── supply_chain.py    # Sign/verify workflows
├── cli/
│   └── main.py            # Click CLI commands
├── web/
│   ├── app.py             # Flask web dashboard
│   └── templates/         # HTML templates
├── tests/
│   └── test_crypto.py     # pytest test suite
├── requirements.txt
├── pytest.ini
├── .gitignore
├── LICENSE
└── README.md
```

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Aabishkar** — ST6051CEM Practical Cryptography  
Softwarica College of IT & E-Commerce / Coventry University  

---

> *"Trust should be mathematically proven, not assumed."*