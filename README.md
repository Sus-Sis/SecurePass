# SecurePass: Zero-Knowledge Password Manager

SecurePass is a production-ready, zero-knowledge password manager designed to secure credentials. It features a client-side encrypted web dashboard (React), a secure backend API (FastAPI), database storage (PostgreSQL/SQLite), and a Manifest V3 browser extension (Chrome/Firefox) with login detection and autofill support.

---

## Security Architecture

### 1. Zero-Knowledge Cryptography
ALL encryption and decryption happen strictly on the client side (in-browser or inside the extension) using the native **Web Crypto API** and **WebAssembly/JS Argon2id**. The server never receives, stores, or processes:
- Plaintext passwords or credentials
- The user's Master Password
- The Master Key used to encrypt vault data
- Static password hashes over the wire

The server stores only:
1. An encrypted vault payload (ciphertext).
2. The user's public KDF salt.
3. User-calibrated Argon2id KDF parameters (`memoryCost`, `timeCost`, `parallelism`).
4. An SRP-6a verifier $v = g^x \bmod N$ (used for zero-knowledge challenge-response authentication).
5. An encrypted key recovery payload.

### 2. Encryption & Key Derivation Specifications
- **Master Key Derivation**: Derived using **Argon2id (RFC 9106)** with client-side **adaptive benchmarking**. At registration, the client benchmarks its device performance to select optimal parameters (`memory_cost`, `time_cost`, `parallelism`) targeting ~300ms latency. Supports PBKDF2 as a legacy fallback.
- **Zero-Knowledge Authentication (SRP-6a / PAKE Protocol)**: 
  - Login uses **SRP-6a** (Secure Remote Password - RFC 5054).
  - Client and server run a 2-step challenge-response handshake ($A = g^a \bmod N$, $B = k \cdot v + g^b \bmod N$).
  - Neither password nor static master key verifier is ever transmitted over the wire.
  - Every login produces a unique non-replayable proof ($M_1$ from client, $M_2$ from server).
- **Vault Encryption**: Vault data (a JSON array of credentials) is encrypted using **AES-256-GCM**. A cryptographically secure random 12-byte IV is generated for every encryption operation using `window.crypto.getRandomValues()`.

### 3. Zero-Knowledge Account Recovery Protocol
If a user forgets their master password, they can recover their decrypted vault using their Recovery Code:
1. **Setup (Registration)**: A 32-byte cryptographically secure random Recovery Code is generated for the user.
   - Client derives a Recovery Master Key (RMK) = `SHA-256(Recovery Code)`.
   - Client encrypts the Master Key (MK) using RMK via AES-GCM to produce `encrypted_key_recovery`.
   - Client generates an SRP verifier for the recovery code.
2. **Execution (Recovery)**:
   - User inputs their Recovery Code.
   - Client requests the encrypted recovery payload and vault from the server (`/api/auth/recovery/initiate`).
   - Client derives RMK, decrypts `encrypted_key_recovery` to retrieve the Master Key (MK).
   - Client decrypts the old `encrypted_vault` using MK.
   - User sets a new Master Password.
   - Client derives a new MK' via Argon2id, re-encrypts the vault, generates a new SRP verifier, encrypts MK' with a new recovery code, and sends updates to the server (`/api/auth/recovery/verify`).

---

## Directory Structure

```
SecurePass/
├── backend/
│   ├── app/
│   │   ├── database.py       # DB Connection & Sessions
│   │   ├── models.py         # SQLAlchemy Database Schema (Argon2 params & SRP verifier)
│   │   ├── schemas.py        # Pydantic schemas (Data Validation & SRP models)
│   │   ├── crud.py           # SQL query helpers
│   │   ├── auth.py           # JWT, SRP-6a PAKE cryptography, PyOTP, QR generation
│   │   └── main.py           # FastAPI Endpoints (SRP challenge & authenticate routes)
│   ├── requirements.txt      # Python dependencies
│   ├── Dockerfile            # Container definition
│   └── test_security.py      # Automated security assurance test suite
├── frontend/
│   ├── src/
│   │   ├── context/
│   │   │   └── AuthContext.jsx # Global Auth state & zero-knowledge login flow
│   │   ├── pages/
│   │   │   ├── Register.jsx  # Strength calculations, Argon2 benchmark & Recovery DL
│   │   │   ├── Login.jsx     # SRP-6a authentication & ZK Account Recovery
│   │   │   ├── Dashboard.jsx # Vault CRUD, Clipboard, Pass Generator
│   │   │   └── Settings.jsx  # Password reset, MFA, JSON export, Logs
│   │   ├── utils/
│   │   │   ├── argon2.js     # Argon2id KDF & adaptive benchmarking module
│   │   │   ├── srp.js        # SRP-6a client-side challenge & proof calculation
│   │   │   ├── crypto.js     # Web Crypto API wrapper (AES-GCM / Argon2 / SRP)
│   │   │   └── api.js        # API connection service
│   │   ├── App.jsx           # Routing & nav logic
│   │   ├── main.jsx          # Entry point
│   │   └── index.css         # Premium Glassmorphism UI
│   ├── package.json          # Node dependencies
│   ├── vite.config.js        # Vite build tool config
│   └── Dockerfile            # Container definition
├── extension/
│   ├── manifest.json         # Manifest V3 configuration
│   ├── background.js         # Service worker tab-relay script
│   ├── content.js            # Input listener, autofill, save prompt
│   ├── popup.html            # Quick dashboard panel HTML
│   ├── popup.js              # Popup copy & query controller
│   ├── popup.css             # Styled extension CSS
│   └── icon.svg              # Lock-shield vector graphic
└── docker-compose.yml        # Orchestration (DB + Server)
```

---

## Setup & Running Guide

### 1. Requirements
- Python 3.9+
- Node.js v18+ & npm
- PostgreSQL (Docker Compose spins this up automatically, or falls back to SQLite locally)

---

### 2. Running Backend Locally
1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Initialize virtual environment:
   - **Windows (PowerShell)**:
     ```powershell
     py -m venv venv_win
     .\venv_win\Scripts\activate
     ```
   - **macOS / Linux**:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Start the FastAPI development server:
   - **Windows (PowerShell)**:
     ```powershell
     python -m uvicorn app.main:app --reload --port 8000
     ```
   - **macOS / Linux**:
     ```bash
     uvicorn app.main:app --reload --port 8000
     ```
   *Note: If no database URL environment variable is set, FastAPI will automatically create and connect to a local SQLite database file named `securepass.db` in your backend directory.*

---

### 3. Running Frontend Locally
1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the dev server:
   ```bash
   npm run dev
   ```
4. Open your browser and navigate to the printed local port (usually `http://localhost:5173`).

---

### 4. Running via Docker Compose (PostgreSQL)
Ensure you have Docker and Docker Compose running, then execute from the root directory:
```bash
docker-compose up --build
```
This starts:
- A PostgreSQL database container at port `5432` with persistent volumes.
- The FastAPI backend container at port `8000`.

---

### 5. Installing the Browser Extension
1. Open Google Chrome or Firefox.
2. Go to the Extensions page:
   - Chrome: Navigate to `chrome://extensions/`
   - Firefox: Navigate to `about:debugging#/runtime/this-firefox`
3. Enable **Developer mode** (toggle switch in the top-right corner).
4. Click **Load unpacked** (or "Load Temporary Add-on" in Firefox).
5. Select the `extension` folder inside this repository root.
6. The SecurePass shield icon will appear in your toolbar.

---

## Running Automated Security Tests
We have built an automated test suite verifying all critical security conditions (Argon2id parameters, SRP-6a zero-knowledge handshake, Lockout, Rate Limiting, Registration, Login, Token invalidation). 

To execute the tests:
1. Ensure the virtual environment is active:
   ```bash
   cd backend
   source venv/bin/activate
   ```
2. Run the test script:
   ```bash
   python test_security.py
   ```
On success, you will see a color-coded output indicating all test assertions passed.
