# SecurePass: Zero-Knowledge Password Manager

SecurePass is a production-ready, zero-knowledge password manager designed to secure credentials. It features a client-side encrypted web dashboard (React), a secure backend API (FastAPI), database storage (PostgreSQL/SQLite), and a Manifest V3 browser extension (Chrome/Firefox) with login detection and autofill support.

---

## Security Architecture

### 1. Zero-Knowledge Cryptography
ALL encryption and decryption happen strictly on the client side (in-browser or inside the extension) using the native **Web Crypto API**. The server never receives, stores, or processes:
- Plaintext passwords or credentials
- The user's Master Password
- The Master Key used to encrypt vault data

The server stores only:
1. An encrypted vault payload (ciphertext).
2. The user's public KDF salt.
3. An auth verifier hash (to verify logins).
4. An encrypted key recovery payload.

### 2. Encryption & Key Derivation Specifications
- **Master Key Derivation**: Derived from the Master Password and a unique 64-byte random client salt using `PBKDF2` with `HMAC-SHA-256` and **600,000 iterations**.
- **Auth Verifier**: Derived as the SHA-256 hash of the derived Master Key: `verifier = SHA-256(MasterKey)`. The client sends this verifier to the server.
- **Server Hashing**: The server hashes the incoming Auth Verifier again using `bcrypt` before writing it to the database.
- **Vault Encryption**: Vault data (a JSON array of credentials) is encrypted using **AES-256-GCM**. A cryptographically secure random 12-byte IV is generated for every encryption operation using `window.crypto.getRandomValues()`.

### 3. Zero-Knowledge Account Recovery Protocol
If a user forgets their master password, they can recover their decrypted vault using their Recovery Code:
1. **Setup (Registration)**: A 32-byte cryptographically secure random Recovery Code is generated for the user.
   - Client derives a Recovery Master Key (RMK) = `SHA-256(Recovery Code)`.
   - Client encrypts the Master Key (MK) using RMK via AES-GCM to produce `encrypted_key_recovery`.
   - Client hashes the Recovery Code using `SHA-256` and sends the verifier to the server as `recovery_codes_hash` (stored using `bcrypt`).
2. **Execution (Recovery)**:
   - User inputs their Recovery Code.
   - Client requests the encrypted recovery payload and vault from the server (`/api/auth/recovery/initiate`).
   - Client derives RMK, decrypts `encrypted_key_recovery` to retrieve the Master Key (MK).
   - Client decrypts the old `encrypted_vault` using MK.
   - User sets a new Master Password.
   - Client derives a new MK', re-encrypts the vault, generates a new verifier, encrypts MK' with a new recovery code, and sends updates to the server (`/api/auth/recovery/verify`).

---

## Directory Structure

```
SecurePass/
├── backend/
│   ├── app/
│   │   ├── database.py       # DB Connection & Sessions
│   │   ├── models.py         # SQLAlchemy Database Schema
│   │   ├── schemas.py        # Pydantic schemas (Data Validation)
│   │   ├── crud.py           # SQL query helpers
│   │   ├── auth.py           # JWT, Bcrypt, PyOTP, QR generation
│   │   └── main.py           # FastAPI Endpoints & App initialization
│   ├── requirements.txt      # Python dependencies
│   ├── Dockerfile            # Container definition
│   └── test_security.py      # Automated security assurance test suite
├── frontend/
│   ├── src/
│   │   ├── context/
│   │   │   └── AuthContext.jsx # Global Auth state & key storage
│   │   ├── pages/
│   │   │   ├── Register.jsx  # Strength calculations & Recovery DL
│   │   │   ├── Login.jsx     # MFA checks & ZK Account Recovery
│   │   │   ├── Dashboard.jsx # Vault CRUD, Clipboard, Pass Generator
│   │   │   └── Settings.jsx  # Password reset, MFA, JSON export, Logs
│   │   ├── utils/
│   │   │   ├── crypto.js     # Web Crypto API wrapper (AES-GCM/PBKDF2)
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
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Start the FastAPI development server:
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
We have built an automated test suite verifying all critical security conditions (Lockout, Rate Limiting, Registration, Login, Token invalidation). 

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
