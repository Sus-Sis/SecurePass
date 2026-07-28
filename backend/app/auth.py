import os
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple
from jose import JWTError, jwt
import bcrypt
import pyotp
import qrcode
import io
import base64
from sqlalchemy.orm import Session as DbSession
from . import models

# JWT configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "securepass_super_secret_key_change_me_in_production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# SRP-6a 2048-bit MODP Group 14 Constants (RFC 5054)
SRP_N_HEX = (
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050"
    "A37329CBB4FE29D9C862F2AC7D8725101128093B535D8961353078440A28F27F"
    "25717D50A41D6086B7E325C05752D22CC6888034515E86E20B0C4776DCD88F28"
    "562B28B0237553531F2E84A7851608A3DA2E407221DFB5BD551BF1D45070281F"
    "CDD306C9B0762E404E85C1BE90C5CD710E102E72E77286377197A24FAF92D2F2"
    "CC427027BCEF07F2D172EBF044810620ED2CC295F72A5A609F3A95E407BF33B4"
    "9E7C0579979EC027114A51D14EB5E70B7E0041B1F3C4718CD946B04664F35C83"
    "3C143B80E621C1C85A827F37F159C2479E331405102F3A30BE5EED763321"
)
SRP_N = int(SRP_N_HEX, 16)
SRP_G = 2

def hex_to_bytes(hex_str: str) -> bytes:
    clean = hex_str if len(hex_str) % 2 == 0 else "0" + hex_str
    return bytes.fromhex(clean)

def sha256_hex(*inputs) -> str:
    h = hashlib.sha256()
    for item in inputs:
        if isinstance(item, str):
            if all(c in "0123456789abcdefABCDEF" for c in item) and len(item) > 16:
                h.update(hex_to_bytes(item))
            else:
                h.update(item.encode('utf-8'))
        elif isinstance(item, bytes):
            h.update(item)
        elif isinstance(item, int):
            hex_val = hex(item)[2:]
            if len(hex_val) % 2 != 0:
                hex_val = "0" + hex_val
            h.update(bytes.fromhex(hex_val))
    return h.hexdigest()

def get_srp_k() -> int:
    k_hex = sha256_hex(SRP_N_HEX, "02")
    return int(k_hex, 16)

SRP_EPHEMERAL_SESSIONS: Dict[str, dict] = {}

def cleanup_srp_sessions():
    now = datetime.utcnow()
    expired = [email for email, sess in SRP_EPHEMERAL_SESSIONS.items() if (now - sess["created_at"]).total_seconds() > 300]
    for email in expired:
        SRP_EPHEMERAL_SESSIONS.pop(email, None)

def generate_srp_challenge(email: str, client_A_hex: str, verifier_hex: str) -> str:
    cleanup_srp_sessions()
    A = int(client_A_hex, 16)
    if A % SRP_N == 0:
        raise ValueError("Invalid client public key A")
    
    if verifier_hex.startswith("$2b$") or verifier_hex.startswith("$2a$") or len(verifier_hex) < 64:
        return ""
        
    try:
        v = int(verifier_hex, 16)
    except ValueError:
        return ""
        
    k = get_srp_k()
    
    b_bytes = secrets.token_bytes(32)
    b = int.from_bytes(b_bytes, "big")
    
    B = (k * v + pow(SRP_G, b, SRP_N)) % SRP_N
    B_hex = hex(B)[2:]
    if len(B_hex) % 2 != 0:
        B_hex = "0" + B_hex
    
    SRP_EPHEMERAL_SESSIONS[email.lower()] = {
        "A": A,
        "AHex": client_A_hex,
        "b": b,
        "B": B,
        "BHex": B_hex,
        "v": v,
        "created_at": datetime.utcnow()
    }
    
    return B_hex

def verify_srp_proof(email: str, client_A_hex: str, client_M1_hex: str) -> Tuple[bool, Optional[str]]:
    cleanup_srp_sessions()
    session = SRP_EPHEMERAL_SESSIONS.get(email.lower())
    if not session:
        return False, None
    
    A = session["A"]
    b = session["b"]
    B = session["B"]
    v = session["v"]
    AHex = session["AHex"]
    BHex = session["BHex"]
    
    u_hex = sha256_hex(AHex, BHex)
    u = int(u_hex, 16)
    if u == 0:
        return False, None
    
    v_u = pow(v, u, SRP_N)
    base = (A * v_u) % SRP_N
    S = pow(base, b, SRP_N)
    SHex = hex(S)[2:]
    if len(SHex) % 2 != 0:
        SHex = "0" + SHex
    
    KHex = sha256_hex(SHex)
    expected_M1 = sha256_hex(AHex, BHex, KHex)
    
    if client_M1_hex.lower() != expected_M1.lower():
        return False, None
    
    server_M2 = sha256_hex(AHex, client_M1_hex, KHex)
    SRP_EPHEMERAL_SESSIONS.pop(email.lower(), None)
    
    return True, server_M2

def hash_verifier(verifier: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(verifier.encode('utf-8'), salt).decode('utf-8')

def verify_verifier(plain_verifier: str, hashed_verifier: str) -> bool:
    try:
        if hashed_verifier.startswith("$2b$") or hashed_verifier.startswith("$2a$"):
            return bcrypt.checkpw(plain_verifier.encode('utf-8'), hashed_verifier.encode('utf-8'))
        return plain_verifier == hashed_verifier
    except Exception:
        return False

def hash_sha256(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

def generate_totp_secret() -> str:
    return pyotp.random_base32()

def get_totp_uri(email: str, secret: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="SecurePass")

def generate_qr_code_base64(uri: str) -> str:
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{img_base64}"

def verify_totp(secret: str, code: str) -> bool:
    totp = pyotp.totp.TOTP(secret)
    return totp.verify(code, valid_window=1)

def check_rate_limit_exceeded(db: DbSession, email: str) -> bool:
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    user = db.query(models.User).filter(models.User.email == email.lower()).first()
    if not user:
        return False
        
    failed_attempts_count = db.query(models.ActivityLog).filter(
        models.ActivityLog.user_id == user.id,
        models.ActivityLog.action == "login_failed",
        models.ActivityLog.timestamp >= one_hour_ago
    ).count()
    
    return failed_attempts_count >= 5
