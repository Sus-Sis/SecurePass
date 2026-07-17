import os
import hashlib
from datetime import datetime, timedelta
from typing import Optional
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

def hash_verifier(verifier: str) -> str:
    """Hash the client-provided verifier (SHA256 hash of Master Key) using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(verifier.encode('utf-8'), salt).decode('utf-8')

def verify_verifier(plain_verifier: str, hashed_verifier: str) -> bool:
    """Verify the client-provided verifier against the stored bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_verifier.encode('utf-8'), hashed_verifier.encode('utf-8'))
    except Exception:
        return False

def hash_sha256(text: str) -> str:
    """Helper to compute SHA-256 hash of a string (useful for tokens and recovery codes)."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_access_token(token: str) -> Optional[dict]:
    """Verify a JWT access token and return its payload."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

# MFA (TOTP) helpers
def generate_totp_secret() -> str:
    """Generate a random Base32 TOTP secret."""
    return pyotp.random_base32()

def get_totp_uri(email: str, secret: str) -> str:
    """Get the standard TOTP URI for authenticator apps."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="SecurePass")

def generate_qr_code_base64(uri: str) -> str:
    """Generate a QR code image as a Base64 data URI string."""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{img_base64}"

def verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code against the secret."""
    totp = pyotp.totp.TOTP(secret)
    # Allows a small window of drift (30 seconds before and after)
    return totp.verify(code, valid_window=1)

# Rate Limiting & Lockout helper
def check_rate_limit_exceeded(db: DbSession, email: str) -> bool:
    """
    Check if the login attempts for this email exceed the rate limit of
    5 attempts per hour.
    """
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    
    # We query the User's logs directly. If user doesn't exist, we don't block by DB records,
    # but we will check for user in DB. If user does exist, count login_failed logs.
    # Note: To also rate limit non-existent users, we can check logs with matching action
    # containing the email or matching IP, but email rate limiting on the database is fine.
    # Let's count matching "failed_login" logs associated with the user ID in the last hour.
    user = db.query(models.User).filter(models.User.email == email.lower()).first()
    if not user:
        return False
        
    failed_attempts_count = db.query(models.ActivityLog).filter(
        models.ActivityLog.user_id == user.id,
        models.ActivityLog.action == "login_failed",
        models.ActivityLog.timestamp >= one_hour_ago
    ).count()
    
    return failed_attempts_count >= 5
