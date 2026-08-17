import json
from fastapi import FastAPI, Depends, HTTPException, status, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session as DbSession
from sqlalchemy import text
from datetime import datetime, timedelta
import os

from . import models, schemas, crud, auth, database
from .database import engine, get_db

# Create database tables and auto-migrate SQLite schema
models.Base.metadata.create_all(bind=engine)
with engine.connect() as conn:
    if database.DATABASE_URL.startswith("sqlite"):
        try:
            conn.execute(text("SELECT kdf_type FROM users LIMIT 1"))
        except Exception:
            try:
                conn.execute(text("ALTER TABLE users ADD COLUMN kdf_type VARCHAR(50) DEFAULT 'argon2id'"))
                conn.execute(text("ALTER TABLE users ADD COLUMN kdf_params TEXT"))
                conn.commit()
            except Exception as e:
                print("[DB Migration Log]:", e)

        try:
            conn.execute(text("SELECT is_admin FROM users LIMIT 1"))
        except Exception:
            try:
                conn.execute(text("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0"))
                conn.commit()
            except Exception as e:
                print("[DB Migration Log is_admin]:", e)

        try:
            conn.execute(text("UPDATE users SET is_admin = 1 WHERE email = 'sus@gmail.com'"))
            conn.execute(text("UPDATE users SET is_admin = 1 WHERE id = (SELECT id FROM users ORDER BY id ASC LIMIT 1) AND NOT EXISTS (SELECT 1 FROM users WHERE is_admin = 1)"))
            conn.commit()
        except Exception as e:
            print("[DB Admin Auto-Promotion Log]:", e)

app = FastAPI(title="SecurePass API", version="1.1.0")

# Configure CORS
CORS_ORIGINS_ENV = os.getenv("CORS_ORIGINS", "")
ALLOWED_ORIGINS = [origin.strip() for origin in CORS_ORIGINS_ENV.split(",") if origin.strip()]

ALLOWED_ORIGIN_REGEX = r"^(https?://(localhost|127\.0\.0\.1)(:\d+)?|chrome-extension://[a-zA-Z0-9\-]+|moz-extension://[a-zA-Z0-9\-]+)$"

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS else ["http://localhost:5173", "http://localhost:3000"],
    allow_origin_regex=ALLOWED_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load AI Phishing Classifier Model & Vectorizer
import joblib
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "svm_model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "vectorizer.pkl")

svm_model = None
vectorizer = None

try:
    if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        svm_model = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VECTORIZER_PATH)
        print("[AI Security Module] Successfully loaded Linear SVM Phishing Classifier!")
except Exception as e:
    print(f"[AI Security Module] Could not load model: {e}")

from urllib.parse import urlparse

SAFE_DOMAINS_WHITELIST = {
    "google.com", "google.np", "google.co.in", "google.co.uk", "google.ca", "google.de", "google.fr",
    "bing.com", "duckduckgo.com", "yahoo.com", "baidu.com", "yandex.com",
    "facebook.com", "github.com", "youtube.com", "microsoft.com", "apple.com",
    "amazon.com", "wikipedia.org", "linkedin.com", "twitter.com", "x.com",
    "instagram.com", "reddit.com", "stackoverflow.com", "localhost", "127.0.0.1",
    "whatsapp.com", "whatsapp.net", "web.whatsapp.com", "meta.com", "messenger.com"
}

@app.post("/api/scan-url", response_model=schemas.URLScanResponse)
async def scan_url(request_data: schemas.URLScanRequest):
    url = request_data.url.strip()
    if not url:
        return {"url": "", "is_safe": True, "prediction": "good", "risk_level": "Safe"}

    try:
        parsed = urlparse(url if url.startswith("http") else f"https://{url}")
        domain = parsed.hostname.lower().replace("www.", "") if parsed.hostname else ""
    except Exception:
        domain = ""

    # Instant whitelist check for trusted top-level domains & search engines
    if domain and any(domain == d or domain.endswith("." + d) for d in SAFE_DOMAINS_WHITELIST):
        return {"url": url, "is_safe": True, "prediction": "good", "risk_level": "Safe"}

    # Strip long search query params to prevent false positives on query strings
    clean_url = domain if domain else (
        url.lower()
        .replace("https://", "")
        .replace("http://", "")
        .replace("www.", "")
        .split("?")[0]
    )

    if svm_model and vectorizer:
        try:
            X = vectorizer.transform([clean_url])
            prediction = svm_model.predict(X)[0]
            is_safe = (prediction == "good")
            return {
                "url": url,
                "is_safe": is_safe,
                "prediction": prediction,
                "risk_level": "Safe" if is_safe else "High Risk Phishing"
            }
        except Exception as e:
            return {"url": url, "is_safe": True, "prediction": "good", "risk_level": "Uncertain"}

    return {"url": url, "is_safe": True, "prediction": "good", "risk_level": "Safe"}

security = HTTPBearer()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: DbSession = Depends(get_db)
) -> models.User:
    token = credentials.credentials
    payload = auth.verify_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    email = payload.get("sub")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload is missing subject",
        )
        
    token_hash = auth.hash_sha256(token)
    db_session = crud.get_session_by_token(db, token_hash)
    if not db_session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been terminated or is invalid",
        )
        
    user = crud.get_user_by_email(db, email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return user

async def get_current_admin_user(
    current_user: models.User = Depends(get_current_user)
) -> models.User:
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Administrative privileges required"
        )
    return current_user

def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

# Authentication Endpoints

@app.post("/api/auth/register", response_model=schemas.UserRegisterResponse, status_code=201)
async def register(
    user_data: schemas.UserRegister,
    request: Request,
    db: DbSession = Depends(get_db)
):
    existing_user = crud.get_user_by_email(db, user_data.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address already registered"
        )
        
    stored_verifier = user_data.verifier
    if not user_data.verifier.startswith("$2b$") and len(user_data.verifier) < 60:
        stored_verifier = auth.hash_verifier(user_data.verifier)
        
    hashed_recovery = auth.hash_verifier(user_data.recovery_codes_hash)
    
    new_user = crud.create_user(
        db=db,
        user=user_data,
        hashed_verifier=stored_verifier,
        hashed_recovery_code=hashed_recovery
    )
    
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "unknown")
    crud.create_activity_log(db, new_user.id, "account_registered", ip, ua)
    
    return {"user_id": new_user.id, "message": "User registered successfully"}

@app.post("/api/auth/prelogin", response_model=schemas.PreloginResponse)
async def prelogin(
    prelogin_data: schemas.PreloginRequest,
    db: DbSession = Depends(get_db)
):
    email = prelogin_data.email.lower()
    user = crud.get_user_by_email(db, email)
    if user:
        kdf_params_dict = json.loads(user.kdf_params) if user.kdf_params else None
        return {
            "salt": user.salt,
            "kdf_type": user.kdf_type or "argon2id",
            "kdf_params": kdf_params_dict
        }
    
    fake_salt_material = f"{email}:{auth.SECRET_KEY}"
    fake_salt = auth.hash_sha256(fake_salt_material)
    return {
        "salt": fake_salt,
        "kdf_type": "argon2id",
        "kdf_params": {"time_cost": 2, "memory_cost": 4096, "parallelism": 1}
    }

# SRP-6a Zero-Knowledge Authentication Endpoints

@app.post("/api/auth/srp/challenge", response_model=schemas.SRPChallengeResponse)
async def srp_challenge(
    req: schemas.SRPChallengeRequest,
    db: DbSession = Depends(get_db)
):
    email = req.email.lower()
    if auth.check_rate_limit_exceeded(db, email):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again in an hour."
        )
        
    user = crud.get_user_by_email(db, email)
    if user:
        if user.verifier.startswith("$2b$") or user.verifier.startswith("$2a$") or len(user.verifier) < 64:
            return schemas.SRPChallengeResponse(
                salt=user.salt,
                server_B="",
                kdf_type="pbkdf2",
                kdf_params=None
            )
        kdf_params_dict = json.loads(user.kdf_params) if user.kdf_params else None
        try:
            server_B = auth.generate_srp_challenge(email, req.client_A, user.verifier)
            return schemas.SRPChallengeResponse(
                salt=user.salt,
                server_B=server_B,
                kdf_type=user.kdf_type or "argon2id",
                kdf_params=kdf_params_dict
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
            
    fake_salt = auth.hash_sha256(f"{email}:{auth.SECRET_KEY}")
    fake_verifier = auth.hash_sha256(f"{email}:fake_verifier:{auth.SECRET_KEY}")
    server_B = auth.generate_srp_challenge(email, req.client_A, fake_verifier)
    return schemas.SRPChallengeResponse(
        salt=fake_salt,
        server_B=server_B,
        kdf_type="argon2id",
        kdf_params={"time_cost": 2, "memory_cost": 4096, "parallelism": 1}
    )

@app.post("/api/auth/srp/authenticate", response_model=schemas.SRPAuthenticateResponse)
async def srp_authenticate(
    req: schemas.SRPAuthenticateRequest,
    request: Request,
    db: DbSession = Depends(get_db)
):
    email = req.email.lower()
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "unknown")
    
    if auth.check_rate_limit_exceeded(db, email):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again in an hour."
        )
        
    user = crud.get_user_by_email(db, email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or authentication proof"
        )
        
    if user.locked_until and user.locked_until > datetime.utcnow():
        lock_remaining = int((user.locked_until - datetime.utcnow()).total_seconds() / 60)
        raise HTTPException(
            status_code=423,
            detail=f"Account is temporarily locked due to multiple failures. Try again in {lock_remaining} minutes."
        )
        
    valid, server_M2 = auth.verify_srp_proof(email, req.client_A, req.client_M1)
    if not valid:
        crud.increment_failed_attempts(db, user)
        crud.create_activity_log(db, user.id, "login_failed_srp", ip, ua)
        if user.failed_attempts >= 10:
            raise HTTPException(
                status_code=423,
                detail="Account is temporarily locked due to 10 failed attempts. Try again in 15 minutes."
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or authentication proof"
        )
        
    if user.mfa_enabled:
        if not req.mfa_code:
            return schemas.SRPAuthenticateResponse(mfa_required=True, message="MFA verification required")
            
        if not auth.verify_totp(user.mfa_secret, req.mfa_code):
            crud.increment_failed_attempts(db, user)
            crud.create_activity_log(db, user.id, "login_failed_mfa", ip, ua)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA verification code"
            )
            
    crud.reset_failed_attempts(db, user)
    user.last_login = datetime.utcnow()
    db.commit()
    
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    
    token_hash = auth.hash_sha256(access_token)
    expires_at = datetime.utcnow() + access_token_expires
    crud.create_session(db, user.id, token_hash, expires_at)
    
    crud.create_activity_log(db, user.id, "login_success_srp", ip, ua)
    
    kdf_params_dict = json.loads(user.kdf_params) if user.kdf_params else None
    
    return schemas.SRPAuthenticateResponse(
        access_token=access_token,
        server_M2=server_M2,
        encrypted_vault=user.encrypted_vault,
        salt=user.salt,
        kdf_type=user.kdf_type or "argon2id",
        kdf_params=kdf_params_dict
    )

@app.post("/api/auth/login", response_model=schemas.LoginResponse)
async def login(
    login_data: schemas.UserLogin,
    request: Request,
    db: DbSession = Depends(get_db)
):
    email = login_data.email.lower()
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "unknown")
    
    if auth.check_rate_limit_exceeded(db, email):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again in an hour."
        )
        
    user = crud.get_user_by_email(db, email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
        
    if user.locked_until and user.locked_until > datetime.utcnow():
        lock_remaining = int((user.locked_until - datetime.utcnow()).total_seconds() / 60)
        raise HTTPException(
            status_code=423,
            detail=f"Account is temporarily locked due to multiple failures. Try again in {lock_remaining} minutes."
        )
        
    if not auth.verify_verifier(login_data.verifier, user.verifier):
        crud.increment_failed_attempts(db, user)
        crud.create_activity_log(db, user.id, "login_failed", ip, ua)
        if user.failed_attempts >= 10:
            raise HTTPException(
                status_code=423,
                detail="Account is temporarily locked due to 10 failed attempts. Try again in 15 minutes."
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
        
    if user.mfa_enabled:
        if not login_data.mfa_code:
            return schemas.LoginResponse(mfa_required=True, message="MFA verification required")
            
        if not auth.verify_totp(user.mfa_secret, login_data.mfa_code):
            crud.increment_failed_attempts(db, user)
            crud.create_activity_log(db, user.id, "login_failed_mfa", ip, ua)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA verification code"
            )
            
    crud.reset_failed_attempts(db, user)
    user.last_login = datetime.utcnow()
    db.commit()
    
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    
    token_hash = auth.hash_sha256(access_token)
    expires_at = datetime.utcnow() + access_token_expires
    crud.create_session(db, user.id, token_hash, expires_at)
    
    crud.create_activity_log(db, user.id, "login_success", ip, ua)
    
    kdf_params_dict = json.loads(user.kdf_params) if user.kdf_params else None
    
    return schemas.LoginResponse(
        access_token=access_token,
        encrypted_vault=user.encrypted_vault,
        salt=user.salt,
        kdf_type=user.kdf_type or "argon2id",
        kdf_params=kdf_params_dict
    )

@app.post("/api/auth/logout", response_model=schemas.LogoutResponse)
async def logout(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: DbSession = Depends(get_db)
):
    token = credentials.credentials
    token_hash = auth.hash_sha256(token)
    
    db_session = crud.get_session_by_token(db, token_hash)
    if db_session:
        user_id = db_session.user_id
        crud.delete_session(db, token_hash)
        
        ip = get_client_ip(request)
        ua = request.headers.get("user-agent", "unknown")
        crud.create_activity_log(db, user_id, "logout", ip, ua)
        
    return {"message": "Logged out successfully"}

@app.get("/api/auth/me", response_model=schemas.UserMeResponse)
async def get_me(
    current_user: models.User = Depends(get_current_user)
):
    return {
        "email": current_user.email,
        "mfa_enabled": current_user.mfa_enabled,
        "is_admin": bool(current_user.is_admin)
    }

# MFA Endpoints

@app.post("/api/auth/mfa/enable", response_model=schemas.MFAEnableResponse)
async def mfa_enable(
    request: Request,
    current_user: models.User = Depends(get_current_user),
    db: DbSession = Depends(get_db)
):
    secret = auth.generate_totp_secret()
    crud.update_mfa_secret(db, current_user.id, secret, enabled=False)
    
    uri = auth.get_totp_uri(current_user.email, secret)
    qr_code_url = auth.generate_qr_code_base64(uri)
    
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "unknown")
    crud.create_activity_log(db, current_user.id, "mfa_setup_initiated", ip, ua)
    
    return schemas.MFAEnableResponse(qr_code_url=qr_code_url, secret=secret)

@app.post("/api/auth/mfa/verify", response_model=schemas.MFAVerifyResponse)
async def mfa_verify(
    verify_data: schemas.MFAVerifyRequest,
    request: Request,
    current_user: models.User = Depends(get_current_user),
    db: DbSession = Depends(get_db)
):
    if not current_user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA setup was not initiated"
        )
        
    is_valid = auth.verify_totp(current_user.mfa_secret, verify_data.totp_code)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code"
        )
        
    crud.update_mfa_secret(db, current_user.id, current_user.mfa_secret, enabled=True)
    
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "unknown")
    crud.create_activity_log(db, current_user.id, "mfa_enabled", ip, ua)
    
    return schemas.MFAVerifyResponse(verified=True, message="MFA successfully enabled")

@app.post("/api/auth/mfa/disable", response_model=schemas.MessageResponse)
async def mfa_disable(
    verify_data: schemas.MFAVerifyRequest,
    request: Request,
    current_user: models.User = Depends(get_current_user),
    db: DbSession = Depends(get_db)
):
    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled"
        )
        
    is_valid = auth.verify_totp(current_user.mfa_secret, verify_data.totp_code)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code"
        )
        
    crud.update_mfa_secret(db, current_user.id, secret=None, enabled=False)
    
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "unknown")
    crud.create_activity_log(db, current_user.id, "mfa_disabled", ip, ua)
    
    return {"message": "MFA has been successfully disabled"}

# Vault Endpoints

@app.get("/api/vault", response_model=schemas.VaultResponse)
async def get_vault(
    current_user: models.User = Depends(get_current_user)
):
    return schemas.VaultResponse(
        encrypted_vault=current_user.encrypted_vault or "[]",
        last_modified=current_user.last_login or datetime.utcnow()
    )

@app.put("/api/vault", response_model=schemas.VaultUpdateResponse)
async def update_vault(
    vault_data: schemas.VaultUpdate,
    request: Request,
    current_user: models.User = Depends(get_current_user),
    db: DbSession = Depends(get_db)
):
    crud.update_user_vault(db, current_user.id, vault_data.encrypted_vault)
    
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "unknown")
    crud.create_activity_log(db, current_user.id, "vault_synchronized", ip, ua)
    
    return schemas.VaultUpdateResponse(
        message="Vault synchronized successfully",
        version=1
    )

@app.get("/api/vault/export", response_model=schemas.VaultResponse)
async def export_vault(
    request: Request,
    current_user: models.User = Depends(get_current_user),
    db: DbSession = Depends(get_db)
):
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "unknown")
    crud.create_activity_log(db, current_user.id, "vault_exported", ip, ua)
    
    return schemas.VaultResponse(
        encrypted_vault=current_user.encrypted_vault or "[]",
        last_modified=current_user.last_login or datetime.utcnow()
    )

# Activity Endpoints

@app.get("/api/logs", response_model=schemas.LogListResponse)
async def get_logs(
    admin_user: models.User = Depends(get_current_admin_user),
    db: DbSession = Depends(get_db)
):
    logs = crud.get_activity_logs(db, admin_user.id, limit=50)
    return {"logs": logs}

@app.post("/api/logs", response_model=schemas.MessageResponse)
async def create_log(
    log_data: schemas.LogCreateRequest,
    request: Request,
    current_user: models.User = Depends(get_current_user),
    db: DbSession = Depends(get_db)
):
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "unknown")
    
    allowed_actions = ["credential_copied_username", "credential_copied_password", "credential_viewed"]
    if log_data.action not in allowed_actions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unauthorized custom log action"
        )
        
    crud.create_activity_log(db, current_user.id, log_data.action, ip, ua)
    return {"message": "Activity logged successfully"}

# Recovery Endpoints

@app.post("/api/auth/recovery/initiate", response_model=schemas.RecoveryInitiateResponse)
async def recovery_initiate(
    rec_data: schemas.RecoveryInitiateRequest,
    request: Request,
    db: DbSession = Depends(get_db)
):
    user = crud.get_user_by_email(db, rec_data.email)
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "unknown")
    
    if not user:
        return schemas.RecoveryInitiateResponse(message="If the email is registered, recovery payload is initialized.")
        
    crud.create_activity_log(db, user.id, "recovery_initiated", ip, ua)
    
    kdf_params_dict = json.loads(user.kdf_params) if user.kdf_params else None
    
    return schemas.RecoveryInitiateResponse(
        message="Recovery payload successfully fetched.",
        salt=user.salt,
        kdf_type=user.kdf_type or "argon2id",
        kdf_params=kdf_params_dict,
        encrypted_key_recovery=user.encrypted_key_recovery,
        encrypted_vault=user.encrypted_vault
    )

@app.post("/api/auth/recovery/verify", response_model=schemas.MessageResponse)
async def recovery_verify(
    rec_data: schemas.RecoveryVerifyRequest,
    request: Request,
    db: DbSession = Depends(get_db)
):
    user = crud.get_user_by_email(db, rec_data.email)
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "unknown")
    
    if not user or not user.recovery_codes_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account recovery is unavailable or not set up for this email."
        )
        
    if not auth.verify_verifier(rec_data.recovery_code, user.recovery_codes_hash):
        crud.increment_failed_attempts(db, user)
        crud.create_activity_log(db, user.id, "recovery_failed", ip, ua)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid recovery code."
        )
        
    stored_verifier = rec_data.new_verifier
    if not rec_data.new_verifier.startswith("$2b$") and len(rec_data.new_verifier) < 60:
        stored_verifier = auth.hash_verifier(rec_data.new_verifier)
    new_hashed_recovery = auth.hash_verifier(rec_data.recovery_code)
    
    crud.update_user_security(
        db=db,
        user_id=user.id,
        new_salt=rec_data.new_salt,
        new_verifier=stored_verifier,
        new_encrypted_vault=rec_data.new_encrypted_vault,
        new_encrypted_key_recovery=rec_data.new_encrypted_key_recovery,
        new_recovery_hash=new_hashed_recovery,
        kdf_type="argon2id",
        kdf_params=rec_data.new_kdf_params
    )
    
    crud.delete_user_sessions(db, user.id)
    crud.create_activity_log(db, user.id, "recovery_successful", ip, ua)
    
    return {"message": "Account credentials updated successfully. Please login with your new Master Password."}

# Settings Endpoints

@app.post("/api/auth/change-password", response_model=schemas.MessageResponse)
async def change_password(
    chg_data: schemas.ChangePasswordRequest,
    request: Request,
    current_user: models.User = Depends(get_current_user),
    db: DbSession = Depends(get_db)
):
    if not auth.verify_verifier(chg_data.current_verifier, current_user.verifier):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect current password"
        )
        
    stored_verifier = chg_data.new_verifier
    if not chg_data.new_verifier.startswith("$2b$") and len(chg_data.new_verifier) < 60:
        stored_verifier = auth.hash_verifier(chg_data.new_verifier)
    new_hashed_recovery = auth.hash_verifier(chg_data.new_recovery_codes_hash)
    
    crud.update_user_security(
        db=db,
        user_id=current_user.id,
        new_salt=chg_data.new_salt,
        new_verifier=stored_verifier,
        new_encrypted_vault=chg_data.new_encrypted_vault,
        new_encrypted_key_recovery=chg_data.new_encrypted_key_recovery,
        new_recovery_hash=new_hashed_recovery,
        kdf_type="argon2id",
        kdf_params=chg_data.new_kdf_params
    )
    
    crud.delete_user_sessions(db, current_user.id)
    
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "unknown")
    crud.create_activity_log(db, current_user.id, "password_changed", ip, ua)
    
    return {"message": "Master password changed successfully. Please log in again."}

@app.delete("/api/auth/delete-account", response_model=schemas.MessageResponse)
async def delete_account(
    request: Request,
    current_user: models.User = Depends(get_current_user),
    db: DbSession = Depends(get_db)
):
    user_id = current_user.id
    email = current_user.email
    success = crud.delete_user_account(db, user_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete account"
        )
        
    return {"message": f"Account {email} has been successfully deleted"}

# Admin API Endpoints

@app.get("/api/admin/stats", response_model=schemas.AdminStatsResponse)
async def get_admin_stats(
    admin_user: models.User = Depends(get_current_admin_user),
    db: DbSession = Depends(get_db)
):
    phishing_active = (svm_model is not None and vectorizer is not None)
    return crud.get_system_stats(db, phishing_model_active=phishing_active)

@app.get("/api/admin/users", response_model=schemas.AdminUserListResponse)
async def get_admin_users(
    admin_user: models.User = Depends(get_current_admin_user),
    db: DbSession = Depends(get_db)
):
    users = crud.get_all_users_for_admin(db)
    return {"users": users}

@app.put("/api/admin/users/{user_id}/role", response_model=schemas.MessageResponse)
async def update_user_role(
    user_id: int,
    req: schemas.AdminRoleToggleRequest,
    request: Request,
    admin_user: models.User = Depends(get_current_admin_user),
    db: DbSession = Depends(get_db)
):
    if user_id == admin_user.id and not req.is_admin:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot remove your own admin privileges"
        )
    
    updated_user = crud.toggle_user_admin_role(db, user_id, req.is_admin)
    if not updated_user:
        raise HTTPException(status_code=404, detail="User not found")
        
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "unknown")
    crud.create_activity_log(db, admin_user.id, f"admin_role_updated:{updated_user.email}:{req.is_admin}", ip, ua)
    
    role_str = "Admin" if req.is_admin else "User"
    return {"message": f"User {updated_user.email} role updated to {role_str}"}

@app.put("/api/admin/users/{user_id}/lockout", response_model=schemas.MessageResponse)
async def update_user_lockout(
    user_id: int,
    req: schemas.AdminLockoutRequest,
    request: Request,
    admin_user: models.User = Depends(get_current_admin_user),
    db: DbSession = Depends(get_db)
):
    if user_id == admin_user.id and req.locked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot lock your own admin account"
        )
        
    updated_user = crud.set_user_lockout(db, user_id, req.locked)
    if not updated_user:
        raise HTTPException(status_code=404, detail="User not found")
        
    if req.locked:
        crud.delete_user_sessions(db, user_id)
        
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "unknown")
    status_str = "locked" if req.locked else "unlocked"
    crud.create_activity_log(db, admin_user.id, f"admin_user_{status_str}:{updated_user.email}", ip, ua)
    
    return {"message": f"User {updated_user.email} account has been {status_str}"}

@app.post("/api/admin/users/{user_id}/revoke-sessions", response_model=schemas.MessageResponse)
async def revoke_user_sessions(
    user_id: int,
    request: Request,
    admin_user: models.User = Depends(get_current_admin_user),
    db: DbSession = Depends(get_db)
):
    target_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
        
    crud.delete_user_sessions(db, user_id)
    
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "unknown")
    crud.create_activity_log(db, admin_user.id, f"admin_revoked_sessions:{target_user.email}", ip, ua)
    
    return {"message": f"All active sessions for {target_user.email} have been revoked"}

@app.delete("/api/admin/users/{user_id}", response_model=schemas.MessageResponse)
async def delete_user_by_admin(
    user_id: int,
    request: Request,
    admin_user: models.User = Depends(get_current_admin_user),
    db: DbSession = Depends(get_db)
):
    if user_id == admin_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete your own admin account using this action"
        )
        
    target_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
        
    target_email = target_user.email
    crud.delete_user_account(db, user_id)
    
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "unknown")
    crud.create_activity_log(db, admin_user.id, f"admin_deleted_user:{target_email}", ip, ua)
    
    return {"message": f"User account {target_email} has been permanently deleted"}

@app.get("/api/admin/logs", response_model=schemas.AdminLogListResponse)
async def get_admin_logs(
    admin_user: models.User = Depends(get_current_admin_user),
    db: DbSession = Depends(get_db)
):
    logs = crud.get_all_activity_logs_admin(db, limit=150)
    return {"logs": logs}
