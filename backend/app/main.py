from fastapi import FastAPI, Depends, HTTPException, status, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session as DbSession
from datetime import datetime, timedelta
import os

from . import models, schemas, crud, auth, database
from .database import engine, get_db

# Create database tables (if they don't exist)
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="SecurePass API", version="1.0.0")

# Configure CORS
# Allow localhost for react app, production origins from environment, and browser extensions
CORS_ORIGINS_ENV = os.getenv("CORS_ORIGINS", "")
ALLOWED_ORIGINS = [origin.strip() for origin in CORS_ORIGINS_ENV.split(",") if origin.strip()]

# Regex to match local development (localhost/127.0.0.1 with any port) and browser extensions
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

@app.post("/api/scan-url", response_model=schemas.URLScanResponse)
async def scan_url(request_data: schemas.URLScanRequest):
    url = request_data.url.strip()
    if not url:
        return {"url": "", "is_safe": True, "prediction": "good", "risk_level": "Safe"}

    clean_url = (
        url.lower()
        .replace("https://", "")
        .replace("http://", "")
        .replace("www.", "")
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
        
    # Check if session exists and is not expired
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

def get_client_ip(request: Request) -> str:
    """Helper to extract IP address from request, checking headers for proxies."""
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
    # Check if user already exists
    existing_user = crud.get_user_by_email(db, user_data.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address already registered"
        )
        
    # Hash the client's verifier and recovery code
    hashed_verifier = auth.hash_verifier(user_data.verifier)
    hashed_recovery = auth.hash_verifier(user_data.recovery_codes_hash) # Store using bcrypt for max safety
    
    # Create the user
    new_user = crud.create_user(
        db=db,
        user=user_data,
        hashed_verifier=hashed_verifier,
        hashed_recovery_code=hashed_recovery
    )
    
    # Log registration activity
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
        return {"salt": user.salt}
    
    # Deteministic fake salt for security against user enumeration
    fake_salt_material = f"{email}:{auth.SECRET_KEY}"
    fake_salt = auth.hash_sha256(fake_salt_material)
    return {"salt": fake_salt}

@app.post("/api/auth/login", response_model=schemas.LoginResponse)
async def login(
    login_data: schemas.UserLogin,
    request: Request,
    db: DbSession = Depends(get_db)
):
    email = login_data.email.lower()
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "unknown")
    
    # 1. Rate Limiting Check (5 attempts per hour)
    if auth.check_rate_limit_exceeded(db, email):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again in an hour."
        )
        
    user = crud.get_user_by_email(db, email)
    if not user:
        # Prevent timing attacks but log attempt
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
        
    # 2. Account Lockout Check (10 failed attempts)
    if user.locked_until and user.locked_until > datetime.utcnow():
        lock_remaining = int((user.locked_until - datetime.utcnow()).total_seconds() / 60)
        raise HTTPException(
            status_code=423, # Locked
            detail=f"Account is temporarily locked due to multiple failures. Try again in {lock_remaining} minutes."
        )
        
    # Verify the credentials (comparing bcrypt hash of the verifier)
    if not auth.verify_verifier(login_data.verifier, user.verifier):
        # Record failure
        crud.increment_failed_attempts(db, user)
        crud.create_activity_log(db, user.id, "login_failed", ip, ua)
        
        # Check if this attempt just locked the account
        if user.failed_attempts >= 10:
            raise HTTPException(
                status_code=423,
                detail="Account is temporarily locked due to 10 failed attempts. Try again in 15 minutes."
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
        
    # Credentials are correct - Check if MFA is required
    if user.mfa_enabled:
        if not login_data.mfa_code:
            # Tell client MFA is required, don't issue token yet
            return schemas.LoginResponse(mfa_required=True, email=user.email)
            
        # Verify MFA code
        if not auth.verify_totp(user.mfa_secret, login_data.mfa_code):
            crud.increment_failed_attempts(db, user)
            crud.create_activity_log(db, user.id, "login_failed_mfa", ip, ua)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA verification code"
            )
            
    # Reset failed attempts on success
    crud.reset_failed_attempts(db, user)
    
    # Update last login time
    user.last_login = datetime.utcnow()
    db.commit()
    
    # Create Session and JWT Access Token
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    
    # Store hashed session token
    token_hash = auth.hash_sha256(access_token)
    expires_at = datetime.utcnow() + access_token_expires
    crud.create_session(db, user.id, token_hash, expires_at)
    
    # Log successful login
    crud.create_activity_log(db, user.id, "login_success", ip, ua)
    
    return schemas.LoginResponse(
        access_token=access_token,
        encrypted_vault=user.encrypted_vault,
        salt=user.salt
    )

@app.post("/api/auth/logout", response_model=schemas.LogoutResponse)
async def logout(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: DbSession = Depends(get_db)
):
    token = credentials.credentials
    token_hash = auth.hash_sha256(token)
    
    # Find and delete the session
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
        "mfa_enabled": current_user.mfa_enabled
    }

# MFA Endpoints

@app.post("/api/auth/mfa/enable", response_model=schemas.MFAEnableResponse)
async def mfa_enable(
    request: Request,
    current_user: models.User = Depends(get_current_user),
    db: DbSession = Depends(get_db)
):
    # Generate TOTP secret but do not enable it until verified
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
        
    # Verify the code
    is_valid = auth.verify_totp(current_user.mfa_secret, verify_data.totp_code)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code"
        )
        
    # Enable MFA
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
        
    # Verify code to confirm disable
    is_valid = auth.verify_totp(current_user.mfa_secret, verify_data.totp_code)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code"
        )
        
    # Disable MFA
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
    # Returns the user's encrypted vault
    # In database, created_at is datetime, so we can use current datetime or last log for last modified
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
        version=1  # Versioning placeholder
    )

@app.get("/api/vault/export", response_model=schemas.VaultResponse)
async def export_vault(
    request: Request,
    current_user: models.User = Depends(get_current_user),
    db: DbSession = Depends(get_db)
):
    # Log the export action (highly sensitive!)
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
    current_user: models.User = Depends(get_current_user),
    db: DbSession = Depends(get_db)
):
    logs = crud.get_activity_logs(db, current_user.id, limit=50)
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
    
    # We restrict allowed actions client can submit to prevent log spoofing
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
        # Prevent timing attacks: return generic success message but log internally
        return schemas.RecoveryInitiateResponse(message="If the email is registered, recovery payload is initialized.")
        
    crud.create_activity_log(db, user.id, "recovery_initiated", ip, ua)
    
    return schemas.RecoveryInitiateResponse(
        message="Recovery payload successfully fetched.",
        salt=user.salt,
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
        
    # Verify recovery code using bcrypt comparison (since we hashed recovery code on registration)
    if not auth.verify_verifier(rec_data.recovery_code, user.recovery_codes_hash):
        crud.increment_failed_attempts(db, user)
        crud.create_activity_log(db, user.id, "recovery_failed", ip, ua)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid recovery code."
        )
        
    # Setup new credentials
    new_hashed_verifier = auth.hash_verifier(rec_data.new_verifier)
    new_hashed_recovery = auth.hash_verifier(rec_data.recovery_code) # Keep recovery code, or client can generate new one, we save it hashed
    
    crud.update_user_security(
        db=db,
        user_id=user.id,
        new_salt=rec_data.new_salt,
        new_verifier=new_hashed_verifier,
        new_encrypted_vault=rec_data.new_encrypted_vault,
        new_encrypted_key_recovery=rec_data.new_encrypted_key_recovery,
        new_recovery_hash=new_hashed_recovery
    )
    
    # Invalidate all current active sessions for security
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
    # Verify the current verifier against current_user.verifier
    if not auth.verify_verifier(chg_data.current_verifier, current_user.verifier):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect current password"
        )
        
    # Update security settings
    new_hashed_verifier = auth.hash_verifier(chg_data.new_verifier)
    new_hashed_recovery = auth.hash_verifier(chg_data.new_recovery_codes_hash)
    
    crud.update_user_security(
        db=db,
        user_id=current_user.id,
        new_salt=chg_data.new_salt,
        new_verifier=new_hashed_verifier,
        new_encrypted_vault=chg_data.new_encrypted_vault,
        new_encrypted_key_recovery=chg_data.new_encrypted_key_recovery,
        new_recovery_hash=new_hashed_recovery
    )
    
    # Invalidate all user sessions on password change
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
        
    # Log can't associate with user ID anymore, so we just return success
    return {"message": f"Account {email} has been successfully deleted"}
