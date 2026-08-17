import json
from sqlalchemy.orm import Session as DbSession
from datetime import datetime, timedelta
from typing import Optional
from . import models, schemas

def get_user_by_email(db: DbSession, email: str) -> Optional[models.User]:
    return db.query(models.User).filter(models.User.email == email.lower()).first()

def create_user(db: DbSession, user: schemas.UserRegister, hashed_verifier: str, hashed_recovery_code: str) -> models.User:
    kdf_params_str = json.dumps(user.kdf_params) if user.kdf_params else None
    user_count = db.query(models.User).count()
    is_first_user = (user_count == 0)
    
    db_user = models.User(
        email=user.email.lower(),
        salt=user.salt,
        verifier=hashed_verifier,
        kdf_type=user.kdf_type or "argon2id",
        kdf_params=kdf_params_str,
        encrypted_vault=user.encrypted_vault,
        encrypted_key_recovery=user.encrypted_key_recovery,
        recovery_codes_hash=hashed_recovery_code,
        is_admin=is_first_user,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def update_user_vault(db: DbSession, user_id: int, encrypted_vault: str) -> models.User:
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user:
        db_user.encrypted_vault = encrypted_vault
        db.commit()
        db.refresh(db_user)
    return db_user

def update_user_security(db: DbSession, user_id: int, new_salt: str, new_verifier: str, new_encrypted_vault: str, new_encrypted_key_recovery: str, new_recovery_hash: str, kdf_type: str = "argon2id", kdf_params: Optional[dict] = None) -> models.User:
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user:
        db_user.salt = new_salt
        db_user.verifier = new_verifier
        db_user.kdf_type = kdf_type
        if kdf_params:
            db_user.kdf_params = json.dumps(kdf_params)
        db_user.encrypted_vault = new_encrypted_vault
        db_user.encrypted_key_recovery = new_encrypted_key_recovery
        db_user.recovery_codes_hash = new_recovery_hash
        db_user.failed_attempts = 0
        db_user.locked_until = None
        db.commit()
        db.refresh(db_user)
    return db_user

def delete_user_account(db: DbSession, user_id: int) -> bool:
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user:
        db.delete(db_user)
        db.commit()
        return True
    return False

def update_mfa_secret(db: DbSession, user_id: int, secret: Optional[str], enabled: bool) -> models.User:
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user:
        db_user.mfa_secret = secret
        db_user.mfa_enabled = enabled
        db.commit()
        db.refresh(db_user)
    return db_user

def increment_failed_attempts(db: DbSession, user: models.User) -> models.User:
    user.failed_attempts += 1
    if user.failed_attempts >= 10:
        user.locked_until = datetime.utcnow() + timedelta(minutes=15)
    db.commit()
    db.refresh(user)
    return user

def reset_failed_attempts(db: DbSession, user: models.User) -> models.User:
    user.failed_attempts = 0
    user.locked_until = None
    db.commit()
    db.refresh(user)
    return user

# Session management
def create_session(db: DbSession, user_id: int, token_hash: str, expires_at: datetime) -> models.Session:
    db_session = models.Session(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at
    )
    db.add(db_session)
    db.commit()
    db.refresh(db_session)
    return db_session

def get_session_by_token(db: DbSession, token_hash: str) -> Optional[models.Session]:
    return db.query(models.Session).filter(
        models.Session.token_hash == token_hash,
        models.Session.expires_at > datetime.utcnow()
    ).first()

def delete_session(db: DbSession, token_hash: str) -> bool:
    db_session = db.query(models.Session).filter(models.Session.token_hash == token_hash).first()
    if db_session:
        db.delete(db_session)
        db.commit()
        return True
    return False

def delete_user_sessions(db: DbSession, user_id: int):
    db.query(models.Session).filter(models.Session.user_id == user_id).delete()
    db.commit()

# Logs management
def create_activity_log(db: DbSession, user_id: int, action: str, ip_address: Optional[str], user_agent: Optional[str]) -> models.ActivityLog:
    db_log = models.ActivityLog(
        user_id=user_id,
        action=action,
        ip_address=ip_address,
        user_agent=user_agent
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log

def get_activity_logs(db: DbSession, user_id: int, limit: int = 100) -> list[models.ActivityLog]:
    return db.query(models.ActivityLog).filter(
        models.ActivityLog.user_id == user_id
    ).order_by(models.ActivityLog.timestamp.desc()).limit(limit).all()

# Admin CRUD operations

def get_system_stats(db: DbSession, phishing_model_active: bool = True) -> dict:
    total_users = db.query(models.User).count()
    active_sessions = db.query(models.Session).filter(models.Session.expires_at > datetime.utcnow()).count()
    locked_accounts = db.query(models.User).filter(models.User.locked_until > datetime.utcnow()).count()
    mfa_users = db.query(models.User).filter(models.User.mfa_enabled == True).count()
    total_logs = db.query(models.ActivityLog).count()
    
    return {
        "total_users": total_users,
        "active_sessions": active_sessions,
        "locked_accounts": locked_accounts,
        "mfa_users": mfa_users,
        "total_logs": total_logs,
        "phishing_model_status": "Active (SVM Classifier)" if phishing_model_active else "Offline"
    }

def get_all_users_for_admin(db: DbSession) -> list:
    users = db.query(models.User).order_by(models.User.created_at.desc()).all()
    result = []
    now = datetime.utcnow()
    
    for u in users:
        active_sessions_count = db.query(models.Session).filter(
            models.Session.user_id == u.id,
            models.Session.expires_at > now
        ).count()
        
        result.append({
            "id": u.id,
            "email": u.email,
            "is_admin": bool(u.is_admin),
            "mfa_enabled": bool(u.mfa_enabled),
            "created_at": u.created_at,
            "last_login": u.last_login,
            "failed_attempts": u.failed_attempts or 0,
            "locked_until": u.locked_until,
            "active_sessions_count": active_sessions_count
        })
    return result

def toggle_user_admin_role(db: DbSession, user_id: int, is_admin: bool) -> Optional[models.User]:
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user:
        db_user.is_admin = is_admin
        db.commit()
        db.refresh(db_user)
    return db_user

def set_user_lockout(db: DbSession, user_id: int, locked: bool) -> Optional[models.User]:
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user:
        if locked:
            db_user.locked_until = datetime.utcnow() + timedelta(days=365)
            db_user.failed_attempts = 10
        else:
            db_user.locked_until = None
            db_user.failed_attempts = 0
        db.commit()
        db.refresh(db_user)
    return db_user

def get_all_activity_logs_admin(db: DbSession, limit: int = 150) -> list:
    logs = db.query(models.ActivityLog, models.User.email).join(
        models.User, models.ActivityLog.user_id == models.User.id
    ).order_by(models.ActivityLog.timestamp.desc()).limit(limit).all()
    
    result = []
    for log, email in logs:
        result.append({
            "id": log.id,
            "user_id": log.user_id,
            "email": email,
            "action": log.action,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "timestamp": log.timestamp
        })
    return result

