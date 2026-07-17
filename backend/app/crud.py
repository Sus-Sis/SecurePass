from sqlalchemy.orm import Session as DbSession
from datetime import datetime, timedelta
from typing import Optional
from . import models, schemas

def get_user_by_email(db: DbSession, email: str) -> Optional[models.User]:
    return db.query(models.User).filter(models.User.email == email.lower()).first()

def create_user(db: DbSession, user: schemas.UserRegister, hashed_verifier: str, hashed_recovery_code: str) -> models.User:
    db_user = models.User(
        email=user.email.lower(),
        salt=user.salt,
        verifier=hashed_verifier,
        encrypted_vault=user.encrypted_vault,
        encrypted_key_recovery=user.encrypted_key_recovery,
        recovery_codes_hash=hashed_recovery_code,
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

def update_user_security(db: DbSession, user_id: int, new_salt: str, new_verifier: str, new_encrypted_vault: str, new_encrypted_key_recovery: str, new_recovery_hash: str) -> models.User:
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user:
        db_user.salt = new_salt
        db_user.verifier = new_verifier
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
        # Lock account for 15 minutes
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
