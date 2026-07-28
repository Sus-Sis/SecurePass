from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    salt = Column(Text, nullable=False)
    verifier = Column(Text, nullable=False)  # Stores SRP-6a verifier (v = g^x mod N) in hex
    kdf_type = Column(String(50), default="argon2id")
    kdf_params = Column(Text, nullable=True)  # JSON string of KDF parameters (time_cost, memory_cost, parallelism)
    encrypted_vault = Column(Text, default="[]")
    encrypted_key_recovery = Column(Text, nullable=True)
    mfa_secret = Column(Text, nullable=True)
    mfa_enabled = Column(Boolean, default=False)
    recovery_codes_hash = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    last_login = Column(DateTime, nullable=True)
    failed_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)

    logs = relationship("ActivityLog", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")

class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    action = Column(String(255), nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    timestamp = Column(DateTime, server_default=func.now())

    user = relationship("User", back_populates="logs")

class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(Text, nullable=False)
    expires_at = Column(DateTime, nullable=False)

    user = relationship("User", back_populates="sessions")
