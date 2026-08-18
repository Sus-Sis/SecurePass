from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

class KdfParamsSchema(BaseModel):
    time_cost: int = 2
    memory_cost: int = 32768
    parallelism: int = 1

class UserRegister(BaseModel):
    email: EmailStr
    salt: str
    verifier: str  # SRP-6a verifier (v = g^x mod N)
    kdf_type: Optional[str] = "argon2id"
    kdf_params: Optional[Dict[str, Any]] = None
    encrypted_vault: str
    encrypted_key_recovery: str
    recovery_codes_hash: str

class UserRegisterResponse(BaseModel):
    user_id: int
    message: str

class UserLogin(BaseModel):
    email: EmailStr
    verifier: str

class PreloginRequest(BaseModel):
    email: EmailStr

class PreloginResponse(BaseModel):
    salt: str
    kdf_type: str = "argon2id"
    kdf_params: Optional[Dict[str, Any]] = None

class SRPChallengeRequest(BaseModel):
    email: EmailStr
    client_A: str

class SRPChallengeResponse(BaseModel):
    salt: str
    server_B: str
    kdf_type: str = "argon2id"
    kdf_params: Optional[Dict[str, Any]] = None

class SRPAuthenticateRequest(BaseModel):
    email: EmailStr
    client_A: str
    client_M1: str

class SRPAuthenticateResponse(BaseModel):
    access_token: Optional[str] = None
    server_M2: Optional[str] = None
    encrypted_vault: Optional[str] = None
    salt: Optional[str] = None
    kdf_type: Optional[str] = "argon2id"
    kdf_params: Optional[Dict[str, Any]] = None
    message: Optional[str] = None

class URLScanRequest(BaseModel):
    url: str

class URLScanResponse(BaseModel):
    url: str
    is_safe: bool
    prediction: str
    risk_level: str

class LoginResponse(BaseModel):
    access_token: Optional[str] = None
    encrypted_vault: Optional[str] = None
    salt: Optional[str] = None
    kdf_type: Optional[str] = "argon2id"
    kdf_params: Optional[Dict[str, Any]] = None
    message: Optional[str] = None

class LogoutRequest(BaseModel):
    access_token: str

class LogoutResponse(BaseModel):
    message: str

class VaultResponse(BaseModel):
    encrypted_vault: str
    last_modified: datetime

class VaultUpdate(BaseModel):
    encrypted_vault: str

class VaultUpdateResponse(BaseModel):
    message: str
    version: int

class LogEntry(BaseModel):
    action: str
    timestamp: datetime
    ip_address: Optional[str]

    class Config:
        from_attributes = True

class LogListResponse(BaseModel):
    logs: List[LogEntry]

class LogCreateRequest(BaseModel):
    action: str

class RecoveryInitiateRequest(BaseModel):
    email: EmailStr

class RecoveryInitiateResponse(BaseModel):
    message: str
    salt: Optional[str] = None
    kdf_type: Optional[str] = "argon2id"
    kdf_params: Optional[Dict[str, Any]] = None
    encrypted_key_recovery: Optional[str] = None
    encrypted_vault: Optional[str] = None

class RecoveryVerifyRequest(BaseModel):
    email: EmailStr
    recovery_code: str
    new_verifier: str
    new_salt: str
    new_kdf_params: Optional[Dict[str, Any]] = None
    new_encrypted_vault: str
    new_encrypted_key_recovery: str

class ChangePasswordRequest(BaseModel):
    current_verifier: str
    new_salt: str
    new_verifier: str
    new_kdf_params: Optional[Dict[str, Any]] = None
    new_encrypted_vault: str
    new_encrypted_key_recovery: str
    new_recovery_codes_hash: str

class UserMeResponse(BaseModel):
    email: EmailStr
    is_admin: bool = False

class MessageResponse(BaseModel):
    message: str

class AdminStatsResponse(BaseModel):
    total_users: int
    active_sessions: int
    locked_accounts: int
    total_logs: int
    phishing_model_status: str

class AdminUserItem(BaseModel):
    id: int
    email: str
    is_admin: bool
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    failed_attempts: int = 0
    locked_until: Optional[datetime] = None
    active_sessions_count: int = 0

class AdminUserListResponse(BaseModel):
    users: List[AdminUserItem]

class AdminRoleToggleRequest(BaseModel):
    is_admin: bool

class AdminLockoutRequest(BaseModel):
    locked: bool

class AdminLogItem(BaseModel):
    id: int
    user_id: int
    email: str
    action: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: datetime

class AdminLogListResponse(BaseModel):
    logs: List[AdminLogItem]
