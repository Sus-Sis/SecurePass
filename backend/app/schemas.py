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
    mfa_code: Optional[str] = None

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
    mfa_code: Optional[str] = None

class SRPAuthenticateResponse(BaseModel):
    access_token: Optional[str] = None
    server_M2: Optional[str] = None
    encrypted_vault: Optional[str] = None
    salt: Optional[str] = None
    kdf_type: Optional[str] = "argon2id"
    kdf_params: Optional[Dict[str, Any]] = None
    mfa_required: bool = False
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
    mfa_required: bool = False
    message: Optional[str] = None

class LogoutRequest(BaseModel):
    access_token: str

class LogoutResponse(BaseModel):
    message: str

class MFAEnableResponse(BaseModel):
    qr_code_url: str
    secret: str

class MFAVerifyRequest(BaseModel):
    totp_code: str

class MFAVerifyResponse(BaseModel):
    verified: bool
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
    mfa_enabled: bool

class MessageResponse(BaseModel):
    message: str
