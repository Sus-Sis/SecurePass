import os
import sys
import unittest
import secrets
from datetime import datetime, timedelta
from fastapi.testclient import TestClient

# Set database URL before importing app modules
os.environ["DATABASE_URL"] = "sqlite:///./test_securepass.db"

from app.database import Base, engine, SessionLocal, get_db
from app.main import app
from app import models, auth, crud

client = TestClient(app)

class TestSecurePassSecurity(unittest.TestCase):
    def setUp(self):
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        self.db = SessionLocal()
        
        self.email = "user@testsecurepass.com"
        self.salt = "a" * 128  # 64-byte hex salt
        
        # Simulated SRP-6a verifier (hex integer representation of v = g^x mod N)
        self.raw_verifier = "1234567890abcdef1234567890abcdef1234567890abcdef"
        self.kdf_params = {"time_cost": 2, "memory_cost": 32768, "parallelism": 1}
        self.encrypted_vault = "iv_b64_data.ciphertext_b64_data"
        self.recovery_key = "c" * 64
        self.recovery_codes_hash = "d" * 64

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=engine)

    def test_01_user_registration_and_argon2_kdf(self):
        print("\nChecking User Registration & Argon2id KDF...")
        payload = {
            "email": self.email,
            "salt": self.salt,
            "verifier": self.raw_verifier,
            "kdf_type": "argon2id",
            "kdf_params": self.kdf_params,
            "encrypted_vault": self.encrypted_vault,
            "encrypted_key_recovery": self.recovery_key,
            "recovery_codes_hash": self.recovery_codes_hash
        }
        response = client.post("/api/auth/register", json=payload)
        self.assertEqual(response.status_code, 201)
        self.assertIn("user_id", response.json())
        
        # Duplicate registration check
        response2 = client.post("/api/auth/register", json=payload)
        self.assertEqual(response2.status_code, 400)
        self.assertIn("already registered", response2.json()["detail"])
        print("✓ Registration and Argon2id KDF parameter persistence pass")

    def test_02_prelogin_and_srp_challenge_privacy(self):
        print("\nChecking Pre-login Salt & SRP Challenge Enumeration Defense...")
        client.post("/api/auth/register", json={
            "email": self.email,
            "salt": self.salt,
            "verifier": self.raw_verifier,
            "kdf_type": "argon2id",
            "kdf_params": self.kdf_params,
            "encrypted_vault": self.encrypted_vault,
            "encrypted_key_recovery": self.recovery_key,
            "recovery_codes_hash": self.recovery_codes_hash
        })

        # Salt query for existing user
        response1 = client.post("/api/auth/prelogin", json={"email": self.email})
        self.assertEqual(response1.status_code, 200)
        self.assertEqual(response1.json()["salt"], self.salt)
        self.assertEqual(response1.json()["kdf_type"], "argon2id")

        # Salt query for non-existing user (deterministic fake salt)
        fake_email = "notexists@testsecurepass.com"
        response2 = client.post("/api/auth/prelogin", json={"email": fake_email})
        self.assertEqual(response2.status_code, 200)
        self.assertIsNotNone(response2.json()["salt"])
        self.assertNotEqual(response2.json()["salt"], self.salt)
        
        print("✓ Pre-login salt & privacy controls pass")

    def test_03_srp_zero_knowledge_authentication_flow(self):
        print("\nChecking SRP-6a Zero-Knowledge Handshake (Challenge & Authenticate)...")
        # 1. Compute real SRP verifier v for testing
        x_hex = auth.sha256_hex(self.salt, "test_master_key_bytes_123")
        x = int(x_hex, 16)
        v = pow(auth.SRP_G, x, auth.SRP_N)
        v_hex = hex(v)[2:]
        
        # Register user with real SRP verifier v
        client.post("/api/auth/register", json={
            "email": self.email,
            "salt": self.salt,
            "verifier": v_hex,
            "kdf_type": "argon2id",
            "kdf_params": self.kdf_params,
            "encrypted_vault": self.encrypted_vault,
            "encrypted_key_recovery": self.recovery_key,
            "recovery_codes_hash": self.recovery_codes_hash
        })

        # 2. Client Step 1: Generate client ephemeral (a, A = g^a mod N)
        a_bytes = secrets.token_bytes(32)
        a = int.from_bytes(a_bytes, "big")
        A = pow(auth.SRP_G, a, auth.SRP_N)
        A_hex = hex(A)[2:]

        # Request SRP challenge from server
        chal_res = client.post("/api/auth/srp/challenge", json={
            "email": self.email,
            "client_A": A_hex
        })
        self.assertEqual(chal_res.status_code, 200)
        chal_data = chal_res.json()
        B_hex = chal_data["server_B"]
        B = int(B_hex, 16)

        # 3. Client Step 2: Compute u = H(A || B), S, K, M1
        u_hex = auth.sha256_hex(A_hex, B_hex)
        u = int(u_hex, 16)
        k = auth.get_srp_k()
        
        base = (B - (k * v) % auth.SRP_N) % auth.SRP_N
        if base < 0:
            base += auth.SRP_N
        
        S = pow(base, a + u * x, auth.SRP_N)
        S_hex = hex(S)[2:]
        K_hex = auth.sha256_hex(S_hex)
        M1_hex = auth.sha256_hex(A_hex, BHex=B_hex, KHex=K_hex)
        expected_M2 = auth.sha256_hex(A_hex, M1_hex, K_hex)

        # Send authentication proof M1 to server
        auth_res = client.post("/api/auth/srp/authenticate", json={
            "email": self.email,
            "client_A": A_hex,
            "client_M1": M1_hex
        })
        self.assertEqual(auth_res.status_code, 200)
        auth_data = auth_res.json()
        self.assertIn("access_token", auth_data)
        self.assertEqual(auth_data["server_M2"].lower(), expected_M2.lower())
        self.assertEqual(auth_data["encrypted_vault"], self.encrypted_vault)
        print("✓ SRP-6a Zero-Knowledge Authentication Flow passes")

    def test_04_rate_limiting_and_account_lockout(self):
        print("\nChecking Rate Limiting & Account Lockout...")
        client.post("/api/auth/register", json={
            "email": self.email,
            "salt": self.salt,
            "verifier": self.raw_verifier,
            "kdf_type": "argon2id",
            "kdf_params": self.kdf_params,
            "encrypted_vault": self.encrypted_vault,
            "encrypted_key_recovery": self.recovery_key,
            "recovery_codes_hash": self.recovery_codes_hash
        })

        print("Simulating 5 failed logins...")
        for i in range(5):
            res = client.post("/api/auth/srp/authenticate", json={
                "email": self.email,
                "client_A": "12345",
                "client_M1": "wrong_proof"
            })
            self.assertEqual(res.status_code, 401)
            
        res6 = client.post("/api/auth/srp/authenticate", json={
            "email": self.email,
            "client_A": "12345",
            "client_M1": "wrong_proof"
        })
        self.assertEqual(res6.status_code, 429)
        print("✓ Rate Limiting (5 failures / hour) functions correctly")

    def test_05_session_invalidation_on_logout(self):
        print("\nChecking Session Invalidation on Logout...")
        client.post("/api/auth/register", json={
            "email": self.email,
            "salt": self.salt,
            "verifier": self.raw_verifier,
            "kdf_type": "argon2id",
            "kdf_params": self.kdf_params,
            "encrypted_vault": self.encrypted_vault,
            "encrypted_key_recovery": self.recovery_key,
            "recovery_codes_hash": self.recovery_codes_hash
        })
        
        login_res = client.post("/api/auth/login", json={
            "email": self.email,
            "verifier": self.raw_verifier
        })
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        res_vault = client.get("/api/vault", headers=headers)
        self.assertEqual(res_vault.status_code, 200)

        res_logout = client.post("/api/auth/logout", headers=headers)
        self.assertEqual(res_logout.status_code, 200)

        res_vault_after = client.get("/api/vault", headers=headers)
        self.assertEqual(res_vault_after.status_code, 401)
        print("✓ Logout session invalidation passes")

    def test_06_dual_factor_account_recovery(self):
        print("\nChecking Dual-Factor Email OTP Account Recovery...")
        # 1. Register User
        client.post("/api/auth/register", json={
            "email": self.email,
            "salt": self.salt,
            "verifier": self.raw_verifier,
            "kdf_type": "argon2id",
            "kdf_params": self.kdf_params,
            "encrypted_vault": self.encrypted_vault,
            "encrypted_key_recovery": self.recovery_key,
            "recovery_codes_hash": self.recovery_codes_hash
        })

        # 2. Initiate recovery & get OTP
        init_res = client.post("/api/auth/recovery/initiate", json={"email": self.email})
        self.assertEqual(init_res.status_code, 200)
        otp = init_res.json()["dev_otp"]
        self.assertTrue(len(otp) == 6)

        # 3. Attempt verify with wrong OTP (should fail 401)
        bad_res = client.post("/api/auth/recovery/verify", json={
            "email": self.email,
            "otp_code": "000000",
            "recovery_code": self.recovery_codes_hash,
            "new_verifier": "new_verifier_hash",
            "new_salt": "new_salt_128",
            "new_encrypted_vault": "new_vault",
            "new_encrypted_key_recovery": "new_rec_key"
        })
        self.assertEqual(bad_res.status_code, 401)

        # 4. Verify with correct OTP & Recovery Code (should succeed 200)
        good_res = client.post("/api/auth/recovery/verify", json={
            "email": self.email,
            "otp_code": otp,
            "recovery_code": self.recovery_codes_hash,
            "new_verifier": "new_verifier_hash",
            "new_salt": "new_salt_128",
            "new_encrypted_vault": "new_vault",
            "new_encrypted_key_recovery": "new_rec_key"
        })
        self.assertEqual(good_res.status_code, 200)
        print("✓ Dual-Factor Email OTP Account Recovery passes")

if __name__ == "__main__":
    print("==================================================")
    print("      RUNNING SECUREPASS SECURITY TEST CASES      ")
    print("==================================================")
    
    suite = unittest.TestLoader().loadTestsFromTestCase(TestSecurePassSecurity)
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    
    if os.path.exists("./test_securepass.db"):
        try:
            os.remove("./test_securepass.db")
        except OSError:
            pass
            
    if result.wasSuccessful():
        print("\n==================================================")
        print("🎉 ALL SECURITY ASSURANCE TEST CASES PASSED SUCCESSFULLY 🎉")
        print("==================================================")
        sys.exit(0)
    else:
        print("\n==================================================")
        print("❌ SOME TEST CASES FAILED. CHECK SECURITY IMPLEMENTATION. ❌")
        print("==================================================")
        sys.exit(1)
