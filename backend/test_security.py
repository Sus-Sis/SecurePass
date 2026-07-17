import os
import sys
import unittest
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
        # Create schema on the shared engine (cleans tables before each test)
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        self.db = SessionLocal()
        
        # Test inputs
        self.email = "user@testsecurepass.com"
        self.salt = "a" * 128  # 64-byte hex salt
        self.verifier = "b" * 64  # 32-byte hex verifier hash of MK
        self.encrypted_vault = "iv_b64_data.ciphertext_b64_data"
        self.recovery_key = "c" * 64
        self.recovery_codes_hash = "d" * 64

    def tearDown(self):
        self.db.close()
        # Clean up database tables but keep the file descriptor valid
        Base.metadata.drop_all(bind=engine)

    def test_01_user_registration_and_duplication(self):
        print("\nChecking User Registration...")
        # 1. Successful registration
        payload = {
            "email": self.email,
            "salt": self.salt,
            "verifier": self.verifier,
            "encrypted_vault": self.encrypted_vault,
            "encrypted_key_recovery": self.recovery_key,
            "recovery_codes_hash": self.recovery_codes_hash
        }
        response = client.post("/api/auth/register", json=payload)
        self.assertEqual(response.status_code, 201)
        self.assertIn("user_id", response.json())
        
        # 2. Duplicate registration check
        response2 = client.post("/api/auth/register", json=payload)
        self.assertEqual(response2.status_code, 400)
        self.assertIn("already registered", response2.json()["detail"])
        print("✓ Registration and duplicate detection pass")

    def test_02_prelogin_privacy_protection(self):
        print("\nChecking Pre-login Salt Leak/Enumeration Protection...")
        # Register user first
        payload = {
            "email": self.email,
            "salt": self.salt,
            "verifier": self.verifier,
            "encrypted_vault": self.encrypted_vault,
            "encrypted_key_recovery": self.recovery_key,
            "recovery_codes_hash": self.recovery_codes_hash
        }
        client.post("/api/auth/register", json=payload)

        # 1. Salt query for existing user
        response1 = client.post("/api/auth/prelogin", json={"email": self.email})
        self.assertEqual(response1.status_code, 200)
        self.assertEqual(response1.json()["salt"], self.salt)

        # 2. Salt query for non-existing user (should return deterministic fake salt)
        fake_email = "notexists@testsecurepass.com"
        response2 = client.post("/api/auth/prelogin", json={"email": fake_email})
        self.assertEqual(response2.status_code, 200)
        self.assertIsNotNone(response2.json()["salt"])
        self.assertNotEqual(response2.json()["salt"], self.salt)
        
        # Querying again should return the SAME fake salt (deterministic)
        response3 = client.post("/api/auth/prelogin", json={"email": fake_email})
        self.assertEqual(response2.json()["salt"], response3.json()["salt"])
        print("✓ Pre-login salt privacy controls pass")

    def test_03_login_flow_and_session_generation(self):
        print("\nChecking Login Flow & JWT Session Generation...")
        # Register
        client.post("/api/auth/register", json={
            "email": self.email,
            "salt": self.salt,
            "verifier": self.verifier,
            "encrypted_vault": self.encrypted_vault,
            "encrypted_key_recovery": self.recovery_key,
            "recovery_codes_hash": self.recovery_codes_hash
        })

        # Correct verifier should yield 200 and access token
        response = client.post("/api/auth/login", json={
            "email": self.email,
            "verifier": self.verifier
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["encrypted_vault"], self.encrypted_vault)
        self.assertEqual(data["salt"], self.salt)
        print("✓ Login flow and session token generation pass")

    def test_04_rate_limiting_and_account_lockout(self):
        print("\nChecking Rate Limiting & Account Lockout...")
        # Register user
        client.post("/api/auth/register", json={
            "email": self.email,
            "salt": self.salt,
            "verifier": self.verifier,
            "encrypted_vault": self.encrypted_vault,
            "encrypted_key_recovery": self.recovery_key,
            "recovery_codes_hash": self.recovery_codes_hash
        })

        # 1. Attempt failed login 5 times. All should return 401 Unauthorized
        print("Simulating 5 failed logins to trigger Rate Limiter (5 per hour)...")
        for i in range(5):
            res = client.post("/api/auth/login", json={
                "email": self.email,
                "verifier": "wrong_verifier"
            })
            self.assertEqual(res.status_code, 401)
            
        # 6th attempt should trigger rate limiting block (429 Too Many Requests)
        res6 = client.post("/api/auth/login", json={
            "email": self.email,
            "verifier": "wrong_verifier"
        })
        self.assertEqual(res6.status_code, 429)
        self.assertIn("Too many failed login attempts", res6.json()["detail"])
        print("✓ Rate Limiting (5 failures / hour) functions correctly")

        # 2. To test Lockout (10 failed attempts) without being blocked by rate limiting,
        # we will temporarily bypass the rate limiter check by clearing the hourly login_failed activity logs,
        # but the user's `failed_attempts` column is preserved.
        print("Bypassing rate limiter to test Account Lockout (10 failures)...")
        self.db.query(models.ActivityLog).filter(models.ActivityLog.action == "login_failed").delete()
        self.db.commit()

        # Fail login 4 more times (making it 9 failures total)
        for i in range(4):
            res = client.post("/api/auth/login", json={
                "email": self.email,
                "verifier": "wrong_verifier"
            })
            self.assertEqual(res.status_code, 401)

        # Clear rate limiting logs again before the 10th attempt
        self.db.query(models.ActivityLog).filter(models.ActivityLog.action == "login_failed").delete()
        self.db.commit()

        # The 10th failed login attempt should lock the account immediately (returns 423 Locked)
        res10 = client.post("/api/auth/login", json={
            "email": self.email,
            "verifier": "wrong_verifier"
        })
        self.assertEqual(res10.status_code, 423)
        self.assertIn("locked", res10.json()["detail"].lower())

        # An attempt with correct credentials while locked should STILL return 423 Locked
        res_correct_locked = client.post("/api/auth/login", json={
            "email": self.email,
            "verifier": self.verifier
        })
        self.assertEqual(res_correct_locked.status_code, 423)
        print("✓ Account Lockout (10 failures lock account) functions correctly")

    def test_05_session_invalidation_on_logout(self):
        print("\nChecking Session Invalidation on Logout...")
        # Register & Login
        client.post("/api/auth/register", json={
            "email": self.email,
            "salt": self.salt,
            "verifier": self.verifier,
            "encrypted_vault": self.encrypted_vault,
            "encrypted_key_recovery": self.recovery_key,
            "recovery_codes_hash": self.recovery_codes_hash
        })
        login_res = client.post("/api/auth/login", json={
            "email": self.email,
            "verifier": self.verifier
        })
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Query vault using token (Assert 200)
        res_vault = client.get("/api/vault", headers=headers)
        self.assertEqual(res_vault.status_code, 200)

        # Logout
        res_logout = client.post("/api/auth/logout", headers=headers)
        self.assertEqual(res_logout.status_code, 200)

        # Query vault again using the logged out token (Assert 401 Unauthorized)
        res_vault_after = client.get("/api/vault", headers=headers)
        self.assertEqual(res_vault_after.status_code, 401)
        print("✓ Logout session invalidation passes")

if __name__ == "__main__":
    print("==================================================")
    print("      RUNNING SECUREPASS SECURITY TEST CASES      ")
    print("==================================================")
    
    # Run tests using unittest runner
    suite = unittest.TestLoader().loadTestsFromTestCase(TestSecurePassSecurity)
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    
    # Clean up test database file at the very end of all tests
    if os.path.exists("./test_securepass.db"):
        try:
            os.remove("./test_securepass.db")
        except OSError:
            pass
            
    # Exit with code matching test results
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
