import os
import sys
import unittest
from fastapi.testclient import TestClient

# Use test database
os.environ["DATABASE_URL"] = "sqlite:///./test_admin_securepass.db"

from app.database import Base, engine, SessionLocal
from app.main import app
from app import models, auth

client = TestClient(app)

class TestSecurePassAdmin(unittest.TestCase):
    def setUp(self):
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        self.db = SessionLocal()

        self.admin_email = "admin@securepass.com"
        self.user_email = "user@securepass.com"
        self.salt = "a" * 128
        self.raw_verifier = "1234567890abcdef1234567890abcdef1234567890abcdef"
        self.kdf_params = {"time_cost": 2, "memory_cost": 32768, "parallelism": 1}
        self.encrypted_vault = "iv.ciphertext"
        self.recovery_key = "c" * 64
        self.recovery_hash = "d" * 64

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=engine)
        if os.path.exists("./test_admin_securepass.db"):
            try:
                os.remove("./test_admin_securepass.db")
            except Exception:
                pass

    def _register_user(self, email):
        payload = {
            "email": email,
            "salt": self.salt,
            "verifier": self.raw_verifier,
            "kdf_type": "argon2id",
            "kdf_params": self.kdf_params,
            "encrypted_vault": self.encrypted_vault,
            "encrypted_key_recovery": self.recovery_key,
            "recovery_codes_hash": self.recovery_hash
        }
        res = client.post("/api/auth/register", json=payload)
        self.assertEqual(res.status_code, 201)

    def _login_user(self, email):
        user = self.db.query(models.User).filter(models.User.email == email).first()
        access_token = auth.create_access_token(data={"sub": user.email})
        token_hash = auth.hash_sha256(access_token)
        from datetime import datetime, timedelta
        expires_at = datetime.utcnow() + timedelta(hours=1)
        
        session = models.Session(user_id=user.id, token_hash=token_hash, expires_at=expires_at)
        self.db.add(session)
        self.db.commit()
        return access_token

    def test_admin_rbac_and_management(self):
        print("\n[Admin Test] 1. Registering first user (Admin) and second user (Standard)...")
        # First registered user becomes Admin
        self._register_user(self.admin_email)
        admin_obj = self.db.query(models.User).filter(models.User.email == self.admin_email).first()
        self.assertTrue(admin_obj.is_admin, "First registered user should automatically be an admin")

        # Second registered user is standard user
        self._register_user(self.user_email)
        user_obj = self.db.query(models.User).filter(models.User.email == self.user_email).first()
        self.assertFalse(user_obj.is_admin, "Second registered user should be a standard user")

        admin_token = self._login_user(self.admin_email)
        user_token = self._login_user(self.user_email)

        print("[Admin Test] 2. Verifying RBAC blocking for standard user...")
        res = client.get("/api/admin/stats", headers={"Authorization": f"Bearer {user_token}"})
        self.assertEqual(res.status_code, 403, "Standard user should receive 403 Forbidden")

        res_logs = client.get("/api/admin/logs", headers={"Authorization": f"Bearer {user_token}"})
        self.assertEqual(res_logs.status_code, 403, "Standard user should receive 403 Forbidden for logs")

        print("[Admin Test] 3. Verifying Admin access to stats, user list, and logs...")
        stats_res = client.get("/api/admin/stats", headers={"Authorization": f"Bearer {admin_token}"})
        self.assertEqual(stats_res.status_code, 200)
        self.assertEqual(stats_res.json()["total_users"], 2)

        users_res = client.get("/api/admin/users", headers={"Authorization": f"Bearer {admin_token}"})
        self.assertEqual(users_res.status_code, 200)
        self.assertEqual(len(users_res.json()["users"]), 2)

        logs_res = client.get("/api/admin/logs", headers={"Authorization": f"Bearer {admin_token}"})
        self.assertEqual(logs_res.status_code, 200)

        print("[Admin Test] 4. Testing admin role toggling (Promote/Demote)...")
        # Promote standard user to admin
        toggle_res = client.put(
            f"/api/admin/users/{user_obj.id}/role",
            json={"is_admin": True},
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        self.assertEqual(toggle_res.status_code, 200)
        
        self.db.refresh(user_obj)
        self.assertTrue(user_obj.is_admin)

        # Admin cannot remove their own admin privileges
        self_demote = client.put(
            f"/api/admin/users/{admin_obj.id}/role",
            json={"is_admin": False},
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        self.assertEqual(self_demote.status_code, 400)

        print("[Admin Test] 5. Testing account lockout and session revocation...")
        lock_res = client.put(
            f"/api/admin/users/{user_obj.id}/lockout",
            json={"locked": True},
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        self.assertEqual(lock_res.status_code, 200)
        
        self.db.refresh(user_obj)
        self.assertIsNotNone(user_obj.locked_until)

        # Unlock user
        unlock_res = client.put(
            f"/api/admin/users/{user_obj.id}/lockout",
            json={"locked": False},
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        self.assertEqual(unlock_res.status_code, 200)

        print("[Admin Test] 6. Testing admin account deletion...")
        del_res = client.delete(
            f"/api/admin/users/{user_obj.id}",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        self.assertEqual(del_res.status_code, 200)

        users_after_del = client.get("/api/admin/users", headers={"Authorization": f"Bearer {admin_token}"})
        self.assertEqual(len(users_after_del.json()["users"]), 1)

        print("✓ All Admin RBAC and Management assertions PASSED successfully!")

if __name__ == "__main__":
    unittest.main()
