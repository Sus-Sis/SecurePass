import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), "securepass.db")
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

cursor.execute("SELECT id, email, created_at, is_admin, salt, verifier, encrypted_vault FROM users WHERE email='sus@gmail.com'")
user = cursor.fetchone()

print("=" * 80)
print(" 👤 ACCOUNT DATA FOR: sus@gmail.com")
print("=" * 80)

if user:
    u_id, email, created, is_admin, salt, verifier, enc_vault = user
    print(f"User ID        : {u_id}")
    print(f"Email          : {email}")
    print(f"Created Date   : {created}")
    print(f"Admin Status   : {'Yes (Admin)' if is_admin else 'No'}")
    print(f"\n🔐 Salt (Hex)   :\n{salt}")
    print(f"\n🔐 SRP Verifier:\n{verifier}")
    print(f"\n📦 ENCRYPTED VAULT (Contains Images, Passwords & Documents):\n")
    print(enc_vault)
else:
    print("❌ User 'sus@gmail.com' not found in database.")

print("\n" + "=" * 80)
conn.close()
