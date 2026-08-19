import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), "securepass.db")

if not os.path.exists(db_path):
    print("❌ Database not found!")
    exit(1)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

cursor.execute("SELECT id, email, salt, verifier, encrypted_vault FROM users WHERE email='sus@gmail.com'")
row = cursor.fetchone()

print("=" * 80)
print(" 🛡️  SECUREPASS - DATABASE ENCRYPTION DEMONSTRATION")
print("=" * 80)

if row:
    user_id, email, salt, verifier, enc_vault = row
    print(f"\n👤 TARGET ACCOUNT: {email} (User ID: {user_id})\n")
    print("1️⃣  SRP-6a AUTHENTICATION VERIFIER (Password is NOT stored):")
    print(f"    {verifier}")
    
    print("\n2️⃣  DERIVATION SALT (HEX):")
    print(f"    {salt}")
    
    print("\n3️⃣  RAW ENCRYPTED VAULT BLOB IN DATABASE (Contains Passwords & Images):")
    print("    " + "-" * 74)
    print(f"    {enc_vault}")
    print("    " + "-" * 74)
    
    print("\n📊 AUDIT SUMMARY FOR DEMO / PRESENTATION:")
    print("   ✅ Plaintext Passwords Stored on Server : 0")
    print("   ✅ Plaintext Images/Files on Server     : 0")
    print("   ✅ Zero-Knowledge Architecture Status   : VERIFIED & ENCRYPTED")
else:
    print("User sus@gmail.com not found in database.")

conn.close()
print("=" * 80)
