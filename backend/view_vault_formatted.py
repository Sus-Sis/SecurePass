import sqlite3
import os
import json
import base64

db_path = os.path.join(os.path.dirname(__file__), "securepass.db")

if not os.path.exists(db_path):
    print("❌ Database not found!")
    exit(1)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

cursor.execute("SELECT id, email, salt, kdf_params, encrypted_vault FROM users")
users = cursor.fetchall()

print("=" * 80)
print(" 🔐 SECUREPASS ZERO-KNOWLEDGE VAULT CATEGORIZED STRUCTURE")
print("=" * 80)
print("\nℹ️ NOTE: Because SecurePass uses Zero-Knowledge Architecture, all accounts,")
print("passwords, images, and documents are encrypted TOGETHER into a single ciphertext.")
print("The database server cannot separate them without your Master Password.\n")

for u in users:
    user_id, email, salt, kdf_params, enc_vault = u
    print("=" * 80)
    print(f"👤 USER ACCOUNT: {email} (ID: {user_id})")
    print("=" * 80)
    
    print("\n1️⃣  AUTH & SECURITY PARAMETERS:")
    print(f"    - Salt (Hex): {salt[:30]}...")
    print(f"    - KDF Parameters: {kdf_params}")
    
    print("\n2️⃣  ENCRYPTED VAULT BLOB (Raw Server Storage):")
    if enc_vault and enc_vault != "[]":
        parts = enc_vault.split(".")
        if len(parts) == 2:
            print(f"    - AES-GCM IV (Nonce): {parts[0]}")
            print(f"    - Encrypted Ciphertext: {parts[1][:80]}... (Length: {len(parts[1])} chars)")
        else:
            print(f"    - Raw Encrypted Blob: {enc_vault[:80]}...")
    else:
        print("    - Vault is empty.")

    print("\n3️⃣  DECRYPTED STRUCTURE (Visible inside Web App Dashboard at http://localhost:5173):")
    print("    ┌────────────────────────────────────────────────────────────────────────┐")
    print("    │ 🔑 ACCOUNTS & LOGINS  : Stored as encrypted JSON items with {username, │")
    print("    │                         password, url, title}                          │")
    print("    │ 📄 DOCUMENTS         : Stored with {doc_number, issuer, expiry_date}  │")
    print("    │ 🖼️ IMAGES & PHOTOS    : Stored as encrypted Base64 strings {file_data} │")
    print("    └────────────────────────────────────────────────────────────────────────┘")

conn.close()
print("\n" + "=" * 80)
