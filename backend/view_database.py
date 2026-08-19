import sqlite3
import os
import json

db_path = os.path.join(os.path.dirname(__file__), "securepass.db")

if not os.path.exists(db_path):
    print(f"❌ Database file not found at: {db_path}")
    exit(1)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

print("=" * 70)
print(" 🗄️  SECUREPASS DATABASE CONTENT VIEWER")
print("=" * 70)

# 1. Fetch Users
cursor.execute("SELECT id, email, created_at, is_admin, SUBSTR(encrypted_vault, 1, 60) FROM users")
users = cursor.fetchall()

print(f"\n👥 USERS ({len(users)} records found):")
print("-" * 70)
for u in users:
    vault_preview = u[4] + "..." if u[4] else "Empty"
    print(f"ID: {u[0]} | Email: {u[1]} | Admin: {bool(u[3])} | Created: {u[2]}")
    print(f"   🔒 Encrypted Vault (Ciphertext Preview): {vault_preview}")
    print("-" * 70)

# 2. Fetch Activity Logs
cursor.execute("SELECT id, user_id, action, ip_address, timestamp FROM activity_logs ORDER BY timestamp DESC LIMIT 10")
logs = cursor.fetchall()

print(f"\n📜 RECENT ACTIVITY LOGS (Top 10):")
print("-" * 70)
for l in logs:
    print(f"ID: {l[0]} | User ID: {l[1]} | Action: {l[2]} | IP: {l[3]} | Time: {l[4]}")

conn.close()
print("\n" + "=" * 70)
