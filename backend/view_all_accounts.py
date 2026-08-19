import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), "securepass.db")
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

cursor.execute("SELECT id, email, created_at, is_admin, encrypted_vault FROM users ORDER BY id ASC")
users = cursor.fetchall()

output_lines = []
output_lines.append("=" * 80)
output_lines.append(" 🗄️  SECUREPASS DATABASE - ALL REGISTERED ACCOUNTS & VAULT CONTENT")
output_lines.append("=" * 80 + "\n")

for idx, u in enumerate(users, 1):
    u_id, email, created, is_admin, enc_vault = u
    vault_status = "Empty ([])" if (not enc_vault or enc_vault == "[]") else f"Encrypted Ciphertext ({len(enc_vault)} characters)"
    
    output_lines.append(f"[{idx}] EMAIL         : {email}")
    output_lines.append(f"    User ID       : {u_id}")
    output_lines.append(f"    Role          : {'Admin' if is_admin else 'Standard User'}")
    output_lines.append(f"    Created Date  : {created}")
    output_lines.append(f"    Vault Content : {vault_status}")
    if enc_vault and enc_vault != "[]":
        # Print first 100 chars preview
        preview = enc_vault[:100] + "..." if len(enc_vault) > 100 else enc_vault
        output_lines.append(f"    Vault Preview : {preview}")
    output_lines.append("-" * 80)

summary_text = "\n".join(output_lines)
print(summary_text)

# Also save full detailed export to txt file for convenience
export_file = os.path.join(os.path.dirname(__file__), "all_users_vault_export.txt")
with open(export_file, "w", encoding="utf-8") as f:
    f.write("SECUREPASS FULL DATABASE DUMP (ALL EMAILS AND RAW VAULTS)\n")
    f.write("=" * 80 + "\n\n")
    for u in users:
        u_id, email, created, is_admin, enc_vault = u
        f.write(f"USER ID : {u_id}\n")
        f.write(f"EMAIL   : {email}\n")
        f.write(f"ROLE    : {'Admin' if is_admin else 'User'}\n")
        f.write(f"CREATED : {created}\n")
        f.write(f"RAW VAULT ENCRYPTED CIPHERTEXT:\n{enc_vault}\n")
        f.write("=" * 80 + "\n\n")

print(f"\n📄 Full untruncated export saved to file: backend/all_users_vault_export.txt")
conn.close()
