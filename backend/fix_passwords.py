# ============================================================
# One-shot fix: add/refresh password_hash on existing users
# ============================================================
#   python fix_passwords.py
#
# This updates every user document in the `users` collection
# by writing a fresh `password_hash` for the shared demo
# password. It does NOT touch name, email, or community.
# ============================================================

from werkzeug.security import generate_password_hash

from firebase_rest import list_documents, get_document, set_document


DEMO_PASSWORD = "trinetra123"


def main():
    raw = list_documents("users") or []
    ids = list(raw.keys()) if isinstance(raw, dict) else raw

    if not ids:
        print("No users found. Run:  python main.py --seed-users")
        return

    print("=" * 70)
    print("FIXING PASSWORDS")
    print("=" * 70)
    print()

    fresh_hash = generate_password_hash(DEMO_PASSWORD)

    for uid in ids:
        doc = get_document("users", uid)
        if not isinstance(doc, dict):
            print(f"  ✗ users/{uid}: not a dict, skipping")
            continue

        before = bool(doc.get("password_hash"))

        # Preserve everything, just replace the hash
        doc["password_hash"] = fresh_hash

        try:
            set_document("users", uid, doc)
            status = "updated" if before else "added"
            print(f"  ✓ users/{uid:14s}  hash {status}")
        except Exception as e:
            print(f"  ✗ users/{uid}: {e}")

    print()
    print("=" * 70)
    print(f"Demo password for all users: {DEMO_PASSWORD}")
    print("=" * 70)
    print()
    print("Now run:  python check_users.py")


if __name__ == "__main__":
    main()