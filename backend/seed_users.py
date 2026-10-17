# ============================================================
# MODULE 6 — SEED DEMO USERS (with hashed passwords)
# ============================================================
# Creates a small set of demo users in the `users` collection.
#
#   python seed_users.py
#   # or
#   python main.py --seed-users
#
# Passwords are stored as werkzeug hashes, NEVER as plain text.
# All demo users share the same demo password for convenience:
#
#     trinetra123
#
# Safe to re-run: it overwrites the same four documents.
# ============================================================

import datetime

from werkzeug.security import generate_password_hash

from firebase_rest import set_document


# ------------------------------------------------------------
# Shared demo password
# ------------------------------------------------------------
DEMO_PASSWORD = "trinetra123"


# ------------------------------------------------------------
# Demo users
# ------------------------------------------------------------
DEMO_USERS = [
    {
        "id": "u_student",
        "name": "Chikitha",
        "email": "chikitha@example.com",
        "community": "STUDENT",
    },
    {
        "id": "u_senior",
        "name": "Raman Iyer",
        "email": "raman@example.com",
        "community": "SENIOR_CITIZEN",
    },
    {
        "id": "u_business",
        "name": "Meera Stores",
        "email": "meera@example.com",
        "community": "SME",
    },
    {
        "id": "u_public",
        "name": "Guest User",
        "email": "guest@example.com",
        "community": "GENERAL_PUBLIC",
    },
]


# ------------------------------------------------------------
# Password helper
# ------------------------------------------------------------
def hash_password(plain: str) -> str:
    """Hash a plain-text password using werkzeug's default method."""
    return generate_password_hash(plain)


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
def main():
    print("=" * 60)
    print("SEEDING DEMO USERS INTO FIRESTORE")
    print("=" * 60)
    print()

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for user in DEMO_USERS:
        doc = {
            "name":          user["name"],
            "email":         user["email"],
            "password_hash": hash_password(DEMO_PASSWORD),
            "community":     user["community"],
            "created_at":    now,
        }
        set_document("users", user["id"], doc)
        print(f"  ✓ users/{user['id']:12s} → {user['name']} ({user['community']})")

    print()
    print(f"Done. {len(DEMO_USERS)} users seeded.")
    print()
    print("=" * 60)
    print(f"DEMO PASSWORD FOR ALL USERS: {DEMO_PASSWORD}")
    print("=" * 60)
    print()
    print("Login credentials:")
    for user in DEMO_USERS:
        print(f"  {user['email']:24s}  {DEMO_PASSWORD}")
    print()


if __name__ == "__main__":
    main()