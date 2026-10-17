# ============================================================
# ONE-TIME SETUP — create demo users in Firestore
# ============================================================
# Run:
#   python create_users.py
#
# Creates one user per community, all with the password
# "password123". Change the hashes before deploying.
# ============================================================

from werkzeug.security import generate_password_hash
from firebase_rest import set_document


PASSWORD = "password123"


USERS = {
    "u_chikitha": {
        "name":      "Chikitha",
        "email":     "chikitha@example.com",
        "community": "Students",
    },
    "u_senior": {
        "name":      "Ramesh",
        "email":     "ramesh@example.com",
        "community": "Senior Citizens",
    },
    "u_business": {
        "name":      "Priya",
        "email":     "priya@example.com",
        "community": "Small Businesses",
    },
    "u_public": {
        "name":      "Anon",
        "email":     "anon@example.com",
        "community": "General Public",
    },
}


def main():
    pw_hash = generate_password_hash(PASSWORD)

    for uid, data in USERS.items():
        doc = dict(data)
        doc["password_hash"] = pw_hash
        set_document("users", uid, doc)
        print(f"✓ users/{uid}  ({data['community']})")

    print()
    print(f"All users created with password: {PASSWORD}")


if __name__ == "__main__":
    main()