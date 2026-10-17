import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
from pathlib import Path


# ============================================================
# FIREBASE CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

SERVICE_ACCOUNT_PATH = (
    BASE_DIR.parent
    / "threat-collector"
    / "serviceAccountKey.json"
)


# ============================================================
# CHECK SERVICE ACCOUNT
# ============================================================

if not SERVICE_ACCOUNT_PATH.exists():
    raise FileNotFoundError(
        f"Firebase service account not found:\n"
        f"{SERVICE_ACCOUNT_PATH}"
    )


# ============================================================
# INITIALIZE FIREBASE
# ============================================================

if not firebase_admin._apps:

    cred = credentials.Certificate(
        str(SERVICE_ACCOUNT_PATH)
    )

    firebase_admin.initialize_app(cred)

    print("Firebase Admin initialized!")


# ============================================================
# FIRESTORE CLIENT
# ============================================================

db = firestore.client(database='(default)')


# ============================================================
# DEBUG INFORMATION
# ============================================================

print("Firebase connected successfully!")
print("Project:", db.project)
print("Database:", db._database_string)