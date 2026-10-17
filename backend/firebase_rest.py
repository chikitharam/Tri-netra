import os
import json
from pathlib import Path
from datetime import datetime, timezone

import google.auth
from google.auth.transport.requests import AuthorizedSession
from google.oauth2 import service_account

# ============================================================
# CONFIGURATION
# ============================================================
PROJECT_ID = "trinetra-877a6"
DATABASE_ID = "(default)"
SCOPES = ["https://www.googleapis.com/auth/datastore"]

BASE_DIR = Path(__file__).resolve().parent
SERVICE_ACCOUNT_PATH = (
    BASE_DIR.parent / "threat-collector" / "serviceAccountKey.json"
)

# ============================================================
# GOOGLE SERVICE ACCOUNT (Cloud vs Local)
# ============================================================
# 1. Try to load from Environment Variable (Production/Cloud)
firebase_json_str = os.environ.get("FIREBASE_CREDENTIALS")

if firebase_json_str:
    try:
        creds_dict = json.loads(firebase_json_str)
        credentials = service_account.Credentials.from_service_account_info(
            creds_dict, scopes=SCOPES
        )
        print("Loaded Firebase credentials from Environment Variable.")
    except Exception as e:
        raise ValueError(f"Failed to parse FIREBASE_CREDENTIALS env var: {e}")
else:
    # 2. Fallback to local JSON file (Local Development)
    if not SERVICE_ACCOUNT_PATH.exists():
        raise FileNotFoundError(
            f"Service account file not found:\n{SERVICE_ACCOUNT_PATH}\n"
            "Please set the FIREBASE_CREDENTIALS environment variable for cloud deployment."
        )
    
    credentials = service_account.Credentials.from_service_account_file(
        str(SERVICE_ACCOUNT_PATH), scopes=SCOPES
    )
    print("Loaded Firebase credentials from local JSON file.")

# ============================================================
# AUTHORIZED HTTPS SESSION
# ============================================================
session = AuthorizedSession(credentials)

# ============================================================
# FIRESTORE BASE URL
# ============================================================
BASE_URL = (
    f"https://firestore.googleapis.com/v1/"
    f"projects/{PROJECT_ID}/"
    f"databases/{DATABASE_ID}/documents"
)

# ============================================================
# CONVERT FIRESTORE REST VALUE → PYTHON
# ============================================================
def firestore_value_to_python(value):
    if "stringValue" in value:
        return value["stringValue"]
    if "integerValue" in value:
        return int(value["integerValue"])
    if "doubleValue" in value:
        return float(value["doubleValue"])
    if "booleanValue" in value:
        return value["booleanValue"]
    if "nullValue" in value:
        return None
    if "timestampValue" in value:
        return value["timestampValue"]
    if "arrayValue" in value:
        values = value["arrayValue"].get("values", [])
        return [firestore_value_to_python(v) for v in values]
    if "mapValue" in value:
        fields = value["mapValue"].get("fields", {})
        return {
            key: firestore_value_to_python(val)
            for key, val in fields.items()
        }
    return None

# ============================================================
# CONVERT FIRESTORE DOCUMENT → PYTHON DICT
# ============================================================
def document_to_python(document):
    fields = document.get("fields", {})
    result = {}
    for key, value in fields.items():
        result[key] = firestore_value_to_python(value)
    return result

# ============================================================
# GET DOCUMENT
# ============================================================
def get_document(collection, document_id):
    url = f"{BASE_URL}/{collection}/{document_id}"
    response = session.get(url, timeout=30)

    if response.status_code == 404:
        return None

    if not response.ok:
        raise RuntimeError(
            f"Firestore GET failed: {response.status_code} {response.text}"
        )
    return document_to_python(response.json())

# ============================================================
# LIST DOCUMENTS
# ============================================================
def list_documents(collection):
    url = f"{BASE_URL}/{collection}"
    response = session.get(url, timeout=30)

    if not response.ok:
        raise RuntimeError(
            f"Firestore LIST failed: {response.status_code} {response.text}"
        )

    data = response.json()
    documents = data.get("documents", [])
    doc_ids = [doc["name"].split("/")[-1] for doc in documents]
    return doc_ids

# ============================================================
# PYTHON → FIRESTORE REST VALUE
# ============================================================
def python_to_firestore_value(value):
    if value is None:
        return {"nullValue": None}
    if isinstance(value, bool):
        return {"booleanValue": value}
    if isinstance(value, int):
        return {"integerValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, str):
        return {"stringValue": value}
    if isinstance(value, list):
        return {
            "arrayValue": {
                "values": [python_to_firestore_value(item) for item in value]
            }
        }
    if isinstance(value, dict):
        return {
            "mapValue": {
                "fields": {
                    key: python_to_firestore_value(val)
                    for key, val in value.items()
                }
            }
        }
    raise TypeError(f"Unsupported Firestore value type: {type(value)}")

# ============================================================
# SAVE DOCUMENT
# ============================================================
def set_document(collection, document_id, data):
    url = f"{BASE_URL}/{collection}/{document_id}"
    fields = {key: python_to_firestore_value(value) for key, value in data.items()}
    payload = {"fields": fields}

    response = session.patch(url, json=payload, timeout=30)

    if not response.ok:
        raise RuntimeError(
            f"Firestore SET failed: {response.status_code} {response.text}"
        )
    return document_to_python(response.json())

# ============================================================
# DELETE DOCUMENT
# ============================================================
def delete_document(collection, document_id):
    url = f"{BASE_URL}/{collection}/{document_id}"
    response = session.delete(url, timeout=30)

    if not response.ok and response.status_code != 404:
        raise RuntimeError(
            f"Firestore DELETE failed: {response.status_code} {response.text}"
        )
    return True

# ============================================================
# TEST
# ============================================================
if __name__ == "__main__":
    print("\n============================================")
    print("TRINETRA FIRESTORE REST TEST")
    print("============================================")
    print("Project:", PROJECT_ID)
    print("Database:", DATABASE_ID)
    print("\nReading threat/t1...\n")
    try:
        threat = get_document("threat", "t1")
        if threat is None:
            print("ERROR: threat/t1 not found.")
        else:
            print("SUCCESS!")
            print(json.dumps(threat, indent=4))
    except Exception as e:
        print("\n============================================")
        print("ERROR")
        print("============================================")
        print(type(e).__name__)
        print(str(e))