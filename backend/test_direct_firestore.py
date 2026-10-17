from pathlib import Path
from google.cloud import firestore
from google.oauth2 import service_account

BASE_DIR = Path(__file__).resolve().parent.parent

SERVICE_ACCOUNT = (
    BASE_DIR
    / "threat-collector"
    / "serviceAccountKey.json"
)

credentials = service_account.Credentials.from_service_account_file(
    str(SERVICE_ACCOUNT)
)

print("Project:", credentials.project_id)

db = firestore.Client(
    project="trinetra-877a6",
    credentials=credentials,
    database="(default)"
)

print("Client created!")

doc = db.collection("threat").document("t1").get()

print("Document exists:", doc.exists)

if doc.exists:
    print("DATA:")
    print(doc.to_dict())