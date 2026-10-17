import firebase_admin
from firebase_admin import credentials, firestore

cred = credentials.Certificate("solo-connect-key.json")

firebase_admin.initialize_app(cred)

db = firestore.client()

print("Firebase connected successfully!")