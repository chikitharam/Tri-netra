from firebase_rest import get_document
import json

print()
print("================================")
print("FIRESTORE REST API TEST")
print("================================")

print("Reading threat/t1...")
print()

try:
    threat = get_document("threat", "t1")
    if threat is None:
        print("ERROR: threat/t1 not found.")
    else:
        print("SUCCESS!")
        print()
        print("Document data:")
        print(json.dumps(threat, indent=4))

except Exception as e:
    print()
    print("================================")
    print("ERROR")
    print("================================")
    print(type(e).__name__)
    print(str(e))