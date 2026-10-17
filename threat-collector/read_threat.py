from firebase_config import db

# Get all documents from the threats collection
docs = db.collection("threats").stream()

for doc in docs:

    threat = doc.to_dict()

    print("=" * 50)

    print("Threat ID:", doc.id)
    print("Title:", threat.get("title"))
    print("Description:", threat.get("description"))
    print("Source:", threat.get("source"))
    print("Date:", threat.get("date"))

    print("=" * 50)