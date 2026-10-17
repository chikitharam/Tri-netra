# ============================================================
# Diagnose the users collection
#   python check_users.py
# ============================================================

from firebase_rest import list_documents, get_document


def main():
    raw = list_documents("users") or []
    ids = list(raw.keys()) if isinstance(raw, dict) else raw

    print("=" * 70)
    print(f"USERS COLLECTION — {len(ids)} document(s)")
    print("=" * 70)

    for uid in ids:
        doc = get_document("users", uid)
        if not isinstance(doc, dict):
            print(f"  {uid:20s}  ⚠️  not a dict: {type(doc).__name__}")
            continue

        has_hash = bool(doc.get("password_hash"))
        hash_preview = (doc.get("password_hash") or "")[:30]

        print(f"  id:        {uid}")
        print(f"  name:      {doc.get('name')}")
        print(f"  email:     {doc.get('email')}")
        print(f"  community: {doc.get('community')}")
        print(f"  hash:      {'✓ ' + hash_preview + '…' if has_hash else '❌ MISSING'}")
        print()


if __name__ == "__main__":
    main()