# ============================================================
# THREAT ID VERIFIER  (STEP 2)
# ============================================================
# Run:  python verify_ids.py
#
# Confirms the ID contract holds across the whole system:
#   1. Every threat_intelligence doc has a non-empty ID
#   2. The Firestore key matches the inner `threat_id`
#   3. Every ID is URL-safe
#   4. The dashboard exposes the ID on every returned threat
#   5. No duplicate IDs exist
# ============================================================

import re
from collections import Counter

from firebase_rest import list_documents, get_document
from user_dashboard import UserDashboardBuilder


ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


def check_1_ids_present():
    ids = list_documents("threat_intelligence") or []
    bad = [i for i in ids if not i]
    return (len(ids), bad)


def check_2_id_matches_field():
    mismatches = []
    for tid in list_documents("threat_intelligence") or []:
        doc = get_document("threat_intelligence", tid) or {}
        inner = doc.get("threat_id")
        if inner != tid:
            mismatches.append((tid, inner))
    return mismatches


def check_3_url_safe():
    bad = []
    for tid in list_documents("threat_intelligence") or []:
        if not ID_PATTERN.match(tid or ""):
            bad.append(tid)
    return bad


def check_4_dashboard_exposes_ids():
    missing = []
    builder = UserDashboardBuilder()
    for uid in ["u_chikitha", "u_senior", "u_test_sev"]:
        p = builder.build(uid)
        if not p:
            continue
        for t in p["threats"]:
            if not t.get("id"):
                missing.append((uid, t.get("title")))
    return missing


def check_5_no_duplicates():
    ids = list_documents("threat_intelligence") or []
    counts = Counter(ids)
    return [i for i, n in counts.items() if n > 1]


def main():
    print("=" * 60)
    print("THREAT ID VERIFICATION")
    print("=" * 60)

    total, empties = check_1_ids_present()
    print(f"\n1. {total} docs in threat_intelligence")
    print(f"   {'✓ all have IDs' if not empties else '✗ empty IDs: ' + str(empties)}")

    mismatches = check_2_id_matches_field()
    print(f"\n2. threat_id field vs Firestore key")
    if not mismatches:
        print(f"   ✓ every doc.threat_id matches its Firestore key")
    else:
        print(f"   ✗ {len(mismatches)} mismatch(es):")
        for fs, inner in mismatches:
            print(f"      {fs!r}  vs  {inner!r}")

    unsafe = check_3_url_safe()
    print(f"\n3. URL safety")
    if not unsafe:
        print(f"   ✓ all IDs URL-safe")
    else:
        print(f"   ✗ {len(unsafe)} unsafe ID(s):")
        for i in unsafe:
            print(f"      {i!r}")

    missing = check_4_dashboard_exposes_ids()
    print(f"\n4. dashboard exposes id on every threat")
    if not missing:
        print(f"   ✓ every returned threat has an id")
    else:
        print(f"   ✗ {len(missing)} threat(s) missing id:")
        for uid, title in missing:
            print(f"      user={uid}  title={title!r}")

    dupes = check_5_no_duplicates()
    print(f"\n5. duplicate IDs")
    print(f"   {'✓ no duplicates' if not dupes else '✗ duplicates: ' + str(dupes)}")

    print()
    print("=" * 60)
    all_ok = not (empties or mismatches or unsafe or missing or dupes)
    print("✓ ALL CHECKS PASSED" if all_ok else "✗ SOME CHECKS FAILED")
    print("=" * 60)


if __name__ == "__main__":
    main()