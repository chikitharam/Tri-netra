# ============================================================
# DEBUG — COMMUNITY FILTER DIAGNOSTIC
# ============================================================
#   python debug_filter.py
#
# Shows, for every threat_intelligence document:
#   - its `communities` list
#   - its `simplified.who_is_affected` list
#   - which of the 4 canonical communities it matches
#
# Use this when /me shows too few (or too many) threats.
# ============================================================

from firebase_rest import list_documents, get_document


CANONICAL = [
    "Students",
    "Senior Citizens",
    "Small Businesses",
    "General Public",
]


def fetch_all_intelligence():
    """Return list of (threat_id, doc) for all threat_intelligence docs."""
    raw = list_documents("threat_intelligence") or []
    ids = list(raw.keys()) if isinstance(raw, dict) else raw

    out = []
    for tid in ids:
        doc = get_document("threat_intelligence", tid)
        if isinstance(doc, dict):
            out.append((tid, doc))
    return out


def get_communities(doc):
    """Extract communities from a threat_intelligence doc."""
    communities = doc.get("communities") or []
    if not isinstance(communities, list):
        communities = []

    simplified = doc.get("simplified") or {}
    if isinstance(simplified, dict):
        who = simplified.get("who_is_affected") or []
        if not isinstance(who, list):
            who = []
    else:
        who = []

    return communities, who


def main():
    rows = fetch_all_intelligence()

    print("=" * 110)
    print("MODULE 6 — COMMUNITY FILTER DIAGNOSTIC")
    print("=" * 110)
    print()

    if not rows:
        print("No threat_intelligence documents found.")
        print()
        print("Fix:  python seed_threats.py --process")
        return

    # ============================================================
    # 1. Per-threat detail
    # ============================================================
    print("RAW DATA")
    print("-" * 110)
    print(f"{'threat_id':<22} {'severity':<12} {'communities':<38} {'simplified.who_is_affected':<38}")
    print("-" * 110)

    for tid, doc in rows:
        sev = doc.get("severity", "—")
        communities, who = get_communities(doc)

        comm_str = ", ".join(communities) if communities else "— (empty)"
        who_str = ", ".join(who) if who else "— (empty)"

        print(f"{tid:<22} {sev:<12} {comm_str:<38} {who_str:<38}")

    print()

    # ============================================================
    # 2. Match matrix
    # ============================================================
    print("=" * 110)
    print("MATCH MATRIX  (✓ = threat matches this community)")
    print("=" * 110)
    print()

    header = f"{'threat_id':<22} " + " ".join(f"{c:<17}" for c in CANONICAL)
    print(header)
    print("-" * 110)

    for tid, doc in rows:
        communities, who = get_communities(doc)
        merged = set(communities) | set(who)

        row = f"{tid:<22} "
        for c in CANONICAL:
            mark = "✓" if c in merged else "·"
            row += f"{mark:<17} "
        print(row)

    print()

    # ============================================================
    # 3. Per-community counts
    # ============================================================
    print("=" * 110)
    print("PER-COMMUNITY THREAT COUNTS")
    print("=" * 110)
    print()

    for c in CANONICAL:
        matches = []
        for tid, doc in rows:
            communities, who = get_communities(doc)
            merged = set(communities) | set(who)
            if c in merged:
                matches.append(tid)

        marker = "✓" if matches else "✗"
        print(f"  {marker}  {c:<20}  {len(matches):>2} threat(s)   {'  '.join(matches)}")

    print()
    print("=" * 110)

    # ============================================================
    # 4. Diagnostic hints
    # ============================================================
    empty_communities = [c for c in CANONICAL if not any(
        c in (set(get_communities(doc)[0]) | set(get_communities(doc)[1]))
        for _, doc in rows
    )]

    if empty_communities:
        print()
        print("⚠️  Some communities have ZERO threats:")
        for c in empty_communities:
            print(f"     - {c}")
        print()
        print("   Users in those communities will see an empty feed.")
        print()
        print("   Fix: reprocess a raw threat tagged with that community:")
        print(f"     python main.py --process <threat_id> --force")
        print()
    else:
        print()
        print("✅ Every community has at least one threat.")
        print("   Module 6 filter is fully populated.")
        print()


if __name__ == "__main__":
    main()