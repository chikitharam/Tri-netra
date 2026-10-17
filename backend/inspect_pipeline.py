# ============================================================
# PIPELINE INSPECTOR
# ============================================================
# Runs ONE threat through every stage of the TRINETRA pipeline
# and prints exactly what each stage produced.
#
#   python inspect_pipeline.py t_job_scam
#   python inspect_pipeline.py t_job_scam --live
#
# Without --live:   only reads what's already in Firestore
# With    --live:   actually re-runs Modules 2 and 5
# ============================================================

import sys
import json

from firebase_rest import get_document, list_documents


# ============================================================
# Pretty-printing helpers
# ============================================================
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
CYAN  = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED   = "\033[31m"
MAGENTA = "\033[35m"


def header(title, color=CYAN):
    print()
    print(color + "=" * 70 + RESET)
    print(color + BOLD + title + RESET)
    print(color + "=" * 70 + RESET)


def field(label, value):
    if value is None or value == "" or value == [] or value == {}:
        print(f"  {DIM}{label:24s}: (empty){RESET}")
    elif isinstance(value, (list, dict)):
        print(f"  {BOLD}{label:24s}:{RESET}")
        print(f"    {json.dumps(value, indent=4, ensure_ascii=False)[:1200]}")
    else:
        print(f"  {BOLD}{label:24s}:{RESET} {value}")


def ok(msg):   print(f"  {GREEN}✓{RESET} {msg}")
def warn(msg): print(f"  {YELLOW}⚠{RESET} {msg}")
def fail(msg): print(f"  {RED}✗{RESET} {msg}")


# ============================================================
# Stage 1 — Raw threat
# ============================================================
def inspect_stage_1(threat_id):
    header("STAGE 1 — Raw Threat  (collection: threat)", CYAN)
    doc = get_document("threat", threat_id)
    if not isinstance(doc, dict):
        fail(f"No document 'threat/{threat_id}'")
        return None

    ok(f"threat/{threat_id} found")
    field("title",       doc.get("title"))
    field("category",    doc.get("category"))
    field("community",   doc.get("community"))
    field("location",    doc.get("location"))
    field("description", (doc.get("description") or "")[:200] + "…")
    field("processed",   doc.get("processed"))

    return doc


# ============================================================
# Stage 2-5 — Structured intelligence
# ============================================================
def inspect_stage_2_to_5(threat_id):
    header("STAGE 2–5 — Structured Threat  (collection: threat_intelligence)", MAGENTA)
    doc = get_document("threat_intelligence", threat_id)
    if not isinstance(doc, dict):
        fail(f"No document 'threat_intelligence/{threat_id}'")
        warn(f"Run:  python main.py --process {threat_id} --force")
        return None

    ok(f"threat_intelligence/{threat_id} found")

    print()
    print(f"  {BOLD}Module 2 (Analysis):{RESET}")
    field("threat_type", doc.get("threat_type"))
    field("severity",    doc.get("severity"))
    field("region",      doc.get("region"))
    field("keywords",    doc.get("keywords"))
    field("indicators",  doc.get("indicators"))

    print()
    print(f"  {BOLD}Module 4 (Community Classification):{RESET}")
    field("communities",     doc.get("communities"))
    field("target",          doc.get("target"))
    field("confidence",      doc.get("community_confidence_scores"))
    field("reason",          doc.get("community_reason"))

    print()
    print(f"  {BOLD}Module 5 (Threat Simplifier):{RESET}")
    simplified = doc.get("simplified") or {}
    if not isinstance(simplified, dict):
        fail("simplified block is not a dict")
        return doc

    if not simplified:
        fail("simplified block is EMPTY")
        warn(f"Run:  python main.py --process {threat_id} --force")
        return doc

    ok("simplified block is populated")
    field("simplified.title",            simplified.get("title"))
    field("simplified.what_happened",    simplified.get("what_happened"))
    field("simplified.how_attack_works", simplified.get("how_attack_works"))
    field("simplified.how_to_identify",  simplified.get("how_to_identify"))
    field("simplified.what_to_do",       simplified.get("what_to_do"))
    field("simplified.safety_tip",       simplified.get("safety_tip"))
    field("simplified.ai_used",          simplified.get("ai_used"))
    field("simplified.ai_model",         simplified.get("ai_model"))
    field("simplified.ai_error",         simplified.get("ai_error"))

    return doc


# ============================================================
# Stage 6 — Verification
# ============================================================
def inspect_stage_6(doc):
    header("STAGE 6 — Human Verification", YELLOW)
    if not isinstance(doc, dict):
        fail("No document to inspect")
        return

    verified = doc.get("verified", False)
    if verified:
        ok("Verified")
        field("verified_by",         doc.get("verified_by"))
        field("verified_at",         doc.get("verified_at"))
        field("verification_note",   doc.get("verification_note"))
    else:
        warn("Not yet verified — awaiting human review")

    field("classification_method", doc.get("classification_method"))


# ============================================================
# Stage 7 — Dashboard API
# ============================================================
def inspect_stage_7(threat_id):
    header("STAGE 7 — Dashboard API  (/api/dashboard/<user_id>)", GREEN)

    from user_dashboard import UserDashboardBuilder
    builder = UserDashboardBuilder()

    for user_id in ["u_student", "u_senior", "u_business", "u_public"]:
        payload = builder.build(user_id)
        if not payload:
            fail(f"{user_id}: not found")
            continue

        threats = payload.get("threats", [])
        matched = [t for t in threats if t.get("id") == threat_id]

        if matched:
            ok(f"{user_id} ({payload['community']}) sees this threat")
            t = matched[0]
            field("  title",    t.get("title"))
            field("  severity", t.get("severity"))
            field("  target",   t.get("target"))
            field("  platform", t.get("platform"))
        else:
            print(f"  {DIM}·{RESET} {user_id} ({payload['community']}) does not see this threat")


# ============================================================
# Main
# ============================================================
def main():
    if len(sys.argv) < 2:
        print("Usage:  python inspect_pipeline.py <threat_id> [--live]")
        print()
        print("Example:")
        print("  python inspect_pipeline.py t_job_scam")
        print("  python inspect_pipeline.py t_job_scam --live")
        print()
        print("Available threat IDs:")

        raw = list_documents("threat") or []
        ids = list(raw.keys()) if isinstance(raw, dict) else raw
        for tid in ids:
            print(f"  - {tid}")
        return

    threat_id = sys.argv[1]
    live = "--live" in sys.argv

    print()
    print(BOLD + f"INSPECTING PIPELINE FOR:  {threat_id}" + RESET)
    if live:
        print(YELLOW + "(live mode — will re-run Modules 2 and 5)" + RESET)

    # Stage 1
    inspect_stage_1(threat_id)

    # Live processing
    if live:
        header("LIVE MODE — Running Modules 2 & 5", RED)
        try:
            from ai_engine import process_threat
            process_threat(threat_id, force=True)
            ok("Live pipeline completed")
        except Exception as e:
            fail(f"Live pipeline failed: {e}")
            return

    # Stage 2-5
    doc = inspect_stage_2_to_5(threat_id)

    # Stage 6
    inspect_stage_6(doc)

    # Stage 7
    inspect_stage_7(threat_id)

    # Summary
    header("SUMMARY", CYAN)
    print(f"  Inspect the JSON directly at:")
    print(f"    http://127.0.0.1:5001/api/threat/{threat_id}")
    print()
    print(f"  View the personalized detail page at:")
    print(f"    http://127.0.0.1:5001/app/threat.html?id={threat_id}")
    print()


if __name__ == "__main__":
    main()