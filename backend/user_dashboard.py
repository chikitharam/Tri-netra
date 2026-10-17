# ============================================================
# MODULE 6 — USER DASHBOARD (Personalized Threat Feed)
# ============================================================
# Bridges the existing threat_intelligence collection and
# individual users of the platform.
#
# Responsibilities:
#   1. Load a user's profile (name + community)
#   2. Normalize the community value
#   3. Fetch threats that belong to that community
#   4. Sort them by severity (Critical → High → Medium → Low)
#   5. Pick a relevant safety tip
#   6. Return a clean JSON object for the frontend
#
# It does NOT read the raw `threat` collection. It only
# consumes `threat_intelligence`, which already contains
# Module 4 communities and Module 5 simplified output.
#
# ============================================================
# THREAT ID CONTRACT  (STEP 2 — Module 7 prep)
# ============================================================
# Every threat has one canonical ID: its Firestore document
# ID in `threat_intelligence/<id>`.
#
# The ID is written in exactly two places, always with the
# same value:
#   1. As the Firestore document key        → "t_internship_scam"
#   2. As the `threat_id` field inside it   → "t_internship_scam"
#
# Rules:
#   • IDs must be URL-safe: letters, digits, "_", "-"
#   • IDs never change after a document is created
#   • `_shape_threat()` puts the ID in the "id" field of
#     every threat card, and guarantees it is non-empty
#   • templates/me.html renders every card as
#       <a href="/threat/<id>">
#   • dashboard.threat_detail() resolves the ID via
#       get_document("threat_intelligence", threat_id)
#
# If any of these rules is violated, /threat/<id> returns
# 404 and the Read More button becomes a dead link.
# ============================================================

from __future__ import annotations

import datetime
from typing import Optional

from firebase_rest import get_document, list_documents


# ------------------------------------------------------------
# Community aliasing
# ------------------------------------------------------------
COMMUNITY_ALIASES = {
    "student":            "Students",
    "students":           "Students",

    "senior":             "Senior Citizens",
    "seniors":            "Senior Citizens",
    "senior citizen":     "Senior Citizens",
    "senior citizens":    "Senior Citizens",
    "senior_citizen":     "Senior Citizens",
    "senior-citizen":     "Senior Citizens",
    "elderly":            "Senior Citizens",

    "business":           "Small Businesses",
    "businesses":         "Small Businesses",
    "small business":     "Small Businesses",
    "small businesses":   "Small Businesses",
    "small_business":     "Small Businesses",
    "small-business":     "Small Businesses",
    "sme":                "Small Businesses",
    "shop owner":         "Small Businesses",

    "general":            "General Public",
    "public":             "General Public",
    "general public":     "General Public",
    "general_public":     "General Public",
    "general-public":     "General Public",
    "everyone":           "General Public",
}

VALID_COMMUNITIES = [
    "Students",
    "Senior Citizens",
    "Small Businesses",
    "General Public",
]


def normalize_community(raw) -> str:
    """
    Convert any community label into one of the four canonical
    Module 4 values. Falls back to 'General Public'.

    Examples:
        "STUDENT"         → "Students"
        "student"         → "Students"
        "SENIOR_CITIZEN"  → "Senior Citizens"
        "sme"             → "Small Businesses"
        "everyone"        → "General Public"
    """
    if not raw:
        return "General Public"

    key = (
        str(raw)
        .strip()
        .lower()
        .replace("-", " ")
        .replace("_", " ")
    )

    if key in COMMUNITY_ALIASES:
        return COMMUNITY_ALIASES[key]

    for canonical in VALID_COMMUNITIES:
        if canonical.lower() == key:
            return canonical

    if "student" in key:
        return "Students"
    if "senior" in key or "elder" in key:
        return "Senior Citizens"
    if "business" in key or "sme" in key or "shop" in key:
        return "Small Businesses"

    return "General Public"


# ------------------------------------------------------------
# Severity ordering (STEP 7)
# ------------------------------------------------------------
SEVERITY_RANK = {
    "critical": 0,
    "high":     1,
    "medium":   2,
    "low":      3,
}

DEFAULT_SEVERITY_RANK = 4


def severity_rank(severity) -> int:
    """Return an integer rank for a severity label."""
    if severity is None:
        return DEFAULT_SEVERITY_RANK
    return SEVERITY_RANK.get(str(severity).strip().lower(), DEFAULT_SEVERITY_RANK)


# ============================================================
# STEP 10 — SAFETY TIPS LIBRARY
# ------------------------------------------------------------
# Keyed by CANONICAL community name. get_safety_tip() below
# normalizes the input first, so callers can pass "STUDENT",
# "student", "Students", or any alias — all work.
# ============================================================
SAFETY_TIPS = {
    "Students": [
        "Never share an OTP or pay a fee for an internship, scholarship, or job offer.",
        "Real employers never ask for money to give you a job.",
        "Verify scholarship websites against the official government portal.",
        "Do not share Aadhaar, PAN, or bank details with unknown recruiters.",
    ],
    "Senior Citizens": [
        "Banks never ask for your OTP or PIN over the phone.",
        "Pension departments never call to 'verify KYC' on the spot.",
        "If a caller creates urgency, hang up and call the official number back.",
        "Do not install remote-access apps on request from unknown callers.",
    ],
    "Small Businesses": [
        "Verify every payment request by calling the supplier on a known number.",
        "Enable two-factor authentication on accounting and banking apps.",
        "Keep offline backups of all invoices and payroll records.",
        "Watch for emails that change a vendor's bank account details.",
    ],
    "General Public": [
        "Never share passwords or OTPs with unknown people.",
        "Slow down when a message feels urgent — verify through an official channel.",
        "If an offer sounds too good to be true, it usually is.",
        "Report suspicious messages to the cybercrime helpline.",
    ],
}

# Backwards-compatibility alias (older code imported this name)
DEFAULT_SAFETY_TIPS = SAFETY_TIPS


def get_safety_tip(community, threats=None, intelligence_collection: str = "threat_intelligence") -> str:
    """
    Return a safety tip for the given community.

    Priority:
      1. AI-generated safety_tip from the newest matching threat
      2. First entry in SAFETY_TIPS[canonical community]
      3. SAFETY_TIPS["General Public"][0]

    Args:
        community: any community label ("STUDENT", "student", "Students")
        threats:   optional list of threat dicts (each must have "id")
        intelligence_collection: Firestore collection for lookup

    Returns:
        A non-empty safety tip string.
    """
    canonical = normalize_community(community)

    # 1. AI tip from a threat
    if threats:
        for threat in threats:
            tid = threat.get("id") if isinstance(threat, dict) else None
            if not tid:
                continue
            doc = get_document(intelligence_collection, tid)
            if not isinstance(doc, dict):
                continue
            simplified = doc.get("simplified") or {}
            if isinstance(simplified, dict):
                tip = simplified.get("safety_tip")
                if isinstance(tip, str) and tip.strip():
                    return tip.strip()

    # 2. Community-specific fallback
    tips = SAFETY_TIPS.get(canonical) or SAFETY_TIPS["General Public"]
    if tips:
        return tips[0]

    # 3. Absolute last resort
    return "Stay alert and verify through an official channel before acting."


# ------------------------------------------------------------
# Builder
# ------------------------------------------------------------
class UserDashboardBuilder:
    """
    Builds the personalized threat feed for a single user.
    """

    def __init__(
        self,
        users_collection: str = "users",
        intelligence_collection: str = "threat_intelligence",
        max_threats: int = 20,
    ):
        self.users_collection = users_collection
        self.intelligence_collection = intelligence_collection
        self.max_threats = max_threats

    # --------------------------------------------------------
    # 1. Load user
    # --------------------------------------------------------
    def get_user(self, user_id: str) -> Optional[dict]:
        doc = get_document(self.users_collection, user_id)
        if not isinstance(doc, dict):
            return None

        return {
            "id": user_id,
            "name": doc.get("name", "User"),
            "email": doc.get("email", ""),
            "community": normalize_community(
                doc.get("community") or doc.get("role") or doc.get("type")
            ),
        }

    # --------------------------------------------------------
    # 2. Find threats for a community
    # --------------------------------------------------------
    def get_threats_for_community(self, community: str) -> list:
        """
        Scan threat_intelligence, keep documents whose
        `communities` list contains the given community,
        then sort by severity (Critical → Low) and newest
        first within the same severity.
        """
        all_ids = list_documents(self.intelligence_collection) or []
        if isinstance(all_ids, dict):
            all_ids = list(all_ids.keys())

        matched = []

        for threat_id in all_ids:
            doc = get_document(self.intelligence_collection, threat_id)
            if not isinstance(doc, dict):
                continue

            communities = doc.get("communities") or []
            if not isinstance(communities, list):
                communities = []

            # Filter: must match `communities` OR
            # simplified.who_is_affected (fallback for old docs)
            if community not in communities:
                simplified = doc.get("simplified") or {}
                if isinstance(simplified, dict):
                    who = simplified.get("who_is_affected") or []
                    if community not in who:
                        continue
                else:
                    continue

            matched.append(self._shape_threat(threat_id, doc))

        # STEP 7 — sort by severity, then newest first
        matched.sort(
            key=lambda t: t.get("processed_at", ""),
            reverse=True,
        )
        matched.sort(
            key=lambda t: severity_rank(t.get("severity"))
        )

        return matched[: self.max_threats]

    # --------------------------------------------------------
    # 3. Shape a single threat for the frontend
    # --------------------------------------------------------
    # STEP 2 — the returned dict ALWAYS has a non-empty "id".
    #
    # Two safety nets:
    #   • If `threat_id` (the Firestore document key) is empty
    #     or missing, fall back to the doc's `threat_id` field.
    #   • If BOTH are empty, use a stable placeholder and warn
    #     so the missing ID shows up in logs instead of
    #     silently producing a dead /threat/undefined link.
    # --------------------------------------------------------
    def _shape_threat(self, threat_id: str, doc: dict) -> dict:
        simplified = doc.get("simplified") or {}
        if not isinstance(simplified, dict):
            simplified = {}

        title = (
            simplified.get("title")
            or doc.get("title")
            or doc.get("threat_type")
            or "Untitled threat"
        )

        description = (
            simplified.get("what_happened")
            or doc.get("description")
            or f"A {doc.get('severity', 'Medium').lower()} severity "
               f"{doc.get('threat_type', 'cyber')} threat has been detected."
        )

        # ---- ID resolution (STEP 2) ------------------------
        # 1. Prefer the Firestore document key passed by the caller.
        # 2. Fall back to the doc's own `threat_id` field.
        # 3. If neither is present, warn and use a placeholder so
        #    the link never becomes /threat/undefined.
        resolved_id = threat_id or doc.get("threat_id")

        if not resolved_id:
            print(
                "  ⚠ WARNING: threat_intelligence doc has no "
                "usable ID — title=%r" % (title,)
            )
            resolved_id = "unknown-threat"

        # ------------------------------------------------

        return {
            "id": resolved_id,
            "title": title,
            "severity": doc.get("severity", "Medium"),
            "threat_type": doc.get("threat_type", "Unknown"),
            "target": doc.get("target", []),
            "platform": doc.get("platform", []),
            "region": doc.get("region", "Unknown"),
            "description": description,
            "verified": bool(doc.get("verified", False)),
            "processed_at": doc.get("processed_at", ""),
        }

    # --------------------------------------------------------
    # 4. Safety tip (delegates to module-level function)
    # --------------------------------------------------------
    def pick_safety_tip(self, community: str, threats: list) -> str:
        """
        Prefer an AI-generated safety tip from the newest threat.
        Fall back to a community-specific default.
        """
        return get_safety_tip(
            community=community,
            threats=threats,
            intelligence_collection=self.intelligence_collection,
        )

    # --------------------------------------------------------
    # 5. Public: build the full dashboard payload
    # --------------------------------------------------------
    def build(self, user_id: str) -> Optional[dict]:
        user = self.get_user(user_id)
        if user is None:
            return None

        threats = self.get_threats_for_community(user["community"])
        safety_tip = self.pick_safety_tip(user["community"], threats)

        return {
            "name":         user["name"],
            "community":    user["community"],
            "threat_count": len(threats),
            "threats":      threats,
            "safety_tip":   safety_tip,
            "generated_at": datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat(),
        }

    # --------------------------------------------------------
    # Convenience: build by raw community (no user lookup)
    # --------------------------------------------------------
    def build_for_community(self, community: str, name: str = "Guest") -> dict:
        canonical = normalize_community(community)
        threats = self.get_threats_for_community(canonical)
        return {
            "name":         name,
            "community":    canonical,
            "threat_count": len(threats),
            "threats":      threats,
            "safety_tip":   self.pick_safety_tip(canonical, threats),
            "generated_at": datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat(),
        }


# ============================================================
# SELF-TEST
#   python user_dashboard.py
# ============================================================
if __name__ == "__main__":

    import json

    print("=" * 60)
    print("MODULE 6 — USER DASHBOARD TEST")
    print("=" * 60)
    print()

    # --- Test 1: community normalization ---
    samples = [
        "STUDENT", "student", "Students",
        "SENIOR", "senior_citizen", "Senior Citizens",
        "SME", "small-business", "Small Businesses",
        "everyone", "PUBLIC", None, ""
    ]
    print("Community normalization:")
    for s in samples:
        print(f"  {str(s):<20} → {normalize_community(s)}")
    print()

    # --- Test 2: safety tips ---
    print("Safety tips (raw keys and canonical keys both work):")
    for key in ["STUDENT", "student", "Students",
                "SENIOR_CITIZEN", "Senior Citizens",
                "SME", "Small Businesses",
                "everyone", "General Public"]:
        tip = get_safety_tip(key)
        print(f"  {key:<20} → {tip[:60]}…")
    print()

    # --- Test 3: severity ranking ---
    print("Severity ranking (lower = shown first):")
    for s in ["Critical", "High", "Medium", "Low", "Unknown", None]:
        print(f"  {str(s):<10} → rank {severity_rank(s)}")
    print()

    # --- Test 4: build payload for Students ---
    builder = UserDashboardBuilder()

    payload = builder.build_for_community(
        community="Students",
        name="Chikitha",
    )

    print("=" * 60)
    print("Sample payload for community=Students (sorted by severity)")
    print("=" * 60)
    print(json.dumps(payload, indent=2, ensure_ascii=False))