# ============================================================
# MODULE 1–5 — AI ENGINE
# ============================================================
# Orchestrates the full threat-processing pipeline:
#
#   1. Raw threat      ← firebase: threat/<id>
#   2. Gemini analysis ← Module 2 (extract structured fields)
#   3. Community rules ← Module 4 (hybrid AI + keyword)
#   4. Simplification  ← Module 5 (plain language)
#   5. Save            ← firebase: threat_intelligence/<id>
#
# Model selection is dynamic — see gemini_client.py.
# Callers fall back to rule-based logic if all models fail.
#
# STEP 1 (Module 7 prep) — source propagation:
#   The raw threat doc may carry `source` and `source_url`.
#   They are (a) included in the Gemini prompt so the AI can
#   reference them, and (b) copied into the saved
#   threat_intelligence doc so Module 7 can cite them in
#   notifications.
# ============================================================

import os
import json
import time

from dotenv import load_dotenv
from google import genai
from pydantic import BaseModel
from threat_simplifier import ThreatSimplifier

from firebase_rest import (
    get_document,
    set_document,
    list_documents
)

# Import from new modular structure
from community_classifier import (
    hybrid_classification,
    classify_by_keywords,
    validate_communities,
    normalize_community
)
from community_rules import VALID_COMMUNITIES
from validation import validate_ai_output, format_final_output

# Auto-discover available Gemini models
from gemini_client import make_client


# ============================================================
# 1. LOAD ENVIRONMENT
# ============================================================

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    raise ValueError("GEMINI_API_KEY not found in .env")


# ============================================================
# 2. GEMINI CLIENT & MODELS
# ============================================================
# Auto-discovers the available flash models for this API key.
#
# MODEL_CANDIDATES is a priority-ordered list, best first.
# MODEL_NAME is the primary (first) choice — kept for code
# that expects a single model name.
#
# If the primary model returns 503 UNAVAILABLE, analyze_threat()
# walks down the list until one succeeds. If every model fails,
# it falls back to rule-based classification so the pipeline
# never crashes.

client, MODEL_CANDIDATES = make_client()
MODEL_NAME = MODEL_CANDIDATES[0] if MODEL_CANDIDATES else "gemini-flash-latest"

print()
print("=" * 60)
print(f"Gemini client ready · {len(MODEL_CANDIDATES)} model(s) available")
print(f"Primary:  {MODEL_NAME}")
if len(MODEL_CANDIDATES) > 1:
    print(f"Fallback: {MODEL_CANDIDATES[1:5]}")
print("=" * 60)


# Module 5 — threat simplification helper
simplifier = ThreatSimplifier()


# ============================================================
# 3. STRUCTURED OUTPUT SCHEMA
# ============================================================

class ThreatIntelligence(BaseModel):
    threat_type: str
    target: list[str]
    platform: list[str]
    severity: str
    region: str
    keywords: list[str]
    indicators: list[str]
    recommended_actions: list[str]
    communities: list[str]  # AI-predicted communities


# ============================================================
# 4. SYSTEM PROMPT
# ============================================================

SYSTEM_PROMPT = f"""
You are a Cyber Threat Intelligence Analyst.

Analyze the provided cybersecurity threat information.

Extract:

1. threat_type
2. target
3. platform
4. severity
5. region
6. keywords
7. indicators
8. recommended_actions
9. communities

Severity levels:

Low
Medium
High
Critical

Possible threat types:

Phishing
Malware
Ransomware
Identity Theft
Financial Fraud
Job Scam
Investment Scam
Social Engineering
Data Breach
Account Takeover
Cyberbullying
Other

================================================================================
IMPORTANT – Community Classification Instructions:
================================================================================

Classify the threat into one or more of these communities:

1. Students
2. Senior Citizens
3. Small Businesses
4. General Public

Choose only communities that are realistically affected by this specific threat.
A threat may belong to multiple communities.

Return the communities as a JSON array in the `communities` field.

================================================================================
Additional Intelligence Guidelines:
================================================================================

IMPORTANT – Community Intelligence:

You MUST identify the specific communities or groups that are most likely to be affected by this threat.
Populate the `communities` array with one or more of the possible communities listed above.
If you are unsure, use ["General Public"].

When generating `recommended_actions`, tailor them to the specific target community.

IMPORTANT – Regional Intelligence:

You MUST identify the geographic region most relevant to this threat.
If no region is mentioned, use "Unknown".

================================================================================
Rules:
================================================================================

- Do not invent information.
- If information is unknown, use "Unknown".
- Keep all arrays as arrays.
- Analyze only the information provided.
- Be concise.

Return only valid JSON.
"""


# ============================================================
# 5. SEVERITY RULES (HYBRID LOGIC)
# ============================================================

THREAT_TYPE_SEVERITY = {
    "Ransomware": "Critical",
    "Data Breach": "High",
    "Malware": "High",
    "Identity Theft": "High",
    "Financial Fraud": "High",
    "Account Takeover": "High",
    "Phishing": "Medium",
    "Job Scam": "Medium",
    "Investment Scam": "Medium",
    "Social Engineering": "Medium",
    "Cyberbullying": "Medium",
    "Other": "Medium"
}

KEYWORD_SEVERITY = {
    "ransomware": "Critical",
    "credit card": "High",
    "bank account": "High",
    "password": "High",
    "wire transfer": "High",
    "urgent action required": "High",
    "government": "High",
    "aadhaar": "High",
    "pan card": "High"
}

SEVERITY_RANK = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4
}


def apply_severity_rules(ai_result):
    """Combine AI severity with rule-based logic."""
    current_severity = ai_result.get("severity", "Medium")
    current_rank = SEVERITY_RANK.get(current_severity, 2)

    # 1. Rule by threat_type
    threat_type = ai_result.get("threat_type", "Other")
    rule_severity = THREAT_TYPE_SEVERITY.get(threat_type, "Medium")
    rule_rank = SEVERITY_RANK.get(rule_severity, 2)
    if rule_rank > current_rank:
        current_severity = rule_severity
        current_rank = rule_rank

    # 2. Rule by keywords
    keywords = [kw.lower() for kw in ai_result.get("keywords", [])]
    for keyword, sev in KEYWORD_SEVERITY.items():
        if keyword in " ".join(keywords):
            sev_rank = SEVERITY_RANK.get(sev, 2)
            if sev_rank > current_rank:
                current_severity = sev
                current_rank = sev_rank

    return current_severity


# ============================================================
# 6. COMMUNITY RULES (HYBRID CLASSIFICATION)
# ============================================================

# Threat type → community mapping (additional)
THREAT_COMMUNITY = {
    "Job Scam": ["Job Seekers", "Students"],
    "Phishing": ["General Public"],
    "Financial Fraud": ["Senior Citizens", "General Public"],
    "Ransomware": ["Small Businesses", "General Public"],
    "Data Breach": ["Employees", "General Public"],
    "Identity Theft": ["General Public"],
    "Social Engineering": ["General Public"],
    "Cyberbullying": ["Children", "Students"],
    "Investment Scam": ["General Public", "Senior Citizens"],
    "Account Takeover": ["General Public"],
    "Malware": ["General Public"],
    "Other": ["General Public"]
}


def apply_community_rules(ai_result):
    """
    Hybrid community classification with confidence and reason.
    """
    # Step 1: Get AI-predicted communities
    ai_communities = ai_result.get("communities", [])

    # If `communities` is empty, fallback to `target`
    if not ai_communities:
        ai_communities = ai_result.get("target", [])

    # Step 2: Build text for rule engine
    text = " ".join(ai_result.get("keywords", [])) + " " + ai_result.get("threat_type", "")

    # Step 3: Run HYBRID CLASSIFICATION
    final_communities, confidence, reason, decisions, community_confidence, matched_keywords = hybrid_classification(
        text, ai_communities
    )

    # Step 4: Add threat-type based communities
    threat_type = ai_result.get("threat_type", "Other")
    type_targets = set(THREAT_COMMUNITY.get(threat_type, ["General Public"]))

    # Step 5: Combine all results
    combined = set(final_communities) | type_targets
    if not combined:
        combined = {"General Public"}

    final_list = list(combined)

    # Step 6: Build community reasons
    community_reasons = {}
    for community in final_list:
        matched = matched_keywords.get(community, [])
        if matched:
            reason_text = f"Detected keywords: {', '.join(matched)}"
        else:
            reason_text = "No specific keywords matched (fallback)"
        community_reasons[community] = reason_text

    # Step 7: Filter confidence scores
    final_confidence = {comm: community_confidence.get(comm, 0.0) for comm in final_list}

    # Step 8: Store all results
    ai_result["keyword_scores"] = classify_by_keywords(text)
    ai_result["communities"] = final_list
    ai_result["target"] = final_list
    ai_result["community_confidence"] = confidence
    ai_result["community_reason"] = reason
    ai_result["decision_matrix"] = decisions
    ai_result["community_confidence_scores"] = final_confidence
    ai_result["matched_keywords"] = matched_keywords
    ai_result["community_reasons"] = community_reasons

    return ai_result


# ============================================================
# 7. VALIDATE AI OUTPUT
# ============================================================

def validate_output(result):
    """Wrapper for validation.py validate_ai_output."""
    result = validate_ai_output(result)

    # Apply severity rules
    result["severity"] = apply_severity_rules(result)

    # Apply community rules (hybrid classification)
    result = apply_community_rules(result)

    # Final safety check for severity
    allowed_severity = ["Low", "Medium", "High", "Critical"]
    if result["severity"] not in allowed_severity:
        result["severity"] = "Medium"

    return result


# ============================================================
# 8. ANALYZE THREAT
# ============================================================
# Tries each model in MODEL_CANDIDATES in order.
#
#   • 503 UNAVAILABLE  → skip to the next model immediately
#   • Other errors     → retry the same model a few times
#   • All fail         → return _fallback_intelligence(...)
#
# This means the pipeline always produces a valid dict, even
# if every Gemini model is down.
# ============================================================

def _is_overloaded_error(err_str: str) -> bool:
    """
    True if the error looks like a 503 / high-demand message.
    These are transient and best handled by moving to a
    different model rather than retrying the same one.
    """
    s = err_str.lower()
    return (
        "503" in err_str
        or "unavailable" in s
        or "overloaded" in s
        or "high demand" in s
        or "resource_exhausted" in s
    )


def analyze_threat(threat_text):
    """
    Analyze a threat with Gemini.

    Walks MODEL_CANDIDATES from best to worst. On 503 returns
    from a model, tries the next. On other errors, retries the
    same model briefly. If every model fails, returns a
    rule-based fallback so the pipeline never crashes.
    """
    prompt = f"""
{SYSTEM_PROMPT}

Threat information:

{threat_text}
"""

    print()
    print("Sending threat to Gemini...")

    models_to_try = list(MODEL_CANDIDATES)
    last_error = None

    for model_idx, model_name in enumerate(models_to_try):
        print(f"  Trying model: {model_name}")

        # Quick retries within a single model (for non-503 errors)
        max_attempts = 2

        for attempt in range(1, max_attempts + 1):
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config={
                        "response_mime_type": "application/json",
                        "response_schema": ThreatIntelligence
                    }
                )

                result = ThreatIntelligence.model_validate_json(response.text)
                result_dict = result.model_dump()

                # Validate and normalize
                result_dict = validate_output(result_dict)

                print(f"  ✓ Gemini analysis completed (model={model_name})")
                return result_dict

            except Exception as e:
                last_error = e
                err_str = str(e)

                if _is_overloaded_error(err_str):
                    print(f"  ✗ {model_name} overloaded (503)")
                    break  # move straight to next model

                print(f"  ✗ {model_name} attempt {attempt}/{max_attempts} failed:")
                print(f"    {err_str[:200]}")
                if attempt < max_attempts:
                    wait_time = attempt * 3
                    print(f"    Waiting {wait_time} seconds...")
                    time.sleep(wait_time)

        if model_idx < len(models_to_try) - 1:
            print("  → Trying next model...")

    # All models exhausted — rule-based fallback
    print()
    print("=" * 60)
    print("ALL GEMINI MODELS FAILED")
    print("=" * 60)
    print(f"Last error: {last_error}")
    print()
    print("Possible causes:")
    print("  1. Gemini is having an outage — try again later")
    print("  2. Your API key quota is exhausted")
    print("  3. Network / firewall blocking the API")
    print()
    print("Falling back to rule-based classification so the")
    print("pipeline still produces a valid intelligence dict.")
    print("=" * 60)

    return _fallback_intelligence(threat_text)


def _fallback_intelligence(threat_text):
    """
    Rule-based fallback when Gemini is unreachable.

    Produces a minimal but valid intelligence dict using only
    the raw threat text. Matches the shape of a normal Gemini
    response so downstream code does not need to branch.
    """
    text_lower = (threat_text or "").lower()

    # Guess threat_type by keywords
    threat_type = "Other"
    if "phish" in text_lower or "otp" in text_lower or "credential" in text_lower:
        threat_type = "Phishing"
    elif "ransom" in text_lower or "encrypt" in text_lower:
        threat_type = "Ransomware"
    elif "job" in text_lower or "employment" in text_lower or "recruit" in text_lower:
        threat_type = "Job Scam"
    elif "invest" in text_lower or "return" in text_lower:
        threat_type = "Investment Scam"
    elif "fraud" in text_lower or "money" in text_lower or "refund" in text_lower:
        threat_type = "Financial Fraud"
    elif "malware" in text_lower or "virus" in text_lower:
        threat_type = "Malware"
    elif "identity" in text_lower or "impersonat" in text_lower:
        threat_type = "Identity Theft"

    return {
        "threat_type":         threat_type,
        "target":              ["General Public"],
        "platform":            ["Unknown"],
        "severity":            THREAT_TYPE_SEVERITY.get(threat_type, "Medium"),
        "region":              "Unknown",
        "keywords":            [],
        "indicators":          [],
        "recommended_actions": [
            "Do not click any links in the message",
            "Verify the sender through an official channel",
            "Never share passwords, OTPs or bank details",
            "Report the message to the cybercrime helpline",
        ],
        "communities":          ["General Public"],
        "keyword_scores":       {},
        "community_confidence": 0.5,
        "community_reason":     "Fallback classification (AI unavailable)",
        "decision_matrix":      {},
        "community_confidence_scores": {"General Public": 0.5},
        "matched_keywords":     {},
        "community_reasons":    {"General Public": "Fallback — AI unavailable"},
        "classification_method": "Rule-based fallback",
    }


# ============================================================
# 8b. MODULE 5 — THREAT SIMPLIFICATION
# ------------------------------------------------------------
# STEP 8.6 / 8.7 / 8.8
#
# Active path:   build_simplification_input() +
#                simplifier.simplify_with_ai() called from
#                inside process_threat().
#
# Legacy path:   simplify_threat() — kept for backwards
#                compatibility, no longer called by the
#                pipeline.
# ============================================================

def build_simplification_input(threat_text, intelligence):
    """
    Build the payload that Module 5 sends to Gemini.

    Contains:
      - the original raw threat text, and
      - the structured analysis from Module 4
        (threat_type, severity, communities, etc.).
    """
    return f"""
Original Threat:

{threat_text}

Threat Analysis:

Threat Type:
{intelligence.get("threat_type", "")}

Target:
{intelligence.get("target", [])}

Platform:
{intelligence.get("platform", [])}

Severity:
{intelligence.get("severity", "")}

Region:
{intelligence.get("region", "")}

Communities:
{intelligence.get("communities", [])}

Keywords:
{intelligence.get("keywords", [])}

Indicators:
{intelligence.get("indicators", [])}

Recommended Actions:
{intelligence.get("recommended_actions", [])}
"""


def simplify_threat(intelligence):
    """
    LEGACY Module 5 helper.

    Kept for backwards compatibility only.

    The active path is:
        simplifier.simplify_with_ai(
            build_simplification_input(threat_text, intelligence),
            client,
            MODEL_CANDIDATES,
        )
    which lives inside process_threat().

    This function is no longer called by the pipeline.
    """
    if not intelligence:
        return {}

    prompt = f"""
You are a cybersecurity threat simplification assistant.

Convert the following technical cybersecurity
information into language that an ordinary internet
user can easily understand.

Do not invent information.

Do not remove important security information.

Return ONLY valid JSON.

Required structure:

{{
    "what_happened": "",
    "who_is_affected": [],
    "how_attack_works": "",
    "how_to_identify": [],
    "what_to_do": []
}}

Rules:

1. what_happened:
Explain what happened in simple language.

2. who_is_affected:
Use the communities already classified by TRINETRA.

3. how_attack_works:
Explain the attack step-by-step in simple language.

4. how_to_identify:
Give practical warning signs.

5. what_to_do:
Give practical safety actions.

Existing TRINETRA intelligence:

Threat Type:
{intelligence.get("threat_type", "Unknown")}

Target:
{intelligence.get("target", [])}

Platform:
{intelligence.get("platform", [])}

Severity:
{intelligence.get("severity", "Unknown")}

Region:
{intelligence.get("region", "Unknown")}

Keywords:
{intelligence.get("keywords", [])}

Indicators:
{intelligence.get("indicators", [])}

Recommended Actions:
{intelligence.get("recommended_actions", [])}

Communities:
{intelligence.get("communities", [])}
"""

    response = client.models.generate_content(
        model=MODEL_NAME,
        contents=prompt,
        config={
            "response_mime_type": "application/json"
        }
    )

    simplified = json.loads(response.text)

    return simplified


# ============================================================
# 9. GET THREAT FROM FIREBASE
# ============================================================

def get_threat(threat_id):
    print(f"Reading threat '{threat_id}' from Firebase REST API...")
    threat = get_document("threat", threat_id)
    if threat is None:
        print(f"Threat {threat_id} not found.")
        return None
    print("Threat successfully retrieved from Firebase.")
    return threat


# ============================================================
# 10. BUILD THREAT TEXT
# ============================================================
# STEP 1 (Module 7 prep)
# ------------------------------------------------------------
# `Source` and `Source URL` are appended so Gemini sees them
# in the prompt. The AI is not required to echo them back —
# they are propagated separately by save_intelligence() below.
# ============================================================

def build_threat_text(threat):
    return f"""
Title:
{threat.get("title", "Unknown")}

Description:
{threat.get("description", "Unknown")}

Category:
{threat.get("category", "Unknown")}

Community:
{threat.get("community", "Unknown")}

Location:
{threat.get("location", "Unknown")}

Existing Severity:
{threat.get("severity", "Unknown")}

Source:
{threat.get("source", "Unknown")}

Source URL:
{threat.get("source_url", "Unknown")}
"""


# ============================================================
# 10b. EXTRACT SOURCE FIELDS  (STEP 1 — Module 7 prep)
# ============================================================
# Pulls `source` and `source_url` from a raw threat doc so
# they can be copied onto the saved intelligence doc.
#
# Both keys are optional. If the raw doc doesn't have them,
# both return None and the downstream doc gets None. Module 7
# treats None as "no source cited" and simply omits the
# attribution line in notifications.
# ============================================================

def _extract_source_fields(raw_threat):
    """
    Return (source, source_url) from a raw `threat` doc.

    Safe on any input: missing dict, missing keys, empty
    strings, non-string values. Never raises.
    """
    if not isinstance(raw_threat, dict):
        return (None, None)

    src = raw_threat.get("source")
    url = raw_threat.get("source_url")

    # Normalize whitespace / empties
    if isinstance(src, str):
        src = src.strip() or None
    else:
        src = None

    if isinstance(url, str):
        url = url.strip() or None
    else:
        url = None

    return (src, url)


# ============================================================
# 11. SAVE AI INTELLIGENCE
# ============================================================
# STEP 1 (Module 7 prep)
# ------------------------------------------------------------
# `source` and `source_url` are copied from the raw `threat`
# doc onto the saved intelligence doc.
#
# We use setdefault() so:
#   • first-time save       → copies from raw threat
#   • reprocess with source → keeps the fresh copy
#   • pre-existing value    → preserved (never overwritten by
#                             an empty raw field)
# ============================================================

def save_intelligence(threat_id, intelligence):
    intelligence["threat_id"] = threat_id
    intelligence["processed_at"] = (
        __import__("datetime")
        .datetime.now(__import__("datetime").timezone.utc)
        .isoformat()
    )

    # ========================================================
    # STEP 1 — Propagate source metadata from the raw threat
    # --------------------------------------------------------
    # Reads `threat/<id>` and copies `source` / `source_url`
    # onto the intelligence doc, unless already present.
    # ========================================================
    try:
        raw_threat = get_document("threat", threat_id)
    except Exception as e:
        print(f"  ⚠ Could not read threat/{threat_id} for source: {e}")
        raw_threat = None

    source, source_url = _extract_source_fields(raw_threat)

    # Only set when we actually have a value. This means:
    #   • raw has source    → intelligence gets it
    #   • raw is empty      → intelligence keeps whatever it
    #                         already had (or stays without)
    if source is not None:
        intelligence.setdefault("source", source)
    if source_url is not None:
        intelligence.setdefault("source_url", source_url)

    # ========================================================
    # STEP 11 — Initialize human-verification fields
    # --------------------------------------------------------
    # New AI output starts as "Needs Review". A human must
    # explicitly approve it via the dashboard before it is
    # treated as verified.
    #
    # Using setdefault() means these are only written the
    # FIRST time a threat is processed. If a threat has
    # already been manually verified and is reprocessed,
    # the existing verification state is preserved.
    # ========================================================
    intelligence.setdefault("verified", False)
    intelligence.setdefault("verified_by", None)
    intelligence.setdefault("verified_at", None)
    intelligence.setdefault("verification_note", "")
    intelligence.setdefault("verification_history", [])
    intelligence.setdefault(
        "original_ai_communities",
        intelligence.get("communities", []),
    )

    # Format the final output
    final_output = format_final_output(threat_id, intelligence)

    set_document("threat_intelligence", threat_id, final_output)
    print(f"AI intelligence saved for {threat_id}.")

    # Small confirmation line if we picked up a source
    if source or source_url:
        shown = source or source_url
        print(f"  ↳ Source recorded: {shown}")

    return final_output


# ============================================================
# 12. COMPLETE PIPELINE
# ============================================================

def process_threat(threat_id, force=False):
    """
    Process a single threat end-to-end.

    Args:
        threat_id: ID of the threat document in Firebase.
        force:     If True, reprocess even if the threat is
                   already marked as processed.
    """
    print()
    print("============================================")
    print("PROCESSING THREAT")
    print("============================================")
    print()
    print("Threat ID:", threat_id)

    # Get threat
    threat = get_threat(threat_id)
    if threat is None:
        return None

    # Check if already processed (unless --force)
    if threat.get("processed", False) and not force:
        print(f"Threat {threat_id} already processed. Skipping.")
        print("(Use --force to reprocess anyway.)")
        return {"skipped": True, "threat_id": threat_id}

    if threat.get("processed", False) and force:
        print(f"Threat {threat_id} already processed, but --force is set.")
        print("Reprocessing...")

    # Build text
    threat_text = build_threat_text(threat)
    print()
    print("Threat information:")
    print(threat_text)

    # Analyze with Gemini (Modules 1-4)
    intelligence = analyze_threat(threat_text)

    # ========================================================
    # MODULE 5 — THREAT SIMPLIFICATION
    # --------------------------------------------------------
    # Feed BOTH the raw threat text AND the analyzed
    # intelligence from Module 4 into the shared simplifier.
    #
    # Pass MODEL_CANDIDATES (the full priority list) so the
    # simplifier walks the same fallback chain as Module 2.
    # Previously only MODEL_NAME was passed, which meant a
    # single 503 on the primary model caused Module 5 to
    # give up even though other models were available.
    # ========================================================

    simplification_input = build_simplification_input(
        threat_text,
        intelligence,
    )

    try:
        simplified = simplifier.simplify_with_ai(
            simplification_input,
            client,
            MODEL_CANDIDATES,
        )
    except Exception as e:
        print(f"Module 5 failed: {e}")
        print("Using rule-based fallback for simplified block")
        simplified = simplifier._rule_based_block(intelligence)

    # Attach the simplified block to the intelligence object
    intelligence["simplified"] = simplified

    # Save intelligence (validation.py persists `simplified`,
    # save_intelligence() initializes verification fields and
    # propagates source metadata)
    final_output = save_intelligence(threat_id, intelligence)

    # Mark as processed
    threat["processed"] = True
    set_document("threat", threat_id, threat)
    print(f"Marked threat {threat_id} as processed.")

    return final_output


# ============================================================
# 13. MAIN
# ============================================================

if __name__ == "__main__":
    print("\n================================")
    print("TRINETRA AI THREAT PROCESSING")
    print("================================")

    # Process every unprocessed threat in the `threat` collection.
    threats = list_documents("threat") or {}

    if not threats:
        print("No threats found in Firebase.")
    else:
        for threat_id, threat in threats.items():
            if isinstance(threat, dict) and threat.get("processed", False):
                print(f"Skipping already processed threat: {threat_id}")
                continue

            try:
                process_threat(threat_id)
            except Exception as e:
                print(f"Failed to process threat {threat_id}: {e}")

    print("\n================================")
    print("TRINETRA AI THREAT PROCESSING COMPLETE")
    print("================================")