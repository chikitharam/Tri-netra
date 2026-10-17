# ============================================================
# VALIDATION
# ============================================================
# This file handles validation of AI output, communities,
# and required fields.

from community_rules import VALID_COMMUNITIES
from community_classifier import normalize_community, validate_communities


def validate_ai_output(result):
    """
    Validate and normalize the complete AI output.
    Ensures all required fields exist and are valid.
    """
    required_fields = [
        "threat_type",
        "target",
        "platform",
        "severity",
        "region",
        "keywords",
        "indicators",
        "recommended_actions",
        "communities"
    ]

    # Fill missing fields
    for field in required_fields:
        if field not in result:
            if field in ["target", "platform", "keywords", "indicators", "recommended_actions", "communities"]:
                result[field] = []
            else:
                result[field] = "Unknown"

    # Validate communities
    if "communities" in result:
        result["communities"] = validate_communities(result["communities"])
    else:
        result["communities"] = ["General Public"]

    # Ensure target is valid (sync with communities)
    result["target"] = validate_communities(result.get("target", []))
    if not result["target"]:
        result["target"] = ["General Public"]

    # Validate region
    region = result.get("region", "")
    if not isinstance(region, str) or region.strip() == "":
        result["region"] = "Unknown"

    # Ensure list fields are lists
    for field in ["platform", "keywords", "indicators", "recommended_actions"]:
        if not isinstance(result.get(field), list):
            result[field] = []

    # Validate severity
    allowed_severity = ["Low", "Medium", "High", "Critical"]
    if result.get("severity") not in allowed_severity:
        result["severity"] = "Medium"

    return result


def validate_threat_input(threat_data):
    """
    Validate raw threat input from Firebase.
    """
    required_fields = ["title", "description", "category", "community", "location"]
    missing = []

    for field in required_fields:
        if not threat_data.get(field):
            missing.append(field)

    return {
        "valid": len(missing) == 0,
        "missing_fields": missing
    }


def format_final_output(threat_id, intelligence):
    """
    Format the final threat intelligence output in the standard
    Trinetra JSON structure.
    """
    communities = intelligence.get("communities", ["General Public"])
    confidence_scores = intelligence.get("community_confidence_scores", {})

    community_confidence = {}
    for community in communities:
        community_confidence[community] = confidence_scores.get(community, 0.0)

    return {
        "threat_type": intelligence.get("threat_type", "Unknown"),
        "target": intelligence.get("target", ["General Public"]),
        "platform": intelligence.get("platform", []),
        "severity": intelligence.get("severity", "Medium"),
        "region": intelligence.get("region", "Unknown"),
        "keywords": intelligence.get("keywords", []),
        "indicators": intelligence.get("indicators", []),
        "recommended_actions": intelligence.get("recommended_actions", []),
        "communities": communities,

        # MODULE 5 — Simplified threat explanation
        "simplified": intelligence.get("simplified", {}),

        "community_confidence": community_confidence,
        "classification_method": "AI + Rule-Based Hybrid",
        "community_reason": intelligence.get(
            "community_reason",
            "No reason provided"
        ),
        "matched_keywords": intelligence.get(
            "matched_keywords",
            {}
        ),
        "community_reasons": intelligence.get(
            "community_reasons",
            {}
        ),
        "threat_id": threat_id,
        "processed_at": intelligence.get("processed_at", "")
    }