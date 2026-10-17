# ============================================================
# COMMUNITY CLASSIFIER
# ============================================================
# This file handles rule-based classification, AI + rule
# combination, confidence calculation, and matched keyword
# detection.

from community_rules import (
    COMMUNITY_KEYWORDS,
    VALID_COMMUNITIES,
    COMMUNITY_ALIASES
)


def normalize_community(name):
    """Convert a community name to its canonical form."""
    if not name:
        return None
    name = name.strip()
    if name in VALID_COMMUNITIES:
        return name
    if name in COMMUNITY_ALIASES:
        return COMMUNITY_ALIASES[name]
    name_lower = name.lower()
    for comm in VALID_COMMUNITIES:
        if comm.lower() == name_lower:
            return comm
    return None


def validate_communities(ai_communities):
    """Validate and sanitize AI-predicted communities."""
    if not isinstance(ai_communities, list):
        return []

    valid = []
    for community in ai_communities:
        norm = normalize_community(community)
        if norm:
            valid.append(norm)

    seen = set()
    unique_valid = []
    for comm in valid:
        if comm not in seen:
            seen.add(comm)
            unique_valid.append(comm)

    return unique_valid


def classify_by_keywords(text):
    """
    Score each community based on weighted keyword matches.
    
    Returns:
        dict: Community → weighted score mapping
    """
    if not text:
        return {comm: 0 for comm in VALID_COMMUNITIES}

    text_lower = text.lower()
    scores = {}

    for community, weighted_keywords in COMMUNITY_KEYWORDS.items():
        total_score = 0
        for keyword, weight in weighted_keywords.items():
            if keyword.lower() in text_lower:
                total_score += weight
        scores[community] = total_score

    return scores


def get_matched_keywords(text, community):
    """Get all keywords that matched for a specific community."""
    community = normalize_community(community)
    if not community:
        return []

    text_lower = text.lower()
    matched = []

    keywords = COMMUNITY_KEYWORDS.get(community, {})
    for keyword in keywords.keys():
        if keyword.lower() in text_lower:
            matched.append(keyword)

    return matched


def calculate_confidence(score):
    """
    Calculate rule-based confidence score.
    
    This is NOT machine-learning probability.
    It's a heuristic based on keyword evidence strength.
    """
    if score >= 6:
        return 0.95
    elif score >= 4:
        return 0.85
    elif score >= 2:
        return 0.70
    elif score >= 1:
        return 0.55
    return 0.0


def hybrid_classification(text, ai_communities):
    """
    Enhanced hybrid classification with decision matrix.
    
    Decision Logic:
    1. If AI says YES and rules say YES (score > 0) → INCLUDE
    2. If rules say STRONG (score >= 3) → INCLUDE (override)
    3. If AI says YES and rules say NO (score = 0) → INCLUDE (low confidence)
    4. If rules say WEAK (score 1-2) and AI says NO → EXCLUDE
    
    Returns:
        tuple: (final_communities, confidence, reason, decisions, community_confidence, matched_keywords)
    """
    # Normalize AI communities
    if not isinstance(ai_communities, list):
        ai_communities = []

    normalized_ai = set()
    for comm in ai_communities:
        norm = normalize_community(comm)
        if norm:
            normalized_ai.add(norm)

    # Get rule scores
    scores = classify_by_keywords(text)

    # Get community confidence
    community_confidence = {}
    for community in VALID_COMMUNITIES:
        rule_score = scores.get(community, 0)
        community_confidence[community] = calculate_confidence(rule_score)

    # Get matched keywords
    matched_keywords = {}
    for community in VALID_COMMUNITIES:
        matched = get_matched_keywords(text, community)
        if matched:
            matched_keywords[community] = matched

    # Decision Matrix
    final = []
    decisions = {}
    rule_matches = 0
    ai_matches = 0
    strong_rule_matches = 0

    for community in VALID_COMMUNITIES:
        ai_match = community in normalized_ai
        rule_score = scores.get(community, 0)

        if ai_match and rule_score > 0:
            final.append(community)
            decisions[community] = f"AI + Rules agree (score: {rule_score})"
            ai_matches += 1
            rule_matches += 1
            if rule_score >= 3:
                strong_rule_matches += 1
        elif rule_score >= 3:
            final.append(community)
            decisions[community] = f"Strong rule evidence (score: {rule_score})"
            rule_matches += 1
            strong_rule_matches += 1
        elif ai_match:
            final.append(community)
            decisions[community] = f"AI prediction only (score: {rule_score})"
            ai_matches += 1
        else:
            decisions[community] = f"No evidence (score: {rule_score})"

    if not final:
        final = ["General Public"]
        decisions["General Public"] = "Fallback (no evidence)"
        community_confidence["General Public"] = 0.0
        if "General Public" not in matched_keywords:
            matched_keywords["General Public"] = ["fallback"]

    # Determine overall confidence
    if ai_matches > 0 and rule_matches > 0:
        overlap = len(set(final) & normalized_ai)
        if overlap == len(normalized_ai) and overlap == len([c for c in final if scores.get(c, 0) > 0]):
            overall_confidence = "High"
            reason = "Strong agreement between AI and rules."
        elif overlap > 0:
            overall_confidence = "Medium"
            reason = "Partial agreement between AI and rules."
        else:
            overall_confidence = "Low"
            reason = "Disagreement between AI and rules; using rule overrides."
    elif ai_matches > 0 and rule_matches == 0:
        overall_confidence = "Low"
        reason = "AI prediction only; no rule-based verification."
    elif ai_matches == 0 and rule_matches > 0:
        if strong_rule_matches > 0:
            overall_confidence = "Medium"
            reason = "Rule-based prediction with strong evidence; AI provided no prediction."
        else:
            overall_confidence = "Low"
            reason = "Weak rule-based prediction only; AI provided no prediction."
    else:
        overall_confidence = "Low"
        reason = "Fallback used; no AI or rule evidence."

    return final, overall_confidence, reason, decisions, community_confidence, matched_keywords


def get_rule_based_communities(scores):
    """Convert scores to communities (score > 0)."""
    communities = []
    for community, score in scores.items():
        if score > 0:
            communities.append(community)
    return communities


def get_rule_based_communities_threshold(scores, min_score=1):
    """Convert scores to communities (score >= min_score)."""
    communities = []
    for community, score in scores.items():
        if score >= min_score:
            communities.append(community)
    return communities


def get_top_communities(text, min_score=1, top_n=None):
    """Get top-scoring communities."""
    scores = classify_by_keywords(text)
    filtered = [(comm, score) for comm, score in scores.items() if score >= min_score]
    filtered.sort(key=lambda x: x[1], reverse=True)

    if top_n:
        filtered = filtered[:top_n]

    return [comm for comm, _ in filtered]