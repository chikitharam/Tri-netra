# ============================================================
# TEST COMMUNITY CLASSIFIER
# ============================================================
# Test suite for the community classifier.

from community_classifier import (
    classify_by_keywords,
    hybrid_classification,
    get_rule_based_communities,
    get_rule_based_communities_threshold,
    get_matched_keywords,
    normalize_community,
    VALID_COMMUNITIES
)


def run_test(test_name, threat_text, expected_communities, min_score=2):
    """Run a single test case."""
    print("=" * 60)
    print(f"TEST: {test_name}")
    print("=" * 60)
    print()
    print("Threat Text:", threat_text.strip())
    print()

    # Keyword scores
    scores = classify_by_keywords(threat_text)
    print("Keyword Scores:")
    for community, score in scores.items():
        print(f"  {community}: {score}")
    print()

    # Matched keywords
    print("Matched Keywords:")
    for community in VALID_COMMUNITIES:
        matched = get_matched_keywords(threat_text, community)
        if matched:
            print(f"  {community}: {matched}")
    print()

    # Rule-based communities
    rule_communities = get_rule_based_communities(scores)
    print(f"Rule-based communities (score > 0): {rule_communities}")
    rule_communities_threshold = get_rule_based_communities_threshold(scores, min_score=min_score)
    print(f"Rule-based communities (score >= {min_score}): {rule_communities_threshold}")
    print()

    # Hybrid classification
    final, confidence, reason, decisions, community_confidence, matched_keywords = hybrid_classification(
        threat_text, expected_communities
    )

    print("Hybrid Classification:")
    print(f"  Expected: {expected_communities}")
    print(f"  Final: {final}")
    print(f"  Confidence: {confidence}")
    print(f"  Reason: {reason}")
    print(f"  Decisions: {decisions}")
    print(f"  Community Confidence: {community_confidence}")
    print()

    # Verification
    normalized_expected = set()
    for comm in expected_communities:
        norm = normalize_community(comm)
        if norm:
            normalized_expected.add(norm)

    normalized_actual = set(final)

    if normalized_expected == normalized_actual:
        print("✅ PASSED")
    else:
        print("❌ FAILED")
        print(f"  Expected: {normalized_expected}")
        print(f"  Actual: {normalized_actual}")

    print()
    print("-" * 60)
    print()

    return normalized_expected == normalized_actual


def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("COMMUNITY CLASSIFIER TESTS")
    print("=" * 60)
    print()

    passed = 0
    total = 0

    # Test 1: Student
    total += 1
    result1 = run_test(
        "Test 1: Student Community",
        "Fake internship website asking college students to pay a registration fee.",
        ["Students"]
    )
    if result1:
        passed += 1

    # Test 2: Senior Citizen
    total += 1
    result2 = run_test(
        "Test 2: Senior Citizen Community",
        "Caller claims to be from the pension department and asks senior citizens to share their bank details.",
        ["Senior Citizens"]
    )
    if result2:
        passed += 1

    # Test 3: Small Business
    total += 1
    result3 = run_test(
        "Test 3: Small Business Community",
        "Attackers send fake invoices to small businesses and demand payment.",
        ["Small Businesses"]
    )
    if result3:
        passed += 1

    # Test 4: Multi-Community (Student + Small Business)
    total += 1
    result4 = run_test(
        "Test 4: Multi-Community (Student + Small Business)",
        "Fake internship offers and ransomware attacks targeting students and small businesses.",
        ["Students", "Small Businesses"]
    )
    if result4:
        passed += 1

    # Test 5: Multi-Community (Student + Senior)
    total += 1
    result5 = run_test(
        "Test 5: Multi-Community (Student + Senior)",
        "Scholarship scams and pension fraud targeting both college students and senior citizens.",
        ["Students", "Senior Citizens"]
    )
    if result5:
        passed += 1

    # Test 6: Multi-Community (All three)
    total += 1
    result6 = run_test(
        "Test 6: Multi-Community (All three)",
        "Fake scholarship scams for students, pension fraud for senior citizens, and ransomware attacks on small businesses.",
        ["Students", "Senior Citizens", "Small Businesses"]
    )
    if result6:
        passed += 1

    # Test 7: General Public
    total += 1
    result7 = run_test(
        "Test 7: General Public",
        "A new type of fraud is circulating online. Users are advised to be careful.",
        ["General Public"]
    )
    if result7:
        passed += 1

    # Test 8: Complex Multi-Community
    total += 1
    result8 = run_test(
        "Test 8: Complex Multi-Community",
        "Fake job offers on WhatsApp targeting college students, with pension verification scams targeting elderly, and invoice fraud affecting small businesses.",
        ["Students", "Senior Citizens", "Small Businesses"]
    )
    if result8:
        passed += 1

    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"  Total Tests: {total}")
    print(f"  Passed: {passed}")
    print(f"  Failed: {total - passed}")
    print(f"  Success Rate: {passed/total*100:.1f}%")
    print("=" * 60)

    if passed == total:
        print("\n✅ ALL TESTS PASSED!")
    else:
        print(f"\n⚠️ {total - passed} test(s) failed.")


if __name__ == "__main__":
    main()