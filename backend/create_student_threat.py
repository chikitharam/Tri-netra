# ============================================================
# DEMO DATA — student-targeted threats
# ============================================================
# Run:
#   python create_student_threat.py
#
# Creates two threats that match community = "Students".
# ============================================================

from firebase_rest import set_document


THREATS = {
    "t_internship_scam": {
        "threat_id":     "t_internship_scam",
        "threat_type":   "Job Scam",
        "severity":      "High",
        "region":        "Karnataka",
        "communities":   ["Students"],
        "target":        ["Students"],
        "platform":      ["WhatsApp"],
        "keywords":      ["internship", "registration fee", "WhatsApp"],
        "indicators":    [
            "Asks for a fee before the interview",
            "Offers internship without any screening",
        ],
        "recommended_actions": [
            "Never pay a fee to get an internship",
            "Verify the company on its official website",
            "Report the WhatsApp message to the cybercrime helpline",
        ],
        "verified":      True,
        "verified_by":   "admin",
        "processed_at":  "2026-09-23T14:00:00+00:00",
        "simplified": {
            "title":             "Fake Internship Scam",
            "what_happened":     "Scammers contact students on WhatsApp with a fake internship offer and demand a registration fee.",
            "who_is_affected":   ["Students"],
            "how_attack_works":  "They send an offer letter, ask for a small 'registration' or 'kit' fee, then disappear once you pay.",
            "how_to_identify": [
                "You are offered an internship without any real interview",
                "You are asked to pay a fee before joining",
                "All communication happens on WhatsApp only",
            ],
            "what_to_do": [
                "Never pay money for an internship",
                "Verify the company on its official website",
                "Report the number to cybercrime.gov.in",
            ],
            "safety_tip":  "Never share OTP for internship verification.",
            "ai_used":     True,
            "ai_model":    "demo",
        },
    },

    "t_scholarship_site": {
        "threat_id":     "t_scholarship_site",
        "threat_type":   "Phishing",
        "severity":      "Medium",
        "region":        "India",
        "communities":   ["Students"],
        "target":        ["Students"],
        "platform":      ["Website"],
        "keywords":      ["scholarship", "registration", "fake website"],
        "indicators":    [
            "Website asks for bank details to 'deposit' the scholarship",
            "Domain uses typos of known scholarship portals",
        ],
        "recommended_actions": [
            "Apply only on official government scholarship portals",
            "Never enter bank details on unverified websites",
            "Report the fake site to the cybercrime helpline",
        ],
        "verified":      True,
        "verified_by":   "admin",
        "processed_at":  "2026-09-23T13:00:00+00:00",
        "simplified": {
            "title":             "Fake Scholarship Website",
            "what_happened":     "A fake website is impersonating a government scholarship portal to steal students' bank details.",
            "who_is_affected":   ["Students"],
            "how_attack_works":  "The site looks like a real scholarship page, collects your details, then asks for bank info to 'deposit' the award.",
            "how_to_identify": [
                "The URL has a small spelling mistake vs the official site",
                "You are asked for bank details before any award is confirmed",
                "The page pressures you to apply 'before the deadline today'",
            ],
            "what_to_do": [
                "Apply only through official government portals",
                "Never enter bank details to 'receive' a scholarship",
                "Report the fake site to cybercrime.gov.in",
            ],
            "safety_tip":  "Check the URL twice before entering any personal details.",
            "ai_used":     True,
            "ai_model":    "demo",
        },
    },
}


def main():
    for tid, doc in THREATS.items():
        set_document("threat_intelligence", tid, doc)
        print(f"✓ threat_intelligence/{tid}  ({doc['severity']})")

    print()
    print("Student threats created. Log in as chikitha@example.com.")


if __name__ == "__main__":
    main()