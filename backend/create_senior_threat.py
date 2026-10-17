# ============================================================
# DEMO DATA — senior-citizen-targeted threats
# ============================================================
# Run:
#   python create_senior_threat.py
#
# Creates three threats that match community = "Senior Citizens".
# ============================================================

from firebase_rest import set_document


THREATS = {
    "t_fake_pension_call": {
        "threat_id":     "t_fake_pension_call",
        "threat_type":   "Financial Fraud",
        "severity":      "High",
        "region":        "Karnataka",
        "communities":   ["Senior Citizens"],
        "target":        ["Senior Citizens"],
        "platform":      ["Phone Call"],
        "keywords":      ["pension", "verification", "phone call", "OTP"],
        "indicators":    [
            "Caller claims to be from the pension department",
            "Asks to verify bank account or Aadhaar details",
            "Creates urgency about a stopped pension",
        ],
        "recommended_actions": [
            "Hang up and call the pension office on its official number",
            "Never share OTP, PIN, or bank details over the phone",
            "Report the call to the cybercrime helpline",
        ],
        "verified":      True,
        "verified_by":   "admin",
        "processed_at":  "2026-09-23T15:00:00+00:00",
        "simplified": {
            "title":             "Fake Pension Call",
            "what_happened":     "Scammers call senior citizens pretending to be from the pension department and ask for bank or Aadhaar details.",
            "who_is_affected":   ["Senior Citizens"],
            "how_attack_works":  "The caller claims your pension is blocked and asks you to 'verify' your bank account by sharing an OTP, PIN, or card details.",
            "how_to_identify": [
                "Caller says your pension is blocked and must be fixed today",
                "Caller asks for OTP, PIN, or full bank account details",
                "Caller refuses to give an official call-back number",
            ],
            "what_to_do": [
                "Hang up immediately and do not share any details",
                "Call the pension office on its official number to verify",
                "Report the call to cybercrime.gov.in or 1930",
            ],
            "safety_tip":  "Banks never ask for your OTP.",
            "ai_used":     True,
            "ai_model":    "demo",
        },
    },

    "t_bank_kyc_scam": {
        "threat_id":     "t_bank_kyc_scam",
        "threat_type":   "Phishing",
        "severity":      "High",
        "region":        "India",
        "communities":   ["Senior Citizens"],
        "target":        ["Senior Citizens"],
        "platform":      ["Phone Call", "SMS"],
        "keywords":      ["KYC", "bank account", "blocked", "OTP"],
        "indicators":    [
            "Message or call says your bank account will be blocked",
            "Asks you to click a link to complete KYC",
            "Requests Aadhaar or PAN details on the call",
        ],
        "recommended_actions": [
            "Never click KYC links from unknown SMS",
            "Visit your bank branch in person for any KYC update",
            "Report the message to your bank and cybercrime helpline",
        ],
        "verified":      True,
        "verified_by":   "admin",
        "processed_at":  "2026-09-23T14:30:00+00:00",
        "simplified": {
            "title":             "Bank KYC Scam",
            "what_happened":     "Scammers send fake KYC messages or calls claiming your bank account will be blocked unless you act immediately.",
            "who_is_affected":   ["Senior Citizens"],
            "how_attack_works":  "They ask you to click a link or share Aadhaar and OTP details, then use those to withdraw money from your account.",
            "how_to_identify": [
                "Message threatens your account will be blocked today",
                "Link looks almost like your bank's website but not quite",
                "Caller asks for Aadhaar, PAN, or OTP over the phone",
            ],
            "what_to_do": [
                "Do not click any KYC link from SMS or email",
                "Visit your bank branch in person for KYC",
                "Call your bank's official customer care number to confirm",
            ],
            "safety_tip":  "Banks never ask for your OTP.",
            "ai_used":     True,
            "ai_model":    "demo",
        },
    },

    "t_fake_customer_care": {
        "threat_id":     "t_fake_customer_care",
        "threat_type":   "Social Engineering",
        "severity":      "Medium",
        "region":        "India",
        "communities":   ["Senior Citizens"],
        "target":        ["Senior Citizens"],
        "platform":      ["Phone Call"],
        "keywords":      ["customer care", "support", "remote access"],
        "indicators":    [
            "Caller claims to be from customer care",
            "Asks you to install a remote-access app",
            "Wants you to read out a code from your phone",
        ],
        "recommended_actions": [
            "Never install remote-access apps at a caller's request",
            "Hang up and call the company on its official number",
            "Report the call to the cybercrime helpline",
        ],
        "verified":      True,
        "verified_by":   "admin",
        "processed_at":  "2026-09-23T14:00:00+00:00",
        "simplified": {
            "title":             "Fake Customer Care",
            "what_happened":     "Scammers call pretending to be customer care and ask seniors to install apps that give them control of the phone.",
            "who_is_affected":   ["Senior Citizens"],
            "how_attack_works":  "They ask you to install a remote-access app like AnyDesk or TeamViewer, then transfer money from your phone while you watch.",
            "how_to_identify": [
                "Caller asks you to install an app you've never heard of",
                "Caller asks you to read out a code shown on your screen",
                "Caller says they need to 'check' your phone for a problem",
            ],
            "what_to_do": [
                "Never install any app a caller asks you to install",
                "Hang up and call the company's official customer care",
                "Ask a family member before acting on any such call",
            ],
            "safety_tip":  "No real customer care will ask you to install a remote-access app.",
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
    print("Senior citizen threats created.")
    print("Log in as ramesh@example.com / password123")


if __name__ == "__main__":
    main()