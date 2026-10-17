# ============================================================
# SEED RAW THREATS
# ============================================================
# Populates the `threat` collection with sample threats.
# After seeding, run:
#
#     python main.py --process t_job_scam --force
#     python main.py --process t_scholarship --force
#     python main.py --process t_pension --force
#     ... etc
#
# Or process them all in one go with:
#
#     python seed_threats.py --process
#
# Safe to re-run: it overwrites the same documents.
# ============================================================

import sys

from firebase_rest import set_document


# ------------------------------------------------------------
# Raw threats
# ------------------------------------------------------------
# Structure: {id: {title, description, category, community, location}}
#
# The description is what Gemini reads. Make it realistic.
# ------------------------------------------------------------
DEMO_THREATS = {

    # ---------- STUDENTS ----------
    "t_job_scam": {
        "title": "Fake Internship Scam",
        "description": (
            "Scammers are posting fake internship advertisements on "
            "WhatsApp groups and Instagram, claiming to be from well-known "
            "companies like Infosys and TCS. They ask students to pay a "
            "registration fee of Rs 2000 and share Aadhaar, PAN and bank "
            "details to 'confirm the internship'. No internship is ever "
            "provided and the money is never returned."
        ),
        "category": "Job Scam",
        "community": "Students",
        "location": "Tamil Nadu",
    },

    "t_scholarship": {
        "title": "Fake Scholarship Website",
        "description": (
            "Fraudulent websites mimicking the National Scholarship Portal "
            "are tricking students into entering their personal information, "
            "bank account details and OTPs. The sites look nearly identical "
            "to the official government portal and rank high in search "
            "results during scholarship season."
        ),
        "category": "Phishing",
        "community": "Students",
        "location": "India",
    },

    # ---------- SENIOR CITIZENS ----------
    "t_pension": {
        "title": "Fake Pension Verification Call",
        "description": (
            "Scammers are calling senior citizens and impersonating pension "
            "officials from the EPFO. They claim the pension account needs "
            "urgent KYC verification and ask for Aadhaar number, bank account "
            "details and OTP to 'prevent the pension from being stopped'."
        ),
        "category": "Social Engineering",
        "community": "Senior Citizens",
        "location": "Maharashtra",
    },

    "t_mediclaim": {
        "title": "Fake Mediclaim Refund Scam",
        "description": (
            "Elderly citizens receive phone calls claiming a mediclaim "
            "refund of Rs 15,000 is pending from their insurance company. "
            "The caller asks them to install a remote-access app to 'process "
            "the refund' and then drains the bank account."
        ),
        "category": "Financial Fraud",
        "community": "Senior Citizens",
        "location": "Karnataka",
    },

    # ---------- SMALL BUSINESSES ----------
    "t_gst": {
        "title": "Fake GST Refund Notice",
        "description": (
            "Small business owners are receiving fake emails claiming a GST "
            "refund is pending. The email has an attachment that installs "
            "ransomware when opened, encrypting all accounting files and "
            "demanding payment in Bitcoin to restore access."
        ),
        "category": "Ransomware",
        "community": "Small Businesses",
        "location": "Delhi",
    },

    "t_invoice": {
        "title": "Fake Vendor Invoice Fraud",
        "description": (
            "Attackers impersonate regular suppliers and send fraudulent "
            "invoices with updated bank account details to small businesses. "
            "The shop owners transfer payment to the attacker's account "
            "believing it is a legitimate supplier payment."
        ),
        "category": "Financial Fraud",
        "community": "Small Businesses",
        "location": "Gujarat",
    },

    # ---------- GENERAL PUBLIC ----------
    "t_upi": {
        "title": "UPI Collect Request Scam",
        "description": (
            "Scammers are sending UPI 'collect money' requests to ordinary "
            "users, telling them it is a refund. When the user approves the "
            "request thinking they will receive money, the amount is actually "
            "debited from their account."
        ),
        "category": "Financial Fraud",
        "community": "General Public",
        "location": "India",
    },

    "t_kyc": {
        "title": "Fake Bank KYC Update",
        "description": (
            "Users across India are receiving SMS messages claiming their "
            "bank account will be frozen unless they update KYC immediately. "
            "The link leads to a fake banking page that harvests login "
            "credentials and OTPs, leading to account takeover."
        ),
        "category": "Phishing",
        "community": "General Public",
        "location": "India",
    },
}


# ------------------------------------------------------------
# Seeding
# ------------------------------------------------------------
def seed():
    print("=" * 70)
    print("SEEDING RAW THREATS INTO `threat` COLLECTION")
    print("=" * 70)
    print()

    for threat_id, data in DEMO_THREATS.items():
        doc = {
            "title":       data["title"],
            "description": data["description"],
            "category":    data["category"],
            "community":   data["community"],
            "location":    data["location"],
            "processed":   False,   # important — ai_engine checks this
        }
        set_document("threat", threat_id, doc)
        print(f"  ✓ threat/{threat_id:20s}  → {data['title']}")

    print()
    print(f"Done. {len(DEMO_THREATS)} raw threats seeded.")
    print()
    print("Next steps:")
    print("  python seed_threats.py --process      (process all)")
    print("  OR")
    print("  python main.py --process <id> --force (process one)")


# ------------------------------------------------------------
# Optional: process them all in one go
# ------------------------------------------------------------
def process_all():
    print()
    print("=" * 70)
    print("PROCESSING ALL THREATS THROUGH MODULES 1–5")
    print("=" * 70)

    from ai_engine import process_threat

    for threat_id in DEMO_THREATS.keys():
        print()
        print(f"--- {threat_id} ---")
        try:
            process_threat(threat_id, force=True)
        except Exception as e:
            print(f"  ✗ Failed to process {threat_id}: {e}")

    print()
    print("=" * 70)
    print("PROCESSING COMPLETE")
    print("=" * 70)


# ------------------------------------------------------------
# Entry point
# ------------------------------------------------------------
if __name__ == "__main__":
    seed()

    if "--process" in sys.argv:
        process_all()