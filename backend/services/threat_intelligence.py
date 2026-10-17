# ============================================================
# TRINETRA — THREAT INTELLIGENCE ENTRY POINT
# ============================================================
# This module serves as the main entry point for the
# TRINETRA AI threat intelligence pipeline.
#
# It loads the Gemini API key, verifies the environment,
# and provides a runnable demonstration of the complete
# pipeline (analyze_threat -> simplify_threat -> save).
#
# The final Firebase document stored under
# `threat_intelligence/{threat_id}` now includes the
# Module 5 `simplified` field for ordinary users.
# ============================================================

import os
import json

from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

if api_key:
    print("Gemini API key loaded successfully!")
else:
    print("Gemini API key NOT found!")


# ============================================================
# OPTIONAL — RUN THE FULL PIPELINE
# ============================================================
# Import the pipeline functions from ai_engine.
# These are only imported when this file is executed directly
# so that importing threat_intelligence as a module does not
# trigger Firebase / Gemini calls.
# ============================================================

def run_pipeline(threat_id=None):
    """
    Run the full TRINETRA pipeline.

    If `threat_id` is provided, only that threat is processed.
    Otherwise, every unprocessed threat in Firebase is processed.
    """
    from ai_engine import process_threat
    from firebase_rest import list_documents

    if threat_id:
        print(f"\nProcessing single threat: {threat_id}")
        return process_threat(threat_id)

    print("\nScanning Firebase for unprocessed threats...")
    threats = list_documents("threat") or {}

    if not threats:
        print("No threats found in Firebase.")
        return {}

    results = {}
    for tid, threat in threats.items():
        if isinstance(threat, dict) and threat.get("processed", False):
            print(f"Skipping already processed threat: {tid}")
            continue
        try:
            results[tid] = process_threat(tid)
        except Exception as e:
            print(f"Failed to process threat {tid}: {e}")
            results[tid] = {"error": str(e)}

    return results


# ============================================================
# EXAMPLE — FINAL FIREBASE DOCUMENT SHAPE
# ============================================================
# After the pipeline runs, each document stored under
# `threat_intelligence/{threat_id}` will look like this.
#
# This is the canonical structure that downstream services
# (dashboards, notification systems, public-facing apps)
# should expect to consume.
# ============================================================

EXAMPLE_FINAL_DOCUMENT = {
    "threat_type": "Job Scam",
    "target": ["Students"],
    "platform": ["Email", "Social Media"],
    "severity": "Medium",
    "region": "India",
    "keywords": ["job offer", "registration fee", "work from home"],
    "indicators": ["Unsolicited job offer", "Upfront payment request"],
    "recommended_actions": [
        "Verify the job through official sources",
        "Do not pay any registration fee",
        "Report the offer to cybercrime.gov.in"
    ],
    "communities": ["Students"],

    # --------------------------------------------------------
    # MODULE 5 — Simplified explanation for ordinary users
    # --------------------------------------------------------
    "simplified": {
        "what_happened":
            "Scammers are posting fake job opportunities.",
        "who_is_affected": ["Students"],
        "how_attack_works":
            "The scammer posts a fake job and asks the student "
            "to provide personal information or pay a fee.",
        "how_to_identify": [
            "Unexpected job offers",
            "Requests for registration fees",
            "Suspicious websites"
        ],
        "what_to_do": [
            "Verify the employer",
            "Do not pay unknown recruiters",
            "Do not share sensitive information"
        ]
    },

    # --------------------------------------------------------
    # Community classification metadata
    # --------------------------------------------------------
    "community_confidence": {"Students": 0.85},
    "classification_method": "AI + Rule-Based Hybrid",
    "community_reason": "Matched job-related keywords for Students",
    "matched_keywords": {
        "Students": ["job offer", "internship", "registration fee"]
    },
    "community_reasons": {
        "Students": "Detected keywords: job offer, registration fee"
    },

    # --------------------------------------------------------
    # Metadata
    # --------------------------------------------------------
    "threat_id": "example_threat_001",
    "processed_at": "2026-09-12T10:00:00+00:00"
}


def print_example_document():
    """Pretty-print the canonical final document shape."""
    print("\n================================")
    print("EXAMPLE FINAL FIREBASE DOCUMENT")
    print("================================\n")
    print(json.dumps(EXAMPLE_FINAL_DOCUMENT, indent=4))


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print("\n================================")
    print("TRINETRA THREAT INTELLIGENCE")
    print("================================")

    # Show the canonical output structure that Firebase will store.
    print_example_document()

    # --------------------------------------------------------
    # Uncomment ONE of the following to actually run the pipeline:
    # --------------------------------------------------------
    #
    # Process every unprocessed threat in Firebase:
    # run_pipeline()
    #
    # Or process a single threat by ID:
    # run_pipeline("your_threat_id_here")
    #
    # --------------------------------------------------------

    print("\nPipeline demonstration complete.")
    print("Uncomment run_pipeline(...) to execute live processing.")