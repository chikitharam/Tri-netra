from flask import Flask, jsonify

from firebase_rest import get_document, set_document
from ai_engine import simplify_threat, build_threat_text


app = Flask(__name__)


# ==========================================
# HOME ROUTE
# ==========================================

@app.route("/")
def home():
    return "TRINETRA Threat Intelligence Engine Running"


# ==========================================
# ANALYZE ONE THREAT
# ==========================================

@app.route("/analyze/<threat_id>")
def analyze(threat_id):
    print(f"Analyzing threat: {threat_id}")

    # 1. Get threat from Firebase REST
    threat = get_document("threat", threat_id)

    if threat is None:
        return jsonify({"error": "Threat not found"}), 404

    # 2. Check if already processed
    if threat.get("processed", False):
        return jsonify({
            "message": "Threat already processed",
            "threat_id": threat_id
        })

    # 3. Build the text prompt
    threat_text = build_threat_text(threat)

    # 4. Send to Gemini (with built‑in retries)
    try:
        result = simplify_threat(threat_text)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    # 5. Save AI intelligence back to Firestore
    set_document("threat_intelligence", threat_id, result)

    # 6. Mark the threat as processed (update the original threat document)
    threat["processed"] = True
    set_document("threat", threat_id, threat)

    # 7. Return JSON
    return jsonify(result)


# ==========================================
# RUN SERVER
# ==========================================

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)