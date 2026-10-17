# ============================================================
# TRINETRA DASHBOARD (MODULE 13)
# ============================================================
# Admin console + manual verification + Module 6 personalized
# user dashboard + static frontend server + Module 9 chatbot
# + Module 10 threat reporting + User Registration
# + Module 11 Helpline support + Module 12 Notifications
# + Module 13 Admin Dashboard.
# ============================================================

import os
import datetime

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
    send_from_directory,
)
from werkzeug.security import check_password_hash, generate_password_hash

from firebase_rest import (
    get_document,
    set_document,
    list_documents,
    delete_document,
)
from community_classifier import VALID_COMMUNITIES, normalize_community
from user_dashboard import UserDashboardBuilder
from chatbot_engine import ChatbotEngine


app = Flask(__name__)

app.secret_key = "trinetra-dev-secret-change-me"

_user_dashboard = UserDashboardBuilder()
_chatbot = ChatbotEngine()

FRONTEND_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "frontend")
)


# ============================================================
# HELPER — safe Firestore access
# ============================================================
def safe_get_doc(collection, doc_id):
    doc = get_document(collection, doc_id)
    if isinstance(doc, dict):
        return doc
    return None


def safe_list_ids(collection):
    raw = list_documents(collection)
    if isinstance(raw, dict):
        return list(raw.keys())
    if isinstance(raw, list):
        return raw
    return []


def compute_affected(intelligence, threat_data=None):
    if not isinstance(intelligence, dict):
        intelligence = {}
    simplified = intelligence.get("simplified") or {}
    if isinstance(simplified, dict):
        who = simplified.get("who_is_affected") or []
    else:
        who = []
    if isinstance(who, list) and who:
        return who
    communities = intelligence.get("communities") or []
    if isinstance(communities, list) and communities:
        return communities
    if isinstance(threat_data, dict):
        raw_community = threat_data.get("community")
        if isinstance(raw_community, str) and raw_community.strip():
            return [raw_community.strip()]
        if isinstance(raw_community, list) and raw_community:
            return raw_community
    return ["General Public"]


# ============================================================
# MODULE 12 — NOTIFICATION HELPER
# ============================================================
def _create_alert(threat_id, intelligence):
    """Generates a community-specific alert when a threat is verified."""
    simplified = intelligence.get("simplified", {})
    communities = intelligence.get("communities", [])

    if not communities:
        return

    alert_id = (
        "alt_"
        + datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        + threat_id
    )

    alert_data = {
        "alert_id": alert_id,
        "threat_id": threat_id,
        "title": simplified.get("title", "New Threat Detected"),
        "message": simplified.get(
            "what_happened", "A new threat has been detected."
        ),
        "severity": intelligence.get("severity", "Medium"),
        "target_communities": communities,
        "created_at": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(),
        "read_by": [],
    }

    set_document("alerts", alert_id, alert_data)
    print(f"  🔔 Alert generated for {communities}: {alert_data['title']}")


# ============================================================
# STATIC FRONTEND
# ============================================================
@app.route("/app/")
@app.route("/app/<path:filename>")
def serve_frontend(filename="login.html"):
    return send_from_directory(FRONTEND_DIR, filename)


@app.route("/ping")
def ping():
    exists = os.path.exists(FRONTEND_DIR)
    return jsonify(
        {
            "frontend_dir": FRONTEND_DIR,
            "exists": exists,
            "contents": (
                os.listdir(FRONTEND_DIR) if exists else None
            ),
        }
    )


# ============================================================
# MODULE 13 — ADMIN DASHBOARD
# ============================================================

@app.route("/")
def dashboard():
    threat_ids = safe_list_ids("threat_intelligence")

    stats = {
        "total": 0,
        "high_risk": 0,
        "critical": 0,
        "verified": 0,
        "communities": {c: 0 for c in VALID_COMMUNITIES},
    }

    threats = []
    for threat_id in threat_ids:
        try:
            data = safe_get_doc("threat_intelligence", threat_id)
            if not isinstance(data, dict):
                continue

            threat_data = safe_get_doc("threat", threat_id)
            if not isinstance(threat_data, dict):
                threat_data = {}

            verified = bool(data.get("verified", False))
            affected_display = compute_affected(data, threat_data)
            sev = str(data.get("severity", "Medium")).capitalize()

            stats["total"] += 1
            if sev in ["High", "Critical"]:
                stats["high_risk"] += 1
            if sev == "Critical":
                stats["critical"] += 1
            if verified:
                stats["verified"] += 1

            for c in affected_display:
                if c in stats["communities"]:
                    stats["communities"][c] += 1

            threats.append(
                {
                    "id": threat_id,
                    "title": threat_data.get("title", "Unknown"),
                    "threat_type": data.get("threat_type", "Unknown"),
                    "severity": sev,
                    "communities": data.get("communities", []),
                    "affected_display": affected_display,
                    "verified": verified,
                    "verified_by": data.get("verified_by", None),
                    "processed_at": data.get("processed_at", ""),
                    "description": threat_data.get(
                        "description", "No description available."
                    ),
                    "simplified": data.get("simplified", {}),
                    "target": data.get("target", []),
                    "platform": data.get("platform", []),
                }
            )
        except Exception as e:
            print(f"Error processing threat {threat_id}: {e}")
            continue

    threats.sort(
        key=lambda x: x.get("processed_at", ""), reverse=True
    )
    return render_template(
        "dashboard.html", threats=threats, stats=stats
    )


@app.route("/api/admin/edit-threat/<threat_id>", methods=["POST"])
def api_edit_threat(threat_id):
    """Updates a threat's severity, communities, and verified status."""
    if not session.get("user_id"):
        return jsonify({"error": "not_authenticated"}), 401

    try:
        data = request.get_json() or {}
        intelligence = safe_get_doc("threat_intelligence", threat_id)
        if not intelligence:
            return jsonify({"error": "Threat not found"}), 404

        new_severity = data.get(
            "severity", intelligence.get("severity", "Medium")
        )
        new_communities = data.get(
            "communities", intelligence.get("communities", [])
        )
        new_verified = data.get(
            "verified", intelligence.get("verified", False)
        )

        # Normalize communities to a clean list of strings
        if isinstance(new_communities, str):
            new_communities = [
                c.strip()
                for c in new_communities.split(",")
                if c.strip()
            ]
        elif isinstance(new_communities, list):
            new_communities = [
                str(c).strip()
                for c in new_communities
                if str(c).strip()
            ]
        else:
            new_communities = ["General Public"]

        if not new_communities:
            new_communities = ["General Public"]

        # Write back the normalized fields
        intelligence["severity"] = new_severity
        intelligence["communities"] = new_communities
        intelligence["target"] = new_communities
        intelligence["verified"] = bool(new_verified)

        if new_verified and not intelligence.get("verified_at"):
            intelligence["verified_at"] = datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()
            intelligence["verified_by"] = "Admin"

        if isinstance(intelligence.get("simplified"), dict):
            intelligence["simplified"][
                "who_is_affected"
            ] = new_communities

        set_document("threat_intelligence", threat_id, intelligence)
        return jsonify(
            {"success": True, "message": "Threat updated."}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/delete-threat/<threat_id>", methods=["POST"])
def api_delete_threat(threat_id):
    """Deletes a threat from the database (both collections)."""
    if not session.get("user_id"):
        return jsonify({"error": "not_authenticated"}), 401

    try:
        delete_document("threat_intelligence", threat_id)
        delete_document("threat", threat_id)
        return jsonify(
            {"success": True, "message": "Threat deleted."}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/publish-alert/<threat_id>", methods=["POST"])
def api_publish_alert(threat_id):
    """Manually pushes an alert for a threat."""
    if not session.get("user_id"):
        return jsonify({"error": "not_authenticated"}), 401

    threat = safe_get_doc("threat_intelligence", threat_id)
    if not threat:
        return jsonify({"error": "Threat not found"}), 404

    simplified = threat.get("simplified", {})
    communities = threat.get("communities", [])

    alert_id = (
        "alt_"
        + datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        + threat_id
    )
    alert_data = {
        "alert_id": alert_id,
        "threat_id": threat_id,
        "title": simplified.get("title", "New Threat Detected"),
        "message": simplified.get(
            "what_happened", "A new threat has been detected."
        ),
        "severity": threat.get("severity", "Medium"),
        "target_communities": communities,
        "created_at": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(),
        "read_by": [],
    }

    set_document("alerts", alert_id, alert_data)
    return jsonify(
        {"success": True, "message": "Alert published."}
    )


@app.route("/threat/<threat_id>")
def threat_detail(threat_id):
    intelligence = safe_get_doc("threat_intelligence", threat_id)
    if not isinstance(intelligence, dict):
        return "Threat not found", 404

    threat_data = safe_get_doc("threat", threat_id)
    if not isinstance(threat_data, dict):
        threat_data = {}

    verified = bool(intelligence.get("verified", False))
    verified_by = intelligence.get("verified_by", None)
    verified_at = intelligence.get("verified_at", None)
    verification_note = intelligence.get("verification_note", "")
    original_ai_communities = intelligence.get(
        "original_ai_communities",
        intelligence.get("communities", []),
    )
    classification_method = intelligence.get(
        "classification_method", "AI + Rule-Based"
    )

    verification_history = intelligence.get(
        "verification_history", []
    )
    if not isinstance(verification_history, list):
        verification_history = []

    if "community_confidence" not in intelligence or not isinstance(
        intelligence["community_confidence"], dict
    ):
        intelligence["community_confidence"] = {}
        for comm in intelligence.get("communities", []):
            intelligence["community_confidence"][comm] = 0.85

    if "matched_keywords" not in intelligence or not isinstance(
        intelligence["matched_keywords"], dict
    ):
        intelligence["matched_keywords"] = {}

    if "community_reason" not in intelligence:
        intelligence["community_reason"] = (
            "Classification completed"
        )

    if not isinstance(intelligence.get("simplified"), dict):
        intelligence["simplified"] = {}

    affected_display = compute_affected(
        intelligence, threat_data
    )

    simplified = intelligence["simplified"]
    simplified.setdefault("title", "")
    simplified.setdefault("what_happened", "")
    simplified.setdefault("how_attack_works", "")
    simplified.setdefault("how_to_identify", [])
    simplified.setdefault("what_to_do", [])
    simplified.setdefault("safety_tip", "")
    simplified.setdefault("ai_model", "")
    simplified["who_is_affected"] = affected_display

    return render_template(
        "threat_detail.html",
        threat_id=threat_id,
        intelligence=intelligence,
        threat_data=threat_data,
        verified=verified,
        verified_by=verified_by,
        verified_at=verified_at,
        verification_note=verification_note,
        original_ai_communities=original_ai_communities,
        valid_communities=VALID_COMMUNITIES,
        classification_method=classification_method,
        verification_history=verification_history,
        affected_display=affected_display,
    )


@app.route("/verify/<threat_id>", methods=["POST"])
def verify_threat(threat_id):
    intelligence = safe_get_doc("threat_intelligence", threat_id)
    if not isinstance(intelligence, dict):
        return jsonify({"error": "Threat not found"}), 404

    verified_communities = request.form.getlist("communities")
    verified_by = request.form.get("verified_by", "Admin")
    verification_note = request.form.get(
        "verification_note", ""
    )
    action = request.form.get("action", "verify")

    normalized_communities = []
    for comm in verified_communities:
        norm = normalize_community(comm)
        if norm:
            normalized_communities.append(norm)

    if not normalized_communities:
        normalized_communities = ["General Public"]

    if "original_ai_communities" not in intelligence:
        intelligence["original_ai_communities"] = (
            intelligence.get("communities", [])
        )

    verification_record = {
        "timestamp": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(),
        "verified_by": verified_by,
        "previous_communities": intelligence.get(
            "communities", []
        ),
        "new_communities": normalized_communities,
        "note": verification_note,
        "action": "verify",
    }

    if not isinstance(
        intelligence.get("verification_history"), list
    ):
        intelligence["verification_history"] = []

    intelligence["verification_history"].append(
        verification_record
    )

    intelligence["communities"] = normalized_communities
    intelligence["verified"] = True
    intelligence["verified_by"] = verified_by
    intelligence["verification_note"] = verification_note
    intelligence["verified_at"] = datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat()
    intelligence["classification_method"] = (
        "AI + Rule-Based + Manual Verification"
    )

    simplified = intelligence.get("simplified") or {}
    if not isinstance(simplified, dict):
        simplified = {}
    simplified["who_is_affected"] = normalized_communities
    intelligence["simplified"] = simplified

    intelligence["verification"] = {
        "status": "verified",
        "verified_by": verified_by,
        "verified_at": intelligence["verified_at"],
        "note": verification_note,
        "final_communities": normalized_communities,
    }

    set_document("threat_intelligence", threat_id, intelligence)

    threat = safe_get_doc("threat", threat_id)
    if isinstance(threat, dict):
        threat["verified"] = True
        threat["verified_by"] = verified_by
        threat["verified_at"] = intelligence["verified_at"]
        set_document("threat", threat_id, threat)

    _create_alert(threat_id, intelligence)

    if action == "verify":
        return redirect(
            url_for("threat_detail", threat_id=threat_id)
        )
    else:
        return jsonify(
            {
                "success": True,
                "message": "Verification saved",
                "verification": intelligence["verification"],
            }
        )


@app.route("/unverify/<threat_id>", methods=["POST"])
def unverify_threat(threat_id):
    intelligence = safe_get_doc("threat_intelligence", threat_id)
    if not isinstance(intelligence, dict):
        return jsonify({"error": "Threat not found"}), 404

    unverify_record = {
        "timestamp": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(),
        "verified_by": intelligence.get(
            "verified_by", "System"
        ),
        "previous_communities": intelligence.get(
            "communities", []
        ),
        "new_communities": intelligence.get(
            "original_ai_communities",
            intelligence.get("communities", []),
        ),
        "action": "unverify",
    }

    if not isinstance(
        intelligence.get("verification_history"), list
    ):
        intelligence["verification_history"] = []
    intelligence["verification_history"].append(unverify_record)

    if "original_ai_communities" in intelligence:
        intelligence["communities"] = intelligence[
            "original_ai_communities"
        ]

    intelligence["verified"] = False
    intelligence["verified_by"] = None
    intelligence["verification_note"] = ""
    intelligence["verified_at"] = None
    intelligence["classification_method"] = (
        "AI + Rule-Based Hybrid"
    )

    simplified = intelligence.get("simplified") or {}
    if not isinstance(simplified, dict):
        simplified = {}
    simplified["who_is_affected"] = intelligence.get(
        "communities", []
    )
    intelligence["simplified"] = simplified

    intelligence["verification"] = {
        "status": "unverified",
        "previous_verified_by": unverify_record[
            "verified_by"
        ],
        "previous_verified_at": unverify_record["timestamp"],
    }

    set_document("threat_intelligence", threat_id, intelligence)

    threat = safe_get_doc("threat", threat_id)
    if isinstance(threat, dict):
        threat["verified"] = False
        threat["verified_by"] = None
        set_document("threat", threat_id, threat)

    return redirect(
        url_for("threat_detail", threat_id=threat_id)
    )


# ============================================================
# JSON API — THREATS
# ============================================================

@app.route("/api/threat/<threat_id>")
def api_threat(threat_id):
    intelligence = safe_get_doc("threat_intelligence", threat_id)
    if not isinstance(intelligence, dict):
        return jsonify({"error": "Threat not found"}), 404

    threat_data = safe_get_doc("threat", threat_id)
    if not isinstance(threat_data, dict):
        threat_data = {}

    affected_display = compute_affected(
        intelligence, threat_data
    )

    simplified = intelligence.get("simplified") or {}
    if not isinstance(simplified, dict):
        simplified = {}
    simplified["who_is_affected"] = affected_display

    return jsonify(
        {
            "threat_id": threat_id,
            "communities": intelligence.get("communities", []),
            "affected": affected_display,
            "community_confidence": intelligence.get(
                "community_confidence", {}
            ),
            "classification_method": intelligence.get(
                "classification_method", "AI + Rule-Based"
            ),
            "verified": intelligence.get("verified", False),
            "verified_by": intelligence.get("verified_by", None),
            "verified_at": intelligence.get("verified_at", None),
            "verification_note": intelligence.get(
                "verification_note", ""
            ),
            "verification_history": intelligence.get(
                "verification_history", []
            ),
            "verification": intelligence.get("verification", {}),
            "simplified": simplified,
        }
    )


@app.route("/api/threats")
def api_threats():
    threat_ids = safe_list_ids("threat_intelligence")

    threats = []
    for threat_id in threat_ids:
        try:
            data = safe_get_doc("threat_intelligence", threat_id)
            if not isinstance(data, dict):
                continue

            threat_data = safe_get_doc("threat", threat_id)
            if not isinstance(threat_data, dict):
                threat_data = {}

            affected_display = compute_affected(
                data, threat_data
            )

            simplified = data.get("simplified") or {}
            if not isinstance(simplified, dict):
                simplified = {}
            simplified["who_is_affected"] = affected_display

            threats.append(
                {
                    "id": threat_id,
                    "threat_type": data.get(
                        "threat_type", "Unknown"
                    ),
                    "severity": data.get("severity", "Medium"),
                    "communities": data.get("communities", []),
                    "affected": affected_display,
                    "verified": data.get("verified", False),
                    "verified_by": data.get(
                        "verified_by", None
                    ),
                    "classification_method": data.get(
                        "classification_method",
                        "AI + Rule-Based",
                    ),
                    "simplified": simplified,
                }
            )
        except Exception as e:
            print(
                f"Error processing threat {threat_id} in API: {e}"
            )
            continue

    return jsonify(threats)


# ============================================================
# MODULE 6 — AUTHENTICATION & REGISTRATION
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (
            request.form.get("email") or ""
        ).strip().lower()
        password = (
            request.form.get("password") or ""
        ).strip()

        if not email or not password:
            return render_template(
                "login.html",
                users=_list_demo_users(),
                error="Please enter both email and password.",
            )

        user = _find_user_by_email(email)
        if user is None:
            return render_template(
                "login.html",
                users=_list_demo_users(),
                error="No account matches that email.",
            )

        stored_hash = user.get("password_hash") or ""
        if not stored_hash:
            return render_template(
                "login.html",
                users=_list_demo_users(),
                error="This account has no password configured.",
            )

        if not check_password_hash(stored_hash, password):
            return render_template(
                "login.html",
                users=_list_demo_users(),
                error="Incorrect password.",
            )

        session["user_id"] = user["id"]
        session["user_name"] = user.get("name", "User")
        session["community"] = normalize_community(
            user.get("community")
        )

        return redirect(url_for("me"))

    return render_template(
        "login.html", users=_list_demo_users(), error=None
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (
            request.form.get("email") or ""
        ).strip().lower()
        password = (
            request.form.get("password") or ""
        ).strip()
        community = request.form.get(
            "community", "General Public"
        )

        if not name or not email or not password:
            return render_template(
                "register.html",
                error="All fields are required.",
            )

        if _find_user_by_email(email) is not None:
            return render_template(
                "register.html",
                error="Email already registered.",
            )

        user_id = "u_" + datetime.datetime.now().strftime(
            "%Y%m%d%H%M%S"
        )
        user_data = {
            "name": name,
            "email": email,
            "community": community,
            "password_hash": generate_password_hash(password),
            "created_at": datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat(),
        }

        set_document("users", user_id, user_data)

        session["user_id"] = user_id
        session["user_name"] = name
        session["community"] = normalize_community(community)

        return redirect(url_for("me"))

    return render_template("register.html", error=None)


def _find_user_by_email(email: str):
    user_ids = safe_list_ids("users")
    for uid in user_ids:
        doc = safe_get_doc("users", uid)
        if not isinstance(doc, dict):
            continue
        if (doc.get("email") or "").strip().lower() == email:
            return {"id": uid, **doc}
    return None


def _list_demo_users():
    user_ids = safe_list_ids("users")
    users = []
    for uid in user_ids:
        doc = safe_get_doc("users", uid)
        if isinstance(doc, dict):
            users.append(
                {
                    "id": uid,
                    "name": doc.get("name", "User"),
                    "email": doc.get("email", ""),
                    "community": doc.get(
                        "community", "General Public"
                    ),
                }
            )
    users.sort(key=lambda u: u["name"])
    return users


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("user_name", None)
    session.pop("community", None)
    return redirect(url_for("login"))


@app.route("/me")
def me():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    payload = _user_dashboard.build(user_id)
    if payload is None:
        session.pop("user_id", None)
        session.pop("user_name", None)
        session.pop("community", None)
        return redirect(url_for("login"))

    session["user_name"] = payload.get("name", "User")
    session["community"] = payload.get(
        "community", "General Public"
    )

    return render_template(
        "me.html",
        payload=payload,
        community=payload.get("community"),
        threat_count=payload.get(
            "threat_count", len(payload.get("threats", []))
        ),
    )


# ============================================================
# MODULE 6 — JSON AUTH
# ============================================================

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()

    if not email or not password:
        return (
            jsonify(
                {
                    "error": "missing_fields",
                    "message": "Please enter both email and password.",
                }
            ),
            400,
        )

    user = _find_user_by_email(email)
    if user is None:
        return (
            jsonify(
                {
                    "error": "no_account",
                    "message": "No account matches that email.",
                }
            ),
            401,
        )

    stored_hash = user.get("password_hash") or ""
    if not stored_hash:
        return (
            jsonify(
                {
                    "error": "no_password",
                    "message": "This account has no password configured.",
                }
            ),
            500,
        )

    if not check_password_hash(stored_hash, password):
        return (
            jsonify(
                {
                    "error": "wrong_password",
                    "message": "Incorrect password.",
                }
            ),
            401,
        )

    session["user_id"] = user["id"]
    session["user_name"] = user.get("name", "User")
    session["community"] = normalize_community(
        user.get("community")
    )

    return jsonify(
        {
            "success": True,
            "user_id": user["id"],
            "name": user.get("name", "User"),
            "community": session["community"],
        }
    )


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.pop("user_id", None)
    session.pop("user_name", None)
    session.pop("community", None)
    return jsonify({"success": True})


@app.route("/api/me")
def api_me():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "not_authenticated"}), 401
    return jsonify(
        {
            "user_id": user_id,
            "user_name": session.get("user_name", "User"),
            "community": session.get(
                "community", "General Public"
            ),
        }
    )


# ============================================================
# MODULE 6 — JSON DASHBOARD
# ============================================================

@app.route("/api/dashboard")
def api_dashboard():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "not_authenticated"}), 401

    payload = _user_dashboard.build(user_id)
    if payload is None:
        return jsonify({"error": "user_not_found"}), 404

    q = (request.args.get("q") or "").strip().lower()
    severity = (
        request.args.get("severity") or ""
    ).strip().lower()
    t_type = (
        request.args.get("type") or ""
    ).strip().lower()

    full_threats = payload.get("threats", [])

    available_types = sorted(
        {
            str(t.get("threat_type", "")).strip()
            for t in full_threats
            if t.get("threat_type")
            and t.get("threat_type") != "Unknown"
        }
    )
    payload["available_types"] = available_types

    filtered = []
    for t in full_threats:
        if q:
            haystack = " ".join(
                [
                    str(t.get("title", "")),
                    str(t.get("description", "")),
                    str(t.get("threat_type", "")),
                    str(t.get("region", "")),
                    " ".join(t.get("platform", []) or []),
                    " ".join(t.get("target", []) or []),
                ]
            ).lower()
            if q not in haystack:
                continue
        if (
            severity
            and str(t.get("severity", "")).lower()
            != severity
        ):
            continue
        if (
            t_type
            and str(t.get("threat_type", "")).lower()
            != t_type
        ):
            continue
        filtered.append(t)

    payload["threats"] = filtered
    payload["threat_count"] = len(filtered)

    return jsonify(payload)


@app.route("/api/dashboard/<user_id>")
def api_dashboard_for(user_id):
    payload = _user_dashboard.build(user_id)
    if payload is None:
        return jsonify({"error": "user_not_found"}), 404

    q = (request.args.get("q") or "").strip().lower()
    severity = (
        request.args.get("severity") or ""
    ).strip().lower()
    t_type = (
        request.args.get("type") or ""
    ).strip().lower()

    full_threats = payload.get("threats", [])
    available_types = sorted(
        {
            str(t.get("threat_type", "")).strip()
            for t in full_threats
            if t.get("threat_type")
            and t.get("threat_type") != "Unknown"
        }
    )
    payload["available_types"] = available_types

    filtered = []
    for t in full_threats:
        if q:
            haystack = " ".join(
                [
                    str(t.get("title", "")),
                    str(t.get("description", "")),
                    str(t.get("threat_type", "")),
                    str(t.get("region", "")),
                    " ".join(t.get("platform", []) or []),
                    " ".join(t.get("target", []) or []),
                ]
            ).lower()
            if q not in haystack:
                continue
        if (
            severity
            and str(t.get("severity", "")).lower()
            != severity
        ):
            continue
        if (
            t_type
            and str(t.get("threat_type", "")).lower()
            != t_type
        ):
            continue
        filtered.append(t)

    payload["threats"] = filtered
    payload["threat_count"] = len(filtered)

    return jsonify(payload)


# ============================================================
# MODULE 9 — AI CHATBOT
# ============================================================

@app.route("/api/chat", methods=["POST"])
def api_chat():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "not_authenticated"}), 401

    data = request.get_json(silent=True) or {}
    user_message = (data.get("message") or "").strip()

    if not user_message:
        return (
            jsonify(
                {"error": "Message cannot be empty"}
            ),
            400,
        )

    community = session.get(
        "community", "General Public"
    )
    result = _chatbot.generate_response(
        user_message, community
    )

    return jsonify(
        {
            "success": True,
            "reply": result["reply"],
            "community_context": community,
            "fallback_used": result["error"],
        }
    )


# ============================================================
# MODULE 10 — THREAT REPORTING
# ============================================================

@app.route("/api/report", methods=["POST"])
def api_report():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "not_authenticated"}), 401

    data = request.get_json(silent=True) or {}
    threat_type = data.get("type", "Other")
    description = (
        data.get("description") or ""
    ).strip()
    platform = data.get("platform", "Unknown")
    location = data.get("location", "Unknown")

    if not description:
        return (
            jsonify(
                {"error": "Description is required"}
            ),
            400,
        )

    report_id = (
        "rep_"
        + datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        + str(len(description))
    )

    report_data = {
        "report_id": report_id,
        "reported_by": user_id,
        "threat_type": threat_type,
        "description": description,
        "platform": platform,
        "location": location,
        "status": "Pending",
        "reported_at": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(),
    }

    set_document("user_reports", report_id, report_data)

    return (
        jsonify(
            {
                "success": True,
                "message": "Report submitted successfully.",
                "report_id": report_id,
            }
        ),
        201,
    )


@app.route("/api/my-reports")
def api_my_reports():
    """Fetch the report history for the currently logged-in user."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "not_authenticated"}), 401

    report_ids = safe_list_ids("user_reports")
    my_reports = []

    user_doc = safe_get_doc("users", user_id)
    user_name = (
        user_doc.get("name", "Unknown User")
        if user_doc
        else "Unknown User"
    )

    for rid in report_ids:
        doc = safe_get_doc("user_reports", rid)
        if doc and doc.get("reported_by") == user_id:
            doc["reporter_name"] = user_name
            my_reports.append(doc)

    my_reports.sort(
        key=lambda x: x.get("reported_at", ""), reverse=True
    )
    return jsonify(my_reports)


@app.route("/api/admin/reports")
def api_admin_reports():
    if not session.get("user_id"):
        return jsonify({"error": "not_authenticated"}), 401

    report_ids = safe_list_ids("user_reports")
    pending = []
    for rid in report_ids:
        doc = safe_get_doc("user_reports", rid)
        if doc and doc.get("status") == "Pending":
            reporter_id = doc.get("reported_by")
            reporter_doc = safe_get_doc("users", reporter_id)
            reporter_name = (
                reporter_doc.get("name", "Unknown")
                if reporter_doc
                else "Unknown"
            )

            doc["reporter_name"] = reporter_name
            pending.append(doc)

    pending.sort(
        key=lambda x: x.get("reported_at", ""), reverse=True
    )
    return jsonify(pending)


@app.route(
    "/api/admin/approve-report/<report_id>",
    methods=["POST"],
)
def api_approve_report(report_id):
    if not session.get("user_id"):
        return jsonify({"error": "not_authenticated"}), 401

    report = safe_get_doc("user_reports", report_id)
    if not report or report.get("status") != "Pending":
        return (
            jsonify(
                {
                    "error": "Report not found or already processed"
                }
            ),
            404,
        )

    reporter = safe_get_doc(
        "users", report.get("reported_by")
    )
    reporter_community = (
        reporter.get("community", "General Public")
        if reporter
        else "General Public"
    )

    raw_threat_id = f"raw_{report_id}"
    raw_threat_data = {
        "title": f"User Reported: {report.get('threat_type')}",
        "description": report.get("description"),
        "category": report.get("threat_type"),
        "community": reporter_community,
        "location": report.get("location"),
        "source": "User Report",
        "source_url": "",
        "processed": False,
    }
    set_document("threat", raw_threat_id, raw_threat_data)

    from ai_engine import process_threat

    try:
        process_threat(raw_threat_id, force=True)
    except Exception as e:
        return (
            jsonify(
                {"error": f"AI processing failed: {e}"}
            ),
            500,
        )

    report["status"] = "Approved"
    report["threat_intelligence_id"] = raw_threat_id
    set_document("user_reports", report_id, report)

    new_intel = safe_get_doc(
        "threat_intelligence", raw_threat_id
    )
    if new_intel:
        _create_alert(raw_threat_id, new_intel)

    return jsonify(
        {
            "success": True,
            "message": "Report approved and threat created.",
            "threat_id": raw_threat_id,
        }
    )


@app.route(
    "/api/admin/reject-report/<report_id>",
    methods=["POST"],
)
def api_reject_report(report_id):
    if not session.get("user_id"):
        return jsonify({"error": "not_authenticated"}), 401

    report = safe_get_doc("user_reports", report_id)
    if not report or report.get("status") != "Pending":
        return (
            jsonify(
                {
                    "error": "Report not found or already processed"
                }
            ),
            404,
        )

    report["status"] = "Rejected"
    report["rejected_at"] = datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat()
    set_document("user_reports", report_id, report)

    return jsonify(
        {"success": True, "message": "Report rejected."}
    )


# ============================================================
# MODULE 11 — HELPLINE / SUPPORT
# ============================================================

@app.route("/api/helplines")
def api_helplines():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "not_authenticated"}), 401

    community = session.get(
        "community", "General Public"
    )

    HELPLINES = {
        "Students": [
            {
                "icon": "🚨",
                "title": "Report Cybercrime",
                "number": "1930",
                "desc": "National Cyber Crime Helpline",
            },
            {
                "icon": "🏦",
                "title": "Contact Your Bank",
                "number": "Bank Official App",
                "desc": "For fake scholarship/internship links",
            },
            {
                "icon": "👮",
                "title": "Cyber Police",
                "number": "cybercrime.gov.in",
                "desc": "Report phishing & fake portals",
            },
            {
                "icon": "🎓",
                "title": "Student Helpline",
                "number": "1800-11-1555",
                "desc": "UGC Scholarship Helpdesk",
            },
        ],
        "Senior Citizens": [
            {
                "icon": "🚨",
                "title": "Report Cybercrime",
                "number": "1930",
                "desc": "National Cyber Crime Helpline",
            },
            {
                "icon": "🏦",
                "title": "Contact Your Bank",
                "number": "Bank Official App",
                "desc": "For KYC/Pension scams. Freeze account here.",
            },
            {
                "icon": "👮",
                "title": "Cyber Police",
                "number": "cybercrime.gov.in",
                "desc": "Report digital arrest and fraud",
            },
            {
                "icon": "👴",
                "title": "Elder Helpline",
                "number": "14567",
                "desc": "National Elderline for seniors",
            },
        ],
        "Small Businesses": [
            {
                "icon": "🚨",
                "title": "Report Cybercrime",
                "number": "1930",
                "desc": "National Cyber Crime Helpline",
            },
            {
                "icon": "🏦",
                "title": "Contact Your Bank",
                "number": "Bank Official App",
                "desc": "For fake invoices & BEC fraud",
            },
            {
                "icon": "👮",
                "title": "Cyber Police",
                "number": "cybercrime.gov.in",
                "desc": "Report ransomware & data breaches",
            },
            {
                "icon": "🏪",
                "title": "MSME Helpdesk",
                "number": "1800-11-1555",
                "desc": "Business cyber fraud support",
            },
        ],
        "General Public": [
            {
                "icon": "🚨",
                "title": "Report Cybercrime",
                "number": "1930",
                "desc": "National Cyber Crime Helpline",
            },
            {
                "icon": "🏦",
                "title": "Contact Your Bank",
                "number": "Bank Official App",
                "desc": "For UPI fraud & account takeover",
            },
            {
                "icon": "👮",
                "title": "Cyber Police",
                "number": "cybercrime.gov.in",
                "desc": "Report all cyber fraud here",
            },
            {
                "icon": "📞",
                "title": "Emergency Support",
                "number": "112",
                "desc": "National Emergency Number",
            },
        ],
    }

    return jsonify(
        {
            "community": community,
            "helplines": HELPLINES.get(
                community, HELPLINES["General Public"]
            ),
        }
    )


# ============================================================
# MODULE 12 — NOTIFICATION API
# ============================================================

@app.route("/api/notifications")
def api_notifications():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "not_authenticated"}), 401

    community = session.get(
        "community", "General Public"
    )

    alert_ids = safe_list_ids("alerts")
    my_alerts = []

    for aid in alert_ids:
        doc = safe_get_doc("alerts", aid)
        if not doc:
            continue

        if community in doc.get("target_communities", []):
            read_by = doc.get("read_by", [])
            doc["is_read"] = user_id in read_by
            my_alerts.append(doc)

    my_alerts.sort(
        key=lambda x: x.get("created_at", ""), reverse=True
    )
    return jsonify(my_alerts)


@app.route(
    "/api/notifications/mark-read", methods=["POST"]
)
def api_mark_notifications_read():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "not_authenticated"}), 401

    community = session.get(
        "community", "General Public"
    )
    alert_ids = safe_list_ids("alerts")

    for aid in alert_ids:
        doc = safe_get_doc("alerts", aid)
        if doc and community in doc.get(
            "target_communities", []
        ):
            read_by = doc.get("read_by", [])
            if user_id not in read_by:
                read_by.append(user_id)
                doc["read_by"] = read_by
                set_document("alerts", aid, doc)

    return jsonify({"success": True})


# ============================================================
# MODULE 6 — DEBUG
# ============================================================

@app.route("/debug/me")
def debug_me():
    user_id = session.get("user_id")
    user_name = session.get("user_name")
    community = session.get("community")

    payload = None
    if user_id:
        payload = _user_dashboard.build(user_id)

    return jsonify(
        {
            "session": {
                "user_id": user_id,
                "user_name": user_name,
                "community": community,
            },
            "builder_payload": payload,
        }
    )


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("🛡️ TRINETRA DASHBOARD")
    print("=" * 50)
    
    # Read port from environment variable (for Render/Railway deployment)
    port = int(os.environ.get("PORT", 5001))
    
    print(f"Starting server on http://127.0.0.1:{port}")
    print("Press CTRL+C to stop")
    print("=" * 50 + "\n")

    # Set debug=False for production deployment
    app.run(host="0.0.0.0", port=port, debug=False)