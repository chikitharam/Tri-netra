from flask import Blueprint, request, jsonify
from services.firebase_service import db

users = Blueprint("users", __name__)

@users.route("/users", methods=["POST"])
def create_user():

    data = request.json

    user = {
        "name": data.get("name"),
        "email": data.get("email"),
        "community": data.get("community"),
        "location": data.get("location"),
        "language": data.get("language"),
        "notificationPreference": data.get("notificationPreference")
    }

    doc_ref = db.collection("users").document()
    doc_ref.set(user)

    return jsonify({
        "message": "User profile created",
        "userId": doc_ref.id
    }), 201

@users.route("/users/<user_id>", methods=["GET"])
def get_user(user_id):

    doc = db.collection("users").document(user_id).get()

    if not doc.exists:
        return jsonify({
            "error": "User not found"
        }), 404

    return jsonify(doc.to_dict()), 200

@users.route("/users/<user_id>", methods=["PUT"])
def update_user(user_id):

    data = request.json

    doc_ref = db.collection("users").document(user_id)

    doc = doc_ref.get()

    if not doc.exists:
        return jsonify({
            "error": "User not found"
        }), 404

    doc_ref.update(data)

    return jsonify({
        "message": "Profile updated successfully"
    }), 200