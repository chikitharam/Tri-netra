from flask import Blueprint, request, jsonify
import requests

auth = Blueprint("auth", __name__)

# Paste your Firebase Web API key between the quotes
FIREBASE_API_KEY = "AIzaSyBmXZk8Gi_Jxj1l3N2nRKwbjLvZ9_bAdwk"


# =========================
# REGISTER
# =========================
@auth.route("/register", methods=["POST"])
def register():

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "JSON data is required"
        }), 400

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({
            "error": "Email and password are required"
        }), 400

    url = (
        "https://identitytoolkit.googleapis.com/"
        "v1/accounts:signUp?key="
        + FIREBASE_API_KEY
    )

    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }

    try:

        response = requests.post(url, json=payload)

        result = response.json()

    except Exception as e:

        return jsonify({
            "error": "Could not connect to Firebase",
            "details": str(e)
        }), 500

    if response.status_code != 200:

        return jsonify({
            "error": result
        }), response.status_code

    return jsonify({
        "message": "Registration successful",
        "uid": result["localId"],
        "email": result["email"],
        "idToken": result["idToken"]
    }), 201


# =========================
# LOGIN
# =========================
@auth.route("/login", methods=["POST"])
def login():

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "JSON data is required"
        }), 400

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({
            "error": "Email and password are required"
        }), 400

    url = (
        "https://identitytoolkit.googleapis.com/"
        "v1/accounts:signInWithPassword?key="
        + FIREBASE_API_KEY
    )

    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }

    try:

        response = requests.post(url, json=payload)

        result = response.json()

    except Exception as e:

        return jsonify({
            "error": "Could not connect to Firebase",
            "details": str(e)
        }), 500

    if response.status_code != 200:

        return jsonify({
            "error": result
        }), response.status_code

    return jsonify({
        "message": "Login successful",
        "uid": result["localId"],
        "email": result["email"],
        "idToken": result["idToken"]
    }), 200