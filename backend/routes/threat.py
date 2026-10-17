from flask import Blueprint, request, jsonify
from services.firebase_service import db

threat = Blueprint("threat", __name__)


@threat.route("/threats", methods=["GET"])
def get_threats():

    community = request.args.get("community")
    location = request.args.get("location")

    community = community.lower() if community else None
    location = location.lower() if location else None

    # Get threats from Firebase
    query = db.collection("threat")

    if community:
        query = query.where("community", "==", community)

    results = query.stream()

    threat_list = []

    for doc in results:

        data = doc.to_dict()

        # Convert Firebase location to lowercase for comparison
        firebase_location = str(
            data.get("location", "")
        ).lower()

        # Filter by location
        if location and firebase_location != location:
            continue

        data["id"] = doc.id

        threat_list.append(data)

    return jsonify(threat_list), 200