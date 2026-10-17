import feedparser
import firebase_admin

from firebase_admin import credentials, firestore


# ============================================================
# 1. FIREBASE CONNECTION
# ============================================================

cred = credentials.Certificate("serviceAccountKey.json")

firebase_admin.initialize_app(cred)

db = firestore.client()

print("Firebase connected successfully!")


# ============================================================
# 2. RSS SOURCES
# ============================================================

sources = [
    {
        "name": "CISA",
        "url": "https://www.cisa.gov/news.xml"
    }
]


# ============================================================
# 3. COLLECT THREATS
# ============================================================

for source in sources:

    print("\nReading source:", source["name"])

    feed = feedparser.parse(source["url"])

    print("Articles found:", len(feed.entries))


    # Process only first 10 articles while testing
    for entry in feed.entries[:10]:

        # ----------------------------------------------------
        # Extract basic information
        # ----------------------------------------------------

        title = entry.get("title", "").strip()

        description = entry.get("description", "").strip()

        url = entry.get("link", "").strip()

        date = entry.get("published", "")

        # Combine title + description
        text = (title + " " + description).lower()


        # ----------------------------------------------------
        # CATEGORY
        # ----------------------------------------------------

        if "phishing" in text or "google form" in text:

            category = "Phishing"

        elif "ransomware" in text:

            category = "Ransomware"

        elif "malware" in text:

            category = "Malware"

        elif "job" in text or "internship" in text:

            category = "Job Scam"

        elif "fraud" in text or "scam" in text:

            category = "Fraud"

        else:

            category = "Other"


        # ----------------------------------------------------
        # TARGET COMMUNITY
        # ----------------------------------------------------

        if (
            "student" in text
            or "students" in text
            or "university" in text
            or "college" in text
            or "school" in text
        ):

            target = "Students"

        elif (
            "senior citizen" in text
            or "senior citizens" in text
            or "elderly" in text
        ):

            target = "Senior Citizens"

        elif (
            "small business" in text
            or "small businesses" in text
        ):

            target = "Small Businesses"

        else:

            target = "General Public"


        # ----------------------------------------------------
        # SEVERITY
        # ----------------------------------------------------

        if (
            "ransomware" in text
            or "critical" in text
        ):

            severity = "Critical"

        elif (
            "malware" in text
            or "phishing" in text
        ):

            severity = "High"

        elif (
            "scam" in text
            or "fraud" in text
        ):

            severity = "Medium"

        else:

            severity = "Low"


        # ----------------------------------------------------
        # CREATE THREAT OBJECT
        # ----------------------------------------------------

        threat = {

            "title": title,

            "description": description,

            "category": category,

            "target": target,

            "severity": severity,

            "source": source["name"],

            "date": date,

            "url": url
        }


        # ----------------------------------------------------
        # CHECK FOR DUPLICATES
        # ----------------------------------------------------

        existing = (
            db.collection("threats")
            .where("url", "==", url)
            .limit(1)
            .stream()
        )


        if any(existing):

            print("Already exists:", title)

            continue


        # ----------------------------------------------------
        # SAVE TO FIRESTORE
        # ----------------------------------------------------

        db.collection("threats").add(threat)

        print("Threat added:", title)


print("\nThreat collection completed!")