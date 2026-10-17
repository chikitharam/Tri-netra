# ============================================================
# COMMUNITY RULES
# ============================================================
# This file contains the keyword rules for each community.
# Separate from the classifier logic for easy maintenance.

# Weight scale:
#   3 = Strong indicator (highly specific to this community)
#   2 = Medium indicator (commonly associated)
#   1 = Weak indicator (ambiguous, can apply to multiple communities)

COMMUNITY_KEYWORDS = {

    "Students": {
        "internship": 3,
        "scholarship": 3,
        "placement": 3,
        "student": 3,
        "college": 2,
        "university": 2,
        "exam": 2,
        "admission": 2,
        "campus": 2,
        "course": 1,
        "marks": 1,
        "semester": 1,
        "fee": 1,
        "tuition": 1,
        "project": 1,
        "thesis": 1
    },

    "Senior Citizens": {
        "pension": 3,
        "retirement": 3,
        "senior citizen": 3,
        "life certificate": 3,
        "old age": 3,
        "pension verification": 3,
        "bank pension": 3,
        "elderly": 2,
        "medicare": 2,
        "care home": 2,
        "assisted living": 2,
        "medical": 1,
        "mediclaim": 1
    },

    "Small Businesses": {
        "invoice": 3,
        "ransomware": 3,
        "purchase order": 3,
        "vendor": 2,
        "supplier": 2,
        "gst": 2,
        "quotation": 2,
        "business": 2,
        "startup": 2,
        "proprietor": 2,
        "small business": 2,
        "company": 1,
        "employee": 1,
        "payment": 1
    },

    "General Public": {
        "general": 2,
        "public": 2,
        "everyone": 2,
        "all": 1,
        "people": 1,
        "citizen": 1
    }
}

# Valid community names (canonical)
VALID_COMMUNITIES = {
    "Students",
    "Senior Citizens",
    "Small Businesses",
    "General Public"
}

# Aliases for normalization
COMMUNITY_ALIASES = {
    "Student": "Students",
    "Senior Citizen": "Senior Citizens",
    "Small Business": "Small Businesses",
    "General": "General Public",
    "Public": "General Public",
    "College Students": "Students",
    "Elderly": "Senior Citizens",
    "Seniors": "Senior Citizens",
    "SME": "Small Businesses",
    "Startup": "Small Businesses"
}