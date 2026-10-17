# ============================================================
# THREAT SIMPLIFIER (Module 5)
# ============================================================
# This module takes structured threat intelligence and
# simplifies it for frontend display.

import json
from datetime import datetime


class ThreatSimplifier:
    """Simplifies complex threat intelligence for frontend display."""

    def __init__(self):
        self.severity_icons = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢"
        }
        
        self.community_icons = {
            "Students": "🎓",
            "Senior Citizens": "👴",
            "Small Businesses": "🏢",
            "General Public": "👥"
        }
        
        self.threat_type_icons = {
            "Phishing": "🎣",
            "Malware": "💻",
            "Ransomware": "🔒",
            "Identity Theft": "🆔",
            "Financial Fraud": "💰",
            "Job Scam": "💼",
            "Investment Scam": "📈",
            "Social Engineering": "🧠",
            "Data Breach": "📊",
            "Account Takeover": "🔑",
            "Cyberbullying": "😔",
            "Other": "⚠️"
        }

    def simplify(self, intelligence):
        """
        Simplify structured threat intelligence for frontend display.
        
        Args:
            intelligence: Dict from Module 4 (threat_intelligence document)
        
        Returns:
            dict: Simplified threat summary
        """
        if not intelligence:
            return self._empty_response()
        
        # Extract key information
        threat_type = intelligence.get("threat_type", "Unknown")
        severity = intelligence.get("severity", "Medium")
        communities = intelligence.get("communities", ["General Public"])
        region = intelligence.get("region", "Unknown")
        recommended_actions = intelligence.get("recommended_actions", [])
        
        # Get first community (primary target)
        primary_community = communities[0] if communities else "General Public"
        
        # Build simplified output
        simplified = {
            # 1. Basic threat info
            "threat_type": threat_type,
            "threat_type_icon": self.threat_type_icons.get(threat_type, "⚠️"),
            
            # 2. Severity with icon
            "severity": severity,
            "severity_icon": self.severity_icons.get(severity, "🟡"),
            "severity_level": self._get_severity_level(severity),
            
            # 3. Target communities
            "communities": communities,
            "community_icons": [self.community_icons.get(c, "👥") for c in communities],
            "primary_community": primary_community,
            "primary_community_icon": self.community_icons.get(primary_community, "👥"),
            
            # 4. Region
            "region": region,
            
            # 5. Simplified description
            "simplified_description": self._generate_description(intelligence),
            
            # 6. Top 3 recommended actions (for quick display)
            "quick_actions": recommended_actions[:3] if recommended_actions else [],
            
            # 7. Alert level (for frontend styling)
            "alert_level": self._get_alert_level(severity),
            
            # 8. Key indicators (highlighted)
            "key_indicators": intelligence.get("indicators", [])[:3],
            
            # 9. Verification status
            "verified": intelligence.get("verified", False),
            "verified_by": intelligence.get("verified_by", None),
            
            # 10. Metadata
            "simplified_at": datetime.now().isoformat(),
            "threat_id": intelligence.get("threat_id", "Unknown")
        }
        
        return simplified

    def _generate_description(self, intelligence):
        """
        Generate a human-readable description of the threat.
        """
        threat_type = intelligence.get("threat_type", "Unknown")
        communities = intelligence.get("communities", ["General Public"])
        region = intelligence.get("region", "Unknown")
        severity = intelligence.get("severity", "Medium")
        
        community_str = ", ".join(communities)
        
        if region and region != "Unknown":
            description = f"A {severity.lower()} severity {threat_type} threat targeting {community_str} in {region}."
        else:
            description = f"A {severity.lower()} severity {threat_type} threat targeting {community_str}."
        
        return description

    def _get_severity_level(self, severity):
        """
        Get numeric severity level (1-4) for frontend.
        """
        levels = {
            "Low": 1,
            "Medium": 2,
            "High": 3,
            "Critical": 4
        }
        return levels.get(severity, 2)

    def _get_alert_level(self, severity):
        """
        Get alert level for frontend styling.
        """
        levels = {
            "Low": "info",
            "Medium": "warning",
            "High": "danger",
            "Critical": "critical"
        }
        return levels.get(severity, "info")

    def _empty_response(self):
        """Return empty simplified response."""
        return {
            "threat_type": "Unknown",
            "threat_type_icon": "⚠️",
            "severity": "Unknown",
            "severity_icon": "🟡",
            "severity_level": 0,
            "communities": [],
            "community_icons": [],
            "primary_community": "Unknown",
            "primary_community_icon": "👥",
            "region": "Unknown",
            "simplified_description": "No threat data available.",
            "quick_actions": [],
            "alert_level": "info",
            "key_indicators": [],
            "verified": False,
            "verified_by": None,
            "simplified_at": datetime.now().isoformat(),
            "threat_id": "Unknown"
        }

    def simplify_for_frontend(self, intelligence):
        """
        Alias for simplify() - specifically for frontend consumption.
        """
        return self.simplify(intelligence)

    def get_alert_message(self, intelligence):
        """
        Generate a short alert message for notifications.
        """
        if not intelligence:
            return "No threat data available."
        
        severity = intelligence.get("severity", "Medium")
        threat_type = intelligence.get("threat_type", "Unknown")
        communities = intelligence.get("communities", ["General Public"])
        
        return f"{self.severity_icons.get(severity, '⚠️')} {severity}: {threat_type} targeting {', '.join(communities)}"

    def get_community_alert(self, intelligence, community=None):
        """
        Get community-specific alert.
        """
        if not intelligence:
            return "No threat data available."
        
        communities = intelligence.get("communities", ["General Public"])
        if community and community in communities:
            target_communities = [community]
        else:
            target_communities = communities
        
        actions = intelligence.get("recommended_actions", [])
        threat_type = intelligence.get("threat_type", "Unknown")
        severity = intelligence.get("severity", "Medium")
        
        return {
            "alert": f"🚨 {threat_type} Alert",
            "target": target_communities,
            "severity": severity,
            "severity_icon": self.severity_icons.get(severity, "🟡"),
            "actions": actions[:2] if actions else []
        }