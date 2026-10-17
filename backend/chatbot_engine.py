# ============================================================
# MODULE 9 — COMMUNITY-AWARE AI CHATBOT ENGINE
# ============================================================

import os

from dotenv import load_dotenv
from google import genai

from gemini_client import make_client
from firebase_rest import list_documents, get_document

load_dotenv()

# Reuse the existing Gemini client setup from your project
client, MODEL_CANDIDATES = make_client()


class ChatbotEngine:
    def __init__(self):
        self.system_instructions = """
You are TRINETRA, a specialized cybersecurity assistant for the Indian public.
Your goal is to protect the user from scams and cyber threats.

IMPORTANT RULES:
1. You are NOT a general-purpose AI. You ONLY answer cybersecurity and scam-related questions.
2. If the user asks about anything unrelated to scams, security, or the specific threats provided, politely decline and remind them you are a security assistant.
3. NEVER ask for or accept sensitive information like OTPs, passwords, or full bank details.
4. Be concise, direct, and actionable. 
5. CRITICAL: Keep your response extremely brief (under 4 sentences). Do not use markdown headers or long bulleted lists. Just give the direct answer.
6. Tailor your advice to the user's community (Students, Senior Citizens, Small Businesses, or General Public).
"""

    def _get_active_threats_context(self, community):
        """Fetch recent verified threats to give the AI context (RAG)."""
        threats = []
        try:
            all_ids = list_documents("threat_intelligence") or []
            for tid in all_ids:
                doc = get_document("threat_intelligence", tid)
                if not isinstance(doc, dict):
                    continue

                comms = doc.get("communities", [])
                if community not in comms:
                    continue

                if not doc.get("verified", False):
                    continue

                simplified = doc.get("simplified", {})
                threats.append({
                    "title": simplified.get("title", doc.get("threat_type", "Threat")),
                    "description": simplified.get("what_happened", "No description.")
                })

                if len(threats) >= 2: # Reduced to 2 to save prompt tokens
                    break
        except Exception as e:
            print(f"[chatbot_engine] Context fetch failed: {e}")

        if not threats:
            return "No specific active threats currently listed for this community."

        return "\n".join([f"- {t['title']}: {t['description']}" for t in threats])

    def _get_rule_based_fallback(self, user_message, community):
        """Simple keyword-based fallback if the AI fails."""
        msg = user_message.lower()

        if "otp" in msg or "pin" in msg or "password" in msg:
            return "⚠️ Never share your OTP, PIN, or password with anyone. Banks and official companies will never ask for this. Hang up or delete the message immediately."

        if "internship" in msg or "job" in msg or "selected" in msg:
            return "⚠️ This may be a job scam. Legitimate employers do not ask for registration fees or payment via WhatsApp. Verify the company independently before paying anything."

        if "bank" in msg or "account blocked" in msg or "kyc" in msg:
            return "⚠️ This is a common scam pattern. Do not click links in SMS or share details over the phone. Contact your bank using the official number on the back of your card."

        if "upi" in msg or "refund" in msg:
            return "⚠️ UPI scams often involve 'collect requests' disguised as refunds. Remember: You only enter your PIN to SEND money, never to receive it."

        if "report" in msg or "complain" in msg:
            return "You can report cyber fraud in India by calling the national helpline at 1930 or visiting cybercrime.gov.in."

        return "I can help you identify scams. If you received a suspicious message or call, describe it here. Never share OTPs or bank details."

    def generate_response(self, user_message, community):
        """Main entry point. Returns a dict with the reply."""
        if not user_message or not user_message.strip():
            return {"reply": "Please ask a question or describe a situation.", "error": False}

        community = community or "General Public"
        context = self._get_active_threats_context(community)

        prompt = f"""
        SYSTEM INSTRUCTIONS:
        {self.system_instructions}
        
        USER CONTEXT:
        - Community: {community}
        - Active Threats: {context}

        USER MESSAGE:
        "{user_message}"

        RESPONSE:
        """

        print(f"[chatbot] Sending prompt to Gemini for community: {community}")

        for model_name in MODEL_CANDIDATES:
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config={"tools": []}
                )
                
                reply_text = response.text.strip()
                print(f"[chatbot] ✓ Success with model {model_name}")
                return {"reply": reply_text, "error": False}
                
            except Exception as e:
                print(f"[chatbot] ✗ Model {model_name} failed: {e}")

        print("[chatbot] All models failed. Using rule-based fallback.")
        fallback = self._get_rule_based_fallback(user_message, community)
        return {"reply": fallback, "error": True}