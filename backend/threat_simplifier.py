# ============================================================
# THREAT SIMPLIFIER (Module 5)
# ============================================================
# Takes structured threat intelligence (Module 4 output) and
# produces plain-language guidance for the frontend.
#
# Three ways to simplify:
#   1. AI via Gemini SDK  - simplify_with_ai(client, model)
#   2. AI via HTTP        - simplify() when provider is set
#   3. Rule-based fallback - always available, never crashes
#
# Canonical output (STEP 4.2):
#   title, what_happened, who_is_affected,
#   how_attack_works, how_to_identify, what_to_do
#
# Backwards compatible with the original module - all old keys
# and methods still work.
# ============================================================

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime

from pydantic import BaseModel


# ============================================================
# PYDANTIC SCHEMA (STEP 4.3 / 4.4)
# ------------------------------------------------------------
# This forces Gemini to return exactly these six fields when
# we pass it as `response_schema=` in the Gemini SDK.
# ============================================================
class SimplifiedThreat(BaseModel):
    title: str
    what_happened: str
    who_is_affected: list[str]
    how_attack_works: str
    how_to_identify: list[str]
    what_to_do: list[str]


# ------------------------------------------------------------
# CONFIG (from environment variables - all optional)
# ------------------------------------------------------------
DEFAULT_PROVIDER = os.getenv("THREAT_AI_PROVIDER", "none").strip().lower()
DEFAULT_API_KEY = (
    os.getenv("THREAT_AI_API_KEY")
    or os.getenv("OPENAI_API_KEY")
    or os.getenv("GEMINI_API_KEY")
    or ""
).strip()
DEFAULT_MODEL = os.getenv("THREAT_AI_MODEL", "").strip()
DEFAULT_BASE_URL = os.getenv("THREAT_AI_BASE_URL", "").strip()
DEFAULT_TIMEOUT = float(os.getenv("THREAT_AI_TIMEOUT", "20"))
DEFAULT_RETRIES = int(os.getenv("THREAT_AI_MAX_RETRIES", "2"))
CACHE_TTL_SECONDS = int(os.getenv("THREAT_AI_CACHE_TTL", "900"))

PROVIDER_DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "gemini": "gemini-1.5-flash",
    "ollama": "llama3.1",
}

PROVIDER_DEFAULT_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "gemini": "https://generativelanguage.googleapis.com/v1beta",
    "ollama": "http://localhost:11434",
}


# ------------------------------------------------------------
# Allowed communities (matches community_rules.py)
# ------------------------------------------------------------
SUPPORTED_COMMUNITIES = [
    "Students",
    "Senior Citizens",
    "Small Businesses",
    "General Public",
]


# ------------------------------------------------------------
# Fallback content per threat type (used when AI is off)
# ------------------------------------------------------------
FALLBACK_LIBRARY = {
    "Phishing": {
        "what_happened": "Scammers are sending fake messages or emails to trick people into giving away passwords, OTPs or bank details.",
        "how_attack_works": "The attacker sends a message that looks like it comes from a trusted company and asks the victim to click a link or share personal information.",
        "how_to_identify": [
            "Unexpected messages asking you to act urgently",
            "Links that look almost right but have small spelling changes",
            "Requests for passwords, OTPs, PINs or card details",
            "Generic greetings like \"Dear Customer\"",
        ],
        "what_to_do": [
            "Do not click links or open attachments in the message",
            "Verify the sender through an official phone number or website",
            "Never share passwords, OTPs or bank details",
            "Report the message to the real company and to your bank",
        ],
    },
    "Malware": {
        "what_happened": "Harmful software is being spread to damage devices or steal information from them.",
        "how_attack_works": "The attacker hides the harmful software inside a fake download, attachment or link, and it installs itself when the victim opens it.",
        "how_to_identify": [
            "Your device suddenly becomes slow or starts crashing",
            "New toolbars, pop-ups or apps you did not install",
            "Antivirus or system updates turn off by themselves",
            "Files get renamed, encrypted or disappear",
        ],
        "what_to_do": [
            "Do not open attachments or links from unknown senders",
            "Install apps only from official app stores",
            "Keep your operating system and antivirus updated",
            "Disconnect from the internet and run a full scan if infected",
        ],
    },
    "Ransomware": {
        "what_happened": "A type of malware is locking people's files and demanding payment to unlock them.",
        "how_attack_works": "The attacker gains access to a device, encrypts the files and leaves a ransom note demanding money to restore access.",
        "how_to_identify": [
            "Your files are locked and renamed with odd extensions",
            "A ransom note appears on screen or in every folder",
            "You cannot open documents, photos or spreadsheets",
            "A countdown timer appears with a payment demand",
        ],
        "what_to_do": [
            "Do not pay the ransom - it does not guarantee recovery",
            "Disconnect the infected device from the network immediately",
            "Restore your files from a recent clean backup",
            "Report the incident to your local cybercrime helpline",
        ],
    },
    "Identity Theft": {
        "what_happened": "Someone is using another person's personal information to commit fraud or open fake accounts.",
        "how_attack_works": "The attacker collects personal details through phishing, data leaks or stolen documents and then uses them to impersonate the victim.",
        "how_to_identify": [
            "Bills or statements for accounts you never opened",
            "Credit report shows loans or cards you do not recognise",
            "OTP or verification messages you did not request",
            "Calls from debt collectors about unknown debts",
        ],
        "what_to_do": [
            "Report the fraud to your bank and the police immediately",
            "Freeze your credit so new accounts cannot be opened",
            "Change passwords on all important accounts",
            "Check your bank and credit statements every month",
        ],
    },
    "Financial Fraud": {
        "what_happened": "Scammers are trying to steal money through fake payments, fake refunds or fake investment offers.",
        "how_attack_works": "The attacker builds trust with the victim and then asks for money, card details or a bank transfer that never goes to a real business.",
        "how_to_identify": [
            "You are asked to pay or transfer money urgently",
            "Payment details are requested over chat, email or phone",
            "Someone pressures you to keep the deal secret",
            "The offer is far better than anything else in the market",
        ],
        "what_to_do": [
            "Never transfer money under pressure",
            "Verify the receiver through an official channel",
            "Do not share card details, CVV or OTPs",
            "Report the fraud to your bank and cybercrime helpline",
        ],
    },
    "Job Scam": {
        "what_happened": "Scammers are posting fake job offers to steal money or personal information from job seekers.",
        "how_attack_works": "The attacker posts a fake job advertisement and asks the victim to pay a registration fee or share personal documents.",
        "how_to_identify": [
            "You are hired without any real interview",
            "You must pay a fee for training, kit or registration",
            "Salary is offered for almost no work",
            "Communication happens only on WhatsApp or Telegram",
        ],
        "what_to_do": [
            "Verify the employer through their official website",
            "Do not pay any fee to get a job",
            "Do not share Aadhaar, PAN or bank details with unknown recruiters",
            "Report the fake job posting to the platform",
        ],
    },
    "Investment Scam": {
        "what_happened": "Scammers are promising fake high-return investments to steal money from people.",
        "how_attack_works": "The attacker shows a fake profit dashboard, encourages small deposits, then blocks withdrawals once the victim invests more.",
        "how_to_identify": [
            "Guaranteed high returns with no risk",
            "You are pushed to invest fast before the offer closes",
            "Withdrawals keep getting blocked or delayed",
            "The app or website has no real company details",
        ],
        "what_to_do": [
            "Check if the company is registered with SEBI or RBI",
            "Never invest based on WhatsApp or Telegram tips",
            "Do not share bank or UPI details with unknown apps",
            "Report the scam to the cybercrime helpline",
        ],
    },
    "Social Engineering": {
        "what_happened": "Someone is manipulating people into giving away information or access by pretending to be someone they trust.",
        "how_attack_works": "The attacker pretends to be IT support, a bank official or the police and creates urgency so the victim acts without thinking.",
        "how_to_identify": [
            "Someone claims to be from IT support, bank or police",
            "They already know some of your personal details",
            "They ask you to keep the conversation private",
            "They create panic or urgency to make you act fast",
        ],
        "what_to_do": [
            "Hang up and call the organisation back on its official number",
            "Never share OTPs or passwords over the phone",
            "Do not install remote-access apps on request",
            "Report the call to the cybercrime helpline",
        ],
    },
    "Data Breach": {
        "what_happened": "Personal information of many people has been leaked from a company's system.",
        "how_attack_works": "Attackers break into a company's database and copy user information such as emails, passwords or phone numbers.",
        "how_to_identify": [
            "You are told your data was exposed in a breach",
            "You suddenly get more spam, calls or login alerts",
            "Password reset emails you did not request",
            "Accounts get locked out without explanation",
        ],
        "what_to_do": [
            "Change your password on the affected site immediately",
            "Use a different password for every account",
            "Turn on two-factor authentication everywhere",
            "Watch your bank statements for unusual activity",
        ],
    },
    "Account Takeover": {
        "what_happened": "Someone has gained unauthorised access to a person's online account.",
        "how_attack_works": "The attacker steals login credentials through phishing or a leaked password and then logs in as the victim.",
        "how_to_identify": [
            "You are logged out of accounts you were using",
            "Password or email change alerts arrive unexpectedly",
            "Friends receive strange messages from your account",
            "New devices appear in your account activity list",
        ],
        "what_to_do": [
            "Change your password immediately from a trusted device",
            "Turn on two-factor authentication",
            "Log out of all devices from the account settings",
            "Warn your contacts that your account was compromised",
        ],
    },
    "Cyberbullying": {
        "what_happened": "Someone is using the internet to harass, threaten or embarrass another person.",
        "how_attack_works": "The attacker sends repeated hurtful messages, shares private content or creates fake profiles to target the victim online.",
        "how_to_identify": [
            "Repeated hurtful or threatening messages",
            "Fake profiles created to harass someone",
            "Private photos or chats shared without permission",
            "Being excluded or ganged up on in online groups",
        ],
        "what_to_do": [
            "Do not reply to the bully - save the evidence",
            "Block and report the account on the platform",
            "Tell a trusted adult, friend or family member",
            "Report serious threats to the police",
        ],
    },
    "Other": {
        "what_happened": "A cyber threat has been reported that may affect people in your area.",
        "how_attack_works": "The attacker uses a common online trick such as a fake message, link or call to target the victim.",
        "how_to_identify": [
            "Anything that feels urgent, secret or too good to be true",
            "Requests for money, passwords or personal details",
            "Unknown links, attachments or QR codes",
            "Pressure to act immediately without checking",
        ],
        "what_to_do": [
            "Slow down and verify before acting",
            "Do not share passwords, OTPs or bank details",
            "Report suspicious activity to the cybercrime helpline",
            "Keep your devices and apps updated",
        ],
    },
}


class ThreatSimplifier:
    """Simplifies complex threat intelligence for frontend display."""

    # --------------------------------------------------------
    # INIT
    # --------------------------------------------------------
    def __init__(
        self,
        provider: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        timeout: float | None = None,
        max_retries: int | None = None,
        cache_ttl: int | None = None,
    ):
        self.provider = (provider or DEFAULT_PROVIDER or "none").strip().lower()
        self.api_key = (api_key if api_key is not None else DEFAULT_API_KEY) or ""
        self.model = (
            model or DEFAULT_MODEL or PROVIDER_DEFAULT_MODELS.get(self.provider, "")
        )
        self.base_url = (
            base_url
            or DEFAULT_BASE_URL
            or PROVIDER_DEFAULT_BASE_URLS.get(self.provider, "")
        )
        self.timeout = float(timeout if timeout is not None else DEFAULT_TIMEOUT)
        self.max_retries = int(
            max_retries if max_retries is not None else DEFAULT_RETRIES
        )
        self.cache_ttl = int(cache_ttl if cache_ttl is not None else CACHE_TTL_SECONDS)

        self.ai_enabled = self.provider in ("openai", "gemini", "ollama") and (
            self.provider == "ollama" or bool(self.api_key)
        )

        self.last_error: str | None = None
        self._cache: dict[str, tuple[float, dict]] = {}
        self.stats = {"ai_calls": 0, "ai_success": 0, "ai_failures": 0, "cache_hits": 0}

        # Icon maps (unchanged from original)
        self.severity_icons = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢",
        }
        self.community_icons = {
            "Students": "🎓",
            "Senior Citizens": "👴",
            "Small Businesses": "🏢",
            "General Public": "👥",
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
            "Other": "⚠️",
        }

    # ========================================================
    # PROMPT BUILDERS (STEP 5.3)
    # --------------------------------------------------------
    # create_simplification_prompt() accepts EITHER a
    # structured intelligence dict (used by simplify_with_ai)
    # OR a plain text threat description (STEP 6.10 example).
    # ========================================================
    def create_simplification_prompt(self, threat_input) -> str:
        """
        Create the AI prompt for Module 5.

        Accepts EITHER:
          - a structured intelligence dict (from Module 4), or
          - a plain text threat description (string).

        This keeps the name stable while supporting both flows.
        """
        if isinstance(threat_input, dict):
            return self._build_intelligence_prompt(threat_input)
        return self._build_text_prompt(str(threat_input or "").strip())

    def _build_text_prompt(self, threat_description: str) -> str:
        """
        STEP 5.4 / 5.5
        Prompt used when we only have a plain text threat
        description (no pre-classified communities).

        Instructions come FIRST, output format SECOND,
        actual threat LAST.
        """
        prompt = f"""
You are a cybersecurity threat simplification assistant.

Your job is to convert technical cybersecurity threat
information into simple language that ordinary people
can understand.

Do not remove important security information.

Avoid unnecessary technical jargon.

Explain the threat clearly and practically.

Return ONLY valid JSON.

The JSON must contain:

{{
    "title": "",
    "what_happened": "",
    "who_is_affected": [],
    "how_attack_works": "",
    "how_to_identify": [],
    "what_to_do": []
}}

Rules:

1. what_happened:
   Explain what the threat is in simple language.

2. who_is_affected:
   List the communities likely to be affected.

3. how_attack_works:
   Explain how the attacker carries out the attack
   in simple terms.

4. how_to_identify:
   Give practical warning signs.

5. what_to_do:
   Give practical safety actions.

6. Do not invent facts that are not supported by
   the threat description.

7. Keep the language understandable to a student,
   senior citizen, or ordinary internet user.

Threat description:

{threat_description}
"""
        return prompt

    def _build_intelligence_prompt(self, intelligence: dict) -> str:
        """
        Prompt used when we already have structured intelligence
        with communities classified by Module 4 (used by
        simplify_with_ai() when a dict is passed).
        """
        return f"""
You are TRINETRA's Threat Simplification Assistant.

Your task is to convert technical cybersecurity
threat intelligence into simple language that an
ordinary internet user can understand.

The user may be:
- a student
- a senior citizen
- a small business owner
- a member of the general public

Do not use unnecessary technical jargon.

Do not invent information.

Only use information supported by the provided
threat intelligence.

IMPORTANT:
The communities have already been classified by
TRINETRA's Community Classification Module.

Use those communities when generating
who_is_affected.

Return ONLY valid JSON using exactly this structure:

{{
    "title": "",
    "what_happened": "",
    "who_is_affected": [],
    "how_attack_works": "",
    "how_to_identify": [],
    "what_to_do": []
}}

FIELD RULES:

title:
Give the threat a short, easy-to-understand name.

what_happened:
Explain what happened in simple language.

who_is_affected:
Use the communities already identified by TRINETRA.

how_attack_works:
Explain how the attack happens step-by-step
in simple language.

how_to_identify:
Provide practical warning signs that a person
can recognize.

what_to_do:
Provide practical actions the user should take
to stay safe.

Keep the explanation concise and understandable.

Existing TRINETRA intelligence:

Threat Type:
{intelligence.get("threat_type", "Unknown")}

Target:
{intelligence.get("target", [])}

Platform:
{intelligence.get("platform", [])}

Severity:
{intelligence.get("severity", "Unknown")}

Region:
{intelligence.get("region", "Unknown")}

Keywords:
{intelligence.get("keywords", [])}

Indicators:
{intelligence.get("indicators", [])}

Recommended Actions:
{intelligence.get("recommended_actions", [])}

Communities:
{intelligence.get("communities", [])}
"""

    # ========================================================
    # GEMINI SDK SIMPLIFICATION  (STEP 6.3)
    # --------------------------------------------------------
    # Called from ai_engine.py with a live genai.Client.
    # Uses the Pydantic schema SimplifiedThreat so Gemini
    # is forced to return exactly the six canonical fields.
    #
    # Accepts EITHER a plain text threat description (str)
    # OR a structured intelligence dict from Module 4.
    #
    # Accepts EITHER a single model name (str) OR a list of
    # model names. If given a list, tries each in order,
    # skipping overloaded (503) and JSON-incompatible (400)
    # models automatically.
    # ========================================================
    def simplify_with_ai(
        self,
        threat_input,
        client,
        model_name: str | list[str] = "gemini-1.5-flash",
    ) -> dict:
        """
        Module 5:
        Send the threat description to Gemini and
        receive structured simplified JSON.

        Args:
            threat_input: Either a plain text threat description
                          (str) or a structured intelligence dict
                          from Module 4.
            client:       A live `google.genai.Client` instance.
            model_name:   Gemini model name (str) or a priority-
                          ordered list of names to try in order.

        Returns:
            dict with the six canonical fields.
            On any error, falls back to the rule-based block
            so the caller never crashes.
        """
        if not threat_input:
            return self._rule_based_block({})

        # Normalize model_name to a list of candidates
        if isinstance(model_name, str):
            model_candidates = [model_name]
        else:
            model_candidates = list(model_name or [])

        # Deduplicate while preserving order
        seen: set[str] = set()
        model_candidates = [
            m for m in model_candidates
            if m and not (m in seen or seen.add(m))
        ]
        if not model_candidates:
            model_candidates = ["gemini-flash-latest"]

        # Build the prompt (dispatcher handles str or dict)
        prompt = self.create_simplification_prompt(threat_input)

        print()
        print("Sending threat to Gemini for simplification...")

        last_error: Exception | None = None

        for model_idx, current_model in enumerate(model_candidates):
            print(f"  Trying model: {current_model}")

            try:
                response = client.models.generate_content(
                    model=current_model,
                    contents=prompt,
                    config={
                        "response_mime_type": "application/json",
                        "response_schema": SimplifiedThreat,
                    },
                )

                result = SimplifiedThreat.model_validate_json(response.text)
                block = result.model_dump()

                # Sanitise communities so who_is_affected only contains
                # valid values from SUPPORTED_COMMUNITIES.
                if isinstance(threat_input, dict):
                    fallback_communities = [
                        c for c in (threat_input.get("communities") or [])
                        if c in SUPPORTED_COMMUNITIES
                    ]
                else:
                    fallback_communities = []

                clean_communities = [
                    c for c in (block.get("who_is_affected") or [])
                    if c in SUPPORTED_COMMUNITIES
                ]
                if not clean_communities:
                    clean_communities = fallback_communities or ["General Public"]

                block["who_is_affected"] = clean_communities
                block["ai_used"] = True
                block["ai_provider"] = "gemini"
                block["ai_model"] = current_model
                block["ai_cached"] = False
                block["ai_error"] = None

                print(f"  ✓ Simplification completed (model={current_model})")
                return block

            except Exception as exc:  # noqa: BLE001 - never break the caller
                last_error = exc
                err_str = str(exc)
                err_lower = err_str.lower()

                # 503 / overloaded → move to next model immediately
                if ("503" in err_str
                        or "unavailable" in err_lower
                        or "overloaded" in err_lower
                        or "high demand" in err_lower):
                    print(f"  ✗ {current_model} overloaded (503)")
                    if model_idx < len(model_candidates) - 1:
                        print("  → Trying next model...")
                    continue

                # 400 / invalid argument (e.g. JSON not enabled) →
                # this model will never work for our use case
                if "400" in err_str or "invalid_argument" in err_lower:
                    print(f"  ✗ {current_model} rejected request: {err_str[:140]}")
                    if model_idx < len(model_candidates) - 1:
                        print("  → Trying next model...")
                    continue

                # 404 / not found → skip
                if "404" in err_str or "not_found" in err_lower:
                    print(f"  ✗ {current_model} not available")
                    if model_idx < len(model_candidates) - 1:
                        print("  → Trying next model...")
                    continue

                # Anything else — log and continue to next model
                print(f"  ✗ {current_model} failed: {err_str[:200]}")
                if model_idx < len(model_candidates) - 1:
                    print("  → Trying next model...")

        # All models failed
        print()
        print("=" * 60)
        print("ALL MODELS FAILED for Module 5 — using rule-based fallback")
        print("=" * 60)
        print(f"Last error: {last_error}")

        self.last_error = f"{type(last_error).__name__}: {last_error}" if last_error else "Unknown error"

        if isinstance(threat_input, dict):
            fallback = self._rule_based_block(threat_input)
        else:
            fallback = self._rule_based_block({})
        fallback["ai_error"] = self.last_error
        return fallback

    # ========================================================
    # PUBLIC API
    # ========================================================
    def simplify(self, intelligence: dict, use_ai: bool = True) -> dict:
        """Simplify structured threat intelligence for frontend display."""
        if not intelligence:
            return self._empty_response()

        threat_type = intelligence.get("threat_type", "Unknown")
        severity = intelligence.get("severity", "Medium")
        communities = intelligence.get("communities", ["General Public"]) or [
            "General Public"
        ]
        region = intelligence.get("region", "Unknown")
        recommended_actions = intelligence.get("recommended_actions", []) or []
        primary_community = communities[0] if communities else "General Public"

        simplified = {
            "threat_type": threat_type,
            "threat_type_icon": self.threat_type_icons.get(threat_type, "⚠️"),
            "severity": severity,
            "severity_icon": self.severity_icons.get(severity, "🟡"),
            "severity_level": self._get_severity_level(severity),
            "communities": communities,
            "community_icons": [self.community_icons.get(c, "👥") for c in communities],
            "primary_community": primary_community,
            "primary_community_icon": self.community_icons.get(
                primary_community, "👥"
            ),
            "region": region,
            "simplified_description": self._generate_description(intelligence),
            "quick_actions": recommended_actions[:3] if recommended_actions else [],
            "alert_level": self._get_alert_level(severity),
            "key_indicators": (intelligence.get("indicators") or [])[:3],
            "verified": intelligence.get("verified", False),
            "verified_by": intelligence.get("verified_by", None),
            "simplified_at": datetime.now().isoformat(),
            "threat_id": intelligence.get("threat_id", "Unknown"),
        }

        block = self._ai_simplify(intelligence) if use_ai else None
        if block is None:
            block = self._rule_based_block(intelligence)

        simplified.update(block)
        return simplified

    def simplify_for_frontend(self, intelligence: dict, use_ai: bool = True) -> dict:
        """Alias for simplify()."""
        return self.simplify(intelligence, use_ai=use_ai)

    def simplify_many(self, items: list, use_ai: bool = True) -> list:
        """Simplify a list of intelligence documents."""
        return [self.simplify(item, use_ai=use_ai) for item in (items or [])]

    def get_canonical(self, intelligence: dict, use_ai: bool = True) -> dict:
        """Return ONLY the six canonical frontend fields."""
        full = self.simplify(intelligence, use_ai=use_ai)
        return {
            "title": full.get("title", ""),
            "what_happened": full.get("what_happened", ""),
            "who_is_affected": full.get("who_is_affected", []),
            "how_attack_works": full.get("how_attack_works", ""),
            "how_to_identify": full.get("how_to_identify", []),
            "what_to_do": full.get("what_to_do", []),
        }

    def get_alert_message(self, intelligence: dict) -> str:
        """Short notification message."""
        if not intelligence:
            return "No threat data available."
        severity = intelligence.get("severity", "Medium")
        threat_type = intelligence.get("threat_type", "Unknown")
        communities = intelligence.get("communities", ["General Public"])
        return (
            f"{self.severity_icons.get(severity, '⚠️')} {severity}: {threat_type} "
            f"targeting {', '.join(communities)}"
        )

    def get_community_alert(self, intelligence: dict, community: str | None = None):
        """Community-specific alert."""
        if not intelligence:
            return "No threat data available."

        communities = intelligence.get("communities", ["General Public"])
        target_communities = (
            [community] if community and community in communities else communities
        )
        actions = intelligence.get("recommended_actions", []) or []
        threat_type = intelligence.get("threat_type", "Unknown")
        severity = intelligence.get("severity", "Medium")

        return {
            "alert": f"🚨 {threat_type} Alert",
            "target": target_communities,
            "severity": severity,
            "severity_icon": self.severity_icons.get(severity, "🟡"),
            "actions": actions[:2] if actions else [],
        }

    # ========================================================
    # AI SIMPLIFICATION (HTTP providers - OpenAI / Gemini / Ollama)
    # ========================================================
    def _ai_simplify(self, intelligence: dict) -> dict | None:
        """Ask the LLM for the canonical block. Returns None on any failure."""
        if not self.ai_enabled:
            return None

        cache_key = self._cache_key(intelligence)
        cached = self._cache_get(cache_key)
        if cached is not None:
            self.stats["cache_hits"] += 1
            result = dict(cached)
            result["ai_cached"] = True
            return result

        system_prompt, user_prompt = self._build_prompts(intelligence)
        self.last_error = None
        self.stats["ai_calls"] += 1

        for attempt in range(self.max_retries + 1):
            try:
                raw_text = self._dispatch_llm(system_prompt, user_prompt)
                parsed = self._parse_ai_json(raw_text)
                block = self._sanitize_ai_block(parsed, intelligence)

                if block:
                    block.update(
                        {
                            "ai_used": True,
                            "ai_provider": self.provider,
                            "ai_model": self.model,
                            "ai_cached": False,
                            "ai_error": None,
                        }
                    )
                    self._cache_set(cache_key, block)
                    self.stats["ai_success"] += 1
                    return block

                self.last_error = "AI returned unparsable or empty content"

            except Exception as exc:  # noqa: BLE001
                self.last_error = f"{type(exc).__name__}: {exc}"

            if attempt < self.max_retries:
                time.sleep(0.8 * (attempt + 1))

        self.stats["ai_failures"] += 1
        return None

    def _build_prompts(self, intelligence: dict) -> tuple[str, str]:
        system_prompt = (
            "You are a public-safety cyber threat writer. You turn technical "
            "threat intelligence into short, calm, plain-language guidance for "
            "non-technical people such as students, senior citizens, small "
            "business owners and the general public.\n\n"
            "Rules:\n"
            "- Write at a grade 6-8 reading level. Use short sentences.\n"
            "- Avoid jargon. If a technical term is unavoidable, explain it "
            "in a few simple words.\n"
            "- Never invent facts that are not in the input.\n"
            "- Do not give legal, medical or financial advice.\n"
            "- Be calm and practical, never alarmist.\n"
            "- 'who_is_affected' MUST be chosen ONLY from this list:\n"
            "    Students, Senior Citizens, Small Businesses, General Public.\n"
            "- 'how_to_identify' and 'what_to_do' MUST be JSON arrays of "
            "short strings (3 to 5 items each).\n"
            "- Reply with ONLY a valid JSON object. No markdown, no code "
            "fences, no extra commentary.\n"
        )

        user_prompt = (
            "Threat intelligence from Module 4:\n"
            + json.dumps(intelligence, indent=2, default=str)
            + "\n\n"
            "Return JSON with EXACTLY these six keys and nothing else:\n"
            "{\n"
            '  "title": "short plain name for the threat, max 10 words",\n'
            '  "what_happened": "one simple sentence explaining the threat",\n'
            '  "who_is_affected": ["one or more items from the allowed list"],\n'
            '  "how_attack_works": "one simple sentence explaining the attack",\n'
            '  "how_to_identify": ["3 to 5 short warning signs"],\n'
            '  "what_to_do": ["3 to 5 short action steps"]\n'
            "}\n"
        )
        return system_prompt, user_prompt

    def _dispatch_llm(self, system_prompt: str, user_prompt: str) -> str:
        if self.provider == "openai":
            return self._call_openai(system_prompt, user_prompt)
        if self.provider == "gemini":
            return self._call_gemini(system_prompt, user_prompt)
        if self.provider == "ollama":
            return self._call_ollama(system_prompt, user_prompt)
        raise RuntimeError(f"Unsupported AI provider: {self.provider}")

    def _call_openai(self, system_prompt: str, user_prompt: str) -> str:
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 700,
            "response_format": {"type": "json_object"},
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        data = self._http_post(url, payload, headers)
        return data["choices"][0]["message"]["content"]

    def _call_gemini(self, system_prompt: str, user_prompt: str) -> str:
        url = (
            f"{self.base_url.rstrip('/')}/models/{self.model}:generateContent"
            f"?key={self.api_key}"
        )
        payload = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 700,
                "responseMimeType": "application/json",
            },
        }
        headers = {"Content-Type": "application/json"}
        data = self._http_post(url, payload, headers)
        return data["candidates"][0]["content"]["parts"][0]["text"]

    def _call_ollama(self, system_prompt: str, user_prompt: str) -> str:
        url = f"{self.base_url.rstrip('/')}/api/chat"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.2},
        }
        headers = {"Content-Type": "application/json"}
        data = self._http_post(url, payload, headers)
        return data["message"]["content"]

    def _http_post(self, url: str, payload: dict, headers: dict) -> dict:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
        return json.loads(raw)

    # ========================================================
    # AI OUTPUT PARSING / VALIDATION
    # ========================================================
    def _parse_ai_json(self, raw_text: str) -> dict | None:
        if not raw_text or not isinstance(raw_text, str):
            return None
        text = raw_text.strip()
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        try:
            parsed = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None

    def _sanitize_ai_block(self, data: dict | None, intelligence: dict) -> dict | None:
        if not isinstance(data, dict):
            return None

        title = self._clean_text(data.get("title"), 140)
        what_happened = self._clean_text(data.get("what_happened"), 700)
        how_attack_works = self._clean_text(data.get("how_attack_works"), 700)
        how_to_identify = self._clean_list(
            data.get("how_to_identify"), limit=5, max_len=160
        )
        what_to_do = self._clean_list(data.get("what_to_do"), limit=5, max_len=160)

        who_is_affected = self._clean_list(
            data.get("who_is_affected"), limit=4, max_len=60
        )
        who_is_affected = [c for c in who_is_affected if c in SUPPORTED_COMMUNITIES]
        if not who_is_affected:
            who_is_affected = [
                c
                for c in (intelligence.get("communities") or [])
                if c in SUPPORTED_COMMUNITIES
            ] or ["General Public"]

        if not (title or what_happened or how_attack_works or what_to_do):
            return None

        return {
            "title": title,
            "what_happened": what_happened,
            "who_is_affected": who_is_affected,
            "how_attack_works": how_attack_works,
            "how_to_identify": how_to_identify,
            "what_to_do": what_to_do,
        }

    @staticmethod
    def _clean_text(value, max_len: int = 300) -> str:
        if value is None:
            return ""
        if not isinstance(value, str):
            value = str(value)
        value = re.sub(r"[\x00-\x1f\x7f]+", " ", value)
        value = re.sub(r"\s+", " ", value).strip()
        if len(value) > max_len:
            value = value[: max_len - 1].rstrip() + "…"
        return value

    @classmethod
    def _clean_list(cls, value, limit: int = 5, max_len: int = 160) -> list:
        if value is None:
            return []
        if isinstance(value, str):
            parts = re.split(r"[\n\r]+|(?:^|\s)[-*•]\s+", value)
            items = [p for p in parts if p and p.strip()]
        elif isinstance(value, (list, tuple, set)):
            items = list(value)
        else:
            items = [value]

        cleaned = []
        for item in items:
            text = cls._clean_text(item, max_len)
            if text:
                cleaned.append(text)
            if len(cleaned) >= limit:
                break
        return cleaned

    # ========================================================
    # RULE-BASED FALLBACK
    # ========================================================
    def _rule_based_block(self, intelligence: dict) -> dict:
        threat_type = intelligence.get("threat_type", "Unknown")
        severity = intelligence.get("severity", "Medium")
        communities = intelligence.get("communities", ["General Public"]) or [
            "General Public"
        ]
        region = intelligence.get("region", "Unknown")
        actions = intelligence.get("recommended_actions", []) or []

        who_is_affected = [c for c in communities if c in SUPPORTED_COMMUNITIES]
        if not who_is_affected:
            who_is_affected = ["General Public"]

        lib = FALLBACK_LIBRARY.get(threat_type, FALLBACK_LIBRARY["Other"])

        if threat_type in ("Other", "Unknown"):
            title = f"{severity} Cyber Threat Alert"
        else:
            title = f"{threat_type} targeting {', '.join(who_is_affected)}"
        if region and region != "Unknown":
            title = f"{title} in {region}"
        title = self._clean_text(title, 140)

        if actions:
            what_to_do = self._clean_list(actions, limit=5, max_len=160)
        else:
            what_to_do = list(lib["what_to_do"])

        return {
            "title": title,
            "what_happened": lib["what_happened"],
            "who_is_affected": who_is_affected,
            "how_attack_works": lib["how_attack_works"],
            "how_to_identify": list(lib["how_to_identify"]),
            "what_to_do": what_to_do,
            "ai_used": False,
            "ai_provider": None,
            "ai_model": None,
            "ai_cached": False,
            "ai_error": self.last_error,
        }

    # ========================================================
    # CACHE
    # ========================================================
    def _cache_key(self, intelligence: dict) -> str:
        payload = {
            "id": intelligence.get("threat_id"),
            "type": intelligence.get("threat_type"),
            "severity": intelligence.get("severity"),
            "region": intelligence.get("region"),
            "communities": intelligence.get("communities"),
            "description": intelligence.get("description")
            or intelligence.get("summary"),
            "actions": intelligence.get("recommended_actions"),
            "indicators": intelligence.get("indicators"),
            "model": self.model,
        }
        raw = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _cache_get(self, key: str) -> dict | None:
        entry = self._cache.get(key)
        if not entry:
            return None
        timestamp, value = entry
        if time.time() - timestamp > self.cache_ttl:
            self._cache.pop(key, None)
            return None
        return value

    def _cache_set(self, key: str, value: dict) -> None:
        if len(self._cache) > 256:
            oldest = sorted(self._cache.items(), key=lambda kv: kv[1][0])[:64]
            for old_key, _ in oldest:
                self._cache.pop(old_key, None)
        self._cache[key] = (time.time(), dict(value))

    def clear_cache(self) -> None:
        self._cache.clear()

    # ========================================================
    # HELPERS
    # ========================================================
    def _generate_description(self, intelligence: dict) -> str:
        threat_type = intelligence.get("threat_type", "Unknown")
        communities = intelligence.get("communities", ["General Public"])
        region = intelligence.get("region", "Unknown")
        severity = intelligence.get("severity", "Medium")
        community_str = ", ".join(communities)

        if region and region != "Unknown":
            return (
                f"A {severity.lower()} severity {threat_type} threat targeting "
                f"{community_str} in {region}."
            )
        return (
            f"A {severity.lower()} severity {threat_type} threat targeting "
            f"{community_str}."
        )

    def _get_severity_level(self, severity: str) -> int:
        levels = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        return levels.get(severity, 2)

    def _get_alert_level(self, severity: str) -> str:
        levels = {
            "Low": "info",
            "Medium": "warning",
            "High": "danger",
            "Critical": "critical",
        }
        return levels.get(severity, "info")

    def _empty_response(self) -> dict:
        return {
            # Original keys
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
            "threat_id": "Unknown",
            # Canonical block
            "title": "No threat data available",
            "what_happened": "No threat data available.",
            "who_is_affected": [],
            "how_attack_works": "",
            "how_to_identify": [],
            "what_to_do": [],
            # AI metadata
            "ai_used": False,
            "ai_provider": None,
            "ai_model": None,
            "ai_cached": False,
            "ai_error": None,
        }


# ============================================================
# SELF-TEST  (STEP 7.4)
#   python threat_simplifier.py
# ============================================================
if __name__ == "__main__":

    import json
    import os

    from dotenv import load_dotenv
    from google import genai

    load_dotenv()

    API_KEY = os.getenv("GEMINI_API_KEY")

    if not API_KEY:
        raise ValueError(
            "GEMINI_API_KEY not found in .env"
        )

    client = genai.Client(
        api_key=API_KEY
    )

    MODEL_NAME = "gemini-1.5-flash"

    simplifier = ThreatSimplifier()

    threat = """
    Threat actors are leveraging credential harvesting
    infrastructure to facilitate account takeover through
    adversary-in-the-middle phishing.
    """

    result = simplifier.simplify_with_ai(
        threat,
        client,
        MODEL_NAME
    )

    print()
    print("=" * 60)
    print("MODULE 5 AI RESULT")
    print("=" * 60)
    print()

    print(
        json.dumps(
            result,
            indent=4
        )
    )