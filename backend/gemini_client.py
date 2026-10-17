# ============================================================
# GEMINI CLIENT HELPER
# ============================================================
# Creates a genai.Client and returns a PRIORITY-ORDERED list
# of generateContent models the API key can access.
#
# Why:
#   Google retires Gemini models frequently. Hardcoding
#   "gemini-3.6-flash" works today and 404s tomorrow. This
#   module asks the API which models exist and returns them
#   in preference order.
#
#   Newer models occasionally return 503 UNAVAILABLE when
#   demand spikes. Callers should try each model in order
#   and fall back to the next when one is overloaded.
#
#   Some models expose "flash" in the name but are NOT text
#   generation models (-tts, -image, -vision, -audio). They
#   reject JSON-mode requests with 400 INVALID_ARGUMENT. We
#   filter those out up front.
# ============================================================

from __future__ import annotations

import os

from dotenv import load_dotenv
from google import genai

load_dotenv()


# ------------------------------------------------------------
# Fallback chain
# ------------------------------------------------------------
# Used in two cases:
#   1. The live model listing fails (network error, permissions)
#   2. As the tail of the priority list so callers always have
#      something to try even if the live list is short
#
# This list is hand-curated to exclude non-text variants.
# ------------------------------------------------------------
FALLBACK_MODELS = [
    "gemini-flash-latest",
    "gemini-3.8-flash",
    "gemini-3.7-flash",
    "gemini-3.6-flash",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.0-flash",
    "gemini-2.5-flash",
    "gemini-2.0-flash",
]


# ------------------------------------------------------------
# Model name fragments we never want for JSON text tasks.
# Matching is substring-based on the lowercased model name.
# ------------------------------------------------------------
EXCLUDED_MODEL_FRAGMENTS = (
    "-tts",
    "-image",
    "-vision",
    "-embedding",
    "-embed",
    "-audio",
    "-video",
    "-live",
)


def _is_text_model(name: str) -> bool:
    """True if the model name looks like a text-generation model."""
    name_lower = name.lower()
    return not any(frag in name_lower for frag in EXCLUDED_MODEL_FRAGMENTS)


def _score_model(name: str) -> tuple:
    """
    Score a model name so we can pick the best one.

    Higher score = preferred.

    Preference order:
      1. Contains "flash"       (fast and cheap)
      2. Higher version number  (3.8 > 3.5 > 2.5 > 2.0)
      3. Not preview / exp      (stable releases first)
      4. Shorter name           (mainline over dated snapshots)

    Examples:
        "gemini-3.8-flash"        → (1, 3.8,  0, -16)
        "gemini-3.5-flash-lite"   → (1, 3.5,  0, -21)
        "gemini-2.5-flash-preview"→ (1, 2.5, -1, -25)
        "gemini-3.6-pro"          → (0, 3.6,  0, -14)
    """
    name_lower = name.lower()

    has_flash  = 1 if "flash" in name_lower else 0
    is_preview = -1 if any(x in name_lower for x in ["preview", "exp"]) else 0

    # Extract version like "3.8" or "2.5" from the name
    version = 0.0
    for token in name_lower.replace("/", " ").replace("-", " ").split():
        try:
            version = max(version, float(token))
        except ValueError:
            continue

    # Prefer shorter names (mainline over dated snapshots)
    length_penalty = -len(name)

    return (has_flash, version, is_preview, length_penalty)


def list_available_models(client) -> list[str]:
    """
    Return a priority-sorted list of generateContent flash
    models available to this API key.

    Filters out non-text variants (-tts, -image, -vision, ...)
    so callers never waste a request on a model that rejects
    JSON mode.

    Falls back to FALLBACK_MODELS if the live listing fails
    or returns nothing useful.
    """
    candidates: list[str] = []

    try:
        for m in client.models.list():
            name = getattr(m, "name", "") or ""

            # Strip the "models/" prefix the SDK adds
            if name.startswith("models/"):
                name = name[len("models/"):]

            # Skip non-text variants (-tts, -image, ...)
            if not _is_text_model(name):
                continue

            # Only keep models that support generateContent
            actions = getattr(m, "supported_actions", None) or []
            actions_lower = [a.lower() for a in actions]
            if actions and "generatecontent" not in actions_lower:
                continue

            if "flash" in name.lower():
                candidates.append(name)

        candidates.sort(key=_score_model, reverse=True)

        if candidates:
            print(f"[gemini_client] Live model listing succeeded:")
            print(f"[gemini_client]   Top picks: {candidates[:5]}")
            if len(candidates) > 5:
                print(f"[gemini_client]   Also available: {candidates[5:10]}")
        else:
            print("[gemini_client] No usable flash models found in live listing")

    except Exception as e:
        print(f"[gemini_client] Model listing failed: {type(e).__name__}: {e}")
        print("[gemini_client] Falling back to hardcoded list")

    # Append the hardcoded chain so callers always have options.
    # The hardcoded list is curated to exclude non-text variants.
    for name in FALLBACK_MODELS:
        if name not in candidates:
            candidates.append(name)

    return candidates


def pick_models(client) -> list[str]:
    """
    Return a priority-ordered list of model names to try.

    Order:
      1. GEMINI_MODEL from .env (if set) — highest priority.
         Use this to pin a specific model and skip auto-pick.
      2. Live models the API key can access (sorted by score,
         non-text variants already excluded).
      3. Hardcoded FALLBACK_MODELS appended to guarantee
         there are always options to fall back to.
    """
    env_model = os.getenv("GEMINI_MODEL", "").strip()

    models = list_available_models(client)

    if env_model:
        # Make sure the env override is first
        models = [env_model] + [m for m in models if m != env_model]
        print(f"[gemini_client] GEMINI_MODEL from .env pinned first: {env_model}")
    elif models:
        print(f"[gemini_client] Primary model:    {models[0]}")
        if len(models) > 1:
            print(f"[gemini_client] Fallback models:  {models[1:5]}")
            if len(models) > 5:
                print(f"[gemini_client] Further options:  {models[5:10]}")

    return models


def make_client():
    """
    Create a genai.Client and return (client, models_list).

    The models_list is priority-ordered and already filtered
    to exclude non-text variants. Callers should try each in
    order and fall back when one returns 503.

    Reads GEMINI_API_KEY from environment (or .env).

    Returns:
        (client, models_list) where models_list is a non-empty
        list of model names, best first.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY not found in environment or .env")

    client = genai.Client(api_key=api_key)
    models = pick_models(client)
    return client, models