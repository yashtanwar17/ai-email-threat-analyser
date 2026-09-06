from __future__ import annotations

import json
import os

from google import genai

MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")

SCHEMA = {
    "type": "object",
    "properties": {
        "score": {
            "type": "number",
            "description": "Trustworthiness score from 0 to 10. 10 means highly trustworthy."
        },
        "verdict": {
            "type": "string",
            "enum": ["SAFE", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"]
        },
        "confidence": {
            "type": "number",
            "description": "Confidence from 0 to 1."
        },
        "tags": {"type": "array", "items": {"type": "string"}},
        "executive_summary": {"type": "string"},
        "what_email_is_doing": {"type": "string"},
        "threat_assessment": {"type": "string"},
        "sender_analysis": {"type": "string"},
        "authentication_analysis": {"type": "string"},
        "infrastructure_analysis": {"type": "string"},
        "url_analysis": {"type": "string"},
        "attachment_analysis": {"type": "string"},
        "social_engineering_analysis": {"type": "string"},
        "timeline_and_headers": {"type": "string"},
        "evidence_for_verdict": {"type": "array", "items": {"type": "string"}},
        "red_flags": {"type": "array", "items": {"type": "string"}},
        "benign_signals": {"type": "array", "items": {"type": "string"}},
        "recommended_actions": {"type": "array", "items": {"type": "string"}},
        "technical_details": {"type": "array", "items": {"type": "string"}},
        "limitations": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "score", "verdict", "confidence", "tags", "executive_summary",
        "what_email_is_doing", "threat_assessment", "sender_analysis",
        "authentication_analysis", "infrastructure_analysis", "url_analysis",
        "attachment_analysis", "social_engineering_analysis", "timeline_and_headers",
        "evidence_for_verdict", "red_flags", "benign_signals",
        "recommended_actions", "technical_details", "limitations"
    ]
}

SYSTEM_PROMPT = """You are a senior email threat analyst. Analyze the COMPLETE forensic JSON report supplied by the application.

Rules:
1. Base claims primarily on evidence present in the JSON. Never invent an IOC, location, malware family, sender, authentication result, or user action.
2. Explain exactly what the email appears to be doing, its likely objective, and the attack chain if evidence supports one.
3. Consider headers, Received hops, sender/reply-to/return-path relationships, authentication results, extracted URLs/domains/IPs/hashes, attachments, local tool results, and all API enrichment.
4. Interpret security-tool outputs carefully. A tool being absent, skipped, timed out, or returning an error is not itself proof of safety.
5. For the score: 10 = highly trustworthy; 7-9 = probably benign; 4-6 = uncertain/suspicious; 1-3 = likely malicious; 0 = clearly malicious. Do not inflate confidence when evidence is incomplete.
6. Tags should classify the observed email (examples: phishing, credential theft, invoice scam, BEC, malware delivery, spam, marketing, legitimate notification, extortion, impersonation, suspicious link, malicious attachment). Use only applicable tags.
7. Produce a deep but readable technical analysis for a human analyst. Distinguish direct evidence from reasonable inference.
8. Explicitly mention important negative evidence when relevant (for example, no attachments, no URLs, authentication passed, no malicious verdicts, etc.).
9. A geographic location in the report may represent infrastructure, hosting, an IP geolocation, or another source; do not call it the sender's physical location unless the report explicitly proves that.
10. Do not treat a reputation hit, a geolocation result, or a keyword match alone as conclusive proof of maliciousness. Correlate multiple signals.
"""


def analyze_report(report: dict) -> dict:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not configured.")

    client = genai.Client(api_key=api_key)

    prompt = (
        SYSTEM_PROMPT
        + "\n\nHere is the COMPLETE forensic JSON report. Analyze every field, including nested tool/API results.\n\n"
        + json.dumps(report, ensure_ascii=False, indent=2)
    )

    try:
        # Use the same stable SDK path as the standalone working test.
        # Structured JSON is configured with GenerateContentConfig.
        from google.genai import types

        response = client.models.generate_content(
            model=MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=SCHEMA,
                temperature=0.2,
            ),
        )
    except Exception as exc:
        raise RuntimeError(
            f"Gemini request failed: {type(exc).__name__}: {exc}"
        ) from exc

    text = getattr(response, "text", None)
    if not isinstance(text, str) or not text.strip():
        raise RuntimeError("Gemini returned no text output.")

    try:
        result = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Gemini did not return valid JSON: {text[:1000]}"
        ) from exc

    try:
        result["score"] = max(0.0, min(10.0, float(result.get("score", 0))))
    except (TypeError, ValueError):
        result["score"] = 0.0

    try:
        result["confidence"] = max(0.0, min(1.0, float(result.get("confidence", 0))))
    except (TypeError, ValueError):
        result["confidence"] = 0.0

    result["model"] = MODEL
    return result

