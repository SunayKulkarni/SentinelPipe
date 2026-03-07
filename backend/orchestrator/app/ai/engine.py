"""
AI Decision Engine — wraps Gemini API to decide the next analyzer in the pipeline loop.

Given the output of the most recent analyzer pass, returns:
  { "next_tool": str | None, "reasoning": str }

Implements a three-tier fallback for large/noisy analyzer outputs:
  1. Use raw_output directly if ≤ 4000 chars
  2. Grep keywords.txt matches from the output
  3. Truncate raw_output to 4000 chars
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from google import genai
from google.genai import types

log = logging.getLogger("secflow.ai_engine")

ANALYZER_NAMES = ["malware", "steg", "recon", "web"]
KEYWORDS_FILE = Path(__file__).parent / "keywords.txt"
MAX_CONTEXT_CHARS = 4000

_client: genai.Client | None = None


def _get_client() -> genai.Client:
    global _client
    if _client is None:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY environment variable is not set")
        _client = genai.Client(api_key=api_key)
    return _client


def _load_keywords() -> list[str]:
    if KEYWORDS_FILE.exists():
        return [
            line.strip()
            for line in KEYWORDS_FILE.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
    return []


def _grep_keywords(text: str, keywords: list[str]) -> str:
    """Return lines from text containing any keyword (case-insensitive)."""
    matched: list[str] = []
    for line in text.splitlines():
        if any(kw.lower() in line.lower() for kw in keywords):
            matched.append(line)
    return "\n".join(matched)


def _build_context(raw_output: str) -> str:
    """Select the best context string to pass to Gemini."""
    if len(raw_output) <= MAX_CONTEXT_CHARS:
        return raw_output

    keywords = _load_keywords()
    if keywords:
        grepped = _grep_keywords(raw_output, keywords)
        if grepped:
            return grepped[:MAX_CONTEXT_CHARS]

    return raw_output[:MAX_CONTEXT_CHARS]


def _build_prompt(
    analyzer_output: dict[str, Any],
    pass_number: int,
    max_passes: int,
    context_text: str,
) -> str:
    current_tool = analyzer_output["analyzer"]
    available = [a for a in ANALYZER_NAMES if a != current_tool]
    findings_count = len(analyzer_output.get("findings", []))
    risk_score = analyzer_output.get("risk_score", 0)

    return f"""You are a cybersecurity analysis AI assistant for SecFlow, an automated threat analysis pipeline.

A **{current_tool}** analyzer just completed pass {pass_number} of {max_passes}.
Findings count: {findings_count}  |  Risk score: {risk_score}/10

=== Analyzer output (summary/excerpt) ===
{context_text}
==========================================

Available next analyzers: {available}

Routing guidance:
- If findings include an extracted binary, executable, or payload file → "malware"
- If findings include a URL or HTTP endpoint to investigate → "web"
- If findings include an IP address or domain name → "recon"
- If findings include an image file → "steg"
- If there is nothing meaningful to investigate further → null
- If max passes have been (nearly) reached and no strong leads → null

Respond ONLY with a JSON object in this exact format (no markdown, no extra text):
{{
  "next_tool": "<one of: malware, steg, recon, web, or null>",
  "reasoning": "<one concise sentence explaining the decision>"
}}
"""


def decide_next(
    analyzer_output: dict[str, Any],
    pass_number: int,
    max_passes: int,
) -> dict[str, str | None]:
    """
    Given the output of the most recent analyzer, return the next routing decision.

    Returns:
        { "next_tool": str | None, "reasoning": str }
        next_tool is None when the loop should terminate.
    """
    raw_output = analyzer_output.get("raw_output", "")
    context = _build_context(raw_output)
    prompt = _build_prompt(analyzer_output, pass_number, max_passes, context)

    try:
        client = _get_client()
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.1,
                max_output_tokens=256,
            ),
        )
        text = response.text.strip()

        # Strip markdown code fences if Gemini wraps in ```json ... ```
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)

        result = json.loads(text)

        next_tool = result.get("next_tool")
        # Accept only known names or explicit null/None
        if next_tool not in ANALYZER_NAMES + [None, "null"]:
            log.warning(f"Gemini returned unknown tool '{next_tool}' — treating as null")
            next_tool = None
        if next_tool == "null":
            next_tool = None

        return {
            "next_tool": next_tool,
            "reasoning": result.get("reasoning", ""),
        }

    except json.JSONDecodeError as e:
        log.error(f"Gemini returned non-JSON response: {e}")
        return {"next_tool": None, "reasoning": f"JSON parse error — terminating: {e}"}
    except Exception as e:
        log.error(f"AI decision engine error: {e}")
        return {"next_tool": None, "reasoning": f"AI engine error — terminating: {e}"}
