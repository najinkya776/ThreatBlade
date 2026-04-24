import re
import json
import requests
from colorama import Fore, Style

CLAUDE_MODELS = [
    {"id": "claude-opus-4-7",           "label": "Claude Opus 4.7 (Most Capable)"},
    {"id": "claude-sonnet-4-6",         "label": "Claude Sonnet 4.6 (Balanced)"},
    {"id": "claude-haiku-4-5-20251001", "label": "Claude Haiku 4.5 (Fastest)"},
]

OPENAI_MODELS = [
    {"id": "gpt-4o",       "label": "GPT-4o (Recommended)"},
    {"id": "gpt-4-turbo",  "label": "GPT-4 Turbo"},
    {"id": "gpt-3.5-turbo","label": "GPT-3.5 Turbo (Budget)"},
]

SYSTEM_PROMPT = """You are a senior SOC analyst with expertise in log analysis, threat hunting, and incident response.
Analyze the provided raw log data and respond ONLY with a valid JSON object in this exact format — no markdown, no explanation, just the JSON:

{
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "summary": "2-3 sentence executive summary of what happened",
  "analysis": "Detailed technical analysis covering: attack patterns identified, timeline of events, affected systems/users, attacker behaviour, and any notable techniques (reference MITRE ATT&CK if applicable)",
  "iocs_found": {
    "ips": ["list of suspicious IP addresses found"],
    "urls": ["list of suspicious URLs found"],
    "domains": ["list of suspicious domains found"],
    "hashes": ["list of file hashes found"],
    "emails": ["list of email addresses found"]
  },
  "recommendations": [
    "Immediate action 1",
    "Immediate action 2",
    "Follow-up action 3"
  ],
  "mitre_techniques": ["T1059 - Command and Scripting Interpreter", "..."]
}

Only include IOCs that appear suspicious or relevant to the incident. Private/internal IPs (10.x, 192.168.x, 172.16-31.x) should only be included if they show signs of compromise."""

# Models that support adaptive thinking
_THINKING_MODELS = {"claude-opus-4-7", "claude-sonnet-4-6"}


def _extract_iocs_regex(text):
    """Fallback regex IOC extraction directly from log text."""
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    url_pattern = r'https?://[^\s\'"<>\])]+'
    hash_pattern = r'\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b'
    email_pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|xyz|ru|cn|tk|top|club|online|site|info|biz|co|uk|de|fr|br|in)\b'

    private = re.compile(r'^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)')

    ips = list({ip for ip in re.findall(ip_pattern, text) if not private.match(ip)})
    urls = list(set(re.findall(url_pattern, text)))
    hashes = list(set(re.findall(hash_pattern, text)))
    emails = list(set(re.findall(email_pattern, text)))
    domains = list({d for d in re.findall(domain_pattern, text)
                    if d not in [u.split('/')[2] for u in urls if '/' in u]})

    return {"ips": ips[:20], "urls": urls[:20], "domains": domains[:20],
            "hashes": hashes[:10], "emails": emails[:10]}


def stream_claude(log_text, model, api_key):
    """Generator yielding (event_type, content) tuples.

    Uses the official Anthropic SDK with:
    - Prompt caching on the system prompt (saves cost/latency on repeated calls)
    - Adaptive thinking for Opus 4.7 and Sonnet 4.6 (deeper reasoning)
    - Streaming so tokens appear in the UI in real time
    """
    import anthropic
    client = anthropic.Anthropic(api_key=api_key)

    # Prompt caching: mark the stable system prompt as cacheable
    system = [
        {
            "type": "text",
            "text": SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }
    ]

    kwargs = {
        "model": model,
        "max_tokens": 8000,
        "system": system,
        "messages": [{"role": "user", "content": f"Analyze this log:\n\n{log_text}"}],
    }

    # Adaptive thinking: deeper analysis for supported models
    if model in _THINKING_MODELS:
        kwargs["thinking"] = {"type": "adaptive"}

    full_text = ""
    try:
        with client.messages.stream(**kwargs) as stream:
            for text in stream.text_stream:
                full_text += text
                yield ("token", text)
        yield ("done", full_text)
    except anthropic.AuthenticationError:
        yield ("error", "Invalid Claude API key.")
    except anthropic.RateLimitError:
        yield ("error", "Claude rate limit hit. Try again shortly.")
    except anthropic.APIError as e:
        yield ("error", f"Claude API error: {e}")


def _call_claude(log_text, model, api_key):
    """Synchronous Claude call (used by CLI path and non-streaming fallback)."""
    full_text = ""
    for event_type, content in stream_claude(log_text, model, api_key):
        if event_type == "token":
            full_text += content
        elif event_type == "error":
            raise ValueError(content)
    return full_text


def _call_openai(log_text, model, api_key):
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Analyze this log:\n\n{log_text}"},
        ],
        "max_tokens": 4096,
        "temperature": 0.2,
    }
    r = requests.post("https://api.openai.com/v1/chat/completions", headers=headers,
                      json=body, timeout=60)
    if r.status_code == 200:
        return r.json()["choices"][0]["message"]["content"]
    elif r.status_code == 401:
        raise ValueError("Invalid OpenAI API key.")
    elif r.status_code == 429:
        raise ValueError("OpenAI rate limit hit. Try again shortly.")
    else:
        raise ValueError(f"OpenAI API error {r.status_code}: {r.text[:200]}")


def _parse_ai_response(raw):
    """Parse JSON from AI response, stripping any markdown code fences."""
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r'\{[\s\S]*\}', raw)
        if match:
            try:
                return json.loads(match.group())
            except Exception:
                pass
        return {"raw_response": raw, "parse_error": True}


def _enrich_iocs(iocs):
    """Run discovered IOCs through existing reputation modules."""
    from modules.reputation import check_virustotal_data, check_abuseipdb_data

    enrichment = {}

    for ip in iocs.get("ips", [])[:5]:
        result = {}
        vt = check_virustotal_data(ip, "ip")
        if "error" not in vt:
            result["virustotal"] = vt
        ab = check_abuseipdb_data(ip)
        if "error" not in ab:
            result["abuseipdb"] = ab
        if result:
            enrichment.setdefault("ips", {})[ip] = result

    for url in iocs.get("urls", [])[:5]:
        vt = check_virustotal_data(url, "url")
        if "error" not in vt:
            enrichment.setdefault("urls", {})[url] = {"virustotal": vt}

    for domain in iocs.get("domains", [])[:5]:
        vt = check_virustotal_data(domain, "domain")
        if "error" not in vt:
            enrichment.setdefault("domains", {})[domain] = {"virustotal": vt}

    for h in iocs.get("hashes", [])[:5]:
        vt = check_virustotal_data(h, "hash")
        if "error" not in vt:
            enrichment.setdefault("hashes", {})[h] = {"virustotal": vt}

    return enrichment


def _build_final_result(raw_text, log_text, provider, model):
    """Parse AI text, merge regex IOCs, enrich, and return final result dict."""
    result = _parse_ai_response(raw_text)

    if result.get("parse_error"):
        result["iocs_found"] = _extract_iocs_regex(log_text)
    else:
        ai_iocs = result.get("iocs_found", {})
        regex_iocs = _extract_iocs_regex(log_text)
        for key in ("ips", "urls", "domains", "hashes", "emails"):
            merged = list(set(ai_iocs.get(key, []) + regex_iocs.get(key, [])))
            ai_iocs[key] = merged
        result["iocs_found"] = ai_iocs

    iocs = result.get("iocs_found", {})
    if any(iocs.get(k) for k in ("ips", "urls", "domains", "hashes")):
        result["enrichment"] = _enrich_iocs(iocs)

    result["provider"] = provider
    result["model"] = model
    return result


def analyze_log(log_text, provider, model, api_key):
    """Main entry for CLI: send log to AI, parse result, enrich IOCs."""
    if not log_text.strip():
        return {"error": "No log data provided."}
    if not api_key:
        return {"error": f"No API key provided for {provider}."}

    try:
        if provider == "claude":
            raw = _call_claude(log_text, model, api_key)
        elif provider == "openai":
            raw = _call_openai(log_text, model, api_key)
        else:
            return {"error": f"Unknown provider: {provider}"}
    except ValueError as e:
        return {"error": str(e)}
    except requests.RequestException as e:
        return {"error": f"Network error: {e}"}

    return _build_final_result(raw, log_text, provider, model)


def get_models():
    return {"claude": CLAUDE_MODELS, "openai": OPENAI_MODELS}
