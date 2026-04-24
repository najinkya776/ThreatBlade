import os
import hashlib
import tempfile
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB upload limit


@app.route("/")
def index():
    return render_template("index.html")


# ── Reputation ────────────────────────────────────────────────────────────────

@app.route("/api/reputation", methods=["POST"])
def reputation():
    data = request.json
    ioc = (data.get("ioc") or "").strip()
    ioc_type = data.get("type", "ip")
    if not ioc:
        return jsonify({"error": "No value provided."}), 400

    from modules.reputation import check_virustotal_data, check_abuseipdb_data
    result = {"vt": check_virustotal_data(ioc, ioc_type)}
    if ioc_type == "ip":
        result["abuseipdb"] = check_abuseipdb_data(ioc)
    return jsonify(result)


# ── URL Tools ─────────────────────────────────────────────────────────────────

@app.route("/api/url", methods=["POST"])
def url_tools():
    data = request.json
    action = data.get("action")
    url = (data.get("url") or "").strip()
    text = data.get("text", "")

    from modules.url_tools import (
        sanitize_url, desanitize_url, decode_proofpoint,
        decode_safelinks, decode_base64_url, expand_short_url, extract_urls,
    )

    if action == "sanitize":
        return jsonify({"result": sanitize_url(url)})
    elif action == "desanitize":
        return jsonify({"result": desanitize_url(url)})
    elif action == "proofpoint":
        r = decode_proofpoint(url)
        return jsonify({"result": r} if r else {"error": "Not a recognized ProofPoint URL."})
    elif action == "safelinks":
        r = decode_safelinks(url)
        return jsonify({"result": r} if r else {"error": "Not a recognized SafeLinks URL."})
    elif action == "base64":
        r = decode_base64_url(url)
        return jsonify({"result": r} if r else {"error": "Could not decode as URL."})
    elif action == "expand":
        return jsonify({"result": expand_short_url(url)})
    elif action == "extract":
        urls = extract_urls(text)
        return jsonify({"urls": urls, "count": len(urls)})
    return jsonify({"error": "Unknown action."}), 400


# ── DNS & WHOIS ───────────────────────────────────────────────────────────────

@app.route("/api/dns", methods=["POST"])
def dns():
    data = request.json
    target = (data.get("target") or "").strip()
    lookup_type = data.get("type", "dns")
    if not target:
        return jsonify({"error": "No target provided."}), 400

    from modules.dns_tools import dns_lookup_data, whois_lookup_data, reverse_dns_data

    if lookup_type == "dns":
        return jsonify(dns_lookup_data(target))
    elif lookup_type == "whois":
        return jsonify(whois_lookup_data(target))
    elif lookup_type == "reverse":
        return jsonify(reverse_dns_data(target))
    return jsonify({"error": "Unknown lookup type."}), 400


# ── Hash Tools ────────────────────────────────────────────────────────────────

@app.route("/api/hash/text", methods=["POST"])
def hash_text():
    data = request.json
    text = data.get("text", "")
    from modules.hash_tools import hash_string_data
    return jsonify(hash_string_data(text))


@app.route("/api/hash/check", methods=["POST"])
def hash_check():
    data = request.json
    h = (data.get("hash") or "").strip()
    if not h:
        return jsonify({"error": "No hash provided."}), 400
    from modules.hash_tools import check_hash_virustotal_data
    return jsonify(check_hash_virustotal_data(h))


@app.route("/api/hash/file", methods=["POST"])
def hash_file_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400
    f = request.files["file"]
    check_vt = request.form.get("check_vt") == "true"

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        f.save(tmp.name)
        from modules.hash_tools import hash_file, check_hash_virustotal_data
        hashes = hash_file(tmp.name)
    os.unlink(tmp.name)

    if not hashes:
        return jsonify({"error": "Could not hash file."}), 500

    result = {"filename": f.filename, "hashes": hashes}
    if check_vt:
        result["vt"] = check_hash_virustotal_data(hashes["SHA256"])
    return jsonify(result)


# ── Email Analyzer ────────────────────────────────────────────────────────────

@app.route("/api/email", methods=["POST"])
def analyze_email():
    if "file" not in request.files:
        return jsonify({"error": "No .eml file uploaded."}), 400
    f = request.files["file"]

    import email as email_lib
    from email import policy
    from email.parser import BytesParser
    from modules.email_analyzer import (
        extract_ips, extract_emails_from_text, extract_urls_from_text,
    )

    raw = f.read()
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    headers = {}
    for field in ["From", "To", "Cc", "Reply-To", "Subject", "Date",
                  "Message-ID", "Return-Path", "X-Originating-IP"]:
        v = msg.get(field)
        if v:
            headers[field] = str(v)

    auth = {}
    for field in ["Received-SPF", "DKIM-Signature", "Authentication-Results"]:
        v = msg.get(field)
        if v:
            vl = v.lower()
            auth[field] = "pass" if "pass" in vl else "fail" if "fail" in vl else "unknown"

    body = ""
    attachments = []
    for part in msg.walk():
        ct = part.get_content_type()
        cd = part.get_content_disposition()
        if cd == "attachment":
            attachments.append({
                "name": part.get_filename() or "unknown",
                "type": ct,
                "size": len(part.get_payload(decode=True) or b""),
            })
        elif ct in ("text/plain", "text/html") and cd != "attachment":
            try:
                body += part.get_content() or ""
            except Exception:
                body += (part.get_payload(decode=True) or b"").decode("utf-8", errors="ignore")

    phish_keywords = ["urgent", "verify", "suspended", "account", "click here",
                      "password", "confirm", "invoice", "payment", "alert",
                      "unusual activity", "sign in"]
    found_kw = [k for k in phish_keywords if k in body.lower() or k in headers.get("Subject", "").lower()]

    reply_to = headers.get("Reply-To", "")
    from_addr = headers.get("From", "")
    reply_mismatch = bool(reply_to and reply_to != from_addr)

    return jsonify({
        "headers": headers,
        "auth": auth,
        "urls": extract_urls_from_text(body)[:30],
        "ips": extract_ips(body),
        "emails": extract_emails_from_text(body),
        "attachments": attachments,
        "phishing_keywords": found_kw,
        "reply_mismatch": reply_mismatch,
    })


# ── Breach Check ──────────────────────────────────────────────────────────────

@app.route("/api/breach/email", methods=["POST"])
def breach_email():
    data = request.json
    em = (data.get("email") or "").strip()
    if not em:
        return jsonify({"error": "No email provided."}), 400
    from modules.breach_check import check_hibp_email_data
    return jsonify(check_hibp_email_data(em))


@app.route("/api/breach/domain", methods=["POST"])
def breach_domain():
    data = request.json
    domain = (data.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "No domain provided."}), 400
    from modules.breach_check import check_hibp_domain_data
    return jsonify(check_hibp_domain_data(domain))


@app.route("/api/breach/password", methods=["POST"])
def breach_password():
    data = request.json
    pw = data.get("password", "")
    if not pw:
        return jsonify({"error": "No password provided."}), 400
    from modules.breach_check import check_password_data
    return jsonify(check_password_data(pw))


# ── IP Tools ──────────────────────────────────────────────────────────────────

@app.route("/api/ip", methods=["POST"])
def ip_tools():
    data = request.json
    ip = (data.get("ip") or "").strip()
    checks = data.get("checks", ["geo", "tor", "dnsbl"])
    if not ip:
        return jsonify({"error": "No IP address provided."}), 400

    from modules.ip_tools import geoip_lookup_data, check_tor_exit_data, check_dnsbl_data
    result = {}
    if "geo" in checks:
        result["geo"] = geoip_lookup_data(ip)
    if "tor" in checks:
        result["tor"] = check_tor_exit_data(ip)
    if "dnsbl" in checks:
        result["dnsbl"] = check_dnsbl_data(ip)
    return jsonify(result)


# ── Settings ──────────────────────────────────────────────────────────────────

@app.route("/api/settings", methods=["GET"])
def get_settings():
    from config.settings import load_config
    config = load_config()
    masked = {}
    for k, v in config.items():
        masked[k] = ("*" * (len(v) - 4) + v[-4:]) if len(v) > 4 else ("set" if v else "")
    return jsonify(masked)


@app.route("/api/settings", methods=["POST"])
def save_settings():
    from config.settings import load_config, save_config
    data = request.json
    config = load_config()
    for k, v in data.items():
        if k in config:
            config[k] = v
    save_config(config)
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
