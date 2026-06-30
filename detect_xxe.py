#!/usr/bin/env python3
import argparse
import base64
import gzip
import html
import json
import re
import sys
from urllib.parse import unquote_plus, urlsplit, parse_qsl

COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)

REQUEST_RE = re.compile(
    r'^(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+HTTP/[0-9.]+$',
    re.IGNORECASE
)

XML_PARAMS = {
    "xml", "data", "payload", "body", "content", "request", "input",
    "message", "soap", "wsdl", "svg", "doc", "document", "file",
    "template", "config", "import", "feed", "rss"
}

SENSITIVE_TARGETS = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/group",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/version",
    "c:/windows/win.ini",
    "c:/boot.ini",
    "windows/win.ini",
    "boot.ini",
    ".env",
    ".git/config",
    "web.config",
    "php://filter",
    "expect://",
    "gopher://",
    "dict://"
}

XXE_PATTERNS = {
    "doctype": re.compile(r'<!\s*doctype', re.IGNORECASE),
    "entity": re.compile(r'<!\s*entity', re.IGNORECASE),
    "system": re.compile(r'\bsystem\b', re.IGNORECASE),
    "public": re.compile(r'\bpublic\b', re.IGNORECASE),
    "parameter_entity": re.compile(r'<!\s*entity\s+%', re.IGNORECASE),
    "entity_reference": re.compile(r'&[a-zA-Z0-9_.:-]+;'),
    "external_uri": re.compile(r'(file|http|https|ftp|php|expect|gopher|dict)://', re.IGNORECASE),
    "xinclude": re.compile(r'<\s*(xi:include|include)\b', re.IGNORECASE),
    "xml_declaration": re.compile(r'<\?xml', re.IGNORECASE),
    "svg": re.compile(r'<\s*svg\b', re.IGNORECASE),
    "soap": re.compile(r'<\s*(soap|soapenv):', re.IGNORECASE),
}

RAW_ENCODED_MARKERS = re.compile(
    r'(?i)(%3c|%253c|%21doctype|%21entity|%3fxml|%26[a-z0-9_.:-]+%3b|'
    r'%66%69%6c%65%3a|file%3a|http%3a|https%3a|php%3a|%2fetc%2fpasswd)'
)


def open_log(path):
    if path == "-":
        return sys.stdin
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="ignore")
    return open(path, "r", errors="ignore")


def decode_many(value, rounds=8):
    value = html.unescape(value)

    for _ in range(rounds):
        new_value = unquote_plus(value)
        new_value = html.unescape(new_value)

        if new_value == value:
            break

        value = new_value

    return value


def try_base64_decode(value):
    cleaned = value.strip()

    if len(cleaned) < 20:
        return ""

    if not re.fullmatch(r'[A-Za-z0-9+/=_-]+', cleaned):
        return ""

    try:
        normalized = cleaned.replace("-", "+").replace("_", "/")
        padding = len(normalized) % 4

        if padding:
            normalized += "=" * (4 - padding)

        decoded = base64.b64decode(normalized, validate=False).decode("utf-8", errors="ignore")

        if "<!DOCTYPE" in decoded.upper() or "<!ENTITY" in decoded.upper() or "<?XML" in decoded.upper():
            return decoded

    except Exception:
        return ""

    return ""


def parse_log(line):
    match = COMBINED_RE.match(line)

    if not match:
        return {
            "parsed": False,
            "ip": "-",
            "time": "-",
            "method": "-",
            "target": line.strip(),
            "status": "-",
            "referer": "-",
            "agent": "-",
            "request": line.strip()
        }

    request = match.group("request")
    request_match = REQUEST_RE.match(request)

    method = "-"
    target = request

    if request_match:
        method = request_match.group("method")
        target = request_match.group("target")

    return {
        "parsed": True,
        "ip": match.group("ip"),
        "time": match.group("time"),
        "method": method,
        "target": target,
        "status": match.group("status"),
        "referer": match.group("referer"),
        "agent": match.group("agent"),
        "request": request
    }


def get_host(value):
    try:
        parsed = urlsplit(value)
        return parsed.netloc.lower()
    except Exception:
        return ""


def is_allowed_external(value, allowed_domains):
    if not allowed_domains:
        return False

    host = get_host(value)

    if not host:
        return False

    host = host.split("@")[-1].split(":")[0].strip(".").lower()

    for domain in allowed_domains:
        d = domain.lower().strip(".")
        if host == d or host.endswith("." + d):
            return True

    return False


def evidence(value, param="-", allowed_domains=None):
    allowed_domains = allowed_domains or []

    raw = value
    decoded = decode_many(value)
    low = decoded.lower()

    b64 = try_base64_decode(decoded)
    if b64:
        decoded_for_scan = decoded + "\n" + b64
        low = decoded_for_scan.lower()
    else:
        decoded_for_scan = decoded

    score = 0
    reasons = []

    has_doctype = bool(XXE_PATTERNS["doctype"].search(decoded_for_scan))
    has_entity = bool(XXE_PATTERNS["entity"].search(decoded_for_scan))
    has_system = bool(XXE_PATTERNS["system"].search(decoded_for_scan))
    has_public = bool(XXE_PATTERNS["public"].search(decoded_for_scan))
    has_parameter_entity = bool(XXE_PATTERNS["parameter_entity"].search(decoded_for_scan))
    has_external_uri = bool(XXE_PATTERNS["external_uri"].search(decoded_for_scan))
    has_entity_reference = bool(XXE_PATTERNS["entity_reference"].search(decoded_for_scan))
    has_xinclude = bool(XXE_PATTERNS["xinclude"].search(decoded_for_scan))

    if has_doctype:
        score += 4
        reasons.append("DOCTYPE declaration")

    if has_entity:
        score += 5
        reasons.append("ENTITY declaration")

    if has_system:
        score += 3
        reasons.append("SYSTEM external identifier")

    if has_public:
        score += 2
        reasons.append("PUBLIC external identifier")

    if has_parameter_entity:
        score += 5
        reasons.append("parameter entity declaration")

    if has_external_uri:
        score += 4
        reasons.append("external URI scheme")

    if has_entity_reference:
        score += 2
        reasons.append("entity reference usage")

    if has_xinclude:
        score += 4
        reasons.append("XInclude pattern")

    if XXE_PATTERNS["xml_declaration"].search(decoded_for_scan):
        score += 1
        reasons.append("XML declaration")

    if XXE_PATTERNS["svg"].search(decoded_for_scan):
        score += 1
        reasons.append("SVG XML content")

    if XXE_PATTERNS["soap"].search(decoded_for_scan):
        score += 1
        reasons.append("SOAP XML content")

    if RAW_ENCODED_MARKERS.search(raw):
        score += 2
        reasons.append("encoded XML or URI marker")

    if b64:
        score += 4
        reasons.append("base64 encoded XML payload")

    for marker in SENSITIVE_TARGETS:
        if marker in low:
            score += 6
            reasons.append("sensitive target: " + marker)

    if "%00" in raw.lower() or "\x00" in decoded_for_scan:
        score += 2
        reasons.append("null byte marker")

    if "%0a" in raw.lower() or "%0d" in raw.lower():
        score += 1
        reasons.append("encoded newline marker")

    high = False
    medium = False

    if has_doctype and has_entity and (has_system or has_public or has_external_uri):
        high = True

    if has_parameter_entity and (has_external_uri or has_system or has_public):
        high = True

    if has_xinclude and has_external_uri:
        high = True

    if any(marker in low for marker in SENSITIVE_TARGETS) and (has_doctype or has_entity or has_xinclude or has_external_uri):
        high = True

    if b64 and (has_doctype or has_entity):
        high = True

    if not high:
        if score >= 8 and (has_doctype or has_entity or has_xinclude):
            medium = True
        elif param.lower() in XML_PARAMS and score >= 7:
            medium = True

    return {
        "decoded": decoded_for_scan,
        "score": score,
        "reasons": sorted(set(reasons)),
        "high": high,
        "medium": medium
    }


def scan_url_text(text, source, allowed_domains):
    findings = []

    decoded_text = decode_many(text)

    try:
        split = urlsplit(decoded_text)
        path = split.path
        query = split.query
    except Exception:
        path = decoded_text
        query = ""

    path_ev = evidence(path, "path", allowed_domains)

    if path_ev["high"] or path_ev["medium"]:
        findings.append({
            "source": source,
            "type": "path",
            "param": "-",
            "value": path_ev["decoded"],
            "score": path_ev["score"],
            "reasons": path_ev["reasons"],
            "confidence": "HIGH" if path_ev["high"] else "MEDIUM"
        })

    try:
        params = parse_qsl(query, keep_blank_values=True)
    except Exception:
        params = []

    for name, value in params:
        ev = evidence(value, name, allowed_domains)

        if ev["high"] or ev["medium"]:
            findings.append({
                "source": source,
                "type": "query parameter",
                "param": name,
                "value": ev["decoded"],
                "score": ev["score"],
                "reasons": ev["reasons"],
                "confidence": "HIGH" if ev["high"] else "MEDIUM"
            })

    raw_param_re = re.compile(r'(?i)(?:^|[?&;\s"\'])' + r'([a-z0-9_.-]{1,80})=' + r'([^&\s"\'<>]*)')

    for match in raw_param_re.finditer(decoded_text):
        name = match.group(1)
        value = match.group(2)

        ev = evidence(value, name, allowed_domains)

        if ev["high"] or ev["medium"]:
            findings.append({
                "source": source,
                "type": "raw parameter",
                "param": name,
                "value": ev["decoded"],
                "score": ev["score"],
                "reasons": ev["reasons"],
                "confidence": "HIGH" if ev["high"] else "MEDIUM"
            })

    whole_ev = evidence(decoded_text, "whole-text", allowed_domains)

    if whole_ev["high"]:
        findings.append({
            "source": source,
            "type": "whole text",
            "param": "-",
            "value": whole_ev["decoded"],
            "score": whole_ev["score"],
            "reasons": whole_ev["reasons"],
            "confidence": "HIGH"
        })

    return findings


def unique(findings):
    seen = set()
    output = []

    for item in findings:
        key = (
            item["source"],
            item["type"],
            item["param"],
            item["value"],
            item["confidence"]
        )

        if key in seen:
            continue

        seen.add(key)
        output.append(item)

    return output


def print_text(filename, line_no, meta, finding, raw):
    print("=" * 120)
    print("FILE:       " + filename)
    print("LINE:       " + str(line_no))
    print("CONFIDENCE: " + finding["confidence"])
    print("SCORE:      " + str(finding["score"]))
    print("IP:         " + meta["ip"])
    print("TIME:       " + meta["time"])
    print("METHOD:     " + meta["method"])
    print("STATUS:     " + meta["status"])
    print("SOURCE:     " + finding["source"])
    print("TYPE:       " + finding["type"])
    print("PARAM:      " + finding["param"])
    print("VALUE:      " + finding["value"][:1000])
    print("REASON:     " + ", ".join(finding["reasons"]))
    print("RAW:        " + raw.rstrip())


def print_json(filename, line_no, meta, finding, raw):
    record = {
        "file": filename,
        "line": line_no,
        "confidence": finding["confidence"],
        "score": finding["score"],
        "ip": meta["ip"],
        "time": meta["time"],
        "method": meta["method"],
        "status": meta["status"],
        "source": finding["source"],
        "type": finding["type"],
        "param": finding["param"],
        "value": finding["value"],
        "reasons": finding["reasons"],
        "raw": raw.rstrip()
    }

    print(json.dumps(record, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description="Detect XML External Entity attack attempts in web access logs.")
    parser.add_argument("logs", nargs="+", help="Log files to scan. Supports .gz. Use - for stdin.")
    parser.add_argument("--include-medium", action="store_true", help="Also show medium-confidence findings.")
    parser.add_argument("--only-success", action="store_true", help="Only show HTTP 200 or 2xx responses.")
    parser.add_argument("--json", action="store_true", help="Output JSON lines.")
    parser.add_argument("--allow-domain", action="append", default=[], help="Trusted external domain. Can be used multiple times.")
    parser.add_argument("--debug", action="store_true", help="Show parsing summary.")
    args = parser.parse_args()

    parsed_lines = 0
    alerts = 0

    for filename in args.logs:
        try:
            with open_log(filename) as handle:
                for line_no, raw in enumerate(handle, 1):
                    meta = parse_log(raw)
                    parsed_lines += 1

                    if args.only_success and not meta["status"].startswith("2"):
                        continue

                    sources = [
                        ("request-target", meta["target"]),
                        ("referer", meta["referer"]),
                        ("user-agent", meta["agent"]),
                    ]

                    if not meta["parsed"]:
                        sources.append(("raw-line", raw))

                    findings = []

                    for source_name, text in sources:
                        if not text or text == "-":
                            continue

                        findings.extend(scan_url_text(text, source_name, args.allow_domain))

                    findings = unique(findings)

                    for finding in findings:
                        if finding["confidence"] == "MEDIUM" and not args.include_medium:
                            continue

                        alerts += 1

                        if args.json:
                            print_json(filename, line_no, meta, finding, raw)
                        else:
                            print_text(filename, line_no, meta, finding, raw)

        except FileNotFoundError:
            print("[ERROR] File not found: " + filename, file=sys.stderr)

        except PermissionError:
            print("[ERROR] Permission denied: " + filename, file=sys.stderr)

    if args.debug:
        print("=" * 120)
        print("DEBUG SUMMARY")
        print("Parsed lines: " + str(parsed_lines))
        print("Alerts:       " + str(alerts))
        print("Note: Apache/Nginx access logs usually do not contain POST request bodies.")
        print("If XXE payloads are sent inside POST XML bodies, you need body logging, WAF logs, proxy logs, or application logs.")


if __name__ == "__main__":
    main()
