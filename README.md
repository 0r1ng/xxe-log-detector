# XXE Log Detector

A Python tool for detecting possible XML External Entity (XXE) attack attempts in web access logs.

The script scans Apache/Nginx-style access logs for suspicious XML payloads, encoded XXE patterns, external entity declarations, sensitive file targets, and common XXE indicators.

## Description

XML External Entity (XXE) attacks happen when an application processes unsafe XML input that contains external entity declarations. Attackers may use XXE to read local files, access internal services, perform SSRF, or disclose sensitive information.

Example XXE payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

This tool helps SOC analysts, detection engineers, and security researchers identify possible XXE activity from logs.

## Features

* Detects `DOCTYPE` declarations
* Detects `ENTITY` declarations
* Detects `SYSTEM` and `PUBLIC` external identifiers
* Detects parameter entities
* Detects XML entity references
* Detects `file://`, `http://`, `https://`, `php://`, `gopher://`, and other external URI schemes
* Detects XInclude patterns
* Detects encoded XML payloads
* Detects base64-encoded XML payloads
* Detects sensitive file targets such as `/etc/passwd`, `/etc/shadow`, `.env`, `.git/config`, and `web.config`
* Supports Apache combined log format
* Supports `.gz` compressed log files
* Supports JSON output
* Supports medium-confidence findings
* Can filter successful-looking HTTP responses

## Common XXE Indicators

The script looks for patterns such as:

```text
<!DOCTYPE
<!ENTITY
SYSTEM
PUBLIC
file:///
php://filter
/proc/self/environ
/etc/passwd
/etc/shadow
XInclude
&xxe;
```

It also detects encoded versions such as:

```text
%3C%21DOCTYPE
%3C%21ENTITY
file%3A%2F%2F%2Fetc%2Fpasswd
```

## Installation

No external Python libraries are required.

Clone the repository:

```bash
git clone https://github.com/yourname/xxe-log-detector.git
cd xxe-log-detector
```

Make the script executable:

```bash
chmod +x detect_xxe.py
```

## Usage

Scan one log file:

```bash
python3 detect_xxe.py access.log
```

Save results to a text file:

```bash
python3 detect_xxe.py access.log > xxe_hits.txt
```

Scan multiple log files:

```bash
python3 detect_xxe.py *.log
```

Scan compressed logs:

```bash
python3 detect_xxe.py *.gz
```

Show medium-confidence findings:

```bash
python3 detect_xxe.py --include-medium access.log
```

Show only successful-looking responses:

```bash
python3 detect_xxe.py --only-success access.log
```

Export JSON lines:

```bash
python3 detect_xxe.py --json access.log > xxe_hits.jsonl
```

Run with debug summary:

```bash
python3 detect_xxe.py --debug access.log
```

## Example Test

Create a test log:

```bash
cat > test.log << 'EOF'
178.78.113.5 - - [18/Apr/2023:19:42:00 +0000] "GET /api?xml=%3C%3Fxml%20version%3D%221.0%22%3F%3E%3C!DOCTYPE%20foo%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file%3A///etc/passwd%22%3E%5D%3E%3Cfoo%3E%26xxe%3B%3C/foo%3E HTTP/1.1" 200 2270 "-" "Mozilla/5.0"
178.78.113.5 - - [18/Apr/2023:19:43:00 +0000] "GET /normal?page=home HTTP/1.1" 200 1000 "-" "Mozilla/5.0"
EOF
```

Run the detector:

```bash
python3 detect_xxe.py test.log
```

## Example Output

```text
========================================================================================================================
FILE:       access.log
LINE:       1
CONFIDENCE: HIGH
SCORE:      29
IP:         178.78.113.5
TIME:       18/Apr/2023:19:42:00 +0000
METHOD:     GET
STATUS:     200
SOURCE:     request-target
TYPE:       query parameter
PARAM:      xml
VALUE:      <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
REASON:     DOCTYPE declaration, ENTITY declaration, SYSTEM external identifier, entity reference usage, external URI scheme, sensitive target: /etc/passwd
RAW:        178.78.113.5 - - [18/Apr/2023:19:42:00 +0000] "GET /api?xml=..."
```

## Confidence Levels

### High Confidence

High-confidence findings usually contain strong XXE evidence, such as:

```text
DOCTYPE + ENTITY + SYSTEM
Parameter entity + external URI
XInclude + external URI
Sensitive file target + XML external entity pattern
Base64 XML payload containing ENTITY or DOCTYPE
```

### Medium Confidence

Medium-confidence findings are hidden by default. Use:

```bash
python3 detect_xxe.py --include-medium access.log
```

## Recommended SOC Usage

This tool can be used for:

* SOC alert triage
* Web attack investigation
* Threat hunting
* Incident response
* Detection engineering validation
* WAF log analysis
* Proxy log review
* CTF and lab analysis

Strong XXE indicators usually include:

```text
XML input + DOCTYPE + ENTITY + SYSTEM + file:///etc/passwd
```

## Important Note About POST Requests

Normal Apache/Nginx access logs usually do not store POST request bodies.

If an XXE payload was sent inside an XML POST body, this script may not detect it unless the body was logged by:

* WAF logs
* Reverse proxy logs
* Application logs
* API gateway logs
* Full packet capture
* Request body logging

## Limitations

This tool detects possible XXE attempts from logs. It does not prove successful exploitation by itself.

To confirm exploitation, analysts should review:

* HTTP status code
* Response size
* Application response body
* WAF events
* Server error logs
* Outbound DNS or HTTP callbacks
* Endpoint telemetry
* Application parser errors

## Security Notice

Use this tool only on logs and systems that you own or are authorized to analyze.

## License

MIT License
