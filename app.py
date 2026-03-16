import re

SUSPICIOUS_PATTERNS = [
    ("FAILED_LOGIN", r"Failed login"),
    ("UNAUTHORIZED_ACCESS", r"Unauthorized access"),
    ("WP_LOGIN_SCAN", r"/wp-login\.php"),
    ("PHPMYADMIN_SCAN", r"/phpmyadmin"),
    ("ADMIN_SCAN", r"/admin"),
]

IP_REGEX = r"(?:\d{1,3}\.){3}\d{1,3}"

def extract_ip(line):
    match = re.search(IP_REGEX, line)
    return match.group(0) if match else "UNKNOWN"

def analyze_line(line):
    for event_type, pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return {
                "event_type": event_type,
                "source_ip": extract_ip(line),
                "message": line.strip()
            }
    return None
