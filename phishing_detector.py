"""Rule-based checker that flags common phishing signs in a message.

This is an educational tool. It runs entirely on your computer, does not
contact any website, and does not replace real security software.
A message with no warnings can still be a scam.

Usage:
    python phishing_detector.py "Your message text here"
    cat message.txt | python phishing_detector.py
"""

import re
import sys
from urllib.parse import urlparse

URGENCY_PATTERNS = [
    r"\burgent(ly)?\b",
    r"\bimmediately\b",
    r"\bwithin 24 hours\b",
    r"\bact now\b",
    r"\bfinal warning\b",
    r"\bwill be (locked|suspended|closed|deleted)\b",
    r"\bsuspended\b",
]

SENSITIVE_REQUEST_PATTERNS = [
    r"\bpassword\b",
    r"\bverification code\b",
    r"\bone[- ]time (code|password)\b",
    r"\bcredit card\b",
    r"\bbank account\b",
    r"\bsocial security number\b",
]

GENERIC_GREETING_PATTERNS = [
    r"\bdear (customer|user|client|valued customer)\b",
]

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd"}


def _any_match(patterns, text):
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def check_url(raw):
    """Return a list of warnings for a single link."""
    reasons = []
    url = raw if re.match(r"https?://", raw, re.IGNORECASE) else "http://" + raw
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    if raw.lower().startswith("http://"):
        reasons.append("Link uses unencrypted HTTP")
    if "@" in parsed.netloc:
        reasons.append("Link contains '@', which can hide the real destination")
    if IP_RE.fullmatch(host):
        reasons.append("Link points to a raw IP address")
    if host in SHORTENERS:
        reasons.append("Link uses a URL shortener that hides the destination")
    return reasons


def analyze(text):
    """Analyze a message and return its risk level, score, reasons, and links."""
    reasons = []
    score = 0

    if _any_match(URGENCY_PATTERNS, text):
        score += 2
        reasons.append("Creates urgency or threatens account closure")
    if _any_match(SENSITIVE_REQUEST_PATTERNS, text):
        score += 2
        reasons.append("Asks for sensitive information")
    if _any_match(GENERIC_GREETING_PATTERNS, text):
        score += 1
        reasons.append("Uses a generic greeting instead of your name")

    urls = [u.rstrip(".,;:!?)") for u in URL_RE.findall(text)]
    url_reasons = []
    for url in urls:
        for reason in check_url(url):
            if reason not in url_reasons:
                url_reasons.append(reason)
    score += 2 * len(url_reasons)
    reasons.extend(url_reasons)

    if score >= 5:
        risk = "High"
    elif score >= 3:
        risk = "Medium"
    elif score >= 1:
        risk = "Low"
    else:
        risk = "None detected"

    return {"risk": risk, "score": score, "reasons": reasons, "urls": urls}


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    text = " ".join(args) if args else sys.stdin.read()
    result = analyze(text)

    print(f"Risk level: {result['risk']} (score {result['score']})")
    for reason in result["reasons"]:
        print(f"- {reason}")
    print("\nNo warnings does not guarantee that a message is safe.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
