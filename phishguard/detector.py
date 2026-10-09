"""Rule-based phishing / smishing detector.

Returns a score (0-100), a risk level, the signals that fired, and the text
ranges to highlight. Ranges are expressed in UTF-16 code units so they line up
with JavaScript string indexes in the browser.
"""
import re

F = re.IGNORECASE

RULES = [
    {"label": "urgent", "re": re.compile(r"\burgent(ly)?\b", F), "why": "Creates false urgency"},
    {"label": "immediately", "re": re.compile(r"\bimmediate(ly)?\b", F), "why": "Pressures you to act fast"},
    {"label": "action required", "re": re.compile(r"action required", F), "why": "Pressures you to act fast"},
    {
        "label": "deadline",
        "re": re.compile(r"within \d+ ?(hours?|minutes?|days?)|expires? (today|soon)|final notice", F),
        "why": "Uses a deadline to rush you",
    },
    {
        "label": "suspended",
        "re": re.compile(r"\b(suspended|locked|deactivated|disabled|closed)\b", F),
        "why": "Threatens loss of an account",
    },
    {
        "label": "verify / confirm",
        "re": re.compile(r"\b(verify|confirm|validate)\b", F),
        "why": "Asks you to confirm details",
        "cred": True,
    },
    {
        "label": "password",
        "re": re.compile(r"\b(password|passcode)\b", F),
        "why": "Asks for login credentials",
        "cred": True,
    },
    {
        "label": "OTP / code",
        "re": re.compile(r"\b(otp|one-time (code|password)|security code|pin)\b", F),
        "why": "Asks for a one-time code",
        "cred": True,
    },
    {
        "label": "login",
        "re": re.compile(r"\b(log ?in|sign ?in)\b", F),
        "why": "Pushes you to a login page",
        "cred": True,
    },
    {
        "label": "bank / account",
        "re": re.compile(r"\b(bank|account|credit card)\b", F),
        "why": "Mentions financial or account details",
    },
    {
        "label": "prize / reward",
        "re": re.compile(r"\b(winner|you won|prize|lottery|gift card|reward)\b", F),
        "why": "Offers an unexpected reward",
    },
    {"label": "claim", "re": re.compile(r"\bclaim\b", F), "why": "Asks you to claim something"},
    {"label": "click here", "re": re.compile(r"click (here|below|the link)", F), "why": "Pushes you to click"},
]

RULE_WEIGHT = 15
LINK_RE = re.compile(
    r"(https?://|www\.)\S+|\b(?:[a-z0-9-]+\.)+(com|net|org|io|ly|co|info|xyz|ru|top|click|link)\b(/\S*)?",
    F,
)
SHORT_RE = re.compile(r"\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly)\b", F)
IP_RE = re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}", F)


def _u16(text: str, index: int) -> int:
    """Convert a Python string index to a UTF-16 code-unit index."""
    return len(text[:index].encode("utf-16-le")) // 2


def _ranges(text: str):
    found = []
    for rule in RULES:
        for m in rule["re"].finditer(text):
            if m.end() > m.start():
                found.append([m.start(), m.end(), "word"])
    for m in LINK_RE.finditer(text):
        if m.end() > m.start():
            found.append([m.start(), m.end(), "link"])

    found.sort(key=lambda r: (r[0], -r[1]))
    merged = []
    for start, end, kind in found:
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
            if kind == "link":
                merged[-1][2] = "link"
        else:
            merged.append([start, end, kind])
    return [{"start": _u16(text, s), "end": _u16(text, e), "type": k} for s, e, k in merged]


def analyze(text: str) -> dict:
    hits = []
    score = 0
    asks_for_details = False

    for rule in RULES:
        if rule["re"].search(text):
            hits.append({"label": rule["label"], "why": rule["why"]})
            score += RULE_WEIGHT
            if rule.get("cred"):
                asks_for_details = True

    if LINK_RE.search(text):
        hits.append({"label": "link", "why": "Contains a link. Check the real address before clicking"})
        score += 20
        if SHORT_RE.search(text):
            hits.append({"label": "short link", "why": "Shortened links hide the real destination"})
            score += 15
        if IP_RE.search(text):
            hits.append({"label": "IP address link", "why": "Real services rarely link to a raw IP address"})
            score += 20
        if asks_for_details:
            hits.append(
                {
                    "label": "link + login request",
                    "why": "A link combined with a request for details is a classic phishing pattern",
                }
            )
            score += 15

    score = min(score, 100)
    level = "high" if score >= 60 else "medium" if score >= 25 else "low"
    return {"score": score, "level": level, "hits": hits, "ranges": _ranges(text)}


def threat_type(level: str, channel: str) -> str:
    if level == "high":
        return "Smishing" if channel.upper() == "SMS" else "Phishing"
    return "Suspicious" if level == "medium" else "Safe"


def status_for(level: str) -> str:
    return {"high": "Blocked", "medium": "Flagged", "low": "Allowed"}[level]
