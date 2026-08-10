from fastapi import FastAPI
from pydantic import BaseModel
import math
from collections import Counter

app = FastAPI()

# Domains/TLDs commonly abused by malware campaigns (free registration, low moderation)
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq"}

class ThreatResponse(BaseModel):
    domain: str
    threat_score: float
    classification: str


def shannon_entropy(s: str) -> float:
    """
    Measures how 'random-looking' a string is.
    Low entropy = predictable/repetitive (real words).
    High entropy = random-looking (common in malware-generated domains).
    """
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    # Standard Shannon entropy formula: -sum(p * log2(p)) for each character's probability p
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def calculate_threat_score(domain: str) -> float:
    score = 0.0

    # very long domains are unusual for legitimate sites
    if len(domain) > 40:
        score += 0.2

    # excessive hyphens are a common phishing/typosquatting pattern
    if domain.count('-') > 3:
        score += 0.15

    # high ratio of digits to letters is unusual for real domains
    digit_ratio = sum(c.isdigit() for c in domain) / max(len(domain), 1)
    if digit_ratio > 0.3:
        score += 0.25

    # high entropy suggests algorithmically generated / random domain
    entropy = shannon_entropy(domain)
    if entropy > 3.5:
        score += 0.2

    # cheap/unmoderated TLDs are disproportionately used for malicious domains
    tld = domain.split('.')[-1].lower() if '.' in domain else ''
    if tld in SUSPICIOUS_TLDS:
        score += 0.3

    return min(score, 0.99)  # cap just under 1.0


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.get("/analyze", response_model=ThreatResponse)
async def analyze(domain: str):
    score = calculate_threat_score(domain)

    if score > 0.7:
        classification = "malicious"
    elif score > 0.4:
        classification = "suspicious"
    else:
        classification = "safe"

    return ThreatResponse(domain=domain, threat_score=score, classification=classification)
