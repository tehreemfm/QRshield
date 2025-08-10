import re
import ssl
import socket
import whois
import datetime
import tldextract
import Levenshtein
from urllib.parse import urlparse

TRUSTED_DOMAINS = ['google.com', 'microsoft.com', 'paypal.com', 'hbl.com']

def domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age = (datetime.datetime.now() - creation_date).days
            return age
    except Exception:
        pass
    return 0

def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    return True
    except Exception:
        pass
    return False

def sus_url(url):
    score = 0
    reasons = []

    url = url.strip()
    domain = urlparse(url).netloc
    extracted = tldextract.extract(url)
    domain_name = f"{extracted.domain}.{extracted.suffix}"

    #sus keywords
    keywords = ['login','verify','update','secure','signin','webscr']
    for word in keywords:
        if word in url.lower():
            score += 1
            reasons.append(f"Contains keyword: '{word}' ")

    # IP address instead of domain
    if re.match(r'^https?://(\d{1,3}\.){3}\d{1,3}', url):
        score += 3
        reasons.append("Uses IP address instead of domain name")

    # too many  hyphens
    if url.count('-') > 3:
        score += 1
        reasons.append(f"Too many hyphens")

    # shortened url
    shorteners = ['bit.ly', 'tinyurl', 't.co', 'shorte.st']
    if any(s in url.lower() for s in shorteners):
        score += 2
        reasons.append("Shortened URL")

    # domain age
    age = domain_age(domain_name)
    if age < 180 :
        score += 2
        reasons.append(f"Domain is too new: {age} days old")

    # SSL check
    if not check_ssl(domain):
        score += 2
        reasons.append(f"NO valid SSL certificate")

    # Levenshtein from trusted domains
    min_dist =([Levenshtein.distance(domain_name, legit) for legit in TRUSTED_DOMAINS])
    if min(min_dist) < 3:
        score += 2
        reasons.append(f"Domain looks similar to known site: Levenshtein distance: {min_dist}")

    # final risk assessment
    if score >= 6:
        risk = "[!!] Caution: HIGH risk"
    elif score >= 3:
        risk = "[!!] Caution: MEDIUM risk"
    else:
        risk = "[O] LOW risk"

    return {
        "url": url,
        "score": score,
        "risk": risk,
        "reasons": reasons
    }

