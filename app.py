import streamlit as st
import re
import urllib.parse
from math import log2

# ---------------------------
# Helper functions (features)
# ---------------------------

def has_ip(url):
    return 1 if re.search(r"(\d{1,3}\.){3}\d{1,3}", url) else 0

def entropy(url):
    prob = [float(url.count(c)) / len(url) for c in dict.fromkeys(url)]
    return -sum([p * log2(p) for p in prob])

def extract_features(url):
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc
    
    features = {
        "url_length": len(url),
        "slash_count": url.count("/"),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "starts_with_www": 1 if domain.startswith("www") else 0,
        "has_ip_address": has_ip(url),
        "has_at_symbol": 1 if "@" in url else 0,
        "has_port": 1 if ":" in domain else 0,
        "digit_count": sum(c.isdigit() for c in url),
        "suspicious_chars": sum(c in "%=?_" for c in url),
        "entropy_score": entropy(url),
        "suspicious_keywords": 1 if any(k in url.lower() for k in 
                ["verify", "update", "login", "secure", "bank", "free", "confirm", "alert"]) else 0,
        "suspicious_tld": 1 if re.search(r"\.(xyz|top|club|info|shop|click)$", url) else 0,
    }

    return features


# ---------------------------
# Rule-based risk scoring
# ---------------------------

def evaluate_phishing(url):
    f = extract_features(url)

    score = 0

    # Strong indicators
    if f["has_ip_address"]: score += 3
    if f["has_at_symbol"]: score += 3
    if f["suspicious_keywords"]: score += 2
    if f["suspicious_tld"]: score += 2

    # Structure anomalies
    if f["url_length"] > 30: score += 2
    if f["hyphen_count"] > 3: score += 2
    if f["slash_count"] > 5: score += 2
    if f["digit_count"] > 5: score += 1
    if f["entropy_score"] > 4.0: score += 2

    # Mild indicators
    if not f["starts_with_www"]: score += 0.5
    if f["suspicious_chars"] > 3: score += 1

    # Decision
    if score >= 7:
        verdict = "⚠️ PHISHING"
    elif score >= 4:
        verdict = "❓ SUSPICIOUS"
    else:
        verdict = "✅ LEGIT"

    return verdict, f, score


# ------------------------------------------
# Main program loop: check a URL
# ------------------------------------------
st.title("Simple URL Phishing Checker")
url = st.text_input("Enter URL")
if url!="":
    url = url
    verdict, features, risk_score = evaluate_phishing(url)
    #st.write("\n--- URL ANALYSIS ---")
    #for k, v in features.items():
      #  st.write(f"{k}: {v}")

    st.write(f"\nRISK SCORE = {risk_score}")
    if verdict == "✅ LEGIT":
        st.error(f"RESULT = {verdict}")
        st.balloons()
    else:    
        st.write(f"RESULT = {verdict}")
elif url=="":
    st.write("Enter the URL")   
else:
    st.write("Invalid URL entered.")


