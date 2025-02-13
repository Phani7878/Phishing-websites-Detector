import re
import whois
import requests
import dns.resolver
import tldextract
import os
from datetime import datetime
from bs4 import BeautifulSoup
import numpy as np
import joblib

# Google Safe Browsing API Key (Replace with your own API key)
GOOGLE_SAFE_BROWSING_API_KEY = "YOUR_GOOGLE_API_KEY"

# 1️⃣ URL-based Features Extraction

def extract_url_features(url):
    features = {}
    
    # Length of URL
    features['url_length'] = len(url)
    
    # Presence of IP address in URL
    features['contains_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    
    # Checking for HTTPS
    features['https'] = 1 if url.startswith('https') else 0
    
    # Checking for suspicious characters
    features['contains_at'] = 1 if '@' in url else 0
    features['contains_double_slash'] = 1 if '//' in url[7:] else 0
    features['contains_dash'] = 1 if '-' in url else 0
    
    # Domain Age (WHOIS lookup)
    try:
        extracted_domain = tldextract.extract(url).registered_domain
        domain_info = whois.whois(extracted_domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):  # Handle multiple dates
            creation_date = creation_date[0]
        features['domain_age_days'] = (datetime.now() - creation_date).days if creation_date else 0
    except:
        features['domain_age_days'] = 0  # Default to 0 if WHOIS lookup fails
    
    return features

# 2️⃣ Google Safe Browsing API Check

def check_google_safe_browsing(url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "yourcompany", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(api_url, json=payload)
    if response.status_code == 200 and "matches" in response.json():
        return True
    return False

# 3️⃣ Rule-Based Phishing Detection

def classify_url(features):
    # Simple heuristic rules for phishing detection
    score = 0
    
    if features['contains_ip']: score += 2  # IP in URL is suspicious
    if features['contains_at']: score += 1  # '@' in URL is phishing indicator
    if features['contains_double_slash']: score += 1
    if features['contains_dash']: score += 1
    if features['url_length'] > 75: score += 1  # Long URLs can be phishing
    if features['https'] == 0: score += 1  # Lack of HTTPS is suspicious
    if features['domain_age_days'] < 180: score += 2  # Young domains are risky
    
    if score >= 4:
        return "Phishing"
    return "Legitimate"

# 4️⃣ Real-time Phishing Detection

def detect_phishing_realtime():
    url = input("Enter a website URL to check: ").strip()
    
    if not url.startswith("http"):
        print("Invalid URL. Please enter a valid URL starting with http or https.")
        return
    
    # Check Google Safe Browsing API
    if check_google_safe_browsing(url):
        print("Prediction: Phishing (Flagged by Google Safe Browsing)")
        return
    
    # Extract Features for Additional Analysis
    features = extract_url_features(url)
    prediction = classify_url(features)
    print(f"Prediction: {prediction}")

# Example Usage
if __name__ == "__main__":
    detect_phishing_realtime()
