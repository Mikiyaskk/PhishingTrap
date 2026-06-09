import streamlit as st
import pickle
import pandas as pd
import re

with open('phishing_model (8).pkl', 'rb') as f:
    model = pickle.load(f)

with open('feature_names.pkl', 'rb') as f:
    feature_names = pickle.load(f)

trusted_domains = [
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'linkedin.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'netflix.com', 'reddit.com', 'wikipedia.org', 'stackoverflow.com', 'gmail.com'
]

def analyze_url(url):
    features = {}
    if not isinstance(url, str):
        url = ""
    if not url.startswith('http'):
        url = 'http://' + url

    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0

    suspicious_words = ['login', 'verify', 'bank', 'secure', 'update', 'confirm',
                        'account', 'password', 'credit', 'signin', 'ebayisapi', 'webscr']
    features['suspicious_words'] = sum(1 for word in suspicious_words if word in url.lower())

    features['num_slashes'] = url.count('/')
    features['num_at'] = url.count('@')
    features['num_percent'] = url.count('%')
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['has_https'] = 1 if url.startswith('https') else 0
    features['num_subdomains'] = max(0, url.count('.') - 1)
    features['has_shortener'] = 1 if any(s in url for s in ['bit.ly', 'tinyurl', 'goo.gl', 't.co']) else 0
    features['is_trusted'] = 1 if any(d in url for d in trusted_domains) else 0

    return features

st.title("🎣 PhishingTrap")
st.subheader("Paste a URL below to check if it's safe")

url_input = st.text_input("Enter URL here")

if st.button("Check URL"):
    if url_input:
        is_trusted = any(d in url_input for d in trusted_domains)

        if is_trusted:
            st.success("✅ SAFE — Trusted domain detected")
        else:
            features = analyze_url(url_input)
            df = pd.DataFrame([features])[feature_names]
            prediction = model.predict(df)[0]
            probability = model.predict_proba(df)[0]

            if prediction == 1:
                st.error(f"⚠️ PHISHING DETECTED — {round(probability[1]*100)}% confidence")
            else:
                st.success(f"✅ SAFE — {round(probability[0]*100)}% confidence")

        st.subheader("URL Analysis Breakdown")
        st.write(pd.DataFrame([analyze_url(url_input)]).T.rename(columns={0: 'value'}))
    else:
        st.warning("Please enter a URL first")
