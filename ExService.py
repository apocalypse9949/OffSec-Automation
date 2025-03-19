import joblib

def analyze_banner(banner):
    vectorizer, model = joblib.load("ai_exploit_model.pkl")
    X_new = vectorizer.transform([banner])
    prediction = model.predict(X_new)
    return prediction[0]

service_banner = "Windows SMBv1"
vulnerability = analyze_banner(service_banner)
print(f"[+] AI Detected Vulnerability: {vulnerability}")
