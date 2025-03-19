import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import SVC


data = {
    "Apache 2.4.49": "CVE-2021-41773",
    "nginx 1.18.0": "CVE-2021-23017",
    "OpenSSH 8.2": "CVE-2020-14145",
    "Microsoft IIS 10.0": "CVE-2022-21907",
    "PostgreSQL 9.6": "CVE-2022-1552",
    "Tomcat 8.5": "CVE-2020-9484",
    "Windows SMBv1": "CVE-2017-0144 (EternalBlue)",
    "Struts 2.3": "CVE-2017-5638"
}

df = pd.DataFrame(data.items(), columns=["Service_Banner", "Vulnerability"])

vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(df["Service_Banner"])
y = df["Vulnerability"]

model = SVC(kernel="linear")
model.fit(X, y)

joblib.dump((vectorizer, model), "ai_exploit_model.pkl")
print("[+] AI Model Updated & Saved with More CVEs!")
