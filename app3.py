import streamlit as st
import pandas as pd
import numpy as np
import socket
import requests
from fpdf import FPDF
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt

# App setup
st.set_page_config(page_title="Cyber Security Suite", layout="centered")
st.title("Cyber Security Suite - ML + Web Vulnerability Scanner")

# Set default values
result = None
results = []

# ----------------------------------
# 1. Intrusion Detection (ML-based)
# ----------------------------------
st.markdown("### 1. Intrusion Detection System")

def generate_data(n_samples=1000):
    np.random.seed(42)
    X = pd.DataFrame({
        "duration": np.random.randint(0, 1000, n_samples),
        "src_bytes": np.random.randint(0, 10000, n_samples),
        "dst_bytes": np.random.randint(0, 10000, n_samples),
        "count": np.random.randint(1, 100, n_samples),
        "srv_count": np.random.randint(1, 100, n_samples),
        "wrong_fragment": np.random.randint(0, 3, n_samples),
        "urgent": np.random.randint(0, 2, n_samples)
    })
    y = ((X["src_bytes"] + X["dst_bytes"] > 12000) | (X["count"] > 80) | (X["urgent"] > 0)).astype(int)
    return X, y

X, y = generate_data()
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier()
model.fit(X_train, y_train)
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

# User inputs
duration = st.slider("Duration", 0, 1000, 10)
src_bytes = st.slider("Source Bytes", 0, 10000, 100)
dst_bytes = st.slider("Destination Bytes", 0, 10000, 100)
count = st.slider("Connection Count", 1, 100, 10)
srv_count = st.slider("Service Count", 1, 100, 10)
wrong_fragment = st.slider("Wrong Fragments", 0, 3, 0)
urgent = st.slider("Urgent Packets", 0, 1, 0)

input_data = pd.DataFrame([[duration, src_bytes, dst_bytes, count, srv_count, wrong_fragment, urgent]],
                          columns=X.columns)

if st.button("Predict Intrusion"):
    result = model.predict(input_data)[0]
    if result == 1:
        st.error("Intrusion Detected!")
    else:
        st.success("Normal Traffic")

st.write(f"**Model Accuracy:** {accuracy * 100:.2f}%")

# Confusion Matrix
st.subheader("Confusion Matrix")
cm = confusion_matrix(y_test, y_pred)
fig, ax = plt.subplots()
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=["Normal", "Attack"], yticklabels=["Normal", "Attack"])
plt.xlabel("Predicted")
plt.ylabel("Actual")
st.pyplot(fig)

# ----------------------------------
# 2. Web Vulnerability Scanner
# ----------------------------------
st.markdown("---")
st.markdown("### 2. Web Vulnerability Scanner")

url = st.text_input("Enter website URL (e.g. https://example.com)")

def scan_url(url):
    issues = []

    # Header scan
    try:
        res = requests.get(url, timeout=5)
        headers = res.headers
        if "X-Frame-Options" not in headers:
            issues.append("Missing X-Frame-Options (Clickjacking Risk)")
        if "Content-Security-Policy" not in headers:
            issues.append("Missing Content-Security-Policy (XSS Risk)")
        if "X-XSS-Protection" not in headers:
            issues.append("Missing X-XSS-Protection header")
    except Exception as e:
        issues.append(f"Error accessing site: {str(e)}")

    # Port scan
    try:
        host = url.replace("http://", "").replace("https://", "").split("/")[0]
        ports = [21, 22, 80, 443, 3306]
        for port in ports:
            s = socket.socket()
            s.settimeout(1)
            if s.connect_ex((host, port)) == 0:
                issues.append(f"Port {port} is OPEN")
            s.close()
    except Exception as e:
        issues.append(f"Error during port scan: {str(e)}")

    # Simulated injection checks
    if "id=" in url:
        issues.append("Potential SQL Injection risk in URL")
    if "<script>" in url:
        issues.append("XSS payload detected in URL")

    return issues

if st.button("Scan Website"):
    if url:
        results = scan_url(url)
        if results:
            st.warning("Vulnerabilities Found:")
            for r in results:
                st.write(f"- {r}")
        else:
            st.success("No common vulnerabilities found!")
    else:
        st.error("Please enter a URL.")

# ----------------------------------
# 3. PDF Report Generator
# ----------------------------------
st.markdown("---")
st.subheader("Download PDF Report")

class PDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 12)
        self.cell(0, 10, "Cyber Security Report", ln=True, align='C')

    def add_section(self, title, content):
        self.set_font("Arial", "B", 12)
        self.cell(0, 10, title, ln=True)
        self.set_font("Arial", "", 11)
        if isinstance(content, list):
            for line in content:
                self.multi_cell(0, 10, f"- {line}")
        else:
            self.multi_cell(0, 10, str(content))
        self.ln()

def create_pdf(url, intrusion_result, scan_results):
    pdf = PDF()
    pdf.add_page()
    pdf.add_section("Scanned URL", url if url else "No URL provided")
    pdf.add_section("Intrusion Detection", intrusion_result)
    pdf.add_section("Vulnerability Scan Results", scan_results if scan_results else "No scan performed")
    return pdf.output(dest='S').encode('latin-1')

# Format results
intrusion_text = "Intrusion Detected" if result == 1 else "Normal Traffic" if result == 0 else "Not Tested"

if st.button("Download PDF"):
    pdf_bytes = create_pdf(url, intrusion_text, results)
    st.download_button("Download Cyber Report", data=pdf_bytes, file_name="cyber_security_report.pdf", mime="application/pdf")