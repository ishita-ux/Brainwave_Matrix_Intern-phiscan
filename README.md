# 🛡️ PhishScan - Phishing Link Scanner Tool

**PhishScan** is a smart, Python-based tool that helps analyze suspicious URLs and determine phishing threats with detailed breakdowns and a risk score. Designed as part of the Brainwave Matrix Internship.

---

## 🚀 Features

- 🔍 Scans URL for known phishing indicators
- 📛 Detects blacklisted domains
- 🔐 Checks SSL certificate validity and expiry
- 🕵️ Identifies usage of IP addresses instead of domain names
- 📅 Verifies domain age using WHOIS lookup
- ⚠️ Detects obfuscated URLs (`% encoding`, `@ symbols`, long length)
- 📊 Risk Score Calculation (Low / Medium / High)
- 🎨 Stylish terminal interface using `colorama`

---

## 📁 Project Files

| File | Description |
|------|-------------|
| `main.py` | Main phishing scanner script |
| `requirements.txt` | Python dependencies |
| `README.md` | Project documentation |



## ⚙️ Installation & Usage

### 1. Clone the Repository

```bash
git clone https://github.com/ishita-ux/Brainwave_Matrix_Intern-phiscan.git
cd phishscan
run command :python3 main.py
[+] Scanning URL: http://bit.ly/malicious-link
![Screenshot 2025-06-11 213037](https://github.com/user-attachments/assets/6111834a-1687-4fbf-aedb-fdeaad41bf6f)

🔐 HTTPS Used: No (Insecure connection)
🌐 Domain Name: bit.ly
📡 Resolved IP: 104.20.32.42
🛰️ Origin IP: 104.20.32.42
🚫 Blacklisted Domain: Yes
⚠️ Uses IP Instead of Domain: No
⚠️ URL Contains Encoding: No
📏 URL Length > 75: No
⚠️ Contains '@' Symbol: No
📅 Domain Age: 53 days (Young)
🔒 SSL Issuer: DigiCert Inc
📛 Certificate CN: bit.ly
📆 SSL Expiry Date: 2024-12-25
⏳ Days Until Expiry: 192 days

🎯 Phishing Risk Score: 55/100 — 🟡 Medium Risk
👩‍💻 Author: ISHITA


Made By ❤️  Ishita Arya

