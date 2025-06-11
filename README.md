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

---

## ⚙️ Installation & Usage

### 1. Clone the Repository

```bash
git clone https://github.com/ishita-ux/Brainwave_Matrix_Intern-phiscan.git
cd Brainwave_Matrix_Intern-phiscan
