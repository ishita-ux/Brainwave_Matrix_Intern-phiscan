import re
import socket
import datetime
from urllib.parse import urlparse
import ssl
from colorama import init, Fore, Style
from tabulate import tabulate
import time
import requests
import sys

# Initialize colorama
init(autoreset=True)

# Sample blacklist domains
blacklist = ['bit.ly', 'grabify.link', 'tinyurl.com', 'phishing.com', 'iplogger.org']

# Risk scoring weights
weights = {
    "https": -5,
    "blacklist": 30,
    "ip_in_url": 20,
    "encoding": 10,
    "long_url": 5,
    "at_symbol": 10,
    "young_domain": 15,
    "ssl_expiry_soon": 15
}

def banner():
    print(Fore.MAGENTA + Style.BRIGHT + """
🛡️  ============================================= 🛡️
      🔍 PhishScan - Phishing Link Scanner 🔍
🛡️  ============================================= 🛡️
""" + Fore.CYAN + "        Developed with ❤️ for Cyber Security\n")
    typing("👩\u200d💻 Tool Created by: ISHITA")
    typing("🤖 Enhanced by: J.A.R.V.I.S. for BOSS")

def typing(text, delay=0.02):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def is_ip(url):
    try:
        ip = urlparse(url).netloc
        socket.inet_aton(ip)
        return True
    except:
        return False

def is_encoded(url):
    return '%' in url

def is_blacklisted(url):
    for b in blacklist:
        if b in url:
            return True
    return False

def domain_age(domain):
    try:
        response = requests.get(f"https://api.hackertarget.com/whois/?q={domain}")
        lines = response.text.splitlines()
        for line in lines:
            if 'Creation Date:' in line or 'Created On:' in line:
                date_str = line.split(':')[-1].strip()
                created = datetime.datetime.strptime(date_str[:10], '%Y-%m-%d')
                return (datetime.datetime.now() - created).days
        return -1
    except:
        return -1

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "Unavailable"

def get_origin_ip(domain):
    try:
        response = requests.get(f"https://api.hackertarget.com/dnslookup/?q={domain}")
        for line in response.text.splitlines():
            if line.startswith("A"):
                return line.split()[1]
        return "Not found"
    except:
        return "Unavailable"

def ssl_certificate_info(domain):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])

                common_name = subject.get('commonName', 'N/A')
                issuer_org = issuer.get('organizationName', 'N/A')

                expiry_date_str = cert['notAfter']
                expiry_date = datetime.datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry_date - datetime.datetime.utcnow()).days

                return {
                    "issuer": issuer_org,
                    "common_name": common_name,
                    "expires_in_days": days_left,
                    "expiry_date": expiry_date.strftime('%Y-%m-%d')
                }
    except Exception:
        return {
            "issuer": "Unavailable",
            "common_name": "Unavailable",
            "expires_in_days": -1,
            "expiry_date": "Unavailable"
        }

def scan_url(url):
    print(Fore.YELLOW + "\n[+] Scanning URL: " + Fore.WHITE + url)
    parsed = urlparse(url)
    domain = parsed.netloc
    results = []
    score = 0

    if url.startswith("https://"):
        results.append(["🔐 HTTPS Used", "Yes (⚠️ Still can be phishing)"])
        score += weights["https"]
    else:
        results.append(["❌ HTTPS Used", "No (Insecure connection)"])

    domain_ip = get_ip(domain)
    origin_ip = get_origin_ip(domain)
    results.append(["🌐 Domain Name", domain])
    results.append(["📡 Resolved IP", domain_ip])
    results.append(["🛰️ Origin IP", origin_ip])

    if is_blacklisted(url):
        results.append(["🚫 Blacklisted Domain", "Yes"])
        score += weights["blacklist"]
    else:
        results.append(["✅ Blacklisted Domain", "No"])

    if is_ip(url):
        results.append(["⚠️ Uses IP Instead of Domain", "Yes"])
        score += weights["ip_in_url"]
    else:
        results.append(["✅ Uses Domain", "Yes"])

    if is_encoded(url):
        results.append(["⚠️ URL Contains Encoding", "Yes"])
        score += weights["encoding"]
    else:
        results.append(["✅ No Encoding", "Clean"])

    results.append(["📏 URL Length > 75", "Yes" if len(url) > 75 else "No"])
    if len(url) > 75:
        score += weights["long_url"]

    if '@' in url:
        results.append(["⚠️ Contains '@' Symbol", "Yes"])
        score += weights["at_symbol"]
    else:
        results.append(["✅ No '@' Symbol", "Clean"])

    age = domain_age(domain)
    if age == -1:
        results.append(["📅 Domain Age", "Unknown"])
    else:
        label = f"{age} days"
        if age < 90:
            score += weights["young_domain"]
            label += " (Young)"
        else:
            label += " (Old)"
        results.append(["📅 Domain Age", label])

    if url.startswith("https://"):
        cert_info = ssl_certificate_info(domain)
        results.append(["🔒 SSL Issuer", cert_info['issuer']])
        results.append(["📛 Certificate CN", cert_info['common_name']])
        results.append(["📆 SSL Expiry Date", cert_info['expiry_date']])
        if cert_info['expires_in_days'] != -1:
            results.append(["⏳ Days Until Expiry", f"{cert_info['expires_in_days']} days"])
            if cert_info['expires_in_days'] < 15:
                results.append(["⚠️ SSL Warning", "Certificate expires soon!"])
                score += weights["ssl_expiry_soon"]
        else:
            results.append(["⚠️ SSL Info", "Unavailable"])

    print(Fore.CYAN + "\n📋 Scan Summary:\n")
    print(tabulate(results, headers=["Feature", "Result"], tablefmt="fancy_grid"))

    risk_level = "🔴 High Risk" if score >= 50 else "🟡 Medium Risk" if score >= 20 else "🟢 Low Risk"
    print(Fore.MAGENTA + f"\n🎯 Phishing Risk Score: {score}/100 — {risk_level}")
    print(Fore.GREEN + "\n👩‍💻 Author: ISHITA")
    print(Fore.CYAN + "🤖 Enhanced with ❤️ by JARVIS for BOSS")

def main():
    banner()
    while True:
        try:
            url = input(Fore.GREEN + " 🔗 Enter URL to scan: ").strip()
            if url:
                if not url.startswith("http"):
                    url = "http://" + url
                scan_url(url)

            again = input(Fore.CYAN + " 🔁 Scan another URL? (y/n): ").lower()
            if again != 'y':
                print(Fore.MAGENTA + " 👋 Exiting PhishScan. Stay secure online!")
                break
        except (KeyboardInterrupt, EOFError):
            print(Fore.MAGENTA + " 👋 Exiting PhishScan. Stay secure online!")
            break

if __name__ == "__main__":
    main()

