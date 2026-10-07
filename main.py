import os
import re
import ipaddress
import requests
from dotenv import load_dotenv


def is_domain(ioc):
    pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    return re.fullmatch(pattern, ioc) is not None


def identify_ioc_type(ioc):
    try:
        ipaddress.ip_address(ioc)
        return "IP Address"
    except ValueError:
        pass

    if re.fullmatch(r"[a-fA-F0-9]{32}", ioc):
        return "MD5 Hash"

    if re.fullmatch(r"[a-fA-F0-9]{40}", ioc):
        return "SHA-1 Hash"

    if re.fullmatch(r"[a-fA-F0-9]{64}", ioc):
        return "SHA-256 Hash"

    if is_domain(ioc):
        return "Domain"

    return "Unknown"


def get_virustotal_url(ioc, ioc_type):
    if ioc_type == "IP Address":
        return f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"

    elif ioc_type == "Domain":
        return f"https://www.virustotal.com/api/v3/domains/{ioc}"

    elif ioc_type in ["MD5 Hash", "SHA-1 Hash", "SHA-256 Hash"]:
        return f"https://www.virustotal.com/api/v3/files/{ioc}"

    return None


def query_virustotal(url, api_key):
    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        return response

    except requests.exceptions.RequestException as e:
        print("Error connecting to VirusTotal:", e)
        return None


def query_abuseipdb(ip, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=10
        )
        return response

    except requests.exceptions.RequestException as e:
        print("Error connecting to AbuseIPDB:", e)
        return None


def extract_enrichment(response):
    data = response.json()

    attributes = data.get("data", {}).get("attributes", {})
    analysis_stats = attributes.get("last_analysis_stats", {})

    enrichment = {
        "ioc": data["data"]["id"],
        "reputation": attributes.get("reputation"),
        "malicious": analysis_stats.get("malicious", 0),
        "suspicious": analysis_stats.get("suspicious", 0),
        "harmless": analysis_stats.get("harmless", 0),
        "undetected": analysis_stats.get("undetected", 0)
    }

    return enrichment


def analyze_risk(enrichment, abuse_score=0):
    malicious = enrichment["malicious"]
    suspicious = enrichment["suspicious"]

    if malicious >= 5 or abuse_score >= 75:
        risk = "HIGH"
        reason = "Multiple threat-intelligence signals indicate elevated risk."

    elif malicious >= 1 or suspicious >= 1 or abuse_score >= 50:
        risk = "MEDIUM"
        reason = "One or more threat-intelligence sources indicate potential risk."

    else:
        risk = "LOW"
        reason = "No significant malicious or suspicious indicators were identified."

    return risk, reason


def get_recommendation(risk):
    if risk == "HIGH":
        return "Investigate immediately and consider blocking the IOC."

    elif risk == "MEDIUM":
        return "Investigate the IOC and validate the associated activity."

    else:
        return "No immediate action required; continue monitoring."


load_dotenv()

api_key = os.getenv("VT_API_KEY")
abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")

ioc = input("Enter an IOC: ")

ioc_type = identify_ioc_type(ioc)

print("\nIOC Type:", ioc_type)

url = get_virustotal_url(ioc, ioc_type)

if url is None:
    print("Unsupported or unknown IOC type.")
    exit()

print("\nVirusTotal Results:")

response = query_virustotal(url, api_key)

if response is None:
    exit()

if response.status_code != 200:
    print("VirusTotal request failed.")

    if response.status_code == 401:
        print("Error: Invalid or unauthorized API key.")

    elif response.status_code == 403:
        print("Error: Access forbidden.")

    elif response.status_code == 404:
        print("Error: IOC resource not found.")

    elif response.status_code == 429:
        print("Error: API rate limit exceeded.")

    else:
        print("Status Code:", response.status_code)
        print("Error:", response.text)

    exit()

print("Status Code:", response.status_code)

enrichment = extract_enrichment(response)

print("Input IOC:", ioc)
print("IOC:", enrichment["ioc"])
print("Reputation:", enrichment["reputation"])
print("Malicious:", enrichment["malicious"])
print("Suspicious:", enrichment["suspicious"])
print("Harmless:", enrichment["harmless"])
print("Undetected:", enrichment["undetected"])

abuse_score = 0

if ioc_type == "IP Address":
    abuse_response = query_abuseipdb(ioc, abuseipdb_api_key)

    if abuse_response is None:
        print("\nAbuseIPDB request failed.")

    elif abuse_response.status_code != 200:
        print("\nAbuseIPDB request failed.")
        print("Status Code:", abuse_response.status_code)
        print("Error:", abuse_response.text)

    else:
        abuse_data = abuse_response.json()["data"]
        abuse_score = abuse_data.get("abuseConfidenceScore", 0)

        print("\nAbuseIPDB Results:")
        print("Abuse Confidence Score:", abuse_score)
        print("Total Reports:", abuse_data.get("totalReports"))
        print("Country:", abuse_data.get("countryCode"))
        print("ISP:", abuse_data.get("isp"))

risk, reason = analyze_risk(enrichment, abuse_score)

print("\nRisk Assessment:")
print("Risk Level:", risk)
print("Reason:", reason)

recommendation = get_recommendation(risk)

print("Recommendation:", recommendation)

print("\n========== IOC ENRICHMENT SUMMARY ==========")
print("Input IOC:", ioc)
print("IOC Type:", ioc_type)
print("Risk Level:", risk)
print("Recommendation:", recommendation)
print("============================================")

