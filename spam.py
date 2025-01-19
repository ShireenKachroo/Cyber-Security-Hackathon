import requests
from difflib import SequenceMatcher
from urllib.parse import urlparse

# Trusted payment domains list
TRUSTED_DOMAINS = [
    "www.razorpay.com", "www.payoneer.com", "www.stripe.com", "www.squareup.com",
"www.venmo.com", "www.zellepay.com", "www.adyen.com", "www.authorize.net", "www.skrill.com",
"www.2checkout.com", "www.alipay.com", "www.wepay.com", "www.klarna.com", "www.afterpay.com",
"www.google.com", "www.apple.com", "www.cash.app", "www.revolut.com",
"www.transferwise.com", "www.phonepe.com", "www.billdesk.com", "www.instamojo.com", "www.paytm.com",
"www.ccavenue.com", "www.worldpay.com", "www.braintreepayments.com", "www.dwolla.com",
"www.bluepay.com", "www.payza.com", "www.checkout.com", "www.qiwi.com", "www.yandex.com",
"www.mercadopago.com", "www.pagseguro.uol.com.br", "www.trustly.com", "www.sezzle.com",
"www.shopify.com", "www.fastspring.com", "www.flutterwave.com", "www.moneris.com",
"www.ipay88.com", "www.shopeepay.com", "www.payline.com", "www.payplug.com", "www.coinbase.com",
"www.binance.com", "www.blockchain.com", "www.bitpay.com", "www.cryptopay.me", "www.paxful.com"

]

# Function to check if a URL is trusted
def is_trusted_url(url, trusted_domains):
    domain = urlparse(url).netloc
    if domain in trusted_domains:
        print(f"✅ The URL '{url}' is in the trusted domain list and is SAFE.")
        return True
    return False

# Function to check for typo-squatted domains
def is_typo_squatted(url, trusted_domains):
    domain = urlparse(url).netloc
    for trusted in trusted_domains:
        similarity = SequenceMatcher(None, domain, trusted).ratio()
        if similarity > 0.8:  # Threshold for similarity
            print(f"⚠️ Possible typo-squatted domain detected: {domain} (similar to {trusted})")
            return True
    return False

# Function to check URL with VirusTotal
def check_virustotal(url, api_key):
    api_url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {"apikey": api_key, "resource": url}

    try:
        response = requests.get(api_url, params=params)
        result = response.json()

        if response.status_code == 200 and "positives" in result and "total" in result:
            return {
                "source": "VirusTotal",
                "positives": result["positives"],
                "total": result["total"],
                "url": url,
            }
        else:
            return {"source": "VirusTotal", "error": result.get("verbose_msg", "Unknown error")}
    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}

# Function to check URL with Google Safe Browsing
def check_google_safe_browsing(url, api_key):
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    headers = {"Content-Type": "application/json"}
    payload = {
        "client": {
            "clientId": "your_client_id",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(api_url, headers=headers, json=payload, params={"key": api_key})
        result = response.json()

        if response.status_code == 200:
            if "matches" in result:
                return {"source": "Google Safe Browsing", "threats": result["matches"]}
            else:
                return {"source": "Google Safe Browsing", "threats": []}
        else:
            return {"source": "Google Safe Browsing", "error": result.get("error", {}).get("message", "Unknown error")}
    except Exception as e:
        return {"source": "Google Safe Browsing", "error": str(e)}

def check_url(url):
    # Replace with your virus total, google safe browsing API keys
    vt_api_key = "********************************************"  #hidden due to security reasons
    gsb_api_key = "****************************************"    #hidden due to security reasons

    print(f"🔗 Checking URL: {url}")

    if is_trusted_url(url, TRUSTED_DOMAINS):
        return

    # Check for typo-squatted domains
    if is_typo_squatted(url, TRUSTED_DOMAINS):
        print(f"❌ The URL '{url}' is potentially a SPAM! (Typo-Squatting)")
        return

    # VirusTotal result
    vt_result = check_virustotal(url, vt_api_key)
    vt_is_malicious = False
    if "error" not in vt_result:
        print(f"[VirusTotal] 🚨 Malicious detections: {vt_result['positives']}/{vt_result['total']}")
        if vt_result["positives"] > 0:
            vt_is_malicious = True
    else:
        print(f"[VirusTotal] Error: {vt_result['error']}")

    # Google Safe Browsing result
    gsb_result = check_google_safe_browsing(url, gsb_api_key)
    gsb_is_malicious = False
    if "error" not in gsb_result:
        if gsb_result["threats"]:
            print("[Google Safe Browsing] 🚨 Threats found:")
            gsb_is_malicious = True
        else:
            print("[Google Safe Browsing] ✅ No threats detected.")
    else:
        print(f"[Google Safe Browsing] Error: {gsb_result['error']}")

    if vt_is_malicious or gsb_is_malicious:
        print(f"❌ The URL '{url}' is a SPAM!")
    else:
        print(f"✅ The URL '{url}' is SAFE.")

if __name__ == "__main__":
    url = input("Enter the URL to check: ")
    check_url(url)
