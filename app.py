from flask import Flask, request
from twilio.twiml.messaging_response import MessagingResponse
import re
import validators
import requests
from difflib import SequenceMatcher
from urllib.parse import urlparse


app = Flask(__name__)

# Replace these with your actual API keys
VT_API_KEY = ""
GSB_API_KEY = ""
TWILIO_ACCOUNT_SID = ''
TWILIO_AUTH_TOKEN = ''
TWILIO_WHATSAPP_NUMBER = ''  

# Define trusted domains (example)
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

# Check if the URL is from a trusted domain
def is_trusted_url(url, trusted_domains):
    for domain in trusted_domains:
        if domain in url:
            return True
    return False

# Check for typo-squatted domains (basic check)
def is_typo_squatted(url, trusted_domains):
    for domain in trusted_domains:
        if domain in url and not url.startswith(f"https://{domain}"):
            return True
    return False

# Main function to check URL
def check_url(url, vt_api_key, gsb_api_key):
    # Check if URL is trusted
    if is_trusted_url(url, TRUSTED_DOMAINS):
        return "✅ The URL appears to be safe."

    # Check for typo-squatted domains
    if is_typo_squatted(url, TRUSTED_DOMAINS):
        return "Warning: Please make sure you trust the user who send you this because it seems to be mailcious!!!"

    # VirusTotal check
    vt_result = check_virustotal(url, vt_api_key)
    if "error" in vt_result:
        return f"Error with VirusTotal: {vt_result['error']}"
    if vt_result["positives"] > 0:
        return f"🚨 Warning: Please make sure you trust the user who send you this because it seems to be mailcious!!!"

    # Google Safe Browsing check
    gsb_result = check_google_safe_browsing(url, gsb_api_key)
    if "error" in gsb_result:
        return f"Error with Google Safe Browsing: {gsb_result['error']}"
    if gsb_result["threats"]:
        return "🚨 Warning: Please make sure you trust the user who send you this because it seems to be mailcious!!!"

    return "✅ The URL appears to be safe."

# Flask route to handle incoming WhatsApp messages
@app.route("/whatsapp", methods=["POST"])
def whatsapp():
    incoming_msg = request.form.get("Body")  # Retrieve the message body sent by Twilio
    sender = request.form.get("From")  # Retrieve the sender's phone number
    resp = MessagingResponse()  # Create a Twilio response object
    msg = resp.message()

    # Replace with your VirusTotal and Google Safe Browsing API keys
    vt_api_key = ""
    gsb_api_key = ""

    if validators.url(incoming_msg):
        response = check_url(incoming_msg, vt_api_key, gsb_api_key)
    else:
        response = "Please send a valid URL to check."

    msg.body(response)  # Set the response message
    return str(resp)  # Return the Twilio-compatible response

# Test Route
@app.route("/", methods=["GET"])
def home():
    return "Flask app is running!"

if __name__ == "__main__":
    app.run(debug=True)
