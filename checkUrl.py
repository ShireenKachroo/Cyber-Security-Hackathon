import requests
import base64

API_KEY = "e844603ee89b545691de8713c284538e3a6ddb9aa1fd2f63ba5e575f4931dd1"
BASE_URL = "https://www.virustotal.com/api/v3"

# Function to check URL for maliciousness
def check_url_maliciousness(url_to_check):
    # Encode the URL in base64
    encoded_url = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
    # URL to fetch the analysis result directly
    analysis_url = f"{BASE_URL}/urls/{encoded_url}"
  
    headers = {
        "x-apikey": API_KEY
    }

    # Make the GET request to check the URL analysis directly
    analysis_response = requests.get(analysis_url, headers=headers)
  
    if analysis_response.status_code == 200:
        analysis_data = analysis_response.json()
        malicious = False
        if "data" in analysis_data:
            attributes = analysis_data["data"]["attributes"]
            malicious = attributes["last_analysis_stats"]["malicious"] > 0

        if malicious:
            print("The URL is malicious.")
        else:
            print("The URL is clean.")
    else:
        print(f"Error fetching analysis report: {analysis_response.status_code}, {analysis_response.text}")

# Example usage
if __name__ == "__main__":
    url_to_check =  "https://verifydevice-au.com/"
    check_url_maliciousness(url_to_check)
