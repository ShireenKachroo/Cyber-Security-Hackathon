document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("checkBtn").addEventListener("click", async () => {
        let url = document.getElementById("urlInput").value.trim();
        let resultDiv = document.getElementById("result");

        if (!url) {
            resultDiv.innerText = "❌ Please enter a URL";
            resultDiv.style.color = "red";
            resultDiv.style.display = "block";
            return;
        }

        // Show loading message
        resultDiv.innerText = "⏳ Checking...";
        resultDiv.style.color = "black";
        resultDiv.style.display = "block";

        // Check the URL using VirusTotal
        let virusTotalResult = await checkWithVirusTotal(url);

        // Combine results
        resultDiv.innerText = virusTotalResult;

        // Adjust styling based on results
        if (virusTotalResult.includes("Unsafe") || virusTotalResult.includes("detection(s) found")) {
            resultDiv.style.color = "red";
        } else {
            resultDiv.style.color = "green";
        }
    });
});

async function checkWithVirusTotal(url) {
    const virusTotalKey = "3a68df74b219bbc45d96a3cedf81ee6863a9ff3edd570f748098d343fa16b681";

    if (!virusTotalKey) {
        return "⚠ VirusTotal API Key is missing!";
    }

    const apiUrl = "https://www.virustotal.com/api/v3/urls";

    try {
        // Encode the URL to match VirusTotal's requirements
        const encodedUrl = btoa(url);

        // Submit the URL for scanning
        const scanResponse = await fetch(apiUrl, {
            method: "POST",
            headers: {
                "x-apikey": virusTotalKey,
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: `url=${url}`
        });

        if (!scanResponse.ok) {
            throw new Error(`HTTP Error: ${scanResponse.status}`);
        }

        const scanData = await scanResponse.json();

        // Use the scan ID to get the results
        const analysisId = scanData.data.id;
        const analysisUrl = `https://www.virustotal.com/api/v3/analyses/${analysisId}`;

        // Fetch the results
        const analysisResponse = await fetch(analysisUrl, {
            method: "GET",
            headers: {
                "x-apikey": virusTotalKey
            }
        });

        if (!analysisResponse.ok) {
            throw new Error(`HTTP Error: ${analysisResponse.status}`);
        }

        const analysisData = await analysisResponse.json();

        // Check for any detections
        const maliciousCount = analysisData.data.attributes.stats.malicious;

        if (maliciousCount > 0) {
            return "⚠ Unsafe Website!";
        } else {
            return "✅ Website is safe!";
        }
    } catch (error) {
        console.error("Error checking URL with VirusTotal:", error);
        return `⚠ Error checking URL: ${error.message}`;
    }
}

async function checkWithPhishTank(url) {
    const phishTankUrl = "https://data.phishtank.com/data/online-valid.csv";

    try {
        const response = await fetch(phishTankUrl);
        const csvText = await response.text();

        // Check if URL is in the blacklist
        if (csvText.includes(url)) {
            return "⚠ Phishing URL detected!";
        } else {
            return "✅ No phishing detected!";
        }
    } catch (error) {
        console.error("Error checking URL with PhishTank:", error);
        return "⚠ Error checking PhishTank!";
    }
}
