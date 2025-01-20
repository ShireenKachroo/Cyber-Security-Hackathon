chrome.webNavigation.onCommitted.addListener(async (details) => {
    if (details.transitionType === "link") {
        let result = await checkURL(details.url);
        if (result.includes("⚠️")) {
            alert("Warning: This link may be unsafe!\n" + details.url);
        }
    }
});


async function checkURL(url) {
    const safeBrowsingKey = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"; // Replace with your API key
    const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${safeBrowsingKey}`;
   
    const requestBody = {
        client: { clientId: "linkChecker", clientVersion: "1.0" },
        threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }]
        }
    };


    try {
        const response = await fetch(apiUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(requestBody)
        });


        const data = await response.json();
        return Object.keys(data).length ? "⚠️ Unsafe URL detected!" : "✅ Safe URL!";
    } catch (error) {
        return "⚠️ Error checking URL!";
    }
}



