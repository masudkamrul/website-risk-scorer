chrome.runtime.onInstalled.addListener(() => {
    console.log("FraudShield background installed");
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    console.log("Background received:", msg);

    if (msg.action === "features_extracted") {
        if (chrome.storage && chrome.storage.local) {
            chrome.storage.local.set({
				currentFeatures: msg.features,
				currentUrl: msg.url
			}, () => {
				console.log("Background stored features + URL:", msg.url);
			});
        } else {
            console.log("Storage NOT ready yet");
        }
        sendResponse({ status: "ok" });
    }

    return true;
});
