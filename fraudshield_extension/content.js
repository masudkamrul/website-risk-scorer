// ================= Feature Functions ================ //
function getHasHSTS() {
    try {
        const hsts = document.querySelectorAll(
            'meta[http-equiv="Strict-Transport-Security"]'
        );
        return hsts.length > 0 ? 1 : 0;
    } catch {
        return 0;
    }
}

function getHasCSP() {
    try {
        const metaTags = document.querySelectorAll(
            'meta[http-equiv="Content-Security-Policy"], meta[content*="default-src"], meta[content*="script-src"]'
        );
        return metaTags.length > 0 ? 1 : 0;
    } catch {
        return 0;
    }
}

function getRedirectCount() {
    try {
        return performance.getEntriesByType("navigation")[0].redirectCount || 0;
    } catch {
        return 0;
    }
}

function detectSensitiveForms() {
    const fields = document.querySelectorAll("input");
    return [...fields].some(f =>
        ["password", "email", "tel"].includes(f.type)
    ) ? 1 : 0;
}

function detectCryptoOnlyPayments() {
    const html = document.body.innerText.toLowerCase();
    return (html.includes("bitcoin") || html.includes("crypto")) ? 1 : 0;
}

function getMixedContentCount() {
    try {
        const elements = document.querySelectorAll("img, script, link, iframe");
        let count = 0;
        elements.forEach(el => {
            const src = el.src || el.href || "";
            if (src.startsWith("http://")) count++;
        });
        return count;
    } catch {
        return 0;
    }
}

function getTotalResourceCount() {
    try {
        return document.querySelectorAll("img, script, link, iframe").length;
    } catch {
        return 0;
    }
}

function getMixedContentRatio() {
    const total = getTotalResourceCount();
    const mixed = getMixedContentCount();
    if (total === 0) return 0;
    return mixed / total;
}

function getUsesHttps() {
    return window.location.protocol === "https:" ? 1 : 0;
}

function getSSLStatus() {
    return window.isSecureContext ? 1 : 0;
}

// =============== Extract Features Main Function =============== //
function extractFeaturesFromPage() {
    console.log("Extracting features for:", window.location.href);

    const features = [
        999, // 0 placeholder domain age (server replaces)
        0,0,0, // placeholders
        getSSLStatus(),  // 4
        0,0,             // placeholders
        0,0,0,0,0,0,0,   // placeholders
        detectCryptoOnlyPayments(), // 13
        getRedirectCount(),         // 14
        0,                          // placeholder
        detectSensitiveForms(),     // 16
        0,0,                        // placeholders
        getUsesHttps(),             // 18
        getMixedContentCount(),     // 19
        getTotalResourceCount(),    // 20
        getMixedContentRatio(),     // 21
        getHasHSTS(),               // 22
        getHasCSP()                 // 23
    ];

    return {
        features,
        url: window.location.href
    };
}

// =============== Listener =============== //
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === "extract_features") {
        sendResponse(extractFeaturesFromPage());
    }
});
