// ================= Common Scan Handler ================= //
async function runScan(targetUrl = null) {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        const tab = tabs[0];

        const finalUrl = targetUrl || tab.url;
        if (!finalUrl) return alert("⚠ Unable to detect URL!");

        try {
            const res = await fetch("https://website-risk-scorer-api.onrender.com/scan_url", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: finalUrl })
            });

            if (!res.ok) throw new Error("API error");

            const result = await res.json();
            showRisk(result);

        } catch (err) {
            console.error("Error:", err);
            alert("⚠ Backend error. Please check server status.");
        }
    });
}


// ================= Scan Current Website ================= //
document.getElementById("scanBtn").addEventListener("click", () => {
    runScan();
});


// ================= Manual URL Scan ================= //
document.getElementById("checkBtn").addEventListener("click", () => {
    const url = document.getElementById("manualUrl").value.trim();
    if (!url) return alert("Please enter a valid URL");
    runScan(url);
});


// ================= UI Logic ================= //
function getRiskIcon(classification) {
    switch (classification) {
        case "Safe": return "🟢";
        case "Low Risk": return "🟡";
        case "Suspicious": return "🟠";
        case "High Risk": return "🔴";
        case "Blacklisted Threat": return "☠️";
        default: return "❓";
    }
}

function showRisk(result) {
    const box = document.getElementById("riskBox");

    const score = Number(result.risk_score) || 0;
    const classification = result.risk_class || "Unknown";
    const sbFlag = result.blacklist_flag === 1;

    const icon = getRiskIcon(classification);

    let color = "#4CAF50"; // Safe default
    if (classification === "Low Risk") color = "#FFC107";
    else if (classification === "Suspicious") color = "#FF9800";
    else if (classification === "High Risk") color = "#F44336";
    if (sbFlag) color = "#B71C1C";

let detail = "";
if (sbFlag) {
    detail = "☠ Blacklisted — known dangerous site!";
} else {
    switch (classification) {
        case "Safe":
            detail = "🟢 This website appears legitimate.";
            break;
        case "Low Risk":
            detail = "🟡 Minor risk signals — browse carefully.";
            break;
        case "Suspicious":
            detail = "🟠 Warning: Multiple suspicious signs detected.";
            break;
        case "High Risk":
            detail = "🔴 High likelihood of fraud — avoid using this site.";
            break;
        default:
            detail = "ℹ Additional review advised.";
    }
}

    box.style.backgroundColor = color;
    box.style.color = "#fff";
    box.style.padding = "10px";
    box.style.borderRadius = "6px";

    box.innerHTML = `
        <h3>${icon} ${classification}</h3>
        <p><strong>Risk Score:</strong> ${score.toFixed(2)}%</p>
        <hr style="border:0;border-top:1px solid rgba(255,255,255,0.4);margin:6px 0;">
        <p><strong>Threat Details:</strong> ${detail}</p>
    `;
}
