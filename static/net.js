
// ============================================================
// UNIFIED NETWORK MONITOR - REAL BACKEND CONNECTED JAVASCRIPT
// ============================================================

let currentDeviceId = null;
let currentDeviceIp = null;

function el(id) {
    return document.getElementById(id);
}

function setText(id, value, fallback = "—") {
    const node = el(id);

    if (!node) {
        return;
    }

    if (value === null || value === undefined || value === "") {
        node.textContent = fallback;
    } else {
        node.textContent = value;
    }
}

function riskClass(risk) {
    risk = (risk || "").toLowerCase();

    if (risk === "low" || risk === "medium" || risk === "high") {
        return risk;
    }

    return "";
}


// ============================================================
// PAGE NAVIGATION
// ============================================================

function showDevicePage(name) {

    const isNetwork = name === "network";
    const isDetails =
        name === "details" ||
        name === "device-details-page";

    if (el("network")) {
        el("network").classList.toggle("active", isNetwork);
    }

    if (el("device-details-page")) {
        el("device-details-page").classList.toggle("active", isDetails);
    }

    if (el("nav-network")) {
        el("nav-network").classList.toggle("active", isNetwork);
    }

    if (el("nav-details")) {
        el("nav-details").classList.toggle("active", isDetails);
    }

    if (isNetwork) {
        window.scrollTo({
            top: 0,
            behavior: "smooth"
        });
    }
}


// ============================================================
// NETWORK SCAN
// ============================================================

async function startNetworkScan() {

    const btn = el("net-scan-btn");

    if (btn) {
        btn.disabled = true;
        btn.textContent = "⟳ Scanning…";
    }

    setText("net-scan-status", "Scanning");

    try {

        const response = await fetch("/api/scan");

        if (!response.ok) {
            throw new Error("Network scan failed");
        }

        const data = await response.json();

        console.log("Scan response:", data);

        const devices = data.devices || [];

        renderNetworkTable(devices);

        setText(
            "net-device-count",
            `${devices.length} devices`
        );

        setText(
            "net-count-label",
            `${devices.length} devices`
        );

        setText("net-scan-status", "Complete");

    } catch (error) {

        console.error("Scan error:", error);

        setText("net-scan-status", "Failed");

        const tbody = el("net-device-table");

        if (tbody) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6">
                        Network scan failed. Check the Flask backend.
                    </td>
                </tr>
            `;
        }

    } finally {

        if (btn) {
            btn.disabled = false;
            btn.textContent = "⟳  Scan Network";
        }
    }
}


// ============================================================
// DISPLAY REAL DEVICES
// ============================================================

function renderNetworkTable(devices) {

    const tbody = el("net-device-table");

    if (!tbody) {
        return;
    }

    tbody.innerHTML = "";

    if (!devices || devices.length === 0) {

        tbody.innerHTML = `
            <tr>
                <td colspan="6">
                    No devices found.
                </td>
            </tr>
        `;

        return;
    }

    devices.forEach(function (device) {

        const tr = document.createElement("tr");

        tr.className = "devicetable-row";

        /*
         * Use the IP address as the current device reference.
         * This matches the existing Flask route:
         *
         * /api/device/<ip>
         */

        tr.onclick = function () {

            currentDeviceId =
                device.id ||
                device.device_id ||
                device.ip;

            currentDeviceIp =
                device.ip ||
                device.ip_address;

            if (!currentDeviceIp) {
                console.error("Device IP is missing:", device);
                return;
            }

            showDevicePage("device-details-page");

            renderDeviceDetails(currentDeviceIp);
        };

        const hostname =
            device.hostname ||
            device.device_name ||
            "Unknown";

        const ip =
            device.ip ||
            device.ip_address ||
            "—";

        const mac =
            device.mac ||
            device.mac_address ||
            "—";

        const status =
            device.status ||
            "unknown";

        const vendor =
            device.vendor ||
            "Unknown Vendor";

        const risk =
            device.risk ||
            device.risk_level ||
            "—";

        tr.innerHTML = `
            <td>${hostname}</td>
            <td>${ip}</td>
            <td>${mac}</td>
            <td>${status}</td>
            <td>${vendor}</td>
            <td>
                <span class="risk-badge ${riskClass(risk)}">
                    ${risk}
                </span>
            </td>
        `;

        tbody.appendChild(tr);
    });

    setText(
        "net-count-label",
        `${devices.length} devices`
    );

    setText(
        "net-device-count",
        `${devices.length} devices`
    );
}


// ============================================================
// DEVICE DETAILS
// ============================================================

async function renderDeviceDetails(ip) {

    if (!ip) {
        console.error("No device IP selected");
        return;
    }

    currentDeviceIp = ip;

    console.log("Loading device details:", ip);

    /*
     * Clear old information while loading.
     */

    setText("dd-hostname", "Loading...");
    setText("dd-ip", ip);
    setText("dd-mac", "Loading...");
    setText("dd-vendor", "Loading...");

    setText("qs-status", "Loading...");
    setText("qs-first-seen", "Loading...");
    setText("qs-last-seen", "Loading...");
    setText("qs-open-ports", "—");
    setText("qs-alerts", "—");
    setText("qs-risk", "—");

    try {

        const response =
            await fetch(
                "/api/device/" + encodeURIComponent(ip)
            );

        if (!response.ok) {
            throw new Error(
                "Device details request failed"
            );
        }

        const data = await response.json();

        console.log("Device details:", data);

        displayDeviceDetails(data);

        /*
         * History is loaded separately.
         * This prevents the device details API from becoming too large.
         */

        await loadDeviceHistory(ip);

    } catch (error) {

        console.error(
            "Device details error:",
            error
        );

        setText(
            "dd-hostname",
            "Unable to load device"
        );

        setText(
            "dd-vendor",
            "Backend error"
        );
    }
}


// ============================================================
// DISPLAY DEVICE INFORMATION
// ============================================================

function displayDeviceDetails(data) {

    const hostname =
        data.hostname ||
        data.device_name ||
        "Unknown";

    const ip =
        data.ip ||
        data.ip_address ||
        currentDeviceIp ||
        "—";

    const mac =
        data.mac ||
        data.mac_address ||
        "—";

    const vendor =
        data.vendor ||
        "Unknown Vendor";

    const status =
        data.status ||
        "unknown";

    const risk =
        data.risk ||
        data.risk_level ||
        "—";

    const firstSeen =
        data.first_seen ||
        "—";

    const lastSeen =
        data.last_seen ||
        "—";

    const openPorts =
        data.open_ports_count !== undefined
            ? data.open_ports_count
            : (
                Array.isArray(data.open_ports)
                    ? data.open_ports.length
                    : "—"
            );

    const alerts =
        data.alerts_count !== undefined
            ? data.alerts_count
            : "—";


    // --------------------------------------------------------
    // Main summary
    // --------------------------------------------------------

    setText("dd-hostname", hostname);
    setText("dd-ip", ip);
    setText("dd-mac", mac);
    setText("dd-vendor", vendor);

    const dot = el("dd-status-dot");

    if (dot) {

        dot.className =
            "dd-dot " +
            (
                status.toLowerCase() === "online"
                    ? "online"
                    : "offline"
            );
    }

    const badge = el("dd-risk-badge");

    if (badge) {

        badge.textContent = risk;

        badge.className =
            "risk-badge " +
            riskClass(risk);
    }


    // --------------------------------------------------------
    // Quick statistics
    // --------------------------------------------------------

    setText("qs-status", status);
    setText("qs-first-seen", firstSeen);
    setText("qs-last-seen", lastSeen);
    setText("qs-open-ports", openPorts);
    setText("qs-alerts", alerts);
    setText("qs-risk", risk);


    // --------------------------------------------------------
    // Device identity
    // --------------------------------------------------------

    setText("id-hostname", hostname);
    setText("id-ip", ip);
    setText("id-mac", mac);
    setText("id-vendor", vendor);
    setText("id-status", status);
    setText("id-first-seen", firstSeen);
    setText("id-last-seen", lastSeen);


    // --------------------------------------------------------
    // Device Story
    // --------------------------------------------------------

    renderStory(data);


    // --------------------------------------------------------
    // Investigation Timeline
    // --------------------------------------------------------

    renderTimeline(data);


    // --------------------------------------------------------
    // Open Ports
    // --------------------------------------------------------

        if (Array.isArray(data.open_ports)) {
        displayPorts(data.open_ports);
       } else {
        resetPorts();
    }
}   // ← ADD THIS



// ============================================================
// DEVICE STORY
// ============================================================

function renderStory(data) {

    const storyList = el("dd-story");

    if (!storyList) {
        return;
    }

    storyList.innerHTML = "";

    let story = data.story || [];

    if (!Array.isArray(story)) {
        story = [];
    }

    if (story.length === 0) {

        const li = document.createElement("li");

        li.textContent =
            "No investigation story is available yet.";

        storyList.appendChild(li);

        return;
    }

    story.forEach(function (line) {

        const li = document.createElement("li");

        li.textContent = line;

        storyList.appendChild(li);
    });
}


// ============================================================
// INVESTIGATION TIMELINE
// ============================================================

function renderTimeline(data) {

    const wrapper = el("dd-timeline");

    if (!wrapper) {
        return;
    }

    wrapper.innerHTML = "";

    let timeline = data.timeline || [];

    if (!Array.isArray(timeline)) {
        timeline = [];
    }

    if (timeline.length === 0) {

        wrapper.textContent =
            "No timeline events available.";

        return;
    }

    timeline.forEach(function (event) {

        const item =
            document.createElement("div");

        item.className =
            "dd-timeline-item";

        const time =
            event.time ||
            event.timestamp ||
            "—";

        const title =
            event.title ||
            event.event ||
            "Event";

        const text =
            event.text ||
            event.description ||
            "";

        item.innerHTML = `
            <div class="dd-timeline-dot"></div>

            <div>
                <div class="dd-timeline-time">
                    ${time}
                </div>

                <div class="dd-timeline-title">
                    ${title}
                </div>

                <div class="dd-timeline-text">
                    ${text}
                </div>
            </div>
        `;

        wrapper.appendChild(item);
    });
}


// ============================================================
// PORT SCAN
// ============================================================

async function scanPorts() {

    if (!currentDeviceIp) {
        alert("Please select a device first.");
        return;
    }

    const btn = el("dd-scan-btn");

    if (btn) {
        btn.disabled = true;
        btn.textContent = "🔍 Scanning…";
    }

    const msg = el("dd-ports-msg");

    if (msg) {
        msg.style.display = "block";
        msg.textContent = "Scanning ports…";
    }

    try {

        const response =
            await fetch(
                "/api/ports/" +
                encodeURIComponent(currentDeviceIp)
            );

        if (!response.ok) {
            throw new Error("Port scan failed");
        }

        const data = await response.json();

        console.log("Port scan:", data);

        const ports =
            data.open_ports ||
            data.ports ||
            [];

        displayPorts(ports);

        setText(
            "qs-open-ports",
            ports.length
        );

    } catch (error) {

        console.error(
            "Port scan error:",
            error
        );

        if (msg) {
            msg.textContent =
                "Port scan failed.";
        }

    } finally {

        if (btn) {
            btn.disabled = false;
            btn.textContent = "🔍  Scan Ports";
        }
    }
}


function displayPorts(ports) {

    const msg = el("dd-ports-msg");
    const table = el("dd-ports-table");
    const body = el("dd-ports-body");

    if (!body || !table || !msg) {
        return;
    }

    body.innerHTML = "";

    if (!ports || ports.length === 0) {

        table.style.display = "none";

        msg.style.display = "block";

        msg.textContent =
            "No open ports found.";

        return;
    }

    msg.style.display = "none";

    table.style.display = "";

    ports.forEach(function (port) {

        const tr =
            document.createElement("tr");

        tr.innerHTML = `
            <td>${port.port ?? "—"}</td>
            <td>${port.protocol ?? "TCP"}</td>
            <td>${port.state ?? "open"}</td>
            <td>${port.service ?? "Unknown"}</td>
        `;

        body.appendChild(tr);
    });
}


function resetPorts() {

    const msg = el("dd-ports-msg");
    const table = el("dd-ports-table");
    const body = el("dd-ports-body");

    if (msg) {
        msg.style.display = "block";
        msg.textContent =
            "Ports have not been scanned yet.";
    }

    if (table) {
        table.style.display = "none";
    }

    if (body) {
        body.innerHTML = "";
    }
}


// ============================================================
// SECURITY CHECK
// ============================================================




// ============================================================
// DEVICE HISTORY
// ============================================================

async function loadDeviceHistory(ip) {
    try {
        const response = await fetch(
            "/api/log-history?ip=" + encodeURIComponent(ip)
        );

        if (!response.ok) {
            throw new Error("History request failed");
        }

        const data = await response.json();

        console.log("HISTORY API:", data);

        displayHistory(data.history || []);

    } catch (error) {
        console.error("History error:", error);
        displayHistory([]);
    }
}

function displayHistory(history) {
    const body = el("dd-history-body");

    if (!body) return;

    body.innerHTML = "";

    if (!Array.isArray(history) || history.length === 0) {
        setText("dd-history-count", "0 events");

        const tr = document.createElement("tr");

        tr.innerHTML = `
            <td colspan="4">No history recorded for this device.</td>
        `;

        body.appendChild(tr);
        return;
    }

   el("dd-history-count").textContent = `${history.length} events`;

    history.forEach(function (row) {
        const tr = document.createElement("tr");

        tr.innerHTML = `
            <td>${row.detected_at || "—"}</td>
            <td>Device detected</td>
            <td>${row.ip_address || "—"}</td>
            <td>${row.status || "—"}</td>
        `;

        body.appendChild(tr);
    });
}

// ============================================================
// HISTORY SCROLL
// ============================================================

function scrollToHistory() {

    if (currentDeviceIp) {
        loadDeviceHistory(currentDeviceIp);
    }

    const section =
        el("device-history-section");

    if (section) {

        section.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });
    }
}
// ============================================================
// INITIAL PAGE LOAD
// ============================================================

document.addEventListener("DOMContentLoaded", function () {

    /*
     * Do not use fake/sample devices here.
     *
     * The user must perform a real scan.
     */

    showDevicePage("home");

    setText(
        "net-scan-status",
        "Idle"
    );

    setText(
        "net-device-count",
        "0 devices"
    );

    setText(
        "net-count-label",
        "0 devices"
    );

});

// ============================================================
// NETWORK TRAFFIC USAGE
// ============================================================

async function updateTrafficUsage() {
    try {
        const response = await fetch("/api/traffic");

        if (!response.ok) {
            return;
        }

        const data = await response.json();
        const interfaces = data.interface_stats || {};

        let totalBytes = 0;

        Object.values(interfaces).forEach(function (item) {
            totalBytes += Number(item.bytes_sent || 0);
            totalBytes += Number(item.bytes_recv || 0);
        });

        let usage;

        if (totalBytes >= 1024 * 1024 * 1024) {
            usage = (totalBytes / (1024 * 1024 * 1024)).toFixed(2) + " GB";
        } else if (totalBytes >= 1024 * 1024) {
            usage = (totalBytes / (1024 * 1024)).toFixed(2) + " MB";
        } else if (totalBytes >= 1024) {
            usage = (totalBytes / 1024).toFixed(2) + " KB";
        } else {
            usage = totalBytes + " B";
        }

        setText("net-traffic-usage", usage);

        } catch (error) {
        console.error("Traffic usage error:", error);
    }
}

updateTrafficUsage();