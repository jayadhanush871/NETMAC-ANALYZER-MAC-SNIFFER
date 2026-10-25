/**
 * NetShark - Network MAC & IP Packet Analyzer
 * Interactive Frontend Controller
 */

document.addEventListener("DOMContentLoaded", () => {
    // State variables
    let captureState = "STOPPED";
    let lastPacketId = 0;
    let selectedPacketId = null;
    let autoScroll = true;
    let pollInterval = null;
    let currentProtocolFilter = "";
    let currentSearchQuery = "";
    let capturedPacketsCache = [];

    // DOM Elements
    const interfaceSelect = document.getElementById("interfaceSelect");
    const filterPresetSelect = document.getElementById("filterPresetSelect");
    const customBpfContainer = document.getElementById("customBpfContainer");
    const customBpfInput = document.getElementById("customBpfInput");

    const btnStart = document.getElementById("btnStart");
    const btnPause = document.getElementById("btnPause");
    const btnStop = document.getElementById("btnStop");
    const btnClear = document.getElementById("btnClear");
    const btnExportPcap = document.getElementById("btnExportPcap");
    const btnExportCsv = document.getElementById("btnExportCsv");

    const metricPacketCount = document.getElementById("metricPacketCount");
    const metricState = document.getElementById("metricState");
    const metricInterfaceName = document.getElementById("metricInterfaceName");
    const metricBytes = document.getElementById("metricBytes");
    const metricBytesDetail = document.getElementById("metricBytesDetail");
    const metricElapsed = document.getElementById("metricElapsed");
    const metricPps = document.getElementById("metricPps");
    const metricUniqueMacs = document.getElementById("metricUniqueMacs");
    const metricUniqueIps = document.getElementById("metricUniqueIps");

    const packetTableBody = document.getElementById("packetTableBody");
    const packetTableContainer = document.getElementById("packetTableContainer");
    const emptyRowPlaceholder = document.getElementById("emptyRowPlaceholder");
    const chkAutoScroll = document.getElementById("chkAutoScroll");
    const packetSearchInput = document.getElementById("packetSearchInput");
    const btnClearSearch = document.getElementById("btnClearSearch");

    const inspectionTitle = document.getElementById("inspectionTitle");
    const selectedPacketBadge = document.getElementById("selectedPacketBadge");
    const layerTreeContainer = document.getElementById("layerTreeContainer");
    const hexDumpContent = document.getElementById("hexDumpContent");

    const bannerText = document.getElementById("bannerText");
    const tabButtons = document.querySelectorAll(".tab-btn");
    const tabContents = document.querySelectorAll(".tab-content");
    const protoPills = document.querySelectorAll(".proto-pill");

    // Dynamic Live Analytics & Visual Charts Elements
    const liveChartsSection = document.getElementById("liveChartsSection");
    const chartsGrid = document.getElementById("chartsGrid");
    const chartsPacketBadge = document.getElementById("chartsPacketBadge");
    const btnToggleChartsCollapse = document.getElementById("btnToggleChartsCollapse");
    const collapseIcon = document.getElementById("collapseIcon");
    const collapseText = document.getElementById("collapseText");

    // Chart.js references & time-series data buffers
    let chartProtocol = null;
    let chartPacketsTime = null;
    let chartDataTime = null;
    let chartTopMacs = null;
    let chartsVisible = false;
    let chartsCollapsed = false;

    const MAX_TIME_SLICES = 16;
    const timeLabels = [];
    const packetRateHistory = [];
    const dataRateHistory = [];
    let previousPktCount = 0;
    let previousBytes = 0;
    let lastMacFetchTime = 0;

    // Initialize application
    init();

    async function init() {
        setupEventListeners();
        setupChartsToggle();
        await loadInterfaces();
        updateStatus();
        startStatusPolling();
    }

    // -------------------------------------------------------------
    // Interface Loading
    // -------------------------------------------------------------
    async function loadInterfaces() {
        try {
            const res = await fetch("/api/interfaces");
            const data = await res.json();
            interfaceSelect.innerHTML = "";

            let hotspotOption = null;
            data.interfaces.forEach((iface) => {
                const opt = document.createElement("option");
                opt.value = iface.name;
                opt.textContent = iface.display_name;
                if (iface.is_hotspot) {
                    opt.selected = true;
                    hotspotOption = opt;
                }
                interfaceSelect.appendChild(opt);
            });

            // If hotspot found, select it; otherwise default
            if (!hotspotOption && data.default) {
                interfaceSelect.value = data.default;
            }
        } catch (err) {
            console.error("Failed to load interfaces:", err);
            interfaceSelect.innerHTML = '<option value="">Error loading interfaces</option>';
        }
    }

    // -------------------------------------------------------------
    // Event Listeners
    // -------------------------------------------------------------
    function setupEventListeners() {
        // Filter preset switch
        filterPresetSelect.addEventListener("change", (e) => {
            if (e.target.value === "custom") {
                customBpfContainer.classList.remove("hidden");
            } else {
                customBpfContainer.classList.add("hidden");
            }

            if (e.target.value === "phone_all") {
                bannerText.innerHTML = `<strong>Phone Activity Mode Active:</strong> Starts strictly at 0 packets. Generates packets whenever you use your phone (WhatsApp, Instagram, YouTube, streaming, games, or browsing)!`;
            } else if (e.target.value === "browsing") {
                bannerText.innerHTML = `<strong>Browsing Mode Active:</strong> Filters strictly for web browser traffic (HTTP, HTTPS, DNS queries).`;
            } else if (e.target.value === "all") {
                bannerText.innerHTML = `<strong>Unfiltered Mode:</strong> Captures all packets passing through the selected network interface.`;
            } else {
                bannerText.innerHTML = `<strong>Custom BPF Mode:</strong> Applying custom filter expression.`;
            }
        });

        // Start capture
        btnStart.addEventListener("click", async () => {
            const iface = interfaceSelect.value;
            const preset = filterPresetSelect.value;
            const bpf = customBpfInput.value;

            try {
                btnStart.disabled = true;
                const res = await fetch("/api/capture/start", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ interface: iface, filter_preset: preset, custom_bpf: bpf }),
                });
                const data = await res.json();
                if (data.success) {
                    updateUiState("RUNNING");
                }
            } catch (err) {
                console.error("Start failed:", err);
            } finally {
                btnStart.disabled = false;
            }
        });

        // Pause capture
        btnPause.addEventListener("click", async () => {
            try {
                const endpoint = captureState === "PAUSED" ? "/api/capture/resume" : "/api/capture/pause";
                const res = await fetch(endpoint, { method: "POST" });
                const data = await res.json();
                if (data.success) {
                    updateUiState(captureState === "PAUSED" ? "RUNNING" : "PAUSED");
                }
            } catch (err) {
                console.error("Pause/resume toggle failed:", err);
            }
        });

        // Stop capture
        btnStop.addEventListener("click", async () => {
            try {
                const res = await fetch("/api/capture/stop", { method: "POST" });
                const data = await res.json();
                if (data.success) {
                    updateUiState("STOPPED");
                }
            } catch (err) {
                console.error("Stop failed:", err);
            }
        });

        // Clear / Reset back to 0
        btnClear.addEventListener("click", async () => {
            try {
                const res = await fetch("/api/capture/clear", { method: "POST" });
                const data = await res.json();
                if (data.success) {
                    // Reset client state
                    lastPacketId = 0;
                    selectedPacketId = null;
                    capturedPacketsCache = [];
                    packetTableBody.innerHTML = `
                        <tr class="empty-row" id="emptyRowPlaceholder">
                            <td colspan="9">
                                <div class="empty-state">
                                    <div class="empty-icon">📡</div>
                                    <div class="empty-title">Ready to Capture (0 Packets)</div>
                                    <div class="empty-desc">Click <strong>Start Sniffing</strong> above to begin listening on the Mobile Hotspot adapter.<br>Packets will generate as soon as you use your phone (open any app, stream video, or browse)!</div>
                                </div>
                            </td>
                        </tr>
                    `;
                    resetInspectionPane();
                    updateStatusMetrics({
                        packet_count: 0,
                        total_bytes: 0,
                        elapsed_seconds: 0,
                        state: "STOPPED",
                    });
                    updateUiState("STOPPED");

                    // Hide and destroy charts when cleared back to 0 packets
                    hideCharts();
                }
            } catch (err) {
                console.error("Clear failed:", err);
            }
        });

        // Export PCAP
        btnExportPcap.addEventListener("click", () => {
            window.location.href = "/api/export/pcap";
        });

        // Export CSV
        btnExportCsv.addEventListener("click", () => {
            window.location.href = "/api/export/csv";
        });

        // Auto scroll toggle
        chkAutoScroll.addEventListener("change", (e) => {
            autoScroll = e.target.checked;
        });

        // Protocol pills filter
        protoPills.forEach((pill) => {
            pill.addEventListener("click", () => {
                protoPills.forEach((p) => p.classList.remove("active"));
                pill.classList.add("active");
                currentProtocolFilter = pill.dataset.proto;
                refilterPackets();
            });
        });

        // Search input
        packetSearchInput.addEventListener("input", (e) => {
            currentSearchQuery = e.target.value.trim().toLowerCase();
            refilterPackets();
        });

        btnClearSearch.addEventListener("click", () => {
            packetSearchInput.value = "";
            currentSearchQuery = "";
            refilterPackets();
        });

        // Tab switcher
        tabButtons.forEach((btn) => {
            btn.addEventListener("click", () => {
                tabButtons.forEach((b) => b.classList.remove("active"));
                tabContents.forEach((c) => c.classList.remove("active"));
                btn.classList.add("active");
                const targetTab = document.getElementById(btn.dataset.tab);
                if (targetTab) {
                    targetTab.classList.add("active");
                    if (btn.dataset.tab === "tab-mac-analysis") {
                        loadMacAnalysis();
                    }
                }
            });
        });
    }

    // -------------------------------------------------------------
    // Charts Collapse / Expand Control
    // -------------------------------------------------------------
    function setupChartsToggle() {
        if (!btnToggleChartsCollapse) return;
        btnToggleChartsCollapse.addEventListener("click", () => {
            chartsCollapsed = !chartsCollapsed;
            if (chartsCollapsed) {
                chartsGrid.classList.add("collapsed");
                collapseIcon.textContent = "▸";
                collapseText.textContent = "Expand";
            } else {
                chartsGrid.classList.remove("collapsed");
                collapseIcon.textContent = "▾";
                collapseText.textContent = "Minimize";
                if (chartProtocol) chartProtocol.resize();
                if (chartPacketsTime) chartPacketsTime.resize();
                if (chartDataTime) chartDataTime.resize();
                if (chartTopMacs) chartTopMacs.resize();
            }
        });
    }

    // -------------------------------------------------------------
    // UI State Management
    // -------------------------------------------------------------
    function updateUiState(state) {
        captureState = state;
        if (state === "RUNNING") {
            btnStart.disabled = true;
            btnPause.disabled = false;
            btnPause.innerHTML = '<span class="icon">⏸</span> Pause';
            btnStop.disabled = false;
            metricState.innerHTML = '<span class="status-indicator indicator-running"></span> RUNNING';
        } else if (state === "PAUSED") {
            btnStart.disabled = true;
            btnPause.disabled = false;
            btnPause.innerHTML = '<span class="icon">▶</span> Resume';
            btnStop.disabled = false;
            metricState.innerHTML = '<span class="status-indicator indicator-paused"></span> PAUSED';
        } else {
            // STOPPED
            btnStart.disabled = false;
            btnPause.disabled = true;
            btnPause.innerHTML = '<span class="icon">⏸</span> Pause';
            btnStop.disabled = true;
            metricState.innerHTML = '<span class="status-indicator indicator-stopped"></span> STOPPED';
        }
    }

    // -------------------------------------------------------------
    // Status Polling Loop
    // -------------------------------------------------------------
    let isPollingStatus = false;
    let isFetchingPackets = false;

    function startStatusPolling() {
        if (pollInterval) clearInterval(pollInterval);
        pollInterval = setInterval(async () => {
            if (!isPollingStatus) {
                isPollingStatus = true;
                try {
                    await updateStatus();
                } finally {
                    isPollingStatus = false;
                }
            }

            if (captureState === "RUNNING") {
                await fetchNewPackets();
            }
        }, 500);
    }

    async function updateStatus() {
        try {
            const res = await fetch("/api/status");
            if (!res.ok) return;
            const data = await res.json();
            updateStatusMetrics(data);
            if (data.state !== captureState) {
                updateUiState(data.state);
            }

            // Manage Real-time Visual Charts:
            // STRICT RULE: At initial state (0 packets), NO charts are shown.
            // Charts ONLY appear after packets are captured / generated!
            const totalPackets = data.packet_count || 0;
            if (totalPackets > 0) {
                showCharts(totalPackets);
                updateTimeSeriesCharts(data);
                updateProtocolChart();
                refreshMacAnalyticsForChart();
            } else if (chartsVisible) {
                hideCharts();
            }
        } catch (err) {
            // Server might be busy
        }
    }

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return "0 KB";
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    }

    function formatTime(secs) {
        const h = Math.floor(secs / 3600).toString().padStart(2, "0");
        const m = Math.floor((secs % 3600) / 60).toString().padStart(2, "0");
        const s = Math.floor(secs % 60).toString().padStart(2, "0");
        return `${h}:${m}:${s}`;
    }

    function updateStatusMetrics(data) {
        metricPacketCount.textContent = data.packet_count || 0;
        metricBytes.textContent = formatBytes(data.total_bytes);
        metricBytesDetail.textContent = `${(data.total_bytes || 0).toLocaleString()} bytes on wire`;
        metricElapsed.textContent = formatTime(data.elapsed_seconds || 0);
        metricInterfaceName.textContent = data.interface || "-";

        if (data.elapsed_seconds > 0) {
            const pps = ((data.packet_count || 0) / data.elapsed_seconds).toFixed(1);
            metricPps.textContent = `${pps} pkts/sec`;
        } else {
            metricPps.textContent = "0 pkts/sec";
        }
    }

    // -------------------------------------------------------------
    // Fetch and Append New Packets
    // -------------------------------------------------------------
    async function fetchNewPackets() {
        if (isFetchingPackets) return;
        isFetchingPackets = true;

        try {
            const url = `/api/packets?since_id=${lastPacketId}&limit=100`;
            const res = await fetch(url);
            if (!res.ok) return;
            const data = await res.json();

            if (data.packets && data.packets.length > 0) {
                // Remove empty placeholder
                const emptyRow = document.getElementById("emptyRowPlaceholder");
                if (emptyRow) {
                    emptyRow.remove();
                }

                data.packets.forEach((pkt) => {
                    capturedPacketsCache.push(pkt);
                    if (pkt.id > lastPacketId) {
                        lastPacketId = pkt.id;
                    }
                    if (shouldDisplayPacket(pkt)) {
                        appendPacketRow(pkt);
                    }
                });

                // Update charts when new packets arrive
                if (capturedPacketsCache.length > 0) {
                    showCharts(data.total_captured || capturedPacketsCache.length);
                    updateProtocolChart();
                }

                // Cap memory cache to 3,000 packets
                if (capturedPacketsCache.length > 3000) {
                    capturedPacketsCache.splice(0, capturedPacketsCache.length - 3000);
                }

                // Cap DOM rows to 300 to keep the UI silky smooth
                const rows = packetTableBody.children;
                while (rows.length > 300) {
                    packetTableBody.removeChild(rows[0]);
                }

                if (autoScroll) {
                    packetTableContainer.scrollTop = packetTableContainer.scrollHeight;
                }
            }
        } catch (err) {
            console.error("Failed to fetch packets:", err);
        } finally {
            isFetchingPackets = false;
        }
    }

    function shouldDisplayPacket(pkt) {
        if (currentProtocolFilter && !pkt.protocol.toUpperCase().includes(currentProtocolFilter)) {
            return false;
        }
        if (currentSearchQuery) {
            const q = currentSearchQuery;
            const matches =
                pkt.src_mac.toLowerCase().includes(q) ||
                pkt.dst_mac.toLowerCase().includes(q) ||
                pkt.src_ip.toLowerCase().includes(q) ||
                pkt.dst_ip.toLowerCase().includes(q) ||
                pkt.protocol.toLowerCase().includes(q) ||
                pkt.info.toLowerCase().includes(q);
            if (!matches) return false;
        }
        return true;
    }

    function appendPacketRow(pkt) {
        const tr = document.createElement("tr");
        tr.dataset.id = pkt.id;

        // Protocol badge class
        let protoBadgeClass = `badge-proto proto-${pkt.protocol.replace(/[^a-zA-Z0-9]/g, "")}`;

        tr.innerHTML = `
            <td class="col-id">${pkt.id}</td>
            <td class="col-time">${pkt.time}</td>
            <td class="col-mac" title="${pkt.src_mac_vendor || ''}">${pkt.src_mac}</td>
            <td class="col-mac" title="${pkt.dst_mac_vendor || ''}">${pkt.dst_mac}</td>
            <td class="col-ip">${pkt.src_ip}</td>
            <td class="col-ip">${pkt.dst_ip}</td>
            <td class="col-proto"><span class="${protoBadgeClass}">${pkt.protocol}</span></td>
            <td class="col-len">${pkt.length}</td>
            <td class="col-info" title="${escapeHtml(pkt.info)}">${escapeHtml(pkt.info)}</td>
        `;

        tr.onclick = (e) => {
            e.stopPropagation();
            selectPacket(pkt.id, tr);
        };

        packetTableBody.appendChild(tr);
    }

    function refilterPackets() {
        packetTableBody.innerHTML = "";
        const filtered = capturedPacketsCache.filter(shouldDisplayPacket);
        if (filtered.length === 0) {
            packetTableBody.innerHTML = `
                <tr class="empty-row">
                    <td colspan="9" class="text-center">No packets match the current filter or search criteria.</td>
                </tr>
            `;
            return;
        }

        filtered.slice(-300).forEach((pkt) => {
            appendPacketRow(pkt);
        });

        if (selectedPacketId) {
            const selectedRow = packetTableBody.querySelector(`tr[data-id="${selectedPacketId}"]`);
            if (selectedRow) selectedRow.classList.add("selected");
        }
    }

    // -------------------------------------------------------------
    // Packet Inspection Pane (Wireshark 3-pane style)
    // -------------------------------------------------------------
    async function selectPacket(pktId, rowEl) {
        selectedPacketId = pktId;

        // Highlight selected row
        const prev = packetTableBody.querySelectorAll("tr.selected");
        prev.forEach((r) => r.classList.remove("selected"));
        if (rowEl) rowEl.classList.add("selected");

        selectedPacketBadge.textContent = `Packet #${pktId}`;
        inspectionTitle.innerHTML = `<span>🔎 Frame #${pktId} &bull; Loading details...</span>`;
        hexDumpContent.textContent = "Loading hex data...";

        try {
            const res = await fetch(`/api/packet/${pktId}`);
            if (!res.ok) {
                inspectionTitle.innerHTML = `<span>⚠️ Could not load packet #${pktId}</span>`;
                hexDumpContent.textContent = "0000   -- Error loading packet data --";
                return;
            }

            const pkt = await res.json();
            if (pkt.error) {
                inspectionTitle.innerHTML = `<span>⚠️ ${escapeHtml(pkt.error)}</span>`;
                hexDumpContent.textContent = "0000   -- Error loading packet data --";
                return;
            }

            inspectionTitle.innerHTML = `<span>🔎 Frame #${pkt.id} &bull; ${pkt.protocol} &bull; ${pkt.length} bytes</span>`;

            // 1. Render Hex Dump
            hexDumpContent.textContent = pkt.hex_dump || "0000   -- No payload hex data --";

            // 2. Render Layer Tree
            renderLayerTree(pkt.layer_tree);
        } catch (err) {
            console.error("Inspection error:", err);
            inspectionTitle.innerHTML = `<span>⚠️ Network error inspecting packet #${pktId}</span>`;
            hexDumpContent.textContent = "0000   -- Failed to fetch hex dump --";
        }
    }

    function renderLayerTree(tree) {
        layerTreeContainer.innerHTML = "";
        if (!tree || !Array.isArray(tree) || tree.length === 0) {
            layerTreeContainer.innerHTML = '<div class="tree-placeholder">No layer metadata available.</div>';
            return;
        }

        tree.forEach((layer) => {
            if (!layer) return;
            const item = document.createElement("div");
            item.className = "layer-item";

            const header = document.createElement("div");
            header.className = "layer-header";
            header.innerHTML = `<span>▼</span> <span>${escapeHtml(layer.name || "Layer")}</span>`;

            const fieldsDiv = document.createElement("div");
            fieldsDiv.className = "layer-fields";

            if (layer.fields && typeof layer.fields === "object") {
                for (const [key, val] of Object.entries(layer.fields)) {
                    const row = document.createElement("div");
                    row.className = "field-row";
                    row.innerHTML = `
                        <span class="field-name">${escapeHtml(key)}:</span>
                        <span class="field-value">${escapeHtml(String(val ?? ""))}</span>
                    `;
                    fieldsDiv.appendChild(row);
                }
            }

            // Click header to toggle collapse
            header.onclick = () => {
                if (fieldsDiv.style.display === "none") {
                    fieldsDiv.style.display = "block";
                    header.querySelector("span").textContent = "▼";
                } else {
                    fieldsDiv.style.display = "none";
                    header.querySelector("span").textContent = "▶";
                }
            };

            item.appendChild(header);
            item.appendChild(fieldsDiv);
            layerTreeContainer.appendChild(item);
        });
    }

    function resetInspectionPane() {
        selectedPacketBadge.textContent = "No packet selected";
        inspectionTitle.innerHTML = "<span>🔎 Packet Details: Select a packet above to inspect</span>";
        layerTreeContainer.innerHTML = '<div class="tree-placeholder">Click any row in the packet table to inspect its Ethernet II, IP, and Transport layers here.</div>';
        hexDumpContent.textContent = "0000   -- No packet selected --";
    }

    // -------------------------------------------------------------
    // MAC Address Analysis Dashboard
    // -------------------------------------------------------------
    async function loadMacAnalysis() {
        try {
            const res = await fetch("/api/mac-analysis");
            const data = await res.json();

            // Distribution metrics
            document.getElementById("statUnicast").textContent = data.stats.unicast;
            document.getElementById("statBroadcast").textContent = data.stats.broadcast;
            document.getElementById("statMulticast").textContent = data.stats.multicast;
            document.getElementById("statLaa").textContent = data.stats.randomized_laa;
            document.getElementById("statUaa").textContent = data.stats.hardware_uaa;

            metricUniqueMacs.textContent = data.total_macs;

            // Count unique IPs
            const allIps = new Set();
            data.devices.forEach((d) => d.ips.forEach((ip) => allIps.add(ip)));
            metricUniqueIps.textContent = `${allIps.size} active IPs`;

            // Find client phone & hotspot gateway if present
            const phoneDevice = data.devices.find((d) => d.role.includes("Phone") || d.is_randomized);
            if (phoneDevice) {
                document.getElementById("macPhoneMac").textContent = phoneDevice.mac;
                document.getElementById("macPhoneIp").textContent = phoneDevice.ips.join(", ") || "192.168.137.157";
            }

            const gatewayDevice = data.devices.find((d) => d.role.includes("Gateway"));
            if (gatewayDevice) {
                document.getElementById("macGatewayMac").textContent = gatewayDevice.mac;
            }

            // Populate MAC Devices Table
            const devicesTableBody = document.getElementById("macDevicesTableBody");
            devicesTableBody.innerHTML = "";
            if (data.devices.length === 0) {
                devicesTableBody.innerHTML = `<tr><td colspan="10" class="text-center">No MAC addresses observed yet.</td></tr>`;
            } else {
                data.devices.forEach((dev) => {
                    const tr = document.createElement("tr");
                    const adminBadge = dev.is_randomized
                        ? '<span class="badge-laa">LAA (Randomized)</span>'
                        : '<span class="badge-uaa">UAA (Hardware)</span>';

                    tr.innerHTML = `
                        <td><strong>${dev.mac}</strong></td>
                        <td>${escapeHtml(dev.role)}</td>
                        <td>${escapeHtml(dev.vendor)}</td>
                        <td>${dev.cast_type}</td>
                        <td>${adminBadge}</td>
                        <td>${dev.ips.join(", ") || "-"}</td>
                        <td>${dev.packets_sent}</td>
                        <td>${dev.packets_received}</td>
                        <td>${formatBytes(dev.total_bytes)}</td>
                        <td>${dev.protocols.join(", ") || "-"}</td>
                    `;
                    devicesTableBody.appendChild(tr);
                });
            }

            // Populate Conversations Table
            const convsTableBody = document.getElementById("macConversationsTableBody");
            convsTableBody.innerHTML = "";
            if (data.conversations.length === 0) {
                convsTableBody.innerHTML = `<tr><td colspan="7" class="text-center">No conversation flows detected yet.</td></tr>`;
            } else {
                data.conversations.forEach((c) => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td><strong>${c.mac_a}</strong></td>
                        <td>${escapeHtml(c.mac_a_role)}</td>
                        <td><strong>${c.mac_b}</strong></td>
                        <td>${escapeHtml(c.mac_b_role)}</td>
                        <td>${c.packets}</td>
                        <td>${formatBytes(c.bytes)}</td>
                        <td>${c.protocols.join(", ") || "-"}</td>
                    `;
                    convsTableBody.appendChild(tr);
                });
            }

            // Also update top MACs chart if visible
            updateTopMacsChart(data);
        } catch (err) {
            console.error("Failed to load MAC analysis:", err);
        }
    }

    // -------------------------------------------------------------
    // Real-Time Visual Charts Management (Chart.js)
    // -------------------------------------------------------------
    function showCharts(totalPackets) {
        if (!chartsVisible) {
            if (liveChartsSection) {
                liveChartsSection.classList.remove("hidden");
                liveChartsSection.style.display = "block";
            }
            chartsVisible = true;
            if (!chartProtocol) {
                initCharts();
            }
        }
        if (chartsPacketBadge) {
            chartsPacketBadge.textContent = `${totalPackets} Packets Analyzed`;
        }
    }

    function hideCharts() {
        chartsVisible = false;
        if (liveChartsSection) {
            liveChartsSection.classList.add("hidden");
            liveChartsSection.style.display = "none";
        }
        timeLabels.length = 0;
        packetRateHistory.length = 0;
        dataRateHistory.length = 0;
        previousPktCount = 0;
        previousBytes = 0;

        if (chartProtocol) {
            try { chartProtocol.destroy(); } catch (e) {}
            chartProtocol = null;
        }
        if (chartPacketsTime) {
            try { chartPacketsTime.destroy(); } catch (e) {}
            chartPacketsTime = null;
        }
        if (chartDataTime) {
            try { chartDataTime.destroy(); } catch (e) {}
            chartDataTime = null;
        }
        if (chartTopMacs) {
            try { chartTopMacs.destroy(); } catch (e) {}
            chartTopMacs = null;
        }
    }

    function initCharts() {
        if (typeof Chart === "undefined") {
            console.warn("Chart.js library is not loaded yet.");
            return;
        }

        // Global Chart Defaults for Dark Theme
        Chart.defaults.color = "#94a3b8";
        Chart.defaults.font.family = "'Inter', -apple-system, BlinkMacSystemFont, sans-serif";

        // 1. Protocol Distribution — Donut Chart
        const ctxProto = document.getElementById("chartProtocol");
        if (ctxProto && !chartProtocol) {
            chartProtocol = new Chart(ctxProto, {
                type: "doughnut",
                data: {
                    labels: ["TCP", "UDP", "DNS", "HTTPS", "HTTP", "ARP", "ICMP", "Other"],
                    datasets: [{
                        data: [0, 0, 0, 0, 0, 0, 0, 0],
                        backgroundColor: [
                            "#3b82f6", // TCP (blue)
                            "#f97316", // UDP (orange)
                            "#38bdf8", // DNS (sky)
                            "#10b981", // HTTPS (emerald)
                            "#2dd4bf", // HTTP (teal)
                            "#eab308", // ARP (yellow)
                            "#f43f5e", // ICMP (rose)
                            "#64748b"  // Other (slate)
                        ],
                        borderColor: "#111827",
                        borderWidth: 2,
                        hoverOffset: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: "62%",
                    plugins: {
                        legend: {
                            position: "right",
                            labels: {
                                color: "#94a3b8",
                                font: { size: 11 },
                                boxWidth: 12,
                                padding: 6
                            }
                        },
                        tooltip: {
                            callbacks: {
                                label: (context) => {
                                    const val = context.raw || 0;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const pct = total > 0 ? ((val / total) * 100).toFixed(1) : 0;
                                    return ` ${context.label}: ${val} pkts (${pct}%)`;
                                }
                            }
                        }
                    }
                }
            });
        }

        // 2. Packet Capture Over Time — Line Graph
        const ctxPackets = document.getElementById("chartPacketsTime");
        if (ctxPackets && !chartPacketsTime) {
            chartPacketsTime = new Chart(ctxPackets, {
                type: "line",
                data: {
                    labels: timeLabels,
                    datasets: [{
                        label: "Packets Ingested",
                        data: packetRateHistory,
                        borderColor: "#38bdf8",
                        backgroundColor: "rgba(56, 189, 248, 0.15)",
                        fill: true,
                        tension: 0.35,
                        borderWidth: 2,
                        pointRadius: 3,
                        pointBackgroundColor: "#38bdf8",
                        pointHoverRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: {
                            grid: { color: "rgba(255, 255, 255, 0.05)" },
                            ticks: { color: "#94a3b8", font: { size: 10 }, maxTicksLimit: 7 }
                        },
                        y: {
                            beginAtZero: true,
                            grid: { color: "rgba(255, 255, 255, 0.05)" },
                            ticks: { color: "#94a3b8", font: { size: 10 }, precision: 0 }
                        }
                    },
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            callbacks: {
                                label: (ctx) => ` Rate: ${ctx.raw} pkts/sample`
                            }
                        }
                    }
                }
            });
        }

        // 3. Data Transfer Over Time — Line Graph
        const ctxData = document.getElementById("chartDataTime");
        if (ctxData && !chartDataTime) {
            chartDataTime = new Chart(ctxData, {
                type: "line",
                data: {
                    labels: timeLabels,
                    datasets: [{
                        label: "Data Transferred (KB)",
                        data: dataRateHistory,
                        borderColor: "#10b981",
                        backgroundColor: "rgba(16, 185, 129, 0.15)",
                        fill: true,
                        tension: 0.35,
                        borderWidth: 2,
                        pointRadius: 3,
                        pointBackgroundColor: "#10b981",
                        pointHoverRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: {
                            grid: { color: "rgba(255, 255, 255, 0.05)" },
                            ticks: { color: "#94a3b8", font: { size: 10 }, maxTicksLimit: 7 }
                        },
                        y: {
                            beginAtZero: true,
                            grid: { color: "rgba(255, 255, 255, 0.05)" },
                            ticks: {
                                color: "#94a3b8",
                                font: { size: 10 },
                                callback: (v) => `${v} KB`
                            }
                        }
                    },
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            callbacks: {
                                label: (ctx) => ` Throughput: ${ctx.raw} KB`
                            }
                        }
                    }
                }
            });
        }

        // 4. Top MAC Addresses by Traffic — Horizontal Bar Chart
        const ctxMacs = document.getElementById("chartTopMacs");
        if (ctxMacs && !chartTopMacs) {
            chartTopMacs = new Chart(ctxMacs, {
                type: "bar",
                data: {
                    labels: [],
                    datasets: [{
                        label: "Packets Exchanged",
                        data: [],
                        backgroundColor: [
                            "#6366f1",
                            "#8b5cf6",
                            "#ec4899",
                            "#f59e0b",
                            "#06b6d4",
                            "#3b82f6"
                        ],
                        borderRadius: 6,
                        borderWidth: 0,
                        barThickness: 16
                    }]
                },
                options: {
                    indexAxis: "y",
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: {
                            beginAtZero: true,
                            grid: { color: "rgba(255, 255, 255, 0.05)" },
                            ticks: { color: "#94a3b8", font: { size: 10 }, precision: 0 }
                        },
                        y: {
                            grid: { display: false },
                            ticks: {
                                color: "#cbd5e1",
                                font: { size: 10, family: "'Fira Code', monospace" }
                            }
                        }
                    },
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            callbacks: {
                                label: (ctx) => ` Traffic: ${ctx.raw} packets`
                            }
                        }
                    }
                }
            });
        }
    }

    // Update Protocol Donut Chart Data
    function updateProtocolChart() {
        if (!chartProtocol || capturedPacketsCache.length === 0) return;

        const protoCounts = {
            TCP: 0,
            UDP: 0,
            DNS: 0,
            HTTPS: 0,
            HTTP: 0,
            ARP: 0,
            ICMP: 0,
            Other: 0
        };

        capturedPacketsCache.forEach((pkt) => {
            const p = (pkt.protocol || "").toUpperCase();
            if (p === "TCP" || p.includes("TLS")) protoCounts.TCP++;
            else if (p.includes("HTTPS")) protoCounts.HTTPS++;
            else if (p.includes("HTTP")) protoCounts.HTTP++;
            else if (p === "UDP" || p.includes("QUIC") || p.includes("NTP") || p.includes("MDNS") || p.includes("SSDP")) protoCounts.UDP++;
            else if (p.includes("DNS")) protoCounts.DNS++;
            else if (p.includes("ARP")) protoCounts.ARP++;
            else if (p.includes("ICMP")) protoCounts.ICMP++;
            else protoCounts.Other++;
        });

        chartProtocol.data.datasets[0].data = [
            protoCounts.TCP,
            protoCounts.UDP,
            protoCounts.DNS,
            protoCounts.HTTPS,
            protoCounts.HTTP,
            protoCounts.ARP,
            protoCounts.ICMP,
            protoCounts.Other
        ];
        chartProtocol.update("none");
    }

    // Update Time Series Line Graphs
    function updateTimeSeriesCharts(statusData) {
        if (!chartPacketsTime || !chartDataTime) return;

        const currentPkts = statusData.packet_count || capturedPacketsCache.length;
        const currentBytes = statusData.total_bytes || 0;

        let deltaPkts = currentPkts - previousPktCount;
        if (deltaPkts < 0 || previousPktCount === 0) deltaPkts = currentPkts;

        let deltaBytes = currentBytes - previousBytes;
        if (deltaBytes < 0 || previousBytes === 0) deltaBytes = currentBytes;

        const deltaKb = parseFloat((deltaBytes / 1024).toFixed(2));

        previousPktCount = currentPkts;
        previousBytes = currentBytes;

        const now = new Date();
        const timeLabel = `${now.getHours().toString().padStart(2, "0")}:${now.getMinutes().toString().padStart(2, "0")}:${now.getSeconds().toString().padStart(2, "0")}`;

        timeLabels.push(timeLabel);
        packetRateHistory.push(deltaPkts);
        dataRateHistory.push(deltaKb);

        if (timeLabels.length > MAX_TIME_SLICES) {
            timeLabels.shift();
            packetRateHistory.shift();
            dataRateHistory.shift();
        }

        chartPacketsTime.update("none");
        chartDataTime.update("none");
    }

    // Periodically fetch MAC analysis for Top MACs Horizontal Bar Chart
    async function refreshMacAnalyticsForChart() {
        const now = Date.now();
        if (now - lastMacFetchTime > 2000) {
            lastMacFetchTime = now;
            try {
                const res = await fetch("/api/mac-analysis");
                if (res.ok) {
                    const macData = await res.json();
                    updateTopMacsChart(macData);
                }
            } catch (e) {
                // Ignore transient network errors
            }
        }
    }

    // Update Top MAC Addresses Horizontal Bar Chart
    function updateTopMacsChart(macData) {
        if (!chartTopMacs || !macData || !macData.devices || macData.devices.length === 0) return;

        const topDevices = macData.devices.slice(0, 5);
        chartTopMacs.data.labels = topDevices.map((d) => {
            let label = d.mac;
            if (d.role.includes("Phone")) label += " (Phone)";
            else if (d.role.includes("Gateway")) label += " (Gateway)";
            else if (d.cast_type === "Broadcast") label += " (Broadcast)";
            else if (d.cast_type === "Multicast") label += " (Multicast)";
            return label;
        });

        chartTopMacs.data.datasets[0].data = topDevices.map(
            (d) => d.total_packets || (d.packets_sent + d.packets_received)
        );
        chartTopMacs.update("none");
    }

    // Utility escape
    function escapeHtml(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
