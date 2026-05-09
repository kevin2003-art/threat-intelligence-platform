const API = "";

async function fetchStats() {
    try {
        const res = await fetch(`${API}/api/stats`);
        const data = await res.json();
        document.getElementById("total").textContent = data.total.toLocaleString();
        document.getElementById("critical").textContent = data.critical.toLocaleString();
        document.getElementById("high").textContent = data.high.toLocaleString();
        document.getElementById("blocked").textContent = data.blocked.toLocaleString();
        document.getElementById("rollbacks").textContent = data.rollbacks.toLocaleString();
        drawDonut(data);
        drawBars(data.sources);
    } catch(e) { console.error("Stats error:", e); }
}

function drawDonut(data) {
    const canvas = document.getElementById("severityChart");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const total = data.critical + data.high + data.medium + data.low || 1;
    const segments = [
        { value: data.critical, color: "#ef4444" },
        { value: data.high,     color: "#f97316" },
        { value: data.medium,   color: "#eab308" },
        { value: data.low,      color: "#22c55e" }
    ];
    let angle = -Math.PI / 2;
    const cx = canvas.width / 2, cy = canvas.height / 2;
    const r = Math.min(cx, cy) - 8;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    segments.forEach(s => {
        if (!s.value) return;
        const sweep = (s.value / total) * 2 * Math.PI;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, r, angle, angle + sweep);
        ctx.closePath();
        ctx.fillStyle = s.color;
        ctx.fill();
        angle += sweep;
    });
    ctx.beginPath();
    ctx.arc(cx, cy, r * 0.58, 0, 2 * Math.PI);
    ctx.fillStyle = "#0f172a";
    ctx.fill();
    ctx.fillStyle = "#f1f5f9";
    ctx.font = "bold 18px monospace";
    ctx.textAlign = "center";
    ctx.fillText(total.toLocaleString(), cx, cy - 4);
    ctx.font = "11px monospace";
    ctx.fillStyle = "#64748b";
    ctx.fillText("TOTAL", cx, cy + 14);
}

function drawBars(sources) {
    const canvas = document.getElementById("sourceChart");
    if (!canvas || !sources || !sources.length) return;
    const ctx = canvas.getContext("2d");
    const max = Math.max(...sources.map(s => s.count)) || 1;
    const barW = Math.floor((canvas.width - 40) / sources.length) - 16;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    const colors = ["#3b82f6", "#8b5cf6", "#06b6d4"];
    sources.forEach((s, i) => {
        const barH = Math.floor((s.count / max) * (canvas.height - 50));
        const x = 20 + i * (barW + 16);
        const y = canvas.height - barH - 30;
        const grad = ctx.createLinearGradient(x, y, x, y + barH);
        grad.addColorStop(0, colors[i % colors.length]);
        grad.addColorStop(1, colors[i % colors.length] + "66");
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.roundRect(x, y, barW, barH, 4);
        ctx.fill();
        ctx.fillStyle = "#e2e8f0";
        ctx.font = "bold 11px monospace";
        ctx.textAlign = "center";
        ctx.fillText(s.count.toLocaleString(), x + barW / 2, y - 6);
        ctx.fillStyle = "#64748b";
        ctx.font = "10px monospace";
        const name = s.name.length > 10 ? s.name.substring(0, 9) + "…" : s.name;
        ctx.fillText(name, x + barW / 2, canvas.height - 8);
    });
}

async function fetchIndicators(severity = "") {
    try {
        const url = severity ? `/api/indicators?severity=${severity}&limit=100` : `/api/indicators?limit=100`;
        const res = await fetch(url);
        const data = await res.json();
        const tbody = document.getElementById("indicatorsTable");
        tbody.innerHTML = "";
        data.forEach(ind => {
            const row = document.createElement("tr");
            const sc = ind.severity === "CRITICAL" ? "sev-critical" :
                       ind.severity === "HIGH" ? "sev-high" :
                       ind.severity === "MEDIUM" ? "sev-medium" : "sev-low";
            const score = ind.risk_score || 0;
            const barW = score;
            row.innerHTML = `
                <td class="mono">${ind.value}</td>
                <td><span class="tag">${ind.type || "ip"}</span></td>
                <td>${ind.source}</td>
                <td><span class="badge ${sc}">${ind.severity}</span></td>
                <td>
                    <div class="score-wrap">
                        <div class="score-bar" style="width:${barW}%"></div>
                        <span>${score}</span>
                    </div>
                </td>
                <td>${ind.country || "—"}</td>`;
            tbody.appendChild(row);
        });
    } catch(e) { console.error("Indicators error:", e); }
}

async function fetchBlocked() {
    try {
        const res = await fetch(`/api/blocked`);
        const data = await res.json();
        const tbody = document.getElementById("blockedTable");
        tbody.innerHTML = "";
        document.getElementById("blockedCount").textContent = data.length;
        if (!data.length) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:#64748b">No IPs currently blocked</td></tr>`;
            return;
        }
        data.forEach(ind => {
            const row = document.createElement("tr");
            row.innerHTML = `
                <td class="mono red-text">${ind.value}</td>
                <td><span class="score-pill">${ind.risk_score}</span></td>
                <td>${ind.country || "—"}</td>
                <td>${ind.source}</td>
                <td><button class="btn-rollback" onclick="rollbackIP('${ind.value}')">⟲ Rollback</button></td>`;
            tbody.appendChild(row);
        });
    } catch(e) { console.error("Blocked error:", e); }
}

async function fetchLogs() {
    try {
        const res = await fetch(`/api/logs?limit=50`);
        const data = await res.json();
        const tbody = document.getElementById("logsTable");
        tbody.innerHTML = "";
        data.forEach(log => {
            const row = document.createElement("tr");
            const ac = log.action === "block" ? "action-block" : "action-rollback";
            const icon = log.action === "block" ? "🔴" : "🟢";
            row.innerHTML = `
                <td class="mono">${log.ip}</td>
                <td><span class="badge ${ac}">${icon} ${log.action.toUpperCase()}</span></td>
                <td>${log.severity || "—"}</td>
                <td>${log.source || "—"}</td>
                <td>${log.risk_score || 0}</td>
                <td class="ts">${log.timestamp ? log.timestamp.substring(0,19).replace("T"," ") : "—"}</td>`;
            tbody.appendChild(row);
        });
    } catch(e) { console.error("Logs error:", e); }
}

async function fetchAlerts() {
    try {
        const res = await fetch(`/api/alerts`);
        const data = await res.json();
        const container = document.getElementById("alertsContainer");
        container.innerHTML = "";
        if (!data.length) {
            container.innerHTML = `<div class="no-alerts">No recent alerts</div>`;
            return;
        }
        data.forEach(alert => {
            const div = document.createElement("div");
            div.className = "alert-item";
            div.innerHTML = `
                <div class="alert-top">
                    <span class="alert-icon">⚠</span>
                    <span class="alert-title">SECURITY ALERT — THREAT BLOCKED</span>
                    <span class="alert-time">${alert.timestamp ? alert.timestamp.substring(0,19).replace("T"," ") : ""}</span>
                </div>
                <div class="alert-body">
                    <span class="alert-ip">${alert.ip}</span>
                    <span class="alert-badge">Score: ${alert.risk_score}/100</span>
                    <span class="alert-badge">${alert.severity}</span>
                    <span class="alert-src">${alert.source}</span>
                </div>`;
            container.appendChild(div);
        });
    } catch(e) { console.error("Alerts error:", e); }
}

async function fetchFeedStatus() {
    try {
        const res = await fetch(`/api/feed_status`);
        const data = await res.json();
        const container = document.getElementById("feedStatus");
        container.innerHTML = "";
        data.forEach(feed => {
            const div = document.createElement("div");
            div.className = "feed-row";
            div.innerHTML = `
                <span class="feed-dot online"></span>
                <span class="feed-name">${feed.name}</span>
                <span class="feed-count">${feed.count.toLocaleString()}</span>
                <span class="feed-ok">${feed.status}</span>`;
            container.appendChild(div);
        });
    } catch(e) { console.error("Feed status error:", e); }
}

async function fetchCountries() {
    try {
        const res = await fetch(`/api/countries`);
        const data = await res.json();
        const tbody = document.getElementById("countriesTable");
        tbody.innerHTML = "";
        const max = data[0]?.count || 1;
        data.forEach((c, i) => {
            const row = document.createElement("tr");
            const pct = Math.round((c.count / max) * 100);
            row.innerHTML = `
                <td>${i+1}</td>
                <td>${c.country}</td>
                <td>
                    <div class="country-bar-wrap">
                        <div class="country-bar" style="width:${pct}%"></div>
                        <span>${c.count}</span>
                    </div>
                </td>`;
            tbody.appendChild(row);
        });
    } catch(e) { console.error("Countries error:", e); }
}

async function fetchCompliance() {
    try {
        const res = await fetch(`/api/stats`);
        const data = await res.json();
        document.getElementById("comp-total").textContent = data.blocked;
        document.getElementById("comp-rollbacks").textContent = data.rollbacks;
        document.getElementById("comp-critical").textContent = data.critical;
        document.getElementById("comp-time").textContent = new Date().toISOString().substring(0,19).replace("T"," ") + " UTC";
    } catch(e) {}
}

async function rollbackIP(ip) {
    const reason = prompt(`Reason for rolling back ${ip}:`, "False positive confirmed by SOC analyst");
    if (!reason) return;
    const btn = document.querySelector(`button[onclick="rollbackIP('${ip}')"]`);
    if (btn) { btn.textContent = "Processing..."; btn.disabled = true; }
    try {
        const res = await fetch(`/api/rollback`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ip, reason})
        });
        const data = await res.json();
        if (data.success) {
            showToast(`✓ ${ip} successfully unblocked`, "success");
        } else {
            showToast(`✗ Failed: ${data.message}`, "error");
        }
        refreshAll();
    } catch(e) {
        showToast(`✗ Error: ${e.message}`, "error");
    }
}

function showToast(msg, type) {
    const toast = document.getElementById("toast");
    toast.textContent = msg;
    toast.className = `toast toast-${type} show`;
    setTimeout(() => toast.className = "toast", 3000);
}

function filterBySeverity(sev) {
    document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
    event.target.classList.add("active");
    fetchIndicators(sev);
}

function switchTab(tab) {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    document.querySelector(`[data-tab="${tab}"]`).classList.add("active");
    document.getElementById(`tab-${tab}`).classList.add("active");
}

function updateClock() {
    const now = new Date();
    const el = document.getElementById("clock");
    if (el) el.textContent = now.toISOString().substring(0,19).replace("T"," ") + " UTC";
}

async function refreshAll() {
    document.getElementById("refreshIcon").style.animation = "spin 1s linear infinite";
    await Promise.all([
        fetchStats(),
        fetchIndicators(),
        fetchLogs(),
        fetchBlocked(),
        fetchAlerts(),
        fetchFeedStatus(),
        fetchCountries(),
        fetchCompliance()
    ]);
    document.getElementById("refreshIcon").style.animation = "";
    document.getElementById("lastUpdate").textContent = new Date().toISOString().substring(11,19) + " UTC";
}

setInterval(refreshAll, 30000);
setInterval(updateClock, 1000);
window.onload = () => { updateClock(); refreshAll(); };
