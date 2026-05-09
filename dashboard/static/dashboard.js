// ── STATE ───────────────────────────────────────────────
let currentSeverity = "";

// ── UTILITIES ───────────────────────────────────────────
function ts(str) {
    if (!str) return "—";
    try { return new Date(str).toLocaleString(); }
    catch { return str.substring(0,19).replace("T"," "); }
}

function severityClass(s) {
    return s === "CRITICAL" ? "b-crit" :
           s === "HIGH"     ? "b-high" :
           s === "MEDIUM"   ? "b-med"  : "b-low";
}

function showToast(msg, type="inf") {
    const t = document.getElementById("toast");
    t.textContent = msg;
    t.className = `toast t-${type} show`;
    setTimeout(() => t.className = "toast", 3500);
}

// ── STATS ────────────────────────────────────────────────
async function fetchStats() {
    const d = await fetch("/api/stats").then(r=>r.json());
    document.getElementById("total").textContent    = d.total.toLocaleString();
    document.getElementById("critical").textContent = d.critical.toLocaleString();
    document.getElementById("high").textContent     = d.high.toLocaleString();
    document.getElementById("blocked").textContent  = d.blocked.toLocaleString();
    document.getElementById("rollbacks").textContent= d.rollbacks.toLocaleString();
    document.getElementById("comp-total").textContent    = d.blocked;
    document.getElementById("comp-rollbacks").textContent= d.rollbacks;
    document.getElementById("comp-critical").textContent = d.critical;
    drawDonut(d);
    drawBars(d.sources);
}

// ── DONUT CHART ──────────────────────────────────────────
function drawDonut(d) {
    const cv = document.getElementById("severityChart");
    if (!cv) return;
    const ctx = cv.getContext("2d");
    const total = d.critical + d.high + d.medium + d.low || 1;
    const segs = [
        {v: d.critical, c: "#ff003c"},
        {v: d.high,     c: "#ff8c00"},
        {v: d.medium,   c: "#ffd700"},
        {v: d.low,      c: "#39ff14"}
    ];
    let a = -Math.PI/2;
    const cx=cv.width/2, cy=cv.height/2, r=Math.min(cx,cy)-6;
    ctx.clearRect(0,0,cv.width,cv.height);
    segs.forEach(s => {
        if (!s.v) return;
        const sw = (s.v/total)*2*Math.PI;
        ctx.beginPath();
        ctx.moveTo(cx,cy);
        ctx.arc(cx,cy,r,a,a+sw);
        ctx.closePath();
        ctx.fillStyle = s.c;
        ctx.shadowBlur = 12;
        ctx.shadowColor = s.c;
        ctx.fill();
        ctx.shadowBlur = 0;
        a += sw;
    });
    ctx.beginPath();
    ctx.arc(cx,cy,r*0.6,0,2*Math.PI);
    ctx.fillStyle = "#0a0f18";
    ctx.fill();
    ctx.fillStyle = "#fff";
    ctx.font = "bold 16px JetBrains Mono, monospace";
    ctx.textAlign = "center";
    ctx.fillText(total.toLocaleString(), cx, cy-2);
    ctx.font = "9px JetBrains Mono, monospace";
    ctx.fillStyle = "#4a6080";
    ctx.fillText("TOTAL", cx, cy+13);
}

// ── BAR CHART ────────────────────────────────────────────
function drawBars(sources) {
    const cv = document.getElementById("sourceChart");
    if (!cv || !sources?.length) return;
    const ctx = cv.getContext("2d");
    const max = Math.max(...sources.map(s=>s.count))||1;
    const bw = Math.floor((cv.width-40)/sources.length)-12;
    const colors = ["#00f2ff","#b537f2","#39ff14"];
    ctx.clearRect(0,0,cv.width,cv.height);
    sources.forEach((s,i) => {
        const bh = Math.floor((s.count/max)*(cv.height-50));
        const x = 20+i*(bw+12), y = cv.height-bh-30;
        const g = ctx.createLinearGradient(x,y,x,y+bh);
        g.addColorStop(0, colors[i%colors.length]);
        g.addColorStop(1, colors[i%colors.length]+"33");
        ctx.fillStyle = g;
        ctx.shadowBlur = 10;
        ctx.shadowColor = colors[i%colors.length];
        ctx.beginPath();
        if (ctx.roundRect) ctx.roundRect(x,y,bw,bh,3);
        else ctx.rect(x,y,bw,bh);
        ctx.fill();
        ctx.shadowBlur = 0;
        ctx.fillStyle = "#c8d8e8";
        ctx.font = "bold 11px monospace";
        ctx.textAlign = "center";
        ctx.fillText(s.count.toLocaleString(), x+bw/2, y-6);
        ctx.fillStyle = "#4a6080";
        ctx.font = "9px monospace";
        const nm = s.name.length>10 ? s.name.substring(0,9)+"…" : s.name;
        ctx.fillText(nm, x+bw/2, cv.height-8);
    });
}

// ── THREAT MAP ───────────────────────────────────────────
async function buildThreatMap() {
    const data = await fetch("/api/countries").then(r=>r.json());
    const grid = document.getElementById("mapGrid");
    if (!grid) return;
    grid.innerHTML = "";
    const max = data[0]?.count||1;
    const cells = 200;
    for (let i=0; i<cells; i++) {
        const cell = document.createElement("div");
        cell.className = "map-cell";
        const rand = Math.random();
        const topCountries = data.slice(0,3);
        const density = topCountries.length ? (topCountries[0].count/max) : 0;
        if (rand < density*0.08) cell.classList.add("hot1");
        else if (rand < density*0.18) cell.classList.add("hot2");
        else if (rand < density*0.3) cell.classList.add("hot3");
        else if (rand < 0.15) cell.classList.add("warm");
        grid.appendChild(cell);
    }
}

// ── FEED STATUS ──────────────────────────────────────────
async function fetchFeedStatus() {
    const data = await fetch("/api/feed_status").then(r=>r.json());
    const c = document.getElementById("feedStatus");
    c.innerHTML = "";
    data.forEach(f => {
        c.innerHTML += `
        <div class="feed-row">
          <span class="feed-pulse"></span>
          <span class="feed-name">${f.name}</span>
          <span class="feed-num">${f.count.toLocaleString()}</span>
          <span class="feed-tag">${f.status}</span>
        </div>`;
    });
}

// ── COUNTRIES ────────────────────────────────────────────
async function fetchCountries() {
    const data = await fetch("/api/countries").then(r=>r.json());
    const tbody = document.getElementById("countriesTable");
    tbody.innerHTML = "";
    const max = data[0]?.count||1;
    data.forEach((c,i) => {
        const pct = Math.round((c.count/max)*100);
        tbody.innerHTML += `
        <tr>
          <td class="country-rank">${i+1}</td>
          <td class="country-name">${c.country}</td>
          <td>
            <div class="country-bar-wrap">
              <div class="country-bar" style="width:${pct}%"></div>
              <span class="country-num">${c.count}</span>
            </div>
          </td>
        </tr>`;
    });
}

// ── ALERTS ───────────────────────────────────────────────
async function fetchAlerts() {
    const data = await fetch("/api/alerts").then(r=>r.json());
    const c = document.getElementById("alertsContainer");
    c.innerHTML = "";
    if (!data.length) { c.innerHTML = `<div class="no-data">[ NO RECENT ALERTS ]</div>`; return; }
    data.forEach(a => {
        c.innerHTML += `
        <div class="alert-item">
          <div class="alert-top">
            <span class="alert-icon">⚡</span>
            <span class="alert-title">THREAT BLOCKED — AUTO ENFORCEMENT</span>
            <span class="alert-time">${ts(a.timestamp)}</span>
          </div>
          <div class="alert-body">
            <span class="alert-ip">${a.ip}</span>
            <span class="alert-chip">${a.severity}</span>
            <span class="alert-chip">Score: ${a.risk_score}/100</span>
            <span class="alert-src">${a.source}</span>
          </div>
        </div>`;
    });
}

// ── INDICATORS TABLE ─────────────────────────────────────
async function fetchIndicators(sev="") {
    currentSeverity = sev;
    const url = sev ? `/api/indicators?severity=${sev}&limit=100` : `/api/indicators?limit=100`;
    const data = await fetch(url).then(r=>r.json());
    const tbody = document.getElementById("indicatorsTable");
    tbody.innerHTML = "";
    data.forEach(d => {
        const sc = severityClass(d.severity);
        tbody.innerHTML += `
        <tr>
          <td class="mono">${d.value}</td>
          <td><span class="badge b-tag">${d.type||"ip"}</span></td>
          <td>${d.source}</td>
          <td><span class="badge ${sc}">${d.severity}</span></td>
          <td>
            <div class="score-wrap">
              <div class="score-track"><div class="score-fill" style="width:${d.risk_score||0}%"></div></div>
              <span class="score-num">${d.risk_score||0}</span>
            </div>
          </td>
          <td>${d.country||"—"}</td>
        </tr>`;
    });
}

function filterSev(sev, btn) {
    document.querySelectorAll(".flt-btn").forEach(b=>b.classList.remove("active"));
    btn.classList.add("active");
    fetchIndicators(sev);
}

// ── BLOCKED IPs ──────────────────────────────────────────
async function fetchBlocked() {
    const data = await fetch("/api/blocked").then(r=>r.json());
    const tbody = document.getElementById("blockedTable");
    const cnt = document.getElementById("blockedCount");
    if (cnt) cnt.textContent = data.length;
    tbody.innerHTML = "";
    if (!data.length) {
        tbody.innerHTML = `<tr><td colspan="5" class="no-data">[ NO ACTIVE BLOCKS ]</td></tr>`;
        return;
    }
    data.forEach(d => {
        tbody.innerHTML += `
        <tr>
          <td class="mono red-text">${d.value}</td>
          <td><span style="color:#ff003c;font-weight:700">${d.risk_score}</span></td>
          <td>${d.country||"—"}</td>
          <td>${d.source}</td>
          <td>
            <button class="btn-rollback" onclick="showRollbackMenu('${d.value}')">⟲ Rollback</button>
          </td>
        </tr>`;
    });
}

// ── ROLLBACK MENU ────────────────────────────────────────
function showRollbackMenu(ip) {
    const mode = confirm(
        `ROLLBACK OPTIONS for ${ip}\n\n` +
        `Click OK for PERMANENT rollback\n` +
        `Click Cancel for TEMPORARY (24h) rollback`
    );
    const modeStr = mode ? "permanent" : "temp24h";
    const reason  = prompt("Enter reason:", "False positive confirmed by SOC analyst");
    if (!reason) return;
    doRollback(ip, reason, modeStr);
}

async function doRollback(ip, reason, mode) {
    showToast(`Processing rollback for ${ip}...`, "inf");
    const res  = await fetch("/api/rollback", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({ip, reason, mode})
    });
    const data = await res.json();
    showToast(data.success ? `✓ ${data.message}` : `✗ ${data.message}`,
              data.success ? "ok" : "err");
    if (data.success) refreshAll();
}

// ── ABUSE REPORT ─────────────────────────────────────────
async function abuseReport(ip) {
    const res  = await fetch("/api/abuse-report", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({ip})
    });
    const data = await res.json();
    showToast(data.message, "inf");
    window.open(data.abuseipdb_url, "_blank");
}

// ── AUDIT LOGS ───────────────────────────────────────────
async function fetchLogs() {
    const data = await fetch("/api/logs?limit=50").then(r=>r.json());
    const tbody = document.getElementById("logsTable");
    tbody.innerHTML = "";
    data.forEach(d => {
        const ac = d.action==="block" ? "b-block" : "b-rollbk";
        const icon = d.action==="block" ? "🔴" : "🟢";
        tbody.innerHTML += `
        <tr>
          <td class="mono">${d.ip}</td>
          <td><span class="badge ${ac}">${icon} ${d.action.toUpperCase()}</span></td>
          <td>${d.severity||"—"}</td>
          <td>${d.source||"—"}</td>
          <td>${d.risk_score||0}</td>
          <td class="ts">${ts(d.timestamp)}</td>
        </tr>`;
    });
}

// ── HEALTH MONITOR ───────────────────────────────────────
async function fetchHealth() {
    const data = await fetch("/api/health").then(r=>r.json());
    const c = document.getElementById("healthPanel");
    if (!c) return;

    const mg = data.mongodb;
    const es = data.elasticsearch;
    const ip = data.iptables;

    c.innerHTML = `
    <div class="health-row">
      <span class="health-icon">🗄</span>
      <span class="health-name">MongoDB</span>
      <span class="health-status ${mg.ok?"h-ok":"h-err"}">${mg.status}</span>
    </div>
    <div class="health-row">
      <span class="health-icon">🔍</span>
      <span class="health-name">Elasticsearch</span>
      <span class="health-status ${es.ok?"h-ok":"h-warn"}">${es.status}</span>
    </div>
    <div class="health-row">
      <span class="health-icon">🛡</span>
      <span class="health-name">iptables</span>
      <span class="health-status ${ip.ok?"h-ok":"h-warn"}">${ip.status}</span>
      <span class="health-detail">${ip.rules} rules</span>
    </div>`;
}

// ── WHOIS LOOKUP ─────────────────────────────────────────
async function lookupWhois() {
    const ip = document.getElementById("whoisInput").value.trim();
    if (!ip) { showToast("Enter an IP address", "err"); return; }
    const box = document.getElementById("whoisResult");
    box.innerHTML = `<span style="color:#4a6080">Looking up ${ip}...</span>`;
    try {
        const data = await fetch(`/api/whois/${ip}`).then(r=>r.json());
        if (data.error) { box.innerHTML = `<span class="whois-warn">Error: ${data.error}</span>`; return; }
        const vpn  = data.proxy  ? `<span class="whois-warn">⚠ VPN/PROXY DETECTED</span>` : `<span style="color:#39ff14">✓ No proxy</span>`;
        const host = data.hosting? `<span class="whois-warn">⚠ HOSTING/DC</span>` : `<span style="color:#39ff14">✓ Residential</span>`;
        box.innerHTML = `
        <div><span class="whois-key">IP:      </span><span class="whois-val">${data.ip}</span></div>
        <div><span class="whois-key">Country: </span><span class="whois-val">${data.country}</span></div>
        <div><span class="whois-key">Region:  </span><span class="whois-val">${data.region}, ${data.city}</span></div>
        <div><span class="whois-key">ISP:     </span><span class="whois-val">${data.isp}</span></div>
        <div><span class="whois-key">Org:     </span><span class="whois-val">${data.org}</span></div>
        <div><span class="whois-key">AS:      </span><span class="whois-val">${data.as}</span></div>
        <div><span class="whois-key">Proxy:   </span>${vpn}</div>
        <div><span class="whois-key">Hosting: </span>${host}</div>`;
    } catch(e) {
        box.innerHTML = `<span class="whois-warn">Lookup failed: ${e.message}</span>`;
    }
}

// ── MANUAL BLOCK ─────────────────────────────────────────
async function manualBlock() {
    const ip  = document.getElementById("manualIP").value.trim();
    const sev = document.getElementById("manualSev").value;
    const rsn = document.getElementById("manualReason").value.trim() || "Manual Admin Entry";
    if (!ip) { showToast("Enter an IP address", "err"); return; }

    const btn = document.getElementById("manualBlockBtn");
    btn.textContent = "BLOCKING...";
    btn.disabled = true;

    const res  = await fetch("/api/manual-block", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({ip, severity: sev, reason: rsn})
    });
    const data = await res.json();

    showToast(data.success ? `✓ ${data.message}` : `✗ ${data.message}`,
              data.success ? "ok" : "err");

    btn.textContent = "⚡ TRIGGER BLOCK";
    btn.disabled = false;

    if (data.success) {
        document.getElementById("manualIP").value = "";
        refreshAll();
    }
}

// ── THEME TOGGLE ─────────────────────────────────────────
function toggleTheme() {
    document.body.classList.toggle("light");
    const btn = document.getElementById("themeBtn");
    btn.textContent = document.body.classList.contains("light") ? "🌙 Dark" : "☀ Light";
}

// ── CLOCK ────────────────────────────────────────────────
function updateClock() {
    const el = document.getElementById("clock");
    if (el) el.textContent = new Date().toLocaleString() + " LOCAL";
}

// ── REFRESH ALL ──────────────────────────────────────────
async function refreshAll() {
    const icon = document.getElementById("refreshIcon");
    if (icon) icon.style.animation = "spin 0.8s linear infinite";
    await Promise.allSettled([
        fetchStats(),
        fetchAlerts(),
        fetchIndicators(currentSeverity),
        fetchBlocked(),
        fetchLogs(),
        fetchFeedStatus(),
        fetchCountries(),
        fetchHealth(),
        buildThreatMap()
    ]);
    if (icon) icon.style.animation = "";
    const lu = document.getElementById("lastUpdate");
    if (lu) lu.textContent = new Date().toLocaleTimeString();
    const ct = document.getElementById("comp-time");
    if (ct) ct.textContent = new Date().toLocaleString();
}

setInterval(refreshAll, 30000);
setInterval(updateClock, 1000);
window.onload = () => { updateClock(); refreshAll(); };
