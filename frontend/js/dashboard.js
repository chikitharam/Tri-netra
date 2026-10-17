// ============================================================
// MODULE 6 — Personalized dashboard
// ============================================================

const els = {
    usernameTop:    document.getElementById('userNameTop'),
    username:       document.getElementById('username'),
    community:      document.getElementById('community'),
    community2:     document.getElementById('community2'),
    heroCount:      document.getElementById('heroThreatCount'),
    threatCount:    document.getElementById('threatCount'),
    matchesPlural:  document.getElementById('matchesPlural'),
    safetyTip:      document.getElementById('safetyTip'),
    tipCard:        document.getElementById('tipCard'),
    container:      document.getElementById('threatContainer'),
    loading:        document.getElementById('loading'),
    emptyState:     document.getElementById('emptyState'),
    emptyCommunity: document.getElementById('emptyCommunity'),
    generatedAt:    document.getElementById('generatedAt'),
    logoutBtn:      document.getElementById('logoutBtn'),
};


// ============================================================
// Auth check
// ============================================================
async function checkAuth() {
    const res = await fetch('/api/me');
    if (!res.ok) {
        window.location.href = '/app/login.html';
        return null;
    }
    return res.json();
}


// ============================================================
// Fetch dashboard payload
// ============================================================
async function fetchDashboard() {
    const res = await fetch('/api/dashboard');
    if (res.status === 401) {
        window.location.href = '/app/login.html';
        return null;
    }
    if (!res.ok) throw new Error('Failed to load dashboard');
    return res.json();
}


// ============================================================
// Render top-level page
// ============================================================
function render(data) {
    // Header
    els.usernameTop.textContent    = data.name;
    els.username.textContent       = data.name;
    els.community.textContent      = data.community;
    els.community2.textContent     = data.community;
    els.emptyCommunity.textContent = data.community;

    const count = data.threat_count || 0;
    els.heroCount.textContent     = count;
    els.threatCount.textContent   = count;
    els.matchesPlural.textContent = count === 1 ? '' : 'es';

    // Safety tip
    if (data.safety_tip) {
        els.safetyTip.textContent = data.safety_tip;
        els.tipCard.style.display = '';
    } else {
        els.tipCard.style.display = 'none';
    }

    // Threats
    const threats = data.threats || [];
    if (threats.length === 0) {
        els.container.style.display  = 'none';
        els.emptyState.style.display = '';
    } else {
        displayThreats(threats);
        els.container.style.display  = '';
        els.emptyState.style.display = 'none';
    }

    // Footer timestamp
    if (data.generated_at) {
        els.generatedAt.textContent =
            data.generated_at.slice(0, 19).replace('T', ' ');
    }

    els.loading.style.display = 'none';
}


// ============================================================
// displayThreats() — grouped by severity
// ============================================================
function displayThreats(threats) {
    const container = document.getElementById("threatContainer");
    container.innerHTML = "";

    let currentSev = null;

    threats.forEach(threat => {
        const sev = (threat.severity || "Medium").toLowerCase();

        // Insert a group header when the severity changes
        if (sev !== currentSev) {
            currentSev = sev;
            container.appendChild(buildSeverityHeader(sev));
        }

        container.appendChild(buildThreatCard(threat, sev));
    });
}


// ------------------------------------------------------------
// Severity group header
// ------------------------------------------------------------
function buildSeverityHeader(sev) {
    const label = sev.charAt(0).toUpperCase() + sev.slice(1);
    const div = document.createElement("div");
    div.className = `sev-group ${sev}`;
    div.innerHTML = `<span class="dot"></span><span>${escapeHtml(label)}</span>`;
    return div;
}


// ------------------------------------------------------------
// STEP 14 + STEP 15 — One threat card
// ------------------------------------------------------------
// STEP 14: severity badge on top, labeled fields, footer
// STEP 15: "Read More" button navigates to /app/threat.html?id=...
// ------------------------------------------------------------
function buildThreatCard(threat, sev) {
    const card = document.createElement("div");
    card.className = `threat-card sev-${sev}`;

    // Severity label for the top badge
    const sevLabel = sev.charAt(0).toUpperCase() + sev.slice(1);

    // Format target / platform — they're arrays from the API
    const targets   = Array.isArray(threat.target)   ? threat.target   : [];
    const platforms = Array.isArray(threat.platform) ? threat.platform : [];

    const targetText   = targets.length   ? targets.join(", ")   : "—";
    const platformText = platforms.length ? platforms.join(", ") : "—";

    const detailUrl = `/app/threat.html?id=${encodeURIComponent(threat.id)}`;

    card.innerHTML = `
        <div class="tc-severity sev-${sev}">
            <span class="tc-dot"></span>
            <span class="tc-sev-label">${escapeHtml(sevLabel)}</span>
        </div>

        <h3 class="tc-title">${escapeHtml(threat.title || "Untitled")}</h3>

        <div class="tc-fields">
            <div class="tc-field">
                <span class="tc-key">Target</span>
                <span class="tc-val">${escapeHtml(targetText)}</span>
            </div>

            <div class="tc-field">
                <span class="tc-key">Platform</span>
                <span class="tc-val">${escapeHtml(platformText)}</span>
            </div>

            ${threat.region && threat.region !== "Unknown" ? `
            <div class="tc-field">
                <span class="tc-key">Region</span>
                <span class="tc-val">${escapeHtml(threat.region)}</span>
            </div>
            ` : ""}
        </div>

        <div class="tc-footer">
            ${threat.verified
                ? `<span class="tc-chip verified-chip">✓ Verified</span>`
                : `<span class="tc-chip review-chip">⚠ Needs Review</span>`}

            <a class="read-more-btn" href="${detailUrl}">
                Read More →
            </a>
        </div>
    `;

    return card;
}


// ============================================================
// Helpers
// ============================================================
function escapeHtml(s) {
    return String(s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}


// ============================================================
// Logout
// ============================================================
els.logoutBtn.addEventListener("click", async () => {
    try { await fetch("/api/logout", { method: "POST" }); } catch (_) {}
    window.location.href = "/app/login.html";
});


// ============================================================
// Init
// ============================================================
(async function init() {
    try {
        const me = await checkAuth();
        if (!me) return;

        const data = await fetchDashboard();
        if (!data) return;

        render(data);
    } catch (err) {
        els.loading.innerHTML = `
            <div style="color:var(--critical);">
                Failed to load: ${escapeHtml(err.message)}
            </div>
        `;
    }
})();