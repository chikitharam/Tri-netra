// ============================================================
// MODULE 6 — Threat detail page
// ============================================================
// Reads ?id=<threatId> from the URL, fetches /api/threat/<id>,
// and renders the full detail view.
// ============================================================

(function () {
    "use strict";

    const params = new URLSearchParams(window.location.search);
    const threatId = params.get("id");

    const els = {
        loading:     document.getElementById("loading"),
        errorState:  document.getElementById("errorState"),
        errorTitle:  document.getElementById("errorTitle"),
        errorMsg:    document.getElementById("errorMsg"),
        detail:      document.getElementById("detail"),
        threatId:    document.getElementById("threatId"),
        threatTitle: document.getElementById("threatTitle"),
        threatBadges: document.getElementById("threatBadges"),
        whatHappened: document.getElementById("whatHappened"),
        howAttack:   document.getElementById("howAttack"),
        identifyList: document.getElementById("identifyList"),
        actionList:  document.getElementById("actionList"),
        tipSection:  document.getElementById("tipSection"),
        safetyTip:   document.getElementById("safetyTip"),
        metaId:      document.getElementById("metaId"),
        metaType:    document.getElementById("metaType"),
        metaRegion:  document.getElementById("metaRegion"),
        metaVerified: document.getElementById("metaVerified"),
    };

    // --------------------------------------------------------
    // No id in URL → error out early
    // --------------------------------------------------------
    if (!threatId) {
        showError("Missing threat ID", "This page needs a ?id=<threatId> in the URL.");
        return;
    }

    // --------------------------------------------------------
    // Load
    // --------------------------------------------------------
    loadThreat(threatId);

    async function loadThreat(id) {
        try {
            const res = await fetch(`/api/threat/${encodeURIComponent(id)}`);
            if (res.status === 404) {
                showError("Threat not found", `No threat with ID "${id}".`);
                return;
            }
            if (!res.ok) {
                showError("Server error", `HTTP ${res.status}`);
                return;
            }

            const doc = await res.json();
            render(doc);

        } catch (err) {
            showError("Network error", "Could not reach the backend.");
            console.error(err);
        }
    }

    // --------------------------------------------------------
    // Render
    // --------------------------------------------------------
    function render(doc) {
        const simplified = doc.simplified || {};

        // Hero
        els.threatId.textContent = threatId;
        els.threatTitle.textContent =
            simplified.title || doc.threat_id || "Threat";

        // Badges
        const badges = [];
        if (doc.severity) {
            const sev = String(doc.severity).toLowerCase();
            badges.push(`<span class="sev-pill ${sev}">${escapeHtml(doc.severity)}</span>`);
        }
        if (doc.threat_type && doc.threat_type !== "Unknown") {
            badges.push(`<span class="meta-chip">${escapeHtml(doc.threat_type)}</span>`);
        }
        if (Array.isArray(doc.communities) && doc.communities.length) {
            badges.push(`<span class="meta-chip">👥 ${escapeHtml(doc.communities.join(" • "))}</span>`);
        }
        if (doc.verified) {
            badges.push(`<span class="meta-chip verified-chip">✓ Verified</span>`);
        } else {
            badges.push(`<span class="meta-chip review-chip">⚠ Needs Review</span>`);
        }
        els.threatBadges.innerHTML = badges.join("");

        // Text sections
        els.whatHappened.textContent =
            simplified.what_happened || "No summary available.";

        els.howAttack.textContent =
            simplified.how_attack_works || "No attack description available.";

        // Lists
        fillList(els.identifyList, simplified.how_to_identify, "🚩");
        fillList(els.actionList, simplified.what_to_do, "✓");

        // Safety tip
        if (simplified.safety_tip) {
            els.safetyTip.textContent = simplified.safety_tip;
            els.tipSection.style.display = "";
        } else {
            els.tipSection.style.display = "none";
        }

        // Meta strip
        els.metaId.textContent = threatId;
        els.metaType.textContent = doc.threat_type || "Unknown";
        els.metaRegion.textContent = doc.region || "Unknown";
        els.metaVerified.textContent = doc.verified ? "Yes" : "Pending review";

        // Swap visibility
        els.loading.style.display = "none";
        els.detail.style.display = "";
    }

    function fillList(ul, items, marker) {
        ul.innerHTML = "";

        if (!Array.isArray(items) || items.length === 0) {
            const li = document.createElement("li");
            li.className = "detail-empty";
            li.textContent = "No information available.";
            ul.appendChild(li);
            return;
        }

        items.forEach((item) => {
            const li = document.createElement("li");
            li.innerHTML = `<span class="mark">${marker}</span><span>${escapeHtml(item)}</span>`;
            ul.appendChild(li);
        });
    }

    function showError(title, msg) {
        els.loading.style.display = "none";
        els.detail.style.display = "none";
        els.errorState.style.display = "";
        els.errorTitle.textContent = title;
        els.errorMsg.textContent = msg;
    }

    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }
})();