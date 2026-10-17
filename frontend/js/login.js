// ============================================================
// MODULE 6 — Login page
// ============================================================
// Talks to:
//   POST /api/login   → verify credentials, start session
//   GET  /api/me      → (optional) check if already logged in
//
// On success, redirects to /app/dashboard.html.
// ============================================================

(function () {
    "use strict";

    // --------------------------------------------------------
    // Element lookups
    // --------------------------------------------------------
    const form      = document.getElementById("loginForm");
    const emailInp  = document.getElementById("email");
    const passInp   = document.getElementById("password");
    const submitBtn = document.getElementById("submitBtn");
    const errorBox  = document.getElementById("error");

    // Guard: if any required element is missing, log and bail
    if (!form || !emailInp || !passInp || !submitBtn || !errorBox) {
        console.error("[login.js] Missing required DOM elements. " +
                      "Check that login.html has: #loginForm, #email, " +
                      "#password, #submitBtn, #error.");
        return;
    }

    // --------------------------------------------------------
    // Helpers
    // --------------------------------------------------------
    function showError(message) {
        errorBox.textContent = message;
        errorBox.style.display = "block";
    }

    function clearError() {
        errorBox.textContent = "";
        errorBox.style.display = "none";
    }

    function setBusy(busy) {
        submitBtn.disabled = busy;
        submitBtn.textContent = busy ? "Signing in…" : "Sign In";
    }

    // --------------------------------------------------------
    // Optional: if already logged in, skip the login page
    // --------------------------------------------------------
    (async function checkExistingSession() {
        try {
            const res = await fetch("/api/me", { credentials: "same-origin" });
            if (res.ok) {
                window.location.href = "/app/dashboard.html";
            }
        } catch (_) {
            // Ignore — user stays on the login page
        }
    })();

    // --------------------------------------------------------
    // Form submit
    // --------------------------------------------------------
    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        clearError();

        const email    = emailInp.value.trim().toLowerCase();
        const password = passInp.value;

        if (!email || !password) {
            showError("Please enter both email and password.");
            return;
        }

        setBusy(true);

        try {
            const res = await fetch("/api/login", {
                method: "POST",
                credentials: "same-origin",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, password }),
            });

            const data = await res.json().catch(() => ({}));

            if (!res.ok) {
                showError(data.message || "Login failed.");
                setBusy(false);
                passInp.focus();
                passInp.select();
                return;
            }

            // Success — go to the personalized dashboard
            window.location.href = "/app/dashboard.html";

        } catch (err) {
            console.error("[login.js] Login error:", err);
            showError("Network error. Is the backend running?");
            setBusy(false);
        }
    });

    // --------------------------------------------------------
    // Demo-user quick-fill buttons
    // --------------------------------------------------------
    document.querySelectorAll(".demo-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
            const email = btn.dataset.email || "";
            emailInp.value = email;
            passInp.value  = "trinetra123";
            clearError();
            passInp.focus();
        });
    });

    // --------------------------------------------------------
    // Small UX: clear error as soon as the user starts typing
    // --------------------------------------------------------
    [emailInp, passInp].forEach((inp) => {
        inp.addEventListener("input", clearError);
    });

})();