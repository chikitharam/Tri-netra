let selectedCommunity = "";


const threats = {

    student: [
        {
            title: "Fake Internship Scam",
            location: "Karnataka"
        },
        {
            title: "Fake Scholarship Website",
            location: "Students"
        },
        {
            title: "Phishing Email Targeting Students",
            location: "Karnataka"
        }
    ],

    senior_citizen: [
        {
            title: "Fake Bank Call Scam",
            location: "Karnataka"
        },
        {
            title: "Digital Arrest Scam",
            location: "India"
        },
        {
            title: "Fake Pension Update Message",
            location: "Karnataka"
        }
    ],

    small_business: [
        {
            title: "Fake GST Refund Scam",
            location: "India"
        },
        {
            title: "Business Email Fraud",
            location: "India"
        },
        {
            title: "Fake Vendor Payment Request",
            location: "Karnataka"
        }
    ],

    regional: [
        {
            title: "Regional Phishing Campaign",
            location: "Karnataka"
        },
        {
            title: "Fake Government Scheme",
            location: "Karnataka"
        },
        {
            title: "Local Job Scam",
            location: "Karnataka"
        }
    ]
};

function selectCommunity(community) {

    selectedCommunity = community;

    document.getElementById("selectedCommunity").innerText =
        "Selected: " + community;

    document.getElementById("locationSection").style.display = "block";

    document.getElementById("languageSection").style.display = "block";

    document.getElementById("notificationSection").style.display = "block";

    document.getElementById("continueBtn").disabled = false;
}

function continueToProfile() {

    alert("Community selected: " + selectedCommunity);
}

async function saveProfile() {

    const name = document.getElementById("name").value;
    const email = document.getElementById("email").value;
    const location = document.getElementById("location").value;

    const languageElement =
        document.querySelector('input[name="language"]:checked');

    const notificationElement =
        document.querySelector(
            'input[name="notificationPreference"]:checked'
        );

    const language = languageElement ? languageElement.value : "";
    const notificationPreference =
        notificationElement ? notificationElement.value : "";

    if (!name || !email || !selectedCommunity || !location ||
        !language || !notificationPreference) {

        alert("Please fill all the details.");
        return;
    }

    const userData = {
        name: name,
        email: email,
        community: selectedCommunity,
        location: location,
        language: language,
        notificationPreference: notificationPreference
    };

    try {

        const response = await fetch(
            "http://127.0.0.1:5000/users",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify(userData)
            }
        );

        const result = await response.json();

        if (response.ok) {

            alert("Profile saved successfully! 🎉");

            console.log(result);

            showDashboard();

        } else {

            alert("Error: " + result.error);
        }

    } catch (error) {

        console.error(error);

        alert(
            "Cannot connect to backend. Make sure Flask is running."
        );
    }
}

function showDashboard() {

    const name =
        document.getElementById("name").value;

    const dashboard =
        document.getElementById("dashboard");

    const dashboardTitle =
        document.getElementById("dashboardTitle");

    dashboard.style.display = "block";

    let communityName = "";

    if (selectedCommunity === "student") {

        communityName =
            "🎓 Student Safety Dashboard";

    } else if (selectedCommunity === "senior_citizen") {

        communityName =
            "👴 Senior Citizen Safety Dashboard";

    } else if (selectedCommunity === "small_business") {

        communityName =
            "🏪 Small Business Safety Dashboard";

    } else {

        communityName =
            "🌐 Regional Community Dashboard";
    }

    dashboardTitle.innerText =
        "Welcome, " + name + " 👋\n" +
        communityName;

    // Get real threats from Firebase
    loadThreats();
}

async function loadThreats() {

    const location =
        document.getElementById("location").value;

    try {

        const url =
            `http://127.0.0.1:5000/threats?community=${encodeURIComponent(selectedCommunity)}&location=${encodeURIComponent(location)}`;

        const response = await fetch(url);

        if (!response.ok) {
            throw new Error("Failed to load threats");
        }

        const data = await response.json();

        const threatList =
            document.getElementById("threatList");

        threatList.innerHTML = "";

        if (data.length === 0) {

            threatList.innerHTML =
                "<p>No matching threats found.</p>";

            return;
        }

        data.forEach(function(threat, index) {

            const threatElement =
                document.createElement("div");

            threatElement.className = "threat";

            threatElement.innerHTML = `
                <strong>
                    ${index + 1}. ${threat.title}
                </strong>

                <br>

                <span>
                    📍 ${threat.location}
                </span>

                <br>

                <span>
                    ⚠️ Severity: ${threat.severity}
                </span>

                <br>

                <span>
                    📂 Category: ${threat.category}
                </span>

                <p>
                    ${threat.description}
                </p>
            `;

            threatList.appendChild(threatElement);
        });

    } catch (error) {

        console.error("Threat loading error:", error);

        document.getElementById("threatList").innerHTML =
            "<p>Unable to load threats.</p>";
    }
}