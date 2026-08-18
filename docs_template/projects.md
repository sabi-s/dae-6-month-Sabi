---
permalink: /projects/
layout: single
---

<div style="margin-bottom:3rem;">
  <h2>Featured Projects</h2>
  <p>Showcasing my work in Identity & Access Management (IAM), Governance, Risk & Compliance (GRC), and Salesforce CRM operations.</p>
</div>

## Care Access Navigator: Healthcare IAM + GRC Capstone

<div style="background:#f8f9fa; padding:1.5rem; border-radius:8px; margin:1rem 0; border-left:4px solid #0070f3;">
  <p><strong>Tech Stack:</strong> Keycloak, Microsoft Entra ID, Tableau, Python, Monday.com, Lucidchart</p>
  <p><strong>Status:</strong> Completed (Capstone)</p>
</div>

This project simulates a healthcare cybersecurity environment that combines **Identity and Access Management (IAM)** with **Governance, Risk and Compliance (GRC)** to protect simulated electronic Protected Health Information (ePHI).

**Key Components:**
- **Identity Governance Lab**: Configured Keycloak for RBAC, least privilege, and identity lifecycle management (JML workflows).
- **GRC Framework Implementation**: Developed a risk register, control matrix, and evidence index mapped to HIPAA and NIST frameworks.
- **Security Monitoring**: Simulated authentication and access anomalies, demonstrating end-to-end incident response for identity-related threats.
- **Tableau Management Reporting**: Integrated IAM, risk, and compliance metrics into a professional GRC dashboard.

**Impact:**
- Demonstrated end-to-end identity lifecycle governance for a simulated healthcare workforce.
- Established a repeatable control testing and evidence collection methodology for HIPAA compliance.
- Visualized security posture through automated GRC reporting.

---

## Salesforce Administration & Automation

<div style="background:#f8f9fa; padding:1.5rem; border-radius:8px; margin:1rem 0; border-left:4px solid #28a745;">
  <p><strong>Focus:</strong> CRM Security, Automation, Data Integrity</p>
  <p><strong>Experience:</strong> 3+ Years</p>
</div>

Hands-on experience in managing Salesforce CRM systems, supporting end-users, and optimizing business processes through advanced automation.

**Key Achievements:**
- **Survey Vista Integration**: Led a team to integrate third-party tools into Salesforce, managing feedback loops and tracking project outcomes.
- **Process Automation**: Implemented complex Screen Flows, Record-Triggered Flows, and Approval Processes to streamline user workflows.
- **Data Governance**: Performed data cleansing, auditing, and bulk loading using Data Loader and Import Wizard, maintaining high data integrity.
- **User Training & Adoption**: Developed training content and led sessions to transition users from legacy systems to Salesforce.

---

<div style="text-align:center; margin-top:3rem; padding:2rem; background:#f8f9fa; border-radius:8px;">
  <h3>Interested in Collaboration?</h3>
  <p>I am always looking for opportunities to apply my IAM and Salesforce skills to solve complex security and operational challenges.</p>
  <p><a href="/contact/" style="background:#0070f3; color:white; padding:0.5rem 1.5rem; text-decoration:none; border-radius:99px; font-weight:600;">Get in Touch</a></p>
  
  <div style="text-align:center; margin-top:2rem;">
  <a href="https://www.mydae.org/" target="_blank" rel="noopener">
    <img src="{{ '/assets/img/dae-logo.png' | relative_url }}" alt="DAE Logo" 
         style="height:40px; opacity:0.8; box-shadow:none;">
  </a>
</div>

<!-- Google tag (gtag.js) -->
<script async src="https://www.googletagmanager.com/gtag/js?id=G-4NCZMZSGWD"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){ dataLayer.push(arguments); }
  gtag('js', new Date());
  gtag('config', 'G-4NCZMZSGWD');

  // --- Active time tracking (GA4-ready) ---
  if (!window.__timeOnPageTrackerInitialized) {
    window.__timeOnPageTrackerInitialized = true;

    let seconds = 0;
    const TICK_MS = 5000;          // count every 5s
    const SEND_EVERY_SEC = 30;     // send every 30s
    const IDLE_MS = 60000;         // consider idle after 60s without input

    let pageActive = document.visibilityState === "visible" && document.hasFocus();
    let lastActivity = Date.now();

    const setActive = (state) => {
      pageActive = state;
      if (state) lastActivity = Date.now();
    };

    document.addEventListener("visibilitychange", () => {
      setActive(document.visibilityState === "visible" && document.hasFocus());
    });
    window.addEventListener("focus",  () => setActive(true));
    window.addEventListener("blur",   () => setActive(false));

    // Update lastActivity on user input
    ["mousemove","keydown","mousedown","touchstart","scroll"].forEach(ev => {
      window.addEventListener(ev, () => { lastActivity = Date.now(); }, { passive: true });
    });

    const sendEvent = () => {
      gtag("event", "time_on_page", {
        time_on_page_sec: seconds,       // <-- create a GA4 custom metric for this
        transport_type: "beacon"
        // send_to: "G-4NCZMZSGWD"       // uncomment if you have multiple GA properties configured
      });
    };

    const intervalId = setInterval(() => {
      const idle = Date.now() - lastActivity > IDLE_MS;
      if (pageActive && !idle) {
        seconds += TICK_MS / 1000;
        if (seconds % SEND_EVERY_SEC === 0) sendEvent();
      }
    }, TICK_MS);

    // Flush on page exit
    const flush = () => { if (seconds > 0) sendEvent(); };
    window.addEventListener("pagehide", flush);
    window.addEventListener("beforeunload", flush);
  }
</script>
