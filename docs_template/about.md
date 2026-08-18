---
title: "About Me"
permalink: /about/
layout: single
---

<div style="text-align:center; margin-bottom:2rem;">
  <img src="{{ '/assets/img/avatar.png' | relative_url }}" alt="Akhila Chennamaneni" 
       style="max-width:200px; border-radius:50%; box-shadow:0 4px 12px rgba(0,0,0,.15);">
</div>

## My Journey in IAM & Salesforce

Hi, I’m **Akhila Chennamaneni** — an experienced Salesforce Administrator and Business Analyst transitioning into **Identity and Access Management (IAM)**. With over 3 years of hands-on experience managing complex CRM systems, I specialize in bridging the gap between business requirements and technical implementation.

I’m **actively developing** my technical skills in **Cybersecurity**, specifically focusing on **IAM governance**, **GRC risk assessments**, and **RBAC design** to protect sensitive enterprise data.

Having completed my **Cybersecurity Capstone Project (Care Access Navigator)**, I’m now looking for an **IAM Analyst role** where I can apply my Salesforce administration background to help organizations manage identities and secure access at scale.

---

### Core Interests & Expertise  
- **Identity Governance** – Implementing joiner-mover-leaver (JML) workflows and role-based access control (RBAC).  
- **GRC Operations** – Mapping technical controls to HIPAA/NIST frameworks and managing risk registers.  
- **Business Analysis** – Gathering elicitation requirements and documenting functional specifications for security enhancements.  
- **Data Analytics** – Leveraging Tableau and Excel to visualize access metrics, incident trends, and compliance status. 
- **Salesforce Administration** – Optimizing security models, sharing rules, and automation flows within Salesforce Orgs.

---

### Technical Skills  

**IAM & GRC Tools:**  
- Identity Providers *(Keycloak, Microsoft Entra ID concepts)*  
- GRC Platforms *(Monday.com, Excel Risk Registers)*  
- Data Visualization *(Tableau, Lucidchart)* 

**Salesforce & CRM:**  
- Salesforce CRM *(Flows, Reports, Security & Sharing, NPSP)*  
- Collaboration Tools *(Slack, Confluence, Jira, Asana)* 
- Data Integration *(Data Loader, Workbench)* 

---

**Looking for:** IAM Analyst or GRC-focused role in a growth-oriented security team. 

---

*“Bridging business processes with secure identity governance to protect organizational assets.”*

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
