---
title: "Contact"
permalink: /contact/
layout: single
---

<div style="text-align:center; margin-bottom:3rem;">
  <img src="{{ '/assets/img/avatar.png' | relative_url }}" alt="Akhila Chennamaneni" 
       style="max-width:150px; border-radius:50%; box-shadow:0 4px 12px rgba(0,0,0,.15);">
  <h2 style="margin:1rem 0 0.5rem; color:#2c3e50;">Let's Connect</h2>
  <p style="color:#7f8c8d; font-size:1.1rem;">I'm always interested in discussing IAM, GRC, and Salesforce operations.</p>
</div>

## Get in Touch

<div style="display:grid; gap:1.5rem; margin:2rem 0;">
  
  <div style="background:#f8f9fa; padding:1.5rem; border-radius:8px; border-left:4px solid #0070f3;">
    <h3 style="margin:0 0 0.5rem; color:#2c3e50;">Email</h3>
    <p style="margin:0; font-size:1.1rem;"><a href="mailto:ch.akhilarao@gmail.com" style="color:#0070f3; text-decoration:none;">ch.akhilarao@gmail.com</a></p>
    <p style="margin:0.5rem 0 0; color:#6c757d; font-size:0.9rem;">Best for professional inquiries and project discussions</p>
  </div>
  
  <div style="background:#f8f9fa; padding:1.5rem; border-radius:8px; border-left:4px solid #0077b5;">
    <h3 style="margin:0 0 0.5rem; color:#2c3e50;">LinkedIn</h3>
    <p style="margin:0; font-size:1.1rem;"><a href="https://www.linkedin.com/in/akhila-chennamaneni-228651236" style="color:#0077b5; text-decoration:none;">linkedin.com/in/akhila-chennamaneni</a></p>
    <p style="margin:0.5rem 0 0; color:#6c757d; font-size:0.9rem;">Connect for networking and professional updates</p>
  </div>
  
  <div style="background:#f8f9fa; padding:1.5rem; border-radius:8px; border-left:4px solid #333;">
    <h3 style="margin:0 0 0.5rem; color:#2c3e50;">GitHub</h3>
    <p style="margin:0; font-size:1.1rem;"><a href="https://github.com/Akchrao" style="color:#333; text-decoration:none;">github.com/Akchrao</a></p>
    <p style="margin:0.5rem 0 0; color:#6c757d; font-size:0.9rem;">Explore my capstone artifacts and technical contributions</p>
  </div>
  
</div>

---

## What I'm Looking For

<div style="background:#e8f4fd; padding:2rem; border-radius:8px; margin:2rem 0;">
  <h3 style="margin:0 0 1rem; color:#2c3e50;">IAM Analyst Opportunities</h3>
  <p style="margin:0 0 1rem; line-height:1.6;">I'm actively seeking **IAM Analyst** or **GRC Specialist** roles where I can:</p>
  
  <ul style="margin:0; padding-left:1.5rem; line-height:1.8;">
    <li>Implement and govern identity lifecycle (JML) workflows</li>
    <li>Design and audit RBAC and least-privilege models</li>
    <li>Map technical security controls to compliance frameworks (HIPAA, NIST)</li>
    <li>Leverage my Salesforce background for CRM security and operations</li>
    <li>Contribute to robust governance and risk mitigation strategies</li>
  </ul>
</div>

## Let's Discuss

<div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(250px, 1fr)); gap:1rem; margin:2rem 0;">
  
  <div style="background:#fff3cd; padding:1rem; border-radius:6px; text-align:center;">
    <h4 style="margin:0 0 0.5rem; color:#856404;">Identity Governance</h4>
    <p style="margin:0; font-size:0.9rem; color:#6c757d;">Keycloak, Entra ID, RBAC design</p>
  </div>
  
  <div style="background:#d1ecf1; padding:1rem; border-radius:6px; text-align:center;">
    <h4 style="margin:0 0 0.5rem; color:#0c5460;">GRC & Risk</h4>
    <p style="margin:0; font-size:0.9rem; color:#6c757d;">HIPAA compliance, NIST controls, Risk registers</p>
  </div>
  
  <div style="background:#d4edda; padding:1rem; border-radius:6px; text-align:center;">
    <h4 style="margin:0 0 0.5rem; color:#155724;">Salesforce CRM</h4>
    <p style="margin:0; font-size:0.9rem; color:#6c757d;">CRM security, sharing models, automation</p>
  </div>
  
</div>

---

<div style="text-align:center; margin-top:3rem; padding:2rem; background:#f8f9fa; border-radius:8px;">
  <h3 style="margin:0 0 1rem; color:#2c3e50;">Ready to Connect?</h3>
  <p style="margin:0 0 1.5rem; color:#6c757d;">Whether you're looking to discuss identity governance, GRC strategies, or Salesforce optimization, I'd love to hear from you!</p>
  
  <a href="mailto:ch.akhilarao@gmail.com" style="background:#0070f3; color:white; padding:0.75rem 1.5rem; text-decoration:none; border-radius:99px; font-weight:bold; display:inline-block;">Send me an email</a>
  
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
