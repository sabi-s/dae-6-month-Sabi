# Step 11 – Identity Resilience (Phases 1, 3 and 6)

**Report:** [AccessGuard_Health_Entra_Identity_Resilience_Implementation.pdf](./AccessGuard_Health_Entra_Identity_Resilience_Implementation.pdf) (v1.1, 29 pages, 48 figures)

| Phase | What was done |
|---|---|
| 1 – Emergency access | Two cloud-only break-glass Global Administrators, sign-in tested with MFA; Security Defaults confirmed on; group `SG-CA-Exclude-BreakGlass` for Conditional Access exclusions |
| 3 – Consent and application permissions | User consent disabled; admin consent request workflow with a named reviewer; inventory of 12 enterprise apps; Lab Results Sync permission review; tenant-wide delegated-grant audit (read-only) |
| 6 – Containment and posture | Compromised-account drill on a test user (disable, revoke sessions, check consents); Maester posture report (746 tests) triaged; two fixes: BitLocker key recovery restricted, Microsoft 365 group creation restricted |

All work used Microsoft Entra ID Free ($0). Next phase: Conditional Access – see [step06_conditional_access](../step06_conditional_access/).

Screenshots are masked: tenant domain, e-mail address and identifiers are replaced by `<tenant>`, `<email>` and `<id>`; the administrator's IP address is redacted.
