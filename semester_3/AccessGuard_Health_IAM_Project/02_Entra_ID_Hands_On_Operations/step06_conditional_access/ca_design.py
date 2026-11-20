"""
HVMC Healthcare IAM - Step 6: Conditional Access design (documentation + deployable policy files).

Horizon Valley Medical Center | Author: Sabitha S Karanavar

The tenant runs Entra ID Free with security defaults ON (sign-ins blocked with AADSTS530035 on 2026-10-14).
Conditional Access needs Entra ID P1 (risk-based policies: P2), so this step is DESIGN ONLY:
  * POLICIES below is the specification (persona-based, Microsoft CA framework naming)
  * `python3 ca_design.py` writes one Microsoft Graph conditionalAccessPolicy JSON per policy into policies/,
    every one in state "enabledForReportingButNotEnforced" (report-only), plus test_plan.json
  * deploy_ca.py (dry run only until licensed) shows how they would be created
Nothing in the tenant is changed by this script.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
IDS = json.load(open(os.path.join(HERE, "tenant_ids.json")))
GRP, APP = IDS["groups"], IDS["apps"]

BREAKGLASS = "{{SG-CA-Exclude-BreakGlass}}"            # created at deployment: 2 cloud-only emergency accounts
US_LOCATION = "{{NL-Allowed-Countries-US}}"            # named location created at deployment
AZURE_MGMT = "797f4846-ba00-4fd7-ba43-dac1f8f63013"     # Windows Azure Service Management API
PHISH_RESISTANT = "00000000-0000-0000-0000-000000000004"  # built-in authentication strength
ADMIN_ROLES = {"Global Administrator": "62e90394-69f5-4237-9190-012177145e10",
               "Privileged Role Administrator": "e8611ab8-c189-46e8-94e1-60213ab1f814",
               "Security Administrator": "194ae4cb-b126-40b2-bd5b-6091b380977d",
               "Conditional Access Administrator": "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
               "User Administrator": "fe930be7-5e62-47db-91af-98c3a49a38b1",
               "Application Administrator": "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
               "Cloud Application Administrator": "158c047a-c907-4556-b7ef-446551a6b5f7",
               "Helpdesk Administrator": "729827e3-9c14-49f7-bb1b-9608f156bbb8"}
EPHI_APPS = ["HVMC Electronic Health Record", "HVMC Pharmacy Management System", "HVMC Laboratory Information System", "EHR-Simulated"]
CONTRACTOR_GROUPS = ["SG-Contractors-ITAdmin-Limited", "SG-Contractors-VPN-Read"]
CONTRACTOR_APPS = ["HVMC IT Administration Console", "HVMC VPN Portal"]

# id, name, persona, licence, risks, why, users, apps, conditions, grant, session
POLICIES = [
    ("CA001", "CA001-Global-AllApps-BlockLegacyAuthentication", "Everyone", "P1", "R12",
     "Legacy protocols (IMAP, POP, SMTP AUTH, older Office clients) cannot do MFA and are the main password-spray target.",
     {"includeUsers": ["All"]}, {"includeApplications": ["All"]}, {"clientAppTypes": ["exchangeActiveSync", "other"]},
     {"operator": "OR", "builtInControls": ["block"]}, None),
    ("CA002", "CA002-Admins-AllApps-RequirePhishingResistantMFA", "Administrators", "P1", "R04, R12",
     "Admin accounts are the highest-value target; phishing-resistant methods (FIDO2 passkey, Windows Hello) defeat AiTM proxies.",
     {"includeRoles": list(ADMIN_ROLES.values())}, {"includeApplications": ["All"]}, {},
     {"operator": "OR", "authenticationStrength": {"id": PHISH_RESISTANT}}, {"signInFrequency": {"isEnabled": True, "type": "hours", "value": 4, "frequencyInterval": "timeBased"}}),
    ("CA003", "CA003-Global-AllApps-RequireMFA", "Everyone", "P1", "R12, R06",
     "Baseline: every interactive sign-in to any app requires MFA (replaces security defaults when CA is enforced).",
     {"includeUsers": ["All"]}, {"includeApplications": ["All"]}, {}, {"operator": "OR", "builtInControls": ["mfa"]}, None),
    ("CA004", "CA004-Global-AzureManagement-RequireMFA", "Everyone", "P1", "R02, R15",
     "Portal, CLI and PowerShell can change the ePHI storage and network; always MFA, even from trusted places.",
     {"includeUsers": ["All"]}, {"includeApplications": [AZURE_MGMT]}, {}, {"operator": "OR", "builtInControls": ["mfa"]}, None),
    ("CA005", "CA005-Global-ePHIApps-RequireMFAandManagedDevice", "Clinical users (EHR, Pharmacy, LIS)", "P1 + Intune", "R02, R13",
     "Patient data opens only on a hospital-managed (compliant or hybrid-joined) device with MFA; shift-length session.",
     {"includeUsers": ["All"]}, {"includeApplications": EPHI_APPS}, {},
     {"operator": "AND", "builtInControls": ["mfa", "compliantDevice"]},
     {"signInFrequency": {"isEnabled": True, "type": "hours", "value": 8, "frequencyInterval": "timeBased"}}),
    ("CA006", "CA006-Global-ePHIApps-NoPersistentBrowserOnUnmanaged", "Everyone on unmanaged devices", "P1", "R02",
     "Defence in depth if CA005 is in report-only during rollout: no 'stay signed in', re-authenticate hourly on non-compliant devices.",
     {"includeUsers": ["All"]}, {"includeApplications": EPHI_APPS},
     {"devices": {"deviceFilter": {"mode": "exclude", "rule": "device.isCompliant -eq True"}}}, None,
     {"persistentBrowser": {"isEnabled": True, "mode": "never"},
      "signInFrequency": {"isEnabled": True, "type": "hours", "value": 1, "frequencyInterval": "timeBased"}}),
    ("CA007", "CA007-Contractors-AllExceptAssigned-Block", "Contractors", "P1", "R06",
     "Contractors may reach only the apps their contract covers (IT Admin Console - limited, VPN); everything else is blocked.",
     {"includeGroups": CONTRACTOR_GROUPS}, {"includeApplications": ["All"], "excludeApplications": CONTRACTOR_APPS}, {},
     {"operator": "OR", "builtInControls": ["block"]}, None),
    ("CA008", "CA008-Contractors-AllApps-MFAEverySession", "Contractors", "P1", "R06",
     "Contractors re-authenticate with MFA every sign-in and never get a persistent session.",
     {"includeGroups": CONTRACTOR_GROUPS}, {"includeApplications": ["All"]}, {}, {"operator": "OR", "builtInControls": ["mfa"]},
     {"signInFrequency": {"isEnabled": True, "frequencyInterval": "everyTime"}, "persistentBrowser": {"isEnabled": True, "mode": "never"}}),
    ("CA009", "CA009-Global-AllApps-BlockOutsideAllowedCountries", "Everyone", "P1", "R12",
     "HVMC operates only in the US; sign-ins from other countries are blocked (travel exceptions via a temporary group).",
     {"includeUsers": ["All"]}, {"includeApplications": ["All"]}, {"locations": {"includeLocations": ["All"], "excludeLocations": [US_LOCATION]}},
     {"operator": "OR", "builtInControls": ["block"]}, None),
    ("CA010", "CA010-Global-AllApps-BlockDeviceCodeAndAuthTransfer", "Everyone", "P1", "R12",
     "Device-code phishing and cross-device token transfer are current attack techniques; no HVMC workflow needs them.",
     {"includeUsers": ["All"]}, {"includeApplications": ["All"]}, {"authenticationFlows": {"transferMethods": "deviceCodeFlow,authenticationTransfer"}},
     {"operator": "OR", "builtInControls": ["block"]}, None),
    ("CA011", "CA011-Global-SecurityInfoRegistration-RequireUSLocationOrMFA", "Everyone", "P1", "R12",
     "An attacker with a stolen password must not be able to register their own MFA method.",
     {"includeUsers": ["All"]}, {"includeUserActions": ["urn:user:registersecurityinfo"]},
     {"locations": {"includeLocations": ["All"], "excludeLocations": [US_LOCATION]}}, {"operator": "OR", "builtInControls": ["mfa"]}, None),
    ("CA012", "CA012-Global-AllApps-HighUserRisk-SecurePasswordChange", "Everyone", "P2", "R12",
     "Leaked-credential or high user risk forces MFA plus a password change before access.",
     {"includeUsers": ["All"]}, {"includeApplications": ["All"]}, {"userRiskLevels": ["high"]},
     {"operator": "AND", "builtInControls": ["mfa", "passwordChange"]}, {"signInFrequency": {"isEnabled": True, "frequencyInterval": "everyTime"}}),
    ("CA013", "CA013-Global-AllApps-MediumHighSignInRisk-RequireMFA", "Everyone", "P2", "R12",
     "Suspicious sign-ins (anonymous IP, impossible travel, token anomalies) must pass MFA again.",
     {"includeUsers": ["All"]}, {"includeApplications": ["All"]}, {"signInRiskLevels": ["high", "medium"]},
     {"operator": "OR", "builtInControls": ["mfa"]}, {"signInFrequency": {"isEnabled": True, "frequencyInterval": "everyTime"}}),
]

# persona test plan for the What-If tool / sign-in logs once licensed
TEST_PLAN = [
    ("T01", "Sarah Chen (Physician)", "HVMC Electronic Health Record", "Hospital-managed laptop, US, Authenticator MFA", "CA003, CA005", "Allow after MFA; session 8 h"),
    ("T02", "Sarah Chen (Physician)", "HVMC Electronic Health Record", "Personal laptop at home, US", "CA005, CA006", "Blocked (device not compliant) - CA006 limits session if CA005 still report-only"),
    ("T03", "Grace Nguyen (Reception)", "HVMC Appointment Scheduling", "Front-desk PC, US, MFA", "CA003", "Allow after MFA"),
    ("T04", "Any user", "Exchange Online via IMAP client", "Legacy authentication", "CA001", "Blocked"),
    ("T05", "Sabitha S Karanavar (Global Admin)", "Azure portal", "Password + SMS code", "CA002, CA004", "Blocked until a phishing-resistant method (FIDO2/passkey) is used"),
    ("T06", "Contractor (SG-Contractors-*)", "HVMC VPN Portal", "MFA, US", "CA007, CA008", "Allow; MFA every sign-in; no persistent session"),
    ("T07", "Contractor (SG-Contractors-*)", "HVMC Electronic Health Record", "Any", "CA007", "Blocked (app not in contract)"),
    ("T08", "Any user", "Any app", "Sign-in from outside the US", "CA009", "Blocked"),
    ("T09", "Any user", "Any app", "Device-code flow on a second device", "CA010", "Blocked"),
    ("T10", "Any user", "Register security info", "From outside the US without MFA", "CA011", "MFA required (blocked without it)"),
    ("T11", "Any user", "Any app", "Leaked credentials (user risk high)", "CA012", "MFA + secure password change"),
    ("T12", "Break-glass account", "Azure portal", "FIDO2 key, emergency", "Excluded from all", "Allow; Sentinel alert fires on every use"),
    ("T13", "Carlos Diaz (terminated contractor)", "Any app", "Account disabled (JML-203)", "n/a", "Blocked before CA: account disabled, sessions revoked"),
]


def to_graph(p):
    pid, name, persona, lic, risks, why, users, apps, cond, grant, session = p
    u = dict(users)
    u["includeGroups"] = [GRP[g] for g in u.get("includeGroups", [])]
    u.setdefault("excludeGroups", []).append(BREAKGLASS)
    a = dict(apps)
    a["includeApplications"] = [APP.get(x, x) for x in a.get("includeApplications", [])]
    a["excludeApplications"] = [APP.get(x, x) for x in a.get("excludeApplications", [])]
    body = {"displayName": name, "state": "enabledForReportingButNotEnforced",
            "conditions": dict({"users": u, "applications": a, "clientAppTypes": ["all"]}, **cond)}
    if grant:
        body["grantControls"] = grant
    if session:
        body["sessionControls"] = session
    return body


def main():
    os.makedirs(os.path.join(HERE, "policies"), exist_ok=True)
    for p in POLICIES:
        json.dump(to_graph(p), open(os.path.join(HERE, "policies", p[1] + ".json"), "w"), indent=1)
    json.dump([dict(zip(["id", "persona", "app", "scenario", "policies", "expected"], t)) for t in TEST_PLAN],
              open(os.path.join(HERE, "test_plan.json"), "w"), indent=1)
    lic = {}
    for p in POLICIES:
        lic.setdefault(p[3], []).append(p[0])
    print(f"{len(POLICIES)} policy files written to policies/ (all report-only); {len(TEST_PLAN)} test cases")
    print("licence needed:", {k: ", ".join(v) for k, v in lic.items()})


if __name__ == "__main__":
    main()
