# Step 10 — Activity 4: MFA support (lost phone)

HVMC Healthcare IAM · Microsoft Entra ID Free · Author: Sabitha S Karanavar · Ticket **IAM-0004** · Cost **$0**

Scenario: Dr. Sarah Chen (HVMC-1001, Doctors) has lost the phone with her Microsoft Authenticator app. The help desk
checks it is really her, signs her out everywhere, removes the lost phone's MFA method, and she registers her new phone.

## What you need
- The office Mac with PowerShell (`pwsh`) and your phone with Microsoft Authenticator
- Sarah's password, from the protected staff-password zip (CHG-109). Type it into the browser only; never paste it in a file or chat
- About 45 minutes. Take a screenshot at each 📸 and save it in `ticket/screenshots/` with the name shown

## Steps
Open Terminal, then:
```
pwsh
cd ~/Downloads/HVMC_IAM_Entra_Handson/step10_mfa_support
```

**0. Set-up: give Sarah an MFA method (the "old phone").**
Open a **private** browser window → `https://mysignins.microsoft.com/security-info` → sign in as `sarah.chen@<tenant>`
with her password → **Add sign-in method** → Microsoft Authenticator → follow the prompts with your phone (the account
appears in Authenticator). If a "Let's keep your account secure" screen appears first, follow it instead — same result.
Sign out and close the private window.

**1. Before state (read-only).** A browser sign-in opens the first time; use your HVMC admin account and approve MFA.
```
./Invoke-HvmcMfaSupport.ps1 -Action Status
```
📸 `01_status_before.png` — the Authenticator method is listed. Note the time: this is when the ticket is opened.

**2. Verify the caller (the most important step).** In a real help desk you call back on the number HR has on file, or
confirm with her manager. For the lab, write down how you would verify; you will type it in step 4.

**3. Dry run.**
```
./Invoke-HvmcMfaSupport.ps1 -Action Reset
```
📸 `02_reset_dryrun.png` — the plan: revoke sessions, remove the Authenticator method; nothing changed.

**4. Reset.**
```
./Invoke-HvmcMfaSupport.ps1 -Action Reset -Apply -VerifiedBy "Call-back to the phone number HR has on file"
```
📸 `03_reset_apply.png` — each step `ok`, then `MFA methods: 0` and `RESET DONE`.

**5. Sarah registers the "new phone".** In Authenticator on your phone, delete the old HVMC Sarah entry (that phone is
"lost"). Private browser → `https://mysignins.microsoft.com/security-info` → sign in as Sarah (password only — she has no
MFA method now) → **Add sign-in method** → Microsoft Authenticator → scan the new QR code → approve the test notification.
📸 `04_reregister.png` — the Security info page showing the newly added Authenticator.

**6. Verify** (audit events can take up to 15 minutes to appear; run it again if a check says FAIL).
```
./Invoke-HvmcMfaSupport.ps1 -Action Verify
```
📸 `05_verify.png` — `6/6 checks passed`. Note the time: the ticket is closed.

**7. Audit log in the portal.** `https://entra.microsoft.com` → Users → Sarah Chen → Audit logs.
📸 `06_audit_portal.png` — *Admin deleted security info* and *User registered security info*.
(Sign-in logs are also in the portal; on Free tier they are not available through the API.)

**8. Ticket.** Put the opened/closed times in `ticket/IAM-0004.json` (`"opened"`, `"closed"`), then:
```
exit
python3 ticket/build_ticket.py
```
→ `ticket/Ticket_IAM-0004_MFA_Support.pdf`, filled from the evidence and your screenshots. Then tell Claude to add Step 10
to the IAM report and push.

## Run of 5 November 2026 — done (Verify 6/6)
Ticket: [`ticket/Ticket_IAM-0004_MFA_Support.pdf`](ticket/Ticket_IAM-0004_MFA_Support.pdf) (opened 3:25 PM, closed 3:54 PM) ·
run log: [`HVMC_Step10_MFA_Support_Run_2026-11-05.pdf`](HVMC_Step10_MFA_Support_Run_2026-11-05.pdf) · masked screenshots in `ticket/screenshots/`.

**Changes since the guide was written** (the guide PDF still shows the original plan):
- **Sign in as the help-desk account, not the Global Admin.** Security defaults block the personal-account Global Admin from
  Microsoft Graph PowerShell (AADSTS530035). The reset is done by `helpdesk.admin@<tenant>` ("HVMC Help Desk Admin"),
  roles **Authentication Administrator** + **Reports Reader**, with its own Authenticator — least privilege.
- One-time set-up by the Global Admin (Azure CLI sign-in): `./grant_helpdesk_consent.sh` approves Microsoft Graph Command
  Line Tools for **helpdesk.admin only** (consent type Principal). Undo: `./grant_helpdesk_consent.sh --undo`.
- Sign-in opens a browser window by default (`-DeviceCode` for the code method); the tenant is named at run time.
- After `-Apply` the script waits up to 2 minutes for Entra ID to show the change (a deleted method can still be listed for a
  short time); Verify accepts a later Status run showing 0 MFA methods.
- Audit actors from a personal account are shown as "Global Admin (IAM admin)".

## Safety built in
- Dry run unless `-Apply`; `-Apply` refuses to run without `-VerifiedBy`.
- Accounts with an admin role are refused (admin MFA recovery uses the break-glass process).
- Only MFA methods are removed; the password, the reset email, groups and apps are not touched.
- Phone numbers are masked; evidence JSON stays in `evidence/` (git-ignored).
