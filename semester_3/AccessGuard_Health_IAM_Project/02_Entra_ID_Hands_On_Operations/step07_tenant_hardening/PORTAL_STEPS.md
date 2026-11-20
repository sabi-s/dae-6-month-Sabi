# Step 7 Part A in the Entra admin center (fallback if the script is refused)

Sign in at https://entra.microsoft.com as the Global Administrator.

1. **Identity > Applications > Enterprise applications > Consent and permissions > User consent settings**
   Select **Do not allow user consent**. Save.
2. **Identity > Users > User settings**
   - Users can register applications: **No**
   - Restrict non-admin users from creating tenants: **Yes**
   Save.
3. **Identity > Groups > General**
   - Users can create security groups in Azure portals, API or PowerShell: **No**
   Save.
4. **Identity > External Identities > External collaboration settings**
   - Guest user access: **Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)**
   - Guest invite settings: **Only users assigned to specific admin roles can invite guest users**
   - Enable guest self-service sign up via user flows: **No**
   Save.

Then run `python3 tenant_hardening.py --part settings` (dry run): every line should show "(no change)".
