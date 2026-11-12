# 🪞 Reflection: Learning Azure Key Vault for AccessGuard Health

**Author:** Sabitha S Karanavar · **Period:** 3–10 November 2026 · **Plan:** [PLAN.md](./PLAN.md) · **Log:** [README.md](./README.md)

---

## What I set out to do

Learn one new technology and integrate it into my capstone, AccessGuard Health. I chose **Azure Key Vault** because my
project already runs on Microsoft Entra ID and Azure, and my lab scripts needed credentials. My three tasks were: build a
secure vault, map my RBAC model to Key Vault roles and prove least privilege, and remove a hardcoded secret from a script while
logging every access.

## What I achieved

| Task | Result |
|---|---|
| 1. RBAC vault with purge protection | Vault `hvmc-accessguard-kv` with soft delete, purge protection and two dummy secrets, created by a script with a dry run |
| 2. RBAC mapping and least privilege | Three groups (Administrator, Reader, Secrets User) at vault scope; **all tests passed**: Reader sees names but gets 403 on values; Secrets User reads but cannot create or delete |
| 3. No hardcoded secret + audit logging | `lab_results_sync.py` reads its key with `DefaultAzureCredential`; every read appears as `SecretGet` in Log Analytics; no secret value in any file or commit |

All three success criteria in my plan were met, a week ahead of the target date.

## What I learned

-   **Managing a resource is not the same as reading its data.** As subscription Owner I still could not read a secret. Azure
    separates the control plane from the data plane — the same separation of duties a hospital needs between IT admins and the
    people who use credentials.
-   **Testing the "cannot" matters more than the "can".** A role is only proven when the denied action is shown to fail. Because
    roles add up, I had to make the test identity a member of one group only.
-   **Identity is everything.** Twice a test result was misleading because the terminal was signed in as someone else
    (once as the app, once as the admin). Now I check `az account show` before trusting any result.
-   **Cloud changes take time.** A group change for a service principal took almost two hours to apply, and the first audit logs
    took over 30 minutes to appear. Waiting and verifying beat changing more settings.
-   **Read logs critically.** My first query labelled the caller "Application" when it was really me. Checking the raw fields
    turned a believable mistake into accurate evidence.
-   **Evidence hygiene.** Every screenshot had to be masked (tenant, subscription and object IDs, e-mail, IP) before going to
    GitHub, and PDFs flattened so masked text cannot be copied out.

## What went well

-   Dry runs and small, single-purpose scripts made every change reviewable and repeatable.
-   Reusing my existing project pieces — the Day 2 group naming, the non-human identity *HVMC Lab Results Sync*, the SecOps
    Log Analytics workspace — made Key Vault feel like part of the project, not a side exercise.
-   Costs stayed tiny (about $1 for the month) because I set a budget and checked costs before every Azure change.

## What was hard

-   Getting an active subscription again after the free trial expired, without losing my earlier lab resources.
-   Certificate sign-in for the app (`-p` rejected, `--certificate` needed) and finding the app in group membership lists.
-   Waiting for Azure's caches and log ingestion without knowing how long it would take.

## What I would do differently

-   Turn on diagnostic logging **on day one**, before any secrets are read, so the whole history is audited.
-   Script the group moves and tests from the start, including a "who am I" check before each test.
-   Plan for propagation delays: make a change, then do other work, then test.

## Skills I can now show

Azure Key Vault (RBAC model, soft delete, purge protection) · Azure RBAC role assignments and scopes · Entra ID groups and
service principals · certificate-based app authentication · `DefaultAzureCredential` and the Azure SDK for Python ·
diagnostic settings and KQL in Log Analytics · least-privilege testing · evidence masking.

## Next steps

1.  Run the script as the application or with a **managed identity**, so no person's login is involved.
2.  Alert on unusual `SecretGet` activity; add secret expiry dates and rotation.
3.  Restrict network access to the vault (private endpoint / firewall).
4.  **Next phase: HashiCorp Vault** for the on-premises side of the lab — see [HASHICORP_VAULT_NEXT_PHASE.md](./HASHICORP_VAULT_NEXT_PHASE.md).
