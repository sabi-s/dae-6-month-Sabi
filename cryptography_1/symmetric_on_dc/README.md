# Symmetric Encryption on the Domain Controller (add-on lab)

Horizon Valley Medical Center (HVMC) · Cryptography 1 · Author: Sabitha S Karanavar

This folder takes the symmetric-encryption ideas from [`../symmetric_crypto`](../symmetric_crypto) (AES, key management,
envelope encryption) off the laptop and applies them to the HVMC home lab: the Samba AD domain controller `hvmc-dc01`
(192.168.56.10) and the domain-joined workstation `hvmc-client01` (192.168.56.11). It is an add-on: the
Symmetric Cryptography report and the other cryptography documents are unchanged.

**Start here:** [`HVMC_Symmetric_on_DC_Home_Lab_Guide.pdf`](HVMC_Symmetric_on_DC_Home_Lab_Guide.pdf), a step-by-step
guide for the home lab (about 2 hours).

| Part | What changes on the DC | Evidence |
|---|---|---|
| 1. Kerberos | `kdc supported enctypes = 24` (AES-128 + AES-256): tickets use AES, RC4 is refused | `klist -e`, RC4-only sign-in refused, Kerberos capture |
| 2. File shares | `server smb encrypt = required` on the Week 5 department shares (SMB3, AES) | before/after capture, `smbstatus` encryption column, SMB 2.1 refused |
| 3. Department keys | one AES-256 key per department, readable only by that AD group; envelope encryption with your own AES code; key rotation | tests T1–T7 as the real domain users |

## Contents
- `dc/`: scripts run on `hvmc-dc01` (`00_precheck` · `01_kerberos_aes` · `02_smb_encrypt` · `03_capture` · `04_dept_keys` · `05_analyze` · `06_collect`)
- `client/`: scripts run on `hvmc-client01` (`c0_precheck` · `c1_kerberos` · `c2_smb` · `c3_collect`)
- `tools/`: `smbconf_edit.py` (marked, reversible smb.conf edits), `dept_vault.py` (department key vault built on
  `../symmetric_crypto/aes.py` and `key_management.py`), `analyze.py` (tshark summary), `samples/` (fictional notes)

## Safety
- No passwords, keys or tenant data are stored in this folder. Passwords are typed at prompts and never logged.
- Every smb.conf change is backed up first, checked with `testparm`, rolled back automatically if Samba does not start,
  and can be undone with `./01_kerberos_aes.sh undo` and `./02_smb_encrypt.sh undo`.
- All patient and payroll data used in the tests is fictional and marked `HVMC-DEMO-NOTE`.
- Lab simplification: root can read the department keys. In production the keys live in an HSM or Azure Key Vault.
