# Cryptography — Protecting HVMC Data

Six cryptography rubrics. Each one has Python code written from first principles, a test-and-demo script with saved
results, and a report (PDF) that explains how it protects hospital data.

| Rubric | Code | Report |
|---|---|---|
| Cryptographic fundamentals | [crypto_fundamentals](./crypto_fundamentals/) — SHA-256, Diffie-Hellman | [01_HVMC_Cryptographic_Fundamentals.pdf](./01_HVMC_Cryptographic_Fundamentals.pdf) |
| Symmetric cryptography | [symmetric_crypto](./symmetric_crypto/) — AES, ChaCha20, ECB vs CBC demo, key management | [02_HVMC_Symmetric_Cryptography.pdf](./02_HVMC_Symmetric_Cryptography.pdf) |
| Hash functions and integrity | [hash_integrity](./hash_integrity/) — file integrity, HMAC, password hashing | [03_HVMC_Hash_Functions_and_Integrity.pdf](./03_HVMC_Hash_Functions_and_Integrity.pdf) |
| Public-key cryptography | [public_key_crypto](./public_key_crypto/) — RSA, a simple PKI (root and issuing CA, CRLs), key exchange | [04_HVMC_Public_Key_Cryptography.pdf](./04_HVMC_Public_Key_Cryptography.pdf) |
| Digital signatures | [digital_signatures](./digital_signatures/) — RSA-PSS signing system, certificate management, forged-document detection | [05_HVMC_Digital_Signatures.pdf](./05_HVMC_Digital_Signatures.pdf) |
| Cryptographic protocols | [crypto_protocols](./crypto_protocols/) — TLS analysis of an Entra ID sign-in (Wireshark), live TLS tests, SSH plan | [06_HVMC_Cryptographic_Protocols.pdf](./crypto_protocols/06_HVMC_Cryptographic_Protocols.pdf) |

Also: [symmetric_on_dc](./symmetric_on_dc/) — a home-lab kit to apply AES (Kerberos, SMB encryption) on the Samba domain
controller (prepared, see its README). Private keys are never committed (`.gitignore`).
