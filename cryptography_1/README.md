# Cryptography — Protecting HVMC Data

Six cryptography rubrics. Each one has Python code written from first principles, a test-and-demo script with saved
results, and a report (PDF) that explains how it protects hospital data.

| Rubric | Code | Report |
|---|---|---|
| Cryptographic fundamentals | [crypto_fundamentals](./crypto_fundamentals/) — SHA-256, Diffie-Hellman | [HVMC_Cryptographic_Fundamentals.pdf](./HVMC_Cryptographic_Fundamentals.pdf) |
| Hash functions and integrity | [hash_integrity](./hash_integrity/) — file integrity, HMAC, password hashing | [HVMC_Hash_Functions_and_Integrity.pdf](./HVMC_Hash_Functions_and_Integrity.pdf) |
| Symmetric cryptography | [symmetric_crypto](./symmetric_crypto/) — AES, ChaCha20, ECB vs CBC demo, key management | [HVMC_Symmetric_Cryptography.pdf](./HVMC_Symmetric_Cryptography.pdf) |
| Public-key cryptography | [public_key_crypto](./public_key_crypto/) — RSA, a simple PKI (root and issuing CA, CRLs), key exchange | [HVMC_Public_Key_Cryptography.pdf](./HVMC_Public_Key_Cryptography.pdf) |
| Digital signatures | [digital_signatures](./digital_signatures/) — RSA-PSS signing system, certificate management, forged-document detection | [HVMC_Digital_Signatures.pdf](./HVMC_Digital_Signatures.pdf) |
| Cryptographic protocols | [crypto_protocols](./crypto_protocols/) — TLS analysis of an Entra ID sign-in (Wireshark), live TLS tests, SSH plan | [HVMC_Cryptographic_Protocols.pdf](./crypto_protocols/HVMC_Cryptographic_Protocols.pdf) |

Also: [symmetric_on_dc](./symmetric_on_dc/) — a home-lab kit to apply AES (Kerberos, SMB encryption) on the Samba domain
controller (prepared, see its README). Private keys are never committed (`.gitignore`).
