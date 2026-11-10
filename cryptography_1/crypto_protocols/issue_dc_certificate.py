"""
Issue the TLS certificate for the HVMC domain controller (hvmc-dc01.hvmc.lan) from the
HVMC PKI, for the Configure Cryptographic Protocols rubric. The same certificate is used
by nginx (HTTPS) and by Samba (LDAPS).

Horizon Valley Medical Center (HVMC) - Cryptography 1: Configure Cryptographic Protocols
Author: Sabitha S Karanavar

Works on a copy of the rubric 4 PKI (../public_key_crypto/pki). The issuance policy is
extended to the internal Active Directory domain .hvmc.lan, and the key pair comes from
the from-scratch RSA generator.
Writes pki/ (copy, private keys git-ignored) and home_kit_build/certs/ (git-ignored).
"""
import datetime as dt
import ipaddress
import os
import shutil
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "public_key_crypto"))
import key_management as km  # noqa: E402
import pki  # noqa: E402

PKI_DIR = os.path.join(HERE, "pki")
CERTS_OUT = os.path.join(HERE, "home_kit_build", "certs")
DC_NAMES = ["hvmc-dc01.hvmc.lan", "portal.hvmc.lan"]
DC_IP = "192.168.56.10"

# the internal AD domain is added to the names the CA may certify (no wildcards, as before)
pki.ALLOWED_DNS_SUFFIX = (".hvmc.example", ".hvmc.lan")


def main():
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    if os.path.exists(PKI_DIR):
        shutil.rmtree(PKI_DIR)
    shutil.copytree(os.path.join(HERE, "..", "public_key_crypto", "pki"), PKI_DIR)
    store = km.KeyStore(PKI_DIR, km.get_passphrase(os.path.join(PKI_DIR, "private")))
    issuing_cert = x509.load_pem_x509_certificate(open(os.path.join(PKI_DIR, "certs", "hvmc-issuing-ca-1.crt.pem"), "rb").read())
    root_cert = x509.load_pem_x509_certificate(open(os.path.join(PKI_DIR, "certs", "hvmc-root-ca-r1.crt.pem"), "rb").read())
    ca = pki.IssuingCA(store.private("hvmc-issuing-ca-1"), issuing_cert, os.path.join(PKI_DIR, "ca_register.json"))

    key = store.generate("hvmc-dc01-tls-2026", "tls-server", "IT Infrastructure (domain controller hvmc-dc01)", now)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(pki.name("hvmc-dc01.hvmc.lan", "IT Infrastructure"))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in DC_NAMES]
                                                      + [x509.IPAddress(ipaddress.ip_address(DC_IP))]), critical=False)
           .sign(key, hashes.SHA256()))
    cert = ca.issue(csr, "tls-server", now, "Sabitha S Karanavar (rubric 6 lab, change HVMC-PKI-CHG-405)")

    os.makedirs(CERTS_OUT, exist_ok=True)
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM)
    files = {
        "hvmc-root-ca-r1.crt.pem": pem(root_cert),
        "hvmc-issuing-ca-1.crt.pem": pem(issuing_cert),
        "hvmc-dc01.crt.pem": pem(cert),
        "hvmc-dc01.fullchain.pem": pem(cert) + pem(issuing_cert),
        "hvmc-ca-bundle.pem": pem(issuing_cert) + pem(root_cert),
        # unencrypted: nginx and Samba read it at start-up; it is protected by file permissions (0600, root)
        "hvmc-dc01.key.pem": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                               serialization.NoEncryption()),
    }
    for name, data in files.items():
        path = os.path.join(CERTS_OUT, name)
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, 0o600 if name.endswith(".key.pem") else 0o644)
    with open(os.path.join(PKI_DIR, "certs", "hvmc-dc01.crt.pem"), "wb") as f:
        f.write(pem(cert))
    with open(os.path.join(PKI_DIR, "csr", "hvmc-dc01.csr.pem"), "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    ok, checks = pki.validate_path(cert, [issuing_cert], [root_cert], now, x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                                   "hvmc-dc01.hvmc.lan")
    print(f"issued {cert.subject.rfc4514_string()}  serial {cert.serial_number:x}")
    print(f"  SAN: {', '.join(DC_NAMES)}, IP {DC_IP}; valid {cert.not_valid_before_utc:%Y-%m-%d} to {cert.not_valid_after_utc:%Y-%m-%d}")
    print(f"  path validation: {'VALID' if ok else 'INVALID'} ({len(checks)} checks)")
    print(f"  SHA-256 fingerprint: {cert.fingerprint(hashes.SHA256()).hex()}")
    print(f"  wrote {len(files)} files to {CERTS_OUT}")
    return ok


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
