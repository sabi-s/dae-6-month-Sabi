"""
A simple two-tier PKI for HVMC: an offline root CA, an issuing CA, certificate
signing requests (CSRs) checked against an issuance policy, a certificate
register, a CRL, and certificate path validation.

Horizon Valley Medical Center (HVMC) - Cryptography 1: Utilize Public Key Cryptography
Author: Sabitha S Karanavar

    HVMC Root CA R1 (RSA-4096, 10 years, offline)
      └── HVMC Issuing CA 1 (RSA-3072, 5 years, pathLen 0)
            ├── portal.hvmc.example   (TLS server, RSA-2048, 397 days)
            └── Sarah Chen            (client authentication, RSA-2048, 365 days)

Certificates are built with the `cryptography` package; every key comes from the
from-scratch generator (rsa.py) and every signature is re-checked by the
from-scratch PKCS #1 v1.5 verifier.
"""
import datetime as dt
import json
import os
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import rsa

UTC = dt.timezone.utc
ORG = "Horizon Valley Medical Center"
ALLOWED_DNS_SUFFIX = ".hvmc.example"
ALLOWED_EMAIL_DOMAIN = "@hvmc.example"
CRL_URL = "http://pki.hvmc.example/crl/hvmc-issuing-ca-1.crl"
ROOT_CRL_URL = "http://pki.hvmc.example/crl/hvmc-root-ca-r1.crl"

PROFILES = {
    "tls-server":  {"days": 397, "eku": [ExtendedKeyUsageOID.SERVER_AUTH],
                    "ku": dict(digital_signature=True, key_encipherment=True)},
    "client-auth": {"days": 365, "eku": [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.EMAIL_PROTECTION],
                    "ku": dict(digital_signature=True, key_encipherment=True)},
}


class PolicyViolation(Exception):
    pass


def name(cn, ou=None, email=None):
    attrs = [x509.NameAttribute(NameOID.COUNTRY_NAME, "US"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG)]
    if ou:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    if email:
        attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    return x509.Name(attrs)


def _ku(**on):
    base = dict(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False)
    base.update(on)
    return x509.KeyUsage(**base)


def serial():
    """159-bit random serial (CA/Browser Forum baseline: at least 64 bits of CSPRNG output)."""
    return secrets.randbits(159) | 1


def pem(cert_or_crl):
    return cert_or_crl.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------- CA setup
def create_root(key, now):
    subject = name("HVMC Root CA R1", "Information Security")
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    return (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(serial())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(_ku(key_cert_sign=True, crl_sign=True), critical=True)
            .add_extension(ski, critical=False)
            .sign(key, hashes.SHA384()))


def make_csr(key, cn, ou=None, dns=(), email=None):
    """The requester proves it holds the private key by signing the CSR with it."""
    b = x509.CertificateSigningRequestBuilder().subject_name(name(cn, ou, email))
    sans = [x509.DNSName(d) for d in dns] + ([x509.RFC822Name(email)] if email else [])
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return b.sign(key, hashes.SHA256())


def create_issuing_ca(root_key, root_cert, issuing_key, now):
    csr = make_csr(issuing_key, "HVMC Issuing CA 1", "Information Security")
    if not csr.is_signature_valid:
        raise PolicyViolation("CSR signature invalid")
    cert = (x509.CertificateBuilder()
            .subject_name(csr.subject).issuer_name(root_cert.subject)
            .public_key(csr.public_key()).serial_number(serial())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1825))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_ku(key_cert_sign=True, crl_sign=True), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(issuing_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
            .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                [x509.UniformResourceIdentifier(ROOT_CRL_URL)], None, None, None)]), critical=False)
            .sign(root_key, hashes.SHA384()))
    return csr, cert


class IssuingCA:
    """Issues end-entity certificates from CSRs, keeps a register (like OpenSSL's index.txt)
    and publishes CRLs."""

    def __init__(self, key, cert, register_path):
        self.key, self.cert, self.register_path = key, cert, register_path
        self.register = []
        if os.path.exists(register_path):
            with open(register_path) as f:
                self.register = json.load(f)

    def _save(self):
        with open(self.register_path, "w") as f:
            json.dump(self.register, f, indent=2)

    def check_policy(self, csr, profile):
        """Registration-authority checks before anything is signed."""
        if not csr.is_signature_valid:
            raise PolicyViolation("CSR signature does not verify (requester does not hold the key)")
        bits = csr.public_key().key_size
        if bits < 2048:
            raise PolicyViolation(f"RSA-{bits} is below the HVMC minimum of 2048 bits")
        try:
            sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            raise PolicyViolation("CSR has no subjectAltName")
        dns, emails = sans.get_values_for_type(x509.DNSName), sans.get_values_for_type(x509.RFC822Name)
        for d in dns:
            if not d.endswith(ALLOWED_DNS_SUFFIX) or "*" in d:
                raise PolicyViolation(f"DNS name {d} is outside {ALLOWED_DNS_SUFFIX} (or a wildcard)")
        for e in emails:
            if not e.endswith(ALLOWED_EMAIL_DOMAIN):
                raise PolicyViolation(f"email {e} is outside {ALLOWED_EMAIL_DOMAIN}")
        if profile == "tls-server" and not dns:
            raise PolicyViolation("server certificate needs at least one DNS name")
        if profile == "client-auth" and not emails:
            raise PolicyViolation("client certificate needs an email address")
        return sans

    def issue(self, csr, profile, now, requested_by):
        sans = self.check_policy(csr, profile)
        prof = PROFILES[profile]
        cert = (x509.CertificateBuilder()
                .subject_name(csr.subject).issuer_name(self.cert.subject)
                .public_key(csr.public_key()).serial_number(serial())
                .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=prof["days"]))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(_ku(**prof["ku"]), critical=True)
                .add_extension(x509.ExtendedKeyUsage(prof["eku"]), critical=False)
                .add_extension(sans, critical=False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
                .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                    [x509.UniformResourceIdentifier(CRL_URL)], None, None, None)]), critical=False)
                .sign(self.key, hashes.SHA256()))
        self.register.append({
            "serial": format(cert.serial_number, "x"), "subject": cert.subject.rfc4514_string(),
            "profile": profile, "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(), "requested_by": requested_by,
            "status": "valid", "revoked_at": None, "reason": None,
        })
        self._save()
        return cert

    def crl(self, now, days=7):
        b = (x509.CertificateRevocationListBuilder().issuer_name(self.cert.subject)
             .last_update(now).next_update(now + dt.timedelta(days=days))
             .add_extension(x509.CRLNumber(len([r for r in self.register if r["status"] == "revoked"]) + 1), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False))
        for r in self.register:
            if r["status"] == "revoked":
                b = b.add_revoked_certificate(x509.RevokedCertificateBuilder()
                                              .serial_number(int(r["serial"], 16))
                                              .revocation_date(dt.datetime.fromisoformat(r["revoked_at"])).build())
        return b.sign(self.key, hashes.SHA256())


# ---------------------------------------------------------------- path validation
def _sig_ok(issuer, cert):
    """Check the signature twice: with the library, and with the from-scratch verifier."""
    pub = issuer.public_key()
    try:
        pub.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        lib = True
    except Exception:
        lib = False
    mine = rsa.pkcs1v15_verify(rsa.from_library_public(pub), cert.tbs_certificate_bytes, cert.signature,
                               cert.signature_hash_algorithm.name)
    return lib, mine


def validate_path(leaf, intermediates, roots, at, purpose=None, hostname=None, crls=()):
    """Simplified RFC 5280 section 6 path validation. Returns (ok, list of (check, passed, detail))."""
    checks = []

    def add(label, ok, detail=""):
        checks.append((label, bool(ok), detail))
        return ok

    # build the path leaf -> ... -> trusted root by matching issuer to subject
    path, cur = [leaf], leaf
    pool = list(intermediates) + list(roots)
    while cur.issuer != cur.subject:
        nxt = next((c for c in pool if c.subject == cur.issuer), None)
        if nxt is None:
            add("path building", False, f"no issuer found for {cur.subject.rfc4514_string()}")
            return False, checks
        path.append(nxt)
        cur = nxt
    root = path[-1]
    add("path ends at a trusted root", any(root == r for r in roots), root.subject.rfc4514_string())

    for i, cert in enumerate(path):
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        add(f"{cn}: inside validity period", cert.not_valid_before_utc <= at <= cert.not_valid_after_utc,
            f"{cert.not_valid_before_utc.date()} to {cert.not_valid_after_utc.date()}")
        issuer = path[i + 1] if i + 1 < len(path) else cert
        lib, mine = _sig_ok(issuer, cert)
        add(f"{cn}: signature (library / from-scratch)", lib and mine, f"library={lib}, from-scratch={mine}")
        if i > 0:      # every issuer must be a CA allowed to sign certificates
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            below = i - 1      # number of CA certificates below this one in the path
            add(f"{cn}: basicConstraints CA=TRUE, keyCertSign", bc.ca and ku.key_cert_sign, f"pathLen={bc.path_length}")
            add(f"{cn}: path length constraint", bc.path_length is None or below <= bc.path_length,
                f"{below} CA(s) below, limit {bc.path_length}")
        for crl in (crls if i + 1 < len(path) else ()):     # the trust anchor itself is not checked
            if crl.issuer == cert.issuer:
                add(f"{cn}: CRL signature", crl.is_signature_valid(issuer.public_key()))
                add(f"{cn}: CRL is current", crl.next_update_utc is None or at <= crl.next_update_utc,
                    f"next update {crl.next_update_utc}")
                r = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
                add(f"{cn}: not revoked", r is None, "" if r is None else f"revoked {r.revocation_date_utc}")

    if purpose:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        add(f"leaf: extendedKeyUsage includes {purpose._name}", purpose in eku)
    if hostname:
        sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        add(f"leaf: hostname {hostname} in subjectAltName", hostname in sans, ", ".join(sans))
    return all(c[1] for c in checks), checks


def library_verify_server(leaf, intermediates, root, hostname, at):
    """Second opinion from the library's RFC 5280 / CA-B Forum verifier (cryptography >= 42)."""
    from cryptography.x509.verification import PolicyBuilder, Store
    verifier = PolicyBuilder().store(Store([root])).time(at).build_server_verifier(x509.DNSName(hostname))
    return verifier.verify(leaf, list(intermediates))


def describe(cert):
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    return {
        "subject_cn": cn, "issuer_cn": cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
        "serial": format(cert.serial_number, "x")[:16] + "…", "key": f"RSA-{cert.public_key().key_size}",
        "signature": cert.signature_algorithm_oid._name, "not_after": str(cert.not_valid_after_utc.date()),
        "ca": bc.ca, "path_len": bc.path_length,
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
    }
