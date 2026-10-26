"""
Certificate generation and management for HVMC digital signatures: document-signing
and time-stamping certificates, renewal (re-key), revocation with reason codes,
CRL publication, certificate status and expiry monitoring.

Horizon Valley Medical Center (HVMC) - Cryptography 1: Implement Digital Signatures
Author: Sabitha S Karanavar

Works on a copy of the two-tier HVMC PKI built for the Public Key Cryptography
rubric (../public_key_crypto/pki), so that rubric's published evidence is not changed.
"""
import datetime as dt
import json
import os
import shutil
import sys
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "public_key_crypto"))
import key_management as km  # noqa: E402
import pki  # noqa: E402

RUBRIC4_PKI = os.path.join(HERE, "..", "public_key_crypto", "pki")

# id-kp-documentSigning (RFC 9336) - the EKU for signing documents rather than code, mail or TLS
DOCUMENT_SIGNING = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.36")
# HVMC certificate policy OID. 2.25.<UUID as an integer> is the ITU-T arc that lets anyone mint a
# globally unique OID without registration (ITU-T X.667). Relying parties require this policy.
HVMC_DOC_POLICY = x509.ObjectIdentifier("2.25." + str(uuid.uuid5(uuid.NAMESPACE_DNS, "doc-signing-policy-v1.hvmc.example").int))
CPS_URL = "http://pki.hvmc.example/cps/hvmc-certificate-practice-statement-v1.pdf"

# key types and certificate profiles added to the rubric 4 policy
km.POLICY.setdefault("document-signing", {"bits": 3072, "days": 730, "storage": "encrypted, clinician device (smart card in production)"})
km.POLICY.setdefault("timestamping", {"bits": 3072, "days": 1825, "storage": "encrypted, TSA host (HSM in production)"})
PROFILE_DAYS = {"document-signing": 730, "timestamping": 1825}


def copy_rubric4_pki(dest):
    """Start every run from the rubric 4 PKI (keys, certificates, register, inventory)."""
    if os.path.exists(dest):
        shutil.rmtree(dest)
    shutil.copytree(RUBRIC4_PKI, dest)
    os.chmod(os.path.join(dest, "private"), 0o700)


def load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def cn(cert_or_name):
    name = cert_or_name.subject if hasattr(cert_or_name, "subject") else cert_or_name
    return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def ou(cert):
    attrs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    return attrs[0].value if attrs else ""


class ManagedCA(pki.IssuingCA):
    """The rubric 4 issuing CA plus lifecycle operations."""

    def __init__(self, key, cert, root, now):
        super().__init__(key, cert, os.path.join(root, "ca_register.json"))
        self.root = root
        self.state_path = os.path.join(root, "ca_state.json")
        self.state = {"crl_number": 1}            # rubric 4 published CRL number 1
        if os.path.exists(self.state_path):
            with open(self.state_path) as f:
                self.state = json.load(f)
        self.certs = {}                           # serial (hex) -> certificate

    def _record(self, cert, profile, requested_by, approved_by):
        rec = {
            "serial": format(cert.serial_number, "x"), "subject": cert.subject.rfc4514_string(),
            "profile": profile, "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(), "requested_by": requested_by,
            "approved_by": approved_by, "status": "valid", "revoked_at": None, "reason": None,
            "invalidity_date": None, "replaced_by": None,
        }
        self.register.append(rec)
        self.certs[rec["serial"]] = cert
        self._save()
        return rec

    def issue_signing(self, csr, profile, now, requested_by, approved_by, not_after_cap=None):
        """Document-signing or time-stamping certificate. The registration authority is the
        signer's department lead (the Entra ID manager set in the IAM project)."""
        sans = self.check_policy(csr, profile if profile != "document-signing" else "client-auth")
        not_after = now + dt.timedelta(days=PROFILE_DAYS[profile])
        if not_after_cap and not_after_cap < not_after:
            not_after = not_after_cap                    # e.g. a contractor's end date
        if profile == "document-signing":
            ku = pki._ku(digital_signature=True, content_commitment=True)    # contentCommitment = nonRepudiation
            eku = x509.ExtendedKeyUsage([DOCUMENT_SIGNING, ExtendedKeyUsageOID.EMAIL_PROTECTION])
            eku_critical = False
        else:
            ku = pki._ku(digital_signature=True, content_commitment=True)
            eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING])
            eku_critical = True                          # RFC 3161 section 2.3: must be critical and the only EKU
        policies = x509.CertificatePolicies([x509.PolicyInformation(HVMC_DOC_POLICY, [CPS_URL])])
        cert = (x509.CertificateBuilder()
                .subject_name(csr.subject).issuer_name(self.cert.subject)
                .public_key(csr.public_key()).serial_number(pki.serial())
                .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(not_after)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(ku, critical=True)
                .add_extension(eku, critical=eku_critical)
                .add_extension(sans, critical=False)
                .add_extension(policies, critical=False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
                .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                    [x509.UniformResourceIdentifier(pki.CRL_URL)], None, None, None)]), critical=False)
                .sign(self.key, hashes.SHA256()))
        self._record(cert, profile, requested_by, approved_by)
        return cert

    def issue_tls(self, csr, now, requested_by, approved_by):
        cert = super().issue(csr, "tls-server", now, requested_by)
        self.register[-1].update({"approved_by": approved_by, "invalidity_date": None, "replaced_by": None})
        self.certs[self.register[-1]["serial"]] = cert
        self._save()
        return cert

    def find(self, cert):
        serial = format(cert.serial_number, "x")
        return next(r for r in self.register if r["serial"] == serial)

    def revoke(self, cert, reason, at, note, invalidity=None, replaced_by=None):
        """reason is an x509.ReasonFlags value. For keyCompromise the invalidity date records
        when the key is believed to have been compromised (may be before the revocation)."""
        rec = self.find(cert)
        if rec["status"] == "revoked":
            raise ValueError("already revoked")
        rec.update({"status": "revoked", "revoked_at": at.isoformat(), "reason": reason.value,
                    "invalidity_date": invalidity.isoformat() if invalidity else None, "note": note,
                    "replaced_by": replaced_by})
        self._save()
        return rec

    def crl(self, now, days=7):
        """CRL with a reason code and, for key compromise, an invalidity date for each entry."""
        self.state["crl_number"] += 1
        with open(self.state_path, "w") as f:
            json.dump(self.state, f)
        b = (x509.CertificateRevocationListBuilder().issuer_name(self.cert.subject)
             .last_update(now).next_update(now + dt.timedelta(days=days))
             .add_extension(x509.CRLNumber(self.state["crl_number"]), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False))
        for r in self.register:
            if r["status"] == "revoked" and dt.datetime.fromisoformat(r["revoked_at"]) <= now:
                entry = (x509.RevokedCertificateBuilder().serial_number(int(r["serial"], 16))
                         .revocation_date(dt.datetime.fromisoformat(r["revoked_at"]))
                         .add_extension(x509.CRLReason(x509.ReasonFlags(r["reason"])), critical=False))
                if r["invalidity_date"]:
                    entry = entry.add_extension(x509.InvalidityDate(
                        dt.datetime.fromisoformat(r["invalidity_date"]).replace(tzinfo=None)), critical=False)
                b = b.add_revoked_certificate(entry.build())
        return b.sign(self.key, hashes.SHA256())

    def expiry_report(self, now, window_days=60):
        """Certificates that are valid now but expire inside the renewal window."""
        out = []
        for r in self.register:
            left = (dt.datetime.fromisoformat(r["not_after"]) - now).days
            if r["status"] == "valid" and 0 <= left <= window_days:
                out.append((r["subject"], r["profile"], r["not_after"][:10], left))
        return out


def status(crl, cert):
    """Look a certificate up in a CRL: ('good', None) or ('revoked', details)."""
    entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    if entry is None:
        return "good", None
    reason = entry.extensions.get_extension_for_class(x509.CRLReason).value.reason
    try:
        inv = entry.extensions.get_extension_for_class(x509.InvalidityDate).value.invalidity_date_utc
    except x509.ExtensionNotFound:
        inv = None
    return "revoked", {"revoked_at": entry.revocation_date_utc, "reason": reason, "invalidity_date": inv}


def pem(obj):
    return obj.public_bytes(serialization.Encoding.PEM)
