"""
The HVMC clinical document signing system: signers, a time-stamping authority (TSA),
a trust store, and a step-by-step signature verification process.

Horizon Valley Medical Center (HVMC) - Cryptography 1: Implement Digital Signatures
Author: Sabitha S Karanavar

A signature envelope is a detached JSON signature, modelled on CMS / CAdES:
    signed_attributes: document id and type, SHA-256 of the document, signer certificate
                       hash, claimed signing time, commitment type
    signature:         RSA-PSS-SHA256 (from scratch) over the canonical signed attributes
    certificates:      signer certificate + issuing CA
    timestamp:         token from the HVMC TSA over SHA-256(signature) - proves WHEN it was signed
Signing and verifying use the from-scratch PSS code; the library re-checks each signature.
"""
import base64
import datetime as dt
import hashlib
import json
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtendedKeyUsageOID

import cert_management as cm
import pki
import signatures as sig

ALG = "RSASSA-PSS-SHA256"

# who may sign what (relying-party policy): document type -> departments (certificate OU)
DOCUMENT_POLICY = {
    "discharge-summary": {"Doctors"},
    "nursing-note": {"Nursing"},
    "medication-verification": {"Pharmacy", "Doctors"},
    "change-record": {"IT", "Information Security"},
}


def b64(b):
    return base64.b64encode(b).decode()


def unb64(s):
    return base64.b64decode(s)


def canonical(obj):
    """One exact byte form for the signed attributes (sorted keys, no spaces), so signer and
    verifier hash exactly the same bytes - the job DER does in CMS."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def lib_pss_ok(cert, data, signature):
    try:
        cert.public_key().verify(signature, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                                 hashes.SHA256())
        return True
    except Exception:
        return False


# ---------------------------------------------------------------- trust store
class TrustStore:
    """What a relying party trusts. Anchors are pinned by SHA-256 fingerprint, not by name,
    so a look-alike root with the same name is not trusted."""

    def __init__(self, anchors, required_policy, accepted_algorithms=(ALG,)):
        self.anchors = list(anchors)
        self.pins = {a.fingerprint(hashes.SHA256()).hex() for a in self.anchors}
        self.required_policy = required_policy
        self.accepted_algorithms = set(accepted_algorithms)

    def to_json(self):
        return {
            "anchors": [{"subject": a.subject.rfc4514_string(), "sha256": a.fingerprint(hashes.SHA256()).hex(),
                         "not_after": str(a.not_valid_after_utc.date())} for a in self.anchors],
            "required_certificate_policy": self.required_policy.dotted_string,
            "accepted_algorithms": sorted(self.accepted_algorithms),
            "document_policy": {k: sorted(v) for k, v in DOCUMENT_POLICY.items()},
        }


# ---------------------------------------------------------------- time-stamping authority
class TimestampAuthority:
    """Simplified RFC 3161: the TSA signs (hash of the data, its own clock time, a serial, a nonce).
    Here the clock is passed in so the demo can move through a timeline."""

    def __init__(self, key, cert, chain):
        self.key, self.cert, self.chain = sig.scratch_private(key), cert, chain
        self.serial = 0

    def stamp(self, data_hash, at):
        self.serial += 1
        info = {"version": 1, "policy": cm.HVMC_DOC_POLICY.dotted_string, "hash_alg": "sha256",
                "message_imprint": data_hash.hex(), "gen_time": at.isoformat(), "serial": self.serial,
                "nonce": secrets.token_hex(8), "tsa": cm.cn(self.cert)}
        return {"tst_info": info, "signature": b64(sig.pss_sign(self.key, canonical(info))),
                "tsa_certificate": b64(der(self.cert))}


# ---------------------------------------------------------------- signer
class Signer:
    def __init__(self, key, cert, chain, tsa=None):
        self.key, self.cert, self.chain, self.tsa = sig.scratch_private(key), cert, chain, tsa

    def sign(self, document, doc_id, doc_type, at, commitment="proof-of-approval", timestamp=True):
        attrs = {
            "doc_id": doc_id, "doc_type": doc_type, "doc_sha256": hashlib.sha256(document).hexdigest(),
            "signer_cert_sha256": self.cert.fingerprint(hashes.SHA256()).hex(),
            "claimed_signing_time": at.isoformat(), "commitment_type": commitment,
            "content_type": "application/json",
        }
        signature = sig.pss_sign(self.key, canonical(attrs))
        env = {"format": "HVMC-detached-signature-v1", "algorithm": ALG, "signed_attributes": attrs,
               "signature": b64(signature), "certificates": [b64(der(c)) for c in [self.cert] + self.chain]}
        if timestamp and self.tsa:
            env["timestamp"] = self.tsa.stamp(hashlib.sha256(signature).digest(), at)
        return env


# ---------------------------------------------------------------- verifier
class Result:
    def __init__(self):
        self.steps, self.status, self.signer, self.signing_time = [], None, None, None

    def add(self, step, ok, detail=""):
        self.steps.append((step, ok, detail))
        return ok

    def finish(self, status, why):
        self.status, self.reason = status, why
        return self


class Verifier:
    """Verification process. Returns VALID, INVALID (a check failed) or INDETERMINATE
    (nothing is wrong, but the evidence is not enough to decide - e.g. no trusted time)."""

    def __init__(self, trust, intermediates, crl_provider):
        self.trust, self.intermediates, self.crl_provider = trust, intermediates, crl_provider

    def _chain_ok(self, cert, at, r, label):
        ok, checks = pki.validate_path(cert, self.intermediates, self.trust.anchors, at)
        failed = [c[0] for c in checks if not c[1]]
        root = checks[0][2] if checks else ""
        pinned = any(der_root.subject.rfc4514_string() == root and der_root.fingerprint(hashes.SHA256()).hex()
                     in self.trust.pins for der_root in self.trust.anchors)
        return r.add(f"{label}: certificate path to a pinned HVMC trust anchor (at {at:%Y-%m-%d %H:%M} UTC)",
                     ok and pinned, f"{len(checks)} checks" + (f"; failed: {', '.join(failed)}" if failed else ""))

    def _revocation(self, cert, at_time, now, r, label):
        """Revocation only invalidates signatures made after the cut-off: the revocation date,
        or for key compromise the (earlier) invalidity date."""
        crl = self.crl_provider(now)
        issuer = next(c for c in self.intermediates if c.subject == cert.issuer)
        if not r.add(f"{label}: CRL #{crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number} "
                     f"signed by the issuing CA and current", crl.is_signature_valid(issuer.public_key())
                     and crl.next_update_utc >= now, f"next update {crl.next_update_utc:%Y-%m-%d}"):
            return False
        state, info = cm.status(crl, cert)
        if state == "good":
            return r.add(f"{label}: revocation status", True, "not revoked")
        cutoff = info["invalidity_date"] or info["revoked_at"]
        ok = at_time < cutoff
        return r.add(f"{label}: revocation status", ok,
                     f"revoked {info['revoked_at']:%Y-%m-%d %H:%M} ({info['reason'].value})"
                     + (f", key invalid from {info['invalidity_date']:%Y-%m-%d %H:%M}" if info["invalidity_date"] else "")
                     + (" - signed BEFORE the cut-off, so the signature stays valid" if ok else " - signed AFTER the cut-off"))

    def verify(self, document, env, now):
        r = Result()
        attrs = env["signed_attributes"]
        if not r.add("algorithm accepted by the trust policy", env["algorithm"] in self.trust.accepted_algorithms,
                     env["algorithm"]):
            return r.finish("INVALID", "algorithm not accepted")
        # 1. integrity of the document
        digest = hashlib.sha256(document).hexdigest()
        if not r.add("document SHA-256 matches the signed attribute", digest == attrs["doc_sha256"], digest[:24] + "…"):
            return r.finish("INVALID", "document was modified after signing")
        # 2. signer certificate is the one the signer committed to
        cert = x509.load_der_x509_certificate(unb64(env["certificates"][0]))
        r.signer = f"{cm.cn(cert)} ({cm.ou(cert)})"
        if not r.add("signer certificate matches the signed certificate hash",
                     cert.fingerprint(hashes.SHA256()).hex() == attrs["signer_cert_sha256"], r.signer):
            return r.finish("INVALID", "signer certificate was substituted")
        # 3. the signature itself
        signature = unb64(env["signature"])
        mine = sig.pss_verify(sig.scratch_public(cert.public_key()), canonical(attrs), signature)
        lib = lib_pss_ok(cert, canonical(attrs), signature)
        if not r.add("RSA-PSS signature over the signed attributes", mine and lib,
                     f"from-scratch={mine}, library={lib}"):
            return r.finish("INVALID", "signature does not verify")
        # 4. trusted signing time from the TSA
        signing_time = None
        ts = env.get("timestamp")
        if ts:
            tsa_cert = x509.load_der_x509_certificate(unb64(ts["tsa_certificate"]))
            info = ts["tst_info"]
            t = dt.datetime.fromisoformat(info["gen_time"])
            ok = (info["message_imprint"] == hashlib.sha256(signature).hexdigest()
                  and sig.pss_verify(sig.scratch_public(tsa_cert.public_key()), canonical(info), unb64(ts["signature"]))
                  and ExtendedKeyUsageOID.TIME_STAMPING in tsa_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
            if not r.add("timestamp token: imprint, TSA signature, timeStamping EKU", ok, f"{cm.cn(tsa_cert)}, "
                         f"gen_time {t:%Y-%m-%d %H:%M} UTC"):
                return r.finish("INVALID", "timestamp token invalid")
            if not (self._chain_ok(tsa_cert, t, r, "TSA") and self._revocation(tsa_cert, t, now, r, "TSA")):
                return r.finish("INVALID", "TSA not trusted")
            signing_time = t
        else:
            r.add("timestamp token", True, "none - only the signer's own claimed time, which cannot be trusted")
        r.signing_time = signing_time
        when = signing_time or now     # without a trusted time the certificate must be valid now
        # 5. the signer's certificate at signing time
        if not self._chain_ok(cert, when, r, "signer"):
            if signing_time is None and cert.not_valid_after_utc < now:
                return r.finish("INDETERMINATE", "signer certificate has expired and there is no trusted "
                                "timestamp proving the signature was made while it was valid")
            return r.finish("INVALID", "signer certificate not trusted at signing time")
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        pols = [p.policy_identifier for p in cert.extensions.get_extension_for_class(x509.CertificatePolicies).value]
        if not r.add("key usage digitalSignature + nonRepudiation, EKU documentSigning",
                     ku.digital_signature and ku.content_commitment and cm.DOCUMENT_SIGNING in eku):
            return r.finish("INVALID", "certificate not issued for document signing")
        if not r.add("certificate policy = HVMC Clinical Document Signing Policy",
                     self.trust.required_policy in pols, self.trust.required_policy.dotted_string[:22] + "…"):
            return r.finish("INVALID", "wrong certificate policy")
        # 6. revocation, judged at the signing time
        if not self._revocation(cert, when, now, r, "signer"):
            return r.finish("INVALID", "signer certificate was revoked before the signature was made")
        # 7. authorisation: is this department allowed to sign this document type?
        allowed = DOCUMENT_POLICY.get(attrs["doc_type"], set())
        if not r.add(f"signer's department is authorised for '{attrs['doc_type']}'", cm.ou(cert) in allowed,
                     f"{cm.ou(cert)}; allowed: {', '.join(sorted(allowed))}"):
            return r.finish("INVALID", "signer not authorised for this document type")
        return r.finish("VALID", "all checks passed" + ("" if signing_time else " (no timestamp: valid only while "
                                                           "the certificate is valid and not revoked)"))
