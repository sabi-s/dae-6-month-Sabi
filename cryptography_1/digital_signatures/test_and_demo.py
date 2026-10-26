"""
Tests and demonstrations for the HVMC digital signature system: RSA-PSS and
PKCS #1 v1.5 signatures from scratch, certificate generation and management,
the verification process and the trust model.

Horizon Valley Medical Center (HVMC) - Cryptography 1: Implement Digital Signatures
Author: Sabitha S Karanavar

Run:  python3 test_and_demo.py
Copies the rubric 4 PKI into pki/ (private keys in pki/private/, git-ignored), then
writes signed_documents/, trust_store.json, results.txt, results.json and openssl_checks.txt.
The scenario runs on a simulated timeline that starts at the run time (T0) and moves
forward; OpenSSL checks the published CRL at the simulated time with `-attime`.
"""
import base64
import copy
import datetime as dt
import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa as lib_rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

import cert_management as cm
import signatures as sig
import signing_system as ss
import key_management as km   # rubric 4 (path added by cert_management)
import pki                     # rubric 4

HERE = os.path.dirname(os.path.abspath(__file__))
PKI_DIR = os.path.join(HERE, "pki")
DOCS = os.path.join(HERE, "sample_documents")
OUT_DOCS = os.path.join(HERE, "signed_documents")
UTC = dt.timezone.utc
NOW = dt.datetime.now(UTC).replace(microsecond=0)
T0 = NOW
H = dt.timedelta(hours=1)
D = dt.timedelta(days=1)
T_PUB = T0 + 10 * D      # when the final CRL is published
RESULTS = {"tests": {}, "demos": {}}

PEOPLE = [  # key id, name, department (OU), approver (registration authority), end date cap
    ("sarah-chen-sign-2026", "Sarah Chen", "Doctors", "Denise Coleman (Information Security)", None),
    ("angela-brooks-sign-2026", "Angela Brooks", "Nursing", "Denise Coleman (Information Security)", None),
    ("david-patel-sign-2026", "David Patel", "Pharmacy", "Denise Coleman (Information Security)", None),
    ("carlos-diaz-sign-2026", "Carlos Diaz", "IT", "Kevin O'Brien (sponsor)", dt.datetime(2026, 12, 31, 23, 59, tzinfo=UTC)),
]


def doc(name):
    with open(os.path.join(DOCS, name), "rb") as f:
        return f.read()


def email(name):
    return name.lower().replace(" ", ".") + "@hvmc.example"


# ======================================================================= WORLD
def build_world(root, log=print):
    cm.copy_rubric4_pki(root)
    store = km.KeyStore(root, km.get_passphrase(os.path.join(root, "private")))
    root_cert = cm.load_cert(os.path.join(root, "certs", "hvmc-root-ca-r1.crt.pem"))
    issuing_cert = cm.load_cert(os.path.join(root, "certs", "hvmc-issuing-ca-1.crt.pem"))
    ca = cm.ManagedCA(store.private("hvmc-issuing-ca-1"), issuing_cert, root, T0)
    portal_cert = cm.load_cert(os.path.join(root, "certs", "portal.hvmc.example.crt.pem"))
    ca.certs[format(portal_cert.serial_number, "x")] = portal_cert
    W = {"store": store, "root_cert": root_cert, "issuing_cert": issuing_cert, "ca": ca, "portal_cert": portal_cert,
         "keys": {}, "certs": {}, "crl_cache": {}}
    t = time.time()
    for key_id, name, dept, approver, cap in PEOPLE:
        key = store.generate(key_id, "document-signing", f"{name} ({dept})", T0)
        csr = pki.make_csr(key, name, dept, email=email(name))
        W["keys"][name] = key
        W["certs"][name] = ca.issue_signing(csr, "document-signing", T0, name, approver, cap)
    tsa_key = store.generate("hvmc-tsa-1", "timestamping", "Information Security (TSA)", T0)
    tsa_csr = pki.make_csr(tsa_key, "HVMC Time-Stamping Authority 1", "Information Security", dns=["tsa.hvmc.example"])
    W["tsa_cert"] = ca.issue_signing(tsa_csr, "timestamping", T0, "Denise Coleman", "Denise Coleman (Information Security)")
    log(f"  5 RSA-3072 key pairs generated from scratch in {time.time() - t:.1f}s; 4 document-signing certificates "
        f"and 1 time-stamping certificate issued")
    W["tsa"] = ss.TimestampAuthority(tsa_key, W["tsa_cert"], [issuing_cert])
    W["trust"] = ss.TrustStore([root_cert], cm.HVMC_DOC_POLICY)

    def crl_provider(at):
        if at not in W["crl_cache"]:
            W["crl_cache"][at] = ca.crl(at)
        return W["crl_cache"][at]
    W["verifier"] = ss.Verifier(W["trust"], [issuing_cert], crl_provider)
    W["signers"] = {n: ss.Signer(W["keys"][n], W["certs"][n], [issuing_cert], W["tsa"]) for n in W["keys"]}
    return W


def revoke(W, cert, reason, at, note, invalidity=None, replaced_by=None):
    W["crl_cache"].clear()           # a new CRL is published after every revocation
    return W["ca"].revoke(cert, reason, at, note, invalidity, replaced_by)


def rekey_signer(W, name, dept, key_id, at, approver):
    key = W["store"].generate(key_id, "document-signing", f"{name} ({dept})", at)
    cert = W["ca"].issue_signing(pki.make_csr(key, name, dept, email=email(name)), "document-signing", at,
                                 name, approver)
    W["keys"][name], W["certs"][name] = key, cert
    W["signers"][name] = ss.Signer(key, cert, [W["issuing_cert"]], W["tsa"])
    return cert


def impostor_signer(W, name, dept):
    """An attacker builds its own 'HVMC Root CA R1' and issues itself a perfect-looking certificate."""
    k = lib_rsa.generate_private_key(65537, 3072)
    evil_root = pki.create_root(k, T0)
    evil_ca = cm.ManagedCA(k, evil_root, tempfile.mkdtemp(), T0)
    cert = evil_ca.issue_signing(pki.make_csr(k, name, dept, email=email(name)), "document-signing", T0,
                                 "attacker", "attacker")
    return ss.Signer(k, cert, [evil_root], W["tsa"])


W = None
TW = None    # a second, independent world for the unit tests


# ======================================================================= TESTS
class TestSignatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv = sig.scratch_private(TW["keys"]["Sarah Chen"])
        cls.lib = TW["keys"]["Sarah Chen"]
        cls.pub = cls.priv.public_key

    def test_pss_round_trip_randomised(self):
        m = doc("discharge_summary_HVMC-004417.json")
        s1, s2 = sig.pss_sign(self.priv, m), sig.pss_sign(self.priv, m)
        self.assertNotEqual(s1, s2)                       # random salt
        self.assertTrue(sig.pss_verify(self.pub, m, s1) and sig.pss_verify(self.pub, m, s2))
        self.assertFalse(sig.pss_verify(self.pub, m + b" ", s1))
        bad = bytearray(s1)
        bad[7] ^= 1
        self.assertFalse(sig.pss_verify(self.pub, m, bytes(bad)))
        other = sig.scratch_private(TW["keys"]["David Patel"]).public_key
        self.assertFalse(sig.pss_verify(other, m, s1))    # wrong public key

    def test_pss_interop_with_library(self):
        m = b"HVMC medication verification"
        pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
        self.lib.public_key().verify(sig.pss_sign(self.priv, m), m, pss, hashes.SHA256())   # raises if invalid
        self.assertTrue(sig.pss_verify(self.pub, m, self.lib.sign(m, pss, hashes.SHA256())))
        auto = self.lib.sign(m, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                             hashes.SHA256())
        self.assertTrue(sig.pss_verify(self.pub, m, auto, salt_len=self.priv.k - 32 - 2))

    def test_pss_encoding_structure(self):
        em = sig.emsa_pss_encode(hashlib.sha256(b"x").digest(), 3071, _salt=bytes(32))
        self.assertEqual(em[-1], 0xBC)
        self.assertEqual(len(em), 384)
        self.assertEqual(em[0] & 0x80, 0)                 # 8*emLen - emBits = 1 top bit cleared
        self.assertTrue(sig.emsa_pss_verify(hashlib.sha256(b"x").digest(), em, 3071))

    def test_pkcs1v15_matches_library_byte_for_byte(self):
        m = b"HVMC discharge summary"
        mine = sig.pkcs1v15_sign(self.priv, m)
        self.assertEqual(mine, self.lib.sign(m, padding.PKCS1v15(), hashes.SHA256()))   # deterministic scheme
        self.assertTrue(sig.pkcs1v15_verify(self.pub, m, mine))
        self.assertFalse(sig.pkcs1v15_verify(self.pub, m + b"!", mine))

    def test_textbook_rsa_forgery(self):
        m1, m2 = 1234567, 7654321
        s1, s2 = sig.textbook_sign(self.priv, m1), sig.textbook_sign(self.priv, m2)
        forged = s1 * s2 % self.pub.n                     # never signed by the key holder
        self.assertTrue(sig.textbook_verify(self.pub, m1 * m2 % self.pub.n, forged))
        self.assertTrue(sig.textbook_verify(self.pub, 1, 1))  # s = 1 is a valid signature on m = 1


class TestCertificates(unittest.TestCase):
    def test_document_signing_profile(self):
        c = TW["certs"]["Sarah Chen"]
        ku = c.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(ku.digital_signature and ku.content_commitment and not ku.key_encipherment)
        self.assertIn(cm.DOCUMENT_SIGNING, c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
        pols = c.extensions.get_extension_for_class(x509.CertificatePolicies).value
        self.assertEqual(pols[0].policy_identifier, cm.HVMC_DOC_POLICY)
        self.assertEqual(c.public_key().key_size, 3072)

    def test_contractor_capped_and_tsa_profile(self):
        self.assertEqual(TW["certs"]["Carlos Diaz"].not_valid_after_utc.date(), dt.date(2026, 12, 31))
        eku = TW["tsa_cert"].extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        self.assertTrue(eku.critical)
        self.assertEqual(list(eku.value), [ExtendedKeyUsageOID.TIME_STAMPING])

    def test_key_separation(self):
        # Sarah's signing key is not her authentication key from the rubric 4 PKI
        auth = TW["store"].keys["sarah-chen-client-2026"]["fingerprint_sha256"]
        self.assertNotEqual(auth, TW["store"].keys["sarah-chen-sign-2026"]["fingerprint_sha256"])

    def test_revocation_and_crl(self):
        c = TW["certs"]["David Patel"]
        rec = revoke(TW, c, x509.ReasonFlags.affiliation_changed, T0 + D, "test")
        self.assertEqual(rec["status"], "revoked")
        crl = TW["ca"].crl(T0 + 2 * D)
        self.assertTrue(crl.is_signature_valid(TW["issuing_cert"].public_key()))
        state, info = cm.status(crl, c)
        self.assertEqual((state, info["reason"]), ("revoked", x509.ReasonFlags.affiliation_changed))
        self.assertEqual(cm.status(crl, TW["certs"]["Sarah Chen"])[0], "good")
        with self.assertRaises(ValueError):
            revoke(TW, c, x509.ReasonFlags.unspecified, T0 + 2 * D, "twice")

    def test_policy_rejects_non_hvmc_email(self):
        k = lib_rsa.generate_private_key(65537, 3072)
        with self.assertRaises(pki.PolicyViolation):
            TW["ca"].issue_signing(pki.make_csr(k, "X", "Doctors", email="x@gmail.com"), "document-signing", T0, "x", "x")


class TestVerification(unittest.TestCase):
    def v(self, document, env, at):
        return TW["verifier"].verify(document, env, at).status

    def test_valid_and_tampering(self):
        d = doc("discharge_summary_HVMC-004417.json")
        env = TW["signers"]["Sarah Chen"].sign(d, "DS-HVMC-004417-01", "discharge-summary", T0 + H)
        self.assertEqual(self.v(d, env, T0 + 2 * H), "VALID")
        self.assertEqual(self.v(d.replace(b"home", b"skilled nursing facility"), env, T0 + 2 * H), "INVALID")
        e2 = copy.deepcopy(env)
        e2["signed_attributes"]["doc_type"] = "medication-verification"
        self.assertEqual(self.v(d, e2, T0 + 2 * H), "INVALID")
        e3 = copy.deepcopy(env)
        e3["certificates"][0] = base64.b64encode(TW["certs"]["David Patel"].public_bytes(serialization.Encoding.DER)).decode()
        self.assertEqual(self.v(d, e3, T0 + 2 * H), "INVALID")

    def test_authorisation_and_trust_anchor(self):
        d = doc("discharge_summary_HVMC-004417.json")
        env = TW["signers"]["Angela Brooks"].sign(d, "DS-HVMC-004417-01", "discharge-summary", T0 + H)
        self.assertEqual(self.v(d, env, T0 + 2 * H), "INVALID")          # nurses may not sign discharge summaries
        fake = impostor_signer(TW, "Sarah Chen", "Doctors").sign(d, "DS-HVMC-004417-01", "discharge-summary", T0 + H)
        self.assertEqual(self.v(d, fake, T0 + 2 * H), "INVALID")

    def test_long_term_validation(self):
        d = doc("discharge_summary_HVMC-004417.json")
        later = TW["certs"]["Sarah Chen"].not_valid_after_utc + 30 * D
        with_ts = TW["signers"]["Sarah Chen"].sign(d, "DS-1", "discharge-summary", T0 + H)
        no_ts = TW["signers"]["Sarah Chen"].sign(d, "DS-1", "discharge-summary", T0 + H, timestamp=False)
        self.assertEqual(self.v(d, no_ts, T0 + 2 * H), "VALID")
        self.assertEqual(self.v(d, with_ts, later), "VALID")
        self.assertEqual(self.v(d, no_ts, later), "INDETERMINATE")

    def test_revocation_timing(self):
        d = doc("change_record_HVMC-IAM-CHG-104.json")
        before = TW["signers"]["Carlos Diaz"].sign(d, "HVMC-IAM-CHG-104", "change-record", T0 + H)
        revoke(TW, TW["certs"]["Carlos Diaz"], x509.ReasonFlags.cessation_of_operation, T0 + 4 * D, "test")
        after = TW["signers"]["Carlos Diaz"].sign(d, "HVMC-IAM-CHG-104", "change-record", T0 + 5 * D)
        self.assertEqual(self.v(d, before, T0 + 6 * D), "VALID")
        self.assertEqual(self.v(d, after, T0 + 6 * D), "INVALID")
        n = doc("nursing_note_HVMC-004417.json")
        early = TW["signers"]["Angela Brooks"].sign(n, "NN-1", "nursing-note", T0 + H)
        stolen = TW["signers"]["Angela Brooks"].sign(n, "NN-2", "nursing-note", T0 + 6 * D + 12 * H)
        revoke(TW, TW["certs"]["Angela Brooks"], x509.ReasonFlags.key_compromise, T0 + 7 * D, "test",
               invalidity=T0 + 6 * D)
        self.assertEqual(self.v(n, early, T0 + 8 * D), "VALID")
        self.assertEqual(self.v(n, stolen, T0 + 8 * D), "INVALID")


# ======================================================================= DEMOS
def show(label, res, out):
    print(f"\n  [{res.status}] {label}")
    print(f"      signer: {res.signer}; trusted signing time: "
          f"{res.signing_time.strftime('%Y-%m-%d %H:%M UTC') if res.signing_time else 'none'}; {res.reason}")
    for step, ok, detail in res.steps:
        print(f"      {'pass' if ok else 'FAIL'}  {step}" + (f"  ({detail})" if detail else ""))
    out.append({"scenario": label, "status": res.status, "reason": res.reason, "signer": res.signer,
                "signing_time": res.signing_time.isoformat() if res.signing_time else None,
                "steps": [list(s) for s in res.steps]})


def save_signed(name, document, env):
    os.makedirs(OUT_DOCS, exist_ok=True)
    with open(os.path.join(OUT_DOCS, name), "wb") as f:
        f.write(document)
    with open(os.path.join(OUT_DOCS, name.replace(".json", ".sig.json")), "w") as f:
        json.dump(env, f, indent=2)


def demo_signatures(out):
    print("\n=== Demo 1: RSA signatures from scratch ===")
    priv = sig.scratch_private(W["keys"]["Sarah Chen"])
    m = doc("discharge_summary_HVMC-004417.json")
    t = time.time()
    s = sig.pss_sign(priv, m)
    ms = (time.time() - t) * 1000
    print(f"  RSA-PSS-SHA256 signature by Sarah Chen's RSA-3072 key: {len(s)} bytes, {ms:.0f} ms; "
          f"verifies = {sig.pss_verify(priv.public_key, m, s)}")
    print(f"  signing the same document again gives a different signature (random salt) = "
          f"{sig.pss_sign(priv, m) != s}")
    v15 = sig.pkcs1v15_sign(priv, m)
    print(f"  PKCS #1 v1.5 signature is deterministic and identical to the library's = "
          f"{v15 == W['keys']['Sarah Chen'].sign(m, padding.PKCS1v15(), hashes.SHA256())}")
    m1, m2 = 1234567, 7654321
    forged = sig.textbook_sign(priv, m1) * sig.textbook_sign(priv, m2) % priv.n
    print(f"  textbook RSA (no hash, no padding): signatures on m1 and m2 multiply into a valid signature on "
          f"m1*m2 = {sig.textbook_verify(priv.public_key, m1 * m2, forged)} -> existential forgery; hashing + PSS "
          "padding stop this")
    out["pss_signature_bytes"] = len(s)
    out["pss_ms"] = round(ms)


def demo_certificates(out, ossl):
    print("\n=== Demo 2: Certificate generation and management ===")
    rows = []
    for name, c in list(W["certs"].items()) + [("TSA", W["tsa_cert"])]:
        eku = c.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        rec = W["ca"].find(c)
        rows.append({"subject": cm.cn(c), "ou": cm.ou(c), "key": f"RSA-{c.public_key().key_size}",
                     "eku": ", ".join(o._name if o._name != "Unknown OID" else "documentSigning" for o in eku.value)
                     + (" (critical)" if eku.critical else ""),
                     "not_after": str(c.not_valid_after_utc.date()), "approved_by": rec["approved_by"],
                     "serial": rec["serial"][:12] + "…"})
        print(f"  {cm.cn(c):32} {cm.ou(c):21} {rows[-1]['key']:9} {rows[-1]['eku']:40} until {rows[-1]['not_after']}"
              f"  approved by {rec['approved_by']}")
    out["certificates"] = rows
    print("  Carlos Diaz is a contractor: certificate capped at his contract end date 2026-12-31 (not 2 years)")
    for name, c in W["certs"].items():
        with open(os.path.join(PKI_DIR, "certs", f"{name.lower().replace(' ', '.')}.sign.crt.pem"), "wb") as f:
            f.write(cm.pem(c))
    with open(os.path.join(PKI_DIR, "certs", "hvmc-tsa-1.crt.pem"), "wb") as f:
        f.write(cm.pem(W["tsa_cert"]))


def demo_timeline(out, ossl):
    print("\n=== Demo 3: Signing, verification, revocation and renewal on a timeline ===")
    print(f"  T0 = {T0:%Y-%m-%d %H:%M} UTC (run time; signing certificates issued). Later events are simulated.")
    V = W["verifier"].verify
    S = W["signers"]
    res = []
    docs = {}

    # T0 + 1h: four clinicians and staff sign
    for name, file, doc_id, doc_type in [
            ("Sarah Chen", "discharge_summary_HVMC-004417.json", "DS-HVMC-004417-01", "discharge-summary"),
            ("Angela Brooks", "nursing_note_HVMC-004417.json", "NN-HVMC-004417-07", "nursing-note"),
            ("David Patel", "medication_verification_HVMC-004417.json", "MV-HVMC-004417-03", "medication-verification"),
            ("Carlos Diaz", "change_record_HVMC-IAM-CHG-104.json", "HVMC-IAM-CHG-104", "change-record")]:
        d = doc(file)
        env = S[name].sign(d, doc_id, doc_type, T0 + H)
        docs[file] = (d, env)
        save_signed(file, d, env)
    print("\n  T0+1h  Sarah Chen, Angela Brooks, David Patel and Carlos Diaz sign their documents (timestamped by the HVMC TSA)")
    d, env = docs["discharge_summary_HVMC-004417.json"]
    show("1. Discharge summary signed by Sarah Chen, verified at T0+2h", V(d, env, T0 + 2 * H), res)

    print("\n  T0+2h  attacks on the signed documents")
    d, env = docs["medication_verification_HVMC-004417.json"]
    show("2. Dose changed from 875 mg to 1750 mg after signing", V(d.replace(b"875 mg", b"1750 mg"), env, T0 + 2 * H), res)
    e2 = copy.deepcopy(env)
    e2["signed_attributes"]["doc_id"] = "MV-HVMC-009999-01"
    show("3. Signed attribute edited (document moved to another patient's record)", V(d, e2, T0 + 2 * H), res)
    d1, env1 = docs["discharge_summary_HVMC-004417.json"]
    e3 = copy.deepcopy(env1)
    e3["certificates"][0] = base64.b64encode(W["certs"]["David Patel"].public_bytes(serialization.Encoding.DER)).decode()
    show("4. Signer certificate swapped for another doctor's", V(d1, e3, T0 + 2 * H), res)
    nurse_ds = S["Angela Brooks"].sign(d1, "DS-HVMC-004417-01", "discharge-summary", T0 + 2 * H)
    show("5. A nurse signs a discharge summary (valid key, wrong authority)", V(d1, nurse_ds, T0 + 2 * H), res)
    fake = impostor_signer(W, "Sarah Chen", "Doctors").sign(d1, "DS-HVMC-004417-01", "discharge-summary", T0 + 2 * H)
    show("6. Attacker's own 'HVMC Root CA R1' issues a 'Sarah Chen' certificate", V(d1, fake, T0 + 2 * H), res)

    # T0 + 4d: JML-203 - Carlos Diaz leaves; certificate revoked
    revoke(W, W["certs"]["Carlos Diaz"], x509.ReasonFlags.cessation_of_operation, T0 + 4 * D,
           "JML-203 contractor terminated (Entra account disabled, sessions revoked)")
    print("\n  T0+4d  JML-203: Carlos Diaz's contract ends - certificate revoked (cessationOfOperation)")
    d, env = docs["change_record_HVMC-IAM-CHG-104.json"]
    show("7. Carlos's change record signed at T0+1h, verified after his revocation", V(d, env, T0 + 4 * D + H), res)
    d105 = doc("change_record_HVMC-IAM-CHG-105.json")
    late = S["Carlos Diaz"].sign(d105, "HVMC-IAM-CHG-105", "change-record", T0 + 5 * D)
    save_signed("change_record_HVMC-IAM-CHG-105.json", d105, late)
    show("8. Carlos still has his key file and signs a new change record at T0+5d", V(d105, late, T0 + 5 * D + H), res)

    # T0 + 6.5d: Angela's laptop stolen at T0+6d; attacker signs; reported and revoked at T0+7d
    forged_doc = doc("nursing_note_HVMC-004417_forged.json")
    forged = S["Angela Brooks"].sign(forged_doc, "NN-HVMC-004417-08", "nursing-note", T0 + 6 * D + 12 * H)
    save_signed("nursing_note_HVMC-004417_forged.json", forged_doc, forged)
    revoke(W, W["certs"]["Angela Brooks"], x509.ReasonFlags.key_compromise, T0 + 7 * D,
           "laptop stolen; key compromised from T0+6d", invalidity=T0 + 6 * D)
    print("\n  T0+7d  Angela Brooks reports her laptop stolen on T0+6d - certificate revoked (keyCompromise, "
          "invalidity date T0+6d)")
    show("9. Note signed with Angela's stolen key at T0+6d12h (before anyone knew)", V(forged_doc, forged, T0 + 7 * D + H), res)
    d, env = docs["nursing_note_HVMC-004417.json"]
    show("10. Angela's genuine note from T0+1h, verified after the compromise", V(d, env, T0 + 7 * D + H), res)
    new_cert = rekey_signer(W, "Angela Brooks", "Nursing", "angela-brooks-sign-2026b", T0 + 7 * D + 2 * H,
                            "Denise Coleman (Information Security)")
    W["store"].set_status("angela-brooks-sign-2026", "compromised", "laptop stolen, certificate revoked", T0 + 7 * D)
    with open(os.path.join(PKI_DIR, "certs", "angela.brooks.sign-rekeyed.crt.pem"), "wb") as f:
        f.write(cm.pem(new_cert))
    dv2 = doc("nursing_note_HVMC-004417_v2.json")
    env_v2 = S["Angela Brooks"].sign(dv2, "NN-HVMC-004417-09", "nursing-note", T0 + 8 * D)
    save_signed("nursing_note_HVMC-004417_v2.json", dv2, env_v2)
    show("11. Angela signs with her NEW key and certificate at T0+8d", V(dv2, env_v2, T0 + 8 * D + H), res)

    # renewal: the expiry monitor flags the portal certificate 30 days before it expires
    portal = W["portal_cert"]
    check_at = portal.not_valid_after_utc - 30 * D
    flagged = W["ca"].expiry_report(check_at, 45)
    print(f"\n  Expiry monitor run for {check_at:%Y-%m-%d} (45-day window): "
          + "; ".join(f"{s.split(',')[0]} ({p}) expires {na} - {left} days left" for s, p, na, left in flagged))
    out["expiry_report"] = [list(f) for f in flagged]
    new_key = W["store"].generate("portal-tls-2027", "tls-server", "IT Infrastructure (Kevin O'Brien)", T0 + 9 * D)
    renewed = W["ca"].issue_tls(pki.make_csr(new_key, "portal.hvmc.example", "IT Infrastructure",
                                             dns=["portal.hvmc.example", "ehr.hvmc.example"]), T0 + 9 * D,
                                "Kevin O'Brien (change HVMC-PKI-CHG-404)", "Denise Coleman (Information Security)")
    revoke(W, portal, x509.ReasonFlags.superseded, T0 + 9 * D + 2 * H, "re-keyed: portal-tls-2027",
           replaced_by=format(renewed.serial_number, "x"))
    W["store"].set_status("portal-tls-2026", "retired", "superseded by portal-tls-2027", T0 + 9 * D)
    with open(os.path.join(PKI_DIR, "certs", "portal.hvmc.example.renewed.crt.pem"), "wb") as f:
        f.write(cm.pem(renewed))
    print(f"  T0+9d  renewal (re-key) brought forward to the next change window: new RSA-2048 key portal-tls-2027, new certificate until "
          f"{renewed.not_valid_after_utc:%Y-%m-%d}; old certificate revoked as 'superseded' after cut-over")

    # long-term validation, 30 days after Sarah's certificate expires
    later = W["certs"]["Sarah Chen"].not_valid_after_utc + 30 * D
    d1, env1 = docs["discharge_summary_HVMC-004417.json"]
    no_ts = S["Sarah Chen"].sign(d1, "DS-HVMC-004417-01", "discharge-summary", T0 + H, timestamp=False)
    print(f"\n  {later:%Y-%m-%d}: Sarah's certificate expired on {W['certs']['Sarah Chen'].not_valid_after_utc:%Y-%m-%d}; "
          "an auditor checks the discharge summary")
    show("12. Same document, signature WITH a TSA timestamp", V(d1, env1, later), res)
    show("13. Same document, signature WITHOUT a timestamp", V(d1, no_ts, later), res)
    out["scenarios"] = res

    # publish the CRL at T0+10d and check it with OpenSSL at that simulated time
    W["crl_cache"].clear()
    crl = W["ca"].crl(T_PUB)
    with open(os.path.join(PKI_DIR, "crl", "hvmc-issuing-ca-1.crl.pem"), "wb") as f:
        f.write(cm.pem(crl))
    print(f"\n  T0+10d published CRL #{crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number} with "
          f"{len(list(crl))} entries:")
    out["crl"] = []
    for entry in crl:
        rec = next(r for r in W["ca"].register if int(r["serial"], 16) == entry.serial_number)
        reason = entry.extensions.get_extension_for_class(x509.CRLReason).value.reason.value
        print(f"    {rec['subject'].split(',')[0] if 'CN=' in rec['subject'].split(',')[0] else rec['subject'].split(',')[1]:28} "
              f"revoked {entry.revocation_date_utc:%Y-%m-%d %H:%M}  reason {reason}")
        out["crl"].append([rec["subject"], str(entry.revocation_date_utc), reason, rec.get("invalidity_date")])


HEX_LINE = __import__("re").compile(r"^\s+([0-9a-fA-F]{2}:)+[0-9a-fA-F]{0,2}$")


def strip_hex(o):
    """Drop modulus and signature hex dumps from OpenSSL -text output."""
    def dump(l):    # modulus lines are indented 20 spaces, signature lines 9; keep serial and key IDs
        indent = len(l) - len(l.lstrip())
        return HEX_LINE.match(l) and (indent >= 18 or indent <= 10)
    return "\n".join(l for l in o.splitlines() if "Modulus" not in l and not dump(l))


def run_openssl(args, log, cwd=PKI_DIR, stdin=None, show=None):
    r = subprocess.run(["openssl"] + args, capture_output=True, cwd=cwd, input=stdin)
    out = (r.stdout + r.stderr).decode(errors="replace").strip()
    log.append("$ openssl " + " ".join(args) + "\n" + (show(out) if show else out) + "\n")
    return r.returncode, out


def demo_openssl(out, ossl):
    print("\n=== Demo 4: Independent checks with OpenSSL ===")
    tmp = tempfile.mkdtemp()
    d, env = json.load(open(os.path.join(OUT_DOCS, "discharge_summary_HVMC-004417.sig.json"))), None
    env = d
    with open(os.path.join(tmp, "signed_attributes.bin"), "wb") as f:
        f.write(ss.canonical(env["signed_attributes"]))
    with open(os.path.join(tmp, "signature.bin"), "wb") as f:
        f.write(base64.b64decode(env["signature"]))
    with open(os.path.join(tmp, "sarah.pub.pem"), "wb") as f:
        f.write(subprocess.run(["openssl", "x509", "-in", "certs/sarah.chen.sign.crt.pem", "-pubkey", "-noout"],
                               capture_output=True, cwd=PKI_DIR).stdout)
    rc1, o1 = run_openssl(["dgst", "-sha256", "-verify", os.path.join(tmp, "sarah.pub.pem"), "-sigopt",
                           "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32", "-signature",
                           os.path.join(tmp, "signature.bin"), os.path.join(tmp, "signed_attributes.bin")], ossl)
    # PKCS #1 v1.5: OpenSSL's signature must equal the from-scratch one byte for byte
    pp = os.path.join(PKI_DIR, "private", ".passphrase")
    key_pem = subprocess.run(["openssl", "pkey", "-in", "private/sarah-chen-sign-2026.key.pem", "-passin", "file:" + pp],
                             capture_output=True, cwd=PKI_DIR).stdout
    m = doc("discharge_summary_HVMC-004417.json")
    with open(os.path.join(tmp, "discharge_summary.json"), "wb") as f:
        f.write(m)
    rc2, _ = run_openssl(["dgst", "-sha256", "-sign", "/dev/stdin", "-out", os.path.join(tmp, "v15.sig"),
                          os.path.join(tmp, "discharge_summary.json")], ossl, stdin=key_pem,
                         show=lambda o: o or "(signature written; private key piped from 'openssl pkey', never on disk)")
    same = open(os.path.join(tmp, "v15.sig"), "rb").read() == sig.pkcs1v15_sign(sig.scratch_private(W["keys"]["Sarah Chen"]), m)
    ossl.append(f"from-scratch PKCS #1 v1.5 signature == OpenSSL signature (byte for byte): {same}\n")
    base = ["verify", "-attime", str(int((T_PUB + H).timestamp())), "-CAfile", "certs/hvmc-root-ca-r1.crt.pem", "-untrusted", "certs/hvmc-issuing-ca-1.crt.pem"]
    rc3, o3 = run_openssl(base + ["-crl_check", "-CRLfile", "crl/hvmc-issuing-ca-1.crl.pem", "certs/sarah.chen.sign.crt.pem"], ossl)
    rc4, o4 = run_openssl(base + ["-crl_check", "-CRLfile", "crl/hvmc-issuing-ca-1.crl.pem", "certs/carlos.diaz.sign.crt.pem"], ossl)
    rc5, o5 = run_openssl(base + ["-crl_check", "-CRLfile", "crl/hvmc-issuing-ca-1.crl.pem", "certs/portal.hvmc.example.crt.pem"], ossl)
    rc6, o6 = run_openssl(base + ["-crl_check", "-CRLfile", "crl/hvmc-issuing-ca-1.crl.pem", "-purpose", "sslserver",
                                  "certs/portal.hvmc.example.renewed.crt.pem"], ossl)
    run_openssl(["crl", "-in", "crl/hvmc-issuing-ca-1.crl.pem", "-noout", "-text"], ossl,
                show=strip_hex)
    run_openssl(["x509", "-in", "certs/sarah.chen.sign.crt.pem", "-noout", "-text"], ossl,
                show=strip_hex)
    ossl[:] = [entry.replace(tmp + "/", "").replace("$ openssl dgst -sha256 -sign /dev/stdin",
               "$ openssl pkey -in private/sarah-chen-sign-2026.key.pem -passin file:private/.passphrase | "
               "openssl dgst -sha256 -sign /dev/stdin") for entry in ossl]
    ossl.insert(0, f"-attime {int((T_PUB + H).timestamp())} = {T_PUB + H:%Y-%m-%d %H:%M} UTC, the simulated time "
                   "just after the T0+10d CRL was published\n")
    shutil.rmtree(tmp)
    print(f"  openssl dgst verifies the from-scratch RSA-PSS signature: {o1}")
    print(f"  from-scratch PKCS #1 v1.5 signature identical to OpenSSL's: {same}")
    print(f"  openssl verify -crl_check: Sarah -> {o3.splitlines()[-1]}; Carlos -> revoked = {'revoked' in o4}; "
          f"old portal -> revoked = {'revoked' in o5}; renewed portal -> {o6.splitlines()[-1]}")
    out["openssl"] = {"pss_verify": o1, "pkcs1v15_identical": same, "sarah": o3.splitlines()[-1],
                      "carlos_revoked": "revoked" in o4, "old_portal_revoked": "revoked" in o5,
                      "renewed_portal": o6.splitlines()[-1]}


# ======================================================================= MAIN
class Tee(io.TextIOBase):
    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for st in self.streams:
            st.write(s)
        return len(s)


def main():
    global W, TW
    buf = io.StringIO()
    real = sys.stdout
    sys.stdout = Tee(real, buf)
    env = (f"Python {platform.python_version()} on {platform.system()} {platform.machine()}, "
           f"{NOW.astimezone().strftime('%Y-%m-%d %H:%M')}; cryptography package: {cryptography.__version__}; "
           f"{subprocess.run(['openssl', 'version'], capture_output=True, text=True).stdout.strip()}")
    print("HVMC Digital Signatures - test and demo run")
    print(env)
    print("\n=== Setting up: copy of the rubric 4 PKI in pki/ + signing certificates ===")
    if os.path.exists(OUT_DOCS):
        shutil.rmtree(OUT_DOCS)
    W = build_world(PKI_DIR)
    test_dir = tempfile.mkdtemp()
    TW = build_world(os.path.join(test_dir, "pki"), log=lambda *a: None)

    print("\n=== Unit tests ===")
    stream = io.StringIO()
    suite = unittest.TestSuite()
    for case in (TestSignatures, TestCertificates, TestVerification):
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(case))
    res = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    print(stream.getvalue().rstrip())
    print(f"tests run: {res.testsRun}, failures: {len(res.failures)}, errors: {len(res.errors)}, skipped: {len(res.skipped)}")
    RESULTS["tests"] = {"run": res.testsRun, "failures": len(res.failures), "errors": len(res.errors),
                        "passed": res.testsRun - len(res.failures) - len(res.errors)}
    shutil.rmtree(test_dir)

    ossl = []
    demo_signatures(RESULTS["demos"])
    demo_certificates(RESULTS["demos"], ossl)
    demo_timeline(RESULTS["demos"], ossl)
    demo_openssl(RESULTS["demos"], ossl)

    with open(os.path.join(HERE, "trust_store.json"), "w") as f:
        json.dump(W["trust"].to_json(), f, indent=2)
    sys.stdout = real
    RESULTS["environment"] = env
    RESULTS["t0"] = T0.isoformat()
    with open(os.path.join(HERE, "results.txt"), "w") as f:
        f.write(buf.getvalue())
    with open(os.path.join(HERE, "results.json"), "w") as f:
        json.dump(RESULTS, f, indent=2, default=str)
    with open(os.path.join(HERE, "openssl_checks.txt"), "w") as f:
        f.write("HVMC digital signatures - independent checks with the OpenSSL command line (run from pki/)\n" + env + "\n\n")
        f.write("\n".join(ossl))
    return res.wasSuccessful()


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
