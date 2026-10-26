"""
Tests and demonstrations for HVMC public key cryptography: RSA key generation and
management, RSA-OAEP encryption, a two-tier PKI, and authenticated key exchange.

Horizon Valley Medical Center (HVMC) - Cryptography 1: Utilize Public Key Cryptography
Author: Sabitha S Karanavar

Run:  python3 test_and_demo.py
Rebuilds pki/ (certificates, CRL, key inventory; private keys in pki/private/, which
is git-ignored) and writes results.txt, results.json and openssl_checks.txt.
Needs the `cryptography` package (certificates, PEM storage, AES-GCM, cross-checks).
"""
import base64
import datetime as dt
import io
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

import cryptography
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa as lib_rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import ExtendedKeyUsageOID

import key_exchange as kx
import key_management as km
import pki
import rsa

HERE = os.path.dirname(os.path.abspath(__file__))
PKI_DIR = os.path.join(HERE, "pki")
UTC = dt.timezone.utc
NOW = dt.datetime.now(UTC).replace(microsecond=0)
H = bytes.fromhex
RESULTS = {"tests": {}, "demos": {}}
RECORD = (b'{"mrn":"HVMC-004417","patient":"Synthetic Patient 17","attending":"Sarah Chen",'
          b'"diagnosis":"community-acquired pneumonia","disposition":"home","discharged":"2026-10-12"}')


# ======================================================================= PKI BUILD
def build_hvmc_pki(root, now=NOW, log=print):
    """Create every key and certificate of the HVMC PKI under `root`."""
    if os.path.exists(root):
        shutil.rmtree(root)
    os.makedirs(root)
    store = km.KeyStore(root, km.get_passphrase(os.path.join(root, "private")))
    t = time.time()
    root_key = store.generate("hvmc-root-ca-r1", "root-ca", "Information Security (offline)", now)
    issuing_key = store.generate("hvmc-issuing-ca-1", "issuing-ca", "Information Security", now)
    portal_key = store.generate("portal-tls-2026", "tls-server", "IT Infrastructure (Kevin O'Brien)", now)
    sarah_key = store.generate("sarah-chen-client-2026", "client-auth", "Sarah Chen (Doctors)", now)
    log(f"  generated 4 RSA key pairs from scratch in {time.time() - t:.1f}s (4096, 3072, 2048, 2048 bits)")

    root_cert = pki.create_root(root_key, now)
    issuing_csr, issuing_cert = pki.create_issuing_ca(root_key, root_cert, issuing_key, now)
    ca = pki.IssuingCA(issuing_key, issuing_cert, os.path.join(root, "ca_register.json"))
    portal_csr = pki.make_csr(portal_key, "portal.hvmc.example", "IT Infrastructure",
                              dns=["portal.hvmc.example", "ehr.hvmc.example"])
    sarah_csr = pki.make_csr(sarah_key, "Sarah Chen", "Doctors", email="sarah.chen@hvmc.example")
    portal_cert = ca.issue(portal_csr, "tls-server", now, "Kevin O'Brien (change HVMC-PKI-CHG-401)")
    sarah_cert = ca.issue(sarah_csr, "client-auth", now, "Sarah Chen (approved by Information Security)")
    root_crl_builder = (x509.CertificateRevocationListBuilder().issuer_name(root_cert.subject)
                        .last_update(now).next_update(now + dt.timedelta(days=180))
                        .add_extension(x509.CRLNumber(1), critical=False))
    root_crl = root_crl_builder.sign(root_key, hashes.SHA384())
    issuing_crl = ca.crl(now)

    files = {
        "certs/hvmc-root-ca-r1.crt.pem": pki.pem(root_cert),
        "certs/hvmc-issuing-ca-1.crt.pem": pki.pem(issuing_cert),
        "certs/portal.hvmc.example.crt.pem": pki.pem(portal_cert),
        "certs/sarah.chen.crt.pem": pki.pem(sarah_cert),
        "certs/hvmc-chain.pem": pki.pem(issuing_cert) + pki.pem(root_cert),
        "csr/hvmc-issuing-ca-1.csr.pem": issuing_csr.public_bytes(serialization.Encoding.PEM),
        "csr/portal.hvmc.example.csr.pem": portal_csr.public_bytes(serialization.Encoding.PEM),
        "csr/sarah.chen.csr.pem": sarah_csr.public_bytes(serialization.Encoding.PEM),
        "crl/hvmc-root-ca-r1.crl.pem": pki.pem(root_crl),
        "crl/hvmc-issuing-ca-1.crl.pem": pki.pem(issuing_crl),
    }
    for rel, data in files.items():
        os.makedirs(os.path.join(root, os.path.dirname(rel)), exist_ok=True)
        with open(os.path.join(root, rel), "wb") as f:
            f.write(data)
    return {
        "store": store, "ca": ca,
        "root_key": root_key, "root_cert": root_cert, "issuing_key": issuing_key, "issuing_cert": issuing_cert,
        "portal_key": portal_key, "portal_cert": portal_cert, "sarah_key": sarah_key, "sarah_cert": sarah_cert,
        "crls": [root_crl, issuing_crl],
    }


P = None          # the HVMC PKI, built once in main() and shared by tests and demos


def trust():
    return {"roots": [P["root_cert"]], "intermediates": [P["issuing_cert"]], "crls": P["crls"]}


# ======================================================================= TESTS
class TestRSA(unittest.TestCase):
    def test_textbook_example(self):
        # the classic worked example: p=61, q=53, e=17 -> n=3233; m=65 -> c=2790
        k = rsa.RSAPrivateKey(61, 53, 17)
        self.assertEqual(k.n, 3233)
        self.assertEqual(k.d, 413)                      # e^-1 mod lambda(n)=780 (2753 with phi(n)=3120)
        self.assertEqual(k.public_key.encrypt_raw(65), 2790)
        self.assertEqual(k.decrypt_raw(2790), 65)

    def test_number_theory(self):
        g, x, y = rsa.egcd(240, 46)
        self.assertEqual((g, 240 * x + 46 * y), (2, 2))
        self.assertEqual(rsa.modinv(17, 780), 413)
        self.assertTrue(rsa.is_probable_prime(2 ** 521 - 1))          # Mersenne prime M521
        for carmichael in (561, 1105, 1729, 2465, 41041):              # fool the Fermat test, not Miller-Rabin
            self.assertFalse(rsa.is_probable_prime(carmichael))
        self.assertFalse(rsa.is_probable_prime((2 ** 89 - 1) * (2 ** 107 - 1)))

    def test_keygen_2048_properties_and_library_accepts(self):
        k = rsa.generate_keypair(2048)
        self.assertEqual(k.n.bit_length(), 2048)
        lam = (k.p - 1) * (k.q - 1) // __import__("math").gcd(k.p - 1, k.q - 1)
        self.assertEqual(k.e * k.d % lam, 1)
        self.assertGreater(abs(k.p - k.q), 1 << (1024 - 100))
        lib = rsa.to_library(k)                     # raises if any CRT value is inconsistent
        sig = lib.sign(b"HVMC", padding.PKCS1v15(), hashes.SHA256())
        lib.public_key().verify(sig, b"HVMC", padding.PKCS1v15(), hashes.SHA256())
        with self.assertRaises(ValueError):
            rsa.generate_keypair(1024)              # below HVMC policy

    def test_crt_and_blinding_match_plain_decryption(self):
        k = rsa.generate_keypair(2048)
        for _ in range(5):
            c = int.from_bytes(os.urandom(255), "big")
            self.assertEqual(k.decrypt_raw(c), pow(c, k.d, k.n))
            self.assertEqual(k.decrypt_raw(c, blind=False), pow(c, k.d, k.n))

    def test_oaep_round_trip_random_and_limits(self):
        k = rsa.generate_keypair(2048)
        c1, c2 = rsa.oaep_encrypt(k.public_key, RECORD[:60]), rsa.oaep_encrypt(k.public_key, RECORD[:60])
        self.assertNotEqual(c1, c2)                 # randomized: same message, different ciphertext
        self.assertEqual(rsa.oaep_decrypt(k, c1), RECORD[:60])
        self.assertEqual(rsa.oaep_decrypt(k, rsa.oaep_encrypt(k.public_key, b"x" * 190)), b"x" * 190)
        with self.assertRaises(ValueError):
            rsa.oaep_encrypt(k.public_key, b"x" * 191)  # 256 - 2*32 - 2 = 190 bytes max
        bad = bytearray(c1)
        bad[100] ^= 1
        with self.assertRaises(rsa.DecryptionError):
            rsa.oaep_decrypt(k, bytes(bad))
        with self.assertRaises(rsa.DecryptionError):
            rsa.oaep_decrypt(k, c1, label=b"wrong label")

    def test_oaep_interop_with_library_both_ways(self):
        k = rsa.generate_keypair(2048)
        lib = rsa.to_library(k)
        pad = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b"HVMC")
        self.assertEqual(lib.decrypt(rsa.oaep_encrypt(k.public_key, b"from scratch", label=b"HVMC"), pad),
                         b"from scratch")
        self.assertEqual(rsa.oaep_decrypt(k, lib.public_key().encrypt(b"from library", pad), label=b"HVMC"),
                         b"from library")

    def test_pkcs1v15_verify_on_real_certificates(self):
        leaf, issuer = P["portal_cert"], P["issuing_cert"]
        pub = rsa.from_library_public(issuer.public_key())
        self.assertTrue(rsa.pkcs1v15_verify(pub, leaf.tbs_certificate_bytes, leaf.signature))
        tbs = bytearray(leaf.tbs_certificate_bytes)
        tbs[-10] ^= 1
        self.assertFalse(rsa.pkcs1v15_verify(pub, bytes(tbs), leaf.signature))
        root = P["root_cert"]                       # root is signed with SHA-384
        self.assertTrue(rsa.pkcs1v15_verify(rsa.from_library_public(root.public_key()), issuer.tbs_certificate_bytes,
                                            issuer.signature, "sha384"))


class TestKeyManagement(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = km.KeyStore(self.dir, b"test passphrase")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_encrypted_storage_permissions_and_passphrase(self):
        lib = self.store.generate("k1", "tls-server", "test")
        path = os.path.join(self.dir, "private", "k1.key.pem")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with open(path, "rb") as f:
            self.assertTrue(f.read().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))
        with self.assertRaises(ValueError):
            km.load_private_key(path, b"wrong passphrase")
        self.assertEqual(km.fingerprint(self.store.private("k1").public_key()), km.fingerprint(lib.public_key()))
        self.assertEqual(self.store.keys["k1"]["algorithm"], "RSA-2048")

    def test_hybrid_rotation_and_lifecycle(self):
        self.store.generate("data-v1", "data-encryption", "EHR")
        env = km.hybrid_encrypt(self.store, "data-v1", RECORD, aad=b"HVMC-004417")
        self.assertEqual(km.hybrid_decrypt(self.store, env), RECORD)
        bad = dict(env, ciphertext=base64.b64encode(b"x" + base64.b64decode(env["ciphertext"])[1:]).decode())
        with self.assertRaises(InvalidTag):
            km.hybrid_decrypt(self.store, bad)
        self.store.generate("data-v2", "data-encryption", "EHR")
        env2 = km.rewrap(self.store, env, "data-v2")
        self.assertEqual(env2["ciphertext"], env["ciphertext"])     # bulk data untouched
        self.store.set_status("data-v1", "retired", "rotated to data-v2")
        with self.assertRaises(km.KeyPolicyError):
            km.hybrid_encrypt(self.store, "data-v1", b"new data")
        self.assertEqual(km.hybrid_decrypt(self.store, env), RECORD)  # retired still decrypts
        self.store.set_status("data-v1", "destroyed", "all envelopes rewrapped")
        with self.assertRaises(km.KeyPolicyError):
            km.hybrid_decrypt(self.store, env)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "private", "data-v1.key.pem")))
        self.assertEqual(km.hybrid_decrypt(self.store, env2), RECORD)

    def test_expiry_enforced(self):
        self.store.generate("short", "tls-server", "test", now=NOW - dt.timedelta(days=400))
        with self.assertRaises(km.KeyPolicyError):
            self.store.require("short", "encrypt")


class TestPKI(unittest.TestCase):
    def test_chain_valid_mine_and_library(self):
        ok, checks = pki.validate_path(P["portal_cert"], [P["issuing_cert"]], [P["root_cert"]], NOW,
                                       ExtendedKeyUsageOID.SERVER_AUTH, "portal.hvmc.example", P["crls"])
        self.assertTrue(ok, [c for c in checks if not c[1]])
        chain = pki.library_verify_server(P["portal_cert"], [P["issuing_cert"]], P["root_cert"],
                                          "portal.hvmc.example", NOW)
        self.assertEqual([c.subject for c in chain],
                         [P["portal_cert"].subject, P["issuing_cert"].subject, P["root_cert"].subject])

    def test_rejections(self):
        def fails(**kw):
            args = dict(leaf=P["portal_cert"], intermediates=[P["issuing_cert"]], roots=[P["root_cert"]], at=NOW,
                        purpose=ExtendedKeyUsageOID.SERVER_AUTH, hostname="portal.hvmc.example", crls=P["crls"])
            args.update(kw)
            return not pki.validate_path(**args)[0]
        self.assertTrue(fails(hostname="pharmacy.hvmc.example"))                 # wrong host
        self.assertTrue(fails(at=NOW + dt.timedelta(days=400)))                  # expired
        self.assertTrue(fails(leaf=P["sarah_cert"], hostname=None))              # client cert used as server
        self.assertTrue(fails(intermediates=[]))                                 # missing issuing CA
        # an impostor root with the same name, signed by an attacker's key
        evil_key = lib_rsa.generate_private_key(65537, 2048)
        impostor_root = pki.create_root(evil_key, NOW)
        self.assertTrue(fails(roots=[impostor_root]))
        # pathLen 0 on the issuing CA: a certificate "issued" by the portal's key is rejected
        fake = (x509.CertificateBuilder().subject_name(pki.name("rogue.hvmc.example")).issuer_name(P["portal_cert"].subject)
                .public_key(evil_key.public_key()).serial_number(pki.serial())
                .not_valid_before(NOW - dt.timedelta(hours=1)).not_valid_after(NOW + dt.timedelta(days=30))
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("rogue.hvmc.example")]), critical=False)
                .sign(P["portal_key"], hashes.SHA256()))
        self.assertTrue(fails(leaf=fake, intermediates=[P["portal_cert"], P["issuing_cert"]], hostname="rogue.hvmc.example"))

    def test_csr_policy(self):
        ca = pki.IssuingCA(P["issuing_key"], P["issuing_cert"], os.path.join(tempfile.mkdtemp(), "reg.json"))
        k = lib_rsa.generate_private_key(65537, 2048)
        weak = lib_rsa.generate_private_key(65537, 1024)
        for csr, profile in [(pki.make_csr(k, "x", dns=["portal.evil.example"]), "tls-server"),
                             (pki.make_csr(k, "x", dns=["*.hvmc.example"]), "tls-server"),
                             (pki.make_csr(weak, "x", dns=["lab.hvmc.example"]), "tls-server"),
                             (pki.make_csr(k, "x"), "tls-server"),
                             (pki.make_csr(k, "x", email="someone@gmail.com"), "client-auth")]:
            with self.assertRaises(pki.PolicyViolation):
                ca.issue(csr, profile, NOW, "test")
        cert = ca.issue(pki.make_csr(k, "lab.hvmc.example", dns=["lab.hvmc.example"]), "tls-server", NOW, "test")
        self.assertEqual(len(ca.register), 1)
        self.assertGreaterEqual(cert.serial_number.bit_length(), 64)


class TestKeyExchange(unittest.TestCase):
    def test_rfc7748_vectors(self):
        self.assertEqual(kx.x25519(H("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                                   H("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")).hex(),
                         "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        a, b = (H("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
                H("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
        a_pub, b_pub = kx.x25519(a, kx.BASE_POINT), kx.x25519(b, kx.BASE_POINT)
        self.assertEqual(a_pub.hex(), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        self.assertEqual(b_pub.hex(), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        self.assertEqual(kx.x25519(a, b_pub).hex(), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        self.assertEqual(kx.x25519(b, a_pub), kx.x25519(a, b_pub))

    def test_x25519_matches_library(self):
        for _ in range(3):
            priv, pub = kx.x25519_keypair()
            lib = X25519PrivateKey.from_private_bytes(priv)
            self.assertEqual(lib.public_key().public_bytes_raw(), pub)
            other = X25519PrivateKey.generate()
            self.assertEqual(kx.x25519_shared(priv, other.public_key().public_bytes_raw()),
                             other.exchange(X25519PublicKey.from_public_bytes(pub)))
        with self.assertRaises(ValueError):
            kx.x25519_shared(priv, bytes(32))          # low-order point u=0

    def test_hkdf_rfc5869(self):
        ikm, salt, info = H("0b" * 22), H("000102030405060708090a0b0c"), H("f0f1f2f3f4f5f6f7f8f9")
        self.assertEqual(kx.hkdf_extract(salt, ikm).hex(),
                         "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        okm = kx.hkdf(ikm, salt, info, 42)
        self.assertEqual(okm.hex(), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                                    "34007208d5b887185865")
        self.assertEqual(HKDF(hashes.SHA256(), 42, salt, info).derive(ikm), okm)

    def test_unauthenticated_exchange_is_open_to_mitm(self):
        c, s = kx.unauthenticated_exchange()
        self.assertEqual(c, s)
        mitm = {}
        c, s = kx.unauthenticated_exchange(mitm)
        self.assertNotEqual(c, s)
        self.assertEqual((c, s), (mitm["with_client"], mitm["with_server"]))   # attacker holds both keys

    def test_authenticated_handshake(self):
        client, server = kx.authenticated_handshake({"key": P["portal_key"], "cert": P["portal_cert"]},
                                                    {"key": P["sarah_key"], "cert": P["sarah_cert"]}, trust(), NOW)
        rec = client.seal(b"GET /ehr/HVMC-004417")
        self.assertEqual(server.open(rec), b"GET /ehr/HVMC-004417")
        self.assertEqual(client.open(server.seal(b"200 OK")), b"200 OK")
        tampered = bytearray(client.seal(b"order 5 mg"))
        tampered[3] ^= 1
        with self.assertRaises(InvalidTag):
            server.open(bytes(tampered))

    def test_handshake_rejects_attacks(self):
        srv = {"key": P["portal_key"], "cert": P["portal_cert"]}
        cli = {"key": P["sarah_key"], "cert": P["sarah_cert"]}

        def swap_server_key(stage, m):          # MITM replaces the server's ephemeral key
            if stage == "server_hello":
                m = dict(m, eph=kx.x25519_keypair()[1])
            return m
        with self.assertRaises(kx.HandshakeError):
            kx.authenticated_handshake(srv, cli, trust(), NOW, tamper=swap_server_key)
        evil = lib_rsa.generate_private_key(65537, 2048)
        evil_root = pki.create_root(evil, NOW)
        evil_ca = pki.IssuingCA(evil, evil_root, os.path.join(tempfile.mkdtemp(), "r.json"))
        fake = evil_ca.issue(pki.make_csr(evil, "portal.hvmc.example", dns=["portal.hvmc.example"]),
                             "tls-server", NOW, "attacker")
        with self.assertRaises(kx.HandshakeError):   # impostor certificate for the same hostname
            kx.authenticated_handshake({"key": evil, "cert": fake}, cli, trust(), NOW)
        with self.assertRaises(kx.HandshakeError):   # Sarah's client certificate cannot act as the server
            kx.authenticated_handshake({"key": P["sarah_key"], "cert": P["sarah_cert"]}, cli, trust(), NOW)


# ======================================================================= DEMOS
def run_openssl(args, log, show=None, cwd=PKI_DIR):
    cmd = ["openssl"] + args
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    out = (r.stdout + r.stderr).strip()
    log.append("$ " + " ".join(cmd) + "\n" + (out if show is None else show(out)) + "\n")
    return r.returncode, out


def demo_keygen(out):
    print("\n=== Demo 1: RSA key pair generation (from scratch) ===")
    k = rsa.RSAPrivateKey(61, 53, 17)
    print(f"  toy key: p=61 q=53 n={k.n} lambda(n)=780 e=17 d={k.d}; encrypt 65 -> "
          f"{k.public_key.encrypt_raw(65)} -> decrypt {k.decrypt_raw(2790)}")
    timings = {}
    for bits in (2048, 3072, 4096):
        t = time.time()
        key = rsa.generate_keypair(bits)
        timings[bits] = round(time.time() - t, 2)
        print(f"  RSA-{bits}: generated in {timings[bits]}s, n has {key.n.bit_length()} bits, "
              f"p and q {key.p.bit_length()}/{key.q.bit_length()} bits, d has {key.d.bit_length()} bits, "
              f"|p-q| has {abs(key.p - key.q).bit_length()} bits (> {bits // 2 - 100} required)")
    lib = rsa.to_library(key)
    print(f"  the cryptography package loads the from-scratch RSA-4096 key: key_size={lib.key_size}")
    out["keygen_seconds"] = timings


def demo_key_management(out):
    print("\n=== Demo 2: Key management - storage, inventory, rotation ===")
    st = P["store"]
    print(f"  {'key id':24} {'algorithm':10} {'purpose':16} {'expires':11} {'status':8} fingerprint (SHA-256 of SPKI)")
    for r in st.keys.values():
        print(f"  {r['key_id']:24} {r['algorithm']:10} {r['purpose']:16} {r['expires'][:10]:11} {r['status']:8} "
              f"{r['fingerprint_sha256'][:24]}…")
    priv_dir = os.path.join(PKI_DIR, "private")
    for f in sorted(os.listdir(priv_dir)):
        if f.endswith(".pem"):
            p = os.path.join(priv_dir, f)
            with open(p, "rb") as fh:
                first = fh.readline().decode().strip()
            print(f"  {stat.filemode(os.stat(p).st_mode)}  private/{f:34} {first}")
    try:
        km.load_private_key(os.path.join(priv_dir, "portal-tls-2026.key.pem"), b"guess")
    except ValueError as e:
        print(f"  load with a wrong passphrase -> refused ({type(e).__name__}: {str(e)[:60]})")

    # rotation of the EHR data-encryption key
    st.generate("ehr-data-key-v1", "data-encryption", "EHR key service", NOW)
    env = km.hybrid_encrypt(st, "ehr-data-key-v1", RECORD, aad=b"HVMC-004417")
    print(f"  hybrid encryption of a {len(RECORD)}-byte discharge record: RSA-OAEP-wrapped key "
          f"{len(base64.b64decode(env['wrapped_key']))} bytes + AES-256-GCM ciphertext "
          f"{len(base64.b64decode(env['ciphertext']))} bytes")
    st.generate("ehr-data-key-v2", "data-encryption", "EHR key service", NOW)
    env2 = km.rewrap(st, env, "ehr-data-key-v2")
    st.set_status("ehr-data-key-v1", "retired", "rotated to ehr-data-key-v2 (ticket HVMC-PKI-CHG-402)", NOW)
    print(f"  rotation: data key rewrapped under v2; AES ciphertext unchanged = {env2['ciphertext'] == env['ciphertext']}")
    try:
        km.hybrid_encrypt(st, "ehr-data-key-v1", b"new record")
    except km.KeyPolicyError as e:
        print(f"  encrypt with retired v1 -> refused: {e}")
    print(f"  decrypt old envelope with retired v1 still works: {km.hybrid_decrypt(st, env) == RECORD}")
    st.set_status("ehr-data-key-v1", "destroyed", "all envelopes rewrapped to v2", NOW)
    try:
        km.hybrid_decrypt(st, env)
    except km.KeyPolicyError as e:
        print(f"  after destruction, v1 envelope -> {e}; v2 envelope decrypts: {km.hybrid_decrypt(st, env2) == RECORD}")
    out["inventory"] = list(st.keys.values())
    with open(os.path.join(HERE, "sample_envelope_v2.json"), "w") as f:
        json.dump(env2, f, indent=2)


def demo_encryption(out, ossl):
    print("\n=== Demo 3: Asymmetric encryption - textbook RSA vs RSA-OAEP ===")
    nums = P["store"].private("portal-tls-2026").private_numbers()
    k = rsa.RSAPrivateKey(nums.p, nums.q, nums.public_numbers.e)
    m = int.from_bytes(b"APPROVE 5", "big")
    c1, c2 = k.public_key.encrypt_raw(m), k.public_key.encrypt_raw(m)
    print(f"  textbook RSA is deterministic: same message twice -> identical ciphertext = {c1 == c2}")
    forged = c1 * pow(2, k.e, k.n) % k.n
    print(f"  textbook RSA is malleable: multiply ciphertext by 2^e -> decrypts to 2*m = {k.decrypt_raw(forged) == 2 * m}"
          f" (attacker changed the value without the key)")
    o1, o2 = rsa.oaep_encrypt(k.public_key, b"APPROVE 5"), rsa.oaep_encrypt(k.public_key, b"APPROVE 5")
    print(f"  OAEP is randomized: two encryptions differ = {o1 != o2}; both decrypt correctly = "
          f"{rsa.oaep_decrypt(k, o1) == rsa.oaep_decrypt(k, o2) == b'APPROVE 5'}")
    bad = bytearray(o1)
    bad[50] ^= 0x01
    try:
        rsa.oaep_decrypt(k, bytes(bad))
    except rsa.DecryptionError:
        print("  OAEP rejects a modified ciphertext with a single generic 'decryption error'")
    print(f"  size limit: RSA-2048 + OAEP-SHA-256 carries at most {k.k - 66} bytes -> HVMC uses hybrid encryption")

    # OpenSSL interoperability, both directions
    tmp = tempfile.mkdtemp()
    msg = b"HVMC-004417 lab result key"
    with open(os.path.join(tmp, "from_scratch.bin"), "wb") as f:
        f.write(rsa.oaep_encrypt(k.public_key, msg))
    # LibreSSL 3.3 pkeyutl ignores -passin, so `openssl pkey` decrypts the key and pipes it in:
    # the unencrypted key exists only in the pipe, never on disk
    pp = os.path.join(PKI_DIR, "private", ".passphrase")
    key_pem = subprocess.run(["openssl", "pkey", "-in", "private/portal-tls-2026.key.pem", "-passin", "file:" + pp],
                             capture_output=True, cwd=PKI_DIR).stdout
    cmd = ["pkeyutl", "-decrypt", "-inkey", "/dev/stdin", "-pkeyopt", "rsa_padding_mode:oaep",
           "-pkeyopt", "rsa_oaep_md:sha256", "-pkeyopt", "rsa_mgf1_md:sha256", "-in", os.path.join(tmp, "from_scratch.bin")]
    r = subprocess.run(["openssl"] + cmd, input=key_pem, capture_output=True, cwd=PKI_DIR)
    dec = (r.stdout + r.stderr).decode().strip()
    rc = r.returncode
    ossl.append("$ openssl pkey -in private/portal-tls-2026.key.pem -passin file:private/.passphrase | openssl "
                + " ".join(cmd).replace(tmp + "/", "") + "\n" + dec + "\n")
    ok1 = rc == 0 and dec == msg.decode()
    with open(os.path.join(tmp, "msg.txt"), "wb") as f:
        f.write(b"encrypted by OpenSSL")
    rc, _ = run_openssl(["pkeyutl", "-encrypt", "-pubin", "-inkey", "public/portal-tls-2026.pub.pem",
                         "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
                         "-pkeyopt", "rsa_mgf1_md:sha256", "-in", os.path.join(tmp, "msg.txt"),
                         "-out", os.path.join(tmp, "from_openssl.bin")], ossl, show=lambda o: o or "(ciphertext written)")
    with open(os.path.join(tmp, "from_openssl.bin"), "rb") as f:
        ok2 = rc == 0 and rsa.oaep_decrypt(k, f.read()) == b"encrypted by OpenSSL"
    ossl[:] = [entry.replace(tmp + "/", "") for entry in ossl]
    shutil.rmtree(tmp)
    print(f"  interop: OpenSSL decrypts from-scratch OAEP = {ok1}; from-scratch decrypts OpenSSL OAEP = {ok2}")
    out["openssl_oaep_interop"] = ok1 and ok2


def demo_pki(out, ossl):
    print("\n=== Demo 4: The HVMC PKI ===")
    rows = []
    for c in (P["root_cert"], P["issuing_cert"], P["portal_cert"], P["sarah_cert"]):
        d = pki.describe(c)
        rows.append(d)
        print(f"  {d['subject_cn']:22} issued by {d['issuer_cn']:18} {d['key']:9} {d['signature']:24} "
              f"CA={str(d['ca']):5} pathLen={str(d['path_len']):4} until {d['not_after']}")
    out["certificates"] = rows

    ca = pki.IssuingCA(P["issuing_key"], P["issuing_cert"], os.path.join(tempfile.mkdtemp(), "reg.json"))
    k = lib_rsa.generate_private_key(65537, 2048)
    tests = [("portal.evil.example", dict(dns=["portal.evil.example"]), "tls-server"),
             ("*.hvmc.example", dict(dns=["*.hvmc.example"]), "tls-server"),
             ("RSA-1024 key", dict(dns=["lab.hvmc.example"]), "tls-server"),
             ("someone@gmail.com", dict(email="someone@gmail.com"), "client-auth")]
    out["csr_rejections"] = []
    for label, kw, prof in tests:
        key = lib_rsa.generate_private_key(65537, 1024) if "1024" in label else k
        try:
            ca.issue(pki.make_csr(key, "request", **kw), prof, NOW, "demo")
        except pki.PolicyViolation as e:
            print(f"  CSR for {label:20} -> rejected: {e}")
            out["csr_rejections"].append([label, str(e)])

    ok, checks = pki.validate_path(P["portal_cert"], [P["issuing_cert"]], [P["root_cert"]], NOW,
                                   ExtendedKeyUsageOID.SERVER_AUTH, "portal.hvmc.example", P["crls"])
    print(f"  path validation of portal.hvmc.example: {'VALID' if ok else 'INVALID'} ({len(checks)} checks)")
    for label, passed, detail in checks:
        print(f"    [{'pass' if passed else 'FAIL'}] {label}" + (f"  ({detail})" if detail else ""))
    out["path_checks"] = checks
    chain = pki.library_verify_server(P["portal_cert"], [P["issuing_cert"]], P["root_cert"], "portal.hvmc.example", NOW)
    print(f"  cryptography.x509.verification agrees: chain of {len(chain)} certificates")

    rc1, o1 = run_openssl(["verify", "-CAfile", "certs/hvmc-root-ca-r1.crt.pem", "-untrusted",
                           "certs/hvmc-issuing-ca-1.crt.pem", "-purpose", "sslserver",
                           "certs/portal.hvmc.example.crt.pem"], ossl)
    rc2, o2 = run_openssl(["verify", "-CAfile", "certs/hvmc-root-ca-r1.crt.pem", "-untrusted",
                           "certs/hvmc-issuing-ca-1.crt.pem", "-purpose", "sslclient", "certs/sarah.chen.crt.pem"], ossl)
    rc3, o3 = run_openssl(["verify", "-CAfile", "certs/hvmc-root-ca-r1.crt.pem", "-untrusted",
                           "certs/hvmc-issuing-ca-1.crt.pem", "-purpose", "sslserver", "certs/sarah.chen.crt.pem"], ossl)
    print(f"  openssl verify: portal (sslserver) -> {o1.splitlines()[-1]}; sarah (sslclient) -> {o2.splitlines()[-1]}; "
          f"sarah as sslserver -> rejected = {rc3 != 0}")
    run_openssl(["x509", "-in", "certs/portal.hvmc.example.crt.pem", "-noout", "-text"], ossl,
                show=lambda o: "\n".join(l for l in o.splitlines() if "Modulus" not in l and not l.startswith("                    ")))
    run_openssl(["crl", "-in", "crl/hvmc-issuing-ca-1.crl.pem", "-noout", "-text"], ossl,
                show=lambda o: "\n".join(o.splitlines()[:14]))
    run_openssl(["req", "-in", "csr/portal.hvmc.example.csr.pem", "-noout", "-verify", "-subject"], ossl)
    out["openssl_verify"] = {"portal_sslserver": o1.splitlines()[-1], "sarah_sslclient": o2.splitlines()[-1],
                             "sarah_as_server_rejected": rc3 != 0}


def demo_key_exchange(out):
    print("\n=== Demo 5: Secure key exchange ===")
    mitm = {}
    c, s = kx.unauthenticated_exchange(mitm)
    print(f"  unauthenticated X25519 with an attacker in the middle: client and server keys differ = {c != s}; "
          f"attacker holds the client's key = {mitm['with_client'] == c} and the server's key = {mitm['with_server'] == s}"
          " -> it can read and re-encrypt everything")
    log = []
    cli_ch, srv_ch = kx.authenticated_handshake({"key": P["portal_key"], "cert": P["portal_cert"]},
                                                {"key": P["sarah_key"], "cert": P["sarah_cert"]}, trust(), NOW, log=log)
    for i, line in enumerate(log, 1):
        print(f"  {i}. {line}")
    req = cli_ch.seal(b"GET /ehr/patients/HVMC-004417/discharge")
    print(f"  Sarah -> portal: {len(req)}-byte record {req[:12].hex()}… -> server reads {srv_ch.open(req).decode()!r}")
    rep = srv_ch.seal(RECORD)
    print(f"  portal -> Sarah: {len(rep)}-byte record -> client reads {len(cli_ch.open(rep))} bytes of the record")
    try:
        srv_ch.open(req)
    except InvalidTag:
        print("  replaying Sarah's first record -> rejected (sequence-number nonce, GCM tag fails)")

    def swap(stage, m):
        return dict(m, eph=kx.x25519_keypair()[1]) if stage == "server_hello" else m
    results = {}
    try:
        kx.authenticated_handshake({"key": P["portal_key"], "cert": P["portal_cert"]},
                                   {"key": P["sarah_key"], "cert": P["sarah_cert"]}, trust(), NOW, tamper=swap)
    except kx.HandshakeError as e:
        results["mitm_key_swap"] = str(e)
        print(f"  attacker swaps the server's ephemeral key -> {e}")
    evil = lib_rsa.generate_private_key(65537, 2048)
    evil_root = pki.create_root(evil, NOW)
    fake = pki.IssuingCA(evil, evil_root, os.path.join(tempfile.mkdtemp(), "r.json")).issue(
        pki.make_csr(evil, "portal.hvmc.example", dns=["portal.hvmc.example"]), "tls-server", NOW, "attacker")
    try:
        kx.authenticated_handshake({"key": evil, "cert": fake}, {"key": P["sarah_key"], "cert": P["sarah_cert"]},
                                   trust(), NOW)
    except kx.HandshakeError as e:
        results["impostor_certificate"] = str(e)
        print(f"  attacker presents its own certificate for portal.hvmc.example -> {e}")

    # forward secrecy
    portal_pub = rsa.from_library_public(P["portal_key"].public_key())
    session_key, recorded = kx.rsa_key_transport(portal_pub, rsa.oaep_encrypt)
    nums = P["portal_key"].private_numbers()
    stolen = rsa.RSAPrivateKey(nums.p, nums.q, nums.public_numbers.e)        # server key leaked a year later
    recovered = rsa.oaep_decrypt(stolen, recorded, label=b"HVMC key transport")
    print(f"  RSA key transport: a recorded session + the server's RSA key stolen later -> session key recovered = "
          f"{recovered == session_key} (no forward secrecy)")
    print("  ephemeral X25519: the recording holds only public values and signatures; the ephemeral private keys "
          "were deleted, so the stolen RSA key cannot rebuild the session key (forward secrecy)")
    results["rsa_transport_recovered_after_key_theft"] = recovered == session_key
    out["key_exchange"] = {"handshake_log": log, **results}


# ======================================================================= MAIN
class Tee(io.TextIOBase):
    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for st in self.streams:
            st.write(s)
        return len(s)


def main():
    global P
    buf = io.StringIO()
    real = sys.stdout
    sys.stdout = Tee(real, buf)
    env = (f"Python {platform.python_version()} on {platform.system()} {platform.machine()}, "
           f"{NOW.astimezone().strftime('%Y-%m-%d %H:%M')}; cryptography package: {cryptography.__version__}; "
           f"{subprocess.run(['openssl', 'version'], capture_output=True, text=True).stdout.strip()}")
    print("HVMC Public Key Cryptography - test and demo run")
    print(env)
    print("\n=== Building the HVMC PKI in pki/ ===")
    P = build_hvmc_pki(PKI_DIR)

    print("\n=== Unit tests ===")
    stream = io.StringIO()
    suite = unittest.TestSuite()
    for case in (TestRSA, TestKeyManagement, TestPKI, TestKeyExchange):
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(case))
    res = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    print(stream.getvalue().rstrip())
    print(f"tests run: {res.testsRun}, failures: {len(res.failures)}, errors: {len(res.errors)}, skipped: {len(res.skipped)}")
    RESULTS["tests"] = {"run": res.testsRun, "failures": len(res.failures), "errors": len(res.errors),
                        "passed": res.testsRun - len(res.failures) - len(res.errors)}

    ossl = []
    demo_keygen(RESULTS["demos"])
    demo_key_management(RESULTS["demos"])
    demo_encryption(RESULTS["demos"], ossl)
    demo_pki(RESULTS["demos"], ossl)
    demo_key_exchange(RESULTS["demos"])

    sys.stdout = real
    RESULTS["environment"] = env
    with open(os.path.join(HERE, "results.txt"), "w") as f:
        f.write(buf.getvalue())
    with open(os.path.join(HERE, "results.json"), "w") as f:
        json.dump(RESULTS, f, indent=2, default=str)
    with open(os.path.join(HERE, "openssl_checks.txt"), "w") as f:
        f.write("HVMC PKI - independent checks with the OpenSSL command line (run from pki/)\n" + env + "\n\n")
        f.write("\n".join(ossl))
    return res.wasSuccessful()


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
