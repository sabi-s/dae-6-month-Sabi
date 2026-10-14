"""
Tests and demonstrations for HVMC password hashing, HMAC and file integrity.

Horizon Valley Medical Center (HVMC) - Cryptography 1: Hash Functions and Integrity
Author: Sabitha S Karanavar

Run:  python3 test_and_demo.py
Writes results.txt, results.json and a sample_export/ folder used by the FIM demo.
If the optional `argon2-cffi` and `bcrypt` packages are installed they are included
in the cost comparison (skipped otherwise).
"""
import hashlib
import hmac as std_hmac
import json
import os
import platform
import shutil
import sys
import tempfile
import time
import unittest

from file_integrity import create_baseline, merkle_proof, verify_baseline, verify_proof
from hmac_auth import HMAC, AuthError, Receiver, hmac_sha256, sign_message, verify_tag
from password_hashing import PasswordHasher, check_password_policy, pbkdf2_sha256

try:
    import argon2
    import bcrypt
    HAVE_EXTRA = True
except ImportError:
    HAVE_EXTRA = False

RESULTS = {}


# ======================================================================= TESTS
class TestHMAC(unittest.TestCase):
    def test_rfc4231_vectors(self):
        cases = [
            (b"\x0b" * 20, b"Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
            (b"Jefe", b"what do ya want for nothing?", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
            (b"\xaa" * 20, b"\xdd" * 50, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
            (b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First",
             "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
        ]
        for key, msg, tag in cases:
            self.assertEqual(hmac_sha256(key, msg).hex(), tag)

    def test_matches_stdlib(self):
        for n in (0, 1, 32, 64, 65, 200):
            k, m = os.urandom(n), os.urandom(500)
            self.assertEqual(hmac_sha256(k, m), std_hmac.new(k, m, hashlib.sha256).digest())
            self.assertEqual(HMAC(k, hashlib.sha512).digest(m), std_hmac.new(k, m, hashlib.sha512).digest())

    def test_verify_tag(self):
        k = os.urandom(32)
        t = hmac_sha256(k, b"msg")
        self.assertTrue(verify_tag(k, b"msg", t))
        self.assertFalse(verify_tag(k, b"msG", t))
        self.assertFalse(verify_tag(os.urandom(32), b"msg", t))


class TestPBKDF2(unittest.TestCase):
    def test_rfc7914_vectors(self):
        self.assertEqual(pbkdf2_sha256(b"passwd", b"salt", 1, 64).hex(),
                         "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
                         "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")
        self.assertEqual(pbkdf2_sha256(b"Password", b"NaCl", 80000, 64).hex(),
                         "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
                         "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d")

    def test_matches_hashlib(self):
        for it, dk in ((1, 32), (2, 20), (1000, 32), (1000, 48)):
            p, s = os.urandom(12), os.urandom(16)
            self.assertEqual(pbkdf2_sha256(p, s, it, dk), hashlib.pbkdf2_hmac("sha256", p, s, it, dk))


class TestPasswordHasher(unittest.TestCase):
    def setUp(self):
        self.ph = PasswordHasher(iterations=10_000)

    def test_round_trip_and_wrong_password(self):
        h = self.ph.hash("correct horse battery staple")
        self.assertTrue(self.ph.verify(h, "correct horse battery staple"))
        self.assertFalse(self.ph.verify(h, "correct horse battery stapler"))

    def test_unique_salts(self):
        self.assertNotEqual(self.ph.hash("same"), self.ph.hash("same"))

    def test_needs_rehash(self):
        self.assertTrue(PasswordHasher(iterations=600_000).needs_rehash(self.ph.hash("x")))
        self.assertFalse(self.ph.needs_rehash(self.ph.hash("x")))

    def test_pepper(self):
        peppered = PasswordHasher(iterations=10_000, pepper=os.urandom(32))
        h = peppered.hash("example-password")
        self.assertTrue(peppered.verify(h, "example-password"))
        self.assertFalse(self.ph.verify(h, "example-password"))     # unusable without the pepper

    def test_malformed(self):
        self.assertFalse(self.ph.verify("not-a-hash", "x"))


class TestPolicy(unittest.TestCase):
    def test_rejects_weak(self):
        for pw in ("Password1", "Winter2026!", "short", "hvmc-nurse-portal-2026", "aaaaaaaaaaaaaaaaaa"):
            self.assertTrue(check_password_policy(pw), pw)
        self.assertIn("contains the username", check_password_policy("lisatran-loves-hiking-1", "lisa.tran"))

    def test_accepts_passphrase(self):
        self.assertEqual(check_password_policy("copper kettle meadow sunrise"), [])


class TestAuthenticatedMessages(unittest.TestCase):
    def setUp(self):
        self.keys = {"lis-2026-10": os.urandom(32)}
        self.rx = Receiver(self.keys)

    def test_valid(self):
        m = sign_message(self.keys, "lis-2026-10", "LIS", {"mrn": "HVMC-004417", "K": "4.1"})
        self.assertEqual(self.rx.accept(m)["K"], "4.1")

    def test_rejections(self):
        m = sign_message(self.keys, "lis-2026-10", "LIS", {"mrn": "HVMC-004417", "K": "4.1"})
        self.rx.accept(m)
        with self.assertRaises(AuthError):
            self.rx.accept(m)                                          # replay
        tampered = sign_message(self.keys, "lis-2026-10", "LIS", {"mrn": "HVMC-004417", "K": "4.1"})
        tampered["body"]["K"] = "7.1"
        with self.assertRaises(AuthError):
            self.rx.accept(tampered)
        old = sign_message(self.keys, "lis-2026-10", "LIS", {"x": 1})
        with self.assertRaises(AuthError):
            self.rx.accept(old, now=old["header"]["ts"] + 3600)        # expired
        with self.assertRaises(AuthError):
            Receiver({}).accept(sign_message(self.keys, "lis-2026-10", "LIS", {"x": 1}))   # unknown key


class TestFileIntegrity(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        for n in ("a.txt", "sub/b.txt", "sub/c.txt"):
            os.makedirs(os.path.dirname(os.path.join(self.dir, n)), exist_ok=True)
            with open(os.path.join(self.dir, n), "w") as f:
                f.write(n * 100)
        self.key = os.urandom(32)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_clean_and_changes(self):
        m = create_baseline(self.dir, self.key)
        self.assertTrue(verify_baseline(self.dir, m, self.key)["clean"])
        os.utime(os.path.join(self.dir, "a.txt"), (0, 0))                  # metadata only
        self.assertTrue(verify_baseline(self.dir, m, self.key)["clean"])
        with open(os.path.join(self.dir, "a.txt"), "a") as f:
            f.write("!")
        os.remove(os.path.join(self.dir, "sub/b.txt"))
        open(os.path.join(self.dir, "new.txt"), "w").close()
        r = verify_baseline(self.dir, m, self.key)
        self.assertEqual((r["modified"], r["deleted"], r["added"]), (["a.txt"], ["sub/b.txt"], ["new.txt"]))

    def test_manifest_tamper_detected(self):
        m = create_baseline(self.dir, self.key)
        m["files"]["a.txt"]["sha256"] = "00" * 32
        self.assertFalse(verify_baseline(self.dir, m, self.key)["manifest_ok"])
        self.assertFalse(verify_baseline(self.dir, create_baseline(self.dir, self.key), os.urandom(32))["manifest_ok"])

    def test_merkle_proof(self):
        m = create_baseline(self.dir, self.key)
        for p, v in m["files"].items():
            self.assertTrue(verify_proof(p, v["sha256"], merkle_proof(m["files"], p), m["merkle_root"]))
        self.assertFalse(verify_proof("a.txt", "11" * 32, merkle_proof(m["files"], "a.txt"), m["merkle_root"]))


# ======================================================================= DEMOS
def log(*a):
    print(*a)
    with open("results.txt", "a") as f:
        print(*a, file=f)


def demo_storage():
    log("\n=== Demo 1: secure password storage format ===")
    ph = PasswordHasher()
    t = time.perf_counter()
    h1 = ph.hash("copper kettle meadow sunrise")
    ms = (time.perf_counter() - t) * 1000
    h2 = ph.hash("copper kettle meadow sunrise")
    log("stored hash 1:", h1)
    log("stored hash 2:", h2)
    log(f"same password, different salts -> different stored values: {h1 != h2}")
    log(f"verify correct password: {ph.verify(h1, 'copper kettle meadow sunrise')}; "
        f"verify wrong password: {ph.verify(h1, 'copper kettle meadow sunset')}")
    log(f"cost of one login check at 600,000 iterations: {ms:.0f} ms (acceptable for a user, expensive at scale)")
    RESULTS["storage"] = dict(h1=h1, h2=h2, different=h1 != h2, ms=round(ms))


def demo_cost():
    log("\n=== Demo 2: cost per password-hash computation (this Mac, one core) ===")
    pw, salt = b"copper kettle meadow sunrise", os.urandom(16)

    def per_call(fn, n):
        t = time.perf_counter()
        for _ in range(n):
            fn()
        return (time.perf_counter() - t) / n

    rows = [("MD5 (unsuitable)", per_call(lambda: hashlib.md5(salt + pw).digest(), 100_000)),
            ("SHA-256 (unsuitable)", per_call(lambda: hashlib.sha256(salt + pw).digest(), 100_000)),
            ("PBKDF2-HMAC-SHA256, 600,000 iterations", per_call(lambda: hashlib.pbkdf2_hmac("sha256", pw, salt, 600_000), 3))]
    if HAVE_EXTRA:
        rows.append(("bcrypt, cost 12", per_call(lambda: bcrypt.hashpw(pw, bcrypt.gensalt(12)), 3)))
        a2 = argon2.PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
        rows.append(("Argon2id, 19 MiB, t=2, p=1", per_call(lambda: a2.hash(pw), 5)))
    out = []
    for name, sec in rows:
        log(f"{name:<42} {sec * 1000:>10.4f} ms per hash")
        out.append(dict(name=name, ms=sec * 1000))
    log("A purpose-built password hash is deliberately slow (and Argon2id also memory-hard), which is what")
    log("makes large-scale guessing against a stolen database expensive. Fast hashes are for files, not passwords.")
    RESULTS["cost"] = out
    RESULTS["extra"] = HAVE_EXTRA


def demo_pepper_and_upgrade():
    log("\n=== Demo 3: pepper and automatic cost upgrade ===")
    pepper = os.urandom(32)
    peppered = PasswordHasher(iterations=10_000, pepper=pepper)
    h = peppered.hash("copper kettle meadow sunrise")
    log("with pepper (kept in Key Vault): verify ok =", peppered.verify(h, "copper kettle meadow sunrise"))
    log("database copy alone, no pepper: verify ok =", PasswordHasher(iterations=10_000).verify(h, "copper kettle meadow sunrise"))
    old = PasswordHasher(iterations=100_000).hash("copper kettle meadow sunrise")
    current = PasswordHasher()
    log("legacy hash:", old.split("$")[2], "-> needs_rehash:", current.needs_rehash(old))
    new = current.hash("copper kettle meadow sunrise") if current.verify(old, "copper kettle meadow sunrise") else old
    log("after next successful login:", new.split("$")[2], "-> needs_rehash:", current.needs_rehash(new))
    RESULTS["pepper"] = dict(with_pepper=True, without=PasswordHasher(iterations=10_000).verify(h, "copper kettle meadow sunrise"),
                             old=old.split("$")[2], new=new.split("$")[2])


def demo_policy():
    log("\n=== Demo 4: NIST SP 800-63B password policy screening ===")
    samples = [("Password1", ""), ("Winter2026!", ""), ("Hvmc2026!", ""), ("Tr0ub4dor&3", ""),
               ("lisatran-portal-login", "lisa.tran"), ("aaaaaaaaaaaaaaaaaaaa", ""), ("copper kettle meadow sunrise", ""),
               ("my dog Biscuit hates thunderstorms", "")]
    rows = []
    for pw, user in samples:
        p = check_password_policy(pw, user)
        rows.append(dict(pw=pw, user=user, ok=not p, problems=p))
        log(f"{pw!r:<38} {'ACCEPT' if not p else 'REJECT: ' + '; '.join(p)}")
    RESULTS["policy"] = rows


def demo_hmac():
    log("\n=== Demo 5: HMAC-authenticated LIS -> EHR messages ===")
    keys = {"lis-2026-10": os.urandom(32)}
    rx = Receiver(keys)
    body = {"mrn": "HVMC-004417", "test": "Potassium", "value": "4.1", "unit": "mmol/L", "verified_by": "Elena Petrova"}
    rows = []

    def attempt(label, msg, **kw):
        try:
            rx.accept(msg, **kw)
            res = "ACCEPTED"
        except AuthError as e:
            res = f"REJECTED - {e}"
        rows.append((label, res))
        log(f"{label:<40} {res}")

    m = sign_message(keys, "lis-2026-10", "LIS", body)
    log("tag:", m["tag"])
    attempt("1. genuine message", m)
    attempt("2. same message sent again (replay)", m)
    t = sign_message(keys, "lis-2026-10", "LIS", dict(body))
    t["body"]["value"] = "7.1"
    attempt("3. value changed 4.1 -> 7.1 in transit", t)
    e = sign_message(keys, "lis-2026-10", "LIS", dict(body))
    attempt("4. delivered 1 hour late", e, now=e["header"]["ts"] + 3600)
    f = sign_message({"lis-2026-09": os.urandom(32)}, "lis-2026-09", "LIS", dict(body))
    attempt("5. signed with a retired key id", f)
    RESULTS["hmac"] = dict(tag=m["tag"], rows=rows)


SAMPLE = {
    "lab_results/2026-10-12_chemistry.csv": "mrn,test,value,unit,verified_by\nHVMC-004417,Potassium,4.1,mmol/L,Elena Petrova\n"
                                            "HVMC-004418,Sodium,139,mmol/L,Priya Nair\nHVMC-004419,Glucose,5.6,mmol/L,Thomas Wright\n",
    "lab_results/2026-10-12_hematology.csv": "mrn,test,value,unit,verified_by\nHVMC-004417,Hemoglobin,13.2,g/dL,Elena Petrova\n",
    "ehr_exports/discharge_HVMC-004417.json": '{"mrn":"HVMC-004417","attending":"Sarah Chen","disposition":"home"}\n',
    "ehr_exports/medication_HVMC-004417.json": '{"mrn":"HVMC-004417","drug":"lisinopril","dose":"10 mg daily","pharmacist":"David Patel"}\n',
    "audit/ehr_access_2026-10-12.log": "2026-10-12T08:01:12Z sarah.chen VIEW HVMC-004417\n"
                                       "2026-10-12T08:15:40Z robert.kim VIEW HVMC-004417\n"
                                       "2026-10-12T09:42:03Z elena.petrova UPDATE HVMC-004417 lab\n",
}


def write_sample(folder):
    shutil.rmtree(folder, ignore_errors=True)
    for rel, text in SAMPLE.items():
        path = os.path.join(folder, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)


def demo_fim():
    log("\n=== Demo 6: file integrity monitoring of an EHR export folder ===")
    folder, key = "sample_export", os.urandom(32)
    write_sample(folder)
    t = time.perf_counter()
    m = create_baseline(folder, key)
    log(f"baseline: {m['file_count']} files in {(time.perf_counter() - t) * 1000:.1f} ms; merkle root {m['merkle_root'][:24]}…; sealed with HMAC")
    steps = []

    def check(label):
        r = verify_baseline(folder, m, key)
        summary = (f"clean={r['clean']} manifest_ok={r['manifest_ok']} modified={r['modified']} "
                   f"deleted={r['deleted']} added={r['added']}")
        steps.append(dict(label=label, clean=r["clean"], manifest_ok=r["manifest_ok"], modified=r["modified"],
                          deleted=r["deleted"], added=r["added"]))
        log(f"{label}\n    -> {summary}")

    check("A. no changes")
    os.utime(os.path.join(folder, "audit/ehr_access_2026-10-12.log"), (0, 0))
    check("B. timestamps changed only (file copied / touched)")
    p = os.path.join(folder, "lab_results/2026-10-12_chemistry.csv")
    with open(p) as f:
        txt = f.read()
    with open(p, "w") as f:
        f.write(txt.replace("Potassium,4.1", "Potassium,7.1"))
    check("C. one lab value edited (4.1 -> 7.1)")
    os.remove(os.path.join(folder, "audit/ehr_access_2026-10-12.log"))
    with open(os.path.join(folder, "ehr_exports/unexpected_file.json"), "w") as f:
        f.write("{}\n")
    check("D. audit log deleted and an unexpected file added")
    m["files"]["lab_results/2026-10-12_chemistry.csv"]["sha256"] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    check("E. manifest edited to match the changed lab file (no HMAC key)")
    write_sample(folder)
    clean = create_baseline(folder, key)
    path = "lab_results/2026-10-12_hematology.csv"
    proof = merkle_proof(clean["files"], path)
    ok = verify_proof(path, clean["files"][path]["sha256"], proof, clean["merkle_root"])
    bad = verify_proof(path, "00" * 32, proof, clean["merkle_root"])
    log(f"F. Merkle proof for {path}: {len(proof)} sibling hashes; genuine file verifies: {ok}; altered digest verifies: {bad}")
    RESULTS["fim"] = dict(files=clean["file_count"], steps=steps, proof_len=len(proof), proof_ok=ok, proof_bad=bad,
                          root=clean["merkle_root"])

    t = time.perf_counter()
    h = hashlib.sha256()
    block = os.urandom(1024 * 1024)
    for _ in range(100):
        h.update(block)
    sec = time.perf_counter() - t
    log(f"G. SHA-256 throughput: {100 / sec:,.0f} MB/s (100 MB hashed in {sec * 1000:.0f} ms)")
    RESULTS["throughput"] = round(100 / sec)


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    open("results.txt", "w").close()
    log("HVMC Hash Functions and Integrity - test and demo run")
    log(f"Python {platform.python_version()} on {platform.system()} {platform.machine()}, {time.strftime('%Y-%m-%d %H:%M')}; "
        f"argon2/bcrypt: {'installed' if HAVE_EXTRA else 'not installed (comparison rows skipped)'}")
    log("\n=== Unit tests ===")
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    names = [t.id().split(".", 1)[1] for group in suite for t in group]
    with open("results.txt", "a") as f:
        res = unittest.TextTestRunner(stream=f, verbosity=2).run(suite)
    log(f"tests run: {res.testsRun}, failures: {len(res.failures)}, errors: {len(res.errors)}")
    RESULTS["tests"] = dict(run=res.testsRun, failures=len(res.failures), errors=len(res.errors), names=names)
    if not res.wasSuccessful():
        for _, tb in res.failures + res.errors:
            print(tb)
    for demo in (demo_storage, demo_cost, demo_pepper_and_upgrade, demo_policy, demo_hmac, demo_fim):
        demo()
    with open("results.json", "w") as f:
        json.dump(RESULTS, f, indent=2)
    sys.exit(0 if res.wasSuccessful() else 1)
