"""
Tests and security demonstrations for the from-scratch SHA-256 and Diffie-Hellman.

Horizon Valley Medical Center (HVMC) - Cryptography 1: Cryptographic Fundamentals
Author: Sabitha S Karanavar

Run:  python3 test_and_demo.py
Writes a readable log to results.txt and the numbers to results.json.
"""
import hashlib
import json
import os
import platform
import statistics
import sys
import time
import unittest

from diffie_hellman import (DHParty, G, P_2048, Q_2048, brute_force_dlog, is_probable_prime,
                            mod_pow, random_safe_prime)
from sha256 import digest_to_state, hmac_sha256, pad, sha256, sha256_hex

RESULTS = {}

# Official NIST / FIPS 180-4 example vectors
NIST_VECTORS = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    (b"a" * 1_000_000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
]

LAB_RESULT = (b'{"mrn":"HVMC-004417","test":"Potassium","value":"4.1","unit":"mmol/L",'
              b'"verified_by":"Elena Petrova","ts":"2026-10-13T09:42:00Z"}')


# ======================================================================= TESTS
class TestSHA256(unittest.TestCase):
    def test_nist_vectors(self):
        for msg, expected in NIST_VECTORS:
            self.assertEqual(sha256_hex(msg), expected)

    def test_matches_hashlib_random(self):
        for n in range(0, 300):           # every length 0..299 crosses all padding cases
            msg = os.urandom(n)
            self.assertEqual(sha256(msg), hashlib.sha256(msg).digest())

    def test_padding_is_block_aligned(self):
        for n in range(0, 200):
            self.assertEqual((n + len(pad(n))) % 64, 0)

    def test_hmac_matches_stdlib(self):
        import hmac
        for _ in range(50):
            k, m = os.urandom(32), os.urandom(100)
            self.assertEqual(hmac_sha256(k, m), hmac.new(k, m, hashlib.sha256).digest())


class TestDiffieHellman(unittest.TestCase):
    def test_mod_pow_matches_builtin(self):
        for _ in range(200):
            b, e, m = (int.from_bytes(os.urandom(64), "big") for _ in range(3))
            m |= 1
            self.assertEqual(mod_pow(b, e, m), pow(b, e, m))

    def test_rfc3526_prime_known_hex(self):
        h = format(P_2048, "x").upper()
        self.assertEqual(P_2048.bit_length(), 2048)
        self.assertTrue(h.startswith("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"))
        self.assertTrue(h.endswith("15728E5A8AACAA68FFFFFFFFFFFFFFFF"))

    def test_rfc3526_prime_is_safe_prime(self):
        self.assertTrue(is_probable_prime(P_2048))
        self.assertTrue(is_probable_prime(Q_2048))

    def test_generator_order_is_q(self):
        self.assertEqual(mod_pow(G, Q_2048, P_2048), 1)

    def test_miller_rabin_known_values(self):
        self.assertTrue(is_probable_prime(2**127 - 1))                 # Mersenne prime
        self.assertFalse(is_probable_prime(561))                       # Carmichael number
        self.assertFalse(is_probable_prime((2**61 - 1) * (2**89 - 1)))  # product of two primes

    def test_shared_key_agreement(self):
        for _ in range(5):
            a, b = DHParty("EHR"), DHParty("LIS")
            self.assertEqual(a.session_key(b.public), b.session_key(a.public))

    def test_rejects_bad_public_keys(self):
        a = DHParty("EHR")
        for bad in (0, 1, P_2048 - 1, P_2048):
            with self.assertRaises(ValueError):
                a.shared_secret(bad)

    def test_toy_example_p23(self):
        p, g, a, b = 23, 5, 6, 15
        A, B = mod_pow(g, a, p), mod_pow(g, b, p)
        self.assertEqual((A, B), (8, 19))
        self.assertEqual(mod_pow(B, a, p), mod_pow(A, b, p))
        self.assertEqual(mod_pow(B, a, p), 2)


# ======================================================================= DEMOS
def log(*a):
    print(*a)
    with open("results.txt", "a") as f:
        print(*a, file=f)


def bit_diff(x, y):
    return sum(bin(a ^ b).count("1") for a, b in zip(x, y))


def demo_hvmc_integrity():
    log("\n=== Demo 1: integrity of an HVMC lab result with SHA-256 ===")
    d1 = sha256_hex(LAB_RESULT)
    tampered = LAB_RESULT.replace(b'"4.1"', b'"7.1"')
    d2 = sha256_hex(tampered)
    log("original :", LAB_RESULT.decode())
    log("digest   :", d1)
    log("tampered : value 4.1 -> 7.1 (dangerous hyperkalemia)")
    log("digest   :", d2)
    log("bits that changed:", bit_diff(bytes.fromhex(d1), bytes.fromhex(d2)), "of 256")
    RESULTS["integrity"] = dict(original=d1, tampered=d2, bits=bit_diff(bytes.fromhex(d1), bytes.fromhex(d2)))


def demo_avalanche(trials=1000):
    log(f"\n=== Demo 2: avalanche effect ({trials} one-bit flips) ===")
    diffs = []
    for _ in range(trials):
        m = bytearray(os.urandom(64))
        h1 = sha256(bytes(m))
        i = int.from_bytes(os.urandom(2), "big") % (len(m) * 8)
        m[i // 8] ^= 1 << (i % 8)
        diffs.append(bit_diff(h1, sha256(bytes(m))))
    mean, sd = statistics.mean(diffs), statistics.pstdev(diffs)
    log(f"mean bits changed = {mean:.2f} (ideal 128), std dev = {sd:.2f} (ideal 8.0), min = {min(diffs)}, max = {max(diffs)}")
    RESULTS["avalanche"] = dict(trials=trials, mean=round(mean, 2), sd=round(sd, 2), min=min(diffs), max=max(diffs))


def demo_birthday(bit_sizes=(16, 20, 24), trials=20):
    log("\n=== Demo 3: birthday attack on truncated SHA-256 ===")
    rows = []
    for n in bit_sizes:
        counts = []
        for t in range(trials):
            seen, i = {}, 0
            prefix = os.urandom(8)
            while True:
                tag = sha256(prefix + i.to_bytes(8, "big"))[: n // 8 if n % 8 == 0 else n // 8 + 1]
                tag = int.from_bytes(tag, "big") >> ((8 - n % 8) % 8)
                if tag in seen:
                    break
                seen[tag] = i
                i += 1
            counts.append(i + 1)
        expected = (3.14159265 / 2 * 2**n) ** 0.5
        rows.append(dict(bits=n, mean=round(statistics.mean(counts)), expected=round(expected)))
        log(f"{n}-bit hash: collision after {statistics.mean(counts):,.0f} hashes on average (theory sqrt(pi/2 * 2^{n}) = {expected:,.0f})")
    log("full 256-bit SHA-256: ~2^128 hashes needed -> infeasible")
    RESULTS["birthday"] = rows


def demo_preimage(bits=16, trials=3):
    log(f"\n=== Demo 4: preimage search on {bits}-bit truncated SHA-256 ===")
    counts = []
    for _ in range(trials):
        target = int.from_bytes(os.urandom(2), "big") >> (16 - bits)
        i = 0
        while True:
            if int.from_bytes(sha256(i.to_bytes(8, "big"))[:2], "big") >> (16 - bits) == target:
                break
            i += 1
        counts.append(i + 1)
    log(f"found a preimage after {statistics.mean(counts):,.0f} tries on average (theory 2^{bits} = {2**bits:,})")
    log("full 256-bit SHA-256: ~2^256 tries needed -> infeasible")
    RESULTS["preimage"] = dict(bits=bits, mean=round(statistics.mean(counts)), expected=2**bits)


def demo_length_extension():
    log("\n=== Demo 5: length-extension attack on naive MAC = SHA-256(secret || message) ===")
    secret = os.urandom(16)                          # known only to the HVMC server
    msg = b"user=lisa.tran&role=nurse"
    mac = sha256(secret + msg)                       # attacker sees msg and mac
    extension = b"&role=admin"
    glue = pad(len(secret) + len(msg))               # attacker guesses secret length (16)
    forged_msg = msg + glue + extension
    forged_mac = sha256(extension, state=digest_to_state(mac), prior_len=len(secret) + len(msg) + len(glue))
    server_check = sha256(secret + forged_msg) == forged_mac
    log("original message:", msg.decode())
    log("forged message  :", forged_msg)
    log("server accepts forged MAC without knowing the secret:", server_check)
    hm = hmac_sha256(secret, msg)
    hmac_check = hmac_sha256(secret, forged_msg) == sha256(extension, state=digest_to_state(hm),
                                                           prior_len=64 + len(msg) + len(pad(64 + len(msg))))
    log("same attack against HMAC-SHA256 succeeds:", hmac_check)
    RESULTS["length_extension"] = dict(naive_forged=server_check, hmac_forged=hmac_check)


def demo_dh_exchange():
    log("\n=== Demo 7: 2048-bit Diffie-Hellman between HVMC EHR and LIS ===")
    t = time.perf_counter()
    ehr, lis = DHParty("EHR server"), DHParty("Laboratory Information System")
    k1, k2 = ehr.session_key(lis.public), lis.session_key(ehr.public)
    ms = (time.perf_counter() - t) * 1000
    log("p (first/last 16 hex):", format(P_2048, "x")[:16], "...", format(P_2048, "x")[-16:], f"({P_2048.bit_length()} bits)")
    log("EHR public A = g^a mod p (first 32 hex):", format(ehr.public, "x")[:32], "...")
    log("LIS public B = g^b mod p (first 32 hex):", format(lis.public, "x")[:32], "...")
    log("EHR session key:", k1.hex())
    log("LIS session key:", k2.hex())
    log(f"keys match: {k1 == k2}   (2 key pairs + 2 shared secrets in {ms:.0f} ms)")
    RESULTS["dh"] = dict(match=k1 == k2, ms=round(ms), key=k1.hex(), A=format(ehr.public, "x")[:32], B=format(lis.public, "x")[:32])


def demo_toy_dh():
    log("\n=== Demo 6: worked example with small numbers (p=23, g=5) ===")
    p, g, a, b = 23, 5, 6, 15
    A, B = mod_pow(g, a, p), mod_pow(g, b, p)
    log(f"Alice: a={a}, A = 5^6 mod 23 = {A}")
    log(f"Bob  : b={b}, B = 5^15 mod 23 = {B}")
    log(f"Alice: s = B^a = {B}^{a} mod 23 = {mod_pow(B, a, p)}")
    log(f"Bob  : s = A^b = {A}^{b} mod 23 = {mod_pow(A, b, p)}")
    log(f"Eve brute-forces a from A={A}: a = {brute_force_dlog(g, A, p)}  (trivial for tiny p)")


def demo_dlog_scaling(bit_sizes=(16, 20, 24), trials=5):
    log("\n=== Demo 8: brute-force discrete log vs. key size ===")
    rows = []
    for n in bit_sizes:
        p = random_safe_prime(n)
        q = (p - 1) // 2
        g = 4                                      # 4 = 2^2 is always in the order-q subgroup
        steps, secs, ok = [], [], True
        for _ in range(trials):
            x = secrets_randbelow(q - 2) + 2
            h = mod_pow(g, x, p)
            t = time.perf_counter()
            found = brute_force_dlog(g, h, p)
            secs.append(time.perf_counter() - t)
            steps.append(found)
            ok = ok and mod_pow(g, found, p) == h
        rows.append(dict(bits=n, p=p, q=q, mean_steps=round(statistics.mean(steps)), mean_s=round(statistics.mean(secs), 4),
                         full_s=round(statistics.mean(secs) / max(statistics.mean(steps), 1) * q, 3), ok=ok))
        log(f"{n}-bit p={p}: key recovered in {statistics.mean(steps):,.0f} steps on average over {trials} keys, "
            f"{statistics.mean(secs):.3f} s (search space q={q:,}; all correct: {ok})")
    log("Each extra bit doubles brute-force work. 2048-bit groups resist the best known attack")
    log("(number field sieve) at about 112-bit security (NIST SP 800-57).")
    RESULTS["dlog"] = rows


def secrets_randbelow(n):
    import secrets
    return secrets.randbelow(n)


def demo_mitm():
    log("\n=== Demo 9: man-in-the-middle on unauthenticated Diffie-Hellman ===")
    ehr, lis, mallory_to_ehr, mallory_to_lis = DHParty("EHR"), DHParty("LIS"), DHParty("Mallory"), DHParty("Mallory")
    # Mallory replaces each public key in transit with her own
    ehr_key = ehr.session_key(mallory_to_ehr.public)
    lis_key = lis.session_key(mallory_to_lis.public)
    m_key_ehr = mallory_to_ehr.session_key(ehr.public)
    m_key_lis = mallory_to_lis.session_key(lis.public)
    log("EHR key == LIS key        :", ehr_key == lis_key)
    log("Mallory shares EHR's key  :", m_key_ehr == ehr_key)
    log("Mallory shares LIS's key  :", m_key_lis == lis_key)
    log("=> Mallory can decrypt, read and re-encrypt all traffic. DH needs authentication (signatures/certificates).")
    RESULTS["mitm"] = dict(ehr_eq_lis=ehr_key == lis_key, m_ehr=m_key_ehr == ehr_key, m_lis=m_key_lis == lis_key)


def demo_forward_secrecy():
    log("\n=== Demo 10: fresh (ephemeral) keys per session ===")
    keys = []
    for _ in range(3):
        a, b = DHParty("EHR"), DHParty("LIS")
        keys.append(a.session_key(b.public).hex()[:16])
    log("three sessions, three unrelated keys:", keys)
    RESULTS["ephemeral"] = keys


def demo_speed():
    msg = os.urandom(1024 * 64)
    t = time.perf_counter(); sha256(msg); ours = time.perf_counter() - t
    t = time.perf_counter(); hashlib.sha256(msg).digest(); lib = time.perf_counter() - t
    log(f"\n=== Demo 11: speed on 64 KiB === from-scratch {ours * 1000:.1f} ms vs hashlib {lib * 1000:.3f} ms ({ours / lib:,.0f}x slower)")
    RESULTS["speed"] = dict(ours_ms=round(ours * 1000, 1), lib_ms=round(lib * 1000, 3), ratio=round(ours / lib))


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    open("results.txt", "w").close()
    log("HVMC Cryptographic Fundamentals - test and demo run")
    log(f"Python {platform.python_version()} on {platform.system()} {platform.machine()}, {time.strftime('%Y-%m-%d %H:%M')}")
    log("\n=== Unit tests ===")
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    names = [t.id().split(".", 1)[1] for group in suite for t in group]
    with open("results.txt", "a") as f:
        res = unittest.TextTestRunner(stream=f, verbosity=2).run(suite)
    log(f"tests run: {res.testsRun}, failures: {len(res.failures)}, errors: {len(res.errors)}")
    RESULTS["tests"] = dict(run=res.testsRun, failures=len(res.failures), errors=len(res.errors),
                            names=names)
    for demo in (demo_hvmc_integrity, demo_avalanche, demo_birthday, demo_preimage, demo_length_extension,
                 demo_toy_dh, demo_dh_exchange, demo_dlog_scaling, demo_mitm, demo_forward_secrecy, demo_speed):
        demo()
    with open("results.json", "w") as f:
        json.dump(RESULTS, f, indent=2)
    sys.exit(0 if res.wasSuccessful() else 1)
