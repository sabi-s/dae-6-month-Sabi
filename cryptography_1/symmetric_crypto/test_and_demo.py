"""
Tests and demonstrations for HVMC symmetric cryptography: AES (ECB, CBC), ChaCha20
and key management.

Horizon Valley Medical Center (HVMC) - Cryptography 1: Implement Symmetric Cryptography
Author: Sabitha S Karanavar

Run:  python3 test_and_demo.py
Writes results.txt, results.json and images/*.bmp.
If the optional `cryptography` package is installed, the from-scratch code is also
cross-checked against it (those tests are skipped otherwise).
"""
import json
import os
import platform
import struct
import sys
import time
import unittest

from aes import AES, INV_SBOX, SBOX, PaddingError, cbc_decrypt, cbc_encrypt, ecb_decrypt, ecb_encrypt, pkcs7_pad, pkcs7_unpad
from chacha20 import chacha20_block, chacha20_xor, quarter_round
from chacha20 import decrypt as chacha_decrypt
from chacha20 import encrypt as chacha_encrypt
from key_management import (IntegrityError, KeyRing, KeyUnwrapError, aes_key_unwrap, aes_key_wrap,
                            derive_key_from_password, envelope_decrypt, envelope_encrypt, generate_key, rewrap)

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.keywrap import aes_key_wrap as lib_key_wrap
    import cryptography
    HAVE_LIB = True
except ImportError:
    HAVE_LIB = False

RESULTS = {}
H = bytes.fromhex


# ======================================================================= TESTS
class TestAES(unittest.TestCase):
    def test_sbox_from_maths(self):
        self.assertEqual(SBOX[0x00], 0x63)
        self.assertEqual(SBOX[0x53], 0xED)          # FIPS 197 section 5.1.1 example
        self.assertEqual(sorted(SBOX), list(range(256)))
        self.assertTrue(all(INV_SBOX[SBOX[i]] == i for i in range(256)))

    def test_fips197_appendix_c(self):
        pt = H("00112233445566778899aabbccddeeff")
        for key, ct in [(H("000102030405060708090a0b0c0d0e0f"), "69c4e0d86a7b0430d8cdb78070b4c55a"),
                        (H("000102030405060708090a0b0c0d0e0f1011121314151617"), "dda97ca4864cdfe06eaf70a0ec0d7191"),
                        (H("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), "8ea2b7ca516745bfeafc49904b496089")]:
            self.assertEqual(AES(key).encrypt_block(pt).hex(), ct)
            self.assertEqual(AES(key).decrypt_block(H(ct)), pt)

    SP_KEY = H("2b7e151628aed2a6abf7158809cf4f3c")
    SP_PT = H("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
              "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")

    def test_sp800_38a_ecb(self):
        ct = ("3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
              "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4")
        self.assertEqual(ecb_encrypt(self.SP_KEY, self.SP_PT, pad=False).hex(), ct)
        self.assertEqual(ecb_decrypt(self.SP_KEY, H(ct), pad=False), self.SP_PT)

    def test_sp800_38a_cbc(self):
        iv = H("000102030405060708090a0b0c0d0e0f")
        ct = ("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
              "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7")
        self.assertEqual(cbc_encrypt(self.SP_KEY, self.SP_PT, iv=iv, pad=False).hex(), ct)
        self.assertEqual(cbc_decrypt(self.SP_KEY, H(ct), iv=iv, pad=False), self.SP_PT)

    def test_round_trip_all_key_sizes_and_lengths(self):
        for bits in (128, 192, 256):
            key = generate_key(bits)
            for n in range(0, 50):
                m = os.urandom(n)
                self.assertEqual(ecb_decrypt(key, ecb_encrypt(key, m)), m)
                self.assertEqual(cbc_decrypt(key, cbc_encrypt(key, m)), m)

    def test_pkcs7(self):
        self.assertEqual(pkcs7_pad(b""), bytes([16]) * 16)
        self.assertEqual(pkcs7_pad(b"A" * 15), b"A" * 15 + b"\x01")
        for bad in (b"A" * 15 + b"\x00", b"A" * 14 + b"\x01\x02", b"A" * 16 + b"\x11" * 16):
            with self.assertRaises(PaddingError):
                pkcs7_unpad(bad)

    def test_cbc_random_iv(self):
        k = generate_key()
        self.assertNotEqual(cbc_encrypt(k, b"same message"), cbc_encrypt(k, b"same message"))

    @unittest.skipUnless(HAVE_LIB, "cryptography package not installed")
    def test_matches_cryptography_library(self):
        for bits in (128, 192, 256):
            key, iv, m = generate_key(bits), os.urandom(16), os.urandom(160)
            e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
            self.assertEqual(ecb_encrypt(key, m, pad=False), e.update(m) + e.finalize())
            c = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
            self.assertEqual(cbc_encrypt(key, m, iv=iv, pad=False), c.update(m) + c.finalize())


class TestChaCha20(unittest.TestCase):
    def test_rfc8439_quarter_round(self):
        s = [0] * 16
        s[0], s[1], s[2], s[3] = 0x11111111, 0x01020304, 0x9B8D6F43, 0x01234567
        quarter_round(s, 0, 1, 2, 3)
        self.assertEqual(s[:4], [0xEA2A92F4, 0xCB1CF8CE, 0x4581472E, 0x5881C4BB])

    def test_rfc8439_encryption_vector(self):
        key = bytes(range(32))
        nonce = H("000000000000004a00000000")
        pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
              b"sunscreen would be it.")
        ct = chacha20_xor(key, nonce, pt, counter=1)
        self.assertEqual(ct[:16].hex(), "6e2e359a2568f98041ba0728dd0d6981")
        self.assertEqual(ct[-2:].hex(), "874d")
        self.assertEqual(chacha20_xor(key, nonce, ct, counter=1), pt)

    def test_round_trip(self):
        k = generate_key()
        for n in (0, 1, 63, 64, 65, 1000):
            m = os.urandom(n)
            self.assertEqual(chacha_decrypt(k, chacha_encrypt(k, m)), m)

    @unittest.skipUnless(HAVE_LIB, "cryptography package not installed")
    def test_matches_cryptography_library(self):
        key, nonce, m = generate_key(), os.urandom(12), os.urandom(300)
        enc = Cipher(algorithms.ChaCha20(key, struct.pack("<L", 1) + nonce), mode=None).encryptor()
        self.assertEqual(chacha20_xor(key, nonce, m), enc.update(m))


class TestKeyManagement(unittest.TestCase):
    def test_rfc3394_vectors(self):
        self.assertEqual(aes_key_wrap(bytes(range(16)), H("00112233445566778899aabbccddeeff")).hex(),
                         "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5")
        kek256 = bytes(range(32))
        data = H("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f")
        wrapped = aes_key_wrap(kek256, data)
        self.assertEqual(wrapped.hex(), "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21")
        self.assertEqual(aes_key_unwrap(kek256, wrapped), data)

    def test_unwrap_with_wrong_kek_fails(self):
        w = aes_key_wrap(generate_key(), generate_key())
        with self.assertRaises(KeyUnwrapError):
            aes_key_unwrap(generate_key(), w)

    @unittest.skipUnless(HAVE_LIB, "cryptography package not installed")
    def test_key_wrap_matches_library(self):
        kek, k = generate_key(), generate_key()
        self.assertEqual(aes_key_wrap(kek, k), lib_key_wrap(kek, k))

    def test_generate_key(self):
        keys = {generate_key() for _ in range(1000)}
        self.assertEqual(len(keys), 1000)
        self.assertEqual(len(generate_key(128)), 16)

    def test_pbkdf2_salt(self):
        k1, s1 = derive_key_from_password("Winter2026!", iterations=1000)
        k2, s2 = derive_key_from_password("Winter2026!", iterations=1000)
        self.assertNotEqual(k1, k2)
        self.assertEqual(derive_key_from_password("Winter2026!", salt=s1, iterations=1000)[0], k1)

    def test_envelope_round_trip_tamper_and_rotation(self):
        ring = KeyRing()
        rec = envelope_encrypt(ring, b"lab result", context=b"LIS/HVMC-004417")
        self.assertEqual(envelope_decrypt(ring, rec), b"lab result")
        bad = dict(rec, iv_ct=rec["iv_ct"][:-1] + bytes([rec["iv_ct"][-1] ^ 1]))
        with self.assertRaises(IntegrityError):
            envelope_decrypt(ring, bad)
        ring.rotate()
        new = rewrap(ring, rec)
        self.assertEqual(new["kek_version"], "v2")
        self.assertEqual(new["iv_ct"], rec["iv_ct"])
        ring.retire("v1")
        self.assertEqual(envelope_decrypt(ring, new), b"lab result")
        with self.assertRaises(KeyUnwrapError):
            envelope_decrypt(ring, rec)


# ======================================================================= DEMOS
def log(*a):
    print(*a)
    with open("results.txt", "a") as f:
        print(*a, file=f)


# ---- image helpers (32-bit BMP so 1 AES block = 4 pixels) ----
FONT = {
    "H": ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
    "V": ["10001", "10001", "10001", "10001", "10001", "01010", "00100"],
    "M": ["10001", "11011", "10101", "10101", "10001", "10001", "10001"],
    "C": ["01111", "10000", "10000", "10000", "10000", "10000", "01111"],
}


def make_hvmc_image(w=320, h=128):
    bg, navy, red, white = (238, 242, 248), (31, 56, 100), (200, 40, 40), (255, 255, 255)
    px = [[bg] * w for _ in range(h)]
    for y in range(28, 100):                            # white tile + red medical cross
        for x in range(12, 84):
            px[y][x] = white
    for y in range(36, 92):
        for x in range(40, 56):
            px[y][x] = red
    for y in range(56, 72):
        for x in range(20, 76):
            px[y][x] = red
    for n, ch in enumerate("HVMC"):
        x0, y0 = 96 + n * 56, 36
        for r, row in enumerate(FONT[ch]):
            for c, bit in enumerate(row):
                if bit == "1":
                    for y in range(y0 + r * 8, y0 + r * 8 + 8):
                        for x in range(x0 + c * 8, x0 + c * 8 + 8):
                            px[y][x] = navy
    data = b"".join(bytes((b, g, r, 255)) for row in reversed(px) for (r, g, b) in row)   # bottom-up BGRA
    return w, h, data


def bmp_bytes(w, h, data):
    header = struct.pack("<2sIHHI", b"BM", 54 + len(data), 0, 0, 54)
    info = struct.pack("<IiiHHIIiiII", 40, w, h, 1, 32, 0, len(data), 2835, 2835, 0, 0)
    return header + info + data


def demo_image():
    log("\n=== Demo 1: ECB vs CBC on an image (the 'ECB penguin' with the HVMC logo) ===")
    os.makedirs("images", exist_ok=True)
    w, h, data = make_hvmc_image()
    key = generate_key(128)
    ecb = ecb_encrypt(key, data, pad=False)
    cbc = cbc_encrypt(key, data, pad=False)[16:]          # drop IV so length matches
    for name, d in (("original", data), ("ecb", ecb), ("cbc", cbc)):
        with open(f"images/hvmc_{name}.bmp", "wb") as f:
            f.write(bmp_bytes(w, h, d))
    blocks = lambda d: [d[i:i + 16] for i in range(0, len(d), 16)]
    u = {n: len(set(blocks(d))) for n, d in (("original", data), ("ecb", ecb), ("cbc", cbc))}
    total = len(data) // 16
    log(f"image {w}x{h}, {total:,} AES blocks; distinct blocks: original {u['original']:,}, ECB {u['ecb']:,}, CBC {u['cbc']:,}")
    log("ECB keeps every repeated plaintext block repeated -> the logo stays visible. CBC output has no repeats.")
    RESULTS["image"] = dict(w=w, h=h, blocks=total, distinct=u)


def demo_ecb_records():
    log("\n=== Demo 2: ECB leaks equal values in patient records ===")
    key = generate_key()
    patients = [("Patient-0001", "E11.9 T2 Diabet"), ("Patient-0002", "I10 Hypertensio"), ("Patient-0003", "E11.9 T2 Diabet"),
                ("Patient-0004", "J45 Asthma     "), ("Patient-0005", "E11.9 T2 Diabet"), ("Patient-0006", "I10 Hypertensio")]
    rows = []
    for name, dx in patients:
        rec = f"{name:<16}{dx:<16}".encode()                 # two 16-byte fields = two AES blocks
        ecb = ecb_encrypt(key, rec, pad=False)
        cbc = cbc_encrypt(key, rec, pad=False)
        rows.append((name, dx.strip(), ecb[16:32].hex()[:16], cbc[32:48].hex()[:16]))
        log(f"{name}  dx={dx.strip():<16} ECB dx-block {ecb[16:32].hex()[:16]}…   CBC dx-block {cbc[32:48].hex()[:16]}…")
    groups = len({r[2] for r in rows})
    log(f"ECB: {len(rows)} records but only {groups} distinct diagnosis blocks -> an attacker sees who shares a diagnosis.")
    log("CBC: every block is different because of the random IV.")
    RESULTS["records"] = dict(rows=rows, groups=groups)


def demo_iv_reuse():
    log("\n=== Demo 3: CBC needs a fresh random IV every time ===")
    key, fixed_iv = generate_key(), bytes(16)
    m1 = b"MRN HVMC-004417 | HIV test: NEGATIVE"
    m2 = b"MRN HVMC-004417 | HIV test: POSITIVE"
    c1, c2 = cbc_encrypt(key, m1, iv=fixed_iv), cbc_encrypt(key, m2, iv=fixed_iv)
    same_fixed = sum(c1[i:i + 16] == c2[i:i + 16] for i in range(0, len(c1), 16))
    r1, r2 = cbc_encrypt(key, m1), cbc_encrypt(key, m2)
    same_random = sum(r1[16 + i:32 + i] == r2[16 + i:32 + i] for i in range(0, len(r1) - 16, 16))
    log(f"fixed IV : {same_fixed} identical leading block(s) -> attacker learns the messages share a prefix")
    log(f"random IV: {same_random} identical blocks")
    RESULTS["iv_reuse"] = dict(fixed=same_fixed, random=same_random)


def demo_bit_flip():
    log("\n=== Demo 4: CBC bit-flipping - changing ciphertext without the key ===")
    key = generate_key()
    token = b"role=nurse;user=lisa.tran;ward=4B;exp=2026-10-20"
    ct = bytearray(cbc_encrypt(key, token))
    for i, (a, b) in enumerate(zip(b"nurse", b"admin")):     # IV is ct[0:16]; "nurse" is bytes 5..9 of block 1
        ct[5 + i] ^= a ^ b
    forged = cbc_decrypt(key, bytes(ct))
    log("original :", token.decode())
    log("forged   :", forged.decode())
    ring = KeyRing()
    rec = envelope_encrypt(ring, token)
    tampered = bytearray(rec["iv_ct"])
    for i, (a, b) in enumerate(zip(b"nurse", b"admin")):
        tampered[5 + i] ^= a ^ b
    try:
        envelope_decrypt(ring, dict(rec, iv_ct=bytes(tampered)))
        detected = False
    except IntegrityError:
        detected = True
    log("same attack on encrypt-then-MAC envelope detected:", detected)
    RESULTS["bit_flip"] = dict(original=token.decode(), forged=forged.decode(), detected=detected)


def demo_padding_oracle():
    log("\n=== Demo 5: padding-oracle attack decrypts CBC without the key ===")
    key = generate_key()
    secret = b'{"mrn":"HVMC-004417","dx":"F32.1 depression"}'
    ct = cbc_encrypt(key, secret)
    queries = 0
    aes = AES(key)

    def oracle(two_blocks):
        """A server that only reveals 'padding OK' vs 'padding error' (e.g. different HTTP errors)."""
        nonlocal queries
        queries += 1
        prev, block = two_blocks[:16], two_blocks[16:]
        p = bytes(a ^ b for a, b in zip(aes.decrypt_block(block), prev))
        try:
            pkcs7_unpad(p)
            return True
        except PaddingError:
            return False

    blocks = [ct[i:i + 16] for i in range(0, len(ct), 16)]
    recovered = b""
    t = time.perf_counter()
    for bi in range(1, len(blocks)):
        inter = [0] * 16
        for pos in range(15, -1, -1):
            pad_val = 16 - pos
            for guess in range(256):
                forged = bytearray(16)
                for k in range(pos + 1, 16):
                    forged[k] = inter[k] ^ pad_val
                forged[pos] = guess
                if oracle(bytes(forged) + blocks[bi]):
                    if pad_val == 1:                       # rule out accidental \x02\x02 etc.
                        forged[pos - 1] ^= 0xFF
                        if not oracle(bytes(forged) + blocks[bi]):
                            continue
                    inter[pos] = guess ^ pad_val
                    break
        recovered += bytes(a ^ b for a, b in zip(inter, blocks[bi - 1]))
    secs = time.perf_counter() - t
    plain = pkcs7_unpad(recovered)
    log(f"recovered plaintext: {plain.decode()}")
    log(f"correct: {plain == secret}; {queries:,} oracle queries, {secs:.1f} s, key never used by attacker")
    RESULTS["padding_oracle"] = dict(recovered=plain.decode(), correct=plain == secret, queries=queries, seconds=round(secs, 1),
                                     blocks=len(blocks) - 1)


def demo_chacha():
    log("\n=== Demo 6: ChaCha20 stream cipher ===")
    key = generate_key()
    msg = b"LIS -> EHR | MRN HVMC-004417 | Potassium 4.1 mmol/L | verified E. Petrova"
    blob = chacha_encrypt(key, msg)
    log("nonce      :", blob[:12].hex())
    log("ciphertext :", blob[12:44].hex(), "…", f"({len(blob) - 12} bytes = plaintext length, no padding)")
    log("decrypted  :", chacha_decrypt(key, blob).decode())
    ks = chacha20_block(key, 1, blob[:12])
    log("first keystream block (64 bytes):", ks[:24].hex(), "…")
    RESULTS["chacha"] = dict(nonce=blob[:12].hex(), ct=blob[12:44].hex(), ok=chacha_decrypt(key, blob) == msg, length=len(msg))

    log("\n=== Demo 7: nonce reuse turns ChaCha20 into a two-time pad ===")
    nonce = os.urandom(12)
    p1 = b"MRN HVMC-004417 HbA1c 5.4% NORMAL  "    # attacker knows this (e.g. a template or earlier leak)
    p2 = b"MRN HVMC-004418 HbA1c 9.8% HIGH    "
    c1, c2 = chacha20_xor(key, nonce, p1), chacha20_xor(key, nonce, p2)
    x = bytes(a ^ b for a, b in zip(c1, c2))
    rec = bytes(a ^ b for a, b in zip(x, p1))
    log("c1 XOR c2 == p1 XOR p2:", x == bytes(a ^ b for a, b in zip(p1, p2)))
    log("attacker recovers p2 :", rec.decode())
    RESULTS["nonce_reuse"] = dict(recovered=rec.decode().strip(), ok=rec == p2)


def demo_key_management():
    log("\n=== Demo 8: key management ===")
    k = generate_key()
    log("CSPRNG 256-bit key   :", k.hex()[:32], "…  (secrets.token_bytes, os.urandom)")
    t = time.perf_counter()
    k1, s1 = derive_key_from_password("Winter2026!")
    pb_s = time.perf_counter() - t
    k2, s2 = derive_key_from_password("Winter2026!")
    log(f"PBKDF2 600,000 iter   : {pb_s * 1000:.0f} ms per guess on this Mac -> ~{1 / pb_s:,.0f} guesses/second/core")
    log("same password, 2 salts:", k1.hex()[:16], "vs", k2.hex()[:16], "(different keys)")
    t = time.perf_counter()
    for _ in range(1000):
        derive_key_from_password("Winter2026!", salt=s1, iterations=1)
    one_s = (time.perf_counter() - t) / 1000
    log(f"1 iteration          : {one_s * 1e6:.1f} µs per guess -> stretching makes guessing ~{pb_s / one_s:,.0f}x slower")
    RESULTS["pbkdf2"] = dict(ms=round(pb_s * 1000), guesses=round(1 / pb_s), slowdown=round(pb_s / one_s))

    ring = KeyRing()
    files = {"lab/HVMC-004417.json": b'{"test":"K","value":4.1}', "lab/HVMC-004418.json": b'{"test":"HbA1c","value":9.8}',
             "rx/HVMC-004417.json": b'{"drug":"lisinopril","dose":"10mg"}'}
    recs = {n: envelope_encrypt(ring, d, context=n.encode()) for n, d in files.items()}
    log("envelope encryption  :", ", ".join(f"{n} -> KEK {r['kek_version']}, wrapped DEK {r['wrapped_dek'].hex()[:12]}…" for n, r in recs.items()))
    deks_distinct = len({r["wrapped_dek"] for r in recs.values()}) == len(recs)
    ring.rotate()
    t = time.perf_counter()
    recs2 = {n: rewrap(ring, r) for n, r in recs.items()}
    rot_ms = (time.perf_counter() - t) * 1000
    unchanged = all(recs2[n]["iv_ct"] == recs[n]["iv_ct"] for n in recs)
    ring.retire("v1")
    ok_new = all(envelope_decrypt(ring, r) == files[n] for n, r in recs2.items())
    try:
        envelope_decrypt(ring, recs["lab/HVMC-004417.json"])
        old_blocked = False
    except KeyUnwrapError:
        old_blocked = True
    log(f"rotate KEK v1 -> v2   : {len(recs)} DEKs re-wrapped in {rot_ms:.0f} ms, bulk ciphertext unchanged: {unchanged}")
    log(f"retire v1             : new records decrypt: {ok_new}; old v1-wrapped copies blocked: {old_blocked}")
    swapped = dict(recs2["lab/HVMC-004418.json"], context=b"lab/HVMC-004417.json")
    try:
        envelope_decrypt(ring, swapped)
        ctx = False
    except IntegrityError:
        ctx = True
    log(f"record moved to another patient's file detected (context bound into MAC): {ctx}")
    RESULTS["envelope"] = dict(files=len(recs), distinct=deks_distinct, rot_ms=round(rot_ms), unchanged=unchanged,
                               ok_new=ok_new, old_blocked=old_blocked, ctx=ctx)


def demo_library():
    log("\n=== Demo 9: production comparison (cryptography package) ===")
    if not HAVE_LIB:
        log("cryptography package not installed - skipped")
        RESULTS["library"] = None
        return
    key, data = generate_key(), os.urandom(64 * 1024)
    iv = os.urandom(16)
    t = time.perf_counter(); cbc_encrypt(key, data, iv=iv, pad=False); ours = time.perf_counter() - t
    t = time.perf_counter(); e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor(); e.update(data) + e.finalize(); lib = time.perf_counter() - t
    log(f"AES-256-CBC 64 KiB: from-scratch {ours * 1000:.0f} ms vs cryptography {lib * 1000:.3f} ms ({ours / lib:,.0f}x slower)")
    t = time.perf_counter(); chacha20_xor(key, iv[:12], data); ours_c = time.perf_counter() - t
    log(f"ChaCha20   64 KiB: from-scratch {ours_c * 1000:.0f} ms")
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, b"role=nurse;user=lisa.tran", b"HVMC-session")
    bad = bytearray(ct); bad[5] ^= ord("n") ^ ord("a")
    try:
        aes.decrypt(nonce, bytes(bad), b"HVMC-session"); gcm_detect = False
    except InvalidTag:
        gcm_detect = True
    log(f"AES-256-GCM (recommended): ciphertext+16-byte tag; bit-flip detected -> InvalidTag: {gcm_detect}")
    RESULTS["library"] = dict(version=cryptography.__version__, ours_ms=round(ours * 1000), lib_ms=round(lib * 1000, 3),
                              ratio=round(ours / lib), chacha_ms=round(ours_c * 1000), gcm_detect=gcm_detect)


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    open("results.txt", "w").close()
    log("HVMC Symmetric Cryptography - test and demo run")
    log(f"Python {platform.python_version()} on {platform.system()} {platform.machine()}, {time.strftime('%Y-%m-%d %H:%M')}; "
        f"cryptography package: {cryptography.__version__ if HAVE_LIB else 'not installed (cross-checks skipped)'}")
    log("\n=== Unit tests ===")
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    names = [t.id().split(".", 1)[1] for group in suite for t in group]
    with open("results.txt", "a") as f:
        res = unittest.TextTestRunner(stream=f, verbosity=2).run(suite)
    log(f"tests run: {res.testsRun}, failures: {len(res.failures)}, errors: {len(res.errors)}, skipped: {len(res.skipped)}")
    RESULTS["tests"] = dict(run=res.testsRun, failures=len(res.failures), errors=len(res.errors), skipped=len(res.skipped), names=names)
    if not res.wasSuccessful():
        for _, tb in res.failures + res.errors:
            print(tb)
    for demo in (demo_image, demo_ecb_records, demo_iv_reuse, demo_bit_flip, demo_padding_oracle, demo_chacha,
                 demo_key_management, demo_library):
        demo()
    with open("results.json", "w") as f:
        json.dump(RESULTS, f, indent=2)
    sys.exit(0 if res.wasSuccessful() else 1)
