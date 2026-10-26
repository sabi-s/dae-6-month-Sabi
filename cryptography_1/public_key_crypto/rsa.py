"""
RSA implemented from scratch, for learning purposes (RFC 8017 / PKCS #1 v2.2).

Horizon Valley Medical Center (HVMC) - Cryptography 1: Utilize Public Key Cryptography
Author: Sabitha S Karanavar

Includes: Miller-Rabin prime generation (FIPS 186-5 style checks), key generation
with the Carmichael function, CRT decryption with blinding, I2OSP/OS2IP,
MGF1, RSA-OAEP encryption (RFC 8017 section 7.1) and verification of an
RSA PKCS #1 v1.5 signature on a real X.509 certificate.

Not for production use: Python big-integer arithmetic is not constant-time and
this code has not been audited. HVMC production systems use a vetted library
(the `cryptography` package / OpenSSL) and keep CA keys in an HSM or Key Vault.
"""
import hashlib
import math
import secrets

SMALL_PRIMES = [p for p in range(3, 2000) if all(p % d for d in range(2, int(p ** 0.5) + 1))]


# ---------------------------------------------------------------- number theory
def egcd(a, b):
    """Extended Euclid: returns (g, x, y) with a*x + b*y = g = gcd(a, b)."""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def modinv(a, m):
    """Inverse of a modulo m, from the extended Euclidean algorithm."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("not invertible")
    return x % m


def is_probable_prime(n, rounds=40):
    """Miller-Rabin. A composite passes one round with probability <= 1/4,
    so 40 rounds give an error bound of 2^-80."""
    if n < 2:
        return False
    for p in [2] + SMALL_PRIMES[:50]:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits, e=65537):
    """Random prime of exactly `bits` bits with the top two bits set (so p*q has
    exactly 2*bits bits) and gcd(p - 1, e) = 1 (so e is invertible)."""
    while True:
        cand = secrets.randbits(bits) | (0b11 << (bits - 2)) | 1
        if any(cand % p == 0 for p in SMALL_PRIMES):        # cheap trial division first
            continue
        if math.gcd(cand - 1, e) == 1 and is_probable_prime(cand):
            return cand


# ---------------------------------------------------------------- keys
class RSAPublicKey:
    def __init__(self, n, e):
        self.n, self.e = n, e
        self.k = (n.bit_length() + 7) // 8           # modulus length in bytes

    def encrypt_raw(self, m):
        """RSAEP: c = m^e mod n. 'Textbook' RSA - never use on its own (see oaep_encrypt)."""
        if not 0 <= m < self.n:
            raise ValueError("message representative out of range")
        return pow(m, self.e, self.n)


class RSAPrivateKey:
    def __init__(self, p, q, e=65537):
        if p == q:
            raise ValueError("p and q must differ")
        self.p, self.q, self.e = p, q, e
        self.n = p * q
        lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)    # Carmichael function lambda(n)
        self.d = modinv(e, lam)                             # e*d = 1 (mod lambda(n))
        # CRT values (RFC 8017 section 3.2) make decryption about 3-4x faster
        self.dp, self.dq, self.qinv = self.d % (p - 1), self.d % (q - 1), modinv(q, p)
        self.public_key = RSAPublicKey(self.n, e)
        self.k = self.public_key.k

    def decrypt_raw(self, c, blind=True):
        """RSADP with the Chinese Remainder Theorem and base blinding.
        Blinding multiplies c by r^e first, so the time taken does not depend on
        the ciphertext an attacker chose (a timing side-channel defence)."""
        if not 0 <= c < self.n:
            raise ValueError("ciphertext representative out of range")
        if blind:
            while True:
                r = secrets.randbelow(self.n - 2) + 2
                if math.gcd(r, self.n) == 1:
                    break
            c = c * pow(r, self.e, self.n) % self.n
        m1, m2 = pow(c, self.dp, self.p), pow(c, self.dq, self.q)
        h = self.qinv * (m1 - m2) % self.p
        m = m2 + h * self.q
        return m * modinv(r, self.n) % self.n if blind else m


def generate_keypair(bits=2048, e=65537):
    """RSA key generation. Rejects p, q that are too close together (FIPS 186-5
    requires |p - q| > 2^(nlen/2 - 100), otherwise Fermat factoring finds them)."""
    if bits < 2048:
        raise ValueError("HVMC policy: RSA keys must be at least 2048 bits")
    half = bits // 2
    while True:
        p, q = generate_prime(half, e), generate_prime(bits - half, e)
        if abs(p - q) <= 1 << (half - 100):
            continue
        key = RSAPrivateKey(max(p, q), min(p, q), e)
        if key.n.bit_length() == bits and key.d > 1 << half:   # small d is insecure (Wiener)
            return key


# ---------------------------------------------------------------- PKCS #1 primitives
def i2osp(x, length):
    """Integer to octet string, big-endian (RFC 8017 section 4.1)."""
    if x >= 256 ** length:
        raise ValueError("integer too large")
    return x.to_bytes(length, "big")


def os2ip(b):
    """Octet string to integer (RFC 8017 section 4.2)."""
    return int.from_bytes(b, "big")


def mgf1(seed, length, hash_name="sha256"):
    """Mask generation function MGF1 (RFC 8017 appendix B.2.1)."""
    out, counter = b"", 0
    while len(out) < length:
        out += hashlib.new(hash_name, seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


class DecryptionError(Exception):
    """One error for every OAEP failure, so the error does not tell an attacker
    which check failed (Manger's attack exploits distinguishable errors)."""


def oaep_encrypt(pub, message, label=b"", hash_name="sha256", _seed=None):
    """RSAES-OAEP-ENCRYPT (RFC 8017 section 7.1.1).
    EM = 0x00 || maskedSeed || maskedDB, where DB = lHash || PS || 0x01 || M."""
    h_len = hashlib.new(hash_name).digest_size
    k = pub.k
    if len(message) > k - 2 * h_len - 2:
        raise ValueError(f"message too long: max {k - 2 * h_len - 2} bytes for this key")
    l_hash = hashlib.new(hash_name, label).digest()
    ps = b"\x00" * (k - len(message) - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + message
    seed = _seed if _seed is not None else secrets.token_bytes(h_len)   # fresh randomness every time
    masked_db = _xor(db, mgf1(seed, k - h_len - 1, hash_name))
    masked_seed = _xor(seed, mgf1(masked_db, h_len, hash_name))
    em = b"\x00" + masked_seed + masked_db
    return i2osp(pub.encrypt_raw(os2ip(em)), k)


def oaep_decrypt(priv, ciphertext, label=b"", hash_name="sha256"):
    """RSAES-OAEP-DECRYPT (RFC 8017 section 7.1.2)."""
    h_len = hashlib.new(hash_name).digest_size
    k = priv.k
    if len(ciphertext) != k or k < 2 * h_len + 2:
        raise DecryptionError("decryption error")
    c = os2ip(ciphertext)
    if c >= priv.n:
        raise DecryptionError("decryption error")
    em = i2osp(priv.decrypt_raw(c), k)
    y, masked_seed, masked_db = em[0], em[1:1 + h_len], em[1 + h_len:]
    seed = _xor(masked_seed, mgf1(masked_db, h_len, hash_name))
    db = _xor(masked_db, mgf1(seed, k - h_len - 1, hash_name))
    l_hash = hashlib.new(hash_name, label).digest()
    rest = db[h_len:]
    sep = rest.find(b"\x01")
    zeros_ok = sep >= 0 and rest[:sep] == b"\x00" * sep
    # check everything, then fail once
    if not (secrets.compare_digest(db[:h_len], l_hash) and y == 0 and zeros_ok):
        raise DecryptionError("decryption error")
    return rest[sep + 1:]


# ---------------------------------------------------------------- signature check on a real certificate
# DER DigestInfo prefixes from RFC 8017 section 9.2, note 1
DIGEST_INFO = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
}


def pkcs1v15_verify(pub, message, signature, hash_name="sha256"):
    """RSASSA-PKCS1-v1_5-VERIFY (RFC 8017 section 8.2.2). Rebuilds the full expected
    encoding EM' and compares it with s^e mod n, instead of parsing EM (parsing
    is where 'Bleichenbacher 2006' forgery bugs came from)."""
    if len(signature) != pub.k:
        return False
    em = i2osp(pub.encrypt_raw(os2ip(signature)), pub.k)
    t = DIGEST_INFO[hash_name] + hashlib.new(hash_name, message).digest()
    expected = b"\x00\x01" + b"\xff" * (pub.k - len(t) - 3) + b"\x00" + t
    return secrets.compare_digest(em, expected)


# ---------------------------------------------------------------- interop with the cryptography package
def to_library(priv):
    """Load a from-scratch key into the `cryptography` package (proves it is a valid RSA key)."""
    from cryptography.hazmat.primitives.asymmetric import rsa as lib_rsa
    pub = lib_rsa.RSAPublicNumbers(priv.e, priv.n)
    return lib_rsa.RSAPrivateNumbers(priv.p, priv.q, priv.d, priv.dp, priv.dq, priv.qinv, pub).private_key()


def from_library_public(lib_pub):
    nums = lib_pub.public_numbers()
    return RSAPublicKey(nums.n, nums.e)


if __name__ == "__main__":
    key = generate_keypair(2048)
    ct = oaep_encrypt(key.public_key, b"HVMC-004417 discharge summary key")
    print(key.n.bit_length(), "bit key; OAEP round trip:", oaep_decrypt(key, ct))
