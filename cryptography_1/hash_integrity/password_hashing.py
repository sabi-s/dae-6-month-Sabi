"""
Secure password hashing for the HVMC patient portal.

Horizon Valley Medical Center (HVMC) - Cryptography 1: Hash Functions and Integrity
Author: Sabitha S Karanavar

  * PBKDF2-HMAC-SHA256 implemented from scratch (RFC 8018) on the from-scratch HMAC,
    verified against hashlib.pbkdf2_hmac
  * PasswordHasher: random per-user salt, 600,000 iterations (OWASP), optional pepper,
    self-describing hash strings, constant-time verify, automatic upgrade (needs_rehash)
  * Argon2idHasher: the same interface using Argon2id (RFC 9106), the memory-hard
    algorithm OWASP lists first; used when the optional argon2-cffi package is installed
  * Password policy based on NIST SP 800-63B: length, blocklist, context words,
    no forced composition rules

Staff accounts authenticate through Microsoft Entra ID (passwords never reach HVMC
applications); this module is for the patient-portal accounts HVMC stores itself.
"""
import base64
import hashlib
import hmac as std_hmac
import secrets
import struct

from hmac_auth import HMAC

try:
    import argon2
    HAVE_ARGON2 = True
except ImportError:
    HAVE_ARGON2 = False

DEFAULT_ITERATIONS = 600_000        # OWASP Password Storage Cheat Sheet, PBKDF2-HMAC-SHA256


# ------------------------------------------------------------ PBKDF2 from scratch
def pbkdf2_sha256(password, salt, iterations, dklen=32):
    """RFC 8018 section 5.2.  T_i = U_1 xor U_2 xor ... xor U_c
    with U_1 = PRF(P, S || INT(i)) and U_j = PRF(P, U_{j-1}); PRF = HMAC-SHA256."""
    prf = HMAC(password)
    blocks = []
    for i in range(1, -(-dklen // 32) + 1):
        u = prf.digest(salt + struct.pack(">I", i))
        t = int.from_bytes(u, "big")
        for _ in range(iterations - 1):
            u = prf.digest(u)
            t ^= int.from_bytes(u, "big")
        blocks.append(t.to_bytes(32, "big"))
    return b"".join(blocks)[:dklen]


# ------------------------------------------------------------ storage format
def _b64(b):
    return base64.b64encode(b).decode().rstrip("=")


def _unb64(s):
    return base64.b64decode(s + "=" * (-len(s) % 4))


class PasswordHasher:
    """Produces strings like  $pbkdf2-sha256$i=600000$<salt>$<hash>
    so the algorithm and cost travel with each hash and can be upgraded later."""

    def __init__(self, iterations=DEFAULT_ITERATIONS, pepper=None):
        self.iterations = iterations
        self.pepper = pepper          # server-side secret kept in Key Vault, NOT in the database

    def _prepare(self, password):
        pw = password.encode("utf-8")
        if self.pepper:
            pw = std_hmac.new(self.pepper, pw, hashlib.sha256).digest()
        return pw

    def hash(self, password):
        salt = secrets.token_bytes(16)
        dk = hashlib.pbkdf2_hmac("sha256", self._prepare(password), salt, self.iterations)
        return f"$pbkdf2-sha256$i={self.iterations}${_b64(salt)}${_b64(dk)}"

    def verify(self, stored, password):
        try:
            _, alg, cost, salt, dk = stored.split("$")
            iterations = int(cost.split("=")[1])
        except (ValueError, IndexError):
            return False
        if alg != "pbkdf2-sha256":
            return False
        candidate = hashlib.pbkdf2_hmac("sha256", self._prepare(password), _unb64(salt), iterations)
        return std_hmac.compare_digest(candidate, _unb64(dk))

    def needs_rehash(self, stored):
        """True if the stored hash used fewer iterations than current policy:
        re-hash it the next time the user logs in successfully."""
        try:
            return int(stored.split("$")[2].split("=")[1]) < self.iterations
        except (ValueError, IndexError):
            return True


class Argon2idHasher:
    """Argon2id with OWASP minimum parameters: 19 MiB memory, 2 iterations, 1 lane.
    Output is the standard PHC string $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>."""

    def __init__(self, memory_kib=19456, time_cost=2, parallelism=1, pepper=None):
        if not HAVE_ARGON2:
            raise RuntimeError("install argon2-cffi to use Argon2id (PBKDF2 PasswordHasher works without it)")
        self._ph = argon2.PasswordHasher(time_cost=time_cost, memory_cost=memory_kib, parallelism=parallelism)
        self.pepper = pepper

    def _prepare(self, password):
        pw = password.encode("utf-8")
        return std_hmac.new(self.pepper, pw, hashlib.sha256).digest() if self.pepper else pw

    def hash(self, password):
        return self._ph.hash(self._prepare(password))

    def verify(self, stored, password):
        try:
            return self._ph.verify(stored, self._prepare(password))
        except argon2.exceptions.VerificationError:
            return False
        except argon2.exceptions.InvalidHashError:
            return False

    def needs_rehash(self, stored):
        return self._ph.check_needs_rehash(stored)


def make_hasher(pepper=None):
    """Prefer Argon2id when available, otherwise PBKDF2-HMAC-SHA256."""
    return Argon2idHasher(pepper=pepper) if HAVE_ARGON2 else PasswordHasher(pepper=pepper)


# ------------------------------------------------------------ policy (NIST SP 800-63B)
COMMON_PASSWORDS = {
    "123456", "123456789", "12345678", "password", "password1", "password123", "qwerty", "qwerty123", "abc123",
    "111111", "123123", "letmein", "welcome", "welcome1", "welcome123", "admin", "admin123", "iloveyou", "monkey",
    "dragon", "football", "baseball", "sunshine", "princess", "master", "shadow", "superman", "trustno1", "changeme",
    "passw0rd", "p@ssw0rd", "p@ssword1", "1q2w3e4r", "zaq12wsx", "qazwsx", "hello123", "login", "secret",
    "nurse123", "doctor123", "hospital1", "medical1", "healthcare1", "patient1",
}
SEASONS = ["spring", "summer", "fall", "autumn", "winter"]
CONTEXT_WORDS = ["hvmc", "horizon", "valley", "medical", "horizonvalley"]


def blocklist_candidates():
    """The blocklist an attacker would also try first: common passwords plus season/year/symbol mutations."""
    out = set(COMMON_PASSWORDS)
    for word in SEASONS + CONTEXT_WORDS:
        for year in range(2020, 2028):
            for suffix in ("", "!", "#", "1"):
                for w in (word, word.capitalize()):
                    out.add(f"{w}{year}{suffix}")
    return out


def check_password_policy(password, username="", min_length=15, max_length=64):
    """Return a list of problems (empty list = acceptable).
    NIST SP 800-63B: length matters most; screen against breached/common/context words;
    do NOT require arbitrary composition rules or periodic changes."""
    problems = []
    if len(password) < min_length:
        problems.append(f"shorter than {min_length} characters")
    if len(password) > max_length:
        problems.append(f"longer than {max_length} characters")
    low = password.lower()
    if low in {p.lower() for p in blocklist_candidates()}:
        problems.append("on the common/breached-password blocklist")
    if any(w in low for w in CONTEXT_WORDS):
        problems.append("contains HVMC context words")
    if username and username.split("@")[0].split(".")[0].lower() in low:
        problems.append("contains the username")
    if len(set(password)) <= 2:
        problems.append("repetitive characters")
    return problems
