"""
Key management techniques for HVMC symmetric encryption.

Horizon Valley Medical Center (HVMC) - Cryptography 1: Implement Symmetric Cryptography
Author: Sabitha S Karanavar

Demonstrates:
  1. Key generation from a CSPRNG (secrets), never `random`
  2. Password-based key derivation (PBKDF2-HMAC-SHA256, random salt, 600,000 iterations)
  3. AES Key Wrap (RFC 3394) built on the from-scratch AES
  4. Envelope encryption: a fresh data-encryption key (DEK) per record, wrapped by a
     key-encryption key (KEK) - the model used by Azure Storage + Key Vault
  5. Key separation (separate encryption and MAC keys derived from one DEK)
  6. Versioned KEK rotation and retirement without re-encrypting the data
"""
import hashlib
import hmac
import secrets
import struct

from aes import AES, cbc_decrypt, cbc_encrypt

PBKDF2_ITERATIONS = 600_000      # OWASP Password Storage Cheat Sheet recommendation for PBKDF2-HMAC-SHA256


# ------------------------------------------------------------ 1. generation
def generate_key(bits=256):
    """Generate a symmetric key from the operating system's CSPRNG."""
    if bits not in (128, 192, 256):
        raise ValueError("AES keys are 128, 192 or 256 bits")
    return secrets.token_bytes(bits // 8)


# ------------------------------------------------------------ 2. derivation
def derive_key_from_password(password, salt=None, iterations=PBKDF2_ITERATIONS, length=32):
    """Stretch a human password into a key. The salt makes every derived key unique and
    defeats precomputed (rainbow) tables; the iteration count slows down guessing."""
    salt = secrets.token_bytes(16) if salt is None else salt
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=length)
    return key, salt


def hkdf_like(key, label, length=32):
    """Derive an independent sub-key for one purpose (key separation)."""
    return hmac.new(key, b"HVMC|" + label, hashlib.sha256).digest()[:length]


# ------------------------------------------------------------ 3. AES key wrap (RFC 3394)
DEFAULT_IV = bytes.fromhex("A6A6A6A6A6A6A6A6")


class KeyUnwrapError(ValueError):
    pass


def aes_key_wrap(kek, key_data):
    """Wrap (encrypt) a key with a KEK. Output is 8 bytes longer than the input and includes
    a built-in integrity check, so a wrong KEK or tampered wrapped key is detected."""
    if len(key_data) % 8 or len(key_data) < 16:
        raise ValueError("key data must be a multiple of 8 bytes, at least 16")
    aes = AES(kek)
    n = len(key_data) // 8
    a = DEFAULT_IV
    r = [key_data[i * 8:(i + 1) * 8] for i in range(n)]
    for j in range(6):
        for i in range(n):
            b = aes.encrypt_block(a + r[i])
            t = n * j + i + 1
            a = (struct.unpack(">Q", b[:8])[0] ^ t).to_bytes(8, "big")
            r[i] = b[8:]
    return a + b"".join(r)


def aes_key_unwrap(kek, wrapped):
    aes = AES(kek)
    n = len(wrapped) // 8 - 1
    a = wrapped[:8]
    r = [wrapped[(i + 1) * 8:(i + 2) * 8] for i in range(n)]
    for j in range(5, -1, -1):
        for i in range(n - 1, -1, -1):
            t = n * j + i + 1
            a_xor = (struct.unpack(">Q", a)[0] ^ t).to_bytes(8, "big")
            b = aes.decrypt_block(a_xor + r[i])
            a, r[i] = b[:8], b[8:]
    if not hmac.compare_digest(a, DEFAULT_IV):
        raise KeyUnwrapError("integrity check failed: wrong KEK or tampered wrapped key")
    return b"".join(r)


# ------------------------------------------------------------ 4-6. envelope encryption with rotation
class KeyRing:
    """Holds versioned KEKs. In production the KEKs live in Azure Key Vault / an HSM and never
    leave it; the application only asks the vault to wrap/unwrap DEKs."""

    def __init__(self):
        self.keks, self.retired, self.active = {}, set(), None
        self.rotate()

    def rotate(self):
        version = f"v{len(self.keks) + 1}"
        self.keks[version] = generate_key(256)
        self.active = version
        return version

    def retire(self, version):
        if version == self.active:
            raise ValueError("cannot retire the active key")
        self.retired.add(version)
        self.keks[version] = None          # destroyed (in Python memory cannot be truly zeroized)

    def wrap(self, dek):
        return self.active, aes_key_wrap(self.keks[self.active], dek)

    def unwrap(self, version, wrapped):
        if version in self.retired or self.keks.get(version) is None:
            raise KeyUnwrapError(f"KEK {version} is retired")
        return aes_key_unwrap(self.keks[version], wrapped)


def _mac(mac_key, record):
    msg = b"|".join([record["kek_version"].encode(), record["wrapped_dek"], record["iv_ct"], record["context"]])
    return hmac.new(mac_key, msg, hashlib.sha256).digest()


def envelope_encrypt(keyring, plaintext, context=b""):
    """Encrypt one record with its own DEK (AES-256-CBC + HMAC-SHA256, encrypt-then-MAC)."""
    dek = generate_key(256)
    enc_key, mac_key = hkdf_like(dek, b"enc"), hkdf_like(dek, b"mac")
    version, wrapped = keyring.wrap(dek)
    record = dict(kek_version=version, wrapped_dek=wrapped, iv_ct=cbc_encrypt(enc_key, plaintext), context=context)
    record["tag"] = _mac(mac_key, record)
    return record


class IntegrityError(ValueError):
    pass


def envelope_decrypt(keyring, record):
    dek = keyring.unwrap(record["kek_version"], record["wrapped_dek"])
    enc_key, mac_key = hkdf_like(dek, b"enc"), hkdf_like(dek, b"mac")
    if not hmac.compare_digest(_mac(mac_key, record), record["tag"]):      # verify BEFORE decrypting
        raise IntegrityError("record was modified")
    return cbc_decrypt(enc_key, record["iv_ct"])


def rewrap(keyring, record):
    """Key rotation: re-wrap the DEK under the active KEK. The bulk ciphertext is untouched,
    so rotating a KEK costs one small operation per record, not re-encrypting all data."""
    dek = keyring.unwrap(record["kek_version"], record["wrapped_dek"])
    mac_key = hkdf_like(dek, b"mac")
    new = dict(record)
    new["kek_version"], new["wrapped_dek"] = keyring.wrap(dek)
    new["tag"] = _mac(mac_key, new)
    return new
