"""
RSA digital signatures implemented from scratch (RFC 8017 / PKCS #1 v2.2):
RSASSA-PSS (section 8.1) and RSASSA-PKCS1-v1_5 (section 8.2).

Horizon Valley Medical Center (HVMC) - Cryptography 1: Implement Digital Signatures
Author: Sabitha S Karanavar

Builds on the from-scratch RSA in ../public_key_crypto/rsa.py (key generation,
CRT with blinding, I2OSP/OS2IP, MGF1). Not for production use: Python big-integer
arithmetic is not constant-time. HVMC production signing uses a vetted library
with keys held in an HSM / Key Vault.
"""
import hashlib
import os
import secrets
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "public_key_crypto"))
import rsa  # noqa: E402  (rubric 4 module)
from rsa import DIGEST_INFO, i2osp, mgf1, os2ip  # noqa: E402


class SignatureError(Exception):
    pass


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------- textbook RSA signatures (insecure)
def textbook_sign(priv, m):
    """s = m^d mod n with no hashing or padding - shown only to explain why padding is needed."""
    return priv.decrypt_raw(m)


def textbook_verify(pub, m, s):
    return pub.encrypt_raw(s) == m


# ---------------------------------------------------------------- RSASSA-PSS
def emsa_pss_encode(m_hash, em_bits, salt_len=32, hash_name="sha256", _salt=None):
    """EMSA-PSS-ENCODE (RFC 8017 section 9.1.1).
        M'  = 0x00*8 || mHash || salt
        H   = Hash(M')
        DB  = PS (zeros) || 0x01 || salt
        EM  = (DB xor MGF1(H)) || H || 0xbc
    The random salt makes every signature different and gives PSS its security proof."""
    h_len = len(m_hash)
    em_len = (em_bits + 7) // 8
    if em_len < h_len + salt_len + 2:
        raise SignatureError("encoding error")
    salt = _salt if _salt is not None else secrets.token_bytes(salt_len)
    h = hashlib.new(hash_name, b"\x00" * 8 + m_hash + salt).digest()
    db = b"\x00" * (em_len - salt_len - h_len - 2) + b"\x01" + salt
    masked_db = bytearray(_xor(db, mgf1(h, em_len - h_len - 1, hash_name)))
    masked_db[0] &= 0xFF >> (8 * em_len - em_bits)      # clear bits above em_bits
    return bytes(masked_db) + h + b"\xbc"


def emsa_pss_verify(m_hash, em, em_bits, salt_len=32, hash_name="sha256"):
    """EMSA-PSS-VERIFY (RFC 8017 section 9.1.2). Returns True/False."""
    h_len = len(m_hash)
    em_len = (em_bits + 7) // 8
    if len(em) != em_len or em_len < h_len + salt_len + 2 or em[-1] != 0xBC:
        return False
    masked_db, h = em[:em_len - h_len - 1], em[em_len - h_len - 1:-1]
    top = 0xFF << (8 - (8 * em_len - em_bits)) & 0xFF
    if masked_db[0] & top:
        return False
    db = bytearray(_xor(masked_db, mgf1(h, em_len - h_len - 1, hash_name)))
    db[0] &= 0xFF >> (8 * em_len - em_bits)
    ps_len = em_len - h_len - salt_len - 2
    if db[:ps_len] != b"\x00" * ps_len or db[ps_len] != 0x01:
        return False
    salt = bytes(db[-salt_len:])
    return secrets.compare_digest(hashlib.new(hash_name, b"\x00" * 8 + m_hash + salt).digest(), h)


def pss_sign(priv, message, salt_len=32, hash_name="sha256"):
    """RSASSA-PSS-SIGN (RFC 8017 section 8.1.1): hash, encode, then s = EM^d mod n."""
    mod_bits = priv.n.bit_length()
    em = emsa_pss_encode(hashlib.new(hash_name, message).digest(), mod_bits - 1, salt_len, hash_name)
    s = priv.decrypt_raw(os2ip(em))              # the private-key operation (CRT + blinding)
    if pow(s, priv.e, priv.n) != os2ip(em):       # fault check: a CRT fault would leak a prime factor
        raise SignatureError("signature self-check failed")
    return i2osp(s, priv.k)


def pss_verify(pub, message, signature, salt_len=32, hash_name="sha256"):
    """RSASSA-PSS-VERIFY (RFC 8017 section 8.1.2): EM = s^e mod n, then EMSA-PSS-VERIFY."""
    if len(signature) != pub.k:
        return False
    s = os2ip(signature)
    if s >= pub.n:
        return False
    mod_bits = pub.n.bit_length()
    em = i2osp(pub.encrypt_raw(s), (mod_bits - 1 + 7) // 8)
    return emsa_pss_verify(hashlib.new(hash_name, message).digest(), em, mod_bits - 1, salt_len, hash_name)


# ---------------------------------------------------------------- RSASSA-PKCS1-v1_5
def emsa_pkcs1v15_encode(message, k, hash_name="sha256"):
    """EM = 0x00 || 0x01 || 0xFF..FF || 0x00 || DigestInfo(hash) (RFC 8017 section 9.2).
    Deterministic: the same key and message always give the same signature."""
    t = DIGEST_INFO[hash_name] + hashlib.new(hash_name, message).digest()
    if k < len(t) + 11:
        raise SignatureError("intended encoded message length too short")
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def pkcs1v15_sign(priv, message, hash_name="sha256"):
    em = emsa_pkcs1v15_encode(message, priv.k, hash_name)
    s = priv.decrypt_raw(os2ip(em))
    if pow(s, priv.e, priv.n) != os2ip(em):
        raise SignatureError("signature self-check failed")
    return i2osp(s, priv.k)


pkcs1v15_verify = rsa.pkcs1v15_verify      # rubric 4: rebuilds EM' and compares it whole


# ---------------------------------------------------------------- key conversion helpers
def scratch_private(lib_key):
    """From a `cryptography` private key to the from-scratch key object."""
    n = lib_key.private_numbers()
    return rsa.RSAPrivateKey(n.p, n.q, n.public_numbers.e)


def scratch_public(lib_pub):
    return rsa.from_library_public(lib_pub)
