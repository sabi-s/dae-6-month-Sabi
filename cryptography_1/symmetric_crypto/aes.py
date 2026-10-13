"""
AES (FIPS 197) block cipher with ECB and CBC modes, implemented from scratch.

Horizon Valley Medical Center (HVMC) - Cryptography 1: Implement Symmetric Cryptography
Author: Sabitha S Karanavar

Supports AES-128, AES-192 and AES-256. The S-box is computed from its
mathematical definition (multiplicative inverse in GF(2^8) + affine transform)
instead of being typed in as a table.

For learning only: this code is slow and not constant-time (table lookups can
leak timing). Production code should use the `cryptography` package / OpenSSL.
"""
import secrets

BLOCK = 16


# ------------------------------------------------------------ GF(2^8) maths
def xtime(a):
    """Multiply by x (i.e. 2) in GF(2^8) modulo the AES polynomial x^8 + x^4 + x^3 + x + 1."""
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


def gmul(a, b):
    """Multiply two bytes in GF(2^8) (Russian-peasant multiplication)."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result


def ginv(a):
    """Multiplicative inverse in GF(2^8): a^254 = a^-1 because a^255 = 1. Inverse of 0 is defined as 0."""
    if a == 0:
        return 0
    result, power, e = 1, a, 254
    while e:
        if e & 1:
            result = gmul(result, power)
        power = gmul(power, power)
        e >>= 1
    return result


def _build_sbox():
    sbox = []
    for x in range(256):
        b = ginv(x)
        # affine transform: s = b ^ rotl(b,1) ^ rotl(b,2) ^ rotl(b,3) ^ rotl(b,4) ^ 0x63
        s = b
        for i in range(1, 5):
            s ^= ((b << i) | (b >> (8 - i))) & 0xFF
        sbox.append(s ^ 0x63)
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


SBOX, INV_SBOX = _build_sbox()

# Round constants: successive powers of x (2) in GF(2^8)
RCON = [0x01]
for _ in range(13):
    RCON.append(xtime(RCON[-1]))

# Precomputed multiplication tables for MixColumns (speed only - same maths as gmul)
MUL = {n: [gmul(i, n) for i in range(256)] for n in (2, 3, 9, 11, 13, 14)}


# ------------------------------------------------------------ key schedule
def expand_key(key):
    """Expand a 16/24/32-byte key into (rounds + 1) 16-byte round keys."""
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24 or 32 bytes")
    nk = len(key) // 4
    rounds = nk + 6                       # 10, 12 or 14 rounds
    words = [list(key[i:i + 4]) for i in range(0, len(key), 4)]
    for i in range(nk, 4 * (rounds + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]                    # RotWord
            temp = [SBOX[b] for b in temp]                # SubWord
            temp[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]                # extra SubWord for AES-256
        words.append([a ^ b for a, b in zip(words[i - nk], temp)])
    return [sum(words[r * 4:(r + 1) * 4], []) for r in range(rounds + 1)]


# ------------------------------------------------------------ round functions
# State is a flat list of 16 bytes in column-major order (as in FIPS 197).
def add_round_key(s, k):
    return [a ^ b for a, b in zip(s, k)]


def sub_bytes(s):
    return [SBOX[b] for b in s]


def inv_sub_bytes(s):
    return [INV_SBOX[b] for b in s]


def shift_rows(s):
    # row r is shifted left by r positions; index = col*4 + row
    return [s[((c + r) % 4) * 4 + r] for c in range(4) for r in range(4)]


def inv_shift_rows(s):
    return [s[((c - r) % 4) * 4 + r] for c in range(4) for r in range(4)]


def mix_columns(s):
    m2, m3 = MUL[2], MUL[3]
    out = []
    for c in range(4):
        a0, a1, a2, a3 = s[c * 4:c * 4 + 4]
        out += [m2[a0] ^ m3[a1] ^ a2 ^ a3,
                a0 ^ m2[a1] ^ m3[a2] ^ a3,
                a0 ^ a1 ^ m2[a2] ^ m3[a3],
                m3[a0] ^ a1 ^ a2 ^ m2[a3]]
    return out


def inv_mix_columns(s):
    m9, m11, m13, m14 = MUL[9], MUL[11], MUL[13], MUL[14]
    out = []
    for c in range(4):
        a0, a1, a2, a3 = s[c * 4:c * 4 + 4]
        out += [m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3],
                m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3],
                m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3],
                m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]]
    return out


class AES:
    """The raw AES block cipher: encrypts/decrypts exactly one 16-byte block."""

    def __init__(self, key):
        self.round_keys = expand_key(bytes(key))
        self.rounds = len(self.round_keys) - 1

    def encrypt_block(self, block):
        s = add_round_key(list(block), self.round_keys[0])
        for r in range(1, self.rounds):
            s = add_round_key(mix_columns(shift_rows(sub_bytes(s))), self.round_keys[r])
        s = add_round_key(shift_rows(sub_bytes(s)), self.round_keys[self.rounds])
        return bytes(s)

    def decrypt_block(self, block):
        s = add_round_key(list(block), self.round_keys[self.rounds])
        for r in range(self.rounds - 1, 0, -1):
            s = inv_mix_columns(add_round_key(inv_sub_bytes(inv_shift_rows(s)), self.round_keys[r]))
        s = add_round_key(inv_sub_bytes(inv_shift_rows(s)), self.round_keys[0])
        return bytes(s)


# ------------------------------------------------------------ padding
def pkcs7_pad(data):
    n = BLOCK - len(data) % BLOCK          # always adds 1..16 bytes
    return data + bytes([n]) * n


class PaddingError(ValueError):
    pass


def pkcs7_unpad(data):
    if not data or len(data) % BLOCK:
        raise PaddingError("bad length")
    n = data[-1]
    if not 1 <= n <= BLOCK or data[-n:] != bytes([n]) * n:
        raise PaddingError("bad padding")
    return data[:-n]


# ------------------------------------------------------------ modes
def ecb_encrypt(key, plaintext, pad=True):
    """ECB: each block encrypted independently. Identical blocks -> identical ciphertext. INSECURE."""
    aes = AES(key)
    data = pkcs7_pad(plaintext) if pad else plaintext
    return b"".join(aes.encrypt_block(data[i:i + BLOCK]) for i in range(0, len(data), BLOCK))


def ecb_decrypt(key, ciphertext, pad=True):
    aes = AES(key)
    data = b"".join(aes.decrypt_block(ciphertext[i:i + BLOCK]) for i in range(0, len(ciphertext), BLOCK))
    return pkcs7_unpad(data) if pad else data


def cbc_encrypt(key, plaintext, iv=None, pad=True):
    """CBC: C_i = E_K(P_i XOR C_{i-1}), C_0 = IV. A fresh random IV is generated and
    prepended to the output unless one is supplied (supplying one is for test vectors only)."""
    aes = AES(key)
    fresh_iv = iv is None
    iv = secrets.token_bytes(BLOCK) if fresh_iv else iv
    data = pkcs7_pad(plaintext) if pad else plaintext
    prev, out = iv, []
    for i in range(0, len(data), BLOCK):
        prev = aes.encrypt_block(bytes(a ^ b for a, b in zip(data[i:i + BLOCK], prev)))
        out.append(prev)
    return (iv if fresh_iv else b"") + b"".join(out)


def cbc_decrypt(key, ciphertext, iv=None, pad=True):
    """P_i = D_K(C_i) XOR C_{i-1}. If iv is None, the first 16 bytes of ciphertext are the IV."""
    aes = AES(key)
    if iv is None:
        iv, ciphertext = ciphertext[:BLOCK], ciphertext[BLOCK:]
    if len(ciphertext) % BLOCK:
        raise PaddingError("ciphertext is not a whole number of blocks")
    prev, out = iv, []
    for i in range(0, len(ciphertext), BLOCK):
        block = ciphertext[i:i + BLOCK]
        out.append(bytes(a ^ b for a, b in zip(aes.decrypt_block(block), prev)))
        prev = block
    data = b"".join(out)
    return pkcs7_unpad(data) if pad else data


if __name__ == "__main__":
    k = bytes(range(16))
    print(AES(k).encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff")).hex())
