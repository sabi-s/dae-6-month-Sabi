"""
SHA-256 implemented from scratch (FIPS 180-4), for learning purposes.

Horizon Valley Medical Center (HVMC) - Cryptography 1: Cryptographic Fundamentals
Author: Sabitha S Karanavar

Not for production use: Python's hashlib is faster, audited and constant-time.
This version exists to show how the algorithm works step by step.
"""

MASK32 = 0xFFFFFFFF

# Round constants K[0..63]: first 32 bits of the fractional parts of the
# cube roots of the first 64 prime numbers (FIPS 180-4, section 4.2.2).
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# Initial hash value H(0): first 32 bits of the fractional parts of the
# square roots of the first 8 prime numbers (FIPS 180-4, section 5.3.3).
H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]


def rotr(x, n):
    """Rotate a 32-bit word right by n bits."""
    return ((x >> n) | (x << (32 - n))) & MASK32


def ch(x, y, z):
    """Choose: each bit of x picks the bit from y (if 1) or z (if 0)."""
    return (x & y) ^ (~x & z)


def maj(x, y, z):
    """Majority: each output bit is the majority vote of x, y, z."""
    return (x & y) ^ (x & z) ^ (y & z)


def big_sigma0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def big_sigma1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def small_sigma0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)


def small_sigma1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)


def pad(message_len_bytes):
    """Merkle-Damgard padding: 0x80, zeros, then the 64-bit message length in bits,
    so the padded length is a multiple of 64 bytes (512 bits)."""
    bit_len = message_len_bytes * 8
    padding = b"\x80" + b"\x00" * ((55 - message_len_bytes) % 64)
    return padding + bit_len.to_bytes(8, "big")


def compress(state, block):
    """The SHA-256 compression function: mixes one 512-bit block into the 256-bit state."""
    # 1. Message schedule: expand 16 words into 64.
    w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
    for t in range(16, 64):
        w.append((small_sigma1(w[t - 2]) + w[t - 7] + small_sigma0(w[t - 15]) + w[t - 16]) & MASK32)

    # 2. 64 rounds over the eight working variables.
    a, b, c, d, e, f, g, h = state
    for t in range(64):
        t1 = (h + big_sigma1(e) + ch(e, f, g) + K[t] + w[t]) & MASK32
        t2 = (big_sigma0(a) + maj(a, b, c)) & MASK32
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & MASK32, c, b, a, (t1 + t2) & MASK32

    # 3. Davies-Meyer feed-forward: add the input state back (mod 2^32).
    return [(x + y) & MASK32 for x, y in zip(state, [a, b, c, d, e, f, g, h])]


def sha256(message, state=None, prior_len=0):
    """Return the 32-byte SHA-256 digest of `message`.

    `state` and `prior_len` let the hash continue from a known internal state.
    That is only used to demonstrate the length-extension attack.
    """
    if isinstance(message, str):
        message = message.encode()
    h = list(H0 if state is None else state)
    data = message + pad(prior_len + len(message))
    for i in range(0, len(data), 64):
        h = compress(h, data[i:i + 64])
    return b"".join(x.to_bytes(4, "big") for x in h)


def sha256_hex(message):
    return sha256(message).hex()


def digest_to_state(digest):
    """Split a digest back into the eight 32-bit state words (used for length extension)."""
    return [int.from_bytes(digest[i:i + 4], "big") for i in range(0, 32, 4)]


def hmac_sha256(key, message):
    """HMAC (RFC 2104) built on the from-scratch SHA-256, to show the fix for length extension."""
    if len(key) > 64:
        key = sha256(key)
    key = key.ljust(64, b"\x00")
    ipad = bytes(k ^ 0x36 for k in key)
    opad = bytes(k ^ 0x5C for k in key)
    return sha256(opad + sha256(ipad + message))


if __name__ == "__main__":
    for msg in [b"", b"abc"]:
        print(repr(msg), sha256_hex(msg))
