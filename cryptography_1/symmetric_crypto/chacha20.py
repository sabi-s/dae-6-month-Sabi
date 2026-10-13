"""
ChaCha20 stream cipher (RFC 8439), implemented from scratch.

Horizon Valley Medical Center (HVMC) - Cryptography 1: Implement Symmetric Cryptography
Author: Sabitha S Karanavar

ChaCha20 generates a keystream from (256-bit key, 96-bit nonce, 32-bit counter)
using only Add, Rotate and XOR (ARX) on 32-bit words. Encryption and decryption
are the same operation: ciphertext = plaintext XOR keystream.

For learning only. In production use ChaCha20-Poly1305 (authenticated) from a
vetted library, and NEVER reuse a nonce with the same key.
"""
import secrets
import struct

MASK32 = 0xFFFFFFFF
CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)   # "expand 32-byte k"


def rotl32(v, c):
    return ((v << c) & MASK32) | (v >> (32 - c))


def quarter_round(s, a, b, c, d):
    """The ChaCha quarter round: four add-rotate-xor steps on four state words."""
    s[a] = (s[a] + s[b]) & MASK32; s[d] = rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK32; s[b] = rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK32; s[d] = rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK32; s[b] = rotl32(s[b] ^ s[c], 7)


def chacha20_block(key, counter, nonce):
    """Produce one 64-byte keystream block.
    State (4x4 words): constants | key (8 words) | counter | nonce (3 words)."""
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("key must be 32 bytes and nonce 12 bytes")
    state = list(CONSTANTS) + list(struct.unpack("<8L", key)) + [counter & MASK32] + list(struct.unpack("<3L", nonce))
    working = state[:]
    for _ in range(10):                      # 20 rounds = 10 x (column round + diagonal round)
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)
    # add the original state back so the rounds cannot simply be inverted
    return struct.pack("<16L", *((w + s) & MASK32 for w, s in zip(working, state)))


def chacha20_xor(key, nonce, data, counter=1):
    """Encrypt or decrypt (identical operation) by XORing data with the keystream."""
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = chacha20_block(key, counter + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], ks))
    return bytes(out)


def encrypt(key, plaintext):
    """Convenience API: random 96-bit nonce, returned as nonce || ciphertext."""
    nonce = secrets.token_bytes(12)
    return nonce + chacha20_xor(key, nonce, plaintext)


def decrypt(key, blob):
    return chacha20_xor(key, blob[:12], blob[12:])


if __name__ == "__main__":
    k = secrets.token_bytes(32)
    print(decrypt(k, encrypt(k, b"HVMC lab result")))
