"""
Diffie-Hellman key exchange implemented from scratch, for learning purposes.

Horizon Valley Medical Center (HVMC) - Cryptography 1: Cryptographic Fundamentals
Author: Sabitha S Karanavar

Includes: square-and-multiply modular exponentiation, Miller-Rabin primality
testing, derivation of the RFC 3526 2048-bit MODP group prime from its
published formula, public-key validation, and key derivation with the
from-scratch SHA-256.

Not for production use: this code is not constant-time and has not been
audited. Use a vetted library (e.g. the `cryptography` package or TLS) in practice.
"""
import secrets

from sha256 import sha256


# ---------------------------------------------------------------- number theory
def mod_pow(base, exponent, modulus):
    """Left-to-right square-and-multiply: computes base^exponent mod modulus
    in O(log exponent) multiplications instead of exponent multiplications."""
    if modulus == 1:
        return 0
    result = 1
    base %= modulus
    for bit in bin(exponent)[2:]:
        result = (result * result) % modulus      # square every bit
        if bit == "1":
            result = (result * base) % modulus     # multiply when the bit is 1
    return result


def is_probable_prime(n, rounds=40):
    """Miller-Rabin test. A composite passes one round with probability <= 1/4,
    so 40 rounds give an error bound of 4^-40 = 2^-80."""
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:          # write n - 1 = 2^s * d with d odd
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = mod_pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False       # a is a witness that n is composite
    return True


def random_safe_prime(bits):
    """Find p = 2q + 1 with p and q both prime (used for the small toy groups)."""
    while True:
        q = secrets.randbits(bits - 1) | (1 << (bits - 2)) | 1
        if is_probable_prime(q) and is_probable_prime(2 * q + 1):
            return 2 * q + 1


def pi_fixed_point(bits):
    """floor(pi * 2^bits) using Machin's formula: pi = 16*atan(1/5) - 4*atan(1/239)."""
    guard = 64
    one = 1 << (bits + guard)

    def atan_inv(x):
        total, term, n, sign = 0, one // x, 1, 1
        x2 = x * x
        while term:
            total += sign * (term // n)
            term //= x2
            n += 2
            sign = -sign
        return total

    return (16 * atan_inv(5) - 4 * atan_inv(239)) >> guard


def rfc3526_group14_prime():
    """RFC 3526 section 3: p = 2^2048 - 2^1984 - 1 + 2^64 * ( floor(2^1918 * pi) + 124476 ).
    The digits of pi are a 'nothing-up-my-sleeve' source: nobody could have chosen
    them to hide a weakness."""
    return 2**2048 - 2**1984 - 1 + 2**64 * (pi_fixed_point(1918) + 124476)


P_2048 = rfc3526_group14_prime()
G = 2
Q_2048 = (P_2048 - 1) // 2


# ---------------------------------------------------------------- the protocol
class DHParty:
    """One side of a Diffie-Hellman exchange (e.g. the HVMC EHR server or the LIS)."""

    def __init__(self, name, p=P_2048, g=G):
        self.name, self.p, self.g = name, p, g
        self.q = (p - 1) // 2
        # private key a, chosen uniformly from [2, p-2]
        self._private = secrets.randbelow(p - 3) + 2
        # public key A = g^a mod p
        self.public = mod_pow(g, self._private, p)

    def validate_peer(self, peer_public):
        """Reject values that would make the shared secret predictable:
        1, p-1, and anything outside the prime-order subgroup (small-subgroup attack)."""
        if not 2 <= peer_public <= self.p - 2:
            raise ValueError("peer public key out of range")
        if mod_pow(peer_public, self.q, self.p) != 1:
            raise ValueError("peer public key not in the prime-order subgroup")

    def shared_secret(self, peer_public):
        """s = B^a mod p = (g^b)^a = g^(ab) mod p."""
        self.validate_peer(peer_public)
        return mod_pow(peer_public, self._private, self.p)

    def session_key(self, peer_public):
        """Derive a 256-bit symmetric key from the shared secret with SHA-256."""
        s = self.shared_secret(peer_public)
        s_bytes = s.to_bytes((self.p.bit_length() + 7) // 8, "big")
        return sha256(b"HVMC-DH-v1" + s_bytes)


def brute_force_dlog(g, h, p):
    """Find x with g^x = h (mod p) by trying every exponent. Only feasible for tiny p."""
    value = 1
    for x in range(p):
        if value == h:
            return x
        value = (value * g) % p
    return None


if __name__ == "__main__":
    ehr, lis = DHParty("EHR"), DHParty("LIS")
    k1, k2 = ehr.session_key(lis.public), lis.session_key(ehr.public)
    print("keys match:", k1 == k2, k1.hex())
