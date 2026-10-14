"""
HMAC (RFC 2104) implemented from scratch, plus an authenticated-message protocol
for HVMC system-to-system traffic (LIS -> EHR).

Horizon Valley Medical Center (HVMC) - Cryptography 1: Hash Functions and Integrity
Author: Sabitha S Karanavar

HMAC(K, m) = H( (K' XOR opad) || H( (K' XOR ipad) || m ) )
where K' is the key padded (or first hashed, if longer than the block) to the
hash block size, ipad = 0x36 repeated and opad = 0x5C repeated.
"""
import hashlib
import hmac as std_hmac
import json
import secrets
import time

IPAD, OPAD = 0x36, 0x5C


class HMAC:
    """From-scratch HMAC over any hashlib hash (SHA-256 by default).
    The keyed inner/outer states are computed once and copied per message,
    the same optimisation real libraries use."""

    def __init__(self, key, digestmod=hashlib.sha256):
        self.digestmod = digestmod
        block = digestmod().block_size              # 64 bytes for SHA-256
        if len(key) > block:
            key = digestmod(key).digest()           # long keys are hashed first
        key = key.ljust(block, b"\x00")
        self._inner = digestmod(bytes(b ^ IPAD for b in key))
        self._outer = digestmod(bytes(b ^ OPAD for b in key))

    def digest(self, message):
        inner = self._inner.copy()
        inner.update(message)
        outer = self._outer.copy()
        outer.update(inner.digest())
        return outer.digest()


def hmac_sha256(key, message):
    return HMAC(key).digest(message)


def verify_tag(key, message, tag):
    """Constant-time comparison: the time taken does not depend on how many bytes match,
    so an attacker cannot guess a valid tag byte by byte."""
    return std_hmac.compare_digest(hmac_sha256(key, message), tag)


# ------------------------------------------------------------ authenticated messages
class AuthError(ValueError):
    pass


def canonical(header, body):
    """Deterministic serialisation so sender and receiver MAC exactly the same bytes."""
    return json.dumps({"header": header, "body": body}, sort_keys=True, separators=(",", ":")).encode()


def sign_message(keys, key_id, sender, body):
    header = {"kid": key_id, "from": sender, "ts": int(time.time()), "nonce": secrets.token_hex(12)}
    tag = hmac_sha256(keys[key_id], canonical(header, body))
    return {"header": header, "body": body, "tag": tag.hex()}


class Receiver:
    """Verifies HMAC-signed messages: known key id, fresh timestamp, unused nonce, valid tag."""

    def __init__(self, keys, max_age=300):
        self.keys, self.max_age, self.seen = keys, max_age, set()

    def accept(self, msg, now=None):
        h = msg["header"]
        now = int(time.time()) if now is None else now
        if h["kid"] not in self.keys:
            raise AuthError("unknown or revoked key id")
        if not verify_tag(self.keys[h["kid"]], canonical(h, msg["body"]), bytes.fromhex(msg["tag"])):
            raise AuthError("invalid tag - message altered or wrong key")
        if abs(now - h["ts"]) > self.max_age:
            raise AuthError("message too old (outside 5-minute window)")
        if h["nonce"] in self.seen:
            raise AuthError("replayed message (nonce already used)")
        self.seen.add(h["nonce"])
        return msg["body"]
