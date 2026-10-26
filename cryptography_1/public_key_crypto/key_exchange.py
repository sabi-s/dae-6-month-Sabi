"""
Secure key exchange for HVMC: X25519 (RFC 7748) and HKDF (RFC 5869) from scratch,
an authenticated ephemeral key exchange that uses the HVMC PKI certificates,
and a comparison with RSA key transport (forward secrecy).

Horizon Valley Medical Center (HVMC) - Cryptography 1: Utilize Public Key Cryptography
Author: Sabitha S Karanavar

The handshake follows the same idea as TLS 1.3 (ephemeral ECDHE + certificate +
signature over the transcript + HKDF key schedule), simplified for teaching.
Not for production use: HVMC systems use TLS 1.3 from a vetted library.
"""
import hashlib
import hmac
import secrets
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import ExtendedKeyUsageOID

import pki

# ---------------------------------------------------------------- X25519 (RFC 7748)
P = 2 ** 255 - 19
A24 = 121665                     # (486662 - 2) / 4


def _decode_scalar(k):
    """Clamp: clear the 3 low bits (multiple of the cofactor 8, so small-subgroup
    points give nothing away), clear bit 255, set bit 254 (constant ladder length)."""
    b = bytearray(k)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(b, "little")


def _decode_u(u):
    b = bytearray(u)
    b[31] &= 127                 # ignore the top bit (RFC 7748 section 5)
    return int.from_bytes(b, "little") % P


def x25519(k, u):
    """Montgomery ladder on Curve25519, written as in RFC 7748 section 5.
    Each step does the same work whatever the key bit is, with a conditional swap."""
    k, x1 = _decode_scalar(k), _decode_u(u)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


BASE_POINT = (9).to_bytes(32, "little")


def x25519_keypair():
    private = secrets.token_bytes(32)
    return private, x25519(private, BASE_POINT)


def x25519_shared(private, peer_public):
    shared = x25519(private, peer_public)
    if shared == bytes(32):      # peer sent a low-order point: abort (RFC 7748 section 6.1)
        raise ValueError("all-zero shared secret: invalid peer public key")
    return shared


# ---------------------------------------------------------------- HKDF (RFC 5869)
def hkdf_extract(salt, ikm, hash_name="sha256"):
    return hmac.new(salt or bytes(hashlib.new(hash_name).digest_size), ikm, hash_name).digest()


def hkdf_expand(prk, info, length, hash_name="sha256"):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hash_name).digest()
        out += t
        i += 1
    return out[:length]


def hkdf(ikm, salt, info, length=32):
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


# ---------------------------------------------------------------- record layer
class SecureChannel:
    """AES-256-GCM in each direction with a per-message counter nonce: replayed,
    reordered or modified records fail authentication."""

    def __init__(self, send_key, recv_key):
        self.send, self.recv = AESGCM(send_key), AESGCM(recv_key)
        self.send_seq = self.recv_seq = 0

    @staticmethod
    def _nonce(seq):
        return bytes(4) + struct.pack(">Q", seq)

    def seal(self, plaintext):
        rec = self.send.encrypt(self._nonce(self.send_seq), plaintext, b"HVMC-record")
        self.send_seq += 1
        return rec

    def open(self, record):
        pt = self.recv.decrypt(self._nonce(self.recv_seq), record, b"HVMC-record")
        self.recv_seq += 1
        return pt


def key_schedule(shared, transcript_hash):
    """Separate keys per direction, bound to everything said in the handshake."""
    prk = hkdf_extract(transcript_hash, shared)
    return hkdf_expand(prk, b"HVMC v1 client->server", 32), hkdf_expand(prk, b"HVMC v1 server->client", 32)


# ---------------------------------------------------------------- 1. unauthenticated exchange (insecure)
def unauthenticated_exchange(attacker=None):
    """Plain ephemeral X25519. Returns what each side ends up with. If `attacker` is
    given it sits in the middle and replaces both public keys with its own."""
    c_priv, c_pub = x25519_keypair()
    s_priv, s_pub = x25519_keypair()
    to_server, to_client = c_pub, s_pub
    if attacker is not None:
        m_priv, m_pub = x25519_keypair()
        to_server, to_client = m_pub, m_pub
        attacker["with_client"] = hashlib.sha256(x25519_shared(m_priv, c_pub)).digest()
        attacker["with_server"] = hashlib.sha256(x25519_shared(m_priv, s_pub)).digest()
    client_key = hashlib.sha256(x25519_shared(c_priv, to_client)).digest()
    server_key = hashlib.sha256(x25519_shared(s_priv, to_server)).digest()
    return client_key, server_key


# ---------------------------------------------------------------- 2. authenticated exchange (the HVMC design)
class HandshakeError(Exception):
    pass


def _sign(key, data):
    return key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())


def _verify(cert, sig, data):
    try:
        cert.public_key().verify(sig, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                                 hashes.SHA256())
        return True
    except Exception:
        return False


def authenticated_handshake(server, client, trust, at, tamper=None, log=None):
    """server/client: dict(key=private key, cert=leaf certificate). trust: dict(roots, intermediates, crls).
    tamper: optional function(stage, message) -> message, used to simulate an attacker on the wire.
    Returns (client_channel, server_channel)."""
    log = log if log is not None else []
    wire = tamper or (lambda stage, m: m)
    transcript = hashlib.sha256()

    # 1. ClientHello: client ephemeral key + nonce
    c_eph, c_eph_pub = x25519_keypair()
    hello = wire("client_hello", {"eph": c_eph_pub, "nonce": secrets.token_bytes(32), "server_name": "portal.hvmc.example"})
    transcript.update(hello["eph"] + hello["nonce"] + hello["server_name"].encode())
    log.append("ClientHello: X25519 ephemeral key + 32-byte nonce, SNI portal.hvmc.example")

    # 2. ServerHello: server ephemeral key + nonce, certificate, signature over the transcript
    s_eph, s_eph_pub = x25519_keypair()
    s_nonce = secrets.token_bytes(32)
    transcript.update(s_eph_pub + s_nonce)
    s_sig = _sign(server["key"], b"HVMC server verify" + transcript.digest())
    reply = wire("server_hello", {"eph": s_eph_pub, "nonce": s_nonce, "cert": server["cert"], "sig": s_sig})
    log.append("ServerHello: X25519 ephemeral key + nonce + certificate + RSA-PSS signature over transcript")

    # 3. client checks the server: certificate path to the HVMC root, hostname, purpose, signature
    c_transcript = hashlib.sha256(hello["eph"] + hello["nonce"] + hello["server_name"].encode()
                                  + reply["eph"] + reply["nonce"])
    ok, checks = pki.validate_path(reply["cert"], trust["intermediates"], trust["roots"], at,
                                   purpose=ExtendedKeyUsageOID.SERVER_AUTH, hostname="portal.hvmc.example",
                                   crls=trust["crls"])
    if not ok:
        raise HandshakeError("server certificate rejected: " + "; ".join(c[0] for c in checks if not c[1]))
    if not _verify(reply["cert"], reply["sig"], b"HVMC server verify" + c_transcript.digest()):
        raise HandshakeError("server signature over the handshake does not verify (key substitution?)")
    log.append(f"Client: server certificate path valid ({len(checks)} checks) and transcript signature verified")

    # 4. client authenticates too (mutual TLS style): its certificate + signature
    c_transcript.update(reply["cert"].public_bytes(pki.serialization.Encoding.DER))
    c_sig = _sign(client["key"], b"HVMC client verify" + c_transcript.digest())
    finish = wire("client_finish", {"cert": client["cert"], "sig": c_sig})
    s_transcript = transcript.copy()
    s_transcript.update(server["cert"].public_bytes(pki.serialization.Encoding.DER))
    ok, checks = pki.validate_path(finish["cert"], trust["intermediates"], trust["roots"], at,
                                   purpose=ExtendedKeyUsageOID.CLIENT_AUTH, crls=trust["crls"])
    if not ok:
        raise HandshakeError("client certificate rejected: " + "; ".join(c[0] for c in checks if not c[1]))
    if not _verify(finish["cert"], finish["sig"], b"HVMC client verify" + s_transcript.digest()):
        raise HandshakeError("client signature over the handshake does not verify")
    who = finish["cert"].subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    log.append(f"Server: client certificate valid for clientAuth ({who}) and signature verified")

    # 5. both sides derive the same keys; ephemeral private keys are then discarded
    c_shared = x25519_shared(c_eph, reply["eph"])
    s_shared = x25519_shared(s_eph, hello["eph"])
    c_c2s, c_s2c = key_schedule(c_shared, c_transcript.digest())
    s_c2s, s_s2c = key_schedule(s_shared, s_transcript.digest())
    del c_eph, s_eph
    log.append("Both: HKDF-SHA256 over the X25519 secret and transcript hash -> two AES-256-GCM keys; "
               "ephemeral private keys deleted")
    return SecureChannel(c_c2s, c_s2c), SecureChannel(s_s2c, s_c2s)


# ---------------------------------------------------------------- 3. RSA key transport vs ECDHE (forward secrecy)
def rsa_key_transport(server_pub_scratch, oaep_encrypt):
    """Old TLS-RSA style: the client picks the session key and sends it encrypted to the
    server's long-term RSA key. Anyone who later gets that RSA key can decrypt recordings."""
    session_key = secrets.token_bytes(32)
    return session_key, oaep_encrypt(server_pub_scratch, session_key, label=b"HVMC key transport")
