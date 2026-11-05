import sys, json, struct, collections
from scapy.all import rdpcap, IP, TCP
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
d = json.load(open(sys.argv[2]))
t12 = [f for f in d["flows"] if f.get("sh", {}).get("version") == "TLS 1.2"]
print("TLS 1.2 connections:"); [print("  frame", f["ch_frame"], f["ch"]["sni"], f["sh"]["suite"], "server", f["server_ip"]) for f in t12]
pk = rdpcap(sys.argv[1])
want = {tuple(f["k"]) for f in t12}
streams = collections.defaultdict(dict)
for p in pk:
    if TCP in p and IP in p and p[TCP].sport == 443:
        k = (p[IP].dst, p[TCP].dport, p[IP].src, 443)
        if k in want and bytes(p[TCP].payload): streams[k][p[TCP].seq] = bytes(p[TCP].payload)
for k, segs in streams.items():
    data = b"".join(segs[s] for s in sorted(segs))
    o = 0; hs = b""
    while o + 5 <= len(data):
        ct, rl = data[o], struct.unpack(">H", data[o+3:o+5])[0]
        if ct == 22: hs += data[o+5:o+5+rl]
        if ct == 23: break
        o += 5 + rl
    q = 0
    while q + 4 <= len(hs):
        ht = hs[q]; hl = int.from_bytes(hs[q+1:q+4], "big"); body = hs[q+4:q+4+hl]
        if ht == 11:
            tot = int.from_bytes(body[0:3], "big"); r = 3; n = 0
            print("== chain from", [f["ch"]["sni"] for f in t12 if tuple(f["k"]) == k][0])
            while r < 3 + tot:
                cl = int.from_bytes(body[r:r+3], "big"); c = x509.load_der_x509_certificate(body[r+3:r+3+cl]); r += 3 + cl; n += 1
                pkey = c.public_key()
                kd = f"RSA {pkey.key_size}" if isinstance(pkey, rsa.RSAPublicKey) else f"EC {pkey.curve.name}" if isinstance(pkey, ec.EllipticCurvePublicKey) else type(pkey).__name__
                try: san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
                except Exception: san = []
                print(f"  [{n}] subject={c.subject.rfc4514_string()}\n      issuer={c.issuer.rfc4514_string()}\n      valid {c.not_valid_before_utc:%Y-%m-%d} -> {c.not_valid_after_utc:%Y-%m-%d}  key={kd}  sig={c.signature_hash_algorithm.name if c.signature_hash_algorithm else '?'}  SAN={san[:4]}{'...' if len(san)>4 else ''} ({len(san)} names)")
        q += 4 + hl
print("alerts (frame, from_client, level/desc hex):", d["alerts"])
