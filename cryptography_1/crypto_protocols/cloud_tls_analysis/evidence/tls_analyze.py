"""Parse TLS ClientHello/ServerHello records from TCP/443 by hand (robust, no reassembly needed for hellos)."""
import sys, json, collections, struct, datetime
from scapy.all import rdpcap, IP, IPv6, TCP, UDP

VER = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3", 0x0300: "SSL 3.0"}
CS = {0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
      0xc02b: "ECDHE-ECDSA-AES128-GCM-SHA256", 0xc02f: "ECDHE-RSA-AES128-GCM-SHA256", 0xc02c: "ECDHE-ECDSA-AES256-GCM-SHA384",
      0xc030: "ECDHE-RSA-AES256-GCM-SHA384", 0xcca9: "ECDHE-ECDSA-CHACHA20-POLY1305", 0xcca8: "ECDHE-RSA-CHACHA20-POLY1305",
      0xc013: "ECDHE-RSA-AES128-CBC-SHA", 0xc014: "ECDHE-RSA-AES256-CBC-SHA", 0x009c: "RSA-AES128-GCM-SHA256",
      0x009d: "RSA-AES256-GCM-SHA384", 0x002f: "RSA-AES128-CBC-SHA", 0x0035: "RSA-AES256-CBC-SHA", 0xc009: "ECDHE-ECDSA-AES128-CBC-SHA", 0xc00a: "ECDHE-ECDSA-AES256-CBC-SHA"}
GROUPS = {0x001d: "x25519", 0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x0100: "ffdhe2048", 0x0101: "ffdhe3072",
          0x11ec: "X25519MLKEM768 (post-quantum hybrid)", 0x6399: "X25519Kyber768Draft00 (post-quantum hybrid)"}
SIG = {0x0403: "ecdsa_secp256r1_sha256", 0x0503: "ecdsa_secp384r1_sha384", 0x0603: "ecdsa_secp521r1_sha512", 0x0804: "rsa_pss_rsae_sha256",
       0x0805: "rsa_pss_rsae_sha384", 0x0806: "rsa_pss_rsae_sha512", 0x0401: "rsa_pkcs1_sha256", 0x0501: "rsa_pkcs1_sha384",
       0x0601: "rsa_pkcs1_sha512", 0x0203: "ecdsa_sha1", 0x0201: "rsa_pkcs1_sha1", 0x0807: "ed25519"}

def u16(b, o): return struct.unpack(">H", b[o:o+2])[0]

def exts(b, o, end):
    out = {}
    while o + 4 <= end:
        t, l = u16(b, o), u16(b, o+2); out[t] = b[o+4:o+4+l]; o += 4 + l
    return out

def client_hello(h):
    o = 4; legacy = u16(h, o); o += 2 + 32
    sl = h[o]; o += 1 + sl
    cl = u16(h, o); suites = [u16(h, o+2+i) for i in range(0, cl, 2)]; o += 2 + cl
    o += 1 + h[o]
    el = u16(h, o); e = exts(h, o+2, o+2+el)
    sni = None
    if 0 in e and len(e[0]) > 5: sni = e[0][5:5+u16(e[0], 3)].decode(errors="replace")
    versions = [u16(e[43], 1+i) for i in range(0, e[43][0], 2)] if 43 in e else [legacy]
    groups = [u16(e[10], 2+i) for i in range(0, u16(e[10], 0), 2)] if 10 in e else []
    keyshares = []
    if 51 in e:
        ks = e[51]; p = 2
        while p + 4 <= len(ks): g, l = u16(ks, p), u16(ks, p+2); keyshares.append(g); p += 4 + l
    alpn = []
    if 16 in e:
        a = e[16]; p = 2
        while p < len(a): l = a[p]; alpn.append(a[p+1:p+1+l].decode(errors="replace")); p += 1 + l
    sigs = [u16(e[13], 2+i) for i in range(0, u16(e[13], 0), 2)] if 13 in e else []
    grease = lambda x: (x & 0x0f0f) == 0x0a0a
    return {"sni": sni, "versions": [VER.get(v, hex(v)) for v in versions if not grease(v)],
            "suites": [CS.get(s, hex(s)) for s in suites if not grease(s)], "groups": [GROUPS.get(g, hex(g)) for g in groups if not grease(g)],
            "keyshares": [GROUPS.get(g, hex(g)) for g in keyshares if not grease(g)], "alpn": alpn, "sigalgs": [SIG.get(s, hex(s)) for s in sigs],
            "ech": 0xfe0d in e, "ext_count": len(e)}

def server_hello(h):
    o = 4; legacy = u16(h, o); o += 2
    rnd = h[o:o+32]; o += 32
    o += 1 + h[o]
    suite = u16(h, o); o += 3
    el = u16(h, o); e = exts(h, o+2, o+2+el)
    ver = u16(e[43], 0) if 43 in e else legacy
    ks = u16(e[51], 0) if 51 in e and len(e[51]) >= 2 else None
    alpn = e[16][3:3+e[16][2]].decode(errors="replace") if 16 in e and len(e[16]) > 3 else None
    hrr = rnd.hex() == "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
    return {"version": VER.get(ver, hex(ver)), "suite": CS.get(suite, hex(suite)), "keyshare": GROUPS.get(ks, hex(ks) if ks else None),
            "alpn": alpn, "hrr": hrr}

pk = rdpcap(sys.argv[1]); t0 = float(pk[0].time)
flows = {}; stats = collections.Counter(); certs_seen = 0; appdata = collections.Counter(); alerts = []
for i, p in enumerate(pk, 1):
    if TCP not in p: continue
    ip = p[IP] if IP in p else p[IPv6] if IPv6 in p else None
    pl = bytes(p[TCP].payload)
    if not pl: continue
    cli = p[TCP].dport == 443
    key = (ip.src, p[TCP].sport, ip.dst, p[TCP].dport) if cli else (ip.dst, p[TCP].dport, ip.src, p[TCP].sport)
    f = flows.setdefault(key, {"frame": i, "t": round(float(p.time) - t0, 3), "server_ip": key[2]})
    o = 0
    while o + 5 <= len(pl):
        ct, rv, rl = pl[o], u16(pl, o+1), u16(pl, o+3)
        if ct not in (20, 21, 22, 23) or rv not in VER: break
        body = pl[o+5:o+5+rl]
        if ct == 22 and body:
            ht = body[0]
            try:
                if ht == 1 and cli and "ch" not in f: f["ch"] = client_hello(body); f["ch_frame"] = i
                elif ht == 2 and not cli and "sh" not in f: f["sh"] = server_hello(body); f["sh_frame"] = i
                elif ht == 11: certs_seen += 1
            except Exception as ex: stats["parse_err"] += 1
        elif ct == 23: appdata["c2s" if cli else "s2c"] += 1; f["appdata"] = f.get("appdata", 0) + 1
        elif ct == 21: alerts.append((i, cli, body.hex()))
        o += 5 + rl
json.dump({"flows": [dict(k=list(k), **v) for k, v in flows.items()], "certs_in_clear": certs_seen, "appdata": appdata, "alerts": alerts,
           "stats": stats}, open(sys.argv[2], "w"), indent=1, default=str)
done = [f for f in flows.values() if "ch" in f]
print("TCP/443 connections with ClientHello:", len(done), " with ServerHello:", sum("sh" in f for f in done))
print("negotiated versions:", collections.Counter(f["sh"]["version"] for f in done if "sh" in f))
print("negotiated suites:", collections.Counter(f["sh"]["suite"] for f in done if "sh" in f))
print("key exchange groups:", collections.Counter(f["sh"]["keyshare"] for f in done if "sh" in f))
print("ALPN:", collections.Counter(f["sh"]["alpn"] for f in done if "sh" in f))
print("HelloRetryRequest:", sum(f["sh"]["hrr"] for f in done if "sh" in f), " certificates sent in clear (TLS1.2 only):", certs_seen)
print("app data records c2s/s2c:", dict(appdata), " alerts:", len(alerts))
print("SNIs:", collections.Counter(f["ch"]["sni"] for f in done).most_common(30))
ex = next(f for f in done if f["ch"]["sni"] == "login.microsoftonline.com")
print("EXAMPLE login.microsoftonline.com frame", ex["ch_frame"], json.dumps(ex["ch"], indent=0)[:1500], ex.get("sh"))
