import sys, collections
from scapy.all import rdpcap, IP, UDP, TCP, DNS, DNSQR, DNSRR
pk = rdpcap(sys.argv[1]); t0 = float(pk[0].time)
q = [p for p in pk if UDP in p and (p[UDP].sport == 443 or p[UDP].dport == 443)]
print("QUIC/UDP-443 packets:", len(q), "servers:", collections.Counter(p[IP].src if p[UDP].sport == 443 else p[IP].dst for p in q if IP in p).most_common(4))
lh = [p for p in q if bytes(p[UDP].payload)[:1] and bytes(p[UDP].payload)[0] & 0x80]
print("QUIC long-header (handshake) packets:", len(lh), "versions:", collections.Counter(bytes(p[UDP].payload)[1:5].hex() for p in lh))
d = [p for p in pk if DNS in p]
print("DNS packets:", len(d), "all plain UDP/53:", all(UDP in p and 53 in (p[UDP].sport, p[UDP].dport) for p in d))
for p in pk:
    if DNS in p and p[DNS].qr == 0 and DNSQR in p and b"login.microsoftonline.com" in p[DNSQR].qname:
        print("first DNS query login.microsoftonline.com at t=%.3f" % (float(p.time)-t0)); break
syn = {}
for i, p in enumerate(pk, 1):
    if TCP in p and IP in p and p[TCP].dport == 443 and p[TCP].flags == "S": syn[(p[IP].src, p[TCP].sport)] = (float(p.time), p[IP].dst, i)
print("TCP connections opened (SYN):", len(syn))
