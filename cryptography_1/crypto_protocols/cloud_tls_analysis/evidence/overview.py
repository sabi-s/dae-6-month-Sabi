import sys, collections
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS, DNSQR
for f in sys.argv[1:]:
    pk = rdpcap(f)
    print("==", f.split("/")[-1], len(pk), "packets", "%.1fs" % (float(pk[-1].time - pk[0].time)))
    print("   start", __import__("datetime").datetime.utcfromtimestamp(float(pk[0].time)), "UTC")
    proto = collections.Counter(); ports = collections.Counter(); hosts = collections.Counter(); dns = collections.Counter()
    for p in pk:
        ip = p[IP] if IP in p else p[IPv6] if IPv6 in p else None
        if ip is None: proto["non-IP"] += 1; continue
        if TCP in p: proto["TCP"] += 1; ports["tcp/%d" % min(p[TCP].sport, p[TCP].dport)] += 1
        elif UDP in p: proto["UDP"] += 1; ports["udp/%d" % min(p[UDP].sport, p[UDP].dport)] += 1
        else: proto["other"] += 1
        hosts[ip.src] += 1
        if DNS in p and p[DNS].qr == 0 and DNSQR in p: dns[p[DNSQR].qname.decode(errors="replace")] += 1
    print("  ", dict(proto)); print("   ports", ports.most_common(8)); print("   top src", hosts.most_common(5))
    print("   dns queries", len(dns)); [print("     ", q, n) for q, n in dns.most_common(40)]
