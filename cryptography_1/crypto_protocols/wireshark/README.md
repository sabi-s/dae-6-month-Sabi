# Wireshark capture — Entra ID help-desk sign-in (Rubric 6)

Horizon Valley Medical Center (HVMC) · Cryptography 1 · Configure Cryptographic Protocols · Author: Sabitha S Karanavar

Captured on 5 November 2026 (21:31:54 UTC, 97 seconds, 4,354 packets) on the lab Linux VM (192.168.64.30, Firefox) while the
HVMC help-desk user signed in to mysignins.microsoft.com.

| File | Format |
|---|---|
| `microsoft-login-dump.pcap` | pcap (Linux cooked capture) |
| `microsoft-login-dump.pcapng` | the same packets in pcapng format |

Summary of the analysis: 79 TLS connections on TCP 443 — 73 TLS 1.3 and 6 TLS 1.2, all AES-GCM with ephemeral ECDHE key
exchange; no TLS 1.1/1.0, SSL or plain HTTP; QUIC (HTTP/3) on UDP 443; DNS in clear text on UDP 53.

Useful Wireshark display filters:
- `tls.handshake.type == 1 || tls.handshake.type == 2` — all ClientHello / ServerHello messages
- `tls.handshake.extensions_server_name == "login.microsoftonline.com"` — the Entra ID sign-in handshake
- `tls.handshake.type == 11` — certificates sent in clear (TLS 1.2 only)
- `dns.flags.response == 0` — names looked up
- `quic` — HTTP/3 traffic
- `http` — plain HTTP (none expected)

The traffic is encrypted; no user names, passwords, tokens or tenant identifiers are readable in the capture.
