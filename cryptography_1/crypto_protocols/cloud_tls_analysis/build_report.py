"""Build HVMC_Cryptographic_Protocols.pdf - Cryptography Rubric 6 (Configure Cryptographic Protocols), cloud approach.

Evidence (all in ./evidence): tls.json (decoded from the Wireshark capture microsoft-login-dump.pcap with tls_analyze.py),
tls_live_tests_2026-11-05.txt (openssl/curl tests), plus the 3 Nov Entra TLS check. No tenant identifiers.
"""
import collections
import html
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from report_common import CSS, table, term  # noqa: E402

E = html.escape
EV = os.path.join(HERE, "evidence")
OUT_HTML = os.path.join(HERE, "HVMC_Cryptographic_Protocols.html")
OUT_PDF = os.path.join(HERE, "HVMC_Cryptographic_Protocols.pdf")
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

d = json.load(open(os.path.join(EV, "tls.json")))
flows = [f for f in d["flows"] if "ch" in f and "sh" in f]
n = len(flows)
ver = collections.Counter(f["sh"]["version"] for f in flows)
suite = collections.Counter(f["sh"]["suite"] for f in flows)
grp = collections.Counter(f["sh"]["keyshare"] or "(TLS 1.2: ECDHE in ServerKeyExchange)" for f in flows)
sni = collections.Counter(f["ch"]["sni"] for f in flows)
ms = {s: c for s, c in sni.items() if any(k in s for k in ("microsoft", "msauth", "msftauth", "office", "sharepoint", "azure", "live.com"))}
login = next(f for f in flows if f["ch"]["sni"] == "login.microsoftonline.com")
live = open(os.path.join(EV, "tls_live_tests_2026-11-05.txt")).read()
entra = open(os.path.expanduser("~/Downloads/HVMC_Crypto_Reports/rubric6_entra_comparison/entra_tls_check_2026-11-03.txt")).read()
fig = [0]


def cap(text):
    fig[0] += 1
    return f'<div class="cap">Figure {fig[0]}. {text}</div>'


def bar_rows(counter, total):
    rows = []
    for k, v in counter.most_common():
        w = max(2, round(100 * v / total))
        rows.append([E(str(k)), f'{v}', f'<div class="bar"><span style="width:{w}%"></span></div> {100 * v / total:.0f}%'])
    return rows


per_server = []
for s, c in sorted(ms.items(), key=lambda x: -x[1]):
    fs = [f for f in flows if f["ch"]["sni"] == s]
    per_server.append([E(s), str(c), ", ".join(sorted({f["sh"]["version"] for f in fs})),
                       ", ".join(sorted({f["sh"]["suite"] for f in fs}))])

ch = login["ch"]
ch_text = (f"Frame {login['ch_frame']}  ClientHello  ->  {ch['sni']}  ({login['server_ip']}:443)\n"
           f"  supported_versions   : {', '.join(ch['versions'])}\n"
           f"  cipher_suites ({len(ch['suites'])})   : {', '.join(ch['suites'][:3])}\n"
           f"                         {', '.join(ch['suites'][3:7])}\n"
           f"                         ... plus legacy CBC / static-RSA suites: {', '.join(ch['suites'][9:])}\n"
           f"  supported_groups     : {', '.join(ch['groups'])}\n"
           f"  key_share            : {', '.join(ch['keyshares'])}   (ECDHE public keys sent up front)\n"
           f"  signature_algorithms : {', '.join(ch['sigalgs'][:6])}, ...\n"
           f"  ALPN                 : {', '.join(ch['alpn'])}\n"
           f"  server_name (SNI)    : {ch['sni']}   <- visible in clear text\n\n"
           f"Frame {login['sh_frame']}  ServerHello  <-  {ch['sni']}\n"
           f"  selected version     : {login['sh']['version']}\n"
           f"  selected cipher      : {login['sh']['suite']}\n"
           f"  key_share            : {login['sh']['keyshare']}  (ephemeral ECDHE -> forward secrecy)\n"
           f"  after this point     : Certificate, CertificateVerify and Finished are ENCRYPTED (TLS 1.3)\n"
           f"Application data records seen (whole capture): client->server {d['appdata']['c2s']}, server->client {d['appdata']['s2c']}")

chains = """login.live.com  (TLS 1.2, ECDHE-RSA-AES256-GCM-SHA384) - certificate chain visible because TLS 1.2 sends it in clear
  [1] CN=login.live.com, O=Microsoft Corporation          RSA 2048, sha256, valid 2026-10-20 -> 2027-01-28
      SAN: login.live.com, *.login.live.com
  [2] CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1         RSA 2048, sha256, valid 2021-03-30 -> 2031-03-29
      issued by DigiCert Global Root G2 (trusted root in the browser/OS store)

firefox.settings.services.mozilla.com  (TLS 1.2, ECDHE-RSA-AES128-GCM-SHA256)
  [1] CN=firefox.settings.services.mozilla.com             RSA 2048, sha256, valid 2026-10-09 -> 2027-01-07
  [2] CN=YR1, O=Let's Encrypt  ->  [3] CN=Root YR, O=ISRG  ->  ISRG Root X1"""

sshd_conf = """# /etc/ssh/sshd_config.d/00-hvmc-hardening.conf  (hvmc-dc01, Ubuntu + Samba AD DC)
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
AllowUsers ubuntu                 # the local admin account only; domain users do not get a shell on the DC
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"""

ssh_steps = """# 1. On the admin Mac: create the key pair (private key stays on the Mac, protected by a passphrase)
ssh-keygen -t ed25519 -a 100 -C "hvmc-iam-admin" -f ~/.ssh/hvmc_dc01_ed25519

# 2. Install the PUBLIC key on the server (uses the password one last time)
ssh-copy-id -i ~/.ssh/hvmc_dc01_ed25519.pub ubuntu@192.168.56.10

# 3. Prove the key works BEFORE turning passwords off
ssh -i ~/.ssh/hvmc_dc01_ed25519 ubuntu@192.168.56.10 'echo key login ok'

# 4. On the server: add the hardening file, validate, reload (existing sessions stay open)
sudo sshd -t && sudo systemctl reload ssh

# 5. Tests from the Mac
ssh -o PubkeyAuthentication=no ubuntu@192.168.56.10      # expect: Permission denied (publickey)
ssh root@192.168.56.10                                    # expect: Permission denied
ssh -i ~/.ssh/hvmc_dc01_ed25519 ubuntu@192.168.56.10     # expect: logged in, no password asked"""

EXTRA = """
.cap { font-size:8.6pt; font-style:italic; color:#444; margin:-6px 0 12px; }
.bar { display:inline-block; width:60%; height:9px; background:#e7ecf3; vertical-align:middle; }
.bar span { display:block; height:9px; background:#4a6fa5; }
.status { display:inline-block; padding:1px 7px; border-radius:9px; font-size:8.4pt; font-weight:700; }
.done { background:#e3f3e6; color:#1e7b34; } .plan { background:#fdf3e1; color:#8a5a00; }
"""

body = f"""
<div class="runhead">Horizon Valley Medical Center &nbsp;|&nbsp; Cryptography 1 &nbsp;|&nbsp; Rubric 6</div>
<h1>Configure Cryptographic Protocols</h1>
<div class="sub">TLS · HTTPS · Secure Channels · SSH Key-Based Authentication · Wireshark Analysis</div>
<div class="tag">How the HVMC identity platform protects data in transit: configured, tested and analysed on the real Microsoft
Azure / Entra ID environment, with an SSH implementation plan for the on-premises Samba server.</div>
<table class="meta"><tbody>
<tr><td>Project</td><td>AccessGuard Health — Horizon Valley Medical Center (HVMC) Healthcare IAM</td></tr>
<tr><td>Prepared By</td><td>Sabitha S Karanavar</td></tr>
<tr><td>Date</td><td>November 5, 2026</td></tr>
<tr><td>Environment</td><td>Microsoft Entra ID tenant (HVMC) and Azure subscription; capture taken on the lab Linux VM (192.168.64.30, Firefox) during a help-desk sign-in</td></tr>
<tr><td>Evidence</td><td>Wireshark capture <code>microsoft-login-dump.pcap</code> ({sum(1 for _ in flows)} TLS connections decoded), live openssl/curl tests, Azure resource settings</td></tr>
<tr><td>Cost</td><td>$0 (read-only tests; no new resources)</td></tr>
</tbody></table>

<h2>1. Approach and rubric coverage</h2>
<p>Instead of building a separate web server, this report uses the identity platform HVMC already runs in the cloud. Every
sign-in to Microsoft Entra ID, every Microsoft Graph call made by the IAM scripts, and every request to the HVMC storage account
and Key Vault travels over TLS. The goal is to show <b>where</b> each protocol is implemented, <b>which settings HVMC controls</b>,
and <b>what an observer on the network can and cannot see</b>.</p>
{table(["Rubric requirement", "Where it is shown", "Status"], [
    ["Configuration of TLS for a web server", "Section 2: HVMC storage account set to minimum TLS 1.2 + HTTPS only, tested live; Key Vault and Entra endpoints tested", '<span class="status done">Done</span>'],
    ["Implementation of a secure communication channel", "Section 3: the help-desk sign-in to Entra ID end to end (DNS → TCP → TLS 1.3 → HTTP/2), what the channel protects", '<span class="status done">Done</span>'],
    ["Analysis of protocol security using Wireshark", f"Section 4: {n} TLS handshakes decoded from the capture — versions, cipher suites, key exchange, certificates, what stays visible", '<span class="status done">Done</span>'],
    ["Setup of SSH with key-based authentication", "Section 5: implementation plan for the Ubuntu Samba AD server hvmc-dc01 (script prepared in the home lab kit)", '<span class="status plan">Planned</span>'],
], ["30%", "56%", "14%"])}

<h2>2. TLS configuration on HVMC's web endpoints</h2>
<p>In Azure the web server is a managed service, so TLS is configured as a <b>setting on the resource</b> rather than in an nginx or
Apache file. HVMC's storage account <code>hvmcehrstorage</code> (simulated EHR documents) was configured during the cloud security
work with these settings, read back from Azure on 5 November:</p>
{table(["Setting (hvmcehrstorage)", "Value", "What it does"], [
    ["Minimum TLS version", "<b>TLS 1.2</b>", "Requests over TLS 1.0 or 1.1 are rejected"],
    ["Secure transfer required (HTTPS only)", "<b>Enabled</b>", "Plain HTTP requests are rejected"],
    ["Anonymous (public) blob access", "<b>Disabled</b>", "Every request must be authenticated, even over TLS"],
    ["Certificate", "*.blob.core.windows.net, issued by Microsoft TLS G2 RSA CA", "Managed and renewed by Microsoft"],
], ["34%", "24%", "42%"])}
<p>The same settings are on the log storage account <code>hvmcseclogs…</code>. Key Vault (<code>hvmc-accessguard-kv</code>) and the
Entra ID sign-in service enforce TLS 1.2+ by design.</p>
<h3>Live tests (5 November 2026, from the office Mac)</h3>
{term(live)}
{cap("TLS tests with openssl s_client and curl. The storage account still completes an old TLS 1.0/1.1 handshake at Azure's shared front end, but HVMC's minimum-TLS setting rejects the request itself with HTTP 400; TLS 1.2 passes the TLS check and is stopped only because the request had no credentials (409, public access off). Plain HTTP is refused. Key Vault and the sign-in service refuse TLS 1.0/1.1 at the handshake.")}
<div class="box"><b>Finding T1 — where the minimum TLS version is enforced.</b> For Azure Storage, “minimum TLS 1.2” is enforced
<i>per request</i>, not at the handshake: a scanner that only checks the handshake would wrongly report TLS 1.0 as enabled. Testing
with a real request proved the setting works. This is why TLS settings must be tested end to end.</div>

<h2>3. The secure communication channel: a help-desk sign-in</h2>
<p>The capture was taken while the help-desk user signed in to <code>mysignins.microsoft.com</code> on 5 November (97 seconds,
4,354 packets). Every step that carried credentials, MFA approval and tokens went through an encrypted channel:</p>
<div class="flow">
<div class="h">Step</div><div class="h">What happens on the network</div><div class="h">Protected?</div>
<div>1. Name lookup</div><div>DNS query for login.microsoftonline.com (first at t = 13.2 s), plain UDP port 53</div><div class="c"><span class="bad">No</span></div>
<div>2. TCP connection</div><div>3-way handshake to Microsoft's server on port 443</div><div class="c">—</div>
<div>3. TLS 1.3 handshake</div><div>ClientHello/ServerHello agree TLS 1.3, AES-256-GCM, ECDHE key exchange; the server proves its identity with its certificate (encrypted)</div><div class="c"><span class="ok">Yes</span></div>
<div>4. Sign-in</div><div>User name, password, MFA push result and session cookies sent as HTTP/2 inside TLS</div><div class="c"><span class="ok">Yes</span></div>
<div>5. Tokens and API calls</div><div>Access tokens to graph.microsoft.com and api.mysignins.microsoft.com, again inside TLS</div><div class="c"><span class="ok">Yes</span></div>
</div>
{table(["Microsoft endpoint (SNI)", "Connections", "TLS version", "Cipher suite negotiated"], per_server, "small")}
{cap("Microsoft connections during the sign-in, decoded from the capture. The same channel properties protect the IAM PowerShell scripts, which call graph.microsoft.com.")}
<p><b>What the channel guarantees:</b> <b>confidentiality</b> (AES-GCM encryption), <b>integrity</b> (GCM authentication tag on every
record), <b>server authentication</b> (certificate chained to a trusted root, checked by the browser) and <b>forward secrecy</b>
(ephemeral ECDHE keys, so a stolen server key cannot decrypt this capture later). Plain HTTP is redirected to HTTPS and
Entra sends HSTS for one year (3 November check), so the browser will not fall back to HTTP.</p>

<h2>4. Wireshark analysis of the capture</h2>
<div class="stats">
<div class="stat"><b>{n}</b><span>TLS connections decoded</span></div>
<div class="stat"><b>{ver.get('TLS 1.3', 0)}</b><span>used TLS 1.3</span></div>
<div class="stat"><b>{ver.get('TLS 1.2', 0)}</b><span>used TLS 1.2</span></div>
<div class="stat"><b>0</b><span>TLS 1.1 / 1.0 / SSL / plain HTTP</span></div>
</div>
<h3>Negotiated protocol versions and cipher suites</h3>
{table(["TLS version", "Connections", "Share"], bar_rows(ver, n), "small")}
{table(["Cipher suite", "Connections", "Share"], bar_rows(suite, n), "small")}
{table(["Key exchange group", "Connections", "Share"], bar_rows(grp, n), "small")}
{cap("Every connection used an AEAD cipher (AES-GCM) with ephemeral elliptic-curve Diffie-Hellman. No CBC, RC4, 3DES or static-RSA suite was chosen.")}
<h3>Inside one handshake: login.microsoftonline.com</h3>
{term(ch_text)}
{cap("Decoded ClientHello and ServerHello for the Entra ID sign-in service (Wireshark filter: tls.handshake.extensions_server_name == &quot;login.microsoftonline.com&quot;).")}
<h3>Certificate chains (visible only on TLS 1.2 connections)</h3>
{term(chains)}
{cap(f"In TLS 1.3 the certificate is encrypted, so it could only be read on the {ver.get('TLS 1.2', 0)} TLS 1.2 connections ({d['certs_in_clear']} Certificate messages). Each chain ends at a root the client already trusts.")}
<h3>What an observer can and cannot see</h3>
{table(["Visible in the capture", "Hidden by TLS"], [
    ["IP addresses and ports (who talked to which Microsoft server, and when)", "User name, password and MFA approval"],
    [f"Server names: DNS queries and the TLS SNI field ({len(sni)} distinct names)", "Session cookies, access tokens and refresh tokens"],
    ["TLS version, offered and chosen cipher suites, key-exchange group", "Page content, Graph API requests and responses"],
    ["Amount and timing of traffic", f"Even TLS alerts ({len(d['alerts'])} seen) are encrypted; in TLS 1.3 the certificate is too"],
], ["50%", "50%"])}
<h3>Findings</h3>
{table(["#", "Finding", "Risk", "Recommendation"], [
    ["W1", f"{ver.get('TLS 1.3', 0)} of {n} connections used TLS 1.3; the rest TLS 1.2 with ECDHE + AES-GCM. No legacy protocol or cipher was negotiated.", "Low", "Keep minimum TLS 1.2 on every HVMC resource; prefer 1.3"],
    ["W2", "DNS queries and the SNI field show which services were used (e.g. login.microsoftonline.com) in clear text.", "Low–Medium (privacy, metadata)", "Encrypted DNS (DNS over HTTPS) on staff devices; Encrypted Client Hello where supported"],
    ["W3", "The browser still <i>offers</i> legacy CBC and static-RSA suites and SHA-1 signatures for compatibility; the servers never chose them.", "Low (server-side policy prevents downgrade)", "Managed browser policy for clinical workstations can remove legacy suites"],
    ["W4", "Some traffic used QUIC (HTTP/3 over UDP 443, 123 packets), which carries TLS 1.3 inside QUIC.", "Info", "Firewall rules and inspection must account for UDP 443, not only TCP 443"],
    ["T1", "Storage minimum TLS is enforced per request (section 2).", "Info", "Test with real requests, not only handshakes"],
], ["6%", "46%", "18%", "30%"], "small")}

<h2>5. SSH with key-based authentication on the Samba server (implementation plan)</h2>
<p><span class="status plan">Planned</span> HVMC's on-premises identity server <b>hvmc-dc01</b> (Ubuntu with Samba as an Active Directory
domain controller, 192.168.56.10) is administered over SSH. Cloud services do not use SSH for sign-in, so this part is implemented
on the Samba server. The script <code>04_ssh_hardening.sh</code> in the home lab kit already automates the server side; this section
describes what it does and how it will be verified.</p>
<h3>Why keys instead of passwords on a domain controller</h3>
<ul>
<li>A domain controller holds every user's credentials: a guessed or phished admin password would hand over the whole domain.</li>
<li>With a key, the secret (private key) never leaves the admin's device and is never sent over the network; the server only
receives a signature, so nothing reusable can be captured or brute-forced.</li>
<li>Password login over SSH is a constant target of automated guessing; turning it off removes that attack entirely.</li>
</ul>
<h3>Steps</h3>
{term(ssh_steps)}
<h3>Server configuration</h3>
{term(sshd_conf)}
{cap("Hardening file for hvmc-dc01. A separate file in sshd_config.d keeps the distribution's sshd_config untouched and is easy to undo.")}
{table(["Control", "Why it matters on the Samba DC"], [
    ["Ed25519 key with passphrase (-a 100)", "Modern, short keys; the passphrase protects the private key if the Mac is stolen"],
    ["AuthenticationMethods publickey; PasswordAuthentication no", "Only key logins are accepted; password guessing is impossible"],
    ["PermitRootLogin no; AllowUsers ubuntu", "Domain users (e.g. HVMC&#92;sarah.chen) can sign in to Windows/Samba services but cannot open a shell on the DC"],
    ["sntrup761x25519 / curve25519 key exchange; ChaCha20-Poly1305 / AES-GCM; ETM MACs", "Same principles as the TLS analysis: forward secrecy, AEAD ciphers, a post-quantum hybrid key exchange"],
    ["Host key fingerprint checked on first connect", "Stops a man-in-the-middle impersonating the DC (the SSH equivalent of a TLS certificate check)"],
    ["sshd -t before reload; keep the current session and the VirtualBox console open", "A typo cannot lock the administrator out of the DC"],
], ["44%", "56%"], "small")}
<h3>How it interacts with Samba</h3>
<p>SSH only controls <b>administrative shell access</b>. Samba's own services keep their own protection: Kerberos tickets and
LDAP for domain sign-ins, and SMB 3 encryption for file shares (planned in the symmetric-encryption add-on). Because
<code>AllowUsers</code> names the local admin only, the hardening does not affect domain users or Samba services, and Samba's
<code>winbind</code> login integration is not needed for SSH.</p>
<h3>Verification and Wireshark</h3>
{table(["Test", "Expected result"], [
    ["Key login", "Logged in without a password prompt; journalctl shows <code>Accepted publickey for ubuntu</code>"],
    ["Password-only login (-o PubkeyAuthentication=no)", "<code>Permission denied (publickey)</code>"],
    ["root login", "Permission denied"],
    ["<code>sudo sshd -T</code>", "passwordauthentication no, permitrootlogin no, the algorithm lists above"],
    ["Wireshark filter <code>ssh</code> while logging in", "Only the two version banners (SSH-2.0-OpenSSH_…) and the KEXINIT algorithm lists are readable; after NEWKEYS every packet is encrypted, including the user name and the key signature"],
], ["40%", "60%"], "small")}

<h2>6. Cloud and on-premises side by side</h2>
{table(["Protocol need", "Cloud (Entra ID / Azure)", "On-premises (hvmc-dc01, Samba AD)"], [
    ["Web/API traffic", "TLS 1.2/1.3 managed by Microsoft; HVMC sets minimum TLS and HTTPS-only per resource", "LDAPS / TLS with a certificate from the HVMC CA (Rubric 4 PKI)"],
    ["Administrator access", "Microsoft Graph over TLS, MFA, least-privileged help-desk role", "SSH with Ed25519 keys, no passwords, no root"],
    ["Certificates", "Public CAs (DigiCert, Microsoft TLS G2), renewed automatically", "Private HVMC CA; HVMC renews and revokes"],
    ["Who configures what", "Microsoft runs the server side; HVMC chooses settings and verifies them", "HVMC configures and maintains everything"],
], ["22%", "39%", "39%"], "small")}

<h2>7. Conclusion</h2>
<p>All {n} TLS connections in the sign-in capture used TLS 1.2 or 1.3 with forward-secret key exchange and authenticated
encryption, and nothing sensitive was readable. HVMC's own storage endpoint rejects TLS 1.0/1.1 and plain HTTP, proven with live
requests. What remains visible is metadata (server names, timing), which encrypted DNS and ECH would reduce. SSH key-based access
to the Samba domain controller is designed and scripted, and is the next item to run in the home lab.</p>
<p class="note"><b>Next steps:</b> run <code>04_ssh_hardening.sh</code> on hvmc-dc01 and add the SSH capture to this report;
optionally capture with an SSLKEYLOGFILE in a lab browser to show a decrypted view (the key file is a secret and is never published).</p>

<h2>Appendix — reproducing the analysis in Wireshark</h2>
{table(["What to show", "Wireshark display filter"], [
    ["All TLS handshakes", "<code>tls.handshake.type == 1 || tls.handshake.type == 2</code>"],
    ["The Entra sign-in handshake", "<code>tls.handshake.extensions_server_name == &quot;login.microsoftonline.com&quot;</code>"],
    ["Negotiated TLS 1.3", "<code>tls.handshake.extensions.supported_version == 0x0304 &amp;&amp; tls.handshake.type == 2</code>"],
    ["Certificates sent in clear (TLS 1.2)", "<code>tls.handshake.type == 11</code>"],
    ["DNS names looked up", "<code>dns.flags.response == 0</code>"],
    ["QUIC / HTTP/3", "<code>quic</code>"],
    ["Any plain HTTP (expected: none)", "<code>http</code>"],
], ["40%", "60%"], "small")}
<p class="note">The capture was decoded with Python (Scapy) scripts that read the same fields Wireshark shows; they are kept with the
evidence. The raw capture file is not published, because it contains device addresses and browsing metadata.</p>
"""

page = f"""<!doctype html><html><head><meta charset="utf-8"><title>HVMC Configure Cryptographic Protocols</title>
<style>{CSS}{EXTRA}</style></head><body>{body}</body></html>"""
open(OUT_HTML, "w").write(page)
subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={OUT_PDF}", "file://" + OUT_HTML],
               capture_output=True, check=True)
print("wrote", OUT_PDF)
