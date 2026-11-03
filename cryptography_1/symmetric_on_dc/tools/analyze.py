"""Analyse the symmetric-redo captures with tshark and write a short summary for the report.

Horizon Valley Medical Center (HVMC) - Cryptography 1: Symmetric Encryption on the Domain Controller
Author: Sabitha S Karanavar

  python3 analyze.py <evidence-folder>      (reads pcaps/*.pcap, writes analysis/summary.txt and per-capture files)

Kerberos: lists each AS/TGS request, reply and error with its encryption type (18 = AES-256, 17 = AES-128, 23 = RC4).
SMB: counts the fictional marker text in the raw bytes, and how many packets are SMB3-encrypted (transform header).
"""
import os
import subprocess
import sys

MARKER = b"HVMC-DEMO-NOTE"
ETYPES = {"18": "aes256-cts-hmac-sha1-96", "17": "aes128-cts-hmac-sha1-96", "23": "rc4-hmac (RC4)",
          "24": "rc4-hmac-exp", "3": "des-cbc-md5", "1": "des-cbc-crc"}
MSG = {"10": "AS-REQ", "11": "AS-REP", "12": "TGS-REQ", "13": "TGS-REP", "30": "KRB-ERROR"}
ERRORS = {"14": "KDC_ERR_ETYPE_NOSUPP (encryption type not supported)", "24": "KDC_ERR_PREAUTH_FAILED",
          "25": "KDC_ERR_PREAUTH_REQUIRED (normal first step)", "6": "KDC_ERR_C_PRINCIPAL_UNKNOWN"}


def tshark(pcap, *args):
    r = subprocess.run(["tshark", "-r", pcap, *args], capture_output=True, text=True)
    return r.stdout


def names(field):
    return ", ".join(ETYPES.get(x, x) for x in field.split(",") if x) or "-"


def kerberos(pcap):
    rows = tshark(pcap, "-Y", "kerberos", "-T", "fields", "-E", "separator=|", "-e", "frame.number",
                  "-e", "kerberos.msg_type", "-e", "kerberos.etype", "-e", "kerberos.error_code")
    out = []
    for line in rows.splitlines():
        parts = (line.split("|") + ["", "", "", ""])[:4]
        frame, msg, etype, err = parts
        kind = MSG.get(msg.split(",")[0], msg)
        detail = "offers " + names(etype) if kind.endswith("REQ") else "uses " + names(etype)
        if kind == "KRB-ERROR":
            detail = ERRORS.get(err, "error " + err)
        out.append(f"  frame {frame:>3}  {kind:<9} {detail}")
    return out or ["  (no Kerberos packets decoded)"]


def smb(pcap):
    raw = open(pcap, "rb").read()
    lines = tshark(pcap).splitlines()
    enc = sum("Encrypted SMB3" in x for x in lines)
    smb2 = len(tshark(pcap, "-Y", "smb2").splitlines())
    return [f"  marker text '{MARKER.decode()}' in the raw bytes: {raw.count(MARKER)} time(s)",
            f"  SMB2/3 packets: {smb2}, of which shown as 'Encrypted SMB3': {enc}",
            "  first packets:"] + ["    " + x.strip()[:150] for x in lines[:12]]


def main(evid):
    pc = os.path.join(evid, "pcaps")
    report = ["HVMC symmetric-encryption redo - capture analysis", ""]
    for name in ("krb_before", "krb_after", "smb_before", "smb_after"):
        path = os.path.join(pc, name + ".pcap")
        if not os.path.exists(path):
            report += [f"{name}: not captured", ""]
            continue
        body = kerberos(path) if name.startswith("krb") else smb(path)
        report += [f"{name}.pcap", *body, ""]
        status = os.path.join(evid, "analysis", f"smbstatus_{name}.txt")
        if os.path.exists(status):
            report += ["  smbstatus while connected (see the Encryption column):"]
            report += ["    " + x for x in open(status).read().splitlines() if x.strip()][:14] + [""]
    text = "\n".join(report)
    with open(os.path.join(evid, "analysis", "summary.txt"), "w") as f:
        f.write(text + "\n")
    print(text)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/symdc_evidence"))
