"""
File Integrity Monitoring (FIM) for HVMC EHR exports and audit logs.

Horizon Valley Medical Center (HVMC) - Cryptography 1: Hash Functions and Integrity
Author: Sabitha S Karanavar

  baseline: hash every file (SHA-256, streamed in 64 KiB chunks), build a Merkle tree,
            and seal the manifest with HMAC-SHA256 so an attacker cannot rewrite it
  verify:   re-hash and report MODIFIED / ADDED / DELETED files, and whether the
            manifest itself was tampered with
  proof:    Merkle inclusion proof that one file belongs to a sealed baseline

Usage:
  export HVMC_FIM_KEY=<64 hex chars>          (store the real key in Azure Key Vault)
  python3 file_integrity.py baseline <folder> <manifest.json>
  python3 file_integrity.py verify   <folder> <manifest.json>
"""
import hashlib
import hmac
import json
import os
import sys
import time

CHUNK = 64 * 1024


def hash_file(path):
    """SHA-256 of a file without loading it all into memory."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def scan(folder):
    files = {}
    for root, _, names in os.walk(folder):
        for n in sorted(names):
            full = os.path.join(root, n)
            rel = os.path.relpath(full, folder).replace(os.sep, "/")
            files[rel] = {"sha256": hash_file(full), "size": os.path.getsize(full)}
    return dict(sorted(files.items()))


# ------------------------------------------------------------ Merkle tree
def _leaf(path, digest):
    return hashlib.sha256(b"\x00" + path.encode() + b"\x00" + bytes.fromhex(digest)).digest()


def _node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()     # 0x00/0x01 prefixes: domain separation


def merkle_levels(files):
    level = [_leaf(p, v["sha256"]) for p, v in files.items()] or [hashlib.sha256(b"").digest()]
    levels = [level]
    while len(level) > 1:
        if len(level) % 2:
            level = level + [level[-1]]
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(level)
    return levels


def merkle_root(files):
    return merkle_levels(files)[-1][0].hex()


def merkle_proof(files, path):
    """Sibling hashes from leaf to root proving `path` is in the tree."""
    idx = list(files).index(path)
    proof = []
    for level in merkle_levels(files)[:-1]:
        if len(level) % 2:
            level = level + [level[-1]]
        sib = idx ^ 1
        proof.append(("L" if sib < idx else "R", level[sib].hex()))
        idx //= 2
    return proof


def verify_proof(path, digest, proof, root):
    h = _leaf(path, digest)
    for side, sib in proof:
        h = _node(bytes.fromhex(sib), h) if side == "L" else _node(h, bytes.fromhex(sib))
    return h.hex() == root


# ------------------------------------------------------------ sealed manifest
def _seal_bytes(manifest):
    body = {k: v for k, v in manifest.items() if k != "hmac"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def create_baseline(folder, key, key_id="fim-v1"):
    files = scan(folder)
    manifest = {"algorithm": "sha256", "created": time.strftime("%Y-%m-%dT%H:%M:%S"), "key_id": key_id,
                "file_count": len(files), "merkle_root": merkle_root(files), "files": files}
    manifest["hmac"] = hmac.new(key, _seal_bytes(manifest), hashlib.sha256).hexdigest()
    return manifest


def verify_baseline(folder, manifest, key):
    report = {"manifest_ok": hmac.compare_digest(
        hmac.new(key, _seal_bytes(manifest), hashlib.sha256).hexdigest(), manifest.get("hmac", ""))}
    old, new = manifest["files"], scan(folder)
    report["modified"] = sorted(p for p in old.keys() & new.keys() if old[p]["sha256"] != new[p]["sha256"])
    report["deleted"] = sorted(old.keys() - new.keys())
    report["added"] = sorted(new.keys() - old.keys())
    report["merkle_root_now"] = merkle_root(new)
    report["clean"] = report["manifest_ok"] and not (report["modified"] or report["deleted"] or report["added"])
    return report


def _key_from_env():
    k = os.environ.get("HVMC_FIM_KEY")
    if not k:
        sys.exit("Set HVMC_FIM_KEY to a 64-hex-character secret (keep it in Azure Key Vault, not in the repo).")
    return bytes.fromhex(k)


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] not in ("baseline", "verify"):
        sys.exit(__doc__)
    cmd, folder, mpath = sys.argv[1:]
    key = _key_from_env()
    if cmd == "baseline":
        m = create_baseline(folder, key)
        with open(mpath, "w") as f:
            json.dump(m, f, indent=2)
        print(f"baseline of {m['file_count']} files written to {mpath}; merkle root {m['merkle_root']}")
    else:
        with open(mpath) as f:
            r = verify_baseline(folder, json.load(f), key)
        print(json.dumps(r, indent=2))
        sys.exit(0 if r["clean"] else 2)
