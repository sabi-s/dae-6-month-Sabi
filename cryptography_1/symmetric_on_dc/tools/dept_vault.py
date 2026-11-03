"""HVMC department key vault: one AES-256 key per department, enforced by Active Directory group membership.

Horizon Valley Medical Center (HVMC) - Cryptography 1: Symmetric Encryption on the Domain Controller
Author: Sabitha S Karanavar

Reuses the from-scratch AES and key management code from the Symmetric Cryptography rubric
(cryptography_1/symmetric_crypto: aes.py, key_management.py), now applied to real department access on hvmc-dc01:

  * Each department has a key-encryption key (KEK, AES-256) in /srv/hvmc-vault/keys/<dept>/kek-<version>.key.
    Linux ACLs let ONLY that department's AD security group read it (e.g. HVMC\\sg-doctors-ehr-rw).
  * Each record is envelope-encrypted: a fresh data key (DEK) per record, AES-256-CBC + HMAC-SHA256
    (encrypt-then-MAC), the DEK wrapped with the department KEK (AES Key Wrap, RFC 3394).
  * Encrypted records in /srv/hvmc-vault/records/<dept>/ are readable by anyone: without the key they are useless.
  * Rotation creates a new KEK version, re-wraps every record's DEK (the bulk data is not re-encrypted)
    and destroys the old KEK.

Commands (init/encrypt/rotate as root; decrypt as any user):
  dept_vault.py init <dept>
  dept_vault.py encrypt <dept> <plaintext-file> <record-name>
  dept_vault.py decrypt <dept> <record-name>
  dept_vault.py show <dept> <record-name>          print the stored (encrypted) record
  dept_vault.py tamper-test <dept> <record-name>   change one byte in memory and prove decryption refuses it
  dept_vault.py rotate <dept>
Exit codes: 0 ok, 3 access denied (not in the group), 4 integrity failure, 5 key retired/missing, 6 no such record.

Lab note: root can read every key here. In production the KEKs live in an HSM or Azure Key Vault and never touch
the file system (see learning/PLAN.md).
"""
import base64
import json
import os
import secrets
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from key_management import (IntegrityError, KeyUnwrapError, aes_key_unwrap, aes_key_wrap,  # noqa: E402
                            envelope_decrypt, envelope_encrypt, generate_key, rewrap)

VAULT = os.environ.get("HVMC_VAULT", "/srv/hvmc-vault")
NO_ACL = os.environ.get("HVMC_NO_ACL") == "1"           # only for testing off the domain controller
DEPARTMENTS = {
    "doctors": "HVMC\\sg-doctors-ehr-rw",
    "nursing": "HVMC\\sg-nursing-ehr-rw",
    "finance": "HVMC\\sg-finance-payroll-rw",
}
FIELDS = ("wrapped_dek", "iv_ct", "context", "tag")


class AccessDenied(Exception):
    pass


def keydir(dept):
    return os.path.join(VAULT, "keys", dept)


def recdir(dept):
    return os.path.join(VAULT, "records", dept)


def setfacl(spec, path):
    if not NO_ACL:
        subprocess.run(["setfacl", "-m", spec, path], check=True)


def need_root():
    if os.geteuid() != 0 and not NO_ACL:
        raise SystemExit("this command must be run with sudo (it manages keys)")


class DeptKeyRing:
    """File-backed key ring with the same wrap/unwrap interface as key_management.KeyRing."""

    def __init__(self, dept):
        if dept not in DEPARTMENTS:
            raise SystemExit(f"unknown department '{dept}' - choose from {', '.join(DEPARTMENTS)}")
        self.dept = dept

    def _read(self, name):
        try:
            with open(os.path.join(keydir(self.dept), name)) as f:
                return f.read().strip()
        except PermissionError:
            raise AccessDenied(f"access denied: only members of {DEPARTMENTS[self.dept]} can read the {self.dept} key")
        except FileNotFoundError:
            raise KeyUnwrapError(f"{self.dept} key {name} does not exist (retired or never created)")

    @property
    def active(self):
        return self._read("active")

    def kek(self, version):
        return bytes.fromhex(self._read(f"kek-{version}.key"))

    def wrap(self, dek):
        version = self.active
        return version, aes_key_wrap(self.kek(version), dek)

    def unwrap(self, version, wrapped):
        return aes_key_unwrap(self.kek(version), wrapped)

    def write_kek(self, version):
        path = os.path.join(keydir(self.dept), f"kek-{version}.key")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        with os.fdopen(fd, "w") as f:
            f.write(generate_key(256).hex() + "\n")
        setfacl(f"g:{DEPARTMENTS[self.dept]}:r", path)
        return path

    def set_active(self, version):
        path = os.path.join(keydir(self.dept), "active")
        tmp = path + ".new"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        with os.fdopen(fd, "w") as f:
            f.write(version + "\n")
        os.replace(tmp, path)
        setfacl(f"g:{DEPARTMENTS[self.dept]}:r", path)


def save_record(dept, name, record):
    out = {"kek_version": record["kek_version"], "algorithm": "AES-256-CBC + HMAC-SHA256, DEK wrapped with AES-KW (RFC 3394)"}
    out.update({k: base64.b64encode(record[k]).decode() for k in FIELDS})
    path = os.path.join(recdir(dept), name + ".json")
    tmp = path + ".new"
    with open(tmp, "w") as f:
        json.dump(out, f, indent=2)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
    return path


def load_record(dept, name):
    with open(os.path.join(recdir(dept), name + ".json")) as f:
        raw = json.load(f)
    rec = {k: base64.b64decode(raw[k]) for k in FIELDS}
    rec["kek_version"] = raw["kek_version"]
    return rec


def cmd_init(dept):
    need_root()
    ring = DeptKeyRing(dept)
    if os.path.exists(os.path.join(keydir(dept), "active")):
        print(f"{dept}: key already exists (active {ring.active}) - nothing to do")
        return
    os.makedirs(keydir(dept), mode=0o750, exist_ok=True)
    os.chmod(keydir(dept), 0o750)
    setfacl(f"g:{DEPARTMENTS[dept]}:rx", keydir(dept))
    os.makedirs(recdir(dept), mode=0o755, exist_ok=True)
    ring.write_kek("v1")
    ring.set_active("v1")
    print(f"{dept}: created AES-256 key v1, readable only by {DEPARTMENTS[dept]}")


def cmd_encrypt(dept, infile, name):
    ring = DeptKeyRing(dept)
    with open(infile, "rb") as f:
        data = f.read()
    record = envelope_encrypt(ring, data, context=f"HVMC|{dept}|{name}".encode())
    path = save_record(dept, name, record)
    print(f"{dept}/{name}: encrypted {len(data)} bytes with a new data key, wrapped by {dept} key {record['kek_version']} -> {path}")


def cmd_decrypt(dept, name):
    rec = load_record(dept, name)
    if rec["context"] != f"HVMC|{dept}|{name}".encode():
        raise IntegrityError("record belongs to a different department or name")
    sys.stdout.write(envelope_decrypt(DeptKeyRing(dept), rec).decode())


def cmd_show(dept, name):
    with open(os.path.join(recdir(dept), name + ".json")) as f:
        print(f.read())


def cmd_tamper(dept, name):
    rec = load_record(dept, name)
    ct = bytearray(rec["iv_ct"])
    ct[20] ^= 0x01                                   # flip one bit of the ciphertext, in memory only
    rec["iv_ct"] = bytes(ct)
    try:
        envelope_decrypt(DeptKeyRing(dept), rec)
    except IntegrityError as e:
        print(f"tampered copy refused: {e} (the file on disk is unchanged)")
        return
    raise SystemExit("ERROR: the tampered record was accepted")


def cmd_rotate(dept):
    need_root()
    ring = DeptKeyRing(dept)
    old = ring.active
    new = f"v{int(old[1:]) + 1}"
    ring.write_kek(new)
    ring.set_active(new)
    names = sorted(f[:-5] for f in os.listdir(recdir(dept)) if f.endswith(".json"))
    for name in names:
        save_record(dept, name, rewrap(ring, load_record(dept, name)))
    old_path = os.path.join(keydir(dept), f"kek-{old}.key")
    with open(old_path, "r+") as f:                 # overwrite before deleting (best effort on a lab disk)
        f.write(secrets.token_hex(32) + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.remove(old_path)
    print(f"{dept}: rotated {old} -> {new}; re-wrapped {len(names)} record(s) {names}; key {old} destroyed")


def main(argv):
    cmds = {"init": (cmd_init, 1), "encrypt": (cmd_encrypt, 3), "decrypt": (cmd_decrypt, 2), "show": (cmd_show, 2),
            "tamper-test": (cmd_tamper, 2), "rotate": (cmd_rotate, 1)}
    if len(argv) < 2 or argv[1] not in cmds or len(argv) - 2 != cmds[argv[1]][1]:
        raise SystemExit(__doc__)
    try:
        cmds[argv[1]][0](*argv[2:])
    except AccessDenied as e:
        print(e, file=sys.stderr)
        sys.exit(3)
    except IntegrityError as e:
        print(f"integrity check failed: {e}", file=sys.stderr)
        sys.exit(4)
    except KeyUnwrapError as e:
        print(e, file=sys.stderr)
        sys.exit(5)
    except FileNotFoundError as e:
        print(f"not found: {e.filename}", file=sys.stderr)
        sys.exit(6)


if __name__ == "__main__":
    main(sys.argv)
