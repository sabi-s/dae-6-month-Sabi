"""Small, careful editor for /etc/samba/smb.conf used by the symmetric-encryption redo.

Horizon Valley Medical Center (HVMC) - Cryptography 1: Symmetric Encryption on the Domain Controller
Author: Sabitha S Karanavar

Every line it adds is preceded by a marker comment, so `undo` removes exactly what was added and nothing else.
(Samba does not allow comments at the end of a setting line, so the marker goes on the line above.)

  python3 smbconf_edit.py set-global  "<parameter>" "<value>"          add/replace in [global]
  python3 smbconf_edit.py set-shares  "<parameter>" "<value>" /srv/shares   add to every share whose path is under the prefix
  python3 smbconf_edit.py undo        "<parameter>"                     remove the marked lines for that parameter
  python3 smbconf_edit.py list-shares /srv/shares                       print the share names under the prefix
Optional: --file <path> (default /etc/samba/smb.conf). The caller makes the backup and runs testparm.
"""
import re
import sys

MARK = "# HVMC-SYMDC: added by the symmetric-encryption redo"
SECTION = re.compile(r"^\s*\[([^\]]+)\]\s*$")


def norm(name):
    return " ".join(name.lower().split())


def key_of(line):
    if "=" not in line or line.lstrip().startswith(("#", ";")):
        return None
    return norm(line.split("=", 1)[0])


def sections(lines):
    """Return [(name, header_index, end_index_exclusive)]."""
    found = []
    for i, line in enumerate(lines):
        m = SECTION.match(line)
        if m:
            if found:
                found[-1][2] = i
            found.append([m.group(1).strip(), i, len(lines)])
    return [tuple(s) for s in found]


def share_path(lines, start, end):
    for line in lines[start + 1:end]:
        if key_of(line) == "path":
            return line.split("=", 1)[1].strip()
    return None


def drop_marked(lines, param):
    """Remove marker+setting pairs for this parameter (from an earlier run)."""
    out, skip = [], False
    for i, line in enumerate(lines):
        if skip:
            skip = False
            continue
        if line.strip() == MARK and i + 1 < len(lines) and key_of(lines[i + 1]) == norm(param):
            skip = True
            continue
        out.append(line)
    return out


def set_in(lines, names, param, value):
    lines = drop_marked(lines, param)
    for name, start, end in reversed(sections(lines)):
        if norm(name) not in names:
            continue
        body = [i for i in range(start + 1, end) if key_of(lines[i]) == norm(param)]
        if body:
            raise SystemExit(f"[{name}] already sets '{param}' (not added by this kit) - left unchanged, check by hand")
        lines[start + 1:start + 1] = [f"\t{MARK}", f"\t{param} = {value}"]
    return lines


def main(argv):
    path = "/etc/samba/smb.conf"
    if "--file" in argv:
        i = argv.index("--file")
        path = argv[i + 1]
        del argv[i:i + 2]
    if len(argv) < 2:
        raise SystemExit(__doc__)
    cmd = argv[1]
    lines = open(path).read().splitlines()
    shares = lambda prefix: [n for n, s, e in sections(lines)
                             if (share_path(lines, s, e) or "").startswith(prefix)]
    if cmd == "list-shares":
        print("\n".join(shares(argv[2])))
        return
    if cmd == "set-global":
        lines = set_in(lines, {"global"}, argv[2], argv[3])
    elif cmd == "set-shares":
        names = shares(argv[4])
        if not names:
            raise SystemExit(f"no shares found under {argv[4]}")
        lines = set_in(lines, {norm(n) for n in names}, argv[2], argv[3])
        print("shares changed:", ", ".join(names))
    elif cmd == "undo":
        before = len(lines)
        lines = drop_marked(lines, argv[2])
        print(f"removed {(before - len(lines)) // 2} setting(s) for '{argv[2]}'")
    else:
        raise SystemExit(__doc__)
    open(path, "w").write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main(sys.argv)
