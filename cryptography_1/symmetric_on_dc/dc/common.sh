# Shared helpers for the HVMC symmetric-encryption redo, DOMAIN CONTROLLER side (hvmc-dc01).
# Loaded with: source ./common.sh. Every command and its output is saved under ~/symdc_evidence for the report.
# No passwords are ever written to the evidence: password prompts are typed directly, never logged.

KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYM="$KIT/../symmetric_crypto"                 # the from-scratch AES code from the Symmetric Cryptography rubric
EVID="$HOME/symdc_evidence"
CLIENT_IP="192.168.56.11"
DC_NAME="hvmc-dc01.hvmc.lan"
LAB_IF="enp0s8"
CONF="/etc/samba/smb.conf"
EDIT="$KIT/tools/smbconf_edit.py"
mkdir -p "$EVID/logs" "$EVID/configs" "$EVID/pcaps" "$EVID/analysis"

GREEN=$'\033[32m'; RED=$'\033[31m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

run() {                       # run "title" command args...  -> show and save the command and its output
  local title="$1"; shift
  local log="$EVID/logs/${STEP:-misc}.txt"
  printf '\n%s$ %s%s\n' "$BOLD" "$*" "$RESET"
  printf '\n### %s\n$ %s\n' "$title" "$*" >> "$log"
  "$@" 2>&1 | tee -a "$log"
  return "${PIPESTATUS[0]}"
}
ok()   { printf '%s✅ %s%s\n' "$GREEN" "$*" "$RESET"; echo "PASS: $*" >> "$EVID/logs/${STEP:-misc}.txt"; }
fail() { printf '%s❌ %s%s\n' "$RED" "$*" "$RESET"; echo "FAIL: $*" >> "$EVID/logs/${STEP:-misc}.txt"; }
say()  { printf '\n%s== %s ==%s\n' "$BOLD" "$*" "$RESET"; echo "== $* ==" >> "$EVID/logs/${STEP:-misc}.txt"; }
shot() { printf '\n📸  SCREENSHOT NOW: %s\n' "$*"; }
need_sudo() {
  echo "This step needs administrator rights on the VM. Type your VM password if asked."
  sudo -v || { fail "sudo not available"; exit 1; }
}

backup_conf() {               # backup_conf <label>  -> keeps a dated copy of smb.conf before any change
  local b="$CONF.before-symdc-$1-$(date +%Y%m%d-%H%M%S)"
  sudo cp -p "$CONF" "$b" && echo "$b"
}
conf_ok() { sudo testparm -s >/dev/null 2>"$EVID/logs/testparm-${STEP:-misc}.txt"; }
