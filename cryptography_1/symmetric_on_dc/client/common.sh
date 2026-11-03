# Shared helpers for the HVMC symmetric-encryption redo, CLIENT side (hvmc-client01).
# Loaded with: source ./common.sh. Output is saved under ~/symdc_evidence for the report.
# Passwords are typed at the kinit prompt and are never written to a file or log.

KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVID="$HOME/symdc_evidence"
DC_NAME="hvmc-dc01.hvmc.lan"
REALM="HVMC.LAN"
SHARE="//$DC_NAME/EHR"
MARKER="HVMC-DEMO-NOTE"
mkdir -p "$EVID/logs"

GREEN=$'\033[32m'; RED=$'\033[31m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

run() {
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

# sign_in <user> [ccache]  -> Kerberos sign-in. kinit asks for the password itself (typed, not logged).
sign_in() {
  local user="$1" cc="${2:-}"
  echo
  echo "${BOLD}Sign in as $user (type the lab practice password for $user):${RESET}"
  if [[ -n "$cc" ]]; then KRB5CCNAME="$cc" kinit "$user@$REALM"; else kinit "$user@$REALM"; fi
}
