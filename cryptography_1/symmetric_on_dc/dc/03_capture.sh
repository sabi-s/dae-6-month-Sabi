#!/usr/bin/env bash
# DC STEP 3 - record the lab traffic from the client while the client test runs.
#   ./03_capture.sh krb_before | krb_after    Kerberos sign-in traffic (port 88)
#   ./03_capture.sh smb_before | smb_after    file-share traffic (port 445); also records 'smbstatus' (encryption column)
# Start it here first; it waits. Then run the matching client script. Press Enter here when the client says Done.
STEP=03_capture
source "$(dirname "$0")/common.sh"
NAME="${1:-}"
case "$NAME" in
  krb_before|krb_after) FILTER="host $CLIENT_IP and port 88"; CLIENT_CMD="./c1_kerberos.sh ${NAME#krb_}" ;;
  smb_before|smb_after) FILTER="host $CLIENT_IP and tcp port 445"; CLIENT_CMD="./c2_smb.sh ${NAME#smb_}" ;;
  *) echo "usage: $0 krb_before|krb_after|smb_before|smb_after"; exit 1 ;;
esac
need_sudo
OUT="$EVID/pcaps/$NAME.pcap"
TMP="/tmp/hvmc_symdc_$NAME.pcap"          # tcpdump drops root rights and cannot write into your home folder
STATUS="$EVID/analysis/smbstatus_$NAME.txt"
sudo rm -f "$TMP"; rm -f "$OUT" "$STATUS"

say "Capturing '$FILTER' on $LAB_IF"
sudo tcpdump -i "$LAB_IF" -s 0 -U -w "$TMP" "$FILTER" 2> "$EVID/logs/tcpdump-$NAME.txt" &
sleep 2
echo
echo "${BOLD}Now, in the CLIENT window, run:   $CLIENT_CMD${RESET}"
echo "When it says Done, come back here and press Enter."
while true; do
  if read -r -t 2 _; then break; fi
  if [[ "$NAME" == smb_* ]]; then                      # while the client is connected, save who is connected and how
    S="$(sudo smbstatus 2>/dev/null)"
    grep -q "$CLIENT_IP" <<< "$S" && printf '%s\n' "$S" > "$STATUS"
  fi
done
sleep 1
sudo pkill -INT -f "tcpdump -i $LAB_IF -s 0 -U -w $TMP"; sleep 1
sudo mv "$TMP" "$OUT" && sudo chown "$(id -un)" "$OUT"
N=$(tshark -r "$OUT" 2>/dev/null | wc -l)
run "capture summary" bash -c "cat '$EVID/logs/tcpdump-$NAME.txt'; ls -l '$OUT'; tshark -r '$OUT' 2>/dev/null | head -20"
if [[ "$NAME" == smb_* ]]; then
  if [[ -s "$STATUS" ]]; then run "smbstatus while the client was connected" cat "$STATUS"
  else echo "(smbstatus did not catch the connection - that is fine, the capture still counts.)"; fi
fi
if [[ "$N" -gt 0 ]]; then ok "Captured $N packets into pcaps/$NAME.pcap"
else fail "The capture is empty - run it again and start the client command while this window is waiting"; fi
