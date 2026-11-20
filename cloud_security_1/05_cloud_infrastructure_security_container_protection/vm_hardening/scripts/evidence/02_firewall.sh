#!/bin/bash
# Evidence 2 - host firewall
echo "### ufw status verbose"; ufw status verbose
echo; echo "### ufw status numbered"; ufw status numbered
echo; echo "### listening sockets"; ss -tlnp | awk '{print $1,$4,$6}' | column -t
