# Network Security 1 — Live Evidence (AccessGuard Health home lab)

Real evidence captured on the AccessGuard Health home lab — Oracle VirtualBox, host-only
network `192.168.56.0/24`:

- **hvmc-dc01** — `192.168.56.10`, Ubuntu 24.04 + Samba 4.19 AD DC (the monitored host / scan target)
- **hvmc-client01** — `192.168.56.11`, domain-joined client (the capture/scan host and the source of the test incident)

Every tool was run only against the author's own two virtual machines. The two report PDFs
(Criterion 6 and Criterion 7) live alongside this folder and reference the files below.

## Reports

| Report | Criterion |
|---|---|
| `../06_Network_Security_Tools_Documents.pdf` | 6 — Utilize Network Security Tools |
| `../07_Monitor_And_Respond_To_Network_Security_Events.pdf` | 7 — Monitor and Respond to Network Security Events |

## Evidence files (this folder)

### Criterion 1 — Network Topologies
| File | What it shows |
|---|---|
| `01_topology.txt` | Interfaces, routing, client → DC ping, and the DC as the DNS centre of `hvmc.lan` |
| `01_topology_dc01.png` | Topology output captured on hvmc-dc01 |
| `01_topology_client01.png` | Topology output captured on hvmc-client01 |

### Criterion 3 — Security Fundamentals (firewall + IPS)
| File | What it shows |
|---|---|
| `03_ufw_status.txt` / `03_ufw_status.png` | UFW: default deny incoming; SSH and AD ports allowed from the lab subnet only |
| `03_fail2ban_status.png` | fail2ban sshd jail baseline (0 failed, 0 banned) |
| `03_fail2ban_log.txt` / `03_fail2ban_log.png` | fail2ban log: the "Found" entries and the "Ban" action |

### Criterion 6 — Utilize Network Security Tools
| File | What it shows |
|---|---|
| `06_kerberos_logon.pcap` | Raw packet capture of a real Kerberos logon (`sarah.chen@HVMC.LAN`) — opens in Wireshark |
| `06_kerberos_capture_analysis.txt` | tshark analysis of the capture (protocol hierarchy, AS-REQ/AS-REP, cleartext check) |
| `06_kerberos_logon_terminal.png` | Capture session, successful `kinit`, and the ticket shown by `klist` |
| `06_kerberos_analysis.png` | Screenshot of the tshark analysis report |
| `06_nmap_services.txt` / `06_nmap_services.png` | Nmap service/version + OS scan of the DC (6 open ports behind UFW) |
| `06_nmap_vuln.txt` / `06_nmap_vuln.png` | Nmap vulnerability-script scan (0 flagged VULNERABLE; SMB signing required) |

### Criterion 7 — Monitor and Respond to Network Security Events
| File | What it shows |
|---|---|
| `07_incident_run.png` | Client-side bounded test: 6 failed SSH logins as `itbadlogin` against the DC |
| `07_ssh_auth_failures.txt` / `07_ssh_auth_failures.png` | sshd journal failures and the evidence-collection output |
| `07_fail2ban_ban.png` | `fail2ban-client status sshd` after the incident — 192.168.56.11 banned |
| `07_no_accepted_logins.png` | Containment check: no successful login from the attacker/test client |
| `07_incident_report.md` / `07_incident_report.png` | Incident report: Detect → Contain → Eradicate → Recover → Lessons learned |

## Other criteria (for context)
- **Criterion 4 (Access Control)** — evidenced by the Week 5 department-share test
  (`semester_3/.../Week5_Department_Shared_Folders_Healthcare_IAM.pdf`).
- **Criterion 2 (Protocols/Architecture)** — design deliverable (documents 02–04).
- **Criterion 5 (Wireless)** — stays design-only; the lab has no wireless hardware.

## Honest note
The original documents 01–07 describe the earlier design; this evidence records what was
actually run and captured on the home lab. All activity was a controlled self-test against
the author's own equipment.
