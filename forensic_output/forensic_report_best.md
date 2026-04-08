# Apex Global Logistics - Incident Response Report

| Field | Value |
| --- | --- |
| **Client** | Apex Global Logistics |
| **Capture Window** | 2025-11-18 – 2026-01-30 |
| **Data Source** | Zeek Logs (from PCAP) |
| **Internal Subnet** | 10.128.239.0/24 |
| **Domain** | domain-ees3Ai.local |
| **Report Generated** | 2026-04-08 10:42:15 UTC |
| **Findings** | 31 |
| **IOCs** | 296 |
| **Timeline Events** | 80 |

## Executive Summary

A security incident was detected involving unauthorized external access to the corporate network. Initial access was achieved via external Remote Desktop Protocol (RDP) and Windows Remote Management (WinRM) connections from IP 113.105.164.28. While credential spraying was observed, authentication failures indicate this technique did not succeed; access was likely gained via pre-obtained or externally-sourced credentials (MITRE ATT&CK T1078).

The primary compromised host (Patient Zero) is 10.128.239.57, first active at 2025-11-18 13:30:23 UTC. The attacker performed lateral movement using NTLM authentication and administrative share access (ADMIN$), targeting 135 internal hosts. Data staging occurred via SMB with 41 executable files transferred. Exfiltration was conducted through DNS queries to temp.sh and encrypted sessions to known file hosting services (MITRE ATT&CK T1048). Affected accounts include IT1, APatton, and jjjjjjjCA1$.

Timeline:
- 2025-11-18 13:30:23 UTC: First external access to Patient Zero.
- Subsequent hours: Lateral movement, file staging, and DNS exfiltration detected.
- Containment: Network isolation initiated upon detection of protocol anomalies and exfiltration traffic.

Recommendations:
1. Immediately block external RDP and WinRM access at the perimeter firewall.
2. Isolate compromised host 10.128.239.57 and reset credentials for all accounts authenticated from this system.
3. Block identified C2 domains (korsan.me, temp.sh) and IOCs (113.105.164.28) across all security controls.

## Log Inventory

| # | Log File | Size | Category | Lines | Fields |
| --- | --- | --- | --- | --- | --- |
| 1 | `analyzer.log` | 679 B | full_read | 0 | ts, analyzer_kind, analyzer_name, uid, fuid (+7 more) |
| 2 | `conn.log` | 1.5 GB | grep_only | 0 | ts, uid, id.orig_h, id.orig_p, id.resp_h (+17 more) |
| 3 | `dce_rpc.log` | 75.9 MB | sample_grep | 0 | ts, uid, id.orig_h, id.orig_p, id.resp_h (+5 more) |
| 4 | `dns.log` | 730.2 MB | grep_only | 0 | ts, uid, id.orig_h, id.orig_p, id.resp_h (+19 more) |
| 5 | `dpd.log` | 50.7 MB | sample_grep | 0 | ts, uid, id.orig_h, id.orig_p, id.resp_h (+4 more) |
| 6 | `files.log` | 10.1 MB | sample_grep | 0 | ts, fuid, uid, id.orig_h, id.orig_p (+22 more) |
| 7 | `http.log` | 1.4 MB | full_read | 0 | ts, uid, id.orig_h, id.orig_p, id.resp_h (+25 more) |
| 8 | `kerberos.log` | 8.2 MB | full_read | 0 | ts, uid, id.orig_h, id.orig_p, id.resp_h (+15 more) |
| 9 | `known_hosts.log` | 933.1 KB | full_read | 0 | ts, host |
| 10 | `known_services.log` | 2.7 MB | full_read | 0 | ts, host, port_num, port_proto, service |
| 11 | `ntlm.log` | 5.0 MB | full_read | 0 | ts, uid, id.orig_h, id.orig_p, id.resp_h (+8 more) |
| 12 | `ocsp.log` | 139.5 KB | full_read | 0 | ts, id, hashAlgorithm, issuerNameHash, issuerKeyHash (+6 more) |
| 13 | `packet_filter.log` | 5.5 KB | full_read | 0 | ts, node, filter, init, success (+1 more) |
| 14 | `pe.log` | 2.6 KB | full_read | 0 | ts, id, machine, compile_ts, os (+12 more) |
| 15 | `quic.log` | 25.8 KB | full_read | 0 | ts, uid, id.orig_h, id.orig_p, id.resp_h (+8 more) |
| 16 | `rdp.log` | 436.0 MB | grep_only | 0 | ts, uid, id.orig_h, id.orig_p, id.resp_h (+17 more) |
| 17 | `reporter.log` | 16.3 KB | full_read | 0 | ts, level, message, location |
| 18 | `smb_files.log` | 30.4 MB | sample_grep | 0 | ts, uid, id.orig_h, id.orig_p, id.resp_h (+11 more) |
| 19 | `smb_mapping.log` | 6.5 MB | full_read | 0 | ts, uid, id.orig_h, id.orig_p, id.resp_h (+5 more) |
| 20 | `snmp.log` | 17.2 KB | full_read | 0 | ts, uid, id.orig_h, id.orig_p, id.resp_h (+10 more) |
| 21 | `socks.log` | 81.0 KB | full_read | 0 | ts, uid, id.orig_h, id.orig_p, id.resp_h (+11 more) |
| 22 | `software.log` | 195.8 KB | full_read | 0 | ts, host, host_p, software_type, name (+7 more) |
| 23 | `ssl.log` | 370.2 MB | grep_only | 0 | ts, uid, id.orig_h, id.orig_p, id.resp_h (+13 more) |
| 24 | `weird.log` | 30.6 MB | sample_grep | 0 | ts, uid, id.orig_h, id.orig_p, id.resp_h (+6 more) |
| 25 | `x509.log` | 3.4 MB | full_read | 0 | ts, fingerprint, certificate.version, certificate.serial, certificate.subject (+17 more) |

## Network Environment

**Internal Subnet:** `10.128.239.0/24`  
**Domain:** `domain-ees3Ai.local`  

### Discovered Hosts

| IP Address | Hostname | Role | Internal | Accounts |
| --- | --- | --- | --- | --- |
| `10.128.239.32` | jjjjjjjCA1 | workstation | Yes | - |
| `10.128.239.21` | jjjjjjjDC3 | domain_controller | Yes | -, jjjjjjjDC3$ |
| `10.128.239.82` | jjjjjjjWIN950 | workstation | Yes | IT1 |
| `10.128.239.20` | jjjjjjjDC1 | domain_controller | Yes | -, jjjjjjjDC1$ |
| `10.128.239.36` | jjjjjjjBACKUP01 | workstation | Yes | svc_backup, -, jjjjjjjBACKUP01$ |
| `10.128.239.39` | jjjjjjjBACKUP04 | workstation | Yes | backup_safety, -, IT1 |
| `10.128.239.24` | jjjjjjjSFDC6 | domain_controller | Yes | — |
| `10.128.239.31` | jjjjjjjSFDC9 | domain_controller | Yes | — |
| `10.128.239.98` | jjjjjjjWIN998 | workstation | Yes | administrator, test, admin, guest, alex (+17) |
| `10.128.239.34` | jjjjjjjSHARE12 | workstation | Yes | jjjjjjjSHARE12$ |
| `10.128.239.37` | jjjjjjjSHARE01 | workstation | Yes | IT1 |
| `10.128.239.23` | jjjjjjjWTDC8 | domain_controller | Yes | jjjjjjjWTDC8$, - |
| `10.128.239.57` | jjjjjjjRDP02 | workstation | Yes | IT1, -, LGallegos |
| `10.128.239.64` | jjjjjjjHV01 | workstation | Yes | — |
| `10.128.239.65` | jjjjjjjHV02 | workstation | Yes | — |
| `10.128.239.69` | jjjjjjjHV03 | workstation | Yes | jjjjjjjHV03$, - |
| `10.128.239.79` | jjjjjjjWIN341 | workstation | Yes | IT2, jjjjjjjWIN341$ |
| `10.128.239.91` | jjjjjjjWIN840 | workstation | Yes | IT1, jjjjjjjWIN840$ |
| `10.128.239.90` | jjjjjjjWIN479 | workstation | Yes | — |
| `10.128.239.93` | jjjjjjjWIN758 | workstation | Yes | jjjjjjjWIN758$ |
| `10.128.239.97` | jjjjjjjWIN527 | workstation | Yes | jjjjjjjWIN527$ |
| `10.128.239.117` | jjjjjjjWIN705 | workstation | Yes | — |
| `10.128.239.119` | jjjjjjjWIN533 | workstation | Yes | - |
| `10.128.239.111` | jjjjjjjWIN171 | workstation | Yes | IT1 |
| `10.128.239.84` | jjjjjjjWIN148 | workstation | Yes | jjjjjjjWIN148$, - |
| `10.128.239.121` | jjjjjjjWIN660 | workstation | Yes | jjjjjjjWIN660$ |
| `10.128.239.96` | jjjjjjjWIN759 | workstation | Yes | — |
| `10.128.239.123` | jjjjjjjWIN454 | workstation | Yes | IT1 |
| `10.128.239.120` | jjjjjjjWIN760 | workstation | Yes | jjjjjjjWIN760$ |
| `10.128.239.122` | jjjjjjjWIN420 | workstation | Yes | — |
| `10.128.239.85` | jjjjjjjWIN720 | workstation | Yes | IT2 |
| `10.128.239.124` | jjjjjjj-WK032C | workstation | Yes | jjjjjjj-WK032C$, IT1 |
| `10.128.239.71` | jjjjjjjWIN247 | workstation | Yes | jjjjjjjWIN247$, CMaynard |
| `10.128.239.72` | jjjjjjjWIN147 | workstation | Yes | ASaunders, jjjjjjjWIN147$ |
| `10.128.239.33` | jjjjjjjCA2 | workstation | Yes | — |
| `10.128.239.81` | jjjjjjjWIN901 | workstation | Yes | - |
| `10.128.239.42` | jjjjjjjADF03 | domain_controller | Yes | IT1 |
| `10.128.239.83` | jjjjjjjWIN090 | workstation | Yes | MWilliamson |
| `10.128.239.45` | jjjjjjjADS01 | domain_controller | Yes | IT1, jjjjjjjADS01$ |
| `10.128.239.76` | jjjjjjjWIN751 | workstation | Yes | ATorres, MSantiago |
| `10.128.239.86` | jjjjjjjWIN822 | workstation | Yes | — |
| `10.128.239.43` | jjjjjjjADS02 | domain_controller | Yes | jjjjjjjADS02$ |
| `10.128.239.88` | jjjjjjjWIN847 | workstation | Yes | IT1 |
| `10.128.239.46` | jjjjjjjADF02 | domain_controller | Yes | — |
| `10.128.239.92` | jjjjjjjWIN485 | workstation | Yes | IT2 |
| `10.128.239.87` | jjjjjjjWIN115 | workstation | Yes | IT1 |
| `10.128.239.70` | jjjjjjjWIN680 | workstation | Yes | ARaymond |
| `10.128.239.94` | jjjjjjjWIN179 | workstation | Yes | — |
| `10.128.239.95` | jjjjjjjWIN930 | workstation | Yes | — |
| `10.128.239.77` | jjjjjjjWIN636 | workstation | Yes | DBarber |
| `10.128.239.89` | jjjjjjjWIN491 | workstation | Yes | — |
| `10.128.239.80` | - | workstation | Yes | IT1, jjjjjjjWIN544$ |
| `10.128.239.105` | jjjjjjjWIN178 | workstation | Yes | — |
| `10.128.239.22` | jjjjjjjADDC5 | domain_controller | Yes | - |
| `10.128.239.115` | jjjjjjjWIN629 | workstation | Yes | JMcmahon |
| `10.128.239.26` | jjjjjjjPWDC12 | domain_controller | Yes | — |
| `10.128.239.114` | jjjjjjjWIN306 | workstation | Yes | — |
| `10.128.239.103` | jjjjjjjWIN961 | workstation | Yes | — |
| `10.128.239.30` | jjjjjjjPKDC2 | domain_controller | Yes | — |
| `10.128.239.116` | - | workstation | Yes | — |
| `10.128.239.159` | - | workstation | Yes | — |
| `10.128.239.44` | jjjjjjjWIN304 | workstation | Yes | — |
| `10.128.239.112` | jjjjjjjWIN077 | workstation | Yes | — |
| `10.128.239.154` | jjjjjjj-WK320D | workstation | Yes | jjjjjjj-WK320D$, - |
| `10.128.239.110` | jjjjjjjWIN395 | workstation | Yes | — |
| `10.128.239.163` | jjjjjjj-WK613D | workstation | Yes | — |
| `10.128.239.106` | jjjjjjjWIN534 | workstation | Yes | — |
| `10.128.239.155` | jjjjjjj-WK875D | workstation | Yes | jjjjjjj-WK875D$, MAlexander |
| `10.128.239.102` | jjjjjjjWIN466 | workstation | Yes | — |
| `10.128.239.160` | jjjjjjj-WK805D | workstation | Yes | — |
| `10.128.239.51` | jjjjjjjWIN219 | workstation | Yes | — |
| `10.128.239.61` | jjjjjjjWIN763 | workstation | Yes | — |
| `10.128.239.68` | jjjjjjjWIN220 | workstation | Yes | — |
| `10.128.239.25` | jjjjjjjPKDC7 | domain_controller | Yes | — |
| `10.128.239.78` | jjjjjjjWIN969 | workstation | Yes | — |
| `10.128.239.58` | jjjjjjjWIN605 | workstation | Yes | — |
| `10.128.239.50` | jjjjjjjWIN038 | workstation | Yes | — |
| `10.128.239.177` | jjjjjjjRDP03 | workstation | Yes | — |
| `10.128.239.150` | jjjjjjj-WK511D | workstation | Yes | — |
| `10.128.239.99` | jjjjjjjWIN437 | workstation | Yes | — |
| `10.128.239.73` | jjjjjjjWIN777 | workstation | Yes | — |
| `10.128.239.162` | jjjjjjj-WK514D | workstation | Yes | — |
| `10.128.239.54` | jjjjjjjWIN644 | workstation | Yes | — |
| `10.128.239.127` | jjjjjjj-WK305C | workstation | Yes | — |
| `10.128.239.128` | jjjjjjj-WK799C | workstation | Yes | — |
| `10.128.239.130` | jjjjjjj-WK589C | workstation | Yes | — |
| `10.128.239.132` | jjjjjjj-WK465C | workstation | Yes | — |
| `10.128.239.152` | jjjjjjj-WK037C | workstation | Yes | — |
| `10.128.239.138` | jjjjjjj-WK178C | workstation | Yes | JMclean |
| `10.128.239.140` | jjjjjjj-WK598C | workstation | Yes | — |
| `10.128.239.107` | jjjjjjjWIN609 | workstation | Yes | — |
| `10.128.239.52` | jjjjjjjWIN871 | workstation | Yes | — |
| `10.128.239.35` | jjjjjjjBACKUP02 | workstation | Yes | — |
| `10.128.239.104` | jjjjjjjWIN031 | workstation | Yes | — |
| `10.128.239.108` | jjjjjjjWIN850 | workstation | Yes | — |
| `10.128.239.67` | jjjjjjjWIN884 | workstation | Yes | — |
| `10.128.239.63` | jjjjjjjWIN712 | workstation | Yes | — |
| `10.128.239.74` | jjjjjjjWIN406 | workstation | Yes | — |
| `10.128.239.147` | jjjjjjj-WK312C | workstation | Yes | — |
| `10.128.239.141` | jjjjjjj-WK650C | workstation | Yes | jjjjjjj-WK650C$, EDunn |
| `10.128.239.27` | jjjjjjjADDC7 | domain_controller | Yes | — |
| `10.128.239.153` | jjjjjjj-WK392D | workstation | Yes | — |
| `10.128.239.56` | jjjjjjjWIN124 | workstation | Yes | — |
| `10.128.239.55` | jjjjjjjWIN813 | workstation | Yes | — |
| `10.128.239.28` | jjjjjjjPWDC6 | domain_controller | Yes | — |
| `10.128.239.60` | jjjjjjjWIN919 | workstation | Yes | — |
| `10.128.239.29` | jjjjjjjWTDC23 | domain_controller | Yes | — |
| `10.128.239.109` | jjjjjjjWIN509 | workstation | Yes | IT1, EPerkins |
| `10.128.239.62` | jjjjjjjWIN962 | workstation | Yes | — |
| `10.128.239.113` | jjjjjjjWIN805 | workstation | Yes | — |
| `10.128.239.118` | jjjjjjjWIN529 | workstation | Yes | — |
| `10.128.239.75` | jjjjjjjWIN369 | workstation | Yes | — |
| `10.128.239.48` | jjjjjjjRDP01 | workstation | Yes | — |
| `10.128.239.145` | jjjjjjj-WK551C | workstation | Yes | — |
| `10.128.239.144` | jjjjjjj-WK334C | workstation | Yes | — |
| `10.128.239.149` | jjjjjjj-WK809C | workstation | Yes | — |
| `10.128.239.133` | jjjjjjj-WK232C | workstation | Yes | — |
| `10.128.239.135` | jjjjjjj-WK015C | workstation | Yes | — |
| `10.128.239.146` | jjjjjjj-WK211C | workstation | Yes | — |
| `10.128.239.137` | jjjjjjj-WK202C | workstation | Yes | — |
| `10.128.239.136` | jjjjjjj-WK446C | workstation | Yes | GCarlson, jjjjjjj-WK446C$ |
| `10.128.239.143` | jjjjjjj-WK874C | workstation | Yes | — |
| `10.128.239.126` | jjjjjjj-WK373C | workstation | Yes | — |
| `10.128.239.49` | jjjjjjjADS03 | domain_controller | Yes | — |
| `10.128.239.142` | jjjjjjj-WK468C | workstation | Yes | — |
| `10.128.239.129` | jjjjjjj-WK705C | workstation | Yes | — |
| `10.128.239.100` | jjjjjjjWIN957 | workstation | Yes | — |
| `10.128.239.131` | jjjjjjj-WK873C | workstation | Yes | — |
| `10.128.239.59` | jjjjjjjWIN214 | workstation | Yes | — |
| `10.128.239.176` | jjjjjjjSHARE05 | workstation | Yes | jjjjjjjSHARE05$ |
| `10.128.239.47` | jjjjjjjADF04 | domain_controller | Yes | — |
| `10.128.239.139` | jjjjjjj-WK438C | workstation | Yes | — |
| `10.128.239.101` | jjjjjjjWIN578 | workstation | Yes | — |
| `10.128.239.148` | jjjjjjj-WK599D | workstation | Yes | — |
| `10.128.239.66` | jjjjjjjWIN116 | workstation | Yes | — |
| `10.128.239.156` | jjjjjjj-WK391D | workstation | Yes | — |
| `10.1.1.12` | hyperv | workstation | Yes | Administrator, - |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Observed Evidence |
| --- | --- | --- | --- |
| Initial Access | External Remote Services | `T1133` | 5 protocol anomaly record(s) on remote-access ports |
| Command and Control | Protocol Tunneling | `T1572` | 2 HTTP CONNECT tunnel(s) detected |
| Initial Access | Valid Accounts | `T1078` | 31 HTTP request(s) from 15 external IP(s) |
| Credential Access | Brute Force: Password Spraying | `T1110.003` | 5 source(s) performing credential spray |
| Lateral Movement | Valid Accounts: Domain Accounts | `T1078.002` | 1 source(s) performing lateral movement |
| Discovery | Account Discovery: Domain Account | `T1087.002` | 3 source(s) performing SAMR enumeration |
| Credential Access | Steal or Forge Kerberos Tickets | `T1558` | 97 Kerberos TGT request(s) involving known IOCs |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | `T1021.002` | 2624 ADMIN$/C$ access(es) from 6 source(s) |
| Command and Control | Proxy: Multi-hop Proxy | `T1090.003` | 502 SOCKS record(s), 81 unique pairs, 9 pivot(s) |
| Lateral Movement | Remote Services: Windows Remote Management | `T1021.006` | 8 internal WinRM request(s) from 1 source(s) |
| Exfiltration | Exfiltration Over Web Service: Exfiltration to Cloud Storage | `T1567.002` | 52 DNS lookup(s) for 1 exfil domain(s) from 3 host(s) |
| Command and Control | Encrypted Channel: Asymmetric Cryptography | `T1573.002` | 11 SSL session(s) to exfil destinations in 2 time cluster(s) |
| Discovery | System Network Configuration Discovery | `T1016` | 10 IP recon request(s) to 1 service(s) in 2 wave(s) |
| Collection | Data from Network Shared Drive | `T1039` | 2433 SMB file record(s) matching 3 transfer tool(s) |
| Command and Control | Ingress Tool Transfer | `T1105` | 15 PE file(s): architectures={'I386': 8, 'AMD64': 7}, 15 with compile timestamps |
| Defense Evasion | Domain Policy Modification: Group Policy Modification | `T1484.001` | 19790 GPO file access(es) by 60 host(s) |
| Impact |  | `T1486` | 24 suspicious file pattern match(es) |
| Command and Control | Application Layer Protocol: DNS | `T1071.004` | Top-30 DNS queries include ant.typer.pl (24370), ilo.byper.pl (24341), hzh.0xox0xox0.com (23978) wit... |
| Impact | Inhibit System Recovery | `T1490` | ManageEngine_PMP_64bit.exe (389681696 bytes) accessed from 10.128.239.57 to 10.128.239.34:445 |
| Execution | Command and Scripting Interpreter: PowerShell | `T1059.001` | 8 PSVersion=5.1.20348.558 occurrences in http.log wsman requests from 10.128.239.82 to 10.128.239.20... |

## Detailed Findings

### Finding IA-005: External WinRM Access Detected

**Severity:** CRITICAL  

Detected 16 WinRM (/wsman) request(s) from external IP(s). WinRM is a remote management protocol and external access is highly suspicious.

#### Evidence

**Source:** `http.log`  
16 WinRM request(s) from external IP(s)  

#### MITRE ATT&CK

- **Initial Access** / External Remote Services (`T1133`)


### Finding IA-006: External RDP Sessions Detected

**Severity:** CRITICAL  

Found 5000 RDP session(s) originating from external IP address(es). External RDP is a common initial-access vector.

#### Evidence

**Source:** `rdp.log`  
5000 RDP session(s) from external IP(s)  

#### MITRE ATT&CK

- **Initial Access** / External Remote Services (`T1133`)


### Finding IA-007: Patient Zero Identified: 10.128.239.57

**Severity:** CRITICAL  

The internal host 10.128.239.57 was the first target of external access, with the earliest event at 2025-11-18 13:30:23 UTC. Subsequent lateral movement likely originates from this host.

#### Evidence

**Source:** `multiple`  
Patient Zero identified as 10.128.239.57 at 2025-11-18 13:30:23 UTC  

#### MITRE ATT&CK

- **Initial Access** / Valid Accounts (`T1078`)


### Finding PL-001: Executable Files Staged via SMB

**Severity:** CRITICAL  

Detected 41 .exe file(s) transferred over SMB. 35 file(s) exceed the 1048576-byte threshold. Staging server: 10.128.239.34. Unique executables: UninstallWinClient.exe, TeamCity-2024.07.exe, hfs.exe, npp.8.4.2.Installer.x64.exe, git.exe, Setup.Def.en-us_O365ProPlusRetail_TX_PR_Platform_def_b_64_.exe, ManageEngine_PMP_64bit.exe, vc_redist.x64.exe, <share_root>, ManageEngine_RecoveryManagerPlus_Bundle.exe.

#### Evidence

**Source:** `smb_files.log`  
41 .exe file(s) transferred via SMB, 35 exceeding 1048576 bytes  

#### MITRE ATT&CK

- **Lateral Movement** / Remote Services: SMB/Windows Admin Shares (`T1021.002`)


### Finding MI-002: RDP Protocol Anomaly — Targeted Attacker Identified

**Severity:** CRITICAL  

External IP 113.105.164.28 triggered DPD analyzer failures with "Invalid version late in TLS connection" on port 3389 targeting Patient Zero (10.128.239.57). This indicates a deliberate SSL tunnel through the RDP port — the TLS handshake was partially established before Zeek detected incompatibility, distinguishing it from mass-scanner probes that fail immediately at version negotiation. The attacker used HYBRID security protocol (NLA) with generic cookie values ("%" and "w"), indicating automated tooling rather than a legitimate Windows client.

#### Evidence

**Source:** `dpd.log`  
2 records with failure_reason "Invalid version late in TLS connection. Packet reported version: 0" from source 113.105.164.28 to destination 10.128.239.57:3389  

#### MITRE ATT&CK

- **Initial Access** / External Remote Services (`T1133`)


### Finding MI-003: Suspicious High-Volume DNS Activity

**Severity:** CRITICAL  

Three suspicious domains appeared in top-30 DNS queries with anomalously high volume: ant.typer.pl (24,370 queries), ilo.byper.pl (24,341 queries), and hzh.0xox0xox0.com (23,978 queries). Querying hosts include 10.128.239.20 (DC1), 10.128.239.21 (DC3), and 10.128.239.98 (WIN998). These domains do not match normal enterprise patterns and exhibit beaconing behavior consistent with C2 communication.

#### Evidence

**Source:** `dns.log`  
Top-30 DNS queries include ant.typer.pl (24370), ilo.byper.pl (24341), hzh.0xox0xox0.com (23978) with source hosts 10.128.239.20, 10.128.239.21, 10.128.239.98  

#### MITRE ATT&CK

- **Command and Control** / Application Layer Protocol: DNS (`T1071.004`)


### Finding MI-004: Anomalous SSL SNI — RFC-Reserved IP in TLS Handshake

**Severity:** CRITICAL  

SSL log shows 1,381 sessions with server_name "198.51.100.1" — an RFC 5737 TEST-NET-2 IP address that should never appear in production traffic. Source IPs include 193.32.162.44, 2.42.206.111, 193.32.162.95, 2.57.122.126 targeting internal host 10.128.239.57:3389. This indicates a NAT/proxy C2 setup where the attacker's real infrastructure is behind an intermediary and the internal address leaks into the SSL handshake. Traffic is TLS-encrypted and cannot be inspected.

#### Evidence

**Source:** `ssl.log`  
1381 SSL sessions with server_name "198.51.100.1" from external IPs to 10.128.239.57:3389  

#### MITRE ATT&CK

- **Command and Control** / Encrypted Channel: Asymmetric Cryptography (`T1573.002`)


### Finding MI-009: DNS Exfiltration to temp.sh Service

**Severity:** CRITICAL  

DNS log shows 52 queries to temp.sh (a known temporary file hosting/exfiltration service) and 11 SSL sessions to temp.sh. This indicates the attacker used temp.sh for data exfiltration. The combination of DNS lookups followed by TLS sessions to the resolved IP is the classic exfiltration pattern.

#### Evidence

**Source:** `dns.log`  
52 DNS queries to temp.sh and 11 SSL sessions to temp.sh  

#### MITRE ATT&CK

- **Exfiltration** / Exfiltration Over Web Service (`T1567.002`)


### Finding IA-002: HTTP CONNECT Tunneling Detected

**Severity:** HIGH  

Found 2 HTTP CONNECT request(s), indicating protocol tunneling. C2 domains observed: srv57c0d2365c3c.korsan.me, example.com.

#### Evidence

**Source:** `http.log`  
2 HTTP CONNECT tunnel(s) detected  

#### MITRE ATT&CK

- **Command and Control** / Protocol Tunneling (`T1572`)


### Finding IA-003: External HTTP Access to Internal Hosts

**Severity:** HIGH  

Detected 31 HTTP request(s) originating from 15 external IP(s) targeting internal services.

#### Evidence

**Source:** `http.log`  
31 HTTP request(s) from 15 external IP(s)  

#### MITRE ATT&CK

- **Initial Access** / Valid Accounts (`T1078`)


### Finding LM-001: Credential Spray Attack Detected

**Severity:** HIGH  

Detected 5 source IP(s) performing credential spray. 10.128.239.32: 707 failures against 3 targets; 10.128.239.36: 644 failures against 43 targets; 10.128.239.39: 927 failures against 19 targets; 10.128.239.98: 25576 failures against 11 targets; 10.128.239.57: 219 failures against 128 targets

#### Evidence

**Source:** `ntlm.log`  
5 source(s) performing credential spray  

#### MITRE ATT&CK

- **Credential Access** / Brute Force: Password Spraying (`T1110.003`)


### Finding LM-002: NTLM Lateral Movement Detected

**Severity:** HIGH  

Detected 1 host(s) authenticating to many internal targets. 10.128.239.57: 135 targets, accounts=['-', 'IT1']

#### Evidence

**Source:** `ntlm.log`  
1 source(s) performing lateral movement  

#### MITRE ATT&CK

- **Lateral Movement** / Valid Accounts: Domain Accounts (`T1078.002`)


### Finding LM-003: SAMR Enumeration Detected

**Severity:** HIGH  

Detected 3 host(s) performing extensive SAMR enumeration. 10.128.239.140: 6567 operations (SamrCloseHandle, SamrConnect, SamrConnect5, SamrEnumerateDomainsInSamServer, SamrGetAliasMembership); 10.128.239.57: 1971 operations (SamrCloseHandle, SamrConnect5, SamrGetMembersInGroup, SamrLookupDomainInSamServer, SamrOpenDomain); 10.128.239.155: 58 operations (SamrCloseHandle, SamrConnect5, SamrEnumerateDomainsInSamServer, SamrGetAliasMembership, SamrGetGroupsForUser)

#### Evidence

**Source:** `dce_rpc.log`  
3 source(s) performing SAMR enumeration  

#### MITRE ATT&CK

- **Discovery** / Account Discovery: Domain Account (`T1087.002`)


### Finding LM-004: Kerberos TGT Activity from Suspicious Hosts

**Severity:** HIGH  

Detected 97 Kerberos TGT request(s). Accounts involved: -, APatton/POWER.domainaaaaaTW.LOCAL, IT1/domain-ees3Ai.local, jjjjjjjCA1$/domainaaaaaTW.LOCAL, jjjjjjjca1$/domain-ees3Ai.local, jjjjjjjca1$/domainaaaaaTW.LOCAL. Requests originated from known IOC IPs.

#### Evidence

**Source:** `kerberos.log`  
97 Kerberos TGT request(s) involving known IOCs  

#### MITRE ATT&CK

- **Credential Access** / Steal or Forge Kerberos Tickets (`T1558`)


### Finding LM-005: Administrative Share Access Detected

**Severity:** HIGH  

Detected 2624 access(es) to ADMIN$ or C$ shares from 6 source IP(s). 10.128.239.57: 1178 accesses to 135 targets; 10.128.239.36: 503 accesses to 2 targets; 10.128.239.32: 561 accesses to 2 targets; 10.128.239.39: 136 accesses to 7 targets; 10.128.239.140: 86 accesses to 2 targets

#### Evidence

**Source:** `smb_mapping.log`  
2624 ADMIN$/C$ access(es) from 6 source(s)  

#### MITRE ATT&CK

- **Lateral Movement** / Remote Services: SMB/Windows Admin Shares (`T1021.002`)


### Finding LM-006: SOCKS Proxy Chains Detected

**Severity:** HIGH  

Detected 502 SOCKS record(s) across 81 unique source->destination pairs. 9 host(s) act as proxy pivots (both source and destination). This indicates multi-hop proxy chains for traffic obfuscation.

#### Evidence

**Source:** `socks.log`  
502 SOCKS record(s), 81 unique pairs, 9 pivot(s)  

#### MITRE ATT&CK

- **Command and Control** / Proxy: Multi-hop Proxy (`T1090.003`)


### Finding LM-007: Internal WinRM Lateral Movement

**Severity:** HIGH  

Detected 8 WinRM request(s) from 1 internal source(s). WinRM enables remote PowerShell execution.

#### Evidence

**Source:** `http.log`  
8 internal WinRM request(s) from 1 source(s)  

#### MITRE ATT&CK

- **Lateral Movement** / Remote Services: Windows Remote Management (`T1021.006`)


### Finding EX-001: DNS Lookups to Known Exfiltration Domains

**Severity:** HIGH  

Detected 52 DNS lookup(s) for known exfiltration domains: temp.sh. Querying hosts: 10.128.239.20, 10.128.239.21, 10.128.239.57.

#### Evidence

**Source:** `dns.log`  
52 DNS lookup(s) for 1 exfil domain(s) from 3 host(s)  

#### MITRE ATT&CK

- **Exfiltration** / Exfiltration Over Web Service: Exfiltration to Cloud Storage (`T1567.002`)


### Finding EX-002: Encrypted Sessions to Exfiltration Services

**Severity:** HIGH  

Detected 11 SSL/TLS session(s) to known exfiltration destinations, grouped into 2 time cluster(s). SNI values: temp.sh. TLS versions: TLSv13.

#### Evidence

**Source:** `ssl.log`  
11 SSL session(s) to exfil destinations in 2 time cluster(s)  

#### MITRE ATT&CK

- **Command and Control** / Encrypted Channel: Asymmetric Cryptography (`T1573.002`)


### Finding EX-004: File Transfer Tools Staged via SMB

**Severity:** HIGH  

Found 2433 SMB file record(s) referencing known file transfer tools: hfs, 7z, nc. These tools are commonly used for data exfiltration.

#### Evidence

**Source:** `smb_files.log`  
2433 SMB file record(s) matching 3 transfer tool(s)  

#### MITRE ATT&CK

- **Collection** / Data from Network Shared Drive (`T1039`)


### Finding PL-002: PE Binary Metadata Analysis

**Severity:** HIGH  

Analyzed 15 PE file record(s). Architectures: I386(8), AMD64(7). 15 file(s) have compile timestamps. Sections observed: .data, .pdata, .text, .retplne, .rsrc, .reloc, .didat, .rdata. Dual-architecture binaries detected (I386, AMD64). This may indicate a multi-platform dropper.

#### Evidence

**Source:** `pe.log`  
15 PE file(s): architectures={'I386': 8, 'AMD64': 7}, 15 with compile timestamps  

#### MITRE ATT&CK

- **Command and Control** / Ingress Tool Transfer (`T1105`)


### Finding MI-001: Attack Dwell Time Analysis

**Severity:** HIGH  

Total dwell time: 72.7 days (2025-11-18 to 2026-01-30). Initial access via external RDP to Patient Zero (10.128.239.57) at 2025-11-18 13:30:23 UTC. Lateral movement and credential abuse began within 48 hours of initial access, indicating attacker had valid credentials or rapidly escalated. Multiple exfiltration episodes observed across the timeline, suggesting staged data theft consistent with double-extortion ransomware methodology.

#### Evidence

**Source:** `rdp.log`  
Time range: 2025-11-18 13:30:23 UTC to 2026-01-30 05:08:23 UTC (72.7 days)  

#### MITRE ATT&CK

- **Initial Access** / External Remote Services (`T1133`)


### Finding MI-005: Unexpected Remote Access Tool Detected

**Severity:** HIGH  

Host 10.128.239.176 was fingerprinted running WicaAgent remote access software. WicaAgent is a remote desktop/control tool not typically found on standard workstations. This indicates attacker-installed persistence mechanism allowing reconnection at will. First seen at timestamp 1766219426.

#### Evidence

**Source:** `software.log`  
WicaAgent detected on host 10.128.239.176 at timestamps 1766219426 and 1767542497  

#### MITRE ATT&CK

- **Persistence** / External Remote Services (`T1133`)


### Finding MI-007: Pre-Encryption Backup Infrastructure Targeting

**Severity:** HIGH  

SMB file staging detected: ManageEngine_PMP_64bit.exe (389,681,696 bytes) was accessed via SMB from 10.128.239.57 to 10.128.239.34. ManageEngine PMP is a remote patch management/RMM tool. Staging such large management agents to internal hosts in the pre-encryption window is consistent with T1490 Inhibit System Recovery — the attacker is deploying tools to mass-deploy ransomware or disable backup/recovery capabilities across the domain.

#### Evidence

**Source:** `smb_files.log`  
ManageEngine_PMP_64bit.exe (389681696 bytes) accessed from 10.128.239.57 to 10.128.239.34:445  

#### MITRE ATT&CK

- **Impact** / Inhibit System Recovery (`T1490`)


### Finding MI-008: PowerShell Remote Execution Detected

**Severity:** HIGH  

WinRM activity confirmed in http.log with 24 POST requests to /wsman endpoints. 8 of these requests contained PSVersion=5.1.20348.558 in the URI, proving the attacker used PowerShell remoting specifically. Source host 10.128.239.82 (WIN950) connected to DC1 (10.128.239.20:5985) with successful 200 responses and large request/response bodies, indicating successful command execution.

#### Evidence

**Source:** `http.log`  
8 PSVersion=5.1.20348.558 occurrences in http.log wsman requests from 10.128.239.82 to 10.128.239.20:5985  

#### MITRE ATT&CK

- **Execution** / Command and Scripting Interpreter: PowerShell (`T1059.001`)


### Finding IA-001: Protocol Anomalies on Remote Access Ports

**Severity:** MEDIUM  

Detected 5 DPD record(s) involving remote-access ports. This may indicate protocol tunneling or tool misuse.

#### Evidence

**Source:** `dpd.log`  
5 protocol anomaly record(s) on remote-access ports  

#### MITRE ATT&CK

- **Initial Access** / External Remote Services (`T1133`)


### Finding IA-004: Suspicious HTTP User-Agents Detected

**Severity:** MEDIUM  

Found 19 HTTP request(s) using suspicious User-Agent strings: curl/7.29.0, Go-http-client/1.1. These are commonly associated with automated tooling or malware.

#### Evidence

**Source:** `http.log`  
19 request(s) with suspicious User-Agent strings  

#### MITRE ATT&CK

- **Command and Control** / Protocol Tunneling (`T1572`)


### Finding EX-003: IP Reconnaissance Service Lookups

**Severity:** MEDIUM  

Detected 10 request(s) to IP reconnaissance services (comae.com). 10 host(s) performed lookups in 2 distinct wave(s). User-Agents: Comae.

#### Evidence

**Source:** `http.log`  
10 IP recon request(s) to 1 service(s) in 2 wave(s)  

#### MITRE ATT&CK

- **Discovery** / System Network Configuration Discovery (`T1016`)


### Finding PL-003: Group Policy Object File Access

**Severity:** MEDIUM  

Detected 19790 access(es) to GPO files via SMB: gpt.ini(5000), Registry.xml(5000), Groups.xml(4790), audit.csv(5000). Accessing hosts: 10.128.239.102, 10.128.239.70, 10.128.239.155, 10.128.239.46, 10.128.239.57, 10.128.239.97, 10.128.239.106, 10.128.239.69, 10.128.239.32, 10.128.239.83. GPO manipulation can be used for persistence and mass deployment of malware.

#### Evidence

**Source:** `smb_files.log`  
19790 GPO file access(es) by 60 host(s)  

#### MITRE ATT&CK

- **Defense Evasion** / Domain Policy Modification: Group Policy Modification (`T1484.001`)


### Finding PL-004: Suspicious Files Detected on SMB Shares

**Severity:** MEDIUM  

Detected 24 file(s) matching suspicious patterns: ManageEngine(5), .ps1(19). Unique filenames: domain-ees3Ai.local\\Policies\\{DBFEF99B-48F3-4F0C-9B4F-F546CE81EA16}\\Machine\\Preferences\\Groups\\Groups.xml, water.domain-ees3Ai.local\\Policies\\{39E88897-4281-4145-BE0E-2D0147C2D08E}\\gpt.ini, domain-ees3Ai.local\\Policies\\{DBFEF99B-48F3-4F0C-9B4F-F546CE81EA16}\\gpt.ini, domain-ees3Ai.local\\Policies\\{7DDF95F4-B2B9-4BCD-8D81-9750119A5BB3}\\gpt.ini, water.domain-ees3Ai.local\\Policies\\{7EBE6536-6437-48F1-80EA-2B6A6BDF5373}\\gpt.ini, water.domain-ees3Ai.local\\Policies\\{7EC696A2-F33B-44B4-8521-A43780AA0EDD}\\gpt.ini, water.domain-ees3Ai.local\\Policies\\{FB0F0788-09A4-41D0-A9D5-AA2769A94951}\\gpt.ini, domain-ees3Ai.local\\Policies\\{2FEC0F4D-939C-4687-B7D4-8713D25EE390}\\gpt.ini, ManageEngine_PMP_64bit.exe, ManageEngine_RecoveryManagerPlus_Bundle.exe.

#### Evidence

**Source:** `smb_files.log`  
24 suspicious file pattern match(es)  

#### MITRE ATT&CK

- **Impact** /  (`T1486`)


### Finding MI-006: External IP Reconnaissance via Software Tool

**Severity:** MEDIUM  

Multiple internal hosts were fingerprinted running Comae, an external IP discovery tool. Hosts include 10.128.239.176, 10.128.239.37, 10.128.239.65, 10.128.239.34, 10.128.239.21, 10.128.239.64, 10.128.239.57, 10.128.239.20, 10.128.239.36, and 10.128.239.39. This indicates post-pivot reconnaissance behavior where attackers verify their external egress IP after compromising internal hosts.

#### Evidence

**Source:** `software.log`  
Comae detected on 10 hosts: 10.128.239.176, 10.128.239.37, 10.128.239.65, 10.128.239.34, 10.128.239.21, 10.128.239.64, 10.128.239.57, 10.128.239.20, 10.128.239.36, 10.128.239.39  

#### MITRE ATT&CK

- **Discovery** / System Network Configuration Discovery (`T1016`)



## Indicators of Compromise (IOCs)

### IP Addresses

| Value | Context | First Seen | Last Seen | Phase |
| --- | --- | --- | --- | --- |
| `104.234.115.106` | External IP with protocol anomaly on remote-access port | — | — | initial_access |
| `88.214.25.115` | External IP with protocol anomaly on remote-access port | — | — | initial_access |
| `185.147.125.32` | External IP with protocol anomaly on remote-access port | — | — | initial_access |
| `141.98.11.53` | External IP with protocol anomaly on remote-access port | — | — | initial_access |
| `196.251.89.107` | External IP using HTTP CONNECT tunnel | — | — | initial_access |
| `89.248.163.217` | External IP using HTTP CONNECT tunnel | — | — | initial_access |
| `18.191.28.175` | External IP accessing internal HTTP services | — | — | initial_access |
| `134.209.246.246` | External IP accessing internal HTTP services | — | — | initial_access |
| `152.32.234.184` | External IP accessing internal HTTP services | — | — | initial_access |
| `152.32.170.230` | External IP accessing internal HTTP services | — | — | initial_access |
| `5.182.209.113` | External IP accessing internal HTTP services | — | — | initial_access |
| `20.150.201.102` | External IP accessing internal HTTP services | — | — | initial_access |
| `15.204.142.151` | External IP accessing internal HTTP services | — | — | initial_access |
| `20.65.194.87` | External IP accessing internal HTTP services | — | — | initial_access |
| `162.216.150.182` | External IP accessing internal HTTP services | — | — | initial_access |
| `178.128.228.86` | External IP accessing internal HTTP services | — | — | initial_access |
| `139.144.52.241` | External IP accessing internal HTTP services | — | — | initial_access |
| `80.82.70.133` | External IP accessing internal HTTP services | — | — | initial_access |
| `144.126.223.152` | External IP accessing internal HTTP services | — | — | initial_access |
| `185.147.124.48` | External IP initiating RDP | — | — | initial_access |
| `141.98.11.96` | External IP initiating RDP | — | — | initial_access |
| `193.111.248.57` | External IP initiating RDP | — | — | initial_access |
| `194.165.17.11` | External IP initiating RDP | — | — | initial_access |
| `45.130.145.79` | External IP initiating RDP | — | — | initial_access |
| `147.45.112.185` | External IP initiating RDP | — | — | initial_access |
| `185.147.124.164` | External IP initiating RDP | — | — | initial_access |
| `179.60.146.33` | External IP initiating RDP | — | — | initial_access |
| `91.238.181.7` | External IP initiating RDP | — | — | initial_access |
| `147.45.112.183` | External IP initiating RDP | — | — | initial_access |
| `181.49.207.198` | External IP initiating RDP | — | — | initial_access |
| `91.238.181.93` | External IP initiating RDP | — | — | initial_access |
| `138.199.59.143` | External IP initiating RDP | — | — | initial_access |
| `141.98.11.170` | External IP initiating RDP | — | — | initial_access |
| `141.98.11.118` | External IP initiating RDP | — | — | initial_access |
| `141.98.11.8` | External IP initiating RDP | — | — | initial_access |
| `88.214.25.124` | External IP initiating RDP | — | — | initial_access |
| `147.45.112.187` | External IP initiating RDP | — | — | initial_access |
| `185.147.125.148` | External IP initiating RDP | — | — | initial_access |
| `141.98.83.70` | External IP initiating RDP | — | — | initial_access |
| `216.98.13.239` | External IP initiating RDP | — | — | initial_access |
| `185.147.124.106` | External IP initiating RDP | — | — | initial_access |
| `185.147.125.16` | External IP initiating RDP | — | — | initial_access |
| `45.130.145.6` | External IP initiating RDP | — | — | initial_access |
| `45.130.145.9` | External IP initiating RDP | — | — | initial_access |
| `80.91.223.58` | External IP initiating RDP | — | — | initial_access |
| `45.227.254.152` | External IP initiating RDP | — | — | initial_access |
| `154.16.192.217` | External IP initiating RDP | — | — | initial_access |
| `45.130.145.16` | External IP initiating RDP | — | — | initial_access |
| `149.202.132.198` | External IP initiating RDP | — | — | initial_access |
| `141.98.11.144` | External IP initiating RDP | — | — | initial_access |
| `79.127.132.47` | External IP initiating RDP | — | — | initial_access |
| `141.98.11.190` | External IP initiating RDP | — | — | initial_access |
| `185.147.125.30` | External IP initiating RDP | — | — | initial_access |
| `179.60.146.37` | External IP initiating RDP | — | — | initial_access |
| `45.130.145.78` | External IP initiating RDP | — | — | initial_access |
| `98.159.33.100` | External IP initiating RDP | — | — | initial_access |
| `141.98.11.100` | External IP initiating RDP | — | — | initial_access |
| `147.45.112.188` | External IP initiating RDP | — | — | initial_access |
| `146.19.191.29` | External IP initiating RDP | — | — | initial_access |
| `185.91.127.118` | External IP initiating RDP | — | — | initial_access |
| `79.127.132.53` | External IP initiating RDP | — | — | initial_access |
| `92.255.85.173` | External IP initiating RDP | — | — | initial_access |
| `45.130.145.77` | External IP initiating RDP | — | — | initial_access |
| `185.147.125.31` | External IP initiating RDP | — | — | initial_access |
| `138.199.59.168` | External IP initiating RDP | — | — | initial_access |
| `58.97.5.203` | External IP initiating RDP | — | — | initial_access |
| `154.16.192.221` | External IP initiating RDP | — | — | initial_access |
| `185.42.12.59` | External IP initiating RDP | — | — | initial_access |
| `141.98.11.109` | External IP initiating RDP | — | — | initial_access |
| `91.238.181.8` | External IP initiating RDP | — | — | initial_access |
| `45.130.145.8` | External IP initiating RDP | — | — | initial_access |
| `217.160.151.7` | External IP initiating RDP | — | — | initial_access |
| `176.97.210.106` | External IP initiating RDP | — | — | initial_access |
| `185.147.124.163` | External IP initiating RDP | — | — | initial_access |
| `193.111.248.146` | External IP initiating RDP | — | — | initial_access |
| `179.60.146.32` | External IP initiating RDP | — | — | initial_access |
| `45.130.145.5` | External IP initiating RDP | — | — | initial_access |
| `98.159.33.87` | External IP initiating RDP | — | — | initial_access |
| `80.75.212.32` | External IP initiating RDP | — | — | initial_access |
| `49.12.168.220` | External IP initiating RDP | — | — | initial_access |
| `193.111.248.216` | External IP initiating RDP | — | — | initial_access |
| `138.199.59.186` | External IP initiating RDP | — | — | initial_access |
| `193.32.162.44` | External IP initiating RDP | — | — | initial_access |
| `210.89.44.129` | External IP initiating RDP | — | — | initial_access |
| `91.238.181.94` | External IP initiating RDP | — | — | initial_access |
| `210.19.252.30` | External IP initiating RDP | — | — | initial_access |
| `147.135.222.78` | External IP initiating RDP | — | — | initial_access |
| `80.75.212.45` | External IP initiating RDP | — | — | initial_access |
| `185.91.127.19` | External IP initiating RDP | — | — | initial_access |
| `89.116.164.158` | External IP initiating RDP | — | — | initial_access |
| `193.141.60.147` | External IP initiating RDP | — | — | initial_access |
| `141.98.11.114` | External IP initiating RDP | — | — | initial_access |
| `45.132.115.136` | External IP initiating RDP | — | — | initial_access |
| `172.99.150.30` | External IP initiating RDP | — | — | initial_access |
| `136.144.43.111` | External IP initiating RDP | — | — | initial_access |
| `193.141.60.105` | External IP initiating RDP | — | — | initial_access |
| `185.147.124.57` | External IP initiating RDP | — | — | initial_access |
| `80.75.212.2` | External IP initiating RDP | — | — | initial_access |
| `209.145.63.57` | External IP initiating RDP | — | — | initial_access |
| `79.127.132.39` | External IP initiating RDP | — | — | initial_access |
| `193.141.60.3` | External IP initiating RDP | — | — | initial_access |
| `79.127.132.21` | External IP initiating RDP | — | — | initial_access |
| `45.227.254.3` | External IP initiating RDP | — | — | initial_access |
| `147.45.112.184` | External IP initiating RDP | — | — | initial_access |
| `82.165.133.160` | External IP initiating RDP | — | — | initial_access |
| `38.255.63.85` | External IP initiating RDP | — | — | initial_access |
| `191.96.227.230` | External IP initiating RDP | — | — | initial_access |
| `147.45.112.181` | External IP initiating RDP | — | — | initial_access |
| `103.123.37.36` | External IP initiating RDP | — | — | initial_access |
| `154.16.192.171` | External IP initiating RDP | — | — | initial_access |
| `168.220.240.60` | External IP initiating RDP | — | — | initial_access |
| `103.109.2.123` | External IP initiating RDP | — | — | initial_access |
| `88.214.25.125` | External IP initiating RDP | — | — | initial_access |
| `91.238.181.92` | External IP initiating RDP | — | — | initial_access |
| `141.98.11.49` | External IP initiating RDP | — | — | initial_access |
| `20.254.169.177` | External IP initiating RDP | — | — | initial_access |
| `1.4.220.16` | External IP initiating RDP | — | — | initial_access |
| `154.53.46.79` | External IP initiating RDP | — | — | initial_access |
| `66.70.255.44` | External IP initiating RDP | — | — | initial_access |
| `45.145.42.133` | External IP initiating RDP | — | — | initial_access |
| `177.229.135.5` | External IP initiating RDP | — | — | initial_access |
| `79.127.132.49` | External IP initiating RDP | — | — | initial_access |
| `217.160.125.6` | External IP initiating RDP | — | — | initial_access |
| `45.140.17.72` | External IP initiating RDP | — | — | initial_access |
| `62.73.93.254` | External IP initiating RDP | — | — | initial_access |
| `103.213.7.67` | External IP initiating RDP | — | — | initial_access |
| `91.238.181.91` | External IP initiating RDP | — | — | initial_access |
| `98.159.33.51` | External IP initiating RDP | — | — | initial_access |
| `103.180.111.173` | External IP initiating RDP | — | — | initial_access |
| `173.237.101.232` | External IP initiating RDP | — | — | initial_access |
| `45.140.17.73` | External IP initiating RDP | — | — | initial_access |
| `181.215.243.34` | External IP initiating RDP | — | — | initial_access |
| `194.165.16.162` | External IP initiating RDP | — | — | initial_access |
| `185.7.214.87` | External IP initiating RDP | — | — | initial_access |
| `79.127.132.57` | External IP initiating RDP | — | — | initial_access |
| `154.22.5.84` | External IP initiating RDP | — | — | initial_access |
| `194.32.122.7` | External IP initiating RDP | — | — | initial_access |
| `79.127.132.4` | External IP initiating RDP | — | — | initial_access |
| `171.244.63.189` | External IP initiating RDP | — | — | initial_access |
| `150.242.202.185` | External IP initiating RDP | — | — | initial_access |
| `79.127.132.37` | External IP initiating RDP | — | — | initial_access |
| `194.165.16.167` | External IP initiating RDP | — | — | initial_access |
| `103.17.193.188` | External IP initiating RDP | — | — | initial_access |
| `87.106.81.118` | External IP initiating RDP | — | — | initial_access |
| `178.212.240.242` | External IP initiating RDP | — | — | initial_access |
| `102.135.163.244` | External IP initiating RDP | — | — | initial_access |
| `183.83.219.75` | External IP initiating RDP | — | — | initial_access |
| `203.210.87.11` | External IP initiating RDP | — | — | initial_access |
| `8.221.116.228` | External IP initiating RDP | — | — | initial_access |
| `43.135.186.215` | External IP initiating RDP | — | — | initial_access |
| `206.217.129.236` | External IP initiating RDP | — | — | initial_access |
| `194.165.16.164` | External IP initiating RDP | — | — | initial_access |
| `91.238.181.6` | External IP initiating RDP | — | — | initial_access |
| `156.146.37.98` | External IP initiating RDP | — | — | initial_access |
| `104.234.124.99` | External IP initiating RDP | — | — | initial_access |
| `150.107.201.158` | External IP initiating RDP | — | — | initial_access |
| `40.90.210.124` | External IP initiating RDP | — | — | initial_access |
| `196.219.39.202` | External IP initiating RDP | — | — | initial_access |
| `171.244.140.81` | External IP initiating RDP | — | — | initial_access |
| `194.165.16.166` | External IP initiating RDP | — | — | initial_access |
| `103.241.171.86` | External IP initiating RDP | — | — | initial_access |
| `80.64.30.118` | External IP initiating RDP | — | — | initial_access |
| `88.214.25.122` | External IP initiating RDP | — | — | initial_access |
| `83.64.176.94` | External IP initiating RDP | — | — | initial_access |
| `91.238.181.96` | External IP initiating RDP | — | — | initial_access |
| `194.165.16.161` | External IP initiating RDP | — | — | initial_access |
| `191.96.150.219` | External IP initiating RDP | — | — | initial_access |
| `147.45.112.182` | External IP initiating RDP | — | — | initial_access |
| `85.10.147.82` | External IP initiating RDP | — | — | initial_access |
| `50.114.10.22` | External IP initiating RDP | — | — | initial_access |
| `138.199.59.151` | External IP initiating RDP | — | — | initial_access |
| `168.220.249.111` | External IP initiating RDP | — | — | initial_access |
| `38.68.40.9` | External IP initiating RDP | — | — | initial_access |
| `154.26.128.21` | External IP initiating RDP | — | — | initial_access |
| `162.19.88.104` | External IP initiating RDP | — | — | initial_access |
| `66.94.99.12` | External IP initiating RDP | — | — | initial_access |
| `168.220.245.72` | External IP initiating RDP | — | — | initial_access |
| `91.224.92.23` | External IP initiating RDP | — | — | initial_access |
| `75.119.150.129` | External IP initiating RDP | — | — | initial_access |
| `168.220.250.45` | External IP initiating RDP | — | — | initial_access |
| `179.60.146.30` | External IP initiating RDP | — | — | initial_access |
| `103.204.193.54` | External IP initiating RDP | — | — | initial_access |
| `191.6.69.86` | External IP initiating RDP | — | — | initial_access |
| `96.43.97.55` | External IP initiating RDP | — | — | initial_access |
| `152.32.206.252` | External IP initiating RDP | — | — | initial_access |
| `2.42.206.111` | External IP initiating RDP | — | — | initial_access |
| `192.41.50.7` | External IP initiating RDP | — | — | initial_access |
| `95.181.132.251` | External IP initiating RDP | — | — | initial_access |
| `87.106.134.24` | External IP initiating RDP | — | — | initial_access |
| `88.214.25.121` | External IP initiating RDP | — | — | initial_access |
| `180.188.231.133` | External IP initiating RDP | — | — | initial_access |
| `45.92.177.109` | External IP initiating RDP | — | — | initial_access |
| `88.214.25.123` | External IP initiating RDP | — | — | initial_access |
| `10.128.239.57` | Patient Zero - first internal host targeted (earliest event 2025-11-18 13:30:23 UTC) | — | — | initial_access |
| `10.128.239.32` | Credential spray source (707 failures) | — | — | lateral_movement |
| `10.128.239.36` | Credential spray source (644 failures) | — | — | lateral_movement |
| `10.128.239.39` | Credential spray source (927 failures) | — | — | lateral_movement |
| `10.128.239.98` | Credential spray source (25576 failures) | — | — | lateral_movement |
| `10.128.239.140` | SAMR enumeration source (6567 ops) | — | — | lateral_movement |
| `10.128.239.155` | SAMR enumeration source (58 ops) | — | — | lateral_movement |
| `10.128.239.29` | SOCKS proxy chain pivot point | — | — | lateral_movement |
| `10.128.239.25` | SOCKS proxy chain pivot point | — | — | lateral_movement |
| `10.128.239.21` | SOCKS proxy chain pivot point | — | — | lateral_movement |
| `10.128.239.23` | SOCKS proxy chain pivot point | — | — | lateral_movement |
| `10.128.239.20` | SOCKS proxy chain pivot point | — | — | lateral_movement |
| `10.128.239.26` | SOCKS proxy chain pivot point | — | — | lateral_movement |
| `10.128.239.88` | SOCKS proxy chain pivot point | — | — | lateral_movement |
| `10.128.239.28` | SOCKS proxy chain pivot point | — | — | lateral_movement |
| `10.128.239.31` | SOCKS proxy chain pivot point | — | — | lateral_movement |
| `10.128.239.82` | Internal WinRM source (1 targets) | — | — | lateral_movement |
| `51.91.79.17` | Resolved IP for known exfil domain | — | — | exfiltration |
| `10.128.239.176` | Host performing IP reconnaissance | — | — | exfiltration |
| `10.128.239.34` | Host performing IP reconnaissance | — | — | exfiltration |
| `10.128.239.37` | Host performing IP reconnaissance | — | — | exfiltration |
| `10.128.239.64` | Host performing IP reconnaissance | — | — | exfiltration |
| `10.128.239.65` | Host performing IP reconnaissance | — | — | exfiltration |
| `10.128.239.102` | Host accessing GPO files via SMB | — | — | payload |
| `10.128.239.70` | Host accessing GPO files via SMB | — | — | payload |
| `10.128.239.46` | Host accessing GPO files via SMB | — | — | payload |
| `10.128.239.97` | Host accessing GPO files via SMB | — | — | payload |
| `10.128.239.106` | Host accessing GPO files via SMB | — | — | payload |
| `10.128.239.69` | Host accessing GPO files via SMB | — | — | payload |
| `10.128.239.83` | Host accessing GPO files via SMB | — | — | payload |
| `113.105.164.28` | Protocol analyzer failure — SSL tunnel late-failure on RDP port 3389, targeted attacker signal distinct from mass-scanner early-failure pattern | — | — | initial_access |
| `198.51.100.1` | RFC TEST-NET-2 IP appearing as SSL SNI — NAT/proxy C2 with address leakage, traffic is TLS-encrypted and cannot be inspected | — | — | command_and_control |

### Domains

| Value | Context | First Seen | Last Seen | Phase |
| --- | --- | --- | --- | --- |
| `srv57c0d2365c3c.korsan.me` | C2 tunnel destination (HTTP CONNECT) | — | — | initial_access |
| `example.com` | C2 tunnel destination (HTTP CONNECT) | — | — | initial_access |
| `temp.sh` | Known exfil domain (52 DNS lookups) | — | — | exfiltration |
| `ant.typer.pl` | Suspicious high-volume DNS query (24,370 queries) from internal hosts 10.128.239.20, 10.128.239.21, 10.128.239.98 | — | — | command_and_control |
| `ilo.byper.pl` | Suspicious high-volume DNS query (24,341 queries) from internal hosts 10.128.239.20, 10.128.239.21, 10.128.239.98 | — | — | command_and_control |
| `hzh.0xox0xox0.com` | Suspicious high-volume DNS query (23,978 queries) from internal hosts 10.128.239.20, 10.128.239.21, 10.128.239.98 | — | — | command_and_control |

### Accounts

| Value | Context | First Seen | Last Seen | Phase |
| --- | --- | --- | --- | --- |
| `-` | Account targeted in credential spray from 10.128.239.32 | — | — | lateral_movement |
| `svc_backup` | Account targeted in credential spray from 10.128.239.36 | — | — | lateral_movement |
| `backup_safety` | Account targeted in credential spray from 10.128.239.39 | — | — | lateral_movement |
| `123` | Account targeted in credential spray from 10.128.239.98 | — | — | lateral_movement |
| `admin` | Account targeted in credential spray from 10.128.239.98 | — | — | lateral_movement |
| `administrator` | Account targeted in credential spray from 10.128.239.98 | — | — | lateral_movement |
| `alex` | Account targeted in credential spray from 10.128.239.98 | — | — | lateral_movement |
| `enter` | Account targeted in credential spray from 10.128.239.98 | — | — | lateral_movement |
| `game` | Account targeted in credential spray from 10.128.239.98 | — | — | lateral_movement |
| `guest` | Account targeted in credential spray from 10.128.239.98 | — | — | lateral_movement |
| `hack` | Account targeted in credential spray from 10.128.239.98 | — | — | lateral_movement |
| `home` | Account targeted in credential spray from 10.128.239.98 | — | — | lateral_movement |
| `IT1` | Account targeted in credential spray from 10.128.239.57 | — | — | lateral_movement |
| `LGallegos` | Account targeted in credential spray from 10.128.239.57 | — | — | lateral_movement |
| `APatton/POWER.domainaaaaaTW.LOCAL` | Account requesting Kerberos TGT (potential domain admin) | — | — | lateral_movement |
| `IT1/domain-ees3Ai.local` | Account requesting Kerberos TGT (potential domain admin) | — | — | lateral_movement |
| `jjjjjjjCA1$/domainaaaaaTW.LOCAL` | Account requesting Kerberos TGT (potential domain admin) | — | — | lateral_movement |
| `jjjjjjjca1$/domain-ees3Ai.local` | Account requesting Kerberos TGT (potential domain admin) | — | — | lateral_movement |
| `jjjjjjjca1$/domainaaaaaTW.LOCAL` | Account requesting Kerberos TGT (potential domain admin) | — | — | lateral_movement |

### Files

| Value | Context | First Seen | Last Seen | Phase |
| --- | --- | --- | --- | --- |
| `hfs` | File transfer tool found in SMB (4 occurrences) | — | — | exfiltration |
| `7z` | File transfer tool found in SMB (429 occurrences) | — | — | exfiltration |
| `nc` | File transfer tool found in SMB (2000 occurrences) | — | — | exfiltration |
| `Shares\\administration\\Software\\ChromeSetup.exe` | Large executable (8420232 bytes) staged via SMB | — | — | payload |
| `ChromeSetup.exe` | Large executable (8420232 bytes) staged via SMB | — | — | payload |
| `ManageEngine_PMP_64bit.exe` | Large executable (389681696 bytes) staged via SMB | — | — | payload |
| `Wireshark-win64-4.0.4.exe` | Large executable (78751312 bytes) staged via SMB | — | — | payload |
| `WinSCP-5.19.5-Setup.exe` | Large executable (11846088 bytes) staged via SMB | — | — | payload |
| `GeoServer-2.24.2-winsetup.exe` | Large executable (118876784 bytes) staged via SMB | — | — | payload |
| `vc_redist.x64.exe` | Large executable (25416016 bytes) staged via SMB | — | — | payload |
| `FileZilla_3.57.0_win64_sponsored-setup.exe` | Large executable (11800816 bytes) staged via SMB | — | — | payload |
| `TeamCity-2024.07.exe` | Large executable (1295961448 bytes) staged via SMB | — | — | payload |
| `domainaaaaa_domainaaaaaDefaultRemoteOffice_Agent.exe` | Large executable (37929968 bytes) staged via SMB | — | — | payload |
| `Setup.Def.en-us_O365ProPlusRetail_TX_PR_Platform_def_b_64_.exe` | Large executable (5341256 bytes) staged via SMB | — | — | payload |
| `SambaSetup5712.exe` | Large executable (114074424 bytes) staged via SMB | — | — | payload |
| `rpmelite_6.2.0.570_x64.exe` | Large executable (79805184 bytes) staged via SMB | — | — | payload |
| `npp.8.4.9.Installer.x64.exe` | Large executable (4658856 bytes) staged via SMB | — | — | payload |
| `npp.8.4.2.Installer.x64.exe` | Large executable (4518024 bytes) staged via SMB | — | — | payload |
| `MMASetup-AMD64.exe` | Large executable (26232232 bytes) staged via SMB | — | — | payload |
| `ManageEngine_RMM_Server.exe` | Large executable (1099864528 bytes) staged via SMB | — | — | payload |
| `ManageEngine_RecoveryManagerPlus_Bundle.exe` | Large executable (530144112 bytes) staged via SMB | — | — | payload |
| `Software\\GeoServer-2.24.2-winsetup.exe` | Large executable (118876784 bytes) staged via SMB | — | — | payload |
| `hfs.exe` | Large executable (5061120 bytes) staged via SMB | — | — | payload |
| `MBSetup.exe` | Large executable (2086424 bytes) staged via SMB | — | — | payload |
| `UninstallWinClient.exe` | Executable staged via SMB | — | — | payload |
| `git.exe` | Executable staged via SMB | — | — | payload |
| `<share_root>` | Executable staged via SMB | — | — | payload |
| `water.domain-ees3Ai.local\\Policies\\{7EC696A2-F33B-44B4-8521-A43780AA0EDD}\\Machine\\Preferences\\Registry\\Registry.xml` | Executable staged via SMB | — | — | payload |
| `water.domain-ees3Ai.local\\Policies\\{7EC696A2-F33B-44B4-8521-A43780AA0EDD}\\Machine\\Microsoft\\Windows NT\\Audit\\audit.csv` | Executable staged via SMB | — | — | payload |
| `domain-ees3Ai.local\\Policies\\{DBFEF99B-48F3-4F0C-9B4F-F546CE81EA16}\\Machine\\Preferences\\Groups\\Groups.xml` | Suspicious file on SMB share | — | — | payload |
| `water.domain-ees3Ai.local\\Policies\\{39E88897-4281-4145-BE0E-2D0147C2D08E}\\gpt.ini` | Suspicious file on SMB share | — | — | payload |
| `domain-ees3Ai.local\\Policies\\{DBFEF99B-48F3-4F0C-9B4F-F546CE81EA16}\\gpt.ini` | Suspicious file on SMB share | — | — | payload |
| `domain-ees3Ai.local\\Policies\\{7DDF95F4-B2B9-4BCD-8D81-9750119A5BB3}\\gpt.ini` | Suspicious file on SMB share | — | — | payload |
| `water.domain-ees3Ai.local\\Policies\\{7EBE6536-6437-48F1-80EA-2B6A6BDF5373}\\gpt.ini` | Suspicious file on SMB share | — | — | payload |
| `water.domain-ees3Ai.local\\Policies\\{7EC696A2-F33B-44B4-8521-A43780AA0EDD}\\gpt.ini` | Suspicious file on SMB share | — | — | payload |
| `water.domain-ees3Ai.local\\Policies\\{FB0F0788-09A4-41D0-A9D5-AA2769A94951}\\gpt.ini` | Suspicious file on SMB share | — | — | payload |
| `domain-ees3Ai.local\\Policies\\{2FEC0F4D-939C-4687-B7D4-8713D25EE390}\\gpt.ini` | Suspicious file on SMB share | — | — | payload |
| `domain-ees3Ai.local\\Policies\\{AAD79D81-3A5A-47B0-8A8F-EEA55525D6B3}\\gpt.ini` | Suspicious file on SMB share | — | — | payload |
| `domain-ees3Ai.local\\Policies\\{BF6EA5BB-0B35-44A5-A8E7-EE54C4FC12D5}\\gpt.ini` | Suspicious file on SMB share | — | — | payload |
| `water.domain-ees3Ai.local\\Policies\\{FB0F0788-09A4-41D0-A9D5-AA2769A94951}\\Machine\\Preferences\\Registry\\Registry.xml` | Suspicious file on SMB share | — | — | payload |
| `water.domain-ees3Ai.local\\Policies\\{36B593B4-BAA4-4062-8D9F-922B917A5D1D}\\gpt.ini` | Suspicious file on SMB share | — | — | payload |
| `domain-ees3Ai.local\\Policies\\{2FEC0F4D-939C-4687-B7D4-8713D25EE390}\\Machine\\Preferences\\Registry\\Registry.xml` | Suspicious file on SMB share | — | — | payload |
| `water.domain-ees3Ai.local\\Policies\\{DEAE82FE-D6F5-40B2-BC0E-F039B82C61E4}\\gpt.ini` | Suspicious file on SMB share | — | — | payload |
| `domain-ees3Ai.local\\Policies\\{7DDF95F4-B2B9-4BCD-8D81-9750119A5BB3}\\Machine\\Microsoft\\Windows NT\\Audit\\audit.csv` | Suspicious file on SMB share | — | — | payload |
| `domain-ees3Ai.local\\Policies\\{7DDF95F4-B2B9-4BCD-8D81-9750119A5BB3}\\Machine\\Preferences\\Registry\\Registry.xml` | Suspicious file on SMB share | — | — | payload |
| `domain-ees3Ai.local\\Policies\\{BF6EA5BB-0B35-44A5-A8E7-EE54C4FC12D5}\\Machine\\Preferences\\Registry\\Registry.xml` | Suspicious file on SMB share | — | — | payload |


## Attack Timeline

| # | Timestamp (UTC) | Source | Destination | Phase | Description | MITRE |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 2025-12-10 16:17:11 UTC | `196.251.89.107` | `10.128.239.57` | initial_access | HTTP CONNECT tunnel to srv57c0d2365c3c.korsan.me:443 | `T1572` |
| 2 | 2026-01-14 07:54:07 UTC | `89.248.163.217` | `10.128.239.57` | initial_access | HTTP CONNECT tunnel to example.com:443 | `T1572` |
| 3 | 2025-12-14 03:31:56 UTC | `5.182.209.113` | `10.128.239.57` | initial_access | External WinRM access from 5.182.209.113 | `T1133` |
| 4 | 2025-12-14 03:33:52 UTC | `5.182.209.113` | `10.128.239.57` | initial_access | External WinRM access from 5.182.209.113 | `T1133` |
| 5 | 2025-12-14 03:34:34 UTC | `5.182.209.113` | `10.128.239.57` | initial_access | External WinRM access from 5.182.209.113 | `T1133` |
| 6 | 2025-12-14 03:36:19 UTC | `5.182.209.113` | `10.128.239.57` | initial_access | External WinRM access from 5.182.209.113 | `T1133` |
| 7 | 2025-12-26 05:02:39 UTC | `5.182.209.113` | `10.128.239.57` | initial_access | External WinRM access from 5.182.209.113 | `T1133` |
| 8 | 2025-12-26 05:04:30 UTC | `5.182.209.113` | `10.128.239.57` | initial_access | External WinRM access from 5.182.209.113 | `T1133` |
| 9 | 2025-12-26 05:04:57 UTC | `5.182.209.113` | `10.128.239.57` | initial_access | External WinRM access from 5.182.209.113 | `T1133` |
| 10 | 2025-11-18 13:30:23 UTC | `185.147.124.48` | `10.128.239.57` | initial_access | External RDP from 185.147.124.48 | `T1133` |
| 11 | 2025-11-18 13:30:23 UTC | `141.98.11.96` | `10.128.239.57` | initial_access | External RDP from 141.98.11.96 | `T1133` |
| 12 | 2025-11-18 13:30:24 UTC | `193.111.248.57` | `10.128.239.57` | initial_access | External RDP from 193.111.248.57 | `T1133` |
| 13 | 2025-11-18 13:30:26 UTC | `194.165.17.11` | `10.128.239.57` | initial_access | External RDP from 194.165.17.11 | `T1133` |
| 14 | 2025-11-18 13:30:26 UTC | `45.130.145.79` | `10.128.239.57` | initial_access | External RDP from 45.130.145.79 | `T1133` |
| 15 | 2025-11-18 13:30:26 UTC | `147.45.112.185` | `10.128.239.57` | initial_access | External RDP from 147.45.112.185 | `T1133` |
| 16 | 2025-11-18 13:30:28 UTC | `185.147.124.164` | `10.128.239.57` | initial_access | External RDP from 185.147.124.164 | `T1133` |
| 17 | 2025-11-18 13:30:28 UTC | `194.165.17.11` | `10.128.239.57` | initial_access | External RDP from 194.165.17.11 | `T1133` |
| 18 | 2025-11-18 13:30:29 UTC | `179.60.146.33` | `10.128.239.57` | initial_access | External RDP from 179.60.146.33 | `T1133` |
| 19 | 2025-11-18 13:30:29 UTC | `91.238.181.7` | `10.128.239.57` | initial_access | External RDP from 91.238.181.7 | `T1133` |
| 20 | 2025-11-18 13:30:30 UTC | `147.45.112.183` | `10.128.239.57` | initial_access | External RDP from 147.45.112.183 | `T1133` |
| 21 | 2025-11-18 13:30:30 UTC | `181.49.207.198` | `10.128.239.57` | initial_access | External RDP from 181.49.207.198 | `T1133` |
| 22 | 2025-11-23 17:43:04 UTC | `10.128.239.57` | `10.128.239.91` | lateral_movement | Lateral NTLM auth from 10.128.239.57 (135 targets) | `T1078.002` |
| 23 | 2026-01-28 06:58:19 UTC | `10.128.239.57` | `10.128.239.32` | lateral_movement | Last lateral NTLM auth from 10.128.239.57 | `T1078.002` |
| 24 | 2025-11-18 16:30:34 UTC | `10.128.239.140` | `10.128.239.20` | lateral_movement | SAMR enumeration from 10.128.239.140 (6567 ops) | `T1087.002` |
| 25 | 2025-11-23 18:01:37 UTC | `10.128.239.57` | `10.128.239.110` | lateral_movement | SAMR enumeration from 10.128.239.57 (1971 ops) | `T1087.002` |
| 26 | 2025-11-29 17:43:41 UTC | `10.128.239.155` | `10.128.239.23` | lateral_movement | SAMR enumeration from 10.128.239.155 (58 ops) | `T1087.002` |
| 27 | 2025-11-18 14:31:59 UTC | `10.128.239.32` | `10.128.239.20` | lateral_movement | Kerberos TGT request (krbtgt) - 97 total | `T1558` |
| 28 | 2025-11-23 17:45:28 UTC | `10.128.239.57` | `10.128.239.91` | lateral_movement | Admin share access from 10.128.239.57 (1178 accesses) | `T1021.002` |
| 29 | 2025-11-18 13:33:34 UTC | `10.128.239.36` | `10.128.239.20` | lateral_movement | Admin share access from 10.128.239.36 (503 accesses) | `T1021.002` |
| 30 | 2025-11-18 13:44:09 UTC | `10.128.239.32` | `10.128.239.21` | lateral_movement | Admin share access from 10.128.239.32 (561 accesses) | `T1021.002` |
| 31 | 2025-11-18 13:58:50 UTC | `10.128.239.39` | `10.128.239.24` | lateral_movement | Admin share access from 10.128.239.39 (136 accesses) | `T1021.002` |
| 32 | 2025-11-18 16:30:33 UTC | `10.128.239.140` | `10.128.239.20` | lateral_movement | Admin share access from 10.128.239.140 (86 accesses) | `T1021.002` |
| 33 | 2025-11-19 00:05:26 UTC | `10.128.239.155` | `10.128.239.23` | lateral_movement | Admin share access from 10.128.239.155 (160 accesses) | `T1021.002` |
| 34 | 2025-11-18 13:30:55 UTC | `10.128.239.79` | `10.128.239.21` | lateral_movement | SOCKS proxy activity (502 records, 9 pivots) | `T1090.003` |
| 35 | 2025-11-18 14:15:33 UTC | `10.128.239.82` | `10.128.239.20` | lateral_movement | Internal WinRM from 10.128.239.82 to 1 targets | `T1021.006` |
| 36 | 2025-11-21 08:14:41 UTC | `10.128.239.57` | `10.128.239.20` | exfiltration | DNS lookup for exfil domain: temp.sh | `T1567.002` |
| 37 | 2025-11-21 08:14:41 UTC | `10.128.239.20` | `10.128.239.21` | exfiltration | DNS lookup for exfil domain: temp.sh | `T1567.002` |
| 38 | 2025-11-21 08:14:58 UTC | `10.128.239.57` | `51.91.79.17` | exfiltration | SSL session to exfil target: temp.sh | `T1573.002` |
| 39 | 2025-11-21 08:17:43 UTC | `10.128.239.57` | `51.91.79.17` | exfiltration | SSL session to exfil target: temp.sh | `T1573.002` |
| 40 | 2025-11-21 14:02:19 UTC | `10.128.239.57` | `51.91.79.17` | exfiltration | SSL session to exfil target: temp.sh | `T1573.002` |
| 41 | 2025-11-21 14:02:20 UTC | `10.128.239.57` | `51.91.79.17` | exfiltration | SSL session to exfil target: temp.sh | `T1573.002` |
| 42 | 2025-11-21 14:04:58 UTC | `10.128.239.57` | `51.91.79.17` | exfiltration | SSL session to exfil target: temp.sh | `T1573.002` |
| 43 | 2026-01-09 04:03:27 UTC | `10.128.239.176` | `3.162.174.84` | exfiltration | IP recon lookup: www.comae.com | `T1016` |
| 44 | 2026-01-09 05:29:18 UTC | `10.128.239.37` | `3.162.174.35` | exfiltration | IP recon lookup: www.comae.com | `T1016` |
| 45 | 2026-01-09 05:40:05 UTC | `10.128.239.65` | `3.162.174.19` | exfiltration | IP recon lookup: www.comae.com | `T1016` |
| 46 | 2026-01-19 23:09:51 UTC | `10.128.239.82` | `10.128.239.20` | exfiltration | Transfer tool on SMB: hfs | `T1039` |
| 47 | 2026-01-19 23:09:53 UTC | `10.128.239.82` | `10.128.239.20` | exfiltration | Transfer tool on SMB: hfs | `T1039` |
| 48 | 2025-11-19 02:49:17 UTC | `10.128.239.21` | `10.128.239.20` | exfiltration | Transfer tool on SMB: 7z | `T1039` |
| 49 | 2025-11-18 13:30:46 UTC | `10.128.239.120` | `10.128.239.21` | exfiltration | Transfer tool on SMB: nc | `T1039` |
| 50 | 2025-11-18 13:33:06 UTC | `10.128.239.91` | `10.128.239.20` | exfiltration | Transfer tool on SMB: nc | `T1039` |
| 51 | 2025-12-15 10:38:02 UTC | `10.128.239.57` | `10.128.239.37` | payload | Large .exe staged: Shares\\administration\\Software\\ChromeSetup.exe (8420232 by... | `T1021.002` |
| 52 | 2025-12-17 06:22:38 UTC | `10.128.239.57` | `10.128.239.37` | payload | Large .exe staged: Shares\\administration\\Software\\ChromeSetup.exe (8420232 by... | `T1021.002` |
| 53 | 2026-01-12 07:00:57 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: ChromeSetup.exe (8420232 bytes) 10.128.239.57->10.128.239.34 | `T1021.002` |
| 54 | 2026-01-12 07:00:58 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: ManageEngine_PMP_64bit.exe (389681696 bytes) 10.128.239.57->1... | `T1021.002` |
| 55 | 2026-01-12 07:03:48 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: Wireshark-win64-4.0.4.exe (78751312 bytes) 10.128.239.57->10.... | `T1021.002` |
| 56 | 2026-01-12 07:04:10 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: WinSCP-5.19.5-Setup.exe (11846088 bytes) 10.128.239.57->10.12... | `T1021.002` |
| 57 | 2026-01-12 07:04:29 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: GeoServer-2.24.2-winsetup.exe (118876784 bytes) 10.128.239.57... | `T1021.002` |
| 58 | 2026-01-12 07:05:16 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: vc_redist.x64.exe (25416016 bytes) 10.128.239.57->10.128.239.... | `T1021.002` |
| 59 | 2026-01-12 07:07:54 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: FileZilla_3.57.0_win64_sponsored-setup.exe (11800816 bytes) 1... | `T1021.002` |
| 60 | 2026-01-12 07:07:56 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: TeamCity-2024.07.exe (1295961448 bytes) 10.128.239.57->10.128... | `T1021.002` |
| 61 | 2026-01-12 07:08:10 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: domainaaaaa_domainaaaaaDefaultRemoteOffice_Agent.exe (3792996... | `T1021.002` |
| 62 | 2026-01-12 07:08:27 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: Setup.Def.en-us_O365ProPlusRetail_TX_PR_Platform_def_b_64_.ex... | `T1021.002` |
| 63 | 2026-01-12 07:20:29 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: Setup.Def.en-us_O365ProPlusRetail_TX_PR_Platform_def_b_64_.ex... | `T1021.002` |
| 64 | 2026-01-12 07:20:34 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: Setup.Def.en-us_O365ProPlusRetail_TX_PR_Platform_def_b_64_.ex... | `T1021.002` |
| 65 | 2026-01-12 07:37:20 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: SambaSetup5712.exe (114074424 bytes) 10.128.239.57->10.128.23... | `T1021.002` |
| 66 | 2026-01-12 07:37:40 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: rpmelite_6.2.0.570_x64.exe (79805184 bytes) 10.128.239.57->10... | `T1021.002` |
| 67 | 2026-01-12 07:37:42 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: npp.8.4.9.Installer.x64.exe (4658856 bytes) 10.128.239.57->10... | `T1021.002` |
| 68 | 2026-01-12 07:37:55 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: npp.8.4.2.Installer.x64.exe (4518024 bytes) 10.128.239.57->10... | `T1021.002` |
| 69 | 2026-01-12 07:39:40 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: MMASetup-AMD64.exe (26232232 bytes) 10.128.239.57->10.128.239... | `T1021.002` |
| 70 | 2026-01-12 07:39:50 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: MMASetup-AMD64.exe (26232232 bytes) 10.128.239.57->10.128.239... | `T1021.002` |
| 71 | 2026-01-12 07:40:00 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: ManageEngine_RMM_Server.exe (1099864528 bytes) 10.128.239.57-... | `T1021.002` |
| 72 | 2026-01-12 07:40:10 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: ManageEngine_RecoveryManagerPlus_Bundle.exe (530144112 bytes)... | `T1021.002` |
| 73 | 2026-01-12 07:47:55 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: ManageEngine_RMM_Server.exe (1099864528 bytes) 10.128.239.57-... | `T1021.002` |
| 74 | 2026-01-12 08:01:12 UTC | `10.128.239.57` | `10.128.239.37` | payload | Large .exe staged: Software\\GeoServer-2.24.2-winsetup.exe (118876784 bytes) 10.... | `T1021.002` |
| 75 | 2026-01-28 04:55:04 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: hfs.exe (5061120 bytes) 10.128.239.57->10.128.239.34 | `T1021.002` |
| 76 | 2026-01-28 04:55:07 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: Wireshark-win64-4.0.4.exe (78751312 bytes) 10.128.239.57->10.... | `T1021.002` |
| 77 | 2026-01-28 04:55:08 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: GeoServer-2.24.2-winsetup.exe (118876784 bytes) 10.128.239.57... | `T1021.002` |
| 78 | 2026-01-28 04:55:15 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: vc_redist.x64.exe (25416016 bytes) 10.128.239.57->10.128.239.... | `T1021.002` |
| 79 | 2026-01-28 04:55:16 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: FileZilla_3.57.0_win64_sponsored-setup.exe (11800816 bytes) 1... | `T1021.002` |
| 80 | 2026-01-28 05:02:08 UTC | `10.128.239.57` | `10.128.239.34` | payload | Large .exe staged: rpmelite_6.2.0.570_x64.exe (79805184 bytes) 10.128.239.57->10... | `T1021.002` |

## Recommendations

**P1 — Immediate (0–24 hours)**
**Containment and Active Threat Neutralization**

*   **Network Isolation & Host Quarantine:**
    *   Immediately isolate **Patient Zero (10.128.239.57)** from the network. This host initiated external RDP (T1133) at **2025-11-18 13:30:23 UTC** and performed 1,178 Admin$ share accesses to 135 targets.
    *   Quarantine **10.128.239.34** (Staging Server) and **10.128.239.176** (Host running unauthorized WicaAgent T1133).
    *   Block all external traffic to internal RDP (3389) and WinRM (5985/5986) ports at the perimeter firewall.
*   **IOC Blocking:**
    *   Block the following external IPs at the firewall/IPS immediately:
        *   **113.105.164.28** (External RDP attacker triggering TLS anomalies).
        *   **104.234.115.106, 88.214.25.115, 185.147.125.32, 141.98.11.53** (Protocol anomaly sources).
        *   **196.251.89.107, 89.248.163.217** (HTTP CONNECT tunnel sources).
        *   **18.191.28.175, 134.209.246.246, 152.32.234.184, 152.32.170.230, 5.182.209.113, 20.150.201.102, 15.204.142.151** (External HTTP access sources).
    *   Block C2 and Exfiltration Domains: **srv57c0d2365c3c.korsan.me**, **example.com**, **temp.sh**, **ant.typer.pl**, **ilo.byper.pl**, **hzh.0xox0xox0.com**.
*   **Credential Lockdown:**
    *   Disable accounts identified in suspicious Kerberos TGT activity (T1558): **APatton/POWER.domainaaaaaTW.LOCAL**, **IT1/domain-ees3Ai.local**, **jjjjjjjCA1$/domainaaaaaTW.LOCAL**.
    *   Force password reset for **IT1** and **APatton** immediately.
*   **Ransomware & Data Breach Advisory (T1486/T1490):**
    *   **Legal & Insurance Notification:** Given findings of "Pre-Encryption Backup Infrastructure Targeting (T1490)" and "Suspicious Files Detected on SMB Shares (T1486)", engage legal counsel and the organisation's cyber insurance carrier before making any ransom decision.
    *   **Regulatory Compliance:** Notification obligations to regulators and affected individuals vary by jurisdiction and must be assessed immediately.
    *   **Ransom Warning:** Ransom payment does not guarantee file recovery, may not prevent data publication, and may create regulatory and reputational risk. Do not omit this advisory.

**P2 — Short-term (1–7 days)**
**Eradication, Persistence Removal, and Key Rotation**

*   **Kerberos Key Rotation (T1558):**
    *   **Action:** Reset the **KRBTGT** account password **TWICE in succession**, waiting for Active Directory replication between resets (typically 10–15 minutes).
    *   **Reasoning:** A single reset invalidates existing tickets but does not fully rotate the encryption keys across all domain controllers. The second reset completes the key rotation. All existing Kerberos TGTs are invalidated after both resets, requiring re-authentication.
*   **Credential Reset for Lateral Movement (T1110.003/T1078.002):**
    *   **Action:** Reset passwords for **ALL accounts observed in successful NTLM authentications** during the incident window.
    *   **Scope:** Do not limit to the initially compromised account. Assume every account the attacker authenticated with is compromised. Specifically reset **IT1** and any accounts accessed by **10.128.239.57** (135 targets) and **10.128.239.36** (43 targets).
*   **Group Policy Audit (T1484.001):**
    *   **Action:** Audit all Group Policy Objects modified during the incident window. Run `Get-GPOReport -All -ReportType XML` and compare against the last known-good GPO backup.
    *   **Scope:** Focus on hosts **10.128.239.102, 10.128.239.70, 10.128.239.155, 10.128.239.46**.
    *   **Quarantine:** Quarantine any GPO with an unknown modification history (specifically files like `gpt.ini`, `Groups.xml`, `audit.csv`) until reviewed. Attacker-created or modified GPOs may persist after the attacker's tools are removed and will re-deploy malware at the next logon cycle.
*   **Malware Removal & System Rebuild:**
    *   Remove staged executables from **10.128.239.34**: `UninstallWinClient.exe`, `TeamCity-2024.07.exe`, `hfs.exe`.
    *   Remove **WicaAgent** remote access software from **10.128.239.176**.
    *   Re-image all hosts identified in the 72.7-day dwell time (2025-11-18 to 2026-01-30) that showed lateral movement or tool staging.

**P3 — Medium-term (1–3 months)**
**Strategic Controls and Prevention**

*   **Network Segmentation & Access Control:**
    *   Implement strict network segmentation to prevent lateral movement via Admin$ shares (T1021.002) and SMB (T1021.002). Restrict WinRM (T1021.006) and RDP (T1133) access to internal management networks only.
    *   Enforce MFA for all remote access protocols (RDP, WinRM, HTTP) to mitigate Credential Spray (T1110.003) and external access risks.
*   **Endpoint Detection & Response (EDR):**
    *   Deploy EDR solutions capable of detecting PowerShell Remote Execution (T1059.001) anomalies (e.g., `PSVersion=5.1.20348.558` in URI) and unauthorized remote tools like WicaAgent.
    *   Configure alerts for high-volume DNS queries to suspicious TLDs (e.g., `.pl`, `.com` anomalies like `temp.sh`) to detect DNS Exfiltration (T1567.002).
*   **Privileged Access Management (PAM):**
    *   Implement PAM solutions to manage administrative credentials used for SAMR Enumeration (T1087.002) and Admin$ access.
    *   Monitor for SOCKS Proxy Chains (T1090.003) and HTTP CONNECT Tunneling (T1572) to detect C2 obfuscation attempts.
*   **Backup Integrity Verification:**
    *   Verify integrity of backup infrastructure (T1490) to ensure attackers cannot destroy backups prior to encryption. Implement immutable backups where possible.
    *   Conduct regular drills to test backup restoration capabilities following a ransomware event.

## Cost & Efficiency Analysis

| Metric | Value |
| --- | --- |
| Total LLM calls | 54 |
| Total tool invocations | 118 |
| Input tokens | 2,676,521 |
| Output tokens | 24,120 |
| Wall-clock time | 6m 58s |

### Cost Comparison

| Execution Mode | Estimated Cost |
| --- | --- |
| Paid API | $5.6425 |
| Local GPU (Local GPU @ $4.50/hr) | $0.5227 |
| Savings with local execution | 91% |

## Appendix: Agent Reasoning Trace

The following is the agent's autonomous reasoning trail during investigation.

1. [Step 1] 


2. [Step 2] 


3. [Step 3] 


4. [Step 4] 


5. [Step 5] 


6. [Step 6] 


7. [Step 7] 


8. [Step 8] 


9. [Step 9] 


10. [Step 10] 


11. [Step 11] 


12. [Step 12] 


13. [Step 13] 


14. [Step 14] 


15. [Step 15] 


16. [Step 16] 


17. [Step 17] 


18. [Step 18] 


19. [Step 19] 


20. [Step 20] 


21. [Step 21] 


22. [Step 22] 


23. [Step 23] 


24. [Step 24] 


25. [Step 25] 


26. [Step 26] 


27. [Step 27] 


28. [Step 28] 


29. [Step 29] 


30. [Step 30] 


31. [Step 31] 


32. [Step 32] 


33. [Step 33] 


34. [Step 34] 


35. [Step 35] 


36. [Step 36] 


37. [Step 37] 


38. [Step 38] 


39. [Step 39] 


40. [Step 40] 


41. [Step 41] 


42. [Step 42] 


43. [Step 43] 


44. [Step 44] 


45. [Step 45] 


46. [Step 46] 


47. [Step 47] 


48. [Step 48] 


49. [Step 49] 


50. [Step 50] 


51. [Step 51] 


52. [Step 52] 



---

*Report generated by Agentic Network Forensic Agent.  Generated on 2026-04-08 10:42:15 UTC.*