# Forensic Report Evaluation Checklist

This checklist contains verifiable claims that an AI agent can determine from Zeek-processed PCAP logs alone. Each item is a single atomic fact observable from network telemetry. Items requiring external threat intelligence, business context, or events outside the PCAP capture window have been removed.

---

## 1. Attack Overview (5 points)

- [ ] Victim organisation is **Apex Global Logistics**
- [ ] Attack type: ransomware that encrypted backup servers
- [ ] Analysis based on Zeek-processed PCAP logs only (no endpoint telemetry)
- [ ] PCAP capture window: **Nov 17, 2025 – Jan 29, 2026** (~72 days)
- [ ] Dwell time: **~72 days** from initial compromise (~Nov 18, 2025) to last PCAP activity (~Jan 29, 2026)

## 2. Initial Access (17 points)

- [ ] Internet-facing RDP service on host **10.128.239.57** (Patient Zero) was the initial access vector
- [ ] Attacker IP **113.105.164.28** established **20+ authenticated RDP sessions** to .57
- [ ] RDP sessions used **HYBRID (NLA) authentication**, confirming valid credentials were used
- [ ] Sessions occurred on **Dec 12, 2025** within ~27 minutes, each with a different source port
- [ ] **dpd_sorted.log** contained 2 entries from 113.105.164.28 to .57:3389 with SSL anomalies (Dec 12 and Dec 24, 2025)
- [ ] 113.105.164.28 was the **only external IP** in the entire RDP log with authenticated sessions
- [ ] C2 tunnel: **196.251.89.107** used HTTP CONNECT through .57:3389 to reach **korsan.me:443** (Dec 10, 2025 ~07:57 UTC)
- [ ] External IP **5.182.209.113** sent **16 automated WinRM POST /wsman** requests to .57:3389 (Dec 13 and Dec 25)
- [ ] WinRM requests from 5.182.209.113 used **Go-http-client/1.1** user-agent
- [ ] Host header **198.51.100.1** is an RFC 5737 TEST-NET address, indicating a NAT/proxy in attacker infrastructure
- [ ] .57 was already acting as a proxy/relay **before** the Dec 12 authenticated RDP sessions (Dec 10 C2 tunnel precedes them)
- [ ] MITRE: T1133 (External Remote Services), T1078 (Valid Accounts), T1572 (Protocol Tunnelling)

**Timeline anchors:**
- [ ] Dec 10, 2025 ~07:57 UTC — C2 tunnel via korsan.me through .57:3389 from 196.251.89.107
- [ ] Dec 12, 2025 14:29–14:56 UTC — 20+ authenticated RDP sessions from 113.105.164.28
- [ ] Dec 13, 2025 ~19:11 UTC — WinRM exploitation wave 1 from 5.182.209.113 (9 POSTs)
- [ ] Dec 24, 2025 ~21:27 UTC — Second DPD SSL alert from 113.105.164.28
- [ ] Dec 25, 2025 ~20:29 UTC — WinRM exploitation wave 2 from 5.182.209.113 (7 POSTs)

## 3. Credential Access (7 points)

- [ ] Credential spray from **10.128.239.98** (WIN998): **25,576 NTLM authentication attempts**
- [ ] All 25,576 credential spray attempts **failed**
- [ ] Spray targeted **11 hosts** within seconds
- [ ] Spray occurred on **Nov 19, 2025 ~00:27 UTC**
- [ ] Dictionary usernames included: administrator, test, hack, alex, guest, admin
- [ ] MITRE: T1110.003 (Password Spraying)

**Timeline anchor:**
- [ ] Nov 19, 2025 ~00:27 UTC — Credential spray from .98 (25,576 attempts, all fail)

## 4. Discovery & Enumeration (8 points)

- [ ] SAMR Active Directory enumeration from **10.128.239.140** targeting DC1 (.20)
- [ ] **7,681 total SAMR operations** from .140
- [ ] SAMR operations breakdown: SamrConnect5 (599), SamrEnumerateDomainsInSamServer (585), SamrOpenDomain (1,181), SamrLookupNamesInDomain (576), SamrOpenUser (398), SamrQueryInformationUser (403), SamrGetGroupsForUser (412), SamrGetAliasMembership (401), SamrQuerySecurityObject (396), SamrLookupDomainInSamServer (576)
- [ ] No **SamrCreateUser** or **SamrAddMemberToGroup** observed — attacker used only existing accounts
- [ ] SAMR enumeration occurred on **Nov 19, 2025 ~00:30 UTC**
- [ ] MITRE: T1087.002 (Domain Account Discovery), T1069.002 (Domain Group Discovery)

**Timeline anchor:**
- [ ] Nov 18, 2025 ~22:00 UTC — SAMR recon from .77 to DC3
- [ ] Nov 19, 2025 ~00:30 UTC — SAMR enumeration from .140 (7,681 ops against DC1/DC3)

## 5. Privilege Escalation (6 points)

- [ ] Domain admin account **APatton** obtained within **2 days** of initial access
- [ ] Kerberos TGT for APatton obtained from **.57** requesting access to the **POWER** domain
- [ ] TGT used **aes256-cts-hmac-sha1-96** cipher
- [ ] Privilege escalation occurred on **Nov 20, 2025 ~19:39 UTC**
- [ ] MITRE: T1078.002 (Valid Accounts: Domain Accounts), T1558 (Steal or Forge Kerberos Tickets)

**Timeline anchor:**
- [ ] Nov 20, 2025 ~19:39 UTC — APatton domain admin TGT obtained from .57

## 6. Lateral Movement (16 points)

- [ ] Mass lateral movement using account **IT1** originating from Patient Zero (.57)
- [ ] **2,626 successful NTLM authentications** to **135+ unique internal hosts**
- [ ] Lateral movement began **Nov 23, 2025 ~17:23 UTC**
- [ ] Sequential rapid authentication to DC1, DC3, CA1, BACKUP01, BACKUP04, and 130+ other hosts
- [ ] **2,186 ADMIN$/C$ accesses** from .57 to target hosts (smb_mapping log)
- [ ] Administrative share access began **Nov 24, 2025 ~01:49 UTC**
- [ ] SOCKS5 proxy tunnel chain: **.57 → .29 → .23** (DC8)
- [ ] **535 total SOCKS connections** recorded
- [ ] SOCKS tunnel active from **Nov 18 through Jan 29**
- [ ] WinRM PowerShell execution from **.82 (WIN950)** to **DC1 (.20) on port 5985**
- [ ] WinRM payload sizes: **5.8 KB** (Nov 18) and **8.9 KB** (Jan 19) with HTTP 200 responses
- [ ] MITRE: T1021.002 (SMB/Windows Admin Shares), T1021.006 (WinRM), T1090.003 (Multi-hop Proxy), T1059.001 (PowerShell)

**Timeline anchors:**
- [ ] Nov 18, 2025 ~21:55 UTC — WinRM from .82 to DC1 (5.8 KB PowerShell payload)
- [ ] Nov 23, 2025 ~17:23 UTC — IT1 lateral movement begins from .57 to 135+ hosts
- [ ] Nov 24, 2025 ~01:49 UTC — ADMIN$/C$ share access begins (2,186 total)
- [ ] Jan 19, 2026 ~04:05 UTC — WinRM from .82 to DC1 (8.9 KB payload)

## 7. Exfiltration (21 points)

- [ ] Data exfiltrated from .57 to **temp.sh** (resolved IP: **51.91.79.17**)
- [ ] Exfiltration used **TLS 1.3** (cipher: TLS_AES_128_GCM_SHA256, key exchange: x25519)
- [ ] **11 total TLS sessions** to temp.sh across **2 time windows**
- [ ] Window 1: **Nov 21, 2025** — 6 sessions over ~6 hours (00:14–06:07 UTC)
- [ ] Window 2: **Jan 26, 2026** — 5 sessions over ~1.7 hours
- [ ] DNS lookup for temp.sh from .57 on **Nov 21, 2025 ~00:14 UTC**, resolved to 51.91.79.17
- [ ] Both **A** and **HTTPS (SVCB, type 65)** DNS records were queried for temp.sh
- [ ] **Comae** tool used for external IP discovery (HTTP GET to www.comae.com/getip.php with User-Agent: "Comae")
- [ ] **10 internal hosts** queried their external IP across **2 waves**
- [ ] Wave 1: **Jan 9, 2026** — 5 hosts: .176, .37, .65, .34, .21
- [ ] Wave 2: **Jan 17, 2026** — 5 hosts: .64, .57, .20, .36, .39 (includes both DCs and both backup servers)
- [ ] Wave 2 preceded the second exfiltration window by **9 days**
- [ ] **hfs.exe** (HTTP File Server, 5 MB) accessed by .57 from `\\10.128.239.34\software`
- [ ] **WinSCP 5.19.5** installer (11.8 MB) accessed from the software share by .57
- [ ] **FileZilla 3.57.0** installer (11.8 MB) accessed from the software share by .57
- [ ] MITRE: T1567.002 (Exfiltration to Cloud Storage), T1573.002 (Encrypted Channel), T1039 (Data from Network Shared Drive), T1016 (System Network Configuration Discovery)

**Timeline anchors:**
- [ ] Nov 21, 2025 ~00:14 UTC — DNS lookup for temp.sh; exfiltration Window 1 begins (6 sessions over ~6 hrs)
- [ ] Jan 9, 2026 — Comae Wave 1 (5 hosts)
- [ ] Jan 17, 2026 — Comae Wave 2 (5 hosts, including DCs and backup servers)
- [ ] Jan 26, 2026 — Exfiltration Window 2 (5 TLS sessions to temp.sh)
- [ ] Jan 27, 2026 — hfs.exe accessed from software share

## 8. Payload Staging & Impact (24 points)

- [ ] **20+ executables** (>3.5 GB total) staged on software distribution server (**10.128.239.34**) via SMB
- [ ] Staging occurred **Jan 25–27, 2026**
- [ ] **domainaaaaa_...DefaultRemoteOffice_Agent.exe** — 37.9 MB custom-named executable
- [ ] **ManageEngine_RMM_Server.exe** — 1.1 GB
- [ ] **ManageEngine_RecoveryManagerPlus_Bundle.exe** — 530 MB (targets backup systems)
- [ ] **TeamCity-2024.07.exe** — ~1.3 GB
- [ ] **SambaSetup5712.exe** — ~114 MB
- [ ] **GeoServer-2.24.2-winsetup.exe** — ~119 MB
- [ ] **Wireshark-win64-4.0.4.exe** — ~79 MB
- [ ] **vc_redist.x64.exe** — ~25 MB
- [ ] **MMASetup-AMD64.exe** — ~26 MB
- [ ] **rpmelite_6.2.0.570_x64.exe** — ~80 MB
- [ ] GPO files accessed via SMB: gpt.ini, Registry.xml, Groups.xml, audit.csv (across multiple forest sub-domains)
- [ ] **17 PE files** transferred, compiled for both **I386** (32-bit) and **AMD64** (64-bit) targets
- [ ] PE compile timestamps: **Dec 2024 – Mar 2025** (pre-date the attack)
- [ ] PowerShell commands executed on DC1 via WinRM (likely GPO mass-deployment preparation)
- [ ] **135+ internal hosts** reached during the campaign
- [ ] Both Domain Controllers compromised: **DC1** (.20) and **DC3** (.21)
- [ ] Both backup servers reached: **BACKUP01** (.36) and **BACKUP04** (.39)
- [ ] Certificate Authority (.32) reached
- [ ] MITRE: T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), T1219 (Remote Access Software), T1484.001 (Group Policy Modification)

**Timeline anchors:**
- [ ] Dec 1, 2025 — First PE binary transfer observed
- [ ] Jan 25–27, 2026 — 20+ executables (>3.5 GB) staged on .34 via SMB
- [ ] Jan 29, 2026 — Last PCAP activity recorded

## 9. Network Environment (23 points)

- [ ] Internal domain: **domain-ees3Ai.local**
- [ ] Internal subnet: **10.128.239.0/24**
- [ ] AD Forest sub-domains: **WATER, POWER, SAFETY, PARKS**
- [ ] 10.128.239.1 — OPNsense Gateway/Firewall
- [ ] 10.128.239.20 — jjjjjjjDC1 (Domain Controller 1, Primary)
- [ ] 10.128.239.21 — jjjjjjjDC3 (Domain Controller 3)
- [ ] 10.128.239.23 — jjjjjjjDC8/WTDC8 (DC, WATER subdomain)
- [ ] 10.128.239.24 — jjjjjjjSFDC6 (Safety Forest DC)
- [ ] 10.128.239.29 — Server (attacker relay / pivot point)
- [ ] 10.128.239.31 — jjjjjjjSFDC9 (Safety Forest DC)
- [ ] 10.128.239.32 — jjjjjjjCA1 (Certificate Authority)
- [ ] 10.128.239.34 — Software Distribution Server
- [ ] 10.128.239.36 — jjjjjjjBACKUP01 (Backup Server 1)
- [ ] 10.128.239.37 — File/Application Server
- [ ] 10.128.239.39 — jjjjjjjBACKUP04 (Backup Server 4)
- [ ] 10.128.239.57 — Patient Zero (internet-facing, RDP exposed)
- [ ] 10.128.239.82 — jjjjjjjWIN950 (Workstation, user IT1)
- [ ] 10.128.239.98 — jjjjjjjWIN998 (Workstation, credential spray source)
- [ ] 10.128.239.140 — Workstation (AD enumeration source)
- [ ] 10.128.239.176 — Workstation (WicaAgent + Comae activity)
- [ ] 10.128.239.221 — SonicWALL Firewall/VPN endpoint
- [ ] 10.128.239.226 — Cisco IOS switch/router
- [ ] "jjjjjjj" prefix on hostnames is an artefact of the client's naming convention

## 10. IOCs & Tools (28 points)

### External Threat Actor IPs
- [ ] **113.105.164.28** — Initial Access via RDP, 20+ sessions to .57
- [ ] **196.251.89.107** — C2 Tunnel (HTTP CONNECT to korsan.me:443)
- [ ] **5.182.209.113** — WinRM exploitation (16 /wsman POSTs to .57)
- [ ] **51.91.79.17** — Exfiltration destination (temp.sh)
- [ ] **80.82.70.133** — External HTTP probe to .57
- [ ] **89.248.163.217** — HTTP CONNECT tunnel attempt to .57

### Malicious Domains
- [ ] **srv57c0d2365c3c.korsan.me** — C2 SSL tunnel destination
- [ ] **temp.sh** — Data exfiltration service (resolves to 51.91.79.17)
- [ ] **www.comae.com** — External IP reconnaissance (getip.php)

### Compromised Accounts
- [ ] **IT1** — 2,626 successful NTLM authentications to 135+ hosts from .57
- [ ] **APatton** — Domain Admin (POWER domain), Kerberos TGT obtained from .57
- [ ] **svc_backup** — Service account, 645 NTLM authentications from BACKUP01 (.36)
- [ ] **backup_safety** — Service account, 904 NTLM authentications from BACKUP04 (.39)
- [ ] **LGallegos** — User account, 11 NTLM authentications from .57

### Suspicious Files
- [ ] **domainaaaaa_...DefaultRemoteOffice_Agent.exe** — 37.9 MB
- [ ] **hfs.exe** — 5.0 MB
- [ ] **PE binary delivered via Edge CDN** — 60.2 MB, MD5: be2b1e91ce816fcc3381b98212ff5f53

### Attacker Tools Identified
- [ ] **Comae** — External IP discovery tool (HTTP requests with "Comae" User-Agent)
- [ ] **WicaAgent (UltraVNC)** — Remote access tool detected on .176
- [ ] **hfs.exe** — HTTP File Server (data staging)
- [ ] **WinSCP 5.19.5** — SFTP client
- [ ] **FileZilla 3.57.0** — FTP client
- [ ] **Wireshark 4.0.4** — Network capture tool
- [ ] **Go-http-client/1.1** — Automated HTTP tool used for WinRM exploitation (5.182.209.113)
- [ ] **PowerShell 5.1** (PSVersion=5.1.20348.558) — Remote execution via WinRM
- [ ] **ManageEngine RMM Server** — Mass endpoint management (1.1 GB installer)
- [ ] **domainaaaaa_...Agent.exe** — Custom suspected RAT/backdoor (37.9 MB)
- [ ] SAMR enumeration tool (likely SoftPerfect Network Scanner or NetExec) — AD recon from .140

## 11. Log Coverage & Data Quality (5 points)

- [ ] **30 Zeek log types** produced from the PCAP
- [ ] Key logs used: conn, rdp, dns, http, ssl, ntlm, kerberos, dce_rpc, smb_files, smb_mapping, socks, pe, files, notice, software, dpd
- [ ] **conn.log** (1.6 GB) and **rdp.log** (476 MB) too large for complete line-by-line ingestion
- [ ] **notice.log** reported **37,772 capture-loss events** (11–39% packet loss throughout capture)
- [ ] Encrypted TLS 1.3 traffic to temp.sh cannot be content-inspected; exfiltration volume must be estimated from connection metadata
