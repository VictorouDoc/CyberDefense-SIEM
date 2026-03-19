# Blue Team Project - [ORGANIZATION] ([TEAM])

## Mission Context
We are the new **Blue Team** at [ORGANIZATION]. The previous IT team has just left the premises. We have full access to the infrastructure, which is currently exposed to the Internet.

**Our absolute priority:** Ensure the infrastructure doesn't "blow up". Uptime and confidentiality are critical.

## Main Objectives (Day 1 - Day 2)
1.  **Maintain Infrastructure:** You can change anything, but **do not break any existing services**.
2.  **Visibility (SoC/SIEM):** Build a setup to gain visibility on network activity (a small SIEM-like system).
3.  **Inventory & Audit:** Make an inventory of IT resources and document vulnerabilities.
4.  **Reporting:** Document every step taken and any tools created.

---

## Known Infrastructure (The Bastion)
The infrastructure relies mainly on an exposed Bastion host.

* **Domain:** `example.org`
* **Identified Services:**
    * **SSH:** Ports `221` (Group 1), `222` (Group 2), etc.
    * **HTTP:** Ports `8081` (Group 1), `8082` (Group 2), etc.

> **Warning:** While we have root access to modify the infrastructure, stability is key.

---

## Custom SIEM - Features

### Core Monitoring
- **Real-time packet capture** using Scapy
- **Protocol detection**: HTTP, HTTPS, SSH, DNS, SMTP, FTP, MySQL, PostgreSQL, Redis, RDP, SMB, etc.
- **Dark-themed SOC Dashboard** with Chart.js visualizations

### Threat Detection
| Threat Type | Detection Method |
|-------------|------------------|
| Port Scanning | 10+ ports scanned in 60s |
| DDoS (Packet Flood) | 100+ packets in 10s |
| DDoS (SYN Flood) | 50+ SYN packets in 10s |
| DNS Tunneling | Long domains, many subdomains, suspicious patterns |
| DNS Exfiltration | High-entropy subdomains, hex/base64 labels, query rate |
| HTTP Exfiltration | Large POST, suspicious params, high-entropy cookies |
| C2 Beaconing | Regular-interval outbound connections (CV < 0.3) |
| Fuzzing | Rapid varied requests on monitored ports (80, 5001, 8080) |
| SSTI | Jinja2/Twig/Freemarker/Velocity/Spring EL patterns + real IP extraction |
| SQL Injection | Pattern matching in payloads |
| XSS | Script tags, javascript: URIs |
| Path Traversal | ../ patterns, /etc/passwd |
| Command Injection | Shell metacharacters |
| Vulnerability Exploits | EternalBlue, Log4Shell, Spring4Shell, Redis RCE, Shellshock, etc. |
| SSH/SMTP/POP3 Brute Force | Connection attempt rate tracking |

### Firewall / Fail2ban
Custom fail2ban-like system with:
- **Auto-ban**: IPs exceeding thresholds are automatically banned via iptables
- **Manual ban**: Ban/unban from web interface (`/firewall`)
- **Whitelist**: Protected IPs that can never be banned
- **Configurable duration**: 1h default for auto-ban, permanent option available

### Web Interface
- **Dashboard**: Stats, traffic timeline, protocol distribution, recent alerts
- **Packets**: Browse captured packets with filters
- **Events**: Security events with severity levels
- **Alerts**: Alert management with status workflow
- **Firewall**: IP ban management, stats, whitelist info

---

## Quick Start

### Deploy to Server
```bash
# Copy files to server
scp -r -P 225 ./siem admin@example.org:~/

# Connect with port forwarding
ssh -L 8080:localhost:8080 admin@example.org -p 225

# On server: start SIEM
cd ~/siem && source ~/siem_env/bin/activate
sudo ~/siem_env/bin/python run.py --capture --interface eth0 --port 8080
```

### Access Dashboard
Open http://localhost:8080 in your browser.

---

## Roadmap

### Phase 1: Reconnaissance
- [x] **Inventory:** List running services and open ports
- [x] **Vulnerabilities:** Identify potential weaknesses

### Phase 2: Building the SIEM (Monitoring)
- [x] **Packet Capture:** Scapy-based real-time sniffing
- [x] **Detection Rules:** Port scan, DNS anomaly, attack patterns
- [x] **SOC Dashboard:** Web-based monitoring interface
- [x] **DDoS Detection:** Packet flood & SYN flood detection
- [x] **Firewall/Fail2ban:** Auto-ban system with iptables
- [x] **SSTI Detection:** Server-Side Template Injection with real IP extraction (X-Forwarded-For)
- [x] **DNS Exfiltration:** Entropy analysis, encoded subdomain detection
- [x] **HTTP Exfiltration:** Suspicious outbound data detection
- [x] **C2 Beaconing:** Regular-interval connection detection
- [x] **Fuzzing Detection:** Rapid varied request detection on uptime API & web services
- [x] **Vulnerability Exploit Detection:** EternalBlue, Log4Shell, Redis RCE, Shellshock, etc.

### Phase 3: DRP (Disaster Recovery Plan)
- [ ] **Define RTO/RPO:** Determine acceptable downtime and data loss
- [ ] **Backup:** Ensure backup and restoration processes

### Phase 4: Documentation
- [x] Document SIEM implementation
- [x] Document firewall/fail2ban system
- [ ] Report via Teams channel

---

## Tech Stack
| Component | Technology |
|-----------|------------|
| Backend | Python 3.12 + Flask |
| Packet Capture | Scapy |
| Database | SQLite |
| Frontend | Bootstrap 5 + Chart.js |
| Firewall | iptables |

---

## Incident Response Procedure
Follow the principle: **"Defend, Detect, Respond, Recover"**.
1.  **Containment:** Stop the threat spreading
2.  **Analysis:** Analyze logs and evidence
3.  **Recovery:** Coordinate system restoration

---

## Project Structure
```
.
├── siem/                     # SIEM Application
│   ├── app/                  # Flask application
│   │   ├── routes/           # Web routes & API
│   │   └── templates/        # HTML templates
│   ├── capture/              # Packet capture & analysis
│   ├── run.py                # Entry point
│   └── requirements.txt
├── CONTEXT.md                # Detailed technical documentation
└── README.md                 # This file
```

---

## Success Metrics (KPIs)
* **Uptime:** Service availability
* **MTTD (Mean Time To Detect):** Time to spot a threat
* **MTTR (Mean Time To Respond):** Time to react
