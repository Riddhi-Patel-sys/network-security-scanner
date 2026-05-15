# 🔐 Network Security Scanner & Report Generator

A Python-based network security assessment tool that scans a target host for open ports, identifies running services, assesses risk levels, and automatically generates a **professional PDF security report**.

Built by **Riddhi Patel** — BTech Information Technology, KPU

---

## 🎯 What This Tool Does

- **Port Scanning** — Scans 21 commonly exploited ports using multi-threaded TCP connect scanning
- **Service Detection** — Identifies running services (SSH, FTP, HTTP, SMB, RDP, databases, etc.)
- **Banner Grabbing** — Retrieves service banners for version identification
- **Risk Assessment** — Assigns severity levels: CRITICAL / HIGH / MEDIUM / LOW
- **PDF Report Generation** — Produces a professional security report with findings and recommendations
- **JSON Export** — Saves raw scan data in JSON format for further analysis

---

## 📊 Sample Report Output

The tool generates a professional PDF report containing:

| Section | Contents |
|---|---|
| Scan Summary | Target, IP, date/time, total findings |
| Risk Overview | Risk counts by severity + overall rating |
| Detailed Findings | Port, service, risk level, banner |
| Recommendations | Specific remediation advice per finding |
| Methodology | How the scan was conducted |

---

## 🛠️ Technologies Used

- **Python 3** — Core language
- **socket** — TCP port scanning and banner grabbing
- **concurrent.futures** — Multi-threaded scanning for speed
- **ReportLab** — Professional PDF report generation
- **JSON** — Structured data export

---

## ⚙️ Installation

### Requirements
- Python 3.7 or higher
- pip

### Install Dependencies

```bash
pip install reportlab
```

### Clone the Repository

```bash
git clone https://github.com/Riddhi-Patel-sys/network-security-scanner.git
cd network-security-scanner
```

---

## 🚀 Usage

### Basic Scan (localhost demo)
```bash
python3 scanner.py
```

### Scan a Specific Target
```bash
python3 scanner.py 192.168.1.1
```

### Scan with Custom Report Name
```bash
python3 scanner.py 192.168.1.1 my_report.pdf
```

### Output Files
- `security_report.pdf` — Full professional PDF report
- `scan_results.json` — Raw scan data in JSON format

---

## ⚠️ Legal Disclaimer

> **This tool is for educational purposes and authorized security assessments ONLY.**
> Only scan systems you own or have **written permission** to scan.
> Unauthorized scanning of systems is **illegal** and unethical.
> All testing was performed in an isolated lab environment.

---

## 🔍 Ports Scanned & Risk Levels

| Port | Service | Risk Level |
|---|---|---|
| 21 | FTP | 🟠 HIGH |
| 22 | SSH | 🟡 MEDIUM |
| 23 | Telnet | 🔴 CRITICAL |
| 25 | SMTP | 🟡 MEDIUM |
| 53 | DNS | 🟡 MEDIUM |
| 80 | HTTP | 🟡 MEDIUM |
| 110 | POP3 | 🟠 HIGH |
| 135 | RPC | 🟠 HIGH |
| 139 | NetBIOS | 🟠 HIGH |
| 143 | IMAP | 🟡 MEDIUM |
| 443 | HTTPS | 🟢 LOW |
| 445 | SMB | 🔴 CRITICAL |
| 1433 | MSSQL | 🟠 HIGH |
| 3306 | MySQL | 🟠 HIGH |
| 3389 | RDP | 🔴 CRITICAL |
| 5432 | PostgreSQL | 🟠 HIGH |
| 5900 | VNC | 🔴 CRITICAL |
| 6379 | Redis | 🔴 CRITICAL |
| 8080 | HTTP-Alt | 🟡 MEDIUM |
| 27017 | MongoDB | 🔴 CRITICAL |

---

## 📁 Project Structure

```
network-security-scanner/
├── scanner.py          # Main scanner script
├── requirements.txt    # Python dependencies
├── README.md           # Project documentation
├── sample_report.pdf   # Sample output report
└── sample_results.json # Sample JSON output
```

---

## 🧠 Skills Demonstrated

- **Network Security** — Port scanning, service enumeration, banner grabbing
- **Python Development** — OOP, multi-threading, file I/O, error handling
- **Security Assessment** — Risk classification, vulnerability analysis, report writing
- **Technical Documentation** — Professional report generation, JSON data export
- **Ethical Hacking Concepts** — Responsible disclosure, legal compliance

---

## 🔮 Future Improvements

- [ ] Add OS fingerprinting
- [ ] Add CVE lookup for identified services
- [ ] Add email delivery of reports
- [ ] Add HTML report format
- [ ] Add custom port range support
- [ ] Integrate with Shodan API for extended recon

---

## 👩‍💻 Author

**Riddhi Patel**
BTech Information Technology — Kwantlen Polytechnic University
📧 riddhi.patel@student.kpu.ca
🔗 github.com/Riddhi-Patel-sys
