#!/usr/bin/env python3
"""
Network Security Scanner & Report Generator
Author: Riddhi Patel
GitHub: github.com/Riddhi-Patel-sys
Description: Scans a target host for open ports, identifies services,
             assesses risk levels, and generates a professional PDF security report.
"""

import socket
import datetime
import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Port definitions with service names and risk levels ──
PORT_INFO = {
    21:   {"service": "FTP",           "risk": "HIGH",   "reason": "Unencrypted file transfer — credentials exposed in plaintext"},
    22:   {"service": "SSH",           "risk": "MEDIUM", "reason": "Secure shell — ensure strong passwords and key-based auth"},
    23:   {"service": "Telnet",        "risk": "CRITICAL","reason": "Unencrypted remote access — immediately replace with SSH"},
    25:   {"service": "SMTP",          "risk": "MEDIUM", "reason": "Mail server — could be exploited for spam relay if misconfigured"},
    53:   {"service": "DNS",           "risk": "MEDIUM", "reason": "DNS service — ensure zone transfer is restricted"},
    80:   {"service": "HTTP",          "risk": "MEDIUM", "reason": "Unencrypted web server — sensitive data exposed without HTTPS"},
    110:  {"service": "POP3",          "risk": "HIGH",   "reason": "Unencrypted email retrieval — credentials sent in plaintext"},
    135:  {"service": "RPC",           "risk": "HIGH",   "reason": "Windows RPC — common attack vector, restrict access"},
    139:  {"service": "NetBIOS",       "risk": "HIGH",   "reason": "NetBIOS — information disclosure and lateral movement risk"},
    143:  {"service": "IMAP",          "risk": "MEDIUM", "reason": "Email protocol — use IMAPS (993) for encrypted access"},
    443:  {"service": "HTTPS",         "risk": "LOW",    "reason": "Encrypted web server — ensure TLS certificate is valid"},
    445:  {"service": "SMB",           "risk": "CRITICAL","reason": "SMB — high risk of exploitation (WannaCry, EternalBlue)"},
    1433: {"service": "MSSQL",         "risk": "HIGH",   "reason": "SQL Server exposed — restrict to internal networks only"},
    3306: {"service": "MySQL",         "risk": "HIGH",   "reason": "MySQL exposed — database should not be publicly accessible"},
    3389: {"service": "RDP",           "risk": "CRITICAL","reason": "Remote Desktop — frequent brute force target, restrict access"},
    5432: {"service": "PostgreSQL",    "risk": "HIGH",   "reason": "Database exposed — should be restricted to internal access only"},
    5900: {"service": "VNC",           "risk": "CRITICAL","reason": "VNC remote access — often unencrypted and weakly authenticated"},
    6379: {"service": "Redis",         "risk": "CRITICAL","reason": "Redis — commonly misconfigured with no authentication"},
    8080: {"service": "HTTP-Alt",      "risk": "MEDIUM", "reason": "Alternate HTTP port — often used for admin panels"},
    8443: {"service": "HTTPS-Alt",     "risk": "LOW",    "reason": "Alternate HTTPS — verify certificate validity"},
    27017:{"service": "MongoDB",       "risk": "CRITICAL","reason": "MongoDB — frequently exposed with no authentication enabled"},
}

RISK_COLORS = {
    "CRITICAL": (0.8, 0.1, 0.1),
    "HIGH":     (0.9, 0.4, 0.0),
    "MEDIUM":   (0.9, 0.7, 0.0),
    "LOW":      (0.2, 0.6, 0.2),
    "INFO":     (0.3, 0.5, 0.8),
}

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

def scan_port(host, port, timeout=1.0):
    """Attempt to connect to a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port, result == 0
    except Exception:
        return port, False

def grab_banner(host, port, timeout=2.0):
    """Try to grab a service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if port in [80, 8080]:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner[:100] if banner else "No banner"
    except Exception:
        return "Unable to retrieve banner"

def resolve_host(host):
    """Resolve hostname to IP."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None

def scan_target(host, ports=None, timeout=1.0):
    """Scan target host for open ports using threading."""
    if ports is None:
        ports = list(PORT_INFO.keys())

    ip = resolve_host(host)
    if not ip:
        print(f"[ERROR] Cannot resolve host: {host}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  Network Security Scanner")
    print(f"  Target : {host} ({ip})")
    print(f"  Ports  : {len(ports)} ports")
    print(f"  Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    open_ports = []
    print(f"[*] Scanning {len(ports)} ports...")

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                info = PORT_INFO.get(port, {"service": "Unknown", "risk": "INFO", "reason": "Unknown service"})
                banner = grab_banner(ip, port)
                result = {
                    "port":    port,
                    "service": info["service"],
                    "risk":    info["risk"],
                    "reason":  info["reason"],
                    "banner":  banner,
                    "state":   "OPEN"
                }
                open_ports.append(result)
                risk = info["risk"]
                print(f"  [OPEN] Port {port:5d} | {info['service']:12s} | Risk: {risk}")

    open_ports.sort(key=lambda x: RISK_ORDER.get(x["risk"], 4))

    if not open_ports:
        print("\n  [*] No open ports found in the scanned range.")
    else:
        print(f"\n  [*] Scan complete. Found {len(open_ports)} open port(s).")

    return {
        "host":       host,
        "ip":         ip,
        "scan_time":  datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "open_ports": open_ports,
        "total_open": len(open_ports),
        "risk_summary": {
            "CRITICAL": len([p for p in open_ports if p["risk"] == "CRITICAL"]),
            "HIGH":     len([p for p in open_ports if p["risk"] == "HIGH"]),
            "MEDIUM":   len([p for p in open_ports if p["risk"] == "MEDIUM"]),
            "LOW":      len([p for p in open_ports if p["risk"] == "LOW"]),
        }
    }

def generate_report(scan_data, output_file="security_report.pdf"):
    """Generate a professional PDF security report."""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    HRFlowable, Table, TableStyle)
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

    DARK  = colors.HexColor('#1A3A5C')
    BLUE  = colors.HexColor('#1F6FAA')
    GRAY  = colors.HexColor('#555555')
    LGRAY = colors.HexColor('#F5F5F5')
    WHITE = colors.white

    RISK_PDF = {
        "CRITICAL": colors.HexColor('#CC1A1A'),
        "HIGH":     colors.HexColor('#E56A00'),
        "MEDIUM":   colors.HexColor('#E5B800'),
        "LOW":      colors.HexColor('#2E8B2E'),
        "INFO":     colors.HexColor('#4A80CC'),
    }

    doc = SimpleDocTemplate(output_file, pagesize=letter,
                            topMargin=0.75*inch, bottomMargin=0.75*inch,
                            leftMargin=0.85*inch, rightMargin=0.85*inch)
    story = []

    def S(name, **kw): return ParagraphStyle(name, **kw)

    title_s  = S('t', fontName='Helvetica-Bold', fontSize=22, textColor=DARK,   alignment=TA_CENTER, spaceAfter=4)
    sub_s    = S('s', fontName='Helvetica',      fontSize=10, textColor=GRAY,   alignment=TA_CENTER, spaceAfter=4)
    sec_s    = S('h', fontName='Helvetica-Bold', fontSize=12, textColor=BLUE,   spaceBefore=14, spaceAfter=4)
    bod_s    = S('b', fontName='Helvetica',      fontSize=10, textColor=GRAY,   leading=15, spaceAfter=6, alignment=TA_JUSTIFY)
    sm_s     = S('m', fontName='Helvetica',      fontSize=9,  textColor=GRAY,   leading=13, spaceAfter=4)
    bold_s   = S('bl',fontName='Helvetica-Bold', fontSize=10, textColor=colors.black, spaceAfter=4)

    def HR(color=BLUE, thick=1.5): return HRFlowable(width="100%", thickness=thick, color=color, spaceAfter=6)
    def section(t): return [Paragraph(t, sec_s), HR()]

    # ── HEADER ──
    story += [
        Paragraph("Network Security Assessment Report", title_s),
        Paragraph(f"Generated by Network Security Scanner  |  github.com/Riddhi-Patel-sys", sub_s),
        HR(DARK, 2.5),
        Spacer(1, 6),
    ]

    # ── SCAN SUMMARY TABLE ──
    story += section("1. Scan Summary")
    rs = scan_data["risk_summary"]
    summary_data = [
        ["Field", "Details"],
        ["Target Host",    scan_data["host"]],
        ["Resolved IP",    scan_data["ip"]],
        ["Scan Date/Time", scan_data["scan_time"]],
        ["Total Open Ports", str(scan_data["total_open"])],
        ["Critical Findings", str(rs["CRITICAL"])],
        ["High Findings",    str(rs["HIGH"])],
        ["Medium Findings",  str(rs["MEDIUM"])],
        ["Low Findings",     str(rs["LOW"])],
    ]
    summary_table = Table(summary_data, colWidths=[2.2*inch, 4.8*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (-1,0),  DARK),
        ('TEXTCOLOR',    (0,0), (-1,0),  WHITE),
        ('FONTNAME',     (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',     (0,0), (-1,-1), 10),
        ('BACKGROUND',   (0,1), (0,-1),  LGRAY),
        ('FONTNAME',     (0,1), (0,-1),  'Helvetica-Bold'),
        ('ROWBACKGROUNDS',(1,1),(-1,-1), [WHITE, colors.HexColor('#F0F5FA')]),
        ('GRID',         (0,0), (-1,-1), 0.5, colors.HexColor('#CCCCCC')),
        ('PADDING',      (0,0), (-1,-1), 6),
        ('VALIGN',       (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story += [summary_table, Spacer(1, 12)]

    # ── RISK OVERVIEW ──
    story += section("2. Risk Overview")

    # Risk score calculation
    risk_score = (rs["CRITICAL"]*40 + rs["HIGH"]*20 + rs["MEDIUM"]*10 + rs["LOW"]*2)
    if risk_score == 0:
        overall = "SECURE"; overall_color = RISK_PDF["LOW"]
    elif risk_score <= 20:
        overall = "LOW RISK"; overall_color = RISK_PDF["LOW"]
    elif risk_score <= 50:
        overall = "MEDIUM RISK"; overall_color = RISK_PDF["MEDIUM"]
    elif risk_score <= 100:
        overall = "HIGH RISK"; overall_color = RISK_PDF["HIGH"]
    else:
        overall = "CRITICAL RISK"; overall_color = RISK_PDF["CRITICAL"]

    risk_data = [
        ["Risk Level", "Count", "Description"],
        ["CRITICAL", str(rs["CRITICAL"]), "Immediate action required — severe vulnerability"],
        ["HIGH",     str(rs["HIGH"]),     "Urgent remediation needed — significant exposure"],
        ["MEDIUM",   str(rs["MEDIUM"]),   "Should be addressed — moderate risk exposure"],
        ["LOW",      str(rs["LOW"]),      "Minor risk — monitor and review periodically"],
    ]
    risk_colors_map = [RISK_PDF["CRITICAL"], RISK_PDF["HIGH"], RISK_PDF["MEDIUM"], RISK_PDF["LOW"]]
    risk_table = Table(risk_data, colWidths=[1.5*inch, 1.0*inch, 4.5*inch])
    style = [
        ('BACKGROUND',  (0,0), (-1,0),  DARK),
        ('TEXTCOLOR',   (0,0), (-1,0),  WHITE),
        ('FONTNAME',    (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',    (0,0), (-1,-1), 10),
        ('GRID',        (0,0), (-1,-1), 0.5, colors.HexColor('#CCCCCC')),
        ('PADDING',     (0,0), (-1,-1), 6),
        ('VALIGN',      (0,0), (-1,-1), 'MIDDLE'),
        ('ALIGN',       (1,0), (1,-1),  'CENTER'),
    ]
    for i, c in enumerate(risk_colors_map):
        style.append(('TEXTCOLOR', (0, i+1), (0, i+1), c))
        style.append(('FONTNAME',  (0, i+1), (0, i+1), 'Helvetica-Bold'))
        bg = WHITE if i % 2 == 0 else colors.HexColor('#F0F5FA')
        style.append(('BACKGROUND', (1, i+1), (-1, i+1), bg))
    risk_table.setStyle(TableStyle(style))
    story += [risk_table, Spacer(1, 8)]

    overall_data = [["Overall Risk Assessment", overall]]
    ov_table = Table(overall_data, colWidths=[5.0*inch, 2.0*inch])
    ov_table.setStyle(TableStyle([
        ('BACKGROUND',  (0,0), (0,0),  DARK),
        ('BACKGROUND',  (1,0), (1,0),  overall_color),
        ('TEXTCOLOR',   (0,0), (-1,-1),WHITE),
        ('FONTNAME',    (0,0), (-1,-1),'Helvetica-Bold'),
        ('FONTSIZE',    (0,0), (-1,-1),11),
        ('ALIGN',       (0,0), (-1,-1),'CENTER'),
        ('PADDING',     (0,0), (-1,-1),8),
    ]))
    story += [ov_table, Spacer(1, 12)]

    # ── FINDINGS ──
    story += section("3. Detailed Findings")

    if not scan_data["open_ports"]:
        story.append(Paragraph("No open ports were discovered during this scan.", bod_s))
    else:
        findings_data = [["Port", "Service", "Risk Level", "Banner / Details"]]
        for p in scan_data["open_ports"]:
            banner_short = p["banner"][:45] + "..." if len(p["banner"]) > 45 else p["banner"]
            findings_data.append([
                str(p["port"]),
                p["service"],
                p["risk"],
                banner_short
            ])

        f_style = [
            ('BACKGROUND',  (0,0), (-1,0),  DARK),
            ('TEXTCOLOR',   (0,0), (-1,0),  WHITE),
            ('FONTNAME',    (0,0), (-1,0),  'Helvetica-Bold'),
            ('FONTSIZE',    (0,0), (-1,-1), 9),
            ('GRID',        (0,0), (-1,-1), 0.5, colors.HexColor('#CCCCCC')),
            ('PADDING',     (0,0), (-1,-1), 5),
            ('VALIGN',      (0,0), (-1,-1), 'MIDDLE'),
        ]
        for i, p in enumerate(scan_data["open_ports"]):
            rc = RISK_PDF.get(p["risk"], GRAY)
            f_style.append(('TEXTCOLOR', (2, i+1), (2, i+1), rc))
            f_style.append(('FONTNAME',  (2, i+1), (2, i+1), 'Helvetica-Bold'))
            bg = WHITE if i % 2 == 0 else colors.HexColor('#F0F5FA')
            f_style.append(('BACKGROUND', (0, i+1), (1, i+1), bg))
            f_style.append(('BACKGROUND', (3, i+1), (3, i+1), bg))

        f_table = Table(findings_data, colWidths=[0.7*inch, 1.2*inch, 1.1*inch, 4.0*inch])
        f_table.setStyle(TableStyle(f_style))
        story += [f_table, Spacer(1, 12)]

    # ── RECOMMENDATIONS ──
    story += section("4. Recommendations")

    if scan_data["open_ports"]:
        for p in scan_data["open_ports"]:
            rec_data = [[
                Paragraph(f"Port {p['port']} — {p['service']}", bold_s),
                Paragraph(p["risk"], S('rk', fontName='Helvetica-Bold', fontSize=10,
                                       textColor=RISK_PDF.get(p["risk"], GRAY)))
            ]]
            rec_t = Table(rec_data, colWidths=[5.5*inch, 1.5*inch])
            rec_t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), LGRAY),
                ('PADDING',    (0,0), (-1,-1), 5),
                ('ALIGN',      (1,0), (1,0),   'RIGHT'),
            ]))
            story += [
                rec_t,
                Paragraph(f"⚠ {p['reason']}", sm_s),
                Spacer(1, 6),
            ]
    else:
        story.append(Paragraph("No vulnerabilities detected. Continue monitoring regularly.", bod_s))

    # ── METHODOLOGY ──
    story += section("5. Methodology")
    story.append(Paragraph(
        "This assessment was conducted using a custom Python-based network security scanner. "
        "The tool performs TCP connect scanning across a defined set of commonly exploited ports, "
        "attempts banner grabbing to identify service versions, and cross-references findings against "
        "a curated vulnerability database to assign risk severity levels (Critical, High, Medium, Low). "
        "All testing was performed in a controlled, isolated lab environment. No exploitation was attempted.",
        bod_s))

    # ── DISCLAIMER ──
    story += [HR(), Paragraph(
        "DISCLAIMER: This report is generated for educational and authorized security assessment purposes only. "
        "Unauthorized scanning of systems you do not own is illegal. Always obtain written permission before "
        "conducting any security assessment.",
        S('disc', fontName='Helvetica-Oblique', fontSize=8, textColor=GRAY, alignment=TA_CENTER)
    )]

    doc.build(story)
    print(f"\n  [✓] Report saved: {output_file}")
    return output_file

def save_json(scan_data, output_file="scan_results.json"):
    """Save scan results as JSON."""
    with open(output_file, 'w') as f:
        json.dump(scan_data, f, indent=2)
    print(f"  [✓] JSON saved: {output_file}")

if __name__ == "__main__":
    # ── Default: scan localhost for demo ──
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    output = sys.argv[2] if len(sys.argv) > 2 else "security_report.pdf"

    print("\n  ⚠  IMPORTANT: Only scan systems you own or have written permission to scan.")
    print("     Unauthorized scanning is illegal.\n")

    results = scan_target(target)
    generate_report(results, output)
    save_json(results, output.replace(".pdf", ".json"))

    print(f"\n{'='*60}")
    print(f"  Scan Complete!")
    print(f"  Report : {output}")
    print(f"  JSON   : {output.replace('.pdf', '.json')}")
    print(f"{'='*60}\n")
