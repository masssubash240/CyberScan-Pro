# CyberScan-Pro
# 🔍 CyberScan Pro – Network Security Scanner

**For Educational & Authorized Use Only**

CyberScan Pro is a Python-based network scanner with a graphical interface (Tkinter).  
It performs host discovery (ping sweep) and port scanning on IPv4 networks, presenting results in a clean, color-coded table.

![Demo Screenshot](screenshots/demo.png)

## ✨ Features
- Host discovery using ICMP ping (cross-platform)
- Port scanning on single IPs, ranges (e.g. `192.168.1.1-192.168.1.254`), or CIDR (`192.168.1.0/24`)
- Common ports preset + custom port ranges (e.g. `80,443,1000-2000`)
- Multi‑threaded scanning for performance
- Real‑time output console and status bar
- Export results to CSV or TXT
- Clear ethical disclaimer built into the UI

## ⚠️ Legal & Ethical Warning
This tool is **only** for:
- Scanning your own networks
- Authorized penetration testing (written permission)
- Educational cybersecurity exercises

**Unauthorized scanning is illegal** in many jurisdictions.  
The author assumes no liability for misuse.

## 🧰 Requirements
- Python 3.7+
- Standard library only (no pip install needed)
- On Linux: `sudo apt-get install python3-tk` (if Tkinter missing)

## 🚀 Installation & Usage

```bash
# Clone the repository
git clone https://github.com/your-username/CyberScan-Pro.git
cd CyberScan-Pro

# Run the scanner
python cyber_scan.py
