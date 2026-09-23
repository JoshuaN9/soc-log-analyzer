# SOC Log Analyzer
A Python-based cybersecurity tool that analyzes authentication logs to identify suspicious login activity and potential brute-force attacks.

# Features
* Parses authentication logs
* Detects failed and successful logins
* Identifies suspicious IP addresses
* Detects targeted usernames
* Analyzes operating systems
* Detects potential brute-force activity
* Assigns severity levels
* Generates CSV security reports

# Detection Logic
Potential brute-force activity is flagged when an IP generates **5 or more failed login attempts within 60 seconds**.

| Attempts | Severity |
| -------: | -------- |
|      1–4 | LOW      |
|      5–9 | MEDIUM   |
|    10–19 | HIGH     |
|      20+ | CRITICAL |

# Log Format

```text
DATE TIME STATUS IP USERNAME OS
```

Example:

```text
2026-09-05 10:15:00 FAILED 10.10.10.50 admin Kali_Linux
```

The project includes **300 synthetic log entries** for testing.

# Project Structure
```text
soc-log-analyzer/
├── analyzer.py
├── README.md
├── logs/
│   └── sample.log
└── reports/
    └── security_report.csv
```

# Installation

```bash
git clone https://github.com/JoshuaN9/soc-log-analyzer.git
cd soc-log-analyzer
python -m venv venv
```

# Windows

```powershell
.\venv\Scripts\Activate.ps1
python analyzer.py
```

Analyze a specific log:

```powershell
python analyzer.py -f logs/sample.log
```

# Technologies
**Python 3 • Log Analysis • Threat Detection • SOC Operations • Security Automation**

# Disclaimer
This project is for educational and authorized security testing purposes. All included logs are synthetic.