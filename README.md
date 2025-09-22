# 🕵️‍♂️ Network Anomaly Detector for Windows

A lightweight, Python-based tool to remotely scan multiple Windows machines over the network, fetch security event logs via WinRM, analyze them for known malicious behavior patterns (Event IDs), and store results in a central SQLite database.

> 🚨 This is a Blue Team tool for threat detection and privilege misuse correlation across a Windows environment.

---

## 🚀 Features

✅ Remotely fetches Windows **Security logs**  
✅ Detects anomalies using known **high-risk Windows Event IDs**  
✅ Maps anomalies to **risk levels** (High, Medium, Low, No Risk)  
✅ Stores results in a centralized **SQLite database**  
✅ Works across **multiple hosts** (via `config.yaml`)  
✅ Automatically **installs missing Python libraries**  
✅ Extensible for SIEMs, dashboards, and alerts

---

## 🧱 Architecture Overview

+----------------------+ +---------------------+
| config.yaml |-----> | Multiple Windows PCs|
+----------------------+ +---------------------+
|
v
+--------------------+
| detector.py |
| (via WinRM) |
+--------------------+
|
v
+--------------------+
| db.sqlite (logs) |
+--------------------+


---

## 📦 Requirements

- Python 3.7+
- Remote Windows machines with:
  - **WinRM enabled** (use `Enable-PSRemoting -Force`)
  - Administrator access

---

## 🔧 Installation

1. **Clone this repository:**

```bash
git clone https://github.com/jeffmes3/win_anomaly_detector.git
cd win_anomaly_detector

2. Optional) Create a virtual environment:
python -m venv venv
venv\Scripts\activate  # Windows

3.Run the script:
python detector.py

4.Configuration
Edit the config.yaml file to define which hosts to scan:
hosts:
  - name: workstation01
    ip: 192.168.1.101
    username: Administrator
    password: YourPassword123

  - name: workstation02
    ip: 192.168.1.102
    username: Administrator
    password: YourPassword123

5. Detected Event IDs
The following Windows Event IDs are analyzed and scored:
Event ID	Description	Risk Level
1102	Security log cleared	High
4624	Successful login	Low
4625	Failed login	Medium
4688	Process creation	High
4720	User account created	High
4724	Password reset attempt	High
4739	Domain policy changed	High
4946	Firewall rule added	High
4948	Firewall rule deleted	High
...	and more...

you can update or extend these in win_anomoly_detector.py → EVENT_THREAT_SCORES.

6.Database: db.sqlite
After scanning, all findings are saved to db.sqlite
You can view the data with:
sqlite3 db.sqlite
SELECT * FROM events WHERE risk_level = 'High' ORDER BY timestamp DESC;

7. network-anomaly-detector/
├── config.yaml           # Host configuration
├── detector.py           # Main script
├── db.sqlite             # Auto-generated database
├── models/
│   └── schema.sql        # Database schema
└── README.md             # You're reading this!


Your Name
📧 jeffreymisquita@gmail.com

🐙 GitHub: jeffmes3

License

This project is licensed under the MIT License
For educational and ethical security research only. Do not use this tool for unauthorized access.

License

This project is licensed under the MIT License
.

For educational and ethical security research only. Do not use this tool for unauthorized access.


---

## ✅ How to Use It

- Save the file as `README.md` in your GitHub repo root.
- Replace placeholders:
  - `YourPassword123`
  - `your-username`
  - `your.email@example.com`
- (Optional) Add `LICENSE` if you plan to open source

---

## ✅ Want Me to Generate the GitHub Repo Files?

I can provide a zip/`tree` layout or even a `gh repo create` command example for you — just let me know.

Also available:
- Prebuilt `requirements.txt`
- PyInstaller `.exe` builder config
- Dashboard UI starter (Flask/Streamlit)





