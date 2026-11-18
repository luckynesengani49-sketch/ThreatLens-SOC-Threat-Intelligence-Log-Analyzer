# ThreatLens: SOC Threat Intelligence & Log Analyzer

A web based dashboard that analyzes SSH and web server logs and looks up IP/domain reputation. Built as a portfolio project to demonstrate core SOC analyst skills: log analysis, indicator-of compromise (IOC), triage, risk scoring and MITRE ATT&CK mapping.

![ThreatLens dashboard](docs/screenshots/dashboard.png)

> **Note:** Threat intelligence data in this version is **simulated** for demonstration. The lookup endpoint is structured so real VirusTotal and AbuseIPDB API calls can be added (see [Roadmap](#roadmap)). Log parsing and risk scoring are fully functional.

## Features

- **IOC reputation lookup:** enter an IP or domain and get a risk score, ISP/ASN, country, abuse confidence, vendor detections and a MITRE ATT&CK mapping
- **Log parser:** upload `.log`, `.txt` or `.csv` files (SSH `auth.log`, web server logs) and detect failed logins, invalid users and HTTP anomalies
- **Risk scoring:** automatic classification as Normal, Elevated Risk or Critical Threat
- **Timeline chart:** failed logins/anomalies per hour, drawn with Chart.js
- **Flagged events table:** timestamp, source IP, event type, target user and severity
- **CSV export:** download flagged events as a report
- **Built-in samples:** one-click demo with a clean IP, a malicious IP and a sample SSH brute-force log

## Tech Stack

| Layer         | Technology                       |
|---------------|----------------------------------
| Backend       | Python 3, FastAPI, Uvicorn, Regex 
| Frontend      | HTML5, CSS3 (Grid/Flexbox), vanilla JavaScript 
| Visualization | Chart.js 

## Project Structure

```
threatlens/
├── main.py              
├── requirements.txt
├── README.md
├── docs/
│   └── screenshots/
└── Website/
    ├── index.html       # Dashboard UI
    ├── app.js           # This is frontend logic, API calls, chart and table rendering
    └── style.css        # I used Hack the box theme
```

## Getting Started

### Prerequisites
```
- Python 3.9 or newer
- pip
```

### Installation

```bash
git clone https://github.com/luckynesengani49-sketch/threatlens.git  #Use this link to download my full Repo copy
cd threatlens

python -m venv venv   #This creates a virtual environment, a private, empty Python workspace inside the project in a folder named venv
source venv/bin/activate       #Run it on Mac or Linux

This command is for windows powershell
venv\Scripts\activate    # Run it on windows
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned  # Run this 1st if venv\Scripts\activate give you error

pip install -r requirements.txt
```

### Run
>1. The packages are installed in the Python that VS Code uses.
Open the terminal in VS Code and run, On the `terminal` of idea like vsCode run this command
```
pip install -r requirements.txt
```



>2. You open the whole project folder in VS Code.
Use File  Open Folder and choose the folder that contains main.py and Website/. Don’t open just the single file. Your code has directory="Website", which is a relative path, so it only works when the program runs from the folder that contains Website. If you open only a file, or run from a different folder, the server may crash with “Directory ‘Website’ does not exist”.

>3. You open the browser yourself.
Clicking the Run button ▶ in VS Code starts the server, but it doesn’t open the page. Once the terminal shows Uvicorn running on http://127.0.0.1:8000, go to http://127.0.0.1:8000 in your browser. Keep the terminal running while you use the site. Press Ctrl+C to stop it.

Do not open index.html directly. The page must be served by FastAPI so the api requests reach the backend.

## Usage

1. Quick demo   : Click Malicious IP or Load Sample SSH Brute-Force Log
2. Lookup       : Type an IP or domain into the lookup box and click Scan Indicator
3. Your own logs: Choose a .log, .txt or .csv file and click Analyze Logs
4. Report       : Click Export Report (CSV) to download the flagged events

## API Endpoints

| Method | Endpoint           | Description 
|--------|--------------------|----------------------------------------------------------------------
|  POST  | /api/lookup        | Reputation lookup for an IP or domain. Body: `{"ioc": "185.220.101.4"}
|  POST  | /api/analyze-log   | Upload a log file (multipart form field `logfile`) and receive analysis
|  GET   | /api/sample-log    | Analyze a built in sample SSH brute force log


## How Detection Works

1. Each log line is matched against a regex for failed SSH authentication (Failed password, Invalid user) and extracts the timestamp, username and source IP
2. Web log lines containing `404`, `500` or `error` are flagged as HTTP anomalies or probes
3. Attempts are counted per source IP. IPs with **2 or more** flagged events are marked as suspicious
4. Events from an IP with 3 or more failures are rated **High** severity, otherwise **Medium**
5. The risk score is calculated as:


   risk_score = min(100, failed_logins × 12 + suspicious_ips × 15)

   - **70 and above:** Critical Threat
   - **30 to 69:** Elevated Risk
   - **Below 30:** Normal

6. Failed attempts are grouped by hour to build the timeline chart.

### MITRE ATT&CK Mapping

| Technique                                       | Detected when                         |
|-------------------------------------------------|----------------------------------------
| T1110.001: Password Guessing                    | Failed authentication attempts found in a log 
| T1110: Brute Force / T1090.003: Multi-hop Proxy | Known Tor exit node IP in the sample lookup 

## Security Considerations

- Upload validation: only `.log`, `.txt` and `.csv` files are accepted
- XSS-safe rendering: the events table is built with `textContent`, never `innerHTML`
- CSV export escapes quotes in fields
- Only the first 50 events are returned per analysis to limit response size

## Limitations

- Threat intelligence responses are simulated, not live
- Regex parsing targets common SSH `auth.log` and generic web log formats; other formats may not match
- No authentication, rate limiting or upload size limit yet, so it is intended for local demo use, not public deployment as-is

## Roadmap

-  Integrate the VirusTotal and AbuseIPDB APIs, with keys loaded from environment variables
-  Add rate limiting and a maximum upload size
-  Support more log formats (Apache/Nginx combined, Windows Event logs)
-  Add brute-force detection by time window (for example, 5+ failures within 60 seconds)
-  Add unit tests for the log parser
-  Deploy a live demo


## What I Learned

Replace this section with your own words. Cover things like writing regex for log parsing, how brute-force attacks appear in `auth.log`, mapping activity to MITRE ATT&CK, and building a REST API with FastAPI.


## Author
Nesengani L. Letswalo, Aspiring Cybersecurity Analyst

- GitHub  : luckynesengani49-sketch (https://github.com/luckynesengani49-sketch)
- LinkedIn: Nesengani L. Letswalo (https://www.linkedin.com/in/nesengani-l-letswalo-577440385)



## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.


