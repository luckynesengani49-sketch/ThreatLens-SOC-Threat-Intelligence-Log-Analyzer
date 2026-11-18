import re
from collections import Counter
from datetime import datetime
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="ThreatLens SOC Backend")


class IOCRequest(BaseModel):
    ioc: str


# 1. IP / Domain Reputation Lookup Endpoint
@app.post("/api/lookup")
def lookup_ioc(payload: IOCRequest):
    ioc = payload.ioc.strip()

    # Simulated Threat Intel responses for portfolio demo (ready for VirusTotal/AbuseIPDB API keys)
    if ioc in ["185.220.101.4", "suspicious-domain.com"] or ioc.startswith("185.220."):
        return {
            "metrics": {
                "risk_score": 92,
                "risk_label": "Critical Threat",
                "total_events": 148,
                "failed_logins": 134,
                "malicious_ips": 1,
            },
            "intel": {
                "isp": "Telkom SA (AS37457)",
                "country": "South Africa (SA)",
                "abuse_confidence": "100% (Reported 1,420 times)",
                "vt_detections": "16 / 94 Security Vendors Flagged",
                "mitre_attack": "T1110 - Brute Force / T1090.003 - Multi-hop Proxy",
            },
            "timeline": {
                "labels": ["01:00", "02:00", "03:00", "04:00", "05:00", "06:00"],
                "counts": [0, 12, 34, 56, 23, 18]
            },
            "events": [
                {
                    "timestamp": "2026-11-17 03:14:22",
                    "source_ip": ioc,
                    "event_type": "SSH Failed Password",
                    "target": "root",
                    "severity": "Critical",
                },
                {
                    "timestamp": "2026-11-17 03:14:25",
                    "source_ip": ioc,
                    "event_type": "SSH Invalid User",
                    "target": "admin",
                    "severity": "High",
                },
            ],
        }

    # Clean / Low-Risk IOC Response
    return {
        "metrics": {
            "risk_score": 5,
            "risk_label": "Low Risk / Clean",
            "total_events": 12,
            "failed_logins": 0,
            "malicious_ips": 0,
        },
        "intel": {
            "isp": "MTN SA (AS16637)" if ioc == "8.8.8.8" else "Cloudflare / Verified ASN",
            "country": "South Africa (SA)" if ioc == "8.8.8.8" else "Unknown",
            "abuse_confidence": "0% (Clean)",
            "vt_detections": "0 / 94 Security Vendors Flagged",
            "mitre_attack": "None Detected",
        },
        "timeline": {
            "labels": ["01:00", "02:00", "03:00", "04:00", "05:00", "06:00"],
            "counts": [0, 0, 0, 0, 0, 0]
        },
        "events": [],
    }


# Helper function to parse SSH / Web log lines with Regex
def parse_log_content(content: str):
    lines = content.splitlines()
    events = []
    ip_counter = Counter()
    hour_counter = Counter()
    failed_count = 0

    # Matches common SSH failed login lines & IPv4 addresses
    ssh_pattern = re.compile(
        r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}).*?(Failed password|Invalid user|401|403).*?(?:for\s+(?:invalid user\s+)?(?P<user>\S+))?.*?from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    )
    generic_ip_pattern = re.compile(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")

    for line in lines:
        match = ssh_pattern.search(line)
        if match:
            failed_count += 1
            ip = match.group("ip")
            ts = match.group("timestamp")
            user = match.group("user") or "unknown"
            ip_counter[ip] += 1

            hour_match = re.search(r"(\d{2}):\d{2}:\d{2}", ts)
            if hour_match:
                hour_counter[f"{hour_match.group(1)}:00"] += 1

            events.append({
                "timestamp": ts,
                "source_ip": ip,
                "event_type": "Failed Authentication",
                "target": user,
                "severity": "High" if ip_counter[ip] >= 3 else "Medium",
            })
        elif "404" in line or "500" in line or "error" in line.lower():
            ip_m = generic_ip_pattern.search(line)
            if ip_m:
                ip = ip_m.group("ip")
                ip_counter[ip] += 1
                events.append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": ip,
                    "event_type": "HTTP Anomaly / Probe",
                    "target": "/admin",
                    "severity": "Medium",
                })

    flagged_ips = [ip for ip, count in ip_counter.items() if count >= 2]
    top_ip = ip_counter.most_common(1)[0][0] if ip_counter else "N/A"
    risk_score = min(100, failed_count * 12 + len(flagged_ips) * 15)
    risk_label = "Critical Threat" if risk_score >= 70 else "Elevated Risk" if risk_score >= 30 else "Normal"

    sorted_hours = sorted(hour_counter.keys()) or ["00:00", "01:00", "02:00"]
    hour_counts = [hour_counter[h] for h in sorted_hours] or [0, 0, 0]

    return {
        "metrics": {
            "risk_score": risk_score,
            "risk_label": risk_label,
            "total_events": len(lines),
            "failed_logins": failed_count,
            "malicious_ips": len(flagged_ips),
        },
        "intel": {
            "isp": f"Top Offender: {top_ip}",
            "country": "Multiple / External ASN",
            "abuse_confidence": f"{min(100, failed_count * 15)}% Behavioral Confidence",
            "vt_detections": f"{len(flagged_ips)} Suspicious IPs Extracted",
            "mitre_attack": "T1110.001 - Password Guessing" if failed_count > 0 else "None",
        },
        "timeline": {
            "labels": sorted_hours,
            "counts": hour_counts,
        },
        "events": events[:50],  # Return top 50 events
    }


# 2. Upload Log File Endpoint
@app.post("/api/analyze-log")
async def analyze_log(logfile: UploadFile = File(...)):
    if not logfile.filename.endswith((".log", ".txt", ".csv")):
        raise HTTPException(status_code=400, detail="Invalid file type. Upload .log, .txt, or .csv")

    raw_bytes = await logfile.read()
    content = raw_bytes.decode("utf-8", errors="ignore")
    return parse_log_content(content)


# 3. Sample SSH Brute-Force Log Endpoint
@app.get("/api/sample-log")
def get_sample_log():
    sample_auth_log = """Nov 17 02:11:04 prod-srv sshd[4102]: Failed password for invalid user admin from 185.220.101.4 port 51234 ssh2
    Nov 17 02:11:07 prod-srv sshd[4102]: Failed password for invalid user root from 185.220.101.4 port 51238 ssh2
    Nov 17 02:11:10 prod-srv sshd[4105]: Failed password for root from 185.220.101.4 port 51242 ssh2
    Nov 17 03:22:15 prod-srv sshd[4180]: Failed password for invalid user ubuntu from 45.155.205.93 port 39812 ssh2
    Nov 17 03:22:19 prod-srv sshd[4180]: Failed password for invalid user deploy from 45.155.205.93 port 39815 ssh2
    Nov 17 04:05:44 prod-srv sshd[4291]: Failed password for root from 185.220.101.4 port 60112 ssh2
    Nov 17 04:05:48 prod-srv sshd[4291]: Failed password for invalid user oracle from 185.220.101.4 port 60119 ssh2"""
    return parse_log_content(sample_auth_log)


# 4. Serve Frontend Static Files
app.mount("/", StaticFiles(directory="Website", html=True), name="website")


# Run the FastAPI app with Uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)