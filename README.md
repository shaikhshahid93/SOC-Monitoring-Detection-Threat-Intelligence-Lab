\# Enterprise SOC Monitoring \& Incident Response Lab
An end-to-end Security Operations Center (SOC) home lab built using Splunk Enterprise, Windows Sysmon, Python and VirusTotal.
The project collects endpoint telemetry, detects suspicious activity, enriches external IP addresses with threat intelligence, and centralizes investigation data in Splunk dashboards.

\## Project Objectives
\- Centralize Windows endpoint telemetry in Splunk.
\- Monitor process creation, network connections and DNS activity.
\- Develop detection rules for common security events.
\- Enrich public destination IP addresses using VirusTotal.
\- Automate threat intelligence collection and ingestion.
\- Investigate alerts using endpoint and network evidence.
\- Document incident triage and response decisions.

\## Architecture
```mermaid
flowchart TD

&#x20;   A\[Windows 11 Endpoint] --> B\[Sysmon]

&#x20;   B --> C\[Splunk Universal Forwarder]

&#x20;   C --> D\[Splunk Enterprise]

&#x20;   D --> E\[Python Enrichment Engine]

&#x20;   E --> F\[IP Validation]

&#x20;   F --> G\[VirusTotal API]

&#x20;   G --> H\[JSONL Enrichment Records]

&#x20;   H --> I\[Universal Forwarder]

&#x20;   I --> J\[Splunk Threat Intelligence Index]

&#x20;   J --> K\[SOC Dashboards and Alerts]

&#x20;   K --> L\[Incident Investigation]

```



\## Technology Stack



| Technology | Purpose |

|---|---|

| Splunk Enterprise | SIEM and log analysis |

| Windows Sysmon | Endpoint telemetry |

| Splunk Universal Forwarder | Log forwarding |

| Python | Automation and enrichment |

| VirusTotal API | IP threat intelligence |

| Windows Credential Manager | Credential storage |

| Docker Desktop | Splunk deployment |

| SPL | Detection and investigation queries |



\## Telemetry Collection



The lab collects Windows event data, including:



| Sysmon Event ID | Description |

|---|---|

| 1 | Process Creation |

| 3 | Network Connection |

| 22 | DNS Query |



Windows Security and System event logs are also monitored.



\## Detection Engineering



The following detection use cases were developed:



| Detection | Purpose |

|---|---|

| SOC-DET-001 | Windows Brute Force Login Detection |

| SOC-DET-002 | Encoded PowerShell Execution |

| SOC-DET-003 | Suspicious Outbound Network Connections |

| Outbound Network Anomaly | Identify unusual outbound connection volumes |



Detections use Sysmon and Windows Security telemetry with SPL-based filtering, aggregation and correlation.



The detection rules are designed for a controlled lab environment and require tuning before production deployment.



\## Threat Intelligence Automation



The Python enrichment engine:



1\. Connects to Splunk through its REST API.

2\. Retrieves recent Sysmon network events.

3\. Extracts destination IP addresses.

4\. Filters out non-global and non-IPv4 destinations.

5\. Excludes IPs already present in the enrichment dataset.

6\. Enriches up to three new IPs per execution using VirusTotal.

7\. Saves enrichment records in JSON Lines format.

8\. Sends the records to Splunk through the Universal Forwarder.



Windows Task Scheduler executes the enrichment engine every 30 minutes.



Credentials are retrieved from Windows Credential Manager rather than hardcoded into Python source files.



\## Splunk Dashboard



The dashboard, \*\*Enterprise SOC Monitoring \& Incident Response\*\*, includes:



\- VirusTotal Enriched Destinations

\- Unique Enriched IPs

\- Malicious IPs

\- Suspicious IPs

\- Total Network Connections

\- Top Destination IPs

\- VirusTotal Verdict Distribution

\- Recent Endpoint Events

\- Threat Intelligence Coverage

\- Outbound Network Anomalies

\- Process-wise Network Activity

\- Incident Investigation Queue



\## Incident Investigation



A documented investigation case is included:



\*\*SOC-IR-001 — Potential Suspicious Outbound Connection\*\*



The investigation examines:



\- VirusTotal threat intelligence

\- Sysmon network connection events

\- Process creation telemetry

\- Process GUID correlation

\- Parent process information

\- Command-line arguments

\- File hashes



The case remains pending validation because the available evidence does not establish a confirmed malicious incident.



See `incident\_case\_001.md`.



\## Project Structure



```text

threat-intel/

│

├── enrich\_splunk\_events.py

├── vt\_enrichment.py

├── setup\_credentials.py

├── vt\_enrichment.jsonl

├── incident\_case\_001.md

└── README.md

```



Additional Splunk configuration files, detection searches and screenshots can be included as the project documentation is finalized.



\## Setup and Execution



\### Prerequisites



\- Windows 10/11

\- Docker Desktop

\- Splunk Enterprise

\- Splunk Universal Forwarder

\- Sysmon

\- Python 3

\- VirusTotal API key



\### Install Python dependencies



```powershell

py -m pip install requests urllib3 keyring

```



\### Configure credentials



Run:



```powershell

py setup\_credentials.py

```



Enter the Splunk credentials and VirusTotal API key when prompted.



\### Run enrichment



```powershell

py enrich\_splunk\_events.py

```



The script retrieves telemetry from Splunk, selects eligible public IPv4 destinations and performs threat intelligence enrichment.



\## Security Considerations



\- Never commit API keys, passwords or authentication tokens.

\- Keep credentials in Windows Credential Manager.

\- Do not publish raw endpoint logs or sensitive user information.

\- Restrict access to exported telemetry and enrichment files.

\- The Splunk REST connection uses an unverified certificate for this local lab setup. Production environments must use properly validated TLS certificates.

\- VirusTotal results are intelligence signals, not definitive proof of malicious activity.



\## Current Limitations



\- VirusTotal enrichment is limited to three new IP addresses per execution.

\- IPv6 enrichment is currently excluded.

\- The lab uses a single Windows endpoint.

\- Outbound anomaly thresholds are provisional and require further tuning.

\- A clean VirusTotal verdict does not guarantee that an IP is safe.

\- Alert detections require analyst validation and false-positive review.

\- This is a learning and portfolio lab, not a production SOC deployment.



\## Future Improvements



\- Add additional Windows endpoints.

\- Improve alert deduplication and suppression.

\- Tune anomaly detection thresholds using longer baselines.

\- Add structured incident evidence and response tracking.

\- Improve automated reporting.

\- Expand threat intelligence sources.



\## Disclaimer



This project was developed for educational purposes and authorized security testing in a controlled lab environment.



It is not intended to replace an enterprise-grade SOC platform or professional incident response process.
