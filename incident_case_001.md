

\# SOC Incident Investigation — SOC-IR-001



\## 1. Case Overview



\- Case ID: SOC-IR-001

\- Date: 9 November 2026

\- Incident type: Potential suspicious outbound connection

\- Initial indicator: 172.192.176.118

\- Status: Pending validation

\- Analyst assessment: Unconfirmed



\## 2. Detection Sources



\- Splunk Enterprise

\- Windows Sysmon

\- VirusTotal API

\- Python threat intelligence enrichment script



\## 3. Initial Findings



Splunk identified 43 network connection events involving the destination IP during the seven-day investigation window.



Observed network details:



| Field | Observation |

|---|---|

| Destination IP | 172.192.176.118 |

| Destination port | 443 |

| Protocol | TCP |

| Initiated | True |

| User | SHAHID\\hp |

| Processes observed | SystemSettings.exe, backgroundTaskHost.exe |



\## 4. Threat Intelligence Findings



VirusTotal enrichment returned:



| Field | Result |

|---|---|

| Owner | Microsoft Corporation |

| Country | Japan |

| Reputation | 0 |

| Malicious detections | 1 |

| Suspicious detections | 0 |

| Script verdict | Malicious |

| Script severity | High |



A single vendor detection is insufficient to establish that the destination is malicious.



\## 5. Endpoint Investigation



Sysmon Event ID 3 was used to identify outbound network connections.



Sysmon Event ID 1 was used to investigate process creation.



ProcessGuid correlation was performed to examine process and network context, including command lines, parent processes and file hashes.



The available evidence does not conclusively establish malicious execution.



\## 6. Analyst Assessment



Classification: Unconfirmed



Reasoning:



\- One VirusTotal vendor reported a malicious detection.

\- The reputation score was zero.

\- Windows-related processes appeared in the network activity.

\- No confirmed malicious process execution was established.

\- Additional file-signature and hash reputation validation is required.



\## 7. Response Actions



\- Preserved relevant Splunk events.

\- Reviewed Sysmon process and network telemetry.

\- Retrieved threat intelligence using VirusTotal.

\- Correlated process creation and network activity.

\- No blocking or quarantine performed due to insufficient evidence.



\## 8. MITRE ATT\&CK Mapping



No technique was conclusively established from the available evidence.



\## 9. Lessons Learned



\- Reputation scores and malicious detection counts are different measurements.

\- Threat intelligence should be correlated with endpoint telemetry.

\- A single vendor detection should not automatically trigger containment.

\- Process ancestry and file hashes provide important investigative context.

\- Automated enrichment can improve investigation speed, but analyst validation remains essential.



\## 10. Final Disposition



Status: Pending validation.



The available evidence does not support declaring this a confirmed security incident or a confirmed false positive.
