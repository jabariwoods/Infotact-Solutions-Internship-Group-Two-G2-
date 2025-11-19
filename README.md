## Projects Brief

### Network Intrusion Detection System (NIDS) Lab (Completed)

- Developed and deployed a virtualized security lab environment using Suricata as the NIDS engine.
- Created and tested custom Suricata rules designed to detect specific malicious activities such as reconnaissance scans (Nmap), brute-force login attempts (SSH), and simple malware Command and Control (C2) beaconing.
- Configured alerts and logging to provide real-time notifications for security analysts during simulated attacks.
- Provided comprehensive setup instructions, custom rules, and documentation to facilitate reproduction and further development.

### Web Application Firewall Development Lab (Completed)

- Designed and deployed a custom ModSecurity rule to detect SQL injection attempts targeting the UNION SELECT pattern in POST parameters.
- Hosted a deliberately vulnerable PHP login page on an Ubuntu server to serve as the testbed for WAF evaluation.
- Executed controlled attack payloads from a Kali Linux machine using curl, simulating realistic SQL injection probes and evasion techniques.
- Validated rule effectiveness through ModSecurity audit logs and Apache error logs, confirming successful detection and blocking of malicious requests.
- Recommended layered detection strategies, input normalization, phased rule tuning, and integration of community rule sets (e.g., OWASP CRS, libinjection) to enhance coverage and reduce false positives.
- Provided reproducible setup instructions, rule configuration, and tuning guidance to support further development and educational use.

### Threat Intel Processor (Completed)

- Developed a Python-based tool to automate the ingestion of malicious IP indicators from AbuseIPDB using its API.
- Implemented a local SQLite database to store Indicators of Compromise (IOCs) including IP address, abuse confidence score, and country code.
- Built a pipeline to fetch, parse, and normalize threat data, ensuring duplicate entries are handled gracefully with INSERT OR IGNORE.
- Designed a log correlation engine that scans system/network logs against the IOC database, flagging matches with real-time alerts.
- Simulated attack scenarios by generating sample log files containing both benign and malicious IPs to validate detection accuracy.
- Verified functionality by observing alerts for known malicious IPs, demonstrating effective integration of external threat intelligence into local monitoring workflows.
- Provided reproducible setup instructions, including API key configuration, database initialization, and log scanning examples, to support further development and educational use.

