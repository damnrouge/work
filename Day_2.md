🔹 Start with a simple definition:
“Cloud computing means using someone else’s computer, over the internet, to run software, store files, or process data — instead of doing it on your own machines.”

Cloud computing is like renting services instead of owning them. Companies like Amazon, Microsoft, and Google have giant data centers full of servers. You can use parts of their infrastructure remotely to run your apps, store data, or use software — and you only pay for what you use.

🔹 Why is cloud important?
Companies are moving to the cloud because it’s cheaper, faster, and easier to scale.

That means SOC teams now have to protect cloud environments, not just on-premises systems.

🔍 Cloud Service Models Explained – IaaS, PaaS, SaaS
We divide cloud services into 3 categories based on what you manage vs. what the provider manages.

1️⃣ IaaS – Infrastructure as a Service
📘 What is it?
You rent virtual machines, storage, and networks. You install your own operating system and software on top of it.

🛠️ Example:
Amazon EC2 (Elastic Compute Cloud)

Microsoft Azure Virtual Machines

“Imagine you need a computer to run your app. Instead of buying one, you rent a virtual computer in the cloud and do everything else yourself.”

⚙️ You manage:
Operating system

Apps and security tools

Configurations

☁️ Cloud provider manages:
Physical servers

Networking

Disk storage

Data center security

🔐 SOC relevance:
Monitor login attempts on cloud VMs

Watch for privilege escalations or lateral movement

Investigate brute-force attacks on public-facing servers

2️⃣ PaaS – Platform as a Service
📘 What is it?
The cloud provider gives you a platform to build and run your app — no need to manage servers or OS.

🛠️ Example:
Google App Engine

Heroku

Microsoft Azure App Service

“It’s like using a pre-setup kitchen — the stove, oven, and sink are ready. You just bring the recipe (your code).”

⚙️ You manage:
The application

App-level configurations and data

☁️ Cloud provider manages:
OS and runtime

Middleware, storage, network

🔐 SOC relevance:
Monitor APIs and access patterns

Look for code injection attempts or insecure endpoints

Audit user roles and permissions

3️⃣ SaaS – Software as a Service
📘 What is it?
You access full software applications via a browser. No need to install or manage anything — the provider handles everything.

🛠️ Example:
Gmail, Microsoft 365, Dropbox, Salesforce

“It’s like using Netflix — you don’t worry about the servers or software; you just log in and use it.”

⚙️ You manage:
User accounts

Access permissions

Data (what you upload or share)

☁️ Cloud provider manages:
Software code

Hosting, uptime, security patches

🔐 SOC relevance:
Monitor for account takeovers (e.g., someone logs into your SaaS account from another country)

Use tools like CASB (Cloud Access Security Broker) for data loss prevention

Check logs from Google Workspace or Microsoft 365

✅ Advantages of Cloud Computing
Tell the intern these are the reasons cloud is so widely used:

Cost-effective – Pay only for what you use. No buying expensive servers.

Scalable – Easily scale up (add resources) when needed.

Accessible – Work from anywhere with an internet connection.

Reliable – High availability, backups, and recovery built-in.

Secure – Top providers offer strong encryption, identity access control, and more.

Fast deployment – New resources can be live in minutes.

🔐 Cloud & SOC – What Interns Need to Know
SOC teams are now cloud defenders too. You can’t protect an organization if you don’t understand what’s happening in its cloud.

Here’s how SOC teams are involved:

🔸 1. Cloud Log Monitoring:
AWS: CloudTrail, GuardDuty

Azure: Activity Logs, Defender for Cloud

GCP: Cloud Audit Logs

🗣️ Tell the intern:

“These logs show who did what in the cloud — like launching a server, deleting a file, or changing permissions.”

🔸 2. Detecting Misconfigurations:
Public S3 buckets (data leaks)

Over-permissive IAM roles (too much access)

Unused exposed ports (attack surface)

🗣️ Tell the intern:

“Many attacks happen not because of hacking — but because someone forgot to secure something properly.”

🔸 3. Threat Detection:
Brute-force login attempts

Use of stolen access tokens

Abnormal download activity

🗣️ Tell the intern:

“SOC analysts must review cloud alerts just like on-prem ones — but with different tools and formats.”


______________________________________________________________________________________________________________________________________________________________________________________________________________


+------------------------+----------------------------------+-----------------------------------------------+
|       Tool Name        |            Purpose               |                Common Use Case                |
+------------------------+----------------------------------+-----------------------------------------------+
| VirusTotal             | File, URL, IP reputation         | Check if a file, domain, or IP is malicious   |
| Shodan                 | Device & service search engine   | Find exposed ports/devices on the internet    |
| AbuseIPDB              | IP abuse reporting               | Check if IP is involved in attacks or abuse   |
| urlscan.io             | URL inspection & screenshotting  | Analyze phishing or suspicious URLs safely    |
| GreyNoise              | Noise vs targeted IP analysis    | Identify harmless scanners vs real threats    |
| OTX (AlienVault)       | Threat intel feeds and IOCs      | Correlate indicators with global threat data  |
| Censys                 | Asset discovery & certificates   | Search for exposed systems and SSL data       |
| crt.sh                 | SSL certificate transparency     | View all certs ever issued to a domain        |
| Whois (WhoisXML/API)   | Domain registration details      | Track domain ownership, registration changes  |
| Hunter.io              | Email discovery                  | Discover public emails for a domain/person    |
| SpiderFoot             | Automated OSINT scanning         | Scan domain/IP/email for all linked data      |
| ThreatFox (abuse.ch)   | Malware IOCs                     | Lookup file hashes, URLs, domains linked to malware |
| Robtex                 | DNS, IP and domain mapping       | Deep DNS analysis for investigations          |
| DNSDumpster            | Subdomain enumeration            | Discover attack surface from DNS records      |
| EmailRep.io            | Email reputation scoring         | Evaluate if an email is risky or fake         |
| IntelligenceX          | Historic data breach search      | Look up breached emails, IPs, domains         |
| FOFA (Chinese Shodan)  | Asset search in APAC region      | Alternative to Shodan with broader global coverage |
| RiskIQ Community       | External threat investigation    | Domain, IP, and passive DNS lookup            |
| PublicWWW              | Code & keyword search in sites   | Find sites using specific JS, frameworks, etc |
| BuiltWith              | Technology stack discovery       | See what tech (e.g. WordPress, Cloudflare) a site uses |
| MalShare               | Public malware repository        | Look up and download known malicious samples  |
| Any.run                | Malware sandbox & behavior view  | Watch how malware behaves in a virtual env    |
| CheckPhish.ai          | Phishing URL scanner             | Get real-time threat score and screenshots    |
| Archive.org            | Historical snapshots             | Investigate past versions of websites         |
| Nmap (scripted scans)  | Network discovery                | Scan open ports and services (internal use)   |
+------------------------+----------------------------------+-----------------------------------------------+

______________________________________________________________________________________________________________________________________________________________________________________________________________

+----------------------+------------------------------+----------------------------------------------+
| Tool Type            | Examples                     | Purpose                                      |
+----------------------+------------------------------+----------------------------------------------+
| SIEM                 | Splunk, Wazuh                | Log analysis, alerting, correlation          |
| EDR                  | CrowdStrike, Defender ATP    | Endpoint threat detection and response       |
| SOAR                 | Cortex XSOAR, IBM Resilient  | Automated response and playbook execution    |
| TIP                  | MISP, ThreatConnect          | Threat intelligence and IOC management       |
| NDR                  | Zeek, Corelight, Darktrace   | Network anomaly detection                    |
| IDS/IPS              | Snort, Suricata              | Detect/block malicious network traffic       |
| Case Management      | TheHive, Jira, ServiceNow    | Investigations, workflow, documentation      |
| Log Collection       | Logstash, Filebeat, Fluentd  | Send structured logs to SIEMs                |
| Vulnerability Mgmt   | OpenVAS, Nessus, Qualys      | Identify and rank system vulnerabilities     |
+----------------------+------------------------------+----------------------------------------------+

______________________________________________________________________________________________________________________________________________________________________________________________________________

+---------------------------+----------------------------------------------+-----------------------------+
|         Threat Type       |                 Description                  |           Example           |
+---------------------------+----------------------------------------------+-----------------------------+
| Malware                   | Malicious software designed to harm systems |                             |
|  - Virus                  | Attaches to files, spreads via user action   | Melissa, ILOVEYOU           |
|  - Worm                   | Self-replicates without user interaction     | WannaCry, Code Red          |
|  - Trojan Horse           | Disguised as legitimate software             | Zeus, Emotet                |
|  - Ransomware             | Encrypts data, demands ransom                 | LockBit, REvil              |
|  - Spyware                | Steals user data silently                      | FinFisher, Pegasus          |
|  - Adware                 | Displays unwanted ads                          | Fireball                   |
|  - Rootkit                | Provides hidden admin access                   | ZeroAccess                  |
|  - Keylogger              | Records keystrokes                             | Olympic Vision              |
|  - Fileless Malware       | Resides in memory, uses legit tools           | Astaroth, Kovter            |
+---------------------------+----------------------------------------------+-----------------------------+
| Web-Based Attacks         | Target web users or apps                       |                             |
|  - Phishing               | Fake emails/sites to steal credentials        | Office 365 login scam       |
|  - Spear Phishing         | Targeted phishing to specific individuals     | CEO fraud                   |
|  - Whaling                | Phishing targeting executives                  | CFO wire transfer scam      |
|  - Drive-by Download      | Automatic malware downloads from websites     | Malicious ad campaigns      |
|  - Watering Hole Attack   | Compromises sites frequented by targets        | Polish banking site attack  |
+---------------------------+----------------------------------------------+-----------------------------+
| Network & Infrastructure  | Attacks on network systems                     |                             |
|  - DDoS                   | Overloads systems to cause downtime            | Mirai botnet                |
|  - Man-in-the-Middle      | Intercepts communication                        | HTTPS stripping             |
|  - DNS Poisoning          | Redirects users via altered DNS records        | Kaminsky attack             |
|  - ARP Spoofing           | Fakes ARP messages to intercept traffic        | Internal LAN sniffing       |
|  - Packet Sniffing        | Captures network data                           | Wireshark misuse            |
+---------------------------+----------------------------------------------+-----------------------------+
| Application-Layer Attacks | Target software applications                    |                             |
|  - SQL Injection          | Injects malicious SQL commands                  | Login bypass with ' OR 1=1  |
|  - Cross-Site Scripting   | Injects scripts into websites                    | JavaScript alert injections |
|  - Cross-Site Request Forgery| Tricks users to execute unwanted actions    | Unauthorized bank transfer  |
|  - Remote Code Execution  | Executes code remotely                           | Log4Shell, Shellshock       |
|  - Directory Traversal    | Accesses unauthorized folders                    | ../../../etc/passwd         |
+---------------------------+----------------------------------------------+-----------------------------+
| Endpoint & User Exploits  | Exploiting users or devices                      |                             |
|  - Credential Stuffing    | Uses leaked creds on multiple accounts          | Netflix account takeover    |
|  - Brute Force Attack     | Tries many password combos                       | SSH login attempts          |
|  - Password Spraying      | Common passwords tried across many accounts     | Winter2024! attempts        |
|  - Privilege Escalation   | Gains higher access via flaws                     | Exploiting Linux sudo bug   |
|  - Zero-Day Exploit       | Attacks unknown vulnerabilities                  | Stuxnet                    |
+---------------------------+----------------------------------------------+-----------------------------+
| Social Engineering        | Manipulates humans to gain access                |                             |
|  - Pretexting             | Fabricated story to get info                      | Fake IT support call        |
|  - Baiting                | Entices victims to execute attacks                | Free movie downloads        |
|  - Tailgating             | Physical access by following authorized users    | Fake delivery person        |
|  - Quid Pro Quo           | Offers benefit for info or access                 | Free tech support scam      |
+---------------------------+----------------------------------------------+-----------------------------+
| Insider Threats           | Threats from inside organization                  |                             |
|  - Malicious Insider      | Employee intentionally causing harm              | Edward Snowden case         |
|  - Negligent Insider      | Accidental leaks or mistakes                       | Misaddressed email          |
|  - Compromised Insider    | Legit account hijacked by attackers                | Credential theft            |
+---------------------------+----------------------------------------------+-----------------------------+
| Advanced Persistent Threats (APTs)                          |                             |
|  - Nation-State Attacks   | Sponsored by governments for espionage or sabotage| APT28, APT29                |
|  - Supply Chain Attacks   | Attacks through trusted vendors                   | SolarWinds, Kaseya          |
|  - Living off the Land    | Uses legitimate tools to evade detection          | Cobalt Strike, Mimikatz     |
+---------------------------+----------------------------------------------+-----------------------------+

