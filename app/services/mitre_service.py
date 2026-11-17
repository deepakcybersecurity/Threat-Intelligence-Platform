"""
MITRE ATT&CK Mapping & Matrix Service (Task 12)
================================================
Provides enterprise cyber threat intelligence mapping to the MITRE ATT&CK framework:
1. Full 14 Tactics Kill-Chain Knowledge Base (Reconnaissance through Impact).
2. Enterprise Techniques & Sub-techniques catalog with mitigations, data sources, and platforms.
3. Automated Regex & Heuristic Extraction of MITRE technique IDs from reports, logs, and command lines.
4. Threat-to-MITRE Correlation for Malware, ThreatReports, and Alerts.
5. Real-Time MITRE ATT&CK Heatmap & Coverage Score calculation.
6. MITRE ATT&CK Navigator Layer v4.5 JSON Export for external threat visualization.
"""

from datetime import datetime, timezone
import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from app import db
from app.models import Alert, Malware, ThreatIndicator, ThreatReport

logger = logging.getLogger(__name__)

# =============================================================================
# 1. MITRE ATT&CK TACTICS (14 ENTERPRISE TACTICS IN CHRONOLOGICAL ORDER)
# =============================================================================
MITRE_TACTICS: Dict[str, Dict[str, Any]] = {
    "TA0043": {
        "id": "TA0043",
        "name": "Reconnaissance",
        "short_name": "reconnaissance",
        "description": "Gather information to plan future adversary operations against the target organization.",
        "order": 1,
    },
    "TA0042": {
        "id": "TA0042",
        "name": "Resource Development",
        "short_name": "resource-development",
        "description": "Establish resources such as infrastructure, accounts, and capabilities to support operations.",
        "order": 2,
    },
    "TA0001": {
        "id": "TA0001",
        "name": "Initial Access",
        "short_name": "initial-access",
        "description": "Use various means to gain an initial foothold within a network (e.g. phishing, exploiting public-facing apps).",
        "order": 3,
    },
    "TA0002": {
        "id": "TA0002",
        "name": "Execution",
        "short_name": "execution",
        "description": "Run adversary-controlled code locally or remotely on target systems.",
        "order": 4,
    },
    "TA0003": {
        "id": "TA0003",
        "name": "Persistence",
        "short_name": "persistence",
        "description": "Maintain access across restarts, changed credentials, and other interruptions.",
        "order": 5,
    },
    "TA0004": {
        "id": "TA0004",
        "name": "Privilege Escalation",
        "short_name": "privilege-escalation",
        "description": "Gain higher-level permissions on systems or network resources (e.g. SYSTEM, root, admin).",
        "order": 6,
    },
    "TA0005": {
        "id": "TA0005",
        "name": "Defense Evasion",
        "short_name": "defense-evasion",
        "description": "Avoid detection and circumvent security controls throughout their compromise.",
        "order": 7,
    },
    "TA0006": {
        "id": "TA0006",
        "name": "Credential Access",
        "short_name": "credential-access",
        "description": "Steal account names, passwords, hashes, and API tokens from memory or storage.",
        "order": 8,
    },
    "TA0007": {
        "id": "TA0007",
        "name": "Discovery",
        "short_name": "discovery",
        "description": "Observe and explore the environment, network configuration, and active users.",
        "order": 9,
    },
    "TA0008": {
        "id": "TA0008",
        "name": "Lateral Movement",
        "short_name": "lateral-movement",
        "description": "Extend access to other systems, services, and segments across the network.",
        "order": 10,
    },
    "TA0009": {
        "id": "TA0009",
        "name": "Collection",
        "short_name": "collection",
        "description": "Gather sensitive data, files, screenshots, and keystrokes of interest to the adversary.",
        "order": 11,
    },
    "TA0011": {
        "id": "TA0011",
        "name": "Command and Control",
        "short_name": "command-and-control",
        "description": "Communicate with compromised systems to control implants and exfiltrate telemetry.",
        "order": 12,
    },
    "TA0010": {
        "id": "TA0010",
        "name": "Exfiltration",
        "short_name": "exfiltration",
        "description": "Steal and transfer collected data out of the target environment to adversary servers.",
        "order": 13,
    },
    "TA0040": {
        "id": "TA0040",
        "name": "Impact",
        "short_name": "impact",
        "description": "Manipulate, interrupt, destroy, or encrypt systems, availability, and business data.",
        "order": 14,
    },
}

# Lookup map by short name or case-insensitive name
TACTIC_NAME_TO_ID: Dict[str, str] = {}
for _tid, _tdata in MITRE_TACTICS.items():
    TACTIC_NAME_TO_ID[_tid.lower()] = _tid
    TACTIC_NAME_TO_ID[_tdata["name"].lower()] = _tid
    TACTIC_NAME_TO_ID[_tdata["short_name"].lower()] = _tid

# =============================================================================
# 2. CORE ENTERPRISE ATT&CK TECHNIQUES KNOWLEDGE BASE
# =============================================================================
MITRE_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    # --- Reconnaissance (TA0043) ---
    "T1595": {
        "id": "T1595",
        "name": "Active Scanning",
        "parent_id": None,
        "tactics": ["TA0043"],
        "platforms": ["Network", "PRE"],
        "description": "Adversaries execute active reconnaissance scans to gather information on IP blocks and open ports.",
        "detection": "Monitor network perimeter logs and IDS alerts for sudden spikes in port scan activity.",
        "mitigations": ["M1056: Network Intrusion Prevention", "M1037: Filter Network Traffic"],
    },
    "T1595.001": {
        "id": "T1595.001",
        "name": "Active Scanning: Scanning IP Blocks",
        "parent_id": "T1595",
        "tactics": ["TA0043"],
        "platforms": ["Network", "PRE"],
        "description": "Adversaries scan public IP ranges to map victim network infrastructure and exposed systems.",
        "detection": "Correlate external firewall denial spikes and mass connection attempts.",
        "mitigations": ["M1037: Filter Network Traffic", "M1031: Network Boundary Defense"],
    },
    "T1592": {
        "id": "T1592",
        "name": "Gather Victim Host Information",
        "parent_id": None,
        "tactics": ["TA0043"],
        "platforms": ["PRE"],
        "description": "Adversaries gather host details like software versions, patch status, and firmware before an attack.",
        "detection": "Monitor OSINT query frequency and honeypot interaction logs.",
        "mitigations": ["M1056: Pre-compromise Defense", "M1047: Audit Attack Surface"],
    },

    # --- Resource Development (TA0042) ---
    "T1583": {
        "id": "T1583",
        "name": "Acquire Infrastructure",
        "parent_id": None,
        "tactics": ["TA0042"],
        "platforms": ["PRE"],
        "description": "Adversaries purchase or register domains, DNS services, and VPS servers to host staging tools.",
        "detection": "Track newly registered domains (NRDs) and reputation scoring feeds in threat intelligence.",
        "mitigations": ["M1056: Threat Intelligence Feeds", "M1031: Domain Blacklisting"],
    },
    "T1583.001": {
        "id": "T1583.001",
        "name": "Acquire Infrastructure: Domains",
        "parent_id": "T1583",
        "tactics": ["TA0042"],
        "platforms": ["PRE"],
        "description": "Adversaries register domains for typosquatting or command and control infrastructure.",
        "detection": "Query DNS passive WHOIS databases for newly registered domains mimicking corporate brands.",
        "mitigations": ["M1056: DNS Brand Monitoring", "M1037: Filter Malicious Domains"],
    },
    "T1588": {
        "id": "T1588",
        "name": "Obtain Capabilities",
        "parent_id": None,
        "tactics": ["TA0042"],
        "platforms": ["PRE"],
        "description": "Adversaries buy or download malware, exploits, and digital certificates on underground forums.",
        "detection": "Monitor dark web forums and underground threat reporting.",
        "mitigations": ["M1056: Proactive Threat Intelligence"],
    },

    # --- Initial Access (TA0001) ---
    "T1566": {
        "id": "T1566",
        "name": "Phishing",
        "parent_id": None,
        "tactics": ["TA0001"],
        "platforms": ["Windows", "macOS", "Linux", "SaaS", "Office 365"],
        "description": "Adversaries send malicious emails or links to lure users into opening attachments or entering credentials.",
        "detection": "Email gateway anti-phishing scanning, SPF/DKIM/DMARC inspection, and sandbox detonation.",
        "mitigations": ["M1049: Antivirus/Antimalware", "M1054: Software Configuration", "M1017: User Training"],
    },
    "T1566.001": {
        "id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "parent_id": "T1566",
        "tactics": ["TA0001"],
        "platforms": ["Windows", "macOS", "Linux"],
        "description": "Adversaries attach weaponized documents (e.g. Word with macros, ISO, LNK, ZIP) targeting specific victims.",
        "detection": "Detonate attachments in email sandbox; log process creation spawning from outlook.exe.",
        "mitigations": ["M1049: Attachment Sandboxing", "M1031: Block Dangerous Extensions"],
    },
    "T1566.002": {
        "id": "T1566.002",
        "name": "Phishing: Spearphishing Link",
        "parent_id": "T1566",
        "tactics": ["TA0001"],
        "platforms": ["Windows", "macOS", "Linux"],
        "description": "Adversaries send targeted emails containing links to credential harvesting or exploit sites.",
        "detection": "Inspect web proxy and URL rewrite logs for unknown newly observed domains.",
        "mitigations": ["M1021: Restrict Web-Based Content", "M1017: User Awareness Training"],
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "parent_id": None,
        "tactics": ["TA0001"],
        "platforms": ["Windows", "Linux", "Network", "Internet Facing"],
        "description": "Adversaries exploit vulnerabilities in public-facing software (e.g. web servers, VPNs, firewalls) to gain access.",
        "detection": "Web application firewall (WAF) anomaly alerts, crash dumps, and unauthorized child processes under web servers.",
        "mitigations": ["M1051: Update Software", "M1050: Exploit Protection", "M1037: WAF Deployment"],
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "parent_id": None,
        "tactics": ["TA0001", "TA0003", "TA0004", "TA0005"],
        "platforms": ["Windows", "Linux", "macOS", "Cloud", "Identity"],
        "description": "Adversaries obtain and use credentials of existing legitimate accounts to gain access and evade detection.",
        "detection": "Monitor impossible travel alerts, atypical login hours, and MFA spray attempts.",
        "mitigations": ["M1032: Multi-factor Authentication", "M1026: Privileged Account Management"],
    },

    # --- Execution (TA0002) ---
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "parent_id": None,
        "tactics": ["TA0002"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries abuse command and script interpreters to execute arbitrary commands, scripts, or binaries.",
        "detection": "Enable process command-line logging (Event ID 4688 / Sysmon Event ID 1) and script block auditing.",
        "mitigations": ["M1038: Execution Prevention", "M1042: Disable or Remove Feature or Program"],
    },
    "T1059.001": {
        "id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "parent_id": "T1059",
        "tactics": ["TA0002"],
        "platforms": ["Windows"],
        "description": "Adversaries use PowerShell to execute commands, download payloads, and inject into memory.",
        "detection": "Enable PowerShell Module Logging (Event 4103), Script Block Logging (Event 4104), and transcription.",
        "mitigations": ["M1038: ConstrainedLanguage Mode", "M1047: Restrict PowerShell ExecutionPolicy"],
    },
    "T1059.003": {
        "id": "T1059.003",
        "name": "Command and Scripting Interpreter: Windows Command Shell",
        "parent_id": "T1059",
        "tactics": ["TA0002"],
        "platforms": ["Windows"],
        "description": "Adversaries execute commands via cmd.exe to launch utilities or execute batch (.bat) files.",
        "detection": "Monitor cmd.exe spawned by Office applications, web browsers, or script interpreters.",
        "mitigations": ["M1038: Execution Prevention", "M1042: Restrict Cmdlet Usage"],
    },
    "T1059.004": {
        "id": "T1059.004",
        "name": "Command and Scripting Interpreter: Unix Shell",
        "parent_id": "T1059",
        "tactics": ["TA0002"],
        "platforms": ["Linux", "macOS"],
        "description": "Adversaries abuse Unix shells like bash, sh, or zsh to execute malicious shell commands and scripts.",
        "detection": "Auditd execve logs, shell history tracking, and monitoring web service users executing /bin/sh.",
        "mitigations": ["M1038: Execution Prevention", "M1028: Operating System Configuration"],
    },
    "T1059.005": {
        "id": "T1059.005",
        "name": "Command and Scripting Interpreter: Visual Basic",
        "parent_id": "T1059",
        "tactics": ["TA0002"],
        "platforms": ["Windows"],
        "description": "Adversaries execute VBScript or VBA macros via wscript.exe or cscript.exe to drop or execute payloads.",
        "detection": "Log process creation of wscript.exe or cscript.exe downloading external network assets.",
        "mitigations": ["M1038: Disable VBScript", "M1054: Block Office Macros from the Internet"],
    },
    "T1204": {
        "id": "T1204",
        "name": "User Execution",
        "parent_id": None,
        "tactics": ["TA0002"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries rely on specific actions by the user to execute code, such as opening links or malicious files.",
        "detection": "Correlate user download events with subsequent immediate executable creation.",
        "mitigations": ["M1017: User Training", "M1038: Execution Prevention via AppLocker"],
    },
    "T1204.002": {
        "id": "T1204.002",
        "name": "User Execution: Malicious File",
        "parent_id": "T1204",
        "tactics": ["TA0002"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "An adversary relies on the user executing an email attachment or downloaded archive.",
        "detection": "Process lineage tracking showing explorer.exe or email client spawning untrusted executables.",
        "mitigations": ["M1049: Antivirus/Antimalware", "M1038: Execution Prevention"],
    },

    # --- Persistence (TA0003) ---
    "T1547": {
        "id": "T1547",
        "name": "Boot or Logon Autostart Execution",
        "parent_id": None,
        "tactics": ["TA0003", "TA0004"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries configure system settings to automatically execute a program during boot or logon.",
        "detection": "Monitor modifications to startup directories and registry keys (Sysmon Event ID 12/13).",
        "mitigations": ["M1022: Restrict File and Directory Permissions", "M1047: Audit Startup Registry"],
    },
    "T1547.001": {
        "id": "T1547.001",
        "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "parent_id": "T1547",
        "tactics": ["TA0003", "TA0004"],
        "platforms": ["Windows"],
        "description": "Adversaries add registry keys in HKCU/HKLM Run or RunOnce to survive system reboots.",
        "detection": "Audit registry modifications to CurrentVersion\\Run and CurrentVersion\\RunOnce keys.",
        "mitigations": ["M1022: Restrict Registry Permissions", "M1026: Privileged Account Management"],
    },
    "T1053": {
        "id": "T1053",
        "name": "Scheduled Task/Job",
        "parent_id": None,
        "tactics": ["TA0003", "TA0004", "TA0002"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries abuse task scheduling functionality (schtasks, cron) to facilitate one-time or recurring execution.",
        "detection": "Event ID 4698 (A scheduled task was created) and Sysmon Event 1 for schtasks.exe.",
        "mitigations": ["M1028: Limit Task Scheduler Permissions", "M1018: User Account Management"],
    },
    "T1053.005": {
        "id": "T1053.005",
        "name": "Scheduled Task/Job: Scheduled Task",
        "parent_id": "T1053",
        "tactics": ["TA0003", "TA0004", "TA0002"],
        "platforms": ["Windows"],
        "description": "Adversaries schedule tasks to execute binaries or scripts at recurring intervals or upon system start.",
        "detection": "Inspect Microsoft-Windows-TaskScheduler/Operational log for new task registrations.",
        "mitigations": ["M1028: Operating System Configuration", "M1026: Privileged Account Management"],
    },

    # --- Privilege Escalation (TA0004) ---
    "T1068": {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "parent_id": None,
        "tactics": ["TA0004"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries exploit software vulnerabilities or kernel flaws to elevate permissions.",
        "detection": "Monitor abnormal system token elevation, driver loading, or privilege assignments.",
        "mitigations": ["M1051: Patch Vulnerabilities", "M1026: Least Privilege Architecture"],
    },
    "T1548": {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "parent_id": None,
        "tactics": ["TA0004", "TA0005"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries circumvent elevation control mechanisms like UAC or sudo to gain higher privileges.",
        "detection": "Log UAC bypass techniques utilizing registry hijack or auto-elevating binaries.",
        "mitigations": ["M1026: Set UAC to Always Notify", "M1028: Operating System Configuration"],
    },

    # --- Defense Evasion (TA0005) ---
    "T1055": {
        "id": "T1055",
        "name": "Process Injection",
        "parent_id": None,
        "tactics": ["TA0004", "TA0005"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries inject malicious code into processes to evade process-based defenses and elevate privileges.",
        "detection": "Sysmon Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess requesting PROCESS_VM_WRITE).",
        "mitigations": ["M1040: Endpoint Detection and Response", "M1050: Exploit Protection"],
    },
    "T1055.001": {
        "id": "T1055.001",
        "name": "Process Injection: Dynamic-link Library Injection",
        "parent_id": "T1055",
        "tactics": ["TA0004", "TA0005"],
        "platforms": ["Windows"],
        "description": "Adversaries inject paths to malicious DLLs into running legitimate processes to execute stealthily.",
        "detection": "Track LoadLibrary API calls originating from non-standard module directories.",
        "mitigations": ["M1040: Endpoint Detection and Response", "M1026: Least Privilege"],
    },
    "T1027": {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "parent_id": None,
        "tactics": ["TA0005"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries encode, encrypt, or pack file contents and payloads to hinder analysis.",
        "detection": "Calculate file entropy (score > 7.0 suggests packing/encryption) and scan for base64 decode routines.",
        "mitigations": ["M1049: Antivirus/Antimalware", "M1040: EDR Behavioral Scanning"],
    },
    "T1562": {
        "id": "T1562",
        "name": "Impair Defenses",
        "parent_id": None,
        "tactics": ["TA0005"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries disable or modify security tools, antivirus services, and event logging.",
        "detection": "Monitor stopping of Defender (WinDefend), firewall rules deletion, or clearing of event logs (Event ID 1102).",
        "mitigations": ["M1047: Tamper Protection", "M1026: Restrict Admin Access"],
    },
    "T1562.001": {
        "id": "T1562.001",
        "name": "Impair Defenses: Disable or Modify Tools",
        "parent_id": "T1562",
        "tactics": ["TA0005"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries disable security software like Windows Defender, CrowdStrike sensor, or firewalls.",
        "detection": "Log sc.exe config stop, Set-MpPreference -DisableRealtimeMonitoring commands.",
        "mitigations": ["M1047: Enable EDR Tamper Protection", "M1026: Privileged Account Management"],
    },

    # --- Credential Access (TA0006) ---
    "T1003": {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "parent_id": None,
        "tactics": ["TA0006"],
        "platforms": ["Windows", "Linux"],
        "description": "Adversaries dump credentials to obtain plaintext passwords and hashes from OS credential stores.",
        "detection": "Monitor process access to lsass.exe or SAM/SYSTEM registry file extraction.",
        "mitigations": ["M1027: Password Policies", "M1041: Enable LSA Protection / Credential Guard"],
    },
    "T1003.001": {
        "id": "T1003.001",
        "name": "OS Credential Dumping: LSASS Memory",
        "parent_id": "T1003",
        "tactics": ["TA0006"],
        "platforms": ["Windows"],
        "description": "Adversaries dump memory of the Local Security Authority Subsystem Service (LSASS) using procdump or Mimikatz.",
        "detection": "Sysmon Event ID 10 with targetImage lsass.exe and GrantedAccess 0x1010 or 0x1F0FFF.",
        "mitigations": ["M1041: Run LSASS as Protected Process Light (PPL)", "M1043: Credential Guard"],
    },
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "parent_id": None,
        "tactics": ["TA0006"],
        "platforms": ["Windows", "Linux", "Cloud", "Network"],
        "description": "Adversaries systematically guess passwords or perform credential stuffing against login portals.",
        "detection": "Spike in Event ID 4625 (An account failed to log on) across multiple user accounts.",
        "mitigations": ["M1036: Account Lockout Policies", "M1032: Multi-Factor Authentication"],
    },

    # --- Discovery (TA0007) ---
    "T1082": {
        "id": "T1082",
        "name": "System Information Discovery",
        "parent_id": None,
        "tactics": ["TA0007"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries attempt to gather detailed information about operating system version, hardware, and architecture.",
        "detection": "Execution of systeminfo, uname -a, hostname, or WMI Win32_OperatingSystem queries.",
        "mitigations": ["M1038: Execution Prevention", "M1026: Privileged Account Management"],
    },
    "T1083": {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "parent_id": None,
        "tactics": ["TA0007"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries enumerate files and directories to locate sensitive documents or credentials.",
        "detection": "Repeated dir /s, ls -la, or find commands across sensitive shared folders.",
        "mitigations": ["M1022: Restrict File and Directory Permissions"],
    },
    "T1016": {
        "id": "T1016",
        "name": "System Network Configuration Discovery",
        "parent_id": None,
        "tactics": ["TA0007"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries look at network settings to understand routing, interfaces, and DNS servers.",
        "detection": "Monitoring ipconfig /all, ifconfig, route print, and arp -a executions.",
        "mitigations": ["M1038: Execution Prevention"],
    },

    # --- Lateral Movement (TA0008) ---
    "T1021": {
        "id": "T1021",
        "name": "Remote Services",
        "parent_id": None,
        "tactics": ["TA0008"],
        "platforms": ["Windows", "Linux"],
        "description": "Adversaries use valid credentials to log into remote services such as RDP, SSH, or SMB.",
        "detection": "Monitor internal RDP connections (port 3389) and Event ID 4624 (Logon Type 10 - RemoteInteractive).",
        "mitigations": ["M1030: Network Segmentation", "M1032: Multi-Factor Authentication"],
    },
    "T1021.001": {
        "id": "T1021.001",
        "name": "Remote Services: Remote Desktop Protocol",
        "parent_id": "T1021",
        "tactics": ["TA0008"],
        "platforms": ["Windows"],
        "description": "Adversaries log into remote endpoints via RDP to interact with user sessions directly.",
        "detection": "Event ID 4624 Logon Type 10 with source workstation not recognized as IT admin jump box.",
        "mitigations": ["M1035: Limit RDP Access", "M1032: Enforce MFA for Remote Desktop"],
    },
    "T1021.002": {
        "id": "T1021.002",
        "name": "Remote Services: SMB/Windows Admin Shares",
        "parent_id": "T1021",
        "tactics": ["TA0008"],
        "platforms": ["Windows"],
        "description": "Adversaries access administrative network shares (C$, ADMIN$) to upload implants remotely.",
        "detection": "Event ID 5140 (A network share object was accessed) targeting ADMIN$ or IPC$.",
        "mitigations": ["M1030: Network Segmentation", "M1035: Disable SMBv1 and Restrict Port 445"],
    },

    # --- Collection (TA0009) ---
    "T1005": {
        "id": "T1005",
        "name": "Data from Local System",
        "parent_id": None,
        "tactics": ["TA0009"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries search local file systems to locate target documents, source code, and intellectual property.",
        "detection": "Audit file access spikes to Desktop, Documents, or user downloads directories.",
        "mitigations": ["M1022: Restrict File and Directory Permissions", "M1041: Encrypt Sensitive Data"],
    },
    "T1113": {
        "id": "T1113",
        "name": "Screen Capture",
        "parent_id": None,
        "tactics": ["TA0009"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries capture screenshots of the active desktop to gather sensitive visual intelligence.",
        "detection": "Monitor API calls to BitBlt, GetDC, or desktop capture commands in rapid succession.",
        "mitigations": ["M1040: Endpoint Detection and Response"],
    },

    # --- Command and Control (TA0011) ---
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "parent_id": None,
        "tactics": ["TA0011"],
        "platforms": ["Network", "Windows", "Linux", "macOS"],
        "description": "Adversaries communicate using standard OSI application layer protocols to blend in with legitimate network traffic.",
        "detection": "Analyze proxy logs for periodic beaconing intervals (jitter analysis) and abnormal User-Agent strings.",
        "mitigations": ["M1037: Filter Network Traffic", "M1031: Network Intrusion Prevention"],
    },
    "T1071.001": {
        "id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "parent_id": "T1071",
        "tactics": ["TA0011"],
        "platforms": ["Network", "Windows", "Linux", "macOS"],
        "description": "Adversaries communicate with external C2 servers over HTTP or HTTPS to blend in with web browsing.",
        "detection": "Inspect TLS certificates, JA3/JA4 fingerprinting, and unusual POST payload sizes to unknown IPs.",
        "mitigations": ["M1031: Web Content Filtering", "M1020: SSL/TLS Inspection"],
    },
    "T1105": {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "parent_id": None,
        "tactics": ["TA0011"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries transfer tools and secondary payloads from external infrastructure into the compromised network.",
        "detection": "Monitor certutil.exe -urlcache, bitsadmin, curl, wget downloading executable files from external IPs.",
        "mitigations": ["M1037: Filter Ingress Network Traffic", "M1038: Block Execution from Temp Directories"],
    },

    # --- Exfiltration (TA0010) ---
    "T1048": {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "parent_id": None,
        "tactics": ["TA0010"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries steal and transmit data using protocols different from their main C2 channel (e.g. FTP, DNS, ICMP).",
        "detection": "Detect high outbound traffic volumes over non-standard ports or unusual DNS TXT query lengths.",
        "mitigations": ["M1037: Outbound Network Filtering", "M1057: Data Loss Prevention"],
    },
    "T1567": {
        "id": "T1567",
        "name": "Exfiltration Over Web Service",
        "parent_id": None,
        "tactics": ["TA0010"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries exfiltrate data using legitimate cloud storage services such as Dropbox, Google Drive, or Mega.",
        "detection": "Monitor large outbound uploads to public cloud providers from unexpected internal endpoints.",
        "mitigations": ["M1021: Cloud Access Security Broker (CASB)", "M1037: Restrict Cloud Storage Uploads"],
    },

    # --- Impact (TA0040) ---
    "T1486": {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "parent_id": None,
        "tactics": ["TA0040"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries encrypt data on target systems to interrupt availability and extort ransom payments.",
        "detection": "High rate of file renames with new extensions, deletion of Volume Shadow Copies (vssadmin delete shadows).",
        "mitigations": ["M1053: Automated Offline Backups", "M1040: Behavioral Ransomware Prevention"],
    },
    "T1489": {
        "id": "T1489",
        "name": "Service Stop",
        "parent_id": None,
        "tactics": ["TA0040"],
        "platforms": ["Windows", "Linux"],
        "description": "Adversaries stop or disable critical services to disrupt business operations or disable security controls.",
        "detection": "Event ID 7036 (The service entered the stopped state) targeting databases, security agents, or web servers.",
        "mitigations": ["M1026: Restrict Administrative Privileges", "M1028: Service Hardening"],
    },
    "T1490": {
        "id": "T1490",
        "name": "Inhibit System Recovery",
        "parent_id": None,
        "tactics": ["TA0040"],
        "platforms": ["Windows", "Linux"],
        "description": "Adversaries delete or disable system recovery features like Volume Shadow Copies, backups, and bcdedit recovery.",
        "detection": "Command lines containing 'vssadmin delete shadows /all /quiet' or 'wbadmin delete catalog'.",
        "mitigations": ["M1026: Restrict Access to Shadow Copies", "M1053: Air-Gapped Immutable Backups"],
    },
}

# Regex pattern for MITRE ATT&CK technique IDs (e.g. T1059, T1059.001)
MITRE_TECHNIQUE_REGEX = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


# =============================================================================
# 3. KNOWLEDGE BASE QUERY & LOOKUP FUNCTIONS
# =============================================================================

def get_all_tactics() -> List[Dict[str, Any]]:
    """Return all 14 Enterprise MITRE ATT&CK tactics in chronological order."""
    tactics = list(MITRE_TACTICS.values())
    tactics.sort(key=lambda x: x["order"])
    # Append count of static techniques
    for t in tactics:
        t_id = t["id"]
        t["techniques_count"] = sum(1 for tech in MITRE_TECHNIQUES.values() if t_id in tech["tactics"])
    return tactics


def get_tactic(tactic_id_or_name: str) -> Optional[Dict[str, Any]]:
    """Lookup tactic by ID (TA0001) or name ('Initial Access')."""
    if not tactic_id_or_name:
        return None
    key = str(tactic_id_or_name).strip().lower()
    t_id = TACTIC_NAME_TO_ID.get(key)
    if not t_id:
        # Check if starts with TA
        for tid in MITRE_TACTICS:
            if tid.lower() == key:
                t_id = tid
                break
    return MITRE_TACTICS.get(t_id) if t_id else None


def normalize_technique_id(tech_id: str) -> str:
    """Normalize input like 't1059.001' or 'T1059' to uppercase 'T1059.001'."""
    val = str(tech_id).strip().upper()
    return val


def get_technique(technique_id: str) -> Dict[str, Any]:
    """
    Get technique details by ID. If not present in static dictionary but matches
    valid MITRE format (T#### or T####.###), dynamically generate a valid entry
    with official ATT&CK links and reasonable defaults.
    """
    norm_id = normalize_technique_id(technique_id)
    if norm_id in MITRE_TECHNIQUES:
        entry = dict(MITRE_TECHNIQUES[norm_id])
        entry["url"] = f"https://attack.mitre.org/techniques/{norm_id.replace('.', '/')}"
        entry["tactics_details"] = [MITRE_TACTICS[t] for t in entry["tactics"] if t in MITRE_TACTICS]
        return entry

    # Validate regex format
    if re.match(r"^T\d{4}(?:\.\d{3})?$", norm_id):
        # Dynamic fallback entry
        parent = norm_id.split(".")[0] if "." in norm_id else None
        return {
            "id": norm_id,
            "name": f"Enterprise Technique {norm_id}",
            "parent_id": parent,
            "tactics": ["TA0002"],  # Default fallback
            "platforms": ["Windows", "Linux", "macOS"],
            "description": f"MITRE ATT&CK Enterprise Technique {norm_id}. See official MITRE documentation.",
            "detection": f"Monitor system telemetry, process execution, and network connections for {norm_id}.",
            "mitigations": ["M1040: Endpoint Detection and Response", "M1038: Execution Prevention"],
            "url": f"https://attack.mitre.org/techniques/{norm_id.replace('.', '/')}",
            "tactics_details": [MITRE_TACTICS["TA0002"]],
            "is_dynamic": True,
        }

    return {}


def search_techniques(
    query: Optional[str] = None,
    tactic: Optional[str] = None,
    platform: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """
    Search and filter MITRE techniques by text query, tactic ID/name, or platform.
    """
    results: List[Dict[str, Any]] = []

    norm_tactic_id = None
    if tactic:
        t_obj = get_tactic(tactic)
        if t_obj:
            norm_tactic_id = t_obj["id"]

    query_norm = query.strip().lower() if query else None
    platform_norm = platform.strip().lower() if platform else None

    for tid, tech in MITRE_TECHNIQUES.items():
        # Filter tactic
        if norm_tactic_id and norm_tactic_id not in tech["tactics"]:
            continue

        # Filter platform
        if platform_norm and not any(platform_norm in p.lower() for p in tech.get("platforms", [])):
            continue

        # Filter query
        if query_norm:
            in_id = query_norm in tid.lower()
            in_name = query_norm in tech["name"].lower()
            in_desc = query_norm in tech.get("description", "").lower()
            if not (in_id or in_name or in_desc):
                continue

        tech_copy = dict(tech)
        tech_copy["url"] = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}"
        tech_copy["tactics_details"] = [MITRE_TACTICS[t] for t in tech["tactics"] if t in MITRE_TACTICS]
        results.append(tech_copy)
        if len(results) >= limit:
            break

    # Sort results by ID
    results.sort(key=lambda x: x["id"])
    return results


def extract_mitre_techniques_from_text(text: str) -> List[Dict[str, Any]]:
    """
    Extract all MITRE technique IDs from arbitrary text (reports, logs, command-lines)
    using regex and resolve each to its full technique metadata.
    """
    if not text:
        return []

    found_ids = set()
    for match in MITRE_TECHNIQUE_REGEX.finditer(text):
        found_ids.add(normalize_technique_id(match.group(0)))

    results = []
    for tid in sorted(found_ids):
        tech_info = get_technique(tid)
        if tech_info:
            results.append(tech_info)

    return results


# =============================================================================
# 4. DATABASE THREAT MAPPING & MATRIX HEATMAP ENGINE
# =============================================================================

def map_threat_to_mitre(threat_obj: Any) -> Dict[str, Any]:
    """
    Map an individual Malware, ThreatReport, or Alert record to its full MITRE techniques.
    """
    mapped_techniques: List[Dict[str, Any]] = []
    tactic_set: Set[str] = set()

    if isinstance(threat_obj, Malware):
        if threat_obj.mitre_attack_id:
            # Handle comma/semicolon/space separated IDs
            parts = re.split(r"[,;\s]+", threat_obj.mitre_attack_id)
            for p in parts:
                p = p.strip()
                if p:
                    tech = get_technique(p)
                    if tech:
                        mapped_techniques.append(tech)
                        for t in tech.get("tactics", []):
                            tactic_set.add(t)

        # Also search in description
        if threat_obj.description:
            extracted = extract_mitre_techniques_from_text(threat_obj.description)
            for ex in extracted:
                if not any(m["id"] == ex["id"] for m in mapped_techniques):
                    mapped_techniques.append(ex)
                    for t in ex.get("tactics", []):
                        tactic_set.add(t)

        return {
            "entity_type": "Malware",
            "entity_id": threat_obj.id,
            "entity_name": threat_obj.malware_name,
            "severity": threat_obj.severity,
            "risk_score": threat_obj.risk_score,
            "mitre_techniques": mapped_techniques,
            "tactics_count": len(tactic_set),
            "tactics": [MITRE_TACTICS[t] for t in sorted(tactic_set) if t in MITRE_TACTICS],
        }

    elif isinstance(threat_obj, ThreatReport):
        extracted = extract_mitre_techniques_from_text(threat_obj.description or "")
        # Also check linked malwares
        for m in threat_obj.malwares:
            m_res = map_threat_to_mitre(m)
            for m_tech in m_res["mitre_techniques"]:
                if not any(ex["id"] == m_tech["id"] for ex in extracted):
                    extracted.append(m_tech)

        for ex in extracted:
            for t in ex.get("tactics", []):
                tactic_set.add(t)

        return {
            "entity_type": "ThreatReport",
            "entity_id": threat_obj.id,
            "entity_name": threat_obj.title,
            "severity": threat_obj.severity,
            "mitre_techniques": extracted,
            "tactics_count": len(tactic_set),
            "tactics": [MITRE_TACTICS[t] for t in sorted(tactic_set) if t in MITRE_TACTICS],
        }

    elif isinstance(threat_obj, Alert):
        extracted = extract_mitre_techniques_from_text(threat_obj.description or "")
        if threat_obj.malware:
            m_res = map_threat_to_mitre(threat_obj.malware)
            for m_tech in m_res["mitre_techniques"]:
                if not any(ex["id"] == m_tech["id"] for ex in extracted):
                    extracted.append(m_tech)

        for ex in extracted:
            for t in ex.get("tactics", []):
                tactic_set.add(t)

        return {
            "entity_type": "Alert",
            "entity_id": threat_obj.id,
            "entity_name": threat_obj.title,
            "severity": threat_obj.severity,
            "mitre_techniques": extracted,
            "tactics_count": len(tactic_set),
            "tactics": [MITRE_TACTICS[t] for t in sorted(tactic_set) if t in MITRE_TACTICS],
        }

    return {"error": "Unsupported entity type", "mitre_techniques": []}


def get_mitre_matrix_coverage() -> Dict[str, Any]:
    """
    Scan all active database threats (Malware, ThreatReports, Alerts) and compute
    the full Enterprise MITRE ATT&CK Matrix Heatmap & Tactic Coverage metrics.
    """
    all_tactics = get_all_tactics()

    # Dictionary: tactic_id -> { tactic_info, techniques: { tech_id -> tech_data } }
    matrix_grid: Dict[str, Dict[str, Any]] = {}
    for tac in all_tactics:
        matrix_grid[tac["id"]] = {
            "id": tac["id"],
            "name": tac["name"],
            "short_name": tac["short_name"],
            "description": tac["description"],
            "order": tac["order"],
            "total_observed_count": 0,
            "techniques": {},
        }

    observed_technique_ids: Set[str] = set()
    total_threat_occurrences = 0

    # 1. Process all Malware records
    malwares = Malware.query.all()
    for m in malwares:
        mapping = map_threat_to_mitre(m)
        for tech in mapping["mitre_techniques"]:
            tid = tech["id"]
            observed_technique_ids.add(tid)
            total_threat_occurrences += 1

            for tac_id in tech.get("tactics", []):
                if tac_id in matrix_grid:
                    grid_tac = matrix_grid[tac_id]
                    grid_tac["total_observed_count"] += 1
                    if tid not in grid_tac["techniques"]:
                        grid_tac["techniques"][tid] = {
                            "id": tid,
                            "name": tech["name"],
                            "parent_id": tech.get("parent_id"),
                            "url": tech.get("url"),
                            "detection": tech.get("detection"),
                            "mitigations": tech.get("mitigations", []),
                            "count": 0,
                            "max_severity": "Low",
                            "severity_level": 1,
                            "entities": [],
                        }

                    node = grid_tac["techniques"][tid]
                    node["count"] += 1
                    node["entities"].append({
                        "type": "Malware",
                        "id": m.id,
                        "name": m.malware_name,
                        "severity": m.severity,
                        "risk_score": m.risk_score,
                    })
                    # Severity escalation
                    sev = m.severity or "Medium"
                    sev_weights = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
                    if sev_weights.get(sev, 1) > node["severity_level"]:
                        node["severity_level"] = sev_weights.get(sev, 1)
                        node["max_severity"] = sev

    # 2. Process all Alerts (especially EDR / SIEM alerts)
    alerts = Alert.query.limit(500).all()
    for a in alerts:
        mapping = map_threat_to_mitre(a)
        for tech in mapping["mitre_techniques"]:
            tid = tech["id"]
            observed_technique_ids.add(tid)
            total_threat_occurrences += 1

            for tac_id in tech.get("tactics", []):
                if tac_id in matrix_grid:
                    grid_tac = matrix_grid[tac_id]
                    grid_tac["total_observed_count"] += 1
                    if tid not in grid_tac["techniques"]:
                        grid_tac["techniques"][tid] = {
                            "id": tid,
                            "name": tech["name"],
                            "parent_id": tech.get("parent_id"),
                            "url": tech.get("url"),
                            "detection": tech.get("detection"),
                            "mitigations": tech.get("mitigations", []),
                            "count": 0,
                            "max_severity": "Low",
                            "severity_level": 1,
                            "entities": [],
                        }

                    node = grid_tac["techniques"][tid]
                    node["count"] += 1
                    node["entities"].append({
                        "type": "Alert",
                        "id": a.id,
                        "name": a.title,
                        "severity": a.severity,
                    })
                    sev = a.severity or "Medium"
                    sev_weights = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
                    if sev_weights.get(sev, 1) > node["severity_level"]:
                        node["severity_level"] = sev_weights.get(sev, 1)
                        node["max_severity"] = sev

    # Calculate Tactic Coverage Metrics
    active_tactics_count = sum(1 for tac in matrix_grid.values() if tac["total_observed_count"] > 0)
    total_tactics = len(matrix_grid)
    coverage_pct = round((active_tactics_count / total_tactics) * 100, 1) if total_tactics > 0 else 0.0

    # Find top observed tactic
    top_tactic = max(matrix_grid.values(), key=lambda x: x["total_observed_count"], default=None)
    top_tactic_name = top_tactic["name"] if top_tactic and top_tactic["total_observed_count"] > 0 else "None"

    # Convert technique maps to sorted lists for each tactic
    sorted_grid: List[Dict[str, Any]] = []
    for tac in all_tactics:
        t_data = matrix_grid[tac["id"]]
        tech_list = list(t_data["techniques"].values())
        tech_list.sort(key=lambda x: (-x["count"], -x["severity_level"], x["id"]))
        t_data["techniques_list"] = tech_list
        sorted_grid.append(t_data)

    return {
        "status": "healthy",
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_tactics": total_tactics,
            "active_tactics": active_tactics_count,
            "coverage_percentage": coverage_pct,
            "unique_techniques_observed": len(observed_technique_ids),
            "total_threat_occurrences": total_threat_occurrences,
            "top_tactic": top_tactic_name,
        },
        "tactics": sorted_grid,
    }


# =============================================================================
# 5. MITRE ATT&CK NAVIGATOR LAYER v4.5 GENERATOR
# =============================================================================

def generate_attack_navigator_layer(layer_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate an official MITRE ATT&CK Navigator Layer JSON format (version 4.5).
    Can be imported directly into https://mitre-attack.github.io/attack-navigator/.
    """
    coverage = get_mitre_matrix_coverage()
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    techniques_layer: List[Dict[str, Any]] = []
    seen_technique_ids: Set[str] = set()

    for tac in coverage["tactics"]:
        for tech in tac["techniques_list"]:
            tid = tech["id"]
            if tid in seen_technique_ids:
                continue
            seen_technique_ids.add(tid)

            # Score: based on threat count & severity
            score = min(tech["count"] * 10 + tech["severity_level"] * 15, 100)
            
            # Color code: Critical = #ef4444 (red), High = #f59e0b (amber), Medium = #3b82f6 (blue)
            color = "#ef4444" if tech["max_severity"] == "Critical" else (
                "#f59e0b" if tech["max_severity"] == "High" else "#3b82f6"
            )

            entry: Dict[str, Any] = {
                "techniqueID": tid,
                "tactic": tac["short_name"],
                "score": score,
                "color": color,
                "comment": f"Observed in {tech['count']} threat instances in TIP (Max Severity: {tech['max_severity']})",
                "enabled": True,
                "metadata": [
                    {"name": "ThreatCount", "value": str(tech["count"])},
                    {"name": "MaxSeverity", "value": tech["max_severity"]},
                ],
            }
            techniques_layer.append(entry)

    layer_dict: Dict[str, Any] = {
        "name": layer_name or f"ThreatIntel Platform - Active Threats Layer ({now_str})",
        "versions": {
            "attack": "14",
            "navigator": "4.5",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": f"Exported from Threat Intelligence Platform. Total active techniques: {len(techniques_layer)}.",
        "gradient": {
            "colors": ["#10b981", "#3b82f6", "#f59e0b", "#ef4444"],
            "minValue": 0,
            "maxValue": 100
        },
        "legendItems": [
            {"label": "Critical Severity Threats", "color": "#ef4444"},
            {"label": "High Severity Threats", "color": "#f59e0b"},
            {"label": "Medium Severity Threats", "color": "#3b82f6"},
            {"label": "Low Severity / Baseline", "color": "#10b981"},
        ],
        "techniques": techniques_layer,
    }

    return layer_dict
