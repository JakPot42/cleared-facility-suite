"""seed_data.py — Demo scenarios, pre-baked KEV data, EPSS scores, extractions, and briefs."""

# ---------------------------------------------------------------------------
# Demo KEV catalog entries (subset of real CISA KEV catalog for demo CVEs)
# Source: CISA Known Exploited Vulnerabilities catalog (cisa.gov/known-exploited-vulnerabilities-catalog)
# ---------------------------------------------------------------------------
DEMO_KEV_DATA = {
    "CVE-2021-44228": {
        "cveID": "CVE-2021-44228",
        "vendorProject": "Apache",
        "product": "Log4j2",
        "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
        "dateAdded": "2021-12-10",
        "shortDescription": (
            "Apache Log4j2 contains a vulnerability where JNDI features used in configuration, "
            "log messages, and parameters do not protect against attacker-controlled LDAP and "
            "other JNDI endpoints, allowing remote code execution."
        ),
        "requiredAction": (
            "Apply updates per vendor instructions or discontinue use of affected software. "
            "Upgrade to Apache Log4j2 2.17.1 (Java 8), 2.12.4 (Java 7), or 2.3.2 (Java 6) or later."
        ),
        "dueDate": "2021-12-24",
        "knownRansomwareCampaignUse": "Known",
    },
    "CVE-2021-26855": {
        "cveID": "CVE-2021-26855",
        "vendorProject": "Microsoft",
        "product": "Exchange Server",
        "vulnerabilityName": "Microsoft Exchange Server Remote Code Execution Vulnerability",
        "dateAdded": "2021-03-03",
        "shortDescription": (
            "Microsoft Exchange Server contains a server-side request forgery (SSRF) vulnerability "
            "that allows an attacker to send arbitrary HTTP requests and authenticate as the "
            "Exchange server (ProxyLogon)."
        ),
        "requiredAction": (
            "Apply updates per vendor instructions. Microsoft has released patches for all "
            "supported Exchange Server versions."
        ),
        "dueDate": "2021-03-17",
        "knownRansomwareCampaignUse": "Known",
    },
    "CVE-2021-34527": {
        "cveID": "CVE-2021-34527",
        "vendorProject": "Microsoft",
        "product": "Windows Print Spooler",
        "vulnerabilityName": "Microsoft Windows Print Spooler Remote Code Execution Vulnerability",
        "dateAdded": "2021-07-13",
        "shortDescription": (
            "Microsoft Windows Print Spooler contains an unspecified vulnerability that allows "
            "for privilege escalation and remote code execution (PrintNightmare)."
        ),
        "requiredAction": (
            "Apply updates per vendor instructions or disable the Windows Print Spooler service "
            "on systems that do not require printing."
        ),
        "dueDate": "2021-07-20",
        "knownRansomwareCampaignUse": "Known",
    },
    "CVE-2022-30190": {
        "cveID": "CVE-2022-30190",
        "vendorProject": "Microsoft",
        "product": "Windows Support Diagnostic Tool (MSDT)",
        "vulnerabilityName": "Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability",
        "dateAdded": "2022-06-14",
        "shortDescription": (
            "Microsoft Windows Support Diagnostic Tool (MSDT) contains a vulnerability when "
            "called using the URL protocol from a calling application such as Word, allowing "
            "remote code execution if a user opens a specially crafted file (Follina)."
        ),
        "requiredAction": (
            "Apply updates per vendor instructions. Disable MSDT URL protocol as a temporary "
            "workaround until the patch is applied."
        ),
        "dueDate": "2022-06-28",
        "knownRansomwareCampaignUse": "Unknown",
    },
    "CVE-2022-1388": {
        "cveID": "CVE-2022-1388",
        "vendorProject": "F5",
        "product": "BIG-IP",
        "vulnerabilityName": "F5 BIG-IP iControl REST Authentication Bypass Vulnerability",
        "dateAdded": "2022-05-10",
        "shortDescription": (
            "F5 BIG-IP contains an authentication bypass vulnerability in the iControl REST "
            "component that allows an undisclosed request to bypass iControl REST authentication."
        ),
        "requiredAction": (
            "Apply updates per vendor instructions or apply the temporary workaround outlined "
            "in the F5 security advisory."
        ),
        "dueDate": "2022-05-31",
        "knownRansomwareCampaignUse": "Known",
    },
    "CVE-2023-20198": {
        "cveID": "CVE-2023-20198",
        "vendorProject": "Cisco",
        "product": "IOS XE",
        "vulnerabilityName": "Cisco IOS XE Web UI Privilege Escalation Vulnerability",
        "dateAdded": "2023-10-16",
        "shortDescription": (
            "Cisco IOS XE Web UI contains a privilege escalation vulnerability in the web UI "
            "feature that allows a remote, unauthenticated attacker to create an account on an "
            "affected system with privilege level 15 access."
        ),
        "requiredAction": (
            "Apply updates per vendor instructions. Disable HTTP Server feature on all internet-facing "
            "systems. See Cisco advisory cisco-sa-iosxe-webui-privesc-j22SaA4Z."
        ),
        "dueDate": "2023-10-19",
        "knownRansomwareCampaignUse": "Unknown",
    },
    "CVE-2023-28252": {
        "cveID": "CVE-2023-28252",
        "vendorProject": "Microsoft",
        "product": "Windows Common Log File System Driver",
        "vulnerabilityName": "Microsoft Windows Common Log File System (CLFS) Driver Privilege Escalation Vulnerability",
        "dateAdded": "2023-04-11",
        "shortDescription": (
            "Microsoft Windows Common Log File System (CLFS) driver contains an unspecified "
            "vulnerability that allows for privilege escalation."
        ),
        "requiredAction": "Apply updates per vendor instructions (April 2023 Patch Tuesday).",
        "dueDate": "2023-05-02",
        "knownRansomwareCampaignUse": "Unknown",
    },
    "CVE-2024-3400": {
        "cveID": "CVE-2024-3400",
        "vendorProject": "Palo Alto Networks",
        "product": "PAN-OS",
        "vulnerabilityName": "Palo Alto Networks PAN-OS Command Injection Vulnerability",
        "dateAdded": "2024-04-12",
        "shortDescription": (
            "Palo Alto Networks PAN-OS GlobalProtect gateway contains a command injection "
            "vulnerability that allows an unauthenticated attacker to execute arbitrary code "
            "with root privileges on the firewall."
        ),
        "requiredAction": (
            "Apply updates per vendor instructions. Palo Alto Networks has issued hotfixes. "
            "Disable GlobalProtect gateway and portal if immediate patching is not possible."
        ),
        "dueDate": "2024-04-19",
        "knownRansomwareCampaignUse": "Unknown",
    },
    "CVE-2024-21412": {
        "cveID": "CVE-2024-21412",
        "vendorProject": "Microsoft",
        "product": "Windows",
        "vulnerabilityName": "Microsoft Windows Internet Shortcut Files Security Feature Bypass Vulnerability",
        "dateAdded": "2024-02-13",
        "shortDescription": (
            "Microsoft Windows Internet Shortcut Files contain a security feature bypass "
            "vulnerability that allows an attacker to bypass SmartScreen by crafting a malicious "
            "Internet Shortcut (.url) file."
        ),
        "requiredAction": "Apply updates per vendor instructions (February 2024 Patch Tuesday).",
        "dueDate": "2024-03-05",
        "knownRansomwareCampaignUse": "Unknown",
    },
}

# CVEs NOT in KEV (present in demo scenarios for tier-range demonstration)
DEMO_NOT_IN_KEV = {"CVE-2023-44487", "CVE-2024-38063"}

# ---------------------------------------------------------------------------
# Demo EPSS scores (fixed for DEMO_MODE; live mode fetches from FIRST.org)
# EPSS: probability of exploitation in the next 30 days (0-1 scale)
# Source format: FIRST.org Exploit Prediction Scoring System
# ---------------------------------------------------------------------------
DEMO_EPSS_DATA = {
    "CVE-2021-44228": {"epss": 0.97480, "percentile": 0.99999},
    "CVE-2021-26855": {"epss": 0.97476, "percentile": 0.99999},
    "CVE-2021-34527": {"epss": 0.97345, "percentile": 0.99999},
    "CVE-2022-30190": {"epss": 0.92340, "percentile": 0.99890},
    "CVE-2022-1388":  {"epss": 0.97521, "percentile": 0.99999},
    "CVE-2023-20198": {"epss": 0.97320, "percentile": 0.99998},
    "CVE-2023-28252": {"epss": 0.08210, "percentile": 0.92340},
    "CVE-2024-3400":  {"epss": 0.94510, "percentile": 0.99940},
    "CVE-2024-21412": {"epss": 0.09840, "percentile": 0.93210},
    "CVE-2023-44487": {"epss": 0.04380, "percentile": 0.88120},
    "CVE-2024-38063": {"epss": 0.56000, "percentile": 0.97850},
}

# ---------------------------------------------------------------------------
# Demo scenarios
# ---------------------------------------------------------------------------
DEMO_SCENARIOS = [
    {
        "key": "aegis",
        "system_name": "Aegis Federal Enterprise Portal",
        "system_type": "Federal Government IT System",
        "system_criticality": "HIGH",
        "system_description": (
            "Web application portal serving 2,400 federal employees. Handles internal workflow "
            "routing, document management, and staff directory. Connects to mail infrastructure "
            "and external-facing network perimeter."
        ),
        "inventory_text": (
            "Apache Log4j 2.14.1 on 12 application servers (Tomcat 9.0 runtime). "
            "Microsoft Exchange Server 2016 CU22 on dedicated mail servers. "
            "Palo Alto Networks PAN-OS 10.2.3 on perimeter firewall. "
            "nginx 1.18 with HTTP/2 enabled on load balancers."
        ),
    },
    {
        "key": "vanguard",
        "system_name": "Vanguard Defense Systems Network",
        "system_type": "Defense Contractor Network",
        "system_criticality": "CRITICAL",
        "system_description": (
            "Internal corporate network for a defense contractor with DoD CMMC Level 2 "
            "obligations. Hosts CUI-bearing systems for program management and engineering "
            "collaboration. Multiple internet-accessible services."
        ),
        "inventory_text": (
            "F5 BIG-IP 14.x load balancer (iControl REST API exposed on management interface). "
            "Microsoft Exchange Server 2019 on corporate mail infrastructure. "
            "Cisco IOS XE 17.x with web console enabled on core routers. "
            "Windows Server 2019 domain controllers and file servers. "
            "Reverse proxy with HTTP/2 upstream."
        ),
    },
    {
        "key": "riverside",
        "system_name": "Riverside Municipal IT Infrastructure",
        "system_type": "State/Local Government IT",
        "system_criticality": "MEDIUM",
        "system_description": (
            "Municipal government IT environment supporting city operations including "
            "public works, permitting, and records management. Limited dedicated security "
            "staff; relies on shared IT resources across departments."
        ),
        "inventory_text": (
            "Windows Server 2019 on 8 domain controllers. "
            "Windows 10/11 workstations for 340 employees. "
            "Microsoft Office 365 with on-premises Outlook clients. "
            "Apache Tomcat 9.0 web services for permit portal. "
            "Web servers with HTTP/2 enabled."
        ),
    },
]

# ---------------------------------------------------------------------------
# Demo CVE extractions per scenario
# ---------------------------------------------------------------------------
DEMO_EXTRACTIONS = {
    "aegis": [
        {
            "cve_id": "CVE-2021-44228",
            "component": "Apache Log4j 2.14.1",
            "description": "Remote code execution via JNDI lookup in log messages (Log4Shell). Log4j versions 2.0-beta9 through 2.14.1 are vulnerable.",
        },
        {
            "cve_id": "CVE-2024-3400",
            "component": "Palo Alto Networks PAN-OS 10.2.3",
            "description": "OS command injection via GlobalProtect gateway session cookies. Allows unauthenticated root-level code execution on the firewall.",
        },
        {
            "cve_id": "CVE-2024-21412",
            "component": "Microsoft Windows (Internet Shortcut processing)",
            "description": "Security feature bypass allowing SmartScreen evasion via crafted .url shortcut files, enabling arbitrary code execution.",
        },
        {
            "cve_id": "CVE-2023-44487",
            "component": "nginx 1.18 (HTTP/2)",
            "description": "HTTP/2 Rapid Reset denial-of-service attack via rapid stream open/cancel cycles. Availability impact; does not allow code execution.",
        },
    ],
    "vanguard": [
        {
            "cve_id": "CVE-2022-1388",
            "component": "F5 BIG-IP 14.x (iControl REST API)",
            "description": "Authentication bypass in iControl REST allows unauthenticated attackers to execute arbitrary system commands with admin privileges.",
        },
        {
            "cve_id": "CVE-2021-26855",
            "component": "Microsoft Exchange Server 2019",
            "description": "Server-side request forgery (SSRF) allows unauthenticated attacker to send HTTP requests authenticated as the Exchange server (ProxyLogon). Pre-auth RCE when chained with CVE-2021-27065.",
        },
        {
            "cve_id": "CVE-2023-20198",
            "component": "Cisco IOS XE 17.x (Web UI)",
            "description": "Privilege escalation in web UI feature allows remote unauthenticated attacker to create a privilege level 15 account with full device control.",
        },
        {
            "cve_id": "CVE-2023-28252",
            "component": "Microsoft Windows Server 2019 (CLFS Driver)",
            "description": "Privilege escalation in Windows Common Log File System driver allows a local attacker to gain SYSTEM privileges.",
        },
        {
            "cve_id": "CVE-2024-38063",
            "component": "Windows Server 2019 (TCP/IP stack)",
            "description": "Integer underflow in Windows TCP/IP stack may allow an unauthenticated remote attacker to achieve remote code execution by sending specially crafted IPv6 packets.",
        },
    ],
    "riverside": [
        {
            "cve_id": "CVE-2022-30190",
            "component": "Microsoft Windows (MSDT / Office documents)",
            "description": "Remote code execution when MSDT is called via URL protocol from Office applications. Exploited via malicious Word documents (Follina). No user interaction beyond opening the document required.",
        },
        {
            "cve_id": "CVE-2021-34527",
            "component": "Windows Server 2019 (Print Spooler service)",
            "description": "Remote code execution via Windows Print Spooler service. Allows authenticated attacker to execute code with SYSTEM privileges (PrintNightmare).",
        },
        {
            "cve_id": "CVE-2023-28252",
            "component": "Windows 10/11 workstations (CLFS Driver)",
            "description": "Privilege escalation in Windows Common Log File System driver. Local attacker gains SYSTEM privileges.",
        },
        {
            "cve_id": "CVE-2024-21412",
            "component": "Windows 10/11 workstations (Internet Shortcut files)",
            "description": "SmartScreen security feature bypass via crafted .url files. Allows phishing attacks to execute arbitrary code without SmartScreen warnings.",
        },
        {
            "cve_id": "CVE-2024-38063",
            "component": "Windows Server 2019 / Windows 10 (TCP/IP stack)",
            "description": "Integer underflow in TCP/IP stack potentially allowing remote code execution via specially crafted IPv6 packets.",
        },
    ],
}

# ---------------------------------------------------------------------------
# Demo patch briefs per scenario
# ---------------------------------------------------------------------------
DEMO_BRIEFS = {
    "aegis": """\
## Patch Prioritization Brief — Aegis Federal Enterprise Portal
**Assessment Date:** 2026-06-20 | **System Criticality:** HIGH | **CVEs Assessed:** 4

---

## Executive Summary

The Aegis Federal Enterprise Portal presents **4 vulnerabilities** across assessed components, including **2 CRITICAL** items with confirmed active exploitation and **1 HIGH** item requiring urgent action. Two vulnerabilities — CVE-2021-44228 (Log4Shell) and CVE-2024-3400 (PAN-OS) — appear in CISA's Known Exploited Vulnerabilities (KEV) catalog with EPSS scores exceeding 0.94, indicating adversaries are actively exploiting these vectors at scale. Immediate remediation of all KEV-listed items is required per applicable federal directives (⚠ VERIFY current BOD 22-01 deadlines against CISA's current directive language before finalizing schedule).

---

## CRITICAL Priority — Patch Within 24–48 Hours

### CVE-2021-44228 — Apache Log4j2 Remote Code Execution (Log4Shell)
**Priority Score: 100/100 | CISA KEV: YES (Added 2021-12-10) | Ransomware: Known | EPSS: 0.9748 (99.9th percentile)**

CVE-2021-44228 is listed in CISA's KEV catalog, confirming active exploitation in the wild. Known ransomware campaigns actively leverage this vulnerability. The EPSS score of 0.9748 indicates a 97.5% probability of exploitation attempts within the next 30 days — the highest tier of exploitation likelihood. Unauthenticated remote code execution via JNDI lookup in log messages enables complete system compromise on any host running Apache Log4j 2.x through 2.14.1.

**Affected component:** Apache Log4j 2.14.1 on 12 application servers.

**Required action:** Upgrade Apache Log4j2 to 2.17.1 or later (Java 8), 2.12.4 (Java 7), or 2.3.2 (Java 6). Interim mitigation: set `log4j2.formatMsgNoLookups=true` or remove the JndiLookup class from the classpath.

---

### CVE-2024-3400 — Palo Alto Networks PAN-OS OS Command Injection
**Priority Score: 95/100 | CISA KEV: YES (Added 2024-04-12) | Ransomware: Unknown | EPSS: 0.9451 (99.9th percentile)**

CVE-2024-3400 is a zero-day OS command injection in PAN-OS GlobalProtect added to CISA's KEV catalog on April 12, 2024, with evidence of targeted exploitation prior to patch availability. EPSS score of 0.9451 places it in the 99.9th percentile of all CVEs by exploitation likelihood. Unauthenticated command injection via crafted GlobalProtect session cookies enables root-level code execution on the perimeter firewall — a critical chokepoint for network defense.

**Affected component:** Palo Alto Networks PAN-OS 10.2.3 on perimeter firewall.

**Required action:** Apply PAN-OS hotfix (10.2.9-h1 or later for 10.2.x). If immediate patching is not possible, disable GlobalProtect gateway and portal as a temporary mitigation and apply Threat Prevention signatures.

---

## HIGH Priority — Patch Within 7 Days

### CVE-2024-21412 — Microsoft Windows Internet Shortcut Security Feature Bypass
**Priority Score: 57/100 | CISA KEV: YES (Added 2024-02-13) | Ransomware: Unknown | EPSS: 0.0984 (93.2nd percentile)**

CVE-2024-21412 is listed in CISA's KEV catalog as an actively exploited bypass of Windows SmartScreen. The EPSS score of 0.0984 (9.8% exploitation probability in 30 days, 93.2nd percentile) is lower than the CRITICAL items but KEV listing confirms real-world adversary use. Attackers craft malicious .url shortcut files that execute arbitrary code when opened by a user, bypassing standard SmartScreen warnings. This has been observed in phishing campaigns targeting federal employees.

**Affected component:** Microsoft Windows Internet Shortcut file processing on all Windows hosts.

**Required action:** Apply February 2024 Microsoft Patch Tuesday cumulative update.

---

## LOW Priority — Monitor and Schedule

### CVE-2023-44487 — HTTP/2 Rapid Reset Denial of Service
**Priority Score: 5/100 | CISA KEV: NO | Ransomware: N/A | EPSS: 0.0438 (88.1st percentile)**

CVE-2023-44487 is NOT in CISA's KEV catalog. This is an availability (denial-of-service) vulnerability — not a confidentiality or integrity threat — that does not allow remote code execution or privilege escalation. EPSS score of 0.0438 (4.4% exploitation probability, 88.1st percentile) reflects moderate exploitation interest but low conversion to actual attacks against typical targets. The absence from KEV and lower EPSS relative to other items places this in the lowest priority tier.

**Affected component:** nginx 1.18 load balancers (HTTP/2 rapid stream reset attack).

**Required action:** Upgrade nginx to 1.25.3 or later, or configure HTTP/2 connection limits. Schedule during next maintenance window.

---

## Recommended Patch Schedule

| Priority | CVE ID | Component | Action | Target |
|---|---|---|---|---|
| CRITICAL | CVE-2021-44228 | Apache Log4j 2.14.1 | Upgrade to 2.17.1+ | 24 hours |
| CRITICAL | CVE-2024-3400 | Palo Alto PAN-OS 10.2.3 | Apply hotfix 10.2.9-h1+ | 24 hours |
| HIGH | CVE-2024-21412 | Windows (all hosts) | Apply Feb 2024 Patch Tuesday | 7 days |
| LOW | CVE-2023-44487 | nginx 1.18 | Upgrade to 1.25.3+ | Next maintenance window |

---
*KEV data: CISA Known Exploited Vulnerabilities catalog. EPSS scores: FIRST.org Exploit Prediction Scoring System. ⚠ VERIFY BOD 22-01 remediation deadlines against current CISA directive language before finalizing patch schedule.*\
""",

    "vanguard": """\
## Patch Prioritization Brief — Vanguard Defense Systems Network
**Assessment Date:** 2026-06-20 | **System Criticality:** CRITICAL | **CVEs Assessed:** 5

---

## Executive Summary

The Vanguard Defense Systems Network presents **5 vulnerabilities** across assessed components, including **3 CRITICAL** items with confirmed active exploitation, **1 HIGH**, and **1 MEDIUM**. Three KEV-listed vulnerabilities — CVE-2022-1388, CVE-2021-26855, and CVE-2023-20198 — carry EPSS scores exceeding 0.97, representing the most actively exploited CVEs in the current threat landscape. Given CRITICAL system criticality and CUI-bearing systems, any successful exploitation presents a direct risk to DoD program data. CMMC Level 2 assessment readiness requires all KEV items to be remediated per applicable CMMC requirements (⚠ VERIFY current CMMC v2.0 assessment guide requirements and timelines with your C3PAO before finalizing schedule).

---

## CRITICAL Priority — Patch Within 24–48 Hours

### CVE-2022-1388 — F5 BIG-IP iControl REST Authentication Bypass
**Priority Score: 100/100 | CISA KEV: YES (Added 2022-05-10) | Ransomware: Known | EPSS: 0.9752 (99.9th percentile)**

CVE-2022-1388 is a pre-authentication bypass in the F5 BIG-IP iControl REST API with KEV listing confirmed on May 10, 2022. Known ransomware groups actively exploit this to establish initial access. EPSS score of 0.9752 — the highest of all assessed CVEs — reflects sustained active exploitation two years post-disclosure. An unauthenticated attacker with network access to the management interface can execute arbitrary system commands with admin privileges, effectively taking full control of the load balancer and all traffic flowing through it.

**Affected component:** F5 BIG-IP 14.x (iControl REST API on management interface).

**Required action:** Upgrade to BIG-IP 16.1.x or later. If immediate upgrade is not possible, restrict iControl REST access to trusted management networks only and disable public internet access to the management interface.

---

### CVE-2021-26855 — Microsoft Exchange Server ProxyLogon (Pre-Auth RCE)
**Priority Score: 100/100 | CISA KEV: YES (Added 2021-03-03) | Ransomware: Known | EPSS: 0.9748 (99.9th percentile)**

CVE-2021-26855 (ProxyLogon) is a server-side request forgery vulnerability in Exchange Server that authenticates the attacker as the Exchange server itself. KEV-listed since March 3, 2021. Known ransomware campaigns routinely use this as an initial access vector. When chained with CVE-2021-27065 (post-auth arbitrary file write), it enables full pre-authentication remote code execution on the Exchange server. EPSS score of 0.9748 reflects persistent exploitation activity more than three years post-disclosure — unpatched Exchange servers are being actively swept by threat actors.

**Affected component:** Microsoft Exchange Server 2019 on corporate mail infrastructure.

**Required action:** Apply all Microsoft Exchange Server Cumulative Updates. Ensure the March 2021 security updates are applied at minimum; apply all subsequent CUs. Restrict Exchange to internal networks where external access is not required.

---

### CVE-2023-20198 — Cisco IOS XE Web UI Privilege Escalation
**Priority Score: 98/100 | CISA KEV: YES (Added 2023-10-16) | Ransomware: Unknown | EPSS: 0.9732 (99.9th percentile)**

CVE-2023-20198 allows an unauthenticated attacker to create a privilege level 15 account via the Cisco IOS XE web UI, granting full device control without credentials. CISA added this to KEV on October 16, 2023 following widespread exploitation — over 40,000 Cisco devices were compromised in the initial wave. EPSS score of 0.9732 reflects continued active exploitation activity. Compromise of core routers in a defense contractor network could expose all inter-segment traffic and enable lateral movement.

**Affected component:** Cisco IOS XE 17.x with web console enabled on core routers.

**Required action:** Apply Cisco IOS XE security patch (see cisco-sa-iosxe-webui-privesc-j22SaA4Z). Immediately disable the HTTP Server feature: `no ip http server` / `no ip http secure-server`. Restrict web UI access to management VLAN only.

---

## HIGH Priority — Patch Within 7 Days

### CVE-2023-28252 — Windows CLFS Driver Privilege Escalation
**Priority Score: 58/100 | CISA KEV: YES (Added 2023-04-11) | Ransomware: Unknown | EPSS: 0.0821 (92.3rd percentile)**

CVE-2023-28252 is listed in CISA's KEV catalog as an actively exploited local privilege escalation in the Windows Common Log File System driver. The EPSS score of 0.0821 (8.2% exploitation probability, 92.3rd percentile) is significantly lower than the CRITICAL items but KEV listing confirms real-world exploitation. This vulnerability requires local access to exploit but enables escalation from a standard user account to SYSTEM — making it a critical step in post-exploitation chains.

**Affected component:** Windows Server 2019 domain controllers and file servers.

**Required action:** Apply April 2023 Microsoft Patch Tuesday cumulative update.

---

## MEDIUM Priority — Patch Within 30 Days

### CVE-2024-38063 — Microsoft Windows TCP/IP Remote Code Execution
**Priority Score: 30/100 | CISA KEV: NO | Ransomware: N/A | EPSS: 0.5600 (97.9th percentile)**

CVE-2024-38063 is NOT in CISA's KEV catalog — no confirmed active exploitation as of assessment date. However, the EPSS score of 0.5600 (56% exploitation probability, 97.9th percentile) reflects significant security community concern about a wormable integer underflow in the Windows TCP/IP stack exploitable via specially crafted IPv6 packets. Given CRITICAL system criticality, this is elevated from what would be LOW in a standard system. Patch before the next quarterly cycle.

**Affected component:** Windows Server 2019 systems with IPv6 enabled.

**Required action:** Apply August 2024 Microsoft Patch Tuesday update. If IPv6 is not required, disable it as a defense-in-depth measure.

---

## Recommended Patch Schedule

| Priority | CVE ID | Component | Action | Target |
|---|---|---|---|---|
| CRITICAL | CVE-2022-1388 | F5 BIG-IP 14.x | Upgrade to 16.1.x or restrict mgmt access | 24 hours |
| CRITICAL | CVE-2021-26855 | Exchange Server 2019 | Apply all CUs; restrict external access | 24 hours |
| CRITICAL | CVE-2023-20198 | Cisco IOS XE 17.x | Patch + disable web UI on internet-facing | 24 hours |
| HIGH | CVE-2023-28252 | Windows Server 2019 | Apply Apr 2023 Patch Tuesday | 7 days |
| MEDIUM | CVE-2024-38063 | Windows (TCP/IP) | Apply Aug 2024 Patch Tuesday | 30 days |

---
*KEV data: CISA Known Exploited Vulnerabilities catalog. EPSS scores: FIRST.org Exploit Prediction Scoring System. ⚠ VERIFY CMMC v2.0 patch timeline requirements with your C3PAO and applicable DoD directives before finalizing schedule.*\
""",

    "riverside": """\
## Patch Prioritization Brief — Riverside Municipal IT Infrastructure
**Assessment Date:** 2026-06-20 | **System Criticality:** MEDIUM | **CVEs Assessed:** 5

---

## Executive Summary

The Riverside Municipal IT Infrastructure presents **5 vulnerabilities** across assessed components, including **2 CRITICAL** items with confirmed active exploitation, **2 HIGH**, and **1 MEDIUM**. Two KEV-listed vulnerabilities — CVE-2022-30190 (Follina) and CVE-2021-34527 (PrintNightmare) — with EPSS scores exceeding 0.92 represent confirmed active exploitation vectors that have been observed against local government targets specifically. Ransomware groups targeting municipal governments frequently leverage PrintNightmare in post-exploitation chains. Prioritize the two CRITICAL items before all other IT work.

---

## CRITICAL Priority — Patch Within 24–48 Hours

### CVE-2022-30190 — Microsoft Windows MSDT Remote Code Execution (Follina)
**Priority Score: 92/100 | CISA KEV: YES (Added 2022-06-14) | Ransomware: Unknown | EPSS: 0.9234 (99.9th percentile)**

CVE-2022-30190 (Follina) is a zero-click-adjacent remote code execution vulnerability where Office applications call MSDT via URL protocol to execute attacker-controlled payloads. KEV-listed June 14, 2022. EPSS score of 0.9234 (92.3% exploitation probability, 99.9th percentile) reflects sustained exploitation. This vulnerability is particularly dangerous in a municipal environment with employees routinely opening documents from external parties (permit applications, contracts, correspondence). A phishing email containing a malicious Word document is sufficient to achieve full user-level code execution without macros.

**Affected component:** Microsoft Windows MSDT on all Windows hosts with Office/Outlook clients.

**Required action:** Apply June 2022 Microsoft Patch Tuesday update. If immediate patching is not possible, disable MSDT URL protocol as a temporary mitigation: `reg delete HKEY_CLASSES_ROOT\ms-msdt /f`.

---

### CVE-2021-34527 — Windows Print Spooler Remote Code Execution (PrintNightmare)
**Priority Score: 99/100 | CISA KEV: YES (Added 2021-07-13) | Ransomware: Known | EPSS: 0.9735 (99.9th percentile)**

CVE-2021-34527 (PrintNightmare) is a remote code execution vulnerability in the Windows Print Spooler service. KEV-listed July 13, 2021. Known ransomware campaigns actively exploit this for SYSTEM-level privilege escalation — it has been a staple in ransomware toolkits targeting municipal governments for over three years. EPSS score of 0.9735 (97.4% exploitation probability, 99.9th percentile) reflects persistent exploitation activity. With 8 domain controllers exposed, compromise of Print Spooler enables domain-wide impact.

**Affected component:** Windows Server 2019 domain controllers and Windows 10/11 workstations (Print Spooler service).

**Required action:** Apply July 2021 security updates immediately. As defense-in-depth, disable the Print Spooler service on systems that do not require printing, especially domain controllers. Restrict Point and Print to authorized servers only.

---

## HIGH Priority — Patch Within 7 Days

### CVE-2023-28252 — Windows CLFS Driver Privilege Escalation
**Priority Score: 54/100 | CISA KEV: YES (Added 2023-04-11) | Ransomware: Unknown | EPSS: 0.0821 (92.3rd percentile)**

CVE-2023-28252 is in CISA's KEV catalog as an actively exploited local privilege escalation in the Windows Common Log File System driver. EPSS score of 0.0821 (8.2% probability, 92.3rd percentile). Requires local access but enables SYSTEM-level escalation from a standard user account, making it a commonly observed post-exploitation step after phishing-based initial access.

**Affected component:** Windows 10/11 workstations (340 endpoints).

**Required action:** Apply April 2023 Microsoft Patch Tuesday cumulative update.

---

### CVE-2024-21412 — Windows Internet Shortcut Security Feature Bypass
**Priority Score: 55/100 | CISA KEV: YES (Added 2024-02-13) | Ransomware: Unknown | EPSS: 0.0984 (93.2nd percentile)**

CVE-2024-21412 is in CISA's KEV catalog as an actively exploited SmartScreen bypass. EPSS score of 0.0984 (9.8% probability, 93.2nd percentile). Observed in targeted phishing campaigns delivering malicious .url shortcut files that execute arbitrary code without SmartScreen warnings. Municipal employees processing public-submitted documents are a common target vector.

**Affected component:** Windows 10/11 workstations (340 endpoints).

**Required action:** Apply February 2024 Microsoft Patch Tuesday cumulative update.

---

## MEDIUM Priority — Patch Within 30 Days

### CVE-2024-38063 — Microsoft Windows TCP/IP Remote Code Execution
**Priority Score: 26/100 | CISA KEV: NO | Ransomware: N/A | EPSS: 0.5600 (97.9th percentile)**

CVE-2024-38063 is NOT in CISA's KEV catalog — no confirmed active exploitation as of assessment date. The EPSS score of 0.5600 (56% exploitation probability, 97.9th percentile) reflects significant security community concern, but the absence from KEV and MEDIUM system criticality places this in MEDIUM tier. An integer underflow in the TCP/IP stack is potentially exploitable via IPv6, but requires network access that is typically gated by perimeter controls.

**Affected component:** Windows Server 2019 and Windows 10/11 (IPv6-enabled systems).

**Required action:** Apply August 2024 Microsoft Patch Tuesday update. Review whether IPv6 is operationally required; disable if not needed.

---

## Recommended Patch Schedule

| Priority | CVE ID | Component | Action | Target |
|---|---|---|---|---|
| CRITICAL | CVE-2022-30190 | Windows (MSDT) | Apply Jun 2022 Patch Tuesday; disable MSDT URL protocol | 24 hours |
| CRITICAL | CVE-2021-34527 | Windows (Print Spooler) | Apply Jul 2021 update; disable spooler on DCs | 24 hours |
| HIGH | CVE-2024-21412 | Windows 10/11 workstations | Apply Feb 2024 Patch Tuesday | 7 days |
| HIGH | CVE-2023-28252 | Windows 10/11 workstations | Apply Apr 2023 Patch Tuesday | 7 days |
| MEDIUM | CVE-2024-38063 | Windows (TCP/IP) | Apply Aug 2024 Patch Tuesday | 30 days |

---
*KEV data: CISA Known Exploited Vulnerabilities catalog. EPSS scores: FIRST.org Exploit Prediction Scoring System. Note: local governments may be eligible for free CISA cybersecurity assessments and patch prioritization assistance through CISA's State, Local, Tribal, and Territorial (SLTT) program. ⚠ VERIFY current CISA SLTT program availability and BOD 22-01 applicability to municipal systems before citing in formal documentation.*\
""",
}


# ---------------------------------------------------------------------------
# Seed loader
# ---------------------------------------------------------------------------
def load_seed_data(db):
    """Idempotent seed — skips any scenario whose system_name already exists."""
    from datetime import datetime

    from .models import Scan, VulnItem
    from .priority_engine import score_vuln, _build_rationale
    from . import kev_client
    from . import epss_client

    for scenario in DEMO_SCENARIOS:
        if db.query(Scan).filter_by(system_name=scenario["system_name"]).first():
            continue

        scan = Scan(
            system_name=scenario["system_name"],
            system_type=scenario["system_type"],
            system_criticality=scenario["system_criticality"],
            system_description=scenario["system_description"],
            inventory_text=scenario["inventory_text"],
            status="BRIEF_READY",
            patch_brief_text=DEMO_BRIEFS[scenario["key"]],
            brief_generated_at=datetime.utcnow(),
        )
        db.add(scan)
        db.flush()

        for item_data in DEMO_EXTRACTIONS[scenario["key"]]:
            cve_id = item_data["cve_id"]
            kev_entry = kev_client.lookup_kev(cve_id, demo_mode=True)
            epss_data = epss_client.fetch_epss(cve_id, demo_mode=True)
            result = score_vuln(cve_id, kev_entry, epss_data, scenario["system_criticality"])

            item = VulnItem(
                scan_id=scan.id,
                component=item_data["component"],
                cve_id=cve_id,
                cve_description=item_data["description"],
                in_kev=result["in_kev"],
                kev_vendor_project=result.get("kev_vendor_project"),
                kev_product=result.get("kev_product"),
                kev_vulnerability_name=result.get("kev_vulnerability_name"),
                kev_date_added=result.get("kev_date_added"),
                kev_ransomware_use=result.get("kev_ransomware_use", False),
                kev_required_action=result.get("kev_required_action"),
                kev_due_date=result.get("kev_due_date"),
                kev_short_description=result.get("kev_short_description"),
                epss_score=result["epss_score"],
                epss_percentile=result["epss_percentile"],
                priority_score=result["priority_score"],
                priority_tier=result["priority_tier"],
                engine_rationale=result["rationale"],
            )
            db.add(item)

    db.commit()
