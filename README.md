# Useful Free/Open Source Cyber Security Tools/Resources
A list of free or open source tools or resources that have proven useful over the years.

## Table of Contents
* [Security Engineering](#Security-Engineering)
  * [Active Directory Security](#active-directory-security)
  * [M365 / Entra ID Security](#m365--entra-id-security)
  * [Azure Security](#Azure-Security)
  * [OS Security](#OS-Security)
  * [Application Security](#application-security)
* [Security Operations](#Security-Operations)
  * [Incident Response Tactical](#Incident-response-tactical)
  * [Incident Response Management](#Incident-response-management)
  * [Detection Engineering](#Detection-engineering)
  * [Threat Hunting](#Threat-Hunting)
  * [Cyber Threat Intelligence](#Cyber-Threat-Intelligence)
  * [Vulnerability Management](#vulnerability-management)
  * [Deception](#Deception)
  * [SOC](#Security-Operations-centre)
* [Security Testing](#Security-testing)
* [Table Top Exercises](#Table-top-exercises)
* [Block Lists](#Block-Lists)
* [Organisation OSINT](#Org-OSINT)
* [Lab Resources](#lab-resources)
* [Cheat Sheets](#Cheat-Sheets)
* [Misc Guides](#Misc-Guides)
* [Misc](#misc)

## Security Engineering
### Active Directory Security
| Tool | Description |
| --- | --- |
|[Ping Castle](https://www.pingcastle.com/) | "Get Active Directory Security at 80% in 20% of the time" (See also: [Ping Castle Notify](https://github.com/LuccaSA/PingCastle-Notify))|
|[Script Sentry](https://github.com/techspence/ScriptSentry) | ScriptSentry finds misconfigured and dangerous logon scripts |
|[Locksmith](https://github.com/jakehildreth/Locksmith) | A small tool built to find and fix common misconfigurations in Active Directory Certificate Services |
|[ADeliginator](https://github.com/techspence/ADeleginator) | A companion tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory |
|[GPOZaurr](https://github.com/EvotecIT/GPOZaurr) | Group Policy Eater is a PowerShell module that aims to gather information about Group Policies but also allows fixing issues that you may find in them |
|[Group3r](https://github.com/Group3r/Group3r) | Find vulnerabilities in AD Group Policy |
|[ADSecurity.org](https://adsecurity.org/) | Sean Metcalf ([@PyroTek3](https://x.com/PyroTek3)) is the Identity Security Architect at TrustedSec. Sean performs Windows, Active Directory, & Entra ID security research, the results of which he shares at conferences and on ADSecurity.org |
|[AD Attack Defence](https://github.com/infosecn1nja/AD-Attack-Defense) | Informational asset for those looking to understand the specific tactics, techniques, and procedures (TTPs) attackers are leveraging to compromise active directory and guidance to mitigation, detection, and prevention. |
|[AD Hardening](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-1-%e2%80%93-disabling-ntlmv1/3934787) | Active Directory Hardening Series from Microsoft |

### M365 / Entra ID Security
| Tool | Description |
| --- | --- |
|[Conditional Access Baseline](https://github.com/j0eyv/ConditionalAccessBaseline) | [Joey Verlinden's](https://github.com/j0eyv) Conditional access Baseline |
|[Risk Based CAPs](https://github.com/nathanmcnulty/nathanmcnulty/tree/main/Entra/conditional-access/risk-policies) | [Nathan McNulty's](https://github.com/nathanmcnulty) Risk Based Conditional Access Policies |
|[Maestre](https://maester.dev/docs/intro) | Maester is a PowerShell based test automation framework to help you stay in control of your Microsoft security configuration |
|[Monkey365](https://github.com/silverhack/monkey365) | Monkey365 provides a tool for security consultants to easily conduct not only Microsoft 365, but also Azure subscriptions and Microsoft Entra ID security configuration reviews |
|[SCUBAGear](https://github.com/cisagov/ScubaGear) | Automation to assess the state of your M365 tenant against CISA's baselines |
|[Least Privileged Roles by Task](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/delegate-by-task) | This article describes the least privileged role you should use for several tasks in Microsoft Entra ID |
|[Restricted Management Admin Units](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management) | Restricted management administrative units allow you to protect specific objects in your tenant from modification by anyone other than a specific set of people that you designate. This allows you to meet security or compliance requirements without having to remove tenant-level role assignments from your administrators |
|[Entra ID Power Apps](https://idpowertoys.merill.net/) | idPowerApp is a collection of mini-apps for Microsoft Entra |
|[AzureAD Attack Defence](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense) | This publication is a collection of various common attack scenarios on Microsoft Entra ID (formerly known as Azure Active Directory) and how they can be mitigated or detected |
|[NoPrompt](https://github.com/NotSoSecure/NoPrompt) | NoPrompt is a lightweight security testing tool that checks if Microsoft Entra ID (Azure AD) APIs and login portals allow password-only authentication — meaning access with just a username and password, without requiring Multi-Factor Authentication (MFA) |
|[AzureHound](https://github.com/SpecterOps/AzureHound) | Azure Data Exporter for BloodHound |
|[SecOps for Entra ID](https://learn.microsoft.com/en-us/entra/architecture/security-operations-introduction) | Microsoft Entra security operations guide |

### Azure Security
| Tool | Description |
| --- | --- |
|[Azure Best Practices](https://learn.microsoft.com/en-us/azure/security/fundamentals/best-practices-and-patterns) | This article contains security best practices to use when you're designing, deploying, and managing your cloud solutions by using Azure. These best practices come from our experience with Azure security and the experiences of customers like you |
|[Azure Security Assessment](https://github.com/NetSPI/MicroBurst) | Functions and scripts that support Azure Services discovery, weak configuration auditing, and post exploitation actions such as credential dumping |
|[Azure Red Team](https://github.com/rootsecdev/Azure-Red-Team) | Azure Security Resources and Notes |
|[Azure Attack Paths](https://cloudbrothers.info/en/azure-attack-paths/) | Known Azure attack paths |

### OS Security
| Tool | Description |
| --- | --- |
|[MSRC-PatchReview](https://github.com/f-bader/MSRC-PatchReview) | Powershell script to review Microsoft Patch Tuesday |
|[Harden Windows Security](https://github.com/HotCakeX/Harden-Windows-Security) | Harden Windows Safely, Securely using Official Supported Microsoft methods and proper explanation |
|[PrivEscCheck](https://github.com/itm4n/PrivescCheck) | Windows. Privilege Escalation Enumeration Script for Windows |
|[Harden Windows Security](https://github.com/HotCakeX/Harden-Windows-Security/wiki/) | Harden Windows Safely, Securely, Only With Official Microsoft Methods |
|[Security Hardening](https://github.com/decalage2/awesome-security-hardening) | Various. Security hardening guides, best practices, checklists, benchmarks, tools and other resources |
[AppLockerInspector](https://github.com/techspence/AppLockerInspector) | Windows. Audits an AppLocker policy XML and reports weak/misconfigured/risky settings, including actual ACL checks |

### Application Security
| Tools | Description |
| --- | --- |
|[ThreatMapper](https://github.com/deepfence/ThreatMapper) | Open Source Cloud Native Application Protection Platform cloud, containers, serverless and on-prem |
|[DevSecOps Library](https://github.com/sottlmarek/DevSecOps) | This library contains list of tools and methodologies accompanied with resources. The main goal is to provide to the engineers a guide through opensource DevSecOps tooling |
|[Web App Security Assessment Methodology](https://github.com/tprynn/web-methodology/wiki) | Web application security assessment methodology |
|[SharpSCCM](https://github.com/Mayyhem/SharpSCCM/wiki) | SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr, formerly SCCM) for credential gathering and lateral movement without requiring access to the SCCM administration console GUI. |
|[SCCMHunter](https://github.com/garrettfoster13/sccmhunter) | SCCMHunter is a post-ex tool built to streamline identifying, profiling, and attacking SCCM related assets in an Active Directory domain |

## Security Operations

### Incident Response Tactical
| Tool | Description |
| --- | --- |
|[URLScan](https://urlscan.io/) | urlscan.io is a free service to scan and analyze potentially malicious websites |
|[Any.Run](https://app.any.run/) | Interactive online malware analysis service for dynamic and static research of most types of threats using any environments |
|[Talos](https://www.talosintelligence.com/reputation_center) | The Talos Intelligence Center is the world’s most comprehensive real-time threat detection network |
|[MXToolbox](https://mxtoolbox.com/) | All of your MX record, DNS, blacklist and SMTP diagnostics in one integrated tool |
|[VirusTotal](https://www.virustotal.com/gui/home/upload) | Analyse suspicious files, domains, IPs and URLs to detect malware and other breaches, *automatically share them with the security community* |
|[SOCRadar](https://socradar.io/labs/) | SOCRadar LABS is a new and developing platform which informs users about existing and possible cyber threats with the help of several cyber threat intelligence services |
|[AbuseIPDB](https://www.abuseipdb.com/) | AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet |

### Incident Response Management
| Tool | Description |
| --- | --- |
|[Microsoft IT Ninja Hub](https://aka.ms/MicrosoftIRNinjaHub) | Microsoft Incident Response Ninja Hub |
|[NIST IR Reccomendations](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf) | Help organizations incorporate cybersecurity incident response recommendations and considerations throughout their cybersecurity risk management activities |
|[IR Playbooks](https://github.com/certsocietegenerale/IRM) | List of best practice playbooks for a variety of security incidents |
|[Alerting and Detection Strategy Framework](https://github.com/palantir/alerting-detection-strategy-framework) | A framework for developing alerting and detection strategies for incident response |
|[Practical Ransomware Response](https://m365internals.com/2022/09/19/practical-guidance-for-it-admins-to-respond-to-ransomware-attacks/) | Hire an IR firm. If you are too cheap for that, do this instead |

### Detection Engineering
| Tool | Description |
| --- | --- |
|[DetEng Resources](https://github.com/infosecB/awesome-detection-engineering) | A collated list of Detection Engineering resources |
|[OpenTide](https://github.com/opentidehq/) | Open Threat Informed Detection Engineering is a comprehensive framework to enable Threat & Detection Modelling and Detection-as-Code in a unified workflow |
|[Hunting Queries and Detection Rules](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules) | Library of KQL detection and hunting queries from the excellent [Bert JanP](https://github.com/Bert-JanP) |
|[Anvillogic Forge](https://github.com/anvilogic-forge/armory) | Library of sigma detection rules |
|[MAGMa Use Case Framework](https://www.betaalvereniging.nl/wp-content/uploads/FI-ISAC-use-case-framework-verkorte-versie.pdf) | MaGMa: a framework and tool for use case management |

### Threat Hunting
| Tool | Description |
| --- | --- |
|[PEAK TH Framework](https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html) | Prepare, Execute and Act with Knowledge |
|[Threat Detection and Hunting](https://github.com/0x4D31/awesome-threat-detection) | Curated list of Thrreat Hunting Resources |
|[Threat Hunting Lists](https://github.com/mthcht/awesome-lists/tree/main) | Threat Hunting lists and keywords |
|[Hunting Exchange and Reasearch Threat Hub](https://github.com/THORCollective/HEARTH) | HEARTH is a centralized, open-source platform for security professionals to share, discover, and collaborate on threat hunting hypotheses |

### Cyber Threat Intelligence
| Tool | Description |
| --- | --- |
|[Bert-JanP Threat Intel Feeds](https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds) | Open Source freely usable Threat Intel feeds that can be used without additional requirements |
|[OpenCTI](https://github.com/OpenCTI-Platform/opencti) | OpenCTI is an open source platform allowing organizations to manage their cyber threat intelligence knowledge and observables |
|[Open Source CTI](https://github.com/BushidoUK/Open-source-tools-for-CTI) | Public Repository of Open Source Tools for Cyber Threat Intelligence Analysts and Researchers |
|[OpenSquat](https://github.com/atenreiro/opensquat) | The openSquat is an open-source tool for detecting domain look-alikes by searching for newly registered domains that might be impersonating legit domains and brands |
|[Threat Intelligence Platforms](https://gist.github.com/Te-k/2a5a1885249cfd07f417b47d291c4b98) | A list of threat intelligence platforms |
|[DarkDump](https://github.com/josh0xA/darkdump) | OSINT interface for carrying out deep web investgations |
|[DNSTwist](https://dnstwist.it/) | See what sort of trouble users can get in trying to type your domain name. Find lookalike domains that adversaries can use to attack you. Can detect typosquatters, phishing attacks, fraud, and brand impersonation. Useful as an additional source of targeted threat intelligence |

### Vulnerability Management
| Tool | Description |
| --- | --- |
|[OpenCVE](https://github.com/opencve/opencve) | OpenCVE aggregates vulnerabilities from multiple sources and lets you filter, track, and organize them by vendor, product, severity, and more. You can subscribe to products, receive alerts, analyze changes, and collaborate with your team — all through a simple and powerful interface |
|[VM Metrics](https://www.indusface.com/blog/vulnerability-management-metrics-and-kpis/) | Quantifiable indicators used to measure how well your organization identifies, prioritizes, and remediates vulnerabilities |
|[VM Metrics](https://purplesec.us/learn/vulnerability-management-metrics) | The top 10 vulnerability management metrics you should be measuring |

### Deception
| Tool | Description |
| --- | --- |
|[Canary Tokens](https://canarytokens.org/nest/) | Create a Canarytoken. Deploy it somewhere. Know. When it matters. A excellent and effective method of gaining early warning of intrusions. |
|[Modern Honeypot Network](https://github.com/pwnlandia/mhn) | Centralized server for management and data collection of honeypots |
|[Certiception](https://github.com/dmore/Certiception-ADCS-trap) | An ADCS honeypot to catch attackers in your internal network |
|[Kerberoasting Honeypot](https://www.pentestpartners.com/security-blog/honeyroasting-how-to-detect-kerberoast-breaches-with-honeypots/) | Create and monitor a kerberoastable honeypot to detect this type of attack |
|[Honeypot Accounts](https://www.hub.trimarcsecurity.com/post/the-art-of-the-honeypot-account-making-the-unusual-look-normal) | The Art of Honeypot Account Making: Making the unusual look normal |

### Security Operations Centre
| Tool | Description |
| --- | --- |
|[Awesome SOC](https://github.com/cyb3rxp/awesome-soc) | A collection of sources of documentation, as well as field best practices, to build/run a SOC |
|[MS Entra SecOps Guide](https://learn.microsoft.com/en-us/entra/architecture/security-operations-introduction) | Microsoft Entra security operations guide |
|[OpenBAS](https://github.com/OpenBAS-Platform/openbas) | An open source platform allowing organizations to plan, schedule and conduct cyber adversary simulation campaign and tests |
|[Purple Team Framework](https://github.com/scythe-io/purple-team-exercise-framework) | Purple Team Exercise Framework |
|[Greynoise](https://viz.greynoise.io/) | GreyNoise is a cybersecurity platform that collects and analyzes Internet-wide scan and attack traffic. This data is available through the web-based Visualizer and GreyNoise APIs so users can contextualize existing alerts, filter false positives, identify compromised devices, and track emerging threats |
|[Guidance for SIEM and SOAR Implementation](https://www.cisa.gov/resources-tools/resources/guidance-siem-and-soar-implementation) | CISA guides for implementing SIEM and SOAR for Executives and practitioners |

## Security Testing
| Tool | Description |
| --- | --- |
|[MS Zero Trust Assessment](https://learn.microsoft.com/en-gb/security/zero-trust/assessment/overview) | The Zero Trust Assessment uses automation to test for hundreds of security configuration items aligned with the Secure Future Initiative (SFI) and Zero Trust pillars, then guides you through remediation steps to help operationalize Zero Trust principles |
|[Impacket](https://github.com/fortra/impacket) | Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself |
|[Responder](https://github.com/lgandx/Responder) | Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication |
|[SQLMap](https://github.com/sqlmapproject/sqlmap) | sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers |
|[NetExec](https://github.com/Pennyw0rth/NetExec) | The Network Execution Tool. See: [SMB Checklist](https://0xdf.gitlab.io/cheatsheets/smb-enum) |
|[LaZagne](https://github.com/AlessandroZ/LaZagne) | "Credential Recovery" tool |
|[DefendNot](https://github.com/es3n1n/defendnot) | Simple attempt to break Defender |
|[SecLists](https://github.com/danielmiessler/SecLists/tree/master) | A collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more |

## Security Governance
| Tool | Description |
| --- | --- |
|[NIST CSF](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf) | The NIST Cybersecurity Framework (CSF) 2.0 provides guidance to industry, government agencies, and other organizations to manage cybersecurity risks |
|[NCSC CAF](https://www.ncsc.gov.uk/collection/cyber-assessment-framework) | The CAF is a collection of cyber security guidance for organisations that play a vital role in the day-to-day life of the UK, with a focus on essential functions |
|[CISO Assistant](https://github.com/intuitem/ciso-assistant-community) | CISO Assistant is a one-stop-shop for GRC, covering Risk, AppSec, Compliance/Audit Management, Privacy and supporting +100 frameworks |
|[Mergers and Acquisitions](https://www.microsoft.com/en-us/security/blog/2022/11/02/microsoft-security-tips-for-mitigating-risk-in-mergers-and-acquisitions/) | Security tips for mitigating risk in mergers and acquisitions |

# Table Top Exercises
| Tool | Description |
| --- | --- |
|[M365 Scorched Earth](https://ericazelic.medium.com/scorched-earth-m365-and-saas-disaster-recovery-tabletop-exercise-6ea9360fc265) | Scorched Earth: M365 and SaaS Disaster Recovery Tabletop Exercise |
|[NCSC Exercise in a Box](https://www.ncsc.gov.uk/section/exercise-in-a-box/overview) | A free resource to help organisations rehearse their response to cyber attacks |
|[CISA Tabletop Exercise Packages](https://www.cisa.gov/resources-tools/services/cisa-tabletop-exercise-packages) | CISA Tabletop Exercise Packages (CTEP) are a comprehensive set of resources designed to assist stakeholders in conducting their own exercises |

## Block Lists 
| Blocklist | Confidence | Description |
| --- | --- | --- | 
|[SANS top 20 attacking subnets](https://isc.sans.edu/block.txt) | High | Top 20 attacking /24 subnets over the last 72 hours from [SANS DShield](https://dshield.org/)|
|[Proofpoint Compromised IPs](https://rules.emergingthreats.net/blockrules/compromised-ips.txt) | High | IPs confirmed as compromised by [Proofpoint Emerging Threats](https://rules.emergingthreats.net/)|
|[Firehol Level 1](https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset) | High | Collated list of subnets that can be blocked on all systems with high confidence, from [Firehol](https://iplists.firehol.org/) |
|[Phishing Database](https://github.com/Phishing-Database/Phishing.Database) | Mixed | Phishing Domains, urls websites and threats database |
|[Zeltser Blocklists](https://zeltser.com/malicious-ip-blocklists/) | Mixed | Free Blocklists of Suspected Malicious IPs and URLs |
|[LOTS Project](https://lots-project.com/#) | Mixed | Attackers are using popular legitimate domains when conducting phishing, C&C, exfiltration and downloading tools to evade detection. This list of websites allow attackers to use their domain or subdomain |

## Org OSINT
| Tool | Description |
| --- | --- |
|[DNSDumpster](https://dnsdumpster.com/) | DNSDumpster.com is a FREE domain research tool that can discover hosts related to a domain |
|[Shodan](https://www.shodan.io/) | Shodan is a search engine for Internet-connected devices |
|[Censys](https://platform.censys.io/home) | Censys provides the most complete view of the entire public-facing internet |
|[AADInternals OSINT](https://aadinternals.com/osint/) | This Open-source Intelligence (OSINT) tool will extract openly available information for the given tenant (now requires authentication) |
|[Internet NL](https://internet.nl/) | Test websites and email addresses for standards |
|[Cert Search](https://crt.sh/) | Enter a Domain Name, Organization Name, or a Certificate Fingerprint to retrieve a trove of current and historic cert data |

## Lab Resources
| Tool | Description |
| --- | --- |
|[Game of Active Directory](https://github.com/Orange-Cyberdefense/GOAD) | GOAD is a pentest active directory LAB project. The purpose of this lab is to give pentesters a vulnerable Active directory environment ready to use to practice usual attack techniques|
|[Vulnerable AD](https://github.com/safebuffer/vulnerable-AD) | Inject vulnerabilities in to an AD domain |
|[Security Onion](https://github.com/Security-Onion-Solutions/securityonion/blob/2.4/main/DOWNLOAD_AND_VERIFY_ISO.md) | Can be installed stand-alone with example data for analysis |
|[ADLab](https://github.com/PyroTek3/ADLab) | A collection of Active Directory lab scripts |

## Cheat Sheets
| Sheet | Description |
| --- | --- |
|[OWASP](https://cheatsheetseries.owasp.org/) | The OWASP Cheat Sheet Series was created to provide a concise collection of high value information on specific application security topics. These cheat sheets were created by various application security professionals who have expertise in specific topics.|
|[Application Security](https://0xn3va.gitbook.io/cheat-sheets) | A list of cheat sheets for application security. Android, CI/CD, AWS, Container, Linux, Web Apps, Web Application |
|[Reverse Shell](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) | Reverse Shell Cheat Sheet |
|[Privilege Escalation](https://github.com/Ignitetechnologies/Privilege-Escalation) | This cheasheet is aimed at the CTF Players and Beginners to help them understand the fundamentals of Privilege Escalation with examples |
|[Red Teaming](https://github.com/0xJs/RedTeaming_CheatSheet) | Pentesting Cheat Sheet |
|[SMB Enumeration](https://0xdf.gitlab.io/cheatsheets/smb-enum) | 
|[RExpository](https://jaimepolop.github.io/RExpository/) | RExpository contains a wide variety of regular expressions, organized by category, to help you find the perfect expression. These regular expressions can be used in a variety of APIs or applications |

## Misc Guides
| Tool | Description |
| --- | --- |
|[Defender XDR Setting Management](https://docs.kaidojarvemets.com/defender-xdr-settings-management.html) | Complete Implementation Guide with Azure Arc Integration and Sentinel Monitoring |
|[ASRGen](https://asrgen.streamlit.app/) | This project is a comprehensive suite of tools and resources designed to aid in understanding and configuring ASR rules in Microsoft Defender |
|[Demystifying KQL](https://github.com/ml58158/Demystifying-KQL/blob/main/Demystifying-KQL.pdf) | |
|[Purview Deployment Models](https://learn.microsoft.com/en-us/purview/deploymentmodels/depmod-overview#audience) | Deployment models are scenario-based and contain: Purview deployment blueprint, Presentation and Guide |
|[IE HSE Cyber Incident Lessons Learned](https://www.hhs.gov/sites/default/files/lessons-learned-hse-attack.pdf) | Lessons Learned from the HSE Cyber Attack |

## Misc
| Tool | Description |
| --- | --- |
|[MDE Monitoring App](https://github.com/chlaplan/MDE-Monitoring-App) | A Windows (.NET 8 WPF) desktop dashboard providing a consolidated operational view of Microsoft Defender for Endpoint (MDE) state on the local machine |
|[LogExpert](https://github.com/LogExperts/LogExpert) | Windows tail program and log file analyzer |
|[Free Certifications](https://github.com/cloudcommunity/Free-Certifications) | Curated list of free training and certifications |
|[Mermaid](https://mermaid.live/edit) | Diagramming and charting tool |
|[Markdown Guide](https://www.markdownguide.org/) | The Markdown Guide is a free and open-source reference guide that explains how to use Markdown, the simple and easy-to-use markup language you can use to format virtually any document |

