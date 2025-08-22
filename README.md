# Useful Free/Open Source Cyber Security Tools/Resources
A list of free or open source tools or resources that have proven useful over the years.

## Table of Contents
* [Security Engineering](#Security-Egineering)
  * [Active Directory Security](#active-directory-security)
  * [M365 Security](#M365-Security)
  * [Azure Security](#Azure-Security)
  * [OS Security](#OS-Security)
  * [Application Security](#application-security)
* [Security Operations](#Security-Operations)
  * [Incident Response Tactical](#Incident-response-tactical)
  * [Incident Response Management](#Incident-response-management)
  * [Detection Engineering](#Detection-engineering)
  * [Cyber Threat Intelligence](#Cyber-Threat-Intelligence)
  * [Deception](#Deception)
  * [SOC](#Security-Operations-centre)
* [Security Testing](#Security-testing)
* [Block Lists](#Block-Lists)
* [Organisation OSINT](#Org-OSINT)
* [Lab Resources](#lab-resources)
* [Cheat Sheets](#Cheat-Sheets)

## Security Engineering
### Active Directory Security
| Tool | Description |
| --- | --- |
|[Ping Castle](https://www.pingcastle.com/) | "Get Active Directory Security at 80% in 20% of the time" (See also: [Ping Castle Notify](https://github.com/LuccaSA/PingCastle-Notify))|
|[Script Sentry](https://github.com/techspence/ScriptSentry) | ScriptSentry finds misconfigured and dangerous logon scripts |
|[Locksmith](https://github.com/jakehildreth/Locksmith) | A small tool built to find and fix common misconfigurations in Active Directory Certificate Services |
|[Adeliginator](https://github.com/techspence/ADeleginator) | A companion tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory |
|[Group3r](https://github.com/Group3r/Group3r) | Find vulnerabilities in AD Group Policy |
|[AD Attack Defence](https://github.com/infosecn1nja/AD-Attack-Defense) | Informational asset for those looking to understand the specific tactics, techniques, and procedures (TTPs) attackers are leveraging to compromise active directory and guidance to mitigation, detection, and prevention. |

### M365 Security
| Tool | Description |
| --- | --- |
|[Conditional Access Baseline](https://github.com/j0eyv/ConditionalAccessBaseline) | [Joey Verlinden's](https://github.com/j0eyv) Conditional access Baseline |
|[Risk Based CAPs](https://github.com/nathanmcnulty/nathanmcnulty/tree/main/Entra/conditional-access/risk-policies) | [Nathan McNulty's](https://github.com/nathanmcnulty) Risk Based Conditional Access Policies |
|[Monkey365](https://github.com/silverhack/monkey365) | Monkey365 provides a tool for security consultants to easily conduct not only Microsoft 365, but also Azure subscriptions and Microsoft Entra ID security configuration reviews |
|[SCUBAGear](https://github.com/cisagov/ScubaGear) | Automation to assess the state of your M365 tenant against CISA's baselines |
|[Least Privileged Roles by Task](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/delegate-by-task) | This article describes the least privileged role you should use for several tasks in Microsoft Entra ID |

### Azure Security
| Tool | Description |
| --- | --- |
|[Azure Best Practices](https://learn.microsoft.com/en-us/azure/security/fundamentals/best-practices-and-patterns) | This article contains security best practices to use when you're designing, deploying, and managing your cloud solutions by using Azure. These best practices come from our experience with Azure security and the experiences of customers like you.|
|[Azure Red Team](https://github.com/rootsecdev/Azure-Red-Team) | Azure Security Resources and Notes |
|[Azure Attack Paths](https://cloudbrothers.info/en/azure-attack-paths/) | Known Azure attack paths |

### OS Security
| Tool | Description |
| --- | --- |
|[PrivEscCheck](https://github.com/itm4n/PrivescCheck) | Windows. Privilege Escalation Enumeration Script for Windows |
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

### Incident Response Management
| Tool | Description |
| --- | --- |
|[Microsoft IT Ninja Hub](https://aka.ms/MicrosoftIRNinjaHub) | Microsoft Incident Response Ninja Hub |
|[NIST IR Reccomendations](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf) | Help organizations incorporate cybersecurity incident response recommendations and considerations throughout their cybersecurity risk management activities |
|[IR Playbooks](https://github.com/certsocietegenerale/IRM) | List of best practice playbooks for a variety of security incidents |
|[ADS Strategy Framework](https://github.com/palantir/alerting-detection-strategy-framework) | A framework for developing alerting and detection strategies for incident response |

### Detection Engineering
| Tool | Description |
| --- | --- |
|[DetEng Resources](https://github.com/infosecB/awesome-detection-engineering) | Detection Engineering is a tactical function of a cybersecurity defense program that involves the design, implementation, and operation of detective controls with the goal of proactively identifying malicious or unauthorized activity before it negatively impacts an individual or an organization |
|[Hunting Queries and Detection Rules](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules) | Library of KQL detection and hunting queries from the excellent [Bert JanP](https://github.com/Bert-JanP) |
|[Anvillogic Forge](https://github.com/anvilogic-forge/armory) | Library of sigma detection rules |
|[MAGMa Use Case Framework](https://www.betaalvereniging.nl/wp-content/uploads/FI-ISAC-use-case-framework-verkorte-versie.pdf) | MaGMa: a framework and tool for use case management |

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
|[VM Metrics](https://www.indusface.com/blog/vulnerability-management-metrics-and-kpis/) | Quantifiable indicators used to measure how well your organization identifies, prioritizes, and remediates vulnerabilities |
|[VM Metrics](https://purplesec.us/learn/vulnerability-management-metrics) | The top 10 vulnerability management metrics you should be measuring |
|[Purple Team Framework](https://github.com/scythe-io/purple-team-exercise-framework) | Purple Team Exercise Framework |
|[Greynoise](https://viz.greynoise.io/) | GreyNoise is a cybersecurity platform that collects and analyzes Internet-wide scan and attack traffic. This data is available through the web-based Visualizer and GreyNoise APIs so users can contextualize existing alerts, filter false positives, identify compromised devices, and track emerging threats |

## Security Testing
| Tool | Description |
| --- | --- |
|[Impacket](https://github.com/fortra/impacket) | Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself |
|[Responder](https://github.com/lgandx/Responder) | Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication |
|[SQLMap](https://github.com/sqlmapproject/sqlmap) | sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers |
|[SecLists](https://github.com/danielmiessler/SecLists/tree/master) | A collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more |

## Security Governance
| Tool | Description |
| --- | --- |
|[NIST CSF](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf) | The NIST Cybersecurity Framework (CSF) 2.0 provides guidance to industry, government agencies, and other organizations to manage cybersecurity risks |
|[NCSC CAF](https://www.ncsc.gov.uk/collection/cyber-assessment-framework) | The CAF is a collection of cyber security guidance for organisations that play a vital role in the day-to-day life of the UK, with a focus on essential functions |
|[CISO Assistant](https://github.com/intuitem/ciso-assistant-community) | CISO Assistant is a one-stop-shop for GRC, covering Risk, AppSec, Compliance/Audit Management, Privacy and supporting +100 frameworks |
|[Mergers and Acquisitions](https://www.microsoft.com/en-us/security/blog/2022/11/02/microsoft-security-tips-for-mitigating-risk-in-mergers-and-acquisitions/) | Security tips for mitigating risk in mergers and acquisitions |


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
|[AADInternals OSINT](https://aadinternals.com/osint/) | This Open-source Intelligence (OSINT) tool will extract openly available information for the given tenant |
|[Internet NL](https://internet.nl/) | Test websites and email addresses for standards |
|[Cert Search](https://crt.sh/) | Enter a Domain Name, Organization Name, or a Certificate Fingerprint to retrieve a trove of current and historic cert data |
|[NetBlockTool](https://www.netspi.com/blog/technical-blog/network-penetration-testing/netblocktool/) | Find Net Blocks owned by a company and its subsidiaries |

## Lab Resources
| Tool | Description |
| --- | --- |
|[Game of Active Directory](https://github.com/Orange-Cyberdefense/GOAD) | GOAD is a pentest active directory LAB project. The purpose of this lab is to give pentesters a vulnerable Active directory environment ready to use to practice usual attack techniques|
|[Vulnerable AD](https://github.com/safebuffer/vulnerable-AD) | Inject vulnerabilities in to an AD domain |

## Cheat Sheets
| Sheet | Description |
| --- | --- |
|[OWASP](https://cheatsheetseries.owasp.org/) | The OWASP Cheat Sheet Series was created to provide a concise collection of high value information on specific application security topics. These cheat sheets were created by various application security professionals who have expertise in specific topics.|
|[Application Security](https://0xn3va.gitbook.io/cheat-sheets) | A list of cheat sheets for application security. Android, CI/CD, AWS, Container, Linux, Web Apps, Web Application |
|[Reverse Shell](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) | Reverse Shell Cheat Sheet |
|[Privilege Escalation](https://github.com/Ignitetechnologies/Privilege-Escalation) | This cheasheet is aimed at the CTF Players and Beginners to help them understand the fundamentals of Privilege Escalation with examples |
|[Red Teaming](https://github.com/0xJs/RedTeaming_CheatSheet) | Pentesting Cheat Sheet |
