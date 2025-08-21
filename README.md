# Useful Free/Open Source Tools/Resources
A list of free or open source tools or resources that have come in useful over the years.

## Table of Contents
* [Active Directory Security](#active-directory-security)
* [M365 Security](#M365-Security)
* [Azure Security](#Azure-Security)
* [Application Security](#application-security)
* [Cyber Threat Intelligence](#Cyber-Threat-Intelligence)
* [Detection Engineering](#Detection-engineering)
* [Block Lists](#Block-Lists)
* [Security Operations](#Security-Operations)
* [Lab Resources](#lab-resources)
* [Cheat Sheets](#Cheat-Sheets)

### Active Directory Security
| Tool | Description |
| --- | --- |
|[Ping Castle](https://www.pingcastle.com/) | "Get Active Directory Security at 80% in 20% of the time" |
|[Script Sentry](https://github.com/techspence/ScriptSentry) | ScriptSentry finds misconfigured and dangerous logon scripts |
|[Locksmith](https://github.com/jakehildreth/Locksmith) | A small tool built to find and fix common misconfigurations in Active Directory Certificate Services |
|[Adeliginator](https://github.com/techspence/ADeleginator) | A companion tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory |
|[Group3r](https://github.com/Group3r/Group3r) | Find vulnerabilities in AD Group Policy |
|[AD Attack Defence](https://github.com/infosecn1nja/AD-Attack-Defense) | Attack and defend active directory using modern post exploitation adversary tradecraft activity |

### M365 Security
| Tool | Description |
| --- | --- |
|[Monkey365](https://github.com/silverhack/monkey365) | Monkey365 provides a tool for security consultants to easily conduct not only Microsoft 365, but also Azure subscriptions and Microsoft Entra ID security configuration reviews |
|[SCUBAGear](https://github.com/cisagov/ScubaGear) | Automation to assess the state of your M365 tenant against CISA's baselines |
|[Least Privileged Roles by Task](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/delegate-by-task) | This article describes the least privileged role you should use for several tasks in Microsoft Entra ID |

### Azure Security
| Tool | Description |
| --- | --- |
|[Azure Best Practices](https://learn.microsoft.com/en-us/azure/security/fundamentals/best-practices-and-patterns) | This article contains security best practices to use when you're designing, deploying, and managing your cloud solutions by using Azure. These best practices come from our experience with Azure security and the experiences of customers like you.|
|[Azure Red Team](https://github.com/rootsecdev/Azure-Red-Team) | Azure Security Resources and Notes |
|[Azure Attack Paths](https://cloudbrothers.info/en/azure-attack-paths/) | Known Azure attack paths |

### Application Security
| Tools | Description |
| --- | --- |
|[ThreatMapper](https://github.com/deepfence/ThreatMapper) | Open Source Cloud Native Application Protection Platform cloud, containers, serverless and on-prem |
|[DevSecOps Library](https://github.com/sottlmarek/DevSecOps) | This library contains list of tools and methodologies accompanied with resources. The main goal is to provide to the engineers a guide through opensource DevSecOps tooling |
|[Web App Security Assessment Methodology](https://github.com/tprynn/web-methodology/wiki) | Web application security assessment methodology |

### Cyber Threat Intelligence
| Tool | Description |
| --- | --- |
|[Bert-JanP Threat Intel Feeds](https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds) | Open Source freely usable Threat Intel feeds that can be used without additional requirements |
|[OpenCTI](https://github.com/OpenCTI-Platform/opencti) | OpenCTI is an open source platform allowing organizations to manage their cyber threat intelligence knowledge and observables |
|[Open Source CTI](https://github.com/BushidoUK/Open-source-tools-for-CTI) | Public Repository of Open Source Tools for Cyber Threat Intelligence Analysts and Researchers |
|[OpenSquat](https://github.com/atenreiro/opensquat) | The openSquat is an open-source tool for detecting domain look-alikes by searching for newly registered domains that might be impersonating legit domains and brands |
|[Threat Intelligence Platforms](https://gist.github.com/Te-k/2a5a1885249cfd07f417b47d291c4b98) | A list of threat intelligence platforms |

### Detection Engineering
| Tool | Description |
| --- | --- |
|[DetEng Resources](https://github.com/infosecB/awesome-detection-engineering) | List of DetEng resources |
|[Bert JanP Queries](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules) | Library of KQL detection and hunting queries from a master |
|[Anvillogic Forge](https://github.com/anvilogic-forge/armory) | Library of sigma detection rules |
|[MAGMa Use Case Framework](https://www.betaalvereniging.nl/wp-content/uploads/FI-ISAC-use-case-framework-verkorte-versie.pdf) | MaGMa: a framework and tool for use case management |

### Block Lists 
| Blocklist | Confidence | Description |
| --- | --- | --- | 
|[SANS top 20 subnets](https://isc.sans.edu/block.txt) | High | Top 20 attacking /24 subnets over the last 72 hours from [SANS DShield](https://dshield.org/)|
|[Proofpoint Compromised IPs](https://rules.emergingthreats.net/blockrules/compromised-ips.txt) | High | IPs confirmed as compromised by [Proofpoint Emerging Threats](https://rules.emergingthreats.net/)|
|[Firehol Level 1](https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset) | High | Collated list of subnets that can be blocked on all systems with high confidence, fom [Firehol](https://iplists.firehol.org/) |
|[Phishing Database](https://github.com/Phishing-Database/Phishing.Database) | Mixed | Phishing Domains, urls websites and threats database |
|[Zeltser Blocklists](https://zeltser.com/malicious-ip-blocklists/) | Mixed | Free Blocklists of Suspected Malicious IPs and URLs |

### Security Operations
| Tool | Description |
| --- | --- |
|[Awesome SOC](https://github.com/cyb3rxp/awesome-soc) | A collection of sources of documentation, as well as field best practices, to build/run a SOC |
|[MS Entra SecOps Guide](https://learn.microsoft.com/en-us/entra/architecture/security-operations-introduction) | Microsoft Entra security operations guide |

### Lab Resources
| Tool | Description |
| --- | --- |
|[Game of Active Directory](https://mayfly277.github.io/posts/GOADv2/) | Five system forest with vulnerabilities and multiple routes to DA|
|[Vulnerable AD](https://github.com/safebuffer/vulnerable-AD) | Inject vulnerabilities in to an AD domain |

### Cheat Sheets
| Sheet | Description |
| --- | --- |
|[OWASP](https://cheatsheetseries.owasp.org/) | The OWASP Cheat Sheet Series was created to provide a concise collection of high value information on specific application security topics. These cheat sheets were created by various application security professionals who have expertise in specific topics.|
|[Application Security](https://0xn3va.gitbook.io/cheat-sheets) | A list of cheat sheets for application security. Android, CI/CD, AWS, Container, Linux, Web Apps, Web Application |
|[Reverse Shell](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) | Reverse Shell Cheat Sheet |
|[Privilege Escalation](https://github.com/Ignitetechnologies/Privilege-Escalation) | This cheasheet is aimed at the CTF Players and Beginners to help them understand the fundamentals of Privilege Escalation with examples |
|[Red Teaming](https://github.com/0xJs/RedTeaming_CheatSheet) | Pentesting Cheat Sheet |
