# IT & Cybersecurity Interview Handbook
## Realistische Interviewfragen mit kurzen Antworten — Deutsch & Englisch

**Zielprofil:** IT Technician / System Support / Network Support / Cloud Fundamentals / SOC Analyst / Blue Team / Threat Intelligence / Junior Red Team / Penetration Testing

**Antwortstil:** kurz, realistisch, technisch sauber und glaubwürdig.

> **Wichtig:** Passe Antworten an deine echte Erfahrung an. Wenn deine Praxis hauptsächlich aus Labs, Hack The Box, TryHackMe oder LetsDefend stammt, sage das offen. Behaupte keine produktive Enterprise-Erfahrung, wenn du sie nicht hast.

---

# 1. HR & GENERAL INTERVIEW

## 1.1 Tell me about yourself / Erzählen Sie etwas über sich

### DE
**Frage:** Erzählen Sie uns etwas über sich.

**Kurze Antwort:**
Ich komme ursprünglich aus dem IT-Support und der Administration von Systemen und Netzwerken. In den letzten Jahren habe ich meinen Schwerpunkt auf Cybersecurity gelegt, besonders auf SOC, Log-Analyse, Vulnerability Assessment und praktische Security Labs. Jetzt möchte ich diese Kenntnisse in einer professionellen Umgebung weiterentwickeln.

### EN
**Question:** Tell me about yourself.

**Short answer:**
My background is in IT support and administration of systems and networks. In recent years, I have focused more on cybersecurity, especially SOC work, log analysis, vulnerability assessment, and hands-on security labs. I now want to develop these skills further in a professional environment.

---

## 1.2 Why do you want this job?

### DE
**Frage:** Warum möchten Sie diese Position?

**Antwort:**
Die Rolle verbindet meine IT-Grundlagen mit meinem Schwerpunkt Cybersecurity. Besonders interessant finde ich Analyse, Troubleshooting und die Untersuchung von Security Events.

### EN
**Question:** Why do you want this position?

**Answer:**
The role combines my IT fundamentals with my cybersecurity focus. I am especially interested in analysis, troubleshooting, and investigating security events.

---

## 1.3 Why cybersecurity?

### DE
Mich interessiert die Kombination aus Technik, Analyse und Problemlösung. Man muss verstehen, wie Systeme funktionieren und gleichzeitig erkennen können, wie sie angegriffen oder missbraucht werden.

### EN
I like the combination of technology, analysis, and problem-solving. You need to understand how systems work and also recognize how they can be attacked or abused.

---

## 1.4 Why should we hire you?

### DE
Ich bringe solide IT-Grundlagen, praktische Cybersecurity-Erfahrung aus Labs und eine strukturierte Arbeitsweise mit. Ich lerne schnell und bin realistisch darin, was ich bereits kann und was ich noch vertiefen muss.

### EN
I bring solid IT fundamentals, hands-on cybersecurity practice from labs, and a structured way of working. I learn quickly and I am realistic about what I already know and what I still need to develop.

---

## 1.5 What are your strengths?

### DE
Meine Stärken sind analytisches Denken, Troubleshooting, selbstständiges Lernen und eine ruhige, strukturierte Vorgehensweise bei technischen Problemen.

### EN
My strengths are analytical thinking, troubleshooting, self-learning, and a calm, structured approach to technical problems.

---

## 1.6 What is your weakness?

### DE
Ich möchte meine Erfahrung mit produktiven Enterprise-Security-Umgebungen weiter ausbauen. Ich kenne viele Konzepte aus praktischen Labs, aber reale Unternehmensumgebungen sind natürlich komplexer.

### EN
I want to expand my experience with production enterprise security environments. I know many concepts from hands-on labs, but real enterprise environments are naturally more complex.

---

## 1.7 What did you do between two jobs?

### DE
In dieser Zeit habe ich mich beruflich neu orientiert und meine technischen Kenntnisse weiterentwickelt. Später habe ich meinen Schwerpunkt zunehmend auf Cybersecurity gelegt.

### EN
During that period, I was reorienting professionally and continuing to develop my technical skills. Later, I increasingly focused on cybersecurity.

---

## 1.8 Do you have real SOC experience?

### DE
Ich habe bisher keine mehrjährige Erfahrung in einem produktiven Enterprise-SOC. Meine praktische Erfahrung kommt vor allem aus Labs und selbstständigem Training mit SIEM, Log-Analyse und Incident-Szenarien.

### EN
I do not yet have several years of experience in a production enterprise SOC. My practical experience mainly comes from labs and self-directed training with SIEM, log analysis, and incident scenarios.

---

## 1.9 What do you do when you do not know something?

### DE
Ich sage offen, wenn ich etwas nicht genau weiß. Dann versuche ich, das Problem logisch einzugrenzen, Dokumentation zu prüfen und die Lösung nachvollziehbar zu verifizieren.

### EN
I say openly when I do not know something exactly. Then I narrow the problem down logically, check documentation, and verify the solution properly.

---

## 1.10 Where do you see yourself in three years?

### DE
Ich möchte technisch deutlich stärker sein, praktische Enterprise-Erfahrung gesammelt haben und mehr Verantwortung in Security Operations oder Incident Response übernehmen.

### EN
I want to be technically stronger, have real enterprise experience, and take on more responsibility in security operations or incident response.

---

# 2. IT TECHNICIAN / IT SUPPORT

## 2.1 A user cannot log in. What do you check?

### DE
Ich prüfe zuerst Benutzername, Passwort, Account-Status, Netzwerkverbindung und ob das Problem nur einen Benutzer oder mehrere betrifft. Danach schaue ich in relevante Logs oder Active Directory.

### EN
I first check the username, password, account status, network connection, and whether the issue affects one user or several. Then I check relevant logs or Active Directory.

---

## 2.2 A computer has no internet access.

### DE
Ich prüfe Link-Status, IP-Adresse, Gateway, DNS und teste Schritt für Schritt mit `ipconfig`, `ping`, `nslookup` oder `tracert`.

### EN
I check link status, IP address, gateway, and DNS, then test step by step using `ipconfig`, `ping`, `nslookup`, or `tracert`.

---

## 2.3 What is DHCP?

### DE
DHCP vergibt automatisch Netzwerkkonfigurationen wie IP-Adresse, Subnetzmaske, Gateway und DNS-Server.

### EN
DHCP automatically assigns network settings such as IP address, subnet mask, gateway, and DNS server.

---

## 2.4 What is DNS?

### DE
DNS übersetzt Domainnamen wie `example.com` in IP-Adressen.

### EN
DNS translates domain names such as `example.com` into IP addresses.

---

## 2.5 What is Active Directory?

### DE
Active Directory ist Microsofts Verzeichnisdienst zur zentralen Verwaltung von Benutzern, Computern, Gruppen, Richtlinien und Authentifizierung in Windows-Domänen.

### EN
Active Directory is Microsoft's directory service for centrally managing users, computers, groups, policies, and authentication in Windows domains.

---

## 2.6 What is Group Policy?

### DE
Mit Group Policy können Einstellungen und Sicherheitsrichtlinien zentral auf Benutzer und Computer in einer Windows-Domäne angewendet werden.

### EN
Group Policy allows settings and security policies to be centrally applied to users and computers in a Windows domain.

---

## 2.7 Difference between local user and domain user?

### DE
Ein lokaler Benutzer existiert nur auf einem bestimmten Rechner. Ein Domain-Benutzer wird zentral über Active Directory verwaltet und kann abhängig von Berechtigungen mehrere Systeme verwenden.

### EN
A local user exists only on a specific machine. A domain user is centrally managed through Active Directory and can access multiple systems depending on permissions.

---

## 2.8 What is a ticketing system?

### DE
Ein Ticketing-System dokumentiert Incidents und Service Requests, inklusive Priorität, Status, Kommunikation und Lösung.

### EN
A ticketing system tracks incidents and service requests, including priority, status, communication, and resolution.

---

## 2.9 How do you prioritize tickets?

### DE
Nach Business Impact und Dringlichkeit. Ein Ausfall für viele Benutzer hat normalerweise höhere Priorität als ein Problem mit geringem Einfluss für einen einzelnen Benutzer.

### EN
By business impact and urgency. An outage affecting many users normally has higher priority than a low-impact issue affecting one user.

---

## 2.10 What is the difference between incident and service request?

### DE
Ein Incident ist eine ungeplante Störung. Ein Service Request ist eine normale Anfrage, zum Beispiel Softwareinstallation oder Benutzerzugang.

### EN
An incident is an unplanned disruption. A service request is a standard request, such as software installation or user access.

---

## 2.11 What is virtualization?

### DE
Virtualisierung ermöglicht mehrere virtuelle Systeme auf einer physischen Hardware. Beispiele sind VMware, Hyper-V oder VirtualBox.

### EN
Virtualization allows multiple virtual systems to run on physical hardware. Examples include VMware, Hyper-V, and VirtualBox.

---

## 2.12 Snapshot vs backup?

### DE
Ein Snapshot ist ein kurzfristiger Zustand einer VM und kein vollständiger Ersatz für ein Backup. Ein Backup ist für Wiederherstellung und langfristige Datensicherung gedacht.

### EN
A snapshot is a short-term state of a VM and is not a full replacement for a backup. A backup is designed for recovery and long-term data protection.

---

# 3. NETWORKING FUNDAMENTALS

## 3.1 TCP vs UDP

### DE
TCP ist verbindungsorientiert und zuverlässig. UDP ist verbindungslos, schneller und hat weniger Overhead, garantiert aber keine Zustellung.

### EN
TCP is connection-oriented and reliable. UDP is connectionless, faster, and has less overhead, but does not guarantee delivery.

---

## 3.2 What is an IP address?

### DE
Eine IP-Adresse identifiziert ein Gerät beziehungsweise ein Netzwerkinterface logisch in einem IP-Netzwerk.

### EN
An IP address logically identifies a device or network interface in an IP network.

---

## 3.3 Private IPv4 ranges

### DE
- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`

### EN
The private IPv4 ranges are `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`.

---

## 3.4 What is a subnet mask?

### DE
Sie trennt den Netzwerkanteil einer IP-Adresse vom Hostanteil und bestimmt, welche Systeme sich im gleichen Subnetz befinden.

### EN
It separates the network portion of an IP address from the host portion and determines which systems are in the same subnet.

---

## 3.5 What is a default gateway?

### DE
Das Default Gateway ist normalerweise der Router, über den Traffic zu anderen Netzwerken gesendet wird.

### EN
The default gateway is normally the router used to send traffic to other networks.

---

## 3.6 What is NAT?

### DE
NAT übersetzt IP-Adressen zwischen Netzwerken, häufig zwischen privaten internen Adressen und einer öffentlichen IP-Adresse.

### EN
NAT translates IP addresses between networks, often between private internal addresses and a public IP address.

---

## 3.7 What is a VLAN?

### DE
Ein VLAN segmentiert ein physisches Netzwerk logisch in getrennte Broadcast-Domänen.

### EN
A VLAN logically segments a physical network into separate broadcast domains.

---

## 3.8 Router vs switch

### DE
Ein Switch verbindet Geräte innerhalb eines lokalen Netzwerks. Ein Router verbindet unterschiedliche IP-Netzwerke miteinander.

### EN
A switch connects devices within a local network. A router connects different IP networks.

---

## 3.9 What is ARP?

### DE
ARP ordnet in IPv4-Netzwerken eine bekannte IP-Adresse einer MAC-Adresse im lokalen Netzwerk zu.

### EN
ARP maps a known IPv4 address to a MAC address on the local network.

---

## 3.10 What is ICMP?

### DE
ICMP wird für Netzwerkdiagnose und Fehlermeldungen verwendet. `ping` nutzt beispielsweise ICMP.

### EN
ICMP is used for network diagnostics and error reporting. For example, `ping` uses ICMP.

---

## 3.11 What happens when you open a website?

### DE
DNS löst den Namen auf, danach wird eine Netzwerkverbindung aufgebaut. Bei HTTPS folgt ein TLS-Handshake, danach sendet der Browser die HTTP-Anfrage und erhält die Antwort.

### EN
DNS resolves the name, then a network connection is established. With HTTPS, a TLS handshake follows, then the browser sends the HTTP request and receives the response.

---

## 3.12 Common ports

| Service | Port |
|---|---:|
| FTP | 21 |
| SSH | 22 |
| SMTP | 25 |
| DNS | 53 |
| HTTP | 80 |
| POP3 | 110 |
| IMAP | 143 |
| HTTPS | 443 |
| SMB | 445 |
| RDP | 3389 |

---

## 3.13 What is a firewall?

### DE
Eine Firewall kontrolliert Netzwerkverkehr anhand definierter Regeln und erlaubt oder blockiert Verbindungen.

### EN
A firewall controls network traffic based on defined rules and allows or blocks connections.

---

## 3.14 Stateful vs stateless firewall

### DE
Eine stateful Firewall kennt den Zustand bestehender Verbindungen. Eine stateless Firewall bewertet Pakete hauptsächlich einzeln anhand von Regeln.

### EN
A stateful firewall tracks the state of existing connections. A stateless firewall mainly evaluates packets individually based on rules.

---

## 3.15 What is a VPN?

### DE
Ein VPN stellt einen verschlüsselten Tunnel über ein nicht vertrauenswürdiges Netzwerk bereit und ermöglicht sicheren Remote-Zugriff oder Site-to-Site-Verbindungen.

### EN
A VPN creates an encrypted tunnel over an untrusted network and enables secure remote access or site-to-site connectivity.

---

# 4. WINDOWS & LINUX

## 4.1 Useful Windows troubleshooting commands

### DE / EN
- `ipconfig /all`
- `ping`
- `tracert`
- `nslookup`
- `netstat`
- `whoami`
- `tasklist`
- `systeminfo`
- `gpresult`
- `Get-Process`
- `Get-Service`
- `Get-WinEvent`

---

## 4.2 Where do you check Windows security logs?

### DE
Im Windows Event Viewer, besonders unter `Windows Logs > Security`, abhängig vom konkreten Incident.

### EN
In Windows Event Viewer, especially under `Windows Logs > Security`, depending on the incident.

---

## 4.3 Important Windows Event IDs

| Event ID | Bedeutung |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4688 | Process creation |
| 4720 | User account created |
| 4728 | Member added to global security group |
| 4732 | Member added to local security group |
| 4740 | Account locked out |

---

## 4.4 Linux log locations

### DE
Je nach Distribution und Service zum Beispiel `/var/log`, `journalctl`, Authentifizierungslogs und Service-spezifische Logs.

### EN
Depending on the distribution and service, examples include `/var/log`, `journalctl`, authentication logs, and service-specific logs.

---

## 4.5 Useful Linux commands

- `ls`
- `cd`
- `pwd`
- `cat`
- `less`
- `tail`
- `grep`
- `find`
- `ps`
- `top`
- `ss`
- `ip`
- `journalctl`
- `chmod`
- `chown`
- `sudo`

---

## 4.6 chmod 755 means?

### DE
Owner: lesen, schreiben, ausführen. Group und Others: lesen und ausführen.

### EN
Owner: read, write, execute. Group and others: read and execute.

---

## 4.7 What is sudo?

### DE
`sudo` erlaubt autorisierten Benutzern, Befehle mit erhöhten Rechten auszuführen.

### EN
`sudo` allows authorized users to execute commands with elevated privileges.

---

# 5. CLOUD FUNDAMENTALS

## 5.1 What is cloud computing?

### DE
Cloud Computing stellt Rechenleistung, Speicher, Netzwerk und Plattformdienste bedarfsgerecht über einen Provider bereit.

### EN
Cloud computing provides compute, storage, networking, and platform services on demand through a provider.

---

## 5.2 IaaS, PaaS, SaaS

### DE
IaaS liefert Infrastruktur wie VMs und Netzwerke. PaaS bietet eine Plattform für Anwendungen. SaaS liefert fertige Software als Service.

### EN
IaaS provides infrastructure such as VMs and networks. PaaS provides a platform for applications. SaaS delivers complete software as a service.

---

## 5.3 Public, private and hybrid cloud

### DE
Public Cloud läuft beim Cloud Provider. Private Cloud ist einer Organisation dediziert. Hybrid Cloud kombiniert lokale oder private Infrastruktur mit Public Cloud.

### EN
Public cloud runs at a cloud provider. Private cloud is dedicated to one organization. Hybrid cloud combines on-premises or private infrastructure with public cloud.

---

## 5.4 Shared Responsibility Model

### DE
Der Cloud Provider schützt die Cloud-Infrastruktur. Der Kunde bleibt je nach Service-Modell für Dinge wie Identitäten, Konfiguration, Daten und Zugriffsrechte verantwortlich.

### EN
The cloud provider protects the cloud infrastructure. Depending on the service model, the customer remains responsible for identities, configuration, data, and access permissions.

---

## 5.5 What is IAM?

### DE
Identity and Access Management steuert Identitäten, Rollen, Berechtigungen und Zugriff auf Ressourcen.

### EN
Identity and Access Management controls identities, roles, permissions, and access to resources.

---

## 5.6 What is MFA?

### DE
Multi-Factor Authentication verlangt mehr als einen unabhängigen Authentifizierungsfaktor und reduziert das Risiko durch gestohlene Passwörter.

### EN
Multi-factor authentication requires more than one independent authentication factor and reduces the risk from stolen passwords.

---

## 5.7 What is least privilege in cloud?

### DE
Benutzer, Services und Workloads bekommen nur die Berechtigungen, die sie tatsächlich benötigen.

### EN
Users, services, and workloads receive only the permissions they actually need.

---

## 5.8 Cloud security misconfiguration example

### DE
Zum Beispiel öffentlich erreichbarer Storage, zu breite IAM-Rechte oder offen erreichbare Management-Ports.

### EN
Examples include publicly accessible storage, overly broad IAM permissions, or exposed management ports.

---

## 5.9 What is a security group?

### DE
Eine Security Group ist eine virtuelle Firewall für Cloud-Ressourcen und kontrolliert erlaubten ein- und ausgehenden Traffic.

### EN
A security group is a virtual firewall for cloud resources and controls allowed inbound and outbound traffic.

---

## 5.10 Why are cloud logs important?

### DE
Sie helfen bei Audit, Troubleshooting, Detection und Incident Response, zum Beispiel bei Login-Aktivität, API-Aufrufen oder Konfigurationsänderungen.

### EN
They support auditing, troubleshooting, detection, and incident response, for example for login activity, API calls, or configuration changes.

---

# 6. CYBERSECURITY FUNDAMENTALS

## 6.1 CIA Triad

### DE
Confidentiality, Integrity und Availability – Vertraulichkeit, Integrität und Verfügbarkeit.

### EN
Confidentiality, Integrity, and Availability.

---

## 6.2 Threat, vulnerability, risk

### DE
Eine Vulnerability ist eine Schwachstelle. Eine Threat ist eine potenzielle Bedrohung. Risk beschreibt die Kombination aus Wahrscheinlichkeit und möglichem Schaden.

### EN
A vulnerability is a weakness. A threat is a potential danger. Risk describes the combination of likelihood and potential impact.

---

## 6.3 Vulnerability Assessment vs Penetration Test

### DE
Ein Vulnerability Assessment identifiziert und priorisiert Schwachstellen. Ein Penetration Test prüft kontrolliert, ob und wie diese Schwachstellen praktisch ausgenutzt werden können.

### EN
A vulnerability assessment identifies and prioritizes weaknesses. A penetration test checks in a controlled way whether and how those weaknesses can actually be exploited.

---

## 6.4 Authentication vs authorization

### DE
Authentication prüft, wer du bist. Authorization bestimmt, was du tun darfst.

### EN
Authentication verifies who you are. Authorization determines what you are allowed to do.

---

## 6.5 Hashing vs encryption

### DE
Encryption ist reversibel mit einem Schlüssel. Hashing ist grundsätzlich als Einwegfunktion gedacht.

### EN
Encryption is reversible with a key. Hashing is generally designed as a one-way function.

---

## 6.6 Symmetric vs asymmetric encryption

### DE
Symmetrische Verschlüsselung nutzt denselben Schlüssel für Ver- und Entschlüsselung. Asymmetrische Verschlüsselung nutzt ein Public/Private-Key-Paar.

### EN
Symmetric encryption uses the same key for encryption and decryption. Asymmetric encryption uses a public/private key pair.

---

## 6.7 What is TLS?

### DE
TLS schützt Netzwerkkommunikation durch Verschlüsselung, Integrität und Authentifizierung.

### EN
TLS protects network communication through encryption, integrity, and authentication.

---

## 6.8 What is Zero Trust?

### DE
Zero Trust basiert auf dem Prinzip, Zugriffe nicht automatisch zu vertrauen, sondern Identität, Kontext und Berechtigungen kontinuierlich zu überprüfen.

### EN
Zero Trust is based on not automatically trusting access and continuously verifying identity, context, and permissions.

---

# 7. BLUE TEAM / SOC ANALYST

## 7.1 What does a SOC analyst do?

### DE
Ein SOC Analyst überwacht Security Events, untersucht Alerts, bewertet Risiken, dokumentiert Incidents und eskaliert oder unterstützt bei der Reaktion auf Sicherheitsvorfälle.

### EN
A SOC analyst monitors security events, investigates alerts, evaluates risk, documents incidents, and escalates or supports response to security incidents.

---

## 7.2 What is a SIEM?

### DE
Ein SIEM sammelt und korreliert Logs und Events aus verschiedenen Quellen, um verdächtige Aktivitäten sichtbar zu machen und Alerts zu erzeugen.

### EN
A SIEM collects and correlates logs and events from multiple sources to identify suspicious activity and generate alerts.

---

## 7.3 SIEM vs EDR

### DE
SIEM zentralisiert und korreliert Logs aus vielen Quellen. EDR überwacht Endpoints und bietet detaillierte Telemetrie und Reaktionsmöglichkeiten auf Endgeräten.

### EN
A SIEM centralizes and correlates logs from many sources. EDR monitors endpoints and provides detailed telemetry and response capabilities on devices.

---

## 7.4 IDS vs IPS

### DE
Ein IDS erkennt verdächtige Aktivitäten und alarmiert. Ein IPS kann zusätzlich aktiv blockieren.

### EN
An IDS detects suspicious activity and alerts. An IPS can also actively block it.

---

## 7.5 What is an IOC?

### DE
Ein Indicator of Compromise kann zum Beispiel eine IP-Adresse, Domain, URL, Datei-Hash oder ein anderes Artefakt sein, das auf eine Kompromittierung hinweist.

### EN
An indicator of compromise can be an IP address, domain, URL, file hash, or another artifact suggesting compromise.

---

## 7.6 IOC vs IOA

### DE
Ein IOC ist häufig ein konkretes Artefakt. Ein IOA beschreibt eher verdächtiges Verhalten oder eine Angriffstechnik.

### EN
An IOC is often a concrete artifact. An IOA focuses more on suspicious behavior or an attack technique.

---

## 7.7 What is MITRE ATT&CK?

### DE
MITRE ATT&CK ist eine Wissensbasis über Taktiken und Techniken realer Angreifer und hilft bei Detection, Analyse und Threat Hunting.

### EN
MITRE ATT&CK is a knowledge base of tactics and techniques used by real attackers and supports detection, analysis, and threat hunting.

---

## 7.8 What is a false positive?

### DE
Ein Alert sieht zunächst verdächtig aus, stellt sich nach Analyse aber als legitime Aktivität heraus.

### EN
An alert initially looks suspicious but turns out to be legitimate activity after investigation.

---

## 7.9 What is a false negative?

### DE
Eine echte Bedrohung wird nicht erkannt oder erzeugt keinen Alert.

### EN
A real threat is not detected or does not generate an alert.

---

## 7.10 Failed logins followed by successful login

### DE
Ich prüfe Benutzer, Quell-IP, Zeit, Standort und Zielsystem. Danach untersuche ich, ob es nach Brute Force oder Password Spraying aussieht und ob nach dem erfolgreichen Login weitere verdächtige Aktivitäten folgen.

### EN
I check the user, source IP, time, location, and target system. Then I investigate whether it looks like brute force or password spraying and whether suspicious activity follows the successful login.

---

## 7.11 Brute force vs password spraying

### DE
Brute Force testet viele Passwörter gegen wenige Accounts. Password Spraying testet wenige häufige Passwörter gegen viele Accounts.

### EN
Brute force tests many passwords against a small number of accounts. Password spraying tests a small number of common passwords against many accounts.

---

## 7.12 Suspicious PowerShell alert

### DE
Ich prüfe Command Line, Parent Process, Benutzer, Host, Netzwerkverbindungen und ob das Verhalten zum normalen Systembetrieb passt. Danach korreliere ich mit weiteren Endpoint- und SIEM-Events.

### EN
I check the command line, parent process, user, host, network connections, and whether the behavior fits normal system activity. Then I correlate it with additional endpoint and SIEM events.

---

## 7.13 Malware suspected on endpoint

### DE
Ich validiere den Alert, prüfe Impact und Scope und isoliere den Endpoint bei Bedarf gemäß Prozess. Danach analysiere ich Prozesse, Netzwerkverkehr, Dateien, Benutzeraktivität und weitere betroffene Systeme.

### EN
I validate the alert, assess impact and scope, and isolate the endpoint if required by procedure. Then I investigate processes, network traffic, files, user activity, and other potentially affected systems.

---

## 7.14 How do you analyze phishing?

### DE
Ich prüfe Absender, Domain, Header, URLs, Anhänge und Inhalt. Danach suche ich nach IOCs und prüfe, ob weitere Benutzer dieselbe Nachricht erhalten haben.

### EN
I inspect the sender, domain, headers, URLs, attachments, and content. Then I search for IOCs and check whether other users received the same message.

---

## 7.15 What is lateral movement?

### DE
Lateral Movement bedeutet, dass sich ein Angreifer nach dem ersten Zugriff von einem kompromittierten System zu weiteren Systemen bewegt.

### EN
Lateral movement is when an attacker moves from an initially compromised system to additional systems.

---

## 7.16 What is privilege escalation?

### DE
Privilege Escalation bedeutet, dass ein Angreifer höhere Berechtigungen erhält als ursprünglich vorhanden.

### EN
Privilege escalation means an attacker obtains higher privileges than they originally had.

---

## 7.17 What is persistence?

### DE
Persistence sind Techniken, mit denen ein Angreifer seinen Zugriff auch nach Neustart oder Änderungen im System behalten möchte.

### EN
Persistence refers to techniques used by an attacker to maintain access even after restart or system changes.

---

## 7.18 What is command and control?

### DE
Command and Control beschreibt die Kommunikation zwischen kompromittierten Systemen und der Infrastruktur eines Angreifers.

### EN
Command and control describes communication between compromised systems and attacker-controlled infrastructure.

---

## 7.19 What is exfiltration?

### DE
Exfiltration ist das unerlaubte Übertragen von Daten aus einer Umgebung heraus.

### EN
Exfiltration is the unauthorized transfer of data out of an environment.

---

## 7.20 What logs would you check first?

### DE
Das hängt vom Alert ab. Typische Quellen sind Endpoint-Logs, Windows Security Logs, Firewall, VPN, Proxy, DNS, Active Directory, EDR und Cloud Audit Logs.

### EN
It depends on the alert. Typical sources include endpoint logs, Windows Security logs, firewall, VPN, proxy, DNS, Active Directory, EDR, and cloud audit logs.

---

# 8. INCIDENT RESPONSE

## 8.1 Main incident response phases

### DE
Preparation, Identification, Containment, Eradication, Recovery und Lessons Learned.

### EN
Preparation, identification, containment, eradication, recovery, and lessons learned.

---

## 8.2 Containment vs eradication

### DE
Containment begrenzt den Schaden. Eradication entfernt die eigentliche Ursache oder den Angreifer aus der Umgebung.

### EN
Containment limits the damage. Eradication removes the root cause or attacker from the environment.

---

## 8.3 Why preserve evidence?

### DE
Damit Analyse, Root Cause Investigation und gegebenenfalls forensische oder rechtliche Anforderungen zuverlässig unterstützt werden können.

### EN
To support analysis, root-cause investigation, and potentially forensic or legal requirements reliably.

---

## 8.4 What is chain of custody?

### DE
Sie dokumentiert, wer Beweismittel wann erhalten, verarbeitet oder weitergegeben hat, damit Integrität und Nachvollziehbarkeit erhalten bleiben.

### EN
It documents who handled evidence, when, and how, preserving integrity and traceability.

---

# 9. THREAT INTELLIGENCE

## 9.1 What is threat intelligence?

### DE
Threat Intelligence ist die strukturierte Sammlung, Analyse und Bewertung von Informationen über Bedrohungen, Akteure, Infrastruktur und Angriffsmethoden.

### EN
Threat intelligence is the structured collection, analysis, and assessment of information about threats, actors, infrastructure, and attack methods.

---

## 9.2 Strategic, tactical, operational, technical intelligence

### DE
Strategisch unterstützt Managemententscheidungen. Taktisch betrachtet TTPs. Operational beschäftigt sich mit konkreten Kampagnen oder Akteuren. Technical Intelligence umfasst konkrete IOCs wie IPs, Domains und Hashes.

### EN
Strategic intelligence supports management decisions. Tactical intelligence focuses on TTPs. Operational intelligence focuses on specific campaigns or actors. Technical intelligence includes concrete IOCs such as IPs, domains, and hashes.

---

## 9.3 What are TTPs?

### DE
Tactics, Techniques and Procedures beschreiben, wie Angreifer ihre Ziele erreichen und welche Methoden sie dabei verwenden.

### EN
Tactics, Techniques, and Procedures describe how attackers achieve their goals and the methods they use.

---

## 9.4 What is OSINT?

### DE
Open Source Intelligence ist die Sammlung und Analyse öffentlich verfügbarer Informationen aus legal zugänglichen Quellen.

### EN
Open-source intelligence is the collection and analysis of publicly available information from legally accessible sources.

---

## 9.5 IOC enrichment

### DE
Ich würde einen IOC mit zusätzlichem Kontext anreichern, zum Beispiel Reputation, WHOIS, Passive DNS, historische Auflösung, Malware-Bezug und bekannte Kampagnen.

### EN
I would enrich an IOC with additional context such as reputation, WHOIS, passive DNS, historical resolution, malware associations, and known campaigns.

---

## 9.6 Why are IOCs not enough?

### DE
IOCs können schnell veralten oder geändert werden. Verhalten und TTPs sind häufig robuster für Detection und langfristige Analyse.

### EN
IOCs can become outdated or change quickly. Behavior and TTPs are often more durable for detection and long-term analysis.

---

## 9.7 Threat intelligence lifecycle

### DE
Requirements, Collection, Processing, Analysis, Dissemination und Feedback.

### EN
Requirements, collection, processing, analysis, dissemination, and feedback.

---

## 9.8 What makes intelligence actionable?

### DE
Sie muss relevant, zuverlässig, aktuell und mit genügend Kontext versehen sein, damit daraus eine konkrete Entscheidung oder Detection entstehen kann.

### EN
It must be relevant, reliable, timely, and contextual enough to support a concrete decision or detection.

---

# 10. RED TEAM / PENETRATION TESTING

> **Interviewfokus:** Autorisierung, Scope, Methodik, Reporting und saubere technische Grundlagen sind wichtiger als das Nennen möglichst vieler Exploits.

## 10.1 What is penetration testing?

### DE
Ein Penetration Test ist eine autorisierte Sicherheitsprüfung, bei der Schwachstellen kontrolliert identifiziert und gegebenenfalls ausgenutzt werden, um reale Risiken zu bewerten.

### EN
A penetration test is an authorized security assessment where weaknesses are identified and, when appropriate, exploited in a controlled manner to evaluate real risk.

---

## 10.2 What is the first rule of a penetration test?

### DE
Klare schriftliche Autorisierung und ein definierter Scope.

### EN
Clear written authorization and a defined scope.

---

## 10.3 Typical pentest phases

### DE
Scope und Rules of Engagement, Reconnaissance, Enumeration, Vulnerability Analysis, kontrollierte Exploitation, Post-Exploitation falls erlaubt, Cleanup und Reporting.

### EN
Scope and rules of engagement, reconnaissance, enumeration, vulnerability analysis, controlled exploitation, post-exploitation if permitted, cleanup, and reporting.

---

## 10.4 Reconnaissance vs enumeration

### DE
Reconnaissance sammelt allgemeine Informationen über das Ziel. Enumeration fragt Systeme und Services gezielt ab, um konkrete technische Details zu erhalten.

### EN
Reconnaissance gathers general information about the target. Enumeration actively queries systems and services to obtain specific technical details.

---

## 10.5 What do you do after finding an open port?

### DE
Ich identifiziere den Service und die Version, prüfe den Kontext und suche anschließend nach bekannten oder konfigurationsbedingten Schwachstellen.

### EN
I identify the service and version, review the context, and then look for known or configuration-related weaknesses.

---

## 10.6 What is privilege escalation?

### DE
Das Erlangen höherer Berechtigungen, zum Beispiel von einem normalen Benutzer zu Administrator oder root.

### EN
Obtaining higher privileges, for example from a standard user to administrator or root.

---

## 10.7 Horizontal vs vertical privilege escalation

### DE
Horizontal bedeutet Zugriff auf Ressourcen eines anderen Benutzers mit ähnlichen Rechten. Vertikal bedeutet, höhere Berechtigungen zu erlangen.

### EN
Horizontal privilege escalation means accessing another user's resources at a similar privilege level. Vertical privilege escalation means gaining higher privileges.

---

## 10.8 What is SQL injection?

### DE
SQL Injection entsteht, wenn unsichere Eingaben SQL-Abfragen verändern können. Verhindert wird sie unter anderem durch parametrisierte Queries und sichere Input-Verarbeitung.

### EN
SQL injection occurs when unsafe input can alter SQL queries. It can be prevented using parameterized queries and secure input handling.

---

## 10.9 What is XSS?

### DE
Cross-Site Scripting ermöglicht das Einschleusen von Script-Code in Webseiten, der im Browser anderer Benutzer ausgeführt wird.

### EN
Cross-site scripting allows script code to be injected into web pages and executed in other users' browsers.

---

## 10.10 Reflected vs stored XSS

### DE
Reflected XSS wird direkt über eine Anfrage zurückgegeben. Stored XSS wird dauerhaft in der Anwendung gespeichert und später an Benutzer ausgeliefert.

### EN
Reflected XSS is returned directly through a request. Stored XSS is persistently stored in the application and later served to users.

---

## 10.11 What is CSRF?

### DE
CSRF bringt einen authentifizierten Benutzer dazu, unbeabsichtigt eine Aktion in einer Anwendung auszuführen.

### EN
CSRF tricks an authenticated user into performing an unintended action in an application.

---

## 10.12 What is SSRF?

### DE
SSRF erlaubt einer Anwendung, vom Server aus unbeabsichtigte Requests an interne oder externe Ziele zu senden.

### EN
SSRF allows an application to make unintended requests from the server to internal or external targets.

---

## 10.13 What is IDOR?

### DE
IDOR entsteht, wenn eine Anwendung Objektzugriffe nicht korrekt autorisiert und Benutzer dadurch auf fremde Ressourcen zugreifen können.

### EN
IDOR occurs when an application does not correctly authorize object access, allowing users to access resources belonging to others.

---

## 10.14 What is directory traversal?

### DE
Directory Traversal versucht über manipulierte Pfadangaben auf Dateien außerhalb des vorgesehenen Verzeichnisses zuzugreifen.

### EN
Directory traversal uses manipulated path input to access files outside the intended directory.

---

## 10.15 What is reverse shell?

### DE
Eine Reverse Shell ist eine Shell-Verbindung, die vom Zielsystem zurück zu einem kontrollierten System aufgebaut wird. In einem Pentest darf sie nur innerhalb des autorisierten Scopes verwendet werden.

### EN
A reverse shell is a shell connection initiated from the target back to a controlled system. In a penetration test, it must only be used within the authorized scope.

---

## 10.16 Why is reporting important?

### DE
Der eigentliche Wert eines Pentests liegt darin, dass Findings verständlich dokumentiert, nach Risiko priorisiert und mit konkreten Remediation-Empfehlungen versehen werden.

### EN
The real value of a penetration test is documenting findings clearly, prioritizing them by risk, and providing concrete remediation recommendations.

---

# 11. SECURITY TOOLS — SAFE INTERVIEW ANSWERS

## Nmap

### DE
Ich nutze Nmap hauptsächlich zur Host- und Service-Erkennung, Port-Analyse und grundlegenden Enumeration in autorisierten Labs.

### EN
I mainly use Nmap for host and service discovery, port analysis, and basic enumeration in authorized labs.

---

## Wireshark

### DE
Wireshark nutze ich zur Analyse von Netzwerkverkehr, Protokollen und verdächtigen Verbindungen.

### EN
I use Wireshark to analyze network traffic, protocols, and suspicious connections.

---

## Burp Suite

### DE
Burp Suite nutze ich in Web-Security-Labs zur Analyse und Manipulation von HTTP-Anfragen und Antworten.

### EN
I use Burp Suite in web security labs to inspect and modify HTTP requests and responses.

---

## Splunk

### DE
Ich habe Splunk in Trainingsumgebungen für Suche, Filterung, Korrelation und Analyse von Logs genutzt.

### EN
I have used Splunk in training environments for searching, filtering, correlating, and analyzing logs.

---

## Microsoft Sentinel

### DE
Ich kenne die Grundkonzepte von Microsoft Sentinel als Cloud-SIEM und SOAR-Plattform, insbesondere Log-Ingestion, Analytics Rules, Incidents und KQL-basierte Analyse.

### EN
I understand the fundamentals of Microsoft Sentinel as a cloud SIEM and SOAR platform, including log ingestion, analytics rules, incidents, and KQL-based analysis.

---

## Defender for Endpoint

### DE
Microsoft Defender for Endpoint liefert Endpoint-Telemetrie, Detection und Response-Funktionen für die Untersuchung verdächtiger Aktivitäten auf Endgeräten.

### EN
Microsoft Defender for Endpoint provides endpoint telemetry, detection, and response capabilities for investigating suspicious activity on endpoints.

---

# 12. SCENARIO QUESTIONS

## 12.1 User reports phishing mail

### DE
Ich sichere die Nachricht zur Analyse, prüfe Header, Absender, URLs und Anhänge, suche nach IOCs und prüfe, ob weitere Benutzer betroffen sind.

### EN
I preserve the message for analysis, inspect headers, sender, URLs, and attachments, search for IOCs, and check whether other users are affected.

---

## 12.2 One host connects to a known malicious IP

### DE
Ich prüfe zuerst, welcher Prozess die Verbindung aufgebaut hat, welcher Benutzer aktiv war, ob weitere Hosts betroffen sind und ob zusätzliche IOCs oder verdächtige Aktivitäten vorhanden sind.

### EN
I first identify which process created the connection, which user was active, whether other hosts are affected, and whether additional IOCs or suspicious activity are present.

---

## 12.3 Admin account logs in at 03:00 from unusual country

### DE
Ich prüfe, ob der Login legitim sein könnte, kontrolliere MFA, VPN, Source IP, vorherige Login-Muster und Aktivitäten nach dem Login. Bei hohem Verdacht eskaliere ich sofort.

### EN
I check whether the login could be legitimate, review MFA, VPN, source IP, previous login patterns, and post-login activity. If suspicion is high, I escalate immediately.

---

## 12.4 Ransomware suspected

### DE
Priorität ist Containment. Betroffene Systeme sollten gemäß Incident-Response-Prozess isoliert werden. Danach werden Scope, Entry Point, betroffene Accounts, Netzwerkaktivität und weitere kompromittierte Systeme untersucht.

### EN
Containment is the priority. Affected systems should be isolated according to the incident response process. Then the scope, entry point, affected accounts, network activity, and other compromised systems are investigated.

---

## 12.5 Many DNS requests to random domains

### DE
Ich prüfe den Prozess, der die Requests erzeugt, Frequenz und Muster der Domains und korreliere mit Endpoint- und Netzwerklogs. Das könnte beispielsweise auf Malware oder DGA-Aktivität hindeuten.

### EN
I check the process generating the requests, the frequency and pattern of the domains, and correlate with endpoint and network logs. It could indicate malware or DGA activity.

---

## 12.6 New local admin account created

### DE
Ich prüfe, wer den Account erstellt hat, auf welchem System, zu welchem Zeitpunkt und ob ein Change oder Admin-Ticket existiert. Ohne legitimen Kontext behandle ich das als verdächtig.

### EN
I check who created the account, on which system, at what time, and whether an approved change or admin ticket exists. Without legitimate context, I treat it as suspicious.

---

# 13. QUESTIONS ABOUT LAB EXPERIENCE

## 13.1 What did you learn from Hack The Box?

### DE
Vor allem strukturierte Enumeration, Verständnis von Services, Schwachstellenanalyse und die Bedeutung einer sauberen Methodik statt blindem Tool-Einsatz.

### EN
Mainly structured enumeration, understanding services, vulnerability analysis, and the importance of methodology instead of blindly running tools.

---

## 13.2 What did you learn from TryHackMe?

### DE
Ich habe dort verschiedene Security-Grundlagen und praktische SOC-, Netzwerk- und Incident-Szenarien trainiert.

### EN
I used it to practice security fundamentals and hands-on SOC, networking, and incident scenarios.

---

## 13.3 What did you learn from LetsDefend?

### DE
Vor allem Alert-Triage, Log-Analyse, Phishing-Untersuchung und die strukturierte Bewertung von Security Incidents.

### EN
Mainly alert triage, log analysis, phishing investigation, and structured assessment of security incidents.

---

# 14. QUESTIONS YOU CAN ASK THE INTERVIEWER

## DE

1. Wie sieht ein typischer Arbeitstag in dieser Rolle aus?
2. Welche SIEM-, EDR- und Ticketing-Systeme verwenden Sie?
3. Wie ist das SOC beziehungsweise Security-Team aufgebaut?
4. Welche Aufgaben übernimmt ein neuer Analyst in den ersten drei Monaten?
5. Gibt es einen strukturierten Onboarding- oder Mentoring-Prozess?
6. Welche Arten von Incidents sehen Sie am häufigsten?
7. Arbeiten Sie mit MITRE ATT&CK oder eigenen Detection Frameworks?
8. Gibt es Möglichkeiten, sich in Incident Response, Threat Hunting oder Cloud Security weiterzuentwickeln?
9. Wie messen Sie den Erfolg eines Analysts in dieser Rolle?
10. Gibt es Schichtbetrieb oder Rufbereitschaft?

## EN

1. What does a typical day in this role look like?
2. Which SIEM, EDR, and ticketing systems do you use?
3. How is the SOC or security team structured?
4. What would a new analyst typically work on during the first three months?
5. Is there a structured onboarding or mentoring process?
6. What types of incidents do you see most often?
7. Do you use MITRE ATT&CK or internal detection frameworks?
8. Are there opportunities to grow into incident response, threat hunting, or cloud security?
9. How do you measure success for an analyst in this role?
10. Is there shift work or on-call duty?

---

# 15. ANSWERS TO AVOID

## Avoid
- „I know everything about cybersecurity.“
- „I have SOC experience“ if it was only labs.
- „I would immediately block the IP“ without investigation or process context.
- Listing tools you cannot explain.
- Claiming exploitation experience without authorization context.
- Giving extremely long theoretical answers to simple questions.
- Guessing when you do not know.

## Better

### DE
Ich bin mir bei diesem Detail nicht vollständig sicher. Ich würde zuerst den Kontext prüfen und dann die relevanten Logs beziehungsweise die Dokumentation heranziehen.

### EN
I am not fully sure about that detail. I would first check the context and then review the relevant logs or documentation.

---

# 16. 30-SECOND INTRODUCTION

## Deutsch

Ich habe einen technischen IT-Hintergrund mit Erfahrung in Administration, Netzwerken und Troubleshooting. In den letzten Jahren habe ich meinen Schwerpunkt auf Cybersecurity gelegt und praktische Labs in SOC-Analyse, SIEM, Log-Analyse, Vulnerability Assessment und Penetration Testing durchgeführt. Jetzt möchte ich meine technischen Grundlagen und meine Security-Kenntnisse in einer professionellen Umgebung einsetzen und weiterentwickeln.

## English

I have a technical IT background with experience in administration, networking, and troubleshooting. In recent years, I have focused on cybersecurity and completed hands-on labs in SOC analysis, SIEM, log analysis, vulnerability assessment, and penetration testing. I now want to apply and further develop my technical foundation and security skills in a professional environment.

---

# 17. RAPID-FIRE INTERVIEW REVIEW

| Frage / Question | Kurzantwort / Short answer |
|---|---|
| DNS? | Name to IP resolution |
| DHCP? | Automatic IP configuration |
| TCP? | Reliable, connection-oriented |
| UDP? | Connectionless, low overhead |
| VLAN? | Logical network segmentation |
| NAT? | IP address translation |
| VPN? | Encrypted tunnel |
| SIEM? | Centralized log collection and correlation |
| EDR? | Endpoint detection and response |
| IOC? | Indicator of compromise |
| MITRE ATT&CK? | Adversary tactics and techniques knowledge base |
| Least Privilege? | Only required permissions |
| MFA? | Multiple authentication factors |
| Phishing? | Social engineering via deceptive messages |
| Brute Force? | Many passwords against account(s) |
| Password Spraying? | Few passwords against many accounts |
| Lateral Movement? | Moving between compromised systems |
| Persistence? | Maintaining access |
| Privilege Escalation? | Obtaining higher privileges |
| Exfiltration? | Unauthorized data transfer out |
| False Positive? | Benign activity triggers alert |
| False Negative? | Real threat not detected |
| Vulnerability? | Weakness |
| Threat? | Potential danger |
| Risk? | Likelihood × impact |
| Pentest? | Authorized simulated attack |
| SOC? | Security monitoring and incident analysis |
| IAM? | Identity and access management |
| Zero Trust? | Never trust by default; verify continuously |

---

# 18. FINAL INTERVIEW RULES

1. **Keep answers between 20 and 60 seconds unless more detail is requested.**
2. **Start with the direct answer, then add one example.**
3. **Do not exaggerate lab experience.**
4. **Say “I used it in labs” when appropriate.**
5. **For SOC scenarios: Context → Validate → Scope → Contain/Escalate → Document.**
6. **For troubleshooting: Layer by layer, from simple to complex.**
7. **For Red Team: Authorization and scope always come first.**
8. **If you do not know, explain how you would investigate.**
9. **Know your own CV better than any technical topic.**
10. **Prepare two or three concrete examples from your own labs.**

---

# 19. MINI MOCK INTERVIEW — GERMAN

**Interviewer:** Erzählen Sie kurz etwas über Ihren technischen Hintergrund.

**Candidate:** Ich komme aus dem IT-Support und habe Erfahrung mit Systemadministration, Netzwerken und Troubleshooting. In den letzten Jahren habe ich mich stärker auf Cybersecurity spezialisiert und praktische Labs in SOC-Analyse, SIEM und Penetration Testing durchgeführt.

**Interviewer:** Haben Sie bereits in einem produktiven SOC gearbeitet?

**Candidate:** Noch nicht in einem Enterprise-SOC. Meine praktische SOC-Erfahrung kommt hauptsächlich aus Trainingsumgebungen wie TryHackMe und LetsDefend.

**Interviewer:** Sie sehen viele fehlgeschlagene Logins und anschließend einen erfolgreichen Login. Was tun Sie?

**Candidate:** Ich prüfe Benutzer, Quell-IP, Zeitpunkt und Zielsystem und untersuche, ob das Muster zu Brute Force oder Password Spraying passt. Danach kontrolliere ich Aktivitäten nach dem erfolgreichen Login und eskaliere bei bestätigtem Verdacht.

**Interviewer:** Was ist ein SIEM?

**Candidate:** Ein SIEM sammelt und korreliert Logs aus verschiedenen Quellen und hilft dabei, verdächtige Aktivitäten zu erkennen und Incidents zu untersuchen.

**Interviewer:** Warum möchten Sie bei uns arbeiten?

**Candidate:** Die Position verbindet meine IT-Grundlagen mit meinem Cybersecurity-Schwerpunkt. Ich möchte meine bisherige praktische Erfahrung in einer professionellen Umgebung weiterentwickeln.

---

# 20. MINI MOCK INTERVIEW — ENGLISH

**Interviewer:** Tell me briefly about your technical background.

**Candidate:** My background is in IT support, system administration, networking, and troubleshooting. In recent years, I have focused more heavily on cybersecurity and completed hands-on labs in SOC analysis, SIEM, and penetration testing.

**Interviewer:** Have you worked in a production SOC?

**Candidate:** Not yet in an enterprise SOC. My practical SOC experience mainly comes from training environments such as TryHackMe and LetsDefend.

**Interviewer:** You see many failed logins followed by a successful login. What do you do?

**Candidate:** I check the user, source IP, time, and target system and determine whether the pattern looks like brute force or password spraying. Then I review activity after the successful login and escalate if the suspicion is confirmed.

**Interviewer:** What is a SIEM?

**Candidate:** A SIEM collects and correlates logs from different sources and helps detect suspicious activity and investigate incidents.

**Interviewer:** Why do you want to work here?

**Candidate:** The position combines my IT foundation with my cybersecurity focus. I want to develop my current hands-on skills further in a professional environment.

---

# 21. LAST-MINUTE STUDY PRIORITIES

## Must know very well
- TCP/IP
- DNS
- DHCP
- NAT
- VLAN
- HTTP / HTTPS
- Common ports
- Windows Event Logs
- Linux logs
- Active Directory fundamentals
- MFA / IAM / Least Privilege
- SIEM / EDR / IDS / IPS
- Phishing analysis
- Brute Force / Password Spraying
- Incident Response
- MITRE ATT&CK
- IOC / IOA
- Cloud Shared Responsibility
- Basic Azure/AWS security concepts
- Vulnerability Assessment vs Pentest
- Basic OWASP vulnerabilities
- Your own CV and lab examples

---

**End of handbook**
