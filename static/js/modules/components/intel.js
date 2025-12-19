import { safeStorage, addHistory } from '../utils.js';

export const KNOWLEDGE_BASE = [
    {
        id: 'iocs',
        title: 'Indicators of Compromise',
        icon: 'fas fa-fingerprint',
        iconColor: 'text-[#d29922]',
        tags: ['Threat Intel', 'Basics'],
        complexity: 'Beginner',
        summary: 'Forensic artifacts left behind by attackers, from file hashes to network signatures.',
        content: `
            <h4>What are IOCs?</h4>
            <p>Indicators of Compromise (IOCs) are pieces of forensic data, such as data found in system log entries or files, that identify potentially malicious activity on a system or network.</p>
            
            <h4>Common Types of IOCs</h4>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 my-4">
                <div class="bg-[#161b22] p-3 rounded border border-[#30363d]">
                    <h5 class="text-[#58a6ff] font-semibold mb-1">Network Indicators</h5>
                    <ul class="list-disc list-inside text-sm text-[#8b949e]">
                        <li><strong>IP Addresses:</strong> Known C2 servers, botnets, or malware distribution sites.</li>
                        <li><strong>Domain Names:</strong> DGA domains, typosquatted domains.</li>
                        <li><strong>URLs:</strong> Specific paths hosting malicious payloads.</li>
                    </ul>
                </div>
                <div class="bg-[#161b22] p-3 rounded border border-[#30363d]">
                    <h5 class="text-[#58a6ff] font-semibold mb-1">Host Indicators</h5>
                    <ul class="list-disc list-inside text-sm text-[#8b949e]">
                        <li><strong>File Hashes:</strong> MD5, SHA1, SHA256 signatures of malware.</li>
                        <li><strong>Registry Keys:</strong> Persistence mechanisms.</li>
                        <li><strong>Mutexes:</strong> Unique identifiers used by malware.</li>
                    </ul>
                </div>
            </div>

            <h4>The Pyramid of Pain</h4>
            <p>The "Pyramid of Pain" describes how difficult it is for an attacker to change their indicators when you block them.</p>
            <ul class="space-y-2 mt-2">
                <li class="flex items-center gap-2"><span class="w-20 text-xs font-mono bg-red-900/30 text-red-400 px-1 rounded">TTPs</span> <span class="text-sm">Tough! (Tactics, Techniques, and Procedures)</span></li>
                <li class="flex items-center gap-2"><span class="w-20 text-xs font-mono bg-orange-900/30 text-orange-400 px-1 rounded">Tools</span> <span class="text-sm">Challenging</span></li>
                <li class="flex items-center gap-2"><span class="w-20 text-xs font-mono bg-yellow-900/30 text-yellow-400 px-1 rounded">Artifacts</span> <span class="text-sm">Annoying</span></li>
                <li class="flex items-center gap-2"><span class="w-20 text-xs font-mono bg-green-900/30 text-green-400 px-1 rounded">Domain Names</span> <span class="text-sm">Simple</span></li>
                <li class="flex items-center gap-2"><span class="w-20 text-xs font-mono bg-blue-900/30 text-blue-400 px-1 rounded">IP Addresses</span> <span class="text-sm">Easy</span></li>
                <li class="flex items-center gap-2"><span class="w-20 text-xs font-mono bg-gray-800 text-gray-400 px-1 rounded">Hash Values</span> <span class="text-sm">Trivial</span></li>
            </ul>
        `
    },
    {
        id: 'ip-reputation',
        title: 'IP Reputation',
        icon: 'fas fa-globe-americas',
        iconColor: 'text-[#58a6ff]',
        tags: ['Threat Intel', 'Network Security'],
        complexity: 'Beginner',
        summary: 'Understand how IP addresses are scored, why they get blacklisted, and the concept of reputation decay.',
        content: `
            <h4>Understanding IP Reputation</h4>
            <p>IP Reputation is a score or classification assigned to an IP address based on its historical behavior. Security vendors aggregate data from honeypots, spam traps, and user reports to determine if an IP is "clean" or "malicious".</p>

            <h4>Why IPs get a "Bad" Reputation</h4>
            <ul class="list-disc list-inside space-y-2 my-4 text-[#c9d1d9]">
                <li><strong>Spamming:</strong> Sending high volumes of unsolicited email.</li>
                <li><strong>Botnet Activity:</strong> Participating in DDoS attacks or credential stuffing.</li>
                <li><strong>Malware Hosting:</strong> Serving malicious files or acting as a C2 server.</li>
                <li><strong>Scanning:</strong> Indiscriminately scanning the internet for vulnerabilities.</li>
                <li><strong>Open Proxies/Relays:</strong> Misconfigured servers allowed to be abused by attackers.</li>
            </ul>

            <h4>Reputation Decay</h4>
            <p>IP addresses are dynamic. A "bad" IP today might be reassigned to a legitimate user tomorrow. Therefore, reputation scores usually have a "Time to Live" (TTL) or decay factor. An IP that hasn't been seen doing anything malicious for 30 days often returns to a neutral state.</p>
        `
    },
    {
        id: 'passive-dns',
        title: 'Passive DNS',
        icon: 'fas fa-history',
        iconColor: 'text-[#a855f7]',
        tags: ['Threat Intel', 'Network Security'],
        complexity: 'Intermediate',
        summary: 'Explore historical DNS data to pivot between infrastructure and reconstruct attack timelines.',
        content: `
            <h4>What is Passive DNS (pDNS)?</h4>
            <p>Passive DNS is a mechanism to store historical DNS resolution data. Unlike active DNS queries (which tell you where a domain points <em>now</em>), Passive DNS tells you where a domain pointed <em>in the past</em>, or which domains have ever pointed to a specific IP.</p>

            <h4>Key Use Cases</h4>
            <div class="space-y-4 my-4">
                <div class="border-l-2 border-[#58a6ff] pl-4">
                    <h5 class="font-semibold text-[#c9d1d9]">1. Infrastructure Pivoting</h5>
                    <p class="text-sm text-[#8b949e]">You find a malicious domain <code>evil.com</code> pointing to IP <code>1.2.3.4</code>. Using pDNS, you can see that <code>1.2.3.4</code> also hosted <code>phishing-bank.com</code> and <code>malware-drop.net</code> last week. You've now expanded your investigation.</p>
                </div>
                <div class="border-l-2 border-[#58a6ff] pl-4">
                    <h5 class="font-semibold text-[#c9d1d9]">2. Timeline Reconstruction</h5>
                    <p class="text-sm text-[#8b949e]">Determine exactly when a legitimate website was compromised by seeing when its A record changed to a known malicious IP.</p>
                </div>
            </div>

            <h4>How is it collected?</h4>
            <p>Sensors placed at ISP level, recursive resolvers, or large networks "passively" record the DNS responses they see flying by on the wire, without generating new traffic.</p>
        `
    },
    {
        id: 'malware-analysis',
        title: 'Malware Analysis',
        icon: 'fas fa-bug',
        iconColor: 'text-[#f85149]',
        tags: ['Malware', 'Basics'],
        complexity: 'Intermediate',
        summary: 'The difference between Static and Dynamic analysis, sandboxing, and reverse engineering basics.',
        content: `
            <h4>Static vs. Dynamic Analysis</h4>
            <p>Malware analysis is the process of understanding the behavior and purpose of a suspicious file.</p>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-6 my-4">
                <div>
                    <h5 class="text-[#58a6ff] font-semibold border-b border-[#30363d] pb-2 mb-2">Static Analysis</h5>
                    <p class="text-sm text-[#8b949e] mb-2">Examining the code without running it.</p>
                    <ul class="list-disc list-inside text-xs text-[#c9d1d9] space-y-1">
                        <li><strong>Hashing:</strong> Identifying the file.</li>
                        <li><strong>Strings:</strong> Looking for IPs, URLs, or messages inside the binary.</li>
                        <li><strong>PE Headers:</strong> Checking compile time, imports, and exports.</li>
                        <li><strong>Disassembly:</strong> Reading the assembly code (IDA Pro, Ghidra).</li>
                    </ul>
                </div>
                <div>
                    <h5 class="text-[#f85149] font-semibold border-b border-[#30363d] pb-2 mb-2">Dynamic Analysis</h5>
                    <p class="text-sm text-[#8b949e] mb-2">Running the malware in a safe environment.</p>
                    <ul class="list-disc list-inside text-xs text-[#c9d1d9] space-y-1">
                        <li><strong>Sandboxing:</strong> Automated execution (Cuckoo, Joe Sandbox).</li>
                        <li><strong>Network Monitoring:</strong> Watching for C2 callbacks.</li>
                        <li><strong>Process Monitoring:</strong> Watching for file creation or registry changes.</li>
                        <li><strong>Debugging:</strong> Stepping through execution.</li>
                    </ul>
                </div>
            </div>
        `
    },
    {
        id: 'phishing',
        title: 'Phishing & Social Engineering',
        icon: 'fas fa-user-secret',
        iconColor: 'text-[#7ee787]',
        tags: ['Threat Intel', 'Basics'],
        complexity: 'Beginner',
        summary: 'Common techniques like Typosquatting, Homoglyphs, and Subdomain abuse used to deceive users.',
        content: `
            <h4>Anatomy of a Phish</h4>
            <p>Phishing is the fraudulent attempt to obtain sensitive information by disguising oneself as a trustworthy entity.</p>

            <h4>Common Techniques</h4>
            <ul class="space-y-3 my-4">
                <li class="bg-[#161b22] p-3 rounded border border-[#30363d]">
                    <strong class="text-[#c9d1d9]">Typosquatting (URL Hijacking)</strong>
                    <p class="text-xs text-[#8b949e] mt-1">Registering <code>g0ogle.com</code> or <code>faceboook.com</code>. Relying on users missing the typo.</p>
                </li>
                <li class="bg-[#161b22] p-3 rounded border border-[#30363d]">
                    <strong class="text-[#c9d1d9]">Homoglyphs (IDN Homograph Attack)</strong>
                    <p class="text-xs text-[#8b949e] mt-1">Using characters from different scripts that look identical. E.g., Cyrillic 'a' vs Latin 'a'. <code>apple.com</code> vs <code>аpple.com</code>.</p>
                </li>
                <li class="bg-[#161b22] p-3 rounded border border-[#30363d]">
                    <strong class="text-[#c9d1d9]">Subdomain Abuse</strong>
                    <p class="text-xs text-[#8b949e] mt-1"><code>microsoft-login.attacker-site.com</code>. The domain is <code>attacker-site.com</code>, but the subdomain looks legitimate.</p>
                </li>
            </ul>
        `
    },
    {
        id: 'c2-infrastructure',
        title: 'C2 Infrastructure',
        icon: 'fas fa-server',
        iconColor: 'text-[#8b949e]',
        tags: ['Threat Intel', 'Network Security'],
        complexity: 'Advanced',
        summary: 'How attackers control botnets using HTTP, DNS Tunneling, and Fast Flux networks.',
        content: `
            <h4>Command & Control (C2)</h4>
            <p>C2 infrastructure is the set of servers and protocols attackers use to communicate with compromised systems (botnets) inside a target network.</p>

            <h4>Communication Methods</h4>
            <ul class="list-disc list-inside space-y-2 my-4 text-[#c9d1d9]">
                <li><strong>HTTP/HTTPS:</strong> Blending in with normal web traffic.</li>
                <li><strong>DNS Tunneling:</strong> Encoding data in DNS queries (e.g., <code>secret-data.attacker.com</code>).</li>
                <li><strong>Social Media:</strong> Bots checking a specific Twitter account or Reddit thread for instructions.</li>
                <li><strong>Tor/I2P:</strong> Hiding the C2 server location using darknets.</li>
            </ul>

            <h4>Fast Flux</h4>
            <p>A technique used by botnets to hide their C2 servers. A single domain name resolves to hundreds of different IP addresses (compromised hosts) that change rapidly (every few minutes), making it hard to take down.</p>
        `
    },
    {
        id: 'osint-tools',
        title: 'OSINT Tools',
        icon: 'fas fa-tools',
        iconColor: 'text-[#79c0ff]',
        tags: ['Threat Intel', 'Tools'],
        complexity: 'Beginner',
        summary: 'Overview of essential tools like VirusTotal, Shodan, AbuseIPDB, and Urlscan.io.',
        content: `
            <h4>Open Source Intelligence (OSINT)</h4>
            <p>Using publicly available information to gather intelligence on targets.</p>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 my-4">
                <div class="panel p-3 border border-[#30363d]">
                    <h5 class="font-bold text-[#58a6ff]">VirusTotal</h5>
                    <p class="text-xs text-[#8b949e]">Aggregates 70+ antivirus scanners and URL/domain blocklists. The "Google" of malware.</p>
                </div>
                <div class="panel p-3 border border-[#30363d]">
                    <h5 class="font-bold text-[#58a6ff]">Shodan</h5>
                    <p class="text-xs text-[#8b949e]">Search engine for connected devices. Finds webcams, servers, routers, and industrial control systems.</p>
                </div>
                <div class="panel p-3 border border-[#30363d]">
                    <h5 class="font-bold text-[#58a6ff]">AbuseIPDB</h5>
                    <p class="text-xs text-[#8b949e]">Crowdsourced IP reputation. Great for checking if an IP has been reported for SSH brute-forcing.</p>
                </div>
                <div class="panel p-3 border border-[#30363d]">
                    <h5 class="font-bold text-[#58a6ff]">Urlscan.io</h5>
                    <p class="text-xs text-[#8b949e]">Sandboxes a URL, takes a screenshot, and records all network requests (DOM, JS, cookies).</p>
                </div>
            </div>
        `
    },
    {
        id: 'yara-rules',
        title: 'YARA Rules',
        icon: 'fas fa-code',
        iconColor: 'text-[#d2a8ff]',
        tags: ['Malware', 'Tools'],
        complexity: 'Advanced',
        summary: 'The standard for malware description and pattern matching. Learn how rules are structured.',
        content: `
            <h4>What is YARA?</h4>
            <p>YARA is the "Swiss army knife" of pattern matching for malware researchers. It allows you to create descriptions (rules) of malware families based on text or binary patterns.</p>

            <h4>Example Rule</h4>
            <pre class="bg-[#0d1117] p-3 rounded border border-[#30363d] text-xs font-mono text-[#c9d1d9]">
rule SilentBanker_Trojan {
    meta:
        description = "Detects SilentBanker"
        author = "Analyst"
    strings:
        $a = "wininet.dll"
        $b = "POST /login.php"
        $hex = { E2 34 A1 C8 23 FB }
    condition:
        $a and $b and $hex
}</pre>
            <p class="mt-2">If a file contains the string "wininet.dll", "POST /login.php", AND the specific hex sequence, it matches this rule.</p>
        `
    },
    {
        id: 'cloud-shared-responsibility',
        title: 'Shared Responsibility Model',
        icon: 'fas fa-cloud',
        iconColor: 'text-[#58a6ff]',
        tags: ['Cloud Security', 'Basics'],
        complexity: 'Beginner',
        summary: 'Who secures what? Understanding the division of security tasks between provider and customer.',
        content: `
            <h4>The Cloud Security Line in the Sand</h4>
            <p>Security and Compliance is a shared responsibility between Cloud Providers (Microsoft Azure, AWS, GCP) and the customer.</p>
            <div class="grid grid-cols-1 gap-4 my-4">
                <div class="bg-[#161b22] p-3 rounded border border-[#30363d]">
                    <h5 class="text-[#58a6ff] font-semibold mb-1">Provider Responsibility (Security "of" the Cloud)</h5>
                    <p class="text-sm text-[#8b949e]">Hardware, Global Infrastructure, Compute, Storage, Database, Networking software.</p>
                </div>
                <div class="bg-[#161b22] p-3 rounded border border-[#30363d]">
                    <h5 class="text-[#f85149] font-semibold mb-1">Customer Responsibility (Security "in" the Cloud)</h5>
                    <p class="text-sm text-[#8b949e]">Customer Data, IAM (Entra ID), Operating System patches (for VMs), Firewall configuration, Encryption.</p>
                </div>
            </div>
        `
    },
    {
        id: 'entra-id-iam',
        title: 'Microsoft Entra ID (IAM)',
        icon: 'fas fa-id-card',
        iconColor: 'text-[#00a4ef]',
        tags: ['Cloud Security', 'Azure'],
        complexity: 'Intermediate',
        summary: 'Identity and Access Management (IAM) is the new perimeter. Learn about Entra ID and Least Privilege.',
        content: `
            <h4>Identity is the New Perimeter</h4>
            <p>In the cloud, you can't just rely on firewalls. Microsoft Entra ID (formerly Azure AD) controls who can do what.</p>
            
            <h4>Principle of Least Privilege (PoLP)</h4>
            <p>A user or service should have only the minimum permissions necessary to perform their function.</p>
            
            <div class="bg-[#161b22] p-3 rounded border border-[#30363d] my-4">
                <h5 class="text-[#c9d1d9] font-semibold mb-2">Example: Azure Storage Access</h5>
                <div class="space-y-2">
                    <div class="flex items-center gap-2 text-xs">
                        <i class="fas fa-times-circle text-[#f85149]"></i>
                        <span class="text-[#8b949e]"><strong>Bad:</strong> Assigning "Owner" role to a developer.</span>
                    </div>
                    <div class="flex items-center gap-2 text-xs">
                        <i class="fas fa-check-circle text-[#3fb950]"></i>
                        <span class="text-[#8b949e]"><strong>Good:</strong> Assigning "Storage Blob Data Reader" role.</span>
                    </div>
                </div>
            </div>
        `
    },
    {
        id: 'cspm-defender',
        title: 'Microsoft Defender for Cloud',
        icon: 'fas fa-shield-alt',
        iconColor: 'text-[#0078d4]',
        tags: ['Cloud Security', 'Azure'],
        complexity: 'Intermediate',
        summary: 'Cloud Security Posture Management (CSPM) and Workload Protection (CWP) in Azure.',
        content: `
            <h4>What is Defender for Cloud?</h4>
            <p>Microsoft Defender for Cloud is a unified cloud-native application protection platform (CNAPP) that helps strengthen your security posture and protects workloads.</p>

            <h4>Key Capabilities</h4>
            <ul class="list-disc list-inside space-y-2 my-4 text-[#c9d1d9]">
                <li><strong>Secure Score:</strong> A single metric to assess your security posture.</li>
                <li><strong>Recommendations:</strong> Actionable steps to fix misconfigurations (e.g., "Enable MFA", "Encrypt SQL DB").</li>
                <li><strong>Threat Detection:</strong> Alerts on suspicious activities like brute force attacks or malware on VMs.</li>
            </ul>
        `
    },
    {
        id: 'azure-sentinel',
        title: 'Microsoft Sentinel (SIEM)',
        icon: 'fas fa-binoculars',
        iconColor: 'text-[#0078d4]',
        tags: ['Cloud Security', 'Azure'],
        complexity: 'Advanced',
        summary: 'Cloud-native SIEM and SOAR solution for intelligent security analytics and threat intelligence.',
        content: `
            <h4>What is Microsoft Sentinel?</h4>
            <p>Microsoft Sentinel is a scalable, cloud-native, security information and event management (SIEM) and security orchestration, automation, and response (SOAR) solution.</p>

            <h4>Core Functions</h4>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 my-4">
                <div class="panel p-3 border border-[#30363d]">
                    <h5 class="font-bold text-[#58a6ff]">Collect</h5>
                    <p class="text-xs text-[#8b949e]">Data at cloud scale across all users, devices, applications, and infrastructure.</p>
                </div>
                <div class="panel p-3 border border-[#30363d]">
                    <h5 class="font-bold text-[#58a6ff]">Detect</h5>
                    <p class="text-xs text-[#8b949e]">Previously undetected threats and minimize false positives using Microsoft's analytics.</p>
                </div>
                <div class="panel p-3 border border-[#30363d]">
                    <h5 class="font-bold text-[#58a6ff]">Investigate</h5>
                    <p class="text-xs text-[#8b949e]">Threats with artificial intelligence and hunt for suspicious activities at scale.</p>
                </div>
                <div class="panel p-3 border border-[#30363d]">
                    <h5 class="font-bold text-[#58a6ff]">Respond</h5>
                    <p class="text-xs text-[#8b949e]">To incidents rapidly with built-in orchestration and automation of common tasks.</p>
                </div>
            </div>
        `
    },
    {
        id: 'ip-addressing',
        title: 'IP Addressing & CIDR',
        icon: 'fas fa-network-wired',
        iconColor: 'text-[#3fb950]',
        tags: ['Networking', 'Basics'],
        complexity: 'Beginner',
        summary: 'Understanding IPv4, IPv6, Subnet Masks, and CIDR notation.',
        content: `
            <h4>IPv4 vs IPv6</h4>
            <p>IP addresses are unique identifiers for devices on a network.</p>
            <ul class="list-disc list-inside space-y-2 my-4 text-[#c9d1d9]">
                <li><strong>IPv4:</strong> 32-bit address (e.g., <code>192.168.1.1</code>). ~4.3 billion addresses.</li>
                <li><strong>IPv6:</strong> 128-bit address (e.g., <code>2001:0db8:85a3::8a2e:0370:7334</code>). Virtually infinite.</li>
            </ul>

            <h4>CIDR Notation (Classless Inter-Domain Routing)</h4>
            <p>A compact way to represent an IP address and its associated network mask.</p>
            <div class="bg-[#161b22] p-3 rounded border border-[#30363d] my-4 font-mono text-sm">
                <p>Format: IP_Address/Prefix_Length</p>
                <p class="mt-2 text-[#58a6ff]">Example: 192.168.1.0/24</p>
                <ul class="text-[#8b949e] mt-1 ml-4">
                    <li>IP Range: 192.168.1.0 - 192.168.1.255</li>
                    <li>Total IPs: 256</li>
                    <li>Subnet Mask: 255.255.255.0</li>
                </ul>
            </div>
        `
    },
    {
        id: 'azure-networking',
        title: 'Azure Networking Basics',
        icon: 'fas fa-project-diagram',
        iconColor: 'text-[#0078d4]',
        tags: ['Networking', 'Azure'],
        complexity: 'Intermediate',
        summary: 'Virtual Networks (VNet), Subnets, NSGs, and Azure Firewall.',
        content: `
            <h4>Virtual Network (VNet)</h4>
            <p>The fundamental building block for your private network in Azure. VNet enables many types of Azure resources, such as Azure Virtual Machines (VM), to securely communicate with each other, the internet, and on-premises networks.</p>

            <h4>Network Security Groups (NSG)</h4>
            <p>An NSG contains security rules that allow or deny inbound network traffic to, or outbound network traffic from, several types of Azure resources.</p>
            <ul class="list-disc list-inside space-y-2 my-4 text-[#c9d1d9]">
                <li><strong>Inbound Rules:</strong> Control traffic coming into the subnet/VM (e.g., Allow HTTPS on port 443).</li>
                <li><strong>Outbound Rules:</strong> Control traffic leaving the subnet/VM.</li>
            </ul>

            <h4>Azure Firewall</h4>
            <p>A managed, cloud-based network security service that protects your Azure Virtual Network resources. It's a fully stateful firewall as a service with built-in high availability and unrestricted cloud scalability.</p>
        `
    },
    {
        id: 'azure-app-service-dns',
        title: 'Azure App Service DNS',
        icon: 'fas fa-globe',
        iconColor: 'text-[#0078d4]',
        tags: ['Azure', 'Hosting'],
        complexity: 'Intermediate',
        summary: 'Configuring custom domains for Azure Web Apps using CNAME and TXT verification.',
        content: `
            <h4>Custom Domains in Azure App Service</h4>
            <p>To map a custom domain (e.g., <code>www.contoso.com</code>) to your Azure Web App, you typically use a CNAME record.</p>

            <h4>Verification Process</h4>
            <p>Azure needs to verify you own the domain before allowing the mapping. This is often done via a TXT record if you want to map the domain without downtime (pre-verification).</p>
            
            <div class="bg-[#161b22] p-3 rounded border border-[#30363d] my-4">
                <h5 class="text-[#c9d1d9] font-semibold mb-2">The "asuid" Record</h5>
                <p class="text-sm text-[#8b949e] mb-2">To verify ownership without pointing traffic yet, create a TXT record:</p>
                <code class="block bg-[#0d1117] p-2 rounded text-xs text-[#58a6ff]">asuid.www.contoso.com TXT "verification-hash-from-azure"</code>
            </div>

            <h4>Root Domains (Apex)</h4>
            <p>Since CNAMEs are not allowed at the root (<code>contoso.com</code>), Azure recommends using an <strong>A Record</strong> pointing to the App Service IP, or using an <strong>Alias Record</strong> if using Azure DNS.</p>
        `
    },
    {
        id: 'azure-traffic-manager',
        title: 'Azure Traffic Manager',
        icon: 'fas fa-random',
        iconColor: 'text-[#0078d4]',
        tags: ['Azure', 'Networking'],
        complexity: 'Advanced',
        summary: 'DNS-based traffic load balancer that distributes traffic across global Azure regions.',
        content: `
            <h4>What is Traffic Manager?</h4>
            <p>Azure Traffic Manager is a DNS-based traffic load balancer. It allows you to distribute traffic to your public facing applications across the global Azure regions.</p>

            <h4>How it Works</h4>
            <ol class="list-decimal list-inside space-y-2 my-4 text-[#c9d1d9]">
                <li>User queries <code>myapp.contoso.com</code>.</li>
                <li>DNS resolves to Traffic Manager profile (<code>myapp.trafficmanager.net</code>).</li>
                <li>Traffic Manager checks the <strong>Routing Method</strong> (Priority, Weighted, Performance, Geographic).</li>
                <li>Traffic Manager returns the CNAME of the best endpoint (e.g., <code>myapp-eu.azurewebsites.net</code>).</li>
                <li>User connects directly to that endpoint.</li>
            </ol>
            
            <p class="text-sm text-[#8b949e]">Note: Traffic Manager does not see the actual HTTP traffic; it only directs the DNS query.</p>
        `
    },
    {
        id: 'azure-front-door',
        title: 'Azure Front Door',
        icon: 'fas fa-door-open',
        iconColor: 'text-[#79c0ff]',
        tags: ['Azure', 'Networking'],
        complexity: 'Advanced',
        summary: 'Global CDN and Load Balancer using Anycast DNS for low-latency access.',
        content: `
            <h4>Global Entry Point</h4>
            <p>Azure Front Door is a modern Content Delivery Network (CDN) that provides fast, reliable, and secure access between your users and your applications' static and dynamic web content.</p>

            <h4>Anycast DNS</h4>
            <p>Front Door uses Anycast networking. The same IP address is advertised from hundreds of edge locations worldwide. Users connect to the closest Azure POP (Point of Presence).</p>

            <h4>CNAME Flattening</h4>
            <p>Unlike Traffic Manager, Front Door terminates the connection (Split TCP) and proxies the traffic. It supports CNAME flattening (via Alias records in Azure DNS) to allow mapping to the root domain.</p>
        `
    },
    {
        id: 'azure-private-dns',
        title: 'Azure Private DNS',
        icon: 'fas fa-lock',
        iconColor: 'text-[#3fb950]',
        tags: ['Azure', 'Networking'],
        complexity: 'Intermediate',
        summary: 'Resolving domain names in a private virtual network without adding custom DNS servers.',
        content: `
            <h4>Split-Horizon DNS</h4>
            <p>Azure Private DNS allows you to use your own domain names (e.g., <code>db.internal.contoso.com</code>) within your Virtual Networks (VNet).</p>

            <h4>Key Features</h4>
            <ul class="list-disc list-inside space-y-2 my-4 text-[#c9d1d9]">
                <li><strong>No Infrastructure:</strong> You don't need to manage VM-based DNS servers.</li>
                <li><strong>Automatic Registration:</strong> VMs in the VNet can automatically register their A records.</li>
                <li><strong>Split-Horizon:</strong> You can have a public zone <code>contoso.com</code> and a private zone <code>contoso.com</code>. Internal users see internal IPs; external users see public IPs.</li>
            </ul>
        `
    },
    {
        id: 'a-record',
        title: 'A Record',
        icon: 'fas fa-map-marker-alt',
        iconColor: 'text-[#58a6ff]',
        tags: ['DNS', 'Basics'],
        complexity: 'Beginner',
        summary: 'Maps a hostname to an IPv4 address.',
        content: `
            <h4>What is an A Record?</h4>
            <p>The A record is the most fundamental and widely used record type in DNS. Its purpose is to map a hostname directly to a 32-bit IPv4 address. The "A" stands for "Address".</p>
            
            <h4>How A Records Work</h4>
            <p>When a DNS query is made for a domain:</p>
            <ol class="list-decimal list-inside space-y-2 my-4 text-[#c9d1d9]">
              <li>The DNS resolver checks for A records associated with that domain</li>
              <li>The A record returns the IPv4 address (like 192.0.2.1)</li>
              <li>The browser connects to that IP address to load the website</li>
            </ol>
            
            <h4>A Record Format</h4>
            <pre class="bg-[#0d1117] p-3 rounded border border-[#30363d] text-xs font-mono text-[#c9d1d9]"><code>www.example.com. 14400 IN A 192.0.2.1</code></pre>
            <p class="mt-2"><strong>Components:</strong></p>
            <ul class="list-disc list-inside space-y-1 text-sm text-[#8b949e]">
              <li><strong>Name:</strong> www.example.com. (note the trailing dot)</li>
              <li><strong>TTL:</strong> 14400 (14,400 seconds, or 4 hours)</li>
              <li><strong>Class:</strong> IN (Internet)</li>
              <li><strong>Type:</strong> A</li>
              <li><strong>RDATA:</strong> 192.0.2.1 (the IPv4 address)</li>
            </ul>
            
            <h4>Primary Use Cases</h4>
            <ul class="list-disc list-inside space-y-2 my-4 text-[#c9d1d9]">
              <li><strong>Website Address Resolution:</strong> Points domain names to web servers</li>
              <li><strong>Round-Robin Load Balancing:</strong> Multiple A records for the same hostname distribute traffic across servers</li>
              <li><strong>DNS-based Blackhole Lists (DNSBL):</strong> Used by mail servers to combat spam</li>
            </ul>
        `
    },
    {
        id: 'aaaa-record',
        title: 'AAAA Record',
        icon: 'fas fa-map-marker',
        iconColor: 'text-[#58a6ff]',
        tags: ['DNS', 'Basics'],
        complexity: 'Beginner',
        summary: 'Maps a hostname to an IPv6 address.',
        content: `
            <h4>Understanding AAAA Records</h4>
            <p>The AAAA record serves the same purpose as the A record but for the next generation of Internet Protocol, IPv6. It maps a hostname to a 128-bit IPv6 address.</p>
            
            <h4>Format and Example</h4>
            <pre class="bg-[#0d1117] p-3 rounded border border-[#30363d] text-xs font-mono text-[#c9d1d9]"><code>www.example.com. 3600 IN AAAA 2001:db8:85a3::8a2e:370:7334</code></pre>
            
            <h4>Use Cases</h4>
            <ul class="list-disc list-inside space-y-2 my-4 text-[#c9d1d9]">
              <li><strong>IPv6 Accessibility:</strong> Essential as IPv4 addresses become exhausted</li>
              <li><strong>Dual-Stack Operation:</strong> Common to have both A and AAAA records for the same hostname</li>
            </ul>
        `
    },
    {
        id: 'cname-record',
        title: 'CNAME Record',
        icon: 'fas fa-exchange-alt',
        iconColor: 'text-[#a855f7]',
        tags: ['DNS', 'Basics'],
        complexity: 'Intermediate',
        summary: 'Maps one hostname to another (alias).',
        content: `
            <h4>CNAME (Canonical Name) Records Explained</h4>
            <p>A CNAME record does not point a hostname to an IP address. Instead, it creates an alias by mapping one hostname to another, "canonical" hostname.</p>
            
            <h4>Format and Example</h4>
            <pre class="bg-[#0d1117] p-3 rounded border border-[#30363d] text-xs font-mono text-[#c9d1d9]"><code>ftp.example.com. 3600 IN CNAME www.example.com.</code></pre>
            
            <h4>Critical Limitations</h4>
            <div class="bg-[#161b22] p-3 rounded border border-[#30363d] my-4">
              <p class="text-[#f85149] font-semibold">⚠️ Important Restrictions:</p>
              <ul class="list-disc list-inside space-y-1 text-sm text-[#8b949e] mt-2">
                <li><strong>No CNAME at Zone Apex:</strong> Cannot use CNAME for the root domain (example.com)</li>
                <li><strong>Exclusivity Rule:</strong> A hostname with a CNAME cannot have any other record types</li>
                <li><strong>Must Point to Domain:</strong> RDATA must be a domain name, never an IP address</li>
              </ul>
            </div>
        `
    },
    {
        id: 'mx-record',
        title: 'MX Record',
        icon: 'fas fa-envelope',
        iconColor: 'text-[#f85149]',
        tags: ['DNS', 'Email'],
        complexity: 'Intermediate',
        summary: 'Specifies mail servers responsible for accepting email.',
        content: `
            <h4>MX (Mail Exchange) Records Deep Dive</h4>
            <p>An MX record specifies the mail server or servers responsible for accepting email messages on behalf of a domain name.</p>
            
            <h4>Format and Structure</h4>
            <pre class="bg-[#0d1117] p-3 rounded border border-[#30363d] text-xs font-mono text-[#c9d1d9]"><code>example.com. 3600 IN MX 10 mail.example.com.</code></pre>
            
            <h4>Priority System</h4>
            <p>The priority number is crucial. Sending MTAs attempt delivery to the server with the <strong>lowest</strong> priority number first.</p>
            
            <div class="bg-[#161b22] p-3 rounded border border-[#30363d] my-4">
                <h5 class="text-[#c9d1d9] font-semibold mb-2">Redundancy Example</h5>
                <pre class="text-xs text-[#8b949e]">example.com. IN MX 10 primary.mail.example.com.
example.com. IN MX 20 backup.mail.example.com.</pre>
            </div>
        `
    },
    {
        id: 'txt-record',
        title: 'TXT Record',
        icon: 'fas fa-file-alt',
        iconColor: 'text-[#7ee787]',
        tags: ['DNS', 'Basics', 'Security'],
        complexity: 'Intermediate',
        summary: 'Stores text-based information, often for verification (SPF, DKIM).',
        content: `
            <h4>TXT Records: The Swiss Army Knife of DNS</h4>
            <p>Originally designed to associate arbitrary text with a domain, TXT records are now the standard for verification and policy enforcement.</p>
            
            <h4>Common Uses</h4>
            <ul class="list-disc list-inside space-y-2 my-4 text-[#c9d1d9]">
              <li><strong>Domain Verification:</strong> Google/Microsoft verification strings.</li>
              <li><strong>SPF:</strong> <code>"v=spf1 include:_spf.google.com ~all"</code></li>
              <li><strong>DMARC:</strong> <code>"v=DMARC1; p=reject; ..."</code></li>
              <li><strong>DKIM:</strong> Public keys for email signing.</li>
            </ul>
        `
    },
    {
        id: 'ns-record',
        title: 'NS Record',
        icon: 'fas fa-sitemap',
        iconColor: 'text-[#d29922]',
        tags: ['DNS', 'Basics'],
        complexity: 'Intermediate',
        summary: 'Delegates a DNS zone to authoritative name servers.',
        content: `
            <h4>NS (Name Server) Records Authority</h4>
            <p>The NS record is used to delegate a DNS zone to a set of authoritative name servers. These records tell the internet which servers hold the "master copy" of your DNS records.</p>
            
            <h4>Format</h4>
            <pre class="bg-[#0d1117] p-3 rounded border border-[#30363d] text-xs font-mono text-[#c9d1d9]"><code>example.com. 86400 IN NS ns1.example-dns.com.</code></pre>
            
            <div class="bg-[#161b22] p-3 rounded border border-[#30363d] my-4">
              <p class="text-[#d29922] font-semibold">⚠️ Glue Records</p>
              <p class="text-sm text-[#8b949e] mt-1">When a name server is a subdomain of the domain it serves (e.g., ns1.example.com serving example.com), you must provide "Glue Records" (A records for the NS) at the registrar to prevent circular dependencies.</p>
            </div>
        `
    },
    {
        id: 'ptr-record',
        title: 'PTR Record',
        icon: 'fas fa-undo',
        iconColor: 'text-[#79c0ff]',
        tags: ['DNS', 'Email'],
        complexity: 'Advanced',
        summary: 'Reverse DNS: Maps an IP address back to a hostname.',
        content: `
            <h4>PTR Records: Reverse DNS</h4>
            <p>PTR records perform reverse DNS lookups, mapping IP addresses back to domain names. They are the inverse of A records.</p>
            
            <h4>Format</h4>
            <pre class="bg-[#0d1117] p-3 rounded border border-[#30363d] text-xs font-mono text-[#c9d1d9]"><code>1.2.0.192.in-addr.arpa. 3600 IN PTR example.com.</code></pre>
            
            <h4>Importance for Email</h4>
            <p>Mail servers often reject email from IPs that do not have a valid PTR record (Reverse DNS) that matches the hostname in the HELO banner.</p>
        `
    },
    {
        id: 'srv-record',
        title: 'SRV Record',
        icon: 'fas fa-server',
        iconColor: 'text-[#8b949e]',
        tags: ['DNS', 'Advanced'],
        complexity: 'Advanced',
        summary: 'Specifies the location (hostname and port) of servers for specific services.',
        content: `
            <h4>SRV Records for Service Discovery</h4>
            <p>SRV records specify the hostname and port number for specific services (like VoIP, XMPP, or Active Directory).</p>
            
            <h4>Format</h4>
            <pre class="bg-[#0d1117] p-3 rounded border border-[#30363d] text-xs font-mono text-[#c9d1d9]"><code>_service._protocol.name. TTL IN SRV priority weight port target</code></pre>
            
            <h4>Example (SIP)</h4>
            <pre class="bg-[#0d1117] p-3 rounded border border-[#30363d] text-xs font-mono text-[#c9d1d9]"><code>_sip._tcp.example.com. 3600 IN SRV 10 5 5060 sip.example.com.</code></pre>
        `
    },
    {
        id: 'caa-record',
        title: 'CAA Record',
        icon: 'fas fa-certificate',
        iconColor: 'text-[#d2a8ff]',
        tags: ['DNS', 'Security'],
        complexity: 'Advanced',
        summary: 'Specifies which Certificate Authorities are allowed to issue certificates for a domain.',
        content: `
            <h4>CAA Records: Certificate Authority Authorization</h4>
            <p>CAA records allow domain owners to specify which Certificate Authorities (CAs) are allowed to issue SSL/TLS certificates for their domain.</p>
            
            <h4>Example</h4>
            <pre class="bg-[#0d1117] p-3 rounded border border-[#30363d] text-xs font-mono text-[#c9d1d9]"><code>example.com. 3600 IN CAA 0 issue "letsencrypt.org"</code></pre>
            
            <p class="mt-4">This prevents other CAs (like DigiCert or Sectigo) from issuing certificates for this domain, reducing the risk of unauthorized issuance.</p>
        `
    },
    {
        id: 'spf',
        title: 'SPF',
        icon: 'fas fa-shield-alt',
        iconColor: 'text-[#3fb950]',
        tags: ['Email', 'Security'],
        complexity: 'Intermediate',
        summary: 'Sender Policy Framework: Authorizes IPs to send email for a domain.',
        content: `
            <h4>SPF (Sender Policy Framework)</h4>
            <p>SPF is an email authentication mechanism that allows domain owners to specify which mail servers are authorized to send email on behalf of their domain.</p>
            
            <h4>Structure</h4>
            <pre class="bg-[#0d1117] p-3 rounded border border-[#30363d] text-xs font-mono text-[#c9d1d9]"><code>v=spf1 ip4:198.51.100.5 include:_spf.google.com -all</code></pre>
            
            <h4>Qualifiers</h4>
            <ul class="list-disc list-inside space-y-2 my-4 text-[#c9d1d9]">
              <li><strong>-all (Fail):</strong> Reject email from other IPs.</li>
              <li><strong>~all (SoftFail):</strong> Accept but mark as suspicious.</li>
              <li><strong>+all (Pass):</strong> Allow everything (Don't use this!).</li>
            </ul>
        `
    },
    {
        id: 'dkim',
        title: 'DKIM',
        icon: 'fas fa-key',
        iconColor: 'text-[#d29922]',
        tags: ['Email', 'Security'],
        complexity: 'Advanced',
        summary: 'DomainKeys Identified Mail: Adds a cryptographic signature to emails.',
        content: `
            <h4>DKIM: Digital Signatures for Email</h4>
            <p>DKIM ensures email integrity and authenticity by digitally signing messages with a private key. The public key is published in DNS.</p>
            
            <h4>How it Works</h4>
            <ol class="list-decimal list-inside space-y-2 my-4 text-[#c9d1d9]">
              <li>Sender signs email headers/body with private key.</li>
              <li>Receiver retrieves public key from DNS (TXT record).</li>
              <li>Receiver verifies the signature matches the content.</li>
            </ol>
        `
    },
    {
        id: 'dmarc',
        title: 'DMARC',
        icon: 'fas fa-user-shield',
        iconColor: 'text-[#f85149]',
        tags: ['Email', 'Security'],
        complexity: 'Advanced',
        summary: 'Domain-based Message Authentication, Reporting, and Conformance.',
        content: `
            <h4>DMARC: The Ultimate Email Security Protocol</h4>
            <p>DMARC unifies SPF and DKIM. It tells receivers what to do if an email fails authentication (Reject, Quarantine, or None).</p>
            
            <h4>Policies</h4>
            <ul class="list-disc list-inside space-y-2 my-4 text-[#c9d1d9]">
              <li><strong>p=none:</strong> Monitoring only. No action taken.</li>
              <li><strong>p=quarantine:</strong> Send failures to spam folder.</li>
              <li><strong>p=reject:</strong> Block failures completely.</li>
            </ul>
            
            <h4>Reporting</h4>
            <p>DMARC also provides reports (RUA/RUF) so you can see who is sending email as your domain.</p>
        `
    }
];

export function IntelPage() {
    return {
        query: '',
        results: null,
        loading: false,
        error: null,
        
        // Knowledge Base State
        concepts: KNOWLEDGE_BASE,
        conceptSearch: '',
        conceptFilter: 'All',
        
        // Modal State
        conceptModal: false,
        currentConcept: null,
        conceptContent: '',
        loadingConcept: false,
        conceptError: '',

        init() {
            // Check for query param
            const params = new URLSearchParams(window.location.search);
            const q = params.get('q');
            const conceptId = params.get('concept');
            
            if (q) {
                this.query = q;
                this.analyze();
            }
            
            if (conceptId) {
                const concept = this.concepts.find(c => c.id === conceptId);
                if (concept) {
                    this.showConcept(concept);
                }
            }
        },
        
        get filteredConcepts() {
            return this.concepts.filter(c => {
                const matchesSearch = c.title.toLowerCase().includes(this.conceptSearch.toLowerCase()) || 
                                      c.summary.toLowerCase().includes(this.conceptSearch.toLowerCase());
                
                // If user is searching, search the entire knowledge base
                if (this.conceptSearch) {
                    return matchesSearch;
                }

                // Default view: Show only Security/Intel related topics
                // This makes the TI Knowledge Base a "filtered version" of the global one
                if (this.conceptFilter === 'All') {
                     return c.tags.some(t => ['Threat Intel', 'Cloud Security', 'Malware', 'Security'].includes(t));
                } else {
                    // User selected a specific tag (e.g., "DNS")
                    return c.tags.includes(this.conceptFilter);
                }
            });
        },
        
        get allTags() {
            const tags = new Set(['All']);
            this.concepts.forEach(c => c.tags.forEach(t => tags.add(t)));
            return Array.from(tags);
        },

        // --- Investigation Logic ---

        async analyze() {
            if (!this.query.trim()) return;
            
            this.loading = true;
            this.error = null;
            this.results = null;

            const target = this.query.trim();
            const isIP = this.isValidIP(target);
            const isDomain = this.isValidDomain(target);
            const isHash = this.isValidHash(target);

            if (!isIP && !isDomain && !isHash) {
                this.error = "Invalid input. Please enter a valid Domain, IP address, or File Hash (MD5/SHA1/SHA256).";
                this.loading = false;
                return;
            }

            // Generate Deep Links
            const links = this.generateLinks(target, isIP, isDomain, isHash);
            
            this.results = {
                target: target,
                type: isIP ? 'IP Address' : (isHash ? 'File Hash' : 'Domain'),
                links: links
            };

            // Add to History
            addHistory({
                query: target,
                recordTypes: ['INTEL'],
                timestamp: Date.now(),
                success: true,
                duration: 0, // Instant
                results: this.results
            });

            this.loading = false;
        },

        generateLinks(target, isIP, isDomain, isHash) {
            const links = [];

            if (isIP) {
                links.push({ name: 'VirusTotal', url: `https://www.virustotal.com/gui/ip-address/${target}`, icon: 'fas fa-shield-virus', color: 'text-blue-500' });
                links.push({ name: 'AbuseIPDB', url: `https://www.abuseipdb.com/check/${target}`, icon: 'fas fa-ban', color: 'text-red-500' });
                links.push({ name: 'Talos Intelligence', url: `https://talosintelligence.com/reputation_center/lookup?search=${target}`, icon: 'fas fa-crosshairs', color: 'text-green-500' });
                links.push({ name: 'GreyNoise', url: `https://viz.greynoise.io/ip/${target}`, icon: 'fas fa-wave-square', color: 'text-gray-400' });
                links.push({ name: 'Shodan', url: `https://www.shodan.io/search?query=${target}`, icon: 'fas fa-search', color: 'text-red-600' });
                links.push({ name: 'Censys', url: `https://search.censys.io/hosts/${target}`, icon: 'fas fa-database', color: 'text-orange-500' });
                links.push({ name: 'Hybrid Analysis', url: `https://www.hybrid-analysis.com/search?query=${target}`, icon: 'fas fa-microscope', color: 'text-orange-400' });
                links.push({ name: 'Any.Run', url: `https://app.any.run/submissions/#search=${target}`, icon: 'fas fa-play-circle', color: 'text-red-500' });
            } else if (isDomain) {
                links.push({ name: 'VirusTotal', url: `https://www.virustotal.com/gui/domain/${target}`, icon: 'fas fa-shield-virus', color: 'text-blue-500' });
                links.push({ name: 'Urlscan.io', url: `https://urlscan.io/domain/${target}`, icon: 'fas fa-camera', color: 'text-green-500' });
                links.push({ name: 'Talos Intelligence', url: `https://talosintelligence.com/reputation_center/lookup?search=${target}`, icon: 'fas fa-crosshairs', color: 'text-green-500' });
                links.push({ name: 'Google Transparency', url: `https://transparencyreport.google.com/safe-browsing/search?url=${target}`, icon: 'fab fa-google', color: 'text-blue-400' });
                links.push({ name: 'AlienVault OTX', url: `https://otx.alienvault.com/indicator/domain/${target}`, icon: 'fas fa-rocket', color: 'text-green-400' });
                links.push({ name: 'CRT.sh', url: `https://crt.sh/?q=${target}`, icon: 'fas fa-certificate', color: 'text-purple-500' });
                links.push({ name: 'Hybrid Analysis', url: `https://www.hybrid-analysis.com/search?query=${target}`, icon: 'fas fa-microscope', color: 'text-orange-400' });
                links.push({ name: 'Joe Sandbox', url: `https://www.joesandbox.com/search?q=${target}`, icon: 'fas fa-box-open', color: 'text-yellow-500' });
                links.push({ name: 'Any.Run', url: `https://app.any.run/submissions/#search=${target}`, icon: 'fas fa-play-circle', color: 'text-red-500' });
                links.push({ name: 'Triage', url: `https://tria.ge/s?q=${target}`, icon: 'fas fa-bug', color: 'text-yellow-400' });
            } else if (isHash) {
                links.push({ name: 'VirusTotal', url: `https://www.virustotal.com/gui/file/${target}`, icon: 'fas fa-shield-virus', color: 'text-blue-500' });
                links.push({ name: 'Hybrid Analysis', url: `https://www.hybrid-analysis.com/search?query=${target}`, icon: 'fas fa-microscope', color: 'text-orange-400' });
                links.push({ name: 'Joe Sandbox', url: `https://www.joesandbox.com/search?q=${target}`, icon: 'fas fa-box-open', color: 'text-yellow-500' });
                links.push({ name: 'AlienVault OTX', url: `https://otx.alienvault.com/indicator/file/${target}`, icon: 'fas fa-rocket', color: 'text-green-400' });
                links.push({ name: 'Any.Run', url: `https://app.any.run/submissions/#search=${target}`, icon: 'fas fa-play-circle', color: 'text-red-500' });
                links.push({ name: 'Triage', url: `https://tria.ge/s?q=${target}`, icon: 'fas fa-bug', color: 'text-yellow-400' });
            }

            return links;
        },

        isValidIP(str) {
            const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
            return ipRegex.test(str);
        },

        isValidDomain(str) {
            const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
            return domainRegex.test(str);
        },

        isValidHash(str) {
            const md5 = /^[a-f0-9]{32}$/i;
            const sha1 = /^[a-f0-9]{40}$/i;
            const sha256 = /^[a-f0-9]{64}$/i;
            return md5.test(str) || sha1.test(str) || sha256.test(str);
        },

        // --- Knowledge Base Logic ---

        showConcept(concept) {
            // Handle string input (legacy or direct call) or object
            const conceptObj = typeof concept === 'string' 
                ? this.concepts.find(c => c.title === concept || c.id === concept) 
                : concept;

            if (!conceptObj) return;

            this.currentConcept = conceptObj.title;
            this.conceptModal = true;
            this.loadConcept(conceptObj);

            // Add to History
            addHistory({
                query: conceptObj.title,
                recordTypes: ['CONCEPT'],
                timestamp: Date.now(),
                success: true,
                duration: 0,
                results: {
                    id: conceptObj.id,
                    summary: conceptObj.summary
                }
            });
        },
        
        closeConcept() {
            this.conceptModal = false;
            this.conceptContent = '';
            this.conceptError = '';
            this.currentConcept = '';
        },
        
        async loadConcept(conceptObj) {
            this.loadingConcept = true;
            this.conceptError = '';
            this.conceptContent = '';
            
            try {
                // Simulate network delay for "Deep Research" feel
                await new Promise(resolve => setTimeout(resolve, 400));
                this.conceptContent = conceptObj.content;
            } catch (error) {
                this.conceptError = 'Failed to load content.';
            } finally {
                this.loadingConcept = false;
            }
        }
    };
}

