export const SECURITY_CONCEPTS = [
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
        id: 'ddos-attacks',
        title: 'DDoS Attacks',
        icon: 'fas fa-radiation',
        iconColor: 'text-[#f85149]',
        tags: ['Network Security', 'Threat Intel'],
        complexity: 'Intermediate',
        summary: 'Distributed Denial of Service: Overwhelming targets with a flood of internet traffic.',
        content: `
            <h4>Understanding DDoS</h4>
            <p>A Distributed Denial-of-Service (DDoS) attack is a malicious attempt to disrupt the normal traffic of a targeted server, service, or network by overwhelming the target or its surrounding infrastructure with a flood of Internet traffic.</p>
            
            <h4>Common Attack Types</h4>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 my-4">
                <div class="bg-[#161b22] p-3 rounded border border-[#30363d]">
                    <h5 class="text-[#f85149] font-semibold mb-1">Volumetric</h5>
                    <p class="text-xs text-[#8b949e]">Flooding the network with massive amounts of data (e.g., UDP floods, ICMP floods).</p>
                </div>
                <div class="bg-[#161b22] p-3 rounded border border-[#30363d]">
                    <h5 class="text-[#f85149] font-semibold mb-1">Protocol</h5>
                    <p class="text-xs text-[#8b949e]">Exploiting weaknesses in Layer 3 and 4 (e.g., SYN floods, Ping of Death).</p>
                </div>
                <div class="bg-[#161b22] p-3 rounded border border-[#30363d]">
                    <h5 class="text-[#f85149] font-semibold mb-1">Application Layer</h5>
                    <p class="text-xs text-[#8b949e]">Targeting specific web server functions (e.g., HTTP GET/POST floods, Slowloris).</p>
                </div>
                <div class="bg-[#161b22] p-3 rounded border border-[#30363d]">
                    <h5 class="text-[#f85149] font-semibold mb-1">Amplification</h5>
                    <p class="text-xs text-[#8b949e]">Using small queries to generate large responses (e.g., DNS Amplification, NTP Reflection).</p>
                </div>
            </div>
        `
    },
    {
        id: 'domain-generation-algorithms',
        title: 'Domain Generation Algorithms (DGA)',
        icon: 'fas fa-random',
        iconColor: 'text-[#d29922]',
        tags: ['Threat Intel', 'Malware'],
        complexity: 'Advanced',
        summary: 'How malware generates thousands of domains to evade blacklisting and maintain C2 communication.',
        content: `
            <h4>What is a DGA?</h4>
            <p>A Domain Generation Algorithm (DGA) is a technique used by malware to periodically generate a large number of domain names. These domains serve as rendezvous points for Command & Control (C2) servers.</p>

            <h4>Why use DGAs?</h4>
            <p>If malware uses a single hardcoded domain (e.g., <code>evil-c2.com</code>), defenders can easily block it. With DGA, the malware might try 1,000 random domains a day (e.g., <code>xkqz-123.com</code>, <code>abxy-999.net</code>). The attacker only needs to register <strong>one</strong> of them to regain control.</p>

            <h4>Detection</h4>
            <ul class="list-disc list-inside space-y-2 my-4 text-[#c9d1d9]">
                <li><strong>High Entropy:</strong> Domains look like random gibberish (e.g., <code>agbdfhjk.com</code>).</li>
                <li><strong>NXDOMAIN Responses:</strong> A sudden spike in "Domain Not Found" errors as the malware tries non-existent domains.</li>
                <li><strong>Machine Learning:</strong> Classifiers trained to distinguish English words from random strings.</li>
            </ul>
        `
    },
    {
        id: 'fast-flux',
        title: 'Fast Flux',
        icon: 'fas fa-sync-alt',
        iconColor: 'text-[#f85149]',
        tags: ['Threat Intel', 'Network Security'],
        complexity: 'Advanced',
        summary: 'A DNS technique used by botnets to hide phishing and malware delivery sites behind an ever-changing network of compromised hosts.',
        content: `
            <h4>What is Fast Flux?</h4>
            <p>Fast Flux is a DNS technique used by botnets to hide phishing and malware delivery sites behind an ever-changing network of compromised hosts acting as proxies.</p>

            <h4>How it Works</h4>
            <p>The authoritative name server for a malicious domain returns a different set of IP addresses (A records) for every query, with a very short Time-To-Live (TTL). These IPs are usually compromised home routers or IoT devices.</p>

            <h4>Types of Fast Flux</h4>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 my-4">
                <div class="bg-[#161b22] p-3 rounded border border-[#30363d]">
                    <h5 class="text-[#f85149] font-semibold mb-1">Single Flux</h5>
                    <p class="text-xs text-[#8b949e]">The IP addresses of the web server change rapidly.</p>
                </div>
                <div class="bg-[#161b22] p-3 rounded border border-[#30363d]">
                    <h5 class="text-[#f85149] font-semibold mb-1">Double Flux</h5>
                    <p class="text-xs text-[#8b949e]">Both the web server IPs AND the authoritative Name Server IPs change rapidly. Extremely hard to take down.</p>
                </div>
            </div>
        `
    },
    {
        id: 'file-hash-analysis',
        title: 'File Hash Analysis',
        icon: 'fas fa-file-signature',
        iconColor: 'text-[#a855f7]',
        tags: ['Threat Intel', 'Malware'],
        complexity: 'Beginner',
        summary: 'Using cryptographic hashes (MD5, SHA256) to identify known malicious files without executing them.',
        content: `
            <h4>What is a File Hash?</h4>
            <p>A hash is a unique alphanumeric string generated by a mathematical algorithm (like MD5, SHA-1, or SHA-256) based on the contents of a file. If you change a single bit in the file, the hash changes completely.</p>

            <h4>Why use Hashes?</h4>
            <ul class="list-disc list-inside space-y-2 my-4 text-[#c9d1d9]">
                <li><strong>Identification:</strong> Quickly check if a file is known malware by searching its hash in databases like VirusTotal.</li>
                <li><strong>Integrity:</strong> Verify that a downloaded file hasn't been tampered with.</li>
                <li><strong>Safety:</strong> You can share a hash with other analysts without sharing the dangerous malware file itself.</li>
            </ul>

            <h4>Limitations</h4>
            <p>Hashes are brittle. Attackers can change a single byte (e.g., adding a null character) to change the hash ("Hash Busting"), bypassing hash-based detection.</p>
        `
    },
    {
        id: 'dns-sinkhole',
        title: 'DNS Sinkhole',
        icon: 'fas fa-filter',
        iconColor: 'text-[#3fb950]',
        tags: ['Threat Intel', 'Network Security'],
        complexity: 'Intermediate',
        summary: 'A defense mechanism that intercepts DNS queries for malicious domains and redirects them to a safe IP.',
        content: `
            <h4>What is a DNS Sinkhole?</h4>
            <p>A DNS sinkhole is a mechanism used by defenders to intercept DNS queries attempting to resolve known malicious domains (e.g., C2 servers, botnet controllers) and return a false IP address.</p>

            <h4>How it Works</h4>
            <ol class="list-decimal list-inside space-y-2 my-4 text-[#c9d1d9]">
                <li>A compromised device inside the network tries to contact <code>malware-c2.com</code>.</li>
                <li>The internal DNS server checks its blocklist.</li>
                <li>Instead of returning the real IP of the C2 server, it returns the IP of the Sinkhole Server (e.g., <code>10.10.10.10</code>).</li>
                <li>The compromised device connects to the Sinkhole Server instead of the attacker.</li>
            </ol>

            <h4>Benefits</h4>
            <ul class="list-disc list-inside space-y-2 my-4 text-[#c9d1d9]">
                <li><strong>Containment:</strong> Prevents malware from receiving commands or exfiltrating data.</li>
                <li><strong>Identification:</strong> Defenders can monitor logs on the Sinkhole Server to identify exactly which internal machines are infected.</li>
            </ul>
        `
    },
    {
        id: 'fuzzy-hashing',
        title: 'Fuzzy Hashing (SSDEEP)',
        icon: 'fas fa-fingerprint',
        iconColor: 'text-[#d2a8ff]',
        tags: ['Threat Intel', 'Malware'],
        complexity: 'Advanced',
        summary: 'Unlike standard hashes (MD5), fuzzy hashes can detect similarities between two files, even if they are not identical.',
        content: `
            <h4>The Problem with MD5/SHA256</h4>
            <p>Standard cryptographic hashes are designed to be unique. Changing one byte in a file changes the entire hash. This is great for integrity, but bad for malware detection, as attackers can easily "re-compile" malware to change its hash.</p>

            <h4>Enter Fuzzy Hashing</h4>
            <p>Fuzzy hashing (Context Triggered Piecewise Hashing), commonly implemented as <strong>SSDEEP</strong>, breaks a file into chunks and hashes them separately. It then produces a signature that allows analysts to compare two files and calculate a percentage of similarity.</p>

            <h4>Use Case</h4>
            <p>If you have a known malware sample and find a suspicious file that has a different MD5 but a 95% SSDEEP match, it is highly likely a variant of the same malware family.</p>
        `
    },
    {
        id: 'ja3-fingerprinting',
        title: 'JA3 Fingerprinting',
        icon: 'fas fa-handshake',
        iconColor: 'text-[#f85149]',
        tags: ['Threat Intel', 'Network Security'],
        complexity: 'Advanced',
        summary: 'A method to fingerprint SSL/TLS client applications based on the unique way they initiate a connection.',
        content: `
            <h4>What is JA3?</h4>
            <p>JA3 is a method for creating a fingerprint of an SSL/TLS client (like a browser, malware, or script) based on the fields in its <code>Client Hello</code> packet.</p>

            <h4>How it Works</h4>
            <p>When a client initiates a TLS connection, it sends a Hello packet containing:</p>
            <ul class="list-disc list-inside text-sm text-[#8b949e] my-2">
                <li>SSL/TLS Version</li>
                <li>Accepted Cipher Suites</li>
                <li>List of Extensions</li>
                <li>Elliptic Curves</li>
                <li>Elliptic Curve Formats</li>
            </ul>
            <p>These values are concatenated and hashed (MD5) to create a 32-character JA3 fingerprint.</p>

            <h4>Why it Matters</h4>
            <p>Even if malware changes its IP address or domain, its underlying code libraries (e.g., Python requests, Go net/http, or custom C2 code) often produce the same JA3 hash. This allows defenders to track and block tools regardless of where they connect.</p>
        `
    }
];
