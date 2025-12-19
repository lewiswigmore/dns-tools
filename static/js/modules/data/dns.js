export const DNS_CONCEPTS = [
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
        id: 'dnssec',
        title: 'DNSSEC',
        icon: 'fas fa-file-signature',
        iconColor: 'text-[#3fb950]',
        tags: ['DNS', 'Security'],
        complexity: 'Advanced',
        summary: 'DNS Security Extensions: Protecting the DNS infrastructure from cache poisoning and spoofing.',
        content: `
            <h4>What is DNSSEC?</h4>
            <p>DNSSEC (Domain Name System Security Extensions) adds a layer of security to the DNS protocol by enabling DNS responses to be validated. It does not provide privacy (encryption), but it does provide <strong>integrity</strong> and <strong>authenticity</strong>.</p>
            
            <h4>How it Works</h4>
            <p>DNSSEC uses digital signatures based on public-key cryptography. When a DNSSEC-enabled resolver requests a record, it also receives a digital signature (RRSIG). The resolver then uses the public key (DNSKEY) to verify that the record hasn't been tampered with.</p>
            
            <div class="bg-[#161b22] p-3 rounded border border-[#30363d] my-4">
                <h5 class="text-[#c9d1d9] font-semibold mb-2">Key Record Types</h5>
                <ul class="text-xs text-[#8b949e] space-y-1">
                    <li><strong>RRSIG:</strong> Resource Record Signature.</li>
                    <li><strong>DNSKEY:</strong> Contains the public signing key.</li>
                    <li><strong>DS:</strong> Delegation Signer (placed in the parent zone).</li>
                    <li><strong>NSEC/NSEC3:</strong> Next Secure record (proves a record doesn't exist).</li>
                </ul>
            </div>
        `
    }
];
