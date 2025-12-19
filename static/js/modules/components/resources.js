export function ResourcesPage() {
    return {
      conceptModal: false,
      currentConcept: '',
      conceptContent: '',
      loadingConcept: false,
      conceptError: '',
      conceptAnimations: {},
      
      init() {
        // Initialize random pulse animations for DNS concepts
        this.initRandomPulseAnimations();
      },
      
      initRandomPulseAnimations() {
        const concepts = [
          'A Record', 'AAAA Record', 'CNAME Record', 'MX Record', 
          'TXT Record', 'NS Record', 'PTR Record', 'SRV Record', 'CAA Record',
          'SPF', 'DKIM', 'DMARC'
        ];
        
        // Randomly select 3-4 concepts to pulse
        const numToPulse = Math.floor(Math.random() * 2) + 3; // 3 or 4 concepts
        const shuffled = concepts.sort(() => 0.5 - Math.random());
        const selectedConcepts = shuffled.slice(0, numToPulse);
        
        // Initialize all concepts as not pulsing
        concepts.forEach(concept => {
          this.conceptAnimations[concept] = false;
        });
        
        // Add staggered pulse animations
        selectedConcepts.forEach((concept, index) => {
          setTimeout(() => {
            this.conceptAnimations[concept] = true;
            
            // Stop pulsing after user has been on page for a while (15 seconds)
            setTimeout(() => {
              this.conceptAnimations[concept] = false;
            }, 15000);
          }, index * 800); // Stagger the start times by 800ms
        });
      },
      
      showConcept(conceptName) {
        this.currentConcept = conceptName;
        this.conceptModal = true;
        this.loadConcept(conceptName);
      },
      
      closeConcept() {
        this.conceptModal = false;
        this.conceptContent = '';
        this.conceptError = '';
        this.currentConcept = '';
      },
      
      async loadConcept(conceptName) {
        this.loadingConcept = true;
        this.conceptError = '';
        this.conceptContent = '';
        
        try {
          // For now, provide placeholder content until Gemini integration
          await new Promise(resolve => setTimeout(resolve, 800)); // Simulate loading
          
          this.conceptContent = this.getPlaceholderContent(conceptName);
          
          // TODO: Replace with actual Gemini Deep Research API call
          // const response = await fetch('/api/concept-research', {
          //   method: 'POST',
          //   headers: { 'Content-Type': 'application/json' },
          //   body: JSON.stringify({ concept: conceptName })
          // });
          // const data = await response.json();
          // this.conceptContent = data.content;
          
        } catch (error) {
          this.conceptError = 'Failed to load detailed explanation. Please try again.';
        } finally {
          this.loadingConcept = false;
        }
      },
      
      getPlaceholderContent(conceptName) {
        const content = {
          'A Record': `
            <h4>What is an A Record?</h4>
            <p>The A record is the most fundamental and widely used record type in DNS. Its purpose is to map a hostname directly to a 32-bit IPv4 address. The "A" stands for "Address".</p>
            
            <h4>How A Records Work</h4>
            <p>When a DNS query is made for a domain:</p>
            <ol>
              <li>The DNS resolver checks for A records associated with that domain</li>
              <li>The A record returns the IPv4 address (like 192.0.2.1)</li>
              <li>The browser connects to that IP address to load the website</li>
            </ol>
            
            <h4>A Record Format</h4>
            <pre><code>www.example.com. 14400 IN A 192.0.2.1</code></pre>
            <p><strong>Components:</strong></p>
            <ul>
              <li><strong>Name:</strong> www.example.com. (note the trailing dot)</li>
              <li><strong>TTL:</strong> 14400 (14,400 seconds, or 4 hours)</li>
              <li><strong>Class:</strong> IN (Internet)</li>
              <li><strong>Type:</strong> A</li>
              <li><strong>RDATA:</strong> 192.0.2.1 (the IPv4 address)</li>
            </ul>
            
            <h4>Primary Use Cases</h4>
            <ul>
              <li><strong>Website Address Resolution:</strong> Points domain names to web servers</li>
              <li><strong>Round-Robin Load Balancing:</strong> Multiple A records for the same hostname distribute traffic across servers</li>
              <li><strong>DNS-based Blackhole Lists (DNSBL):</strong> Used by mail servers to combat spam</li>
            </ul>
            
            <h4>Best Practices</h4>
            <ul>
              <li>Use appropriate TTL values (300-86400 seconds typical)</li>
              <li>Avoid pointing multiple A records to the same IP unless needed for redundancy</li>
              <li>Consider using AAAA records for IPv6 support alongside A records</li>
              <li>Test changes in a staging environment first</li>
              <li>Lower TTL values before planned IP changes to enable faster propagation</li>
            </ul>
          `,
          'AAAA Record': `
            <h4>Understanding AAAA Records</h4>
            <p>The AAAA record serves the same purpose as the A record but for the next generation of Internet Protocol, IPv6. It maps a hostname to a 128-bit IPv6 address. The name "AAAA" signifies that IPv6 addresses (128 bits) are four times the size of IPv4 addresses (32 bits).</p>
            
            <h4>Format and Example</h4>
            <pre><code>www.example.com. 3600 IN AAAA 2001:db8:85a3::8a2e:370:7334</code></pre>
            <p><strong>Components:</strong></p>
            <ul>
              <li><strong>Name:</strong> www.example.com.</li>
              <li><strong>TTL:</strong> 3600 (1 hour)</li>
              <li><strong>Class:</strong> IN</li>
              <li><strong>Type:</strong> AAAA</li>
              <li><strong>RDATA:</strong> 2001:db8:85a3::8a2e:370:7334 (IPv6 address)</li>
            </ul>
            
            <h4>Use Cases and Considerations</h4>
            <ul>
              <li><strong>IPv6 Accessibility:</strong> Essential as IPv4 addresses become exhausted</li>
              <li><strong>Dual-Stack Operation:</strong> Common to have both A and AAAA records for the same hostname</li>
              <li><strong>Future-Proofing:</strong> Prepares infrastructure for IPv6 adoption</li>
              <li><strong>Client Priority:</strong> IPv6-capable devices typically prioritize AAAA records</li>
            </ul>
            
            <h4>Implementation Strategy</h4>
            <p>To ensure connectivity for all users, maintain an A record as fallback when implementing AAAA records, as not all Internet Service Providers fully support IPv6 yet. This dual-stack configuration ensures universal accessibility.</p>
          `,
          'CNAME Record': `
            <h4>CNAME (Canonical Name) Records Explained</h4>
            <p>A CNAME record does not point a hostname to an IP address. Instead, it creates an alias by mapping one hostname to another, "canonical" hostname. When a DNS resolver encounters a CNAME record, it stops its current query and starts a new one for the canonical name provided.</p>
            
            <h4>Format and Example</h4>
            <pre><code>ftp.example.com. 3600 IN CNAME www.example.com.</code></pre>
            <p><strong>Components:</strong></p>
            <ul>
              <li><strong>Name:</strong> ftp.example.com. (the alias)</li>
              <li><strong>TTL:</strong> 3600</li>
              <li><strong>Class:</strong> IN</li>
              <li><strong>Type:</strong> CNAME</li>
              <li><strong>RDATA:</strong> www.example.com. (the canonical name)</li>
            </ul>
            
            <h4>Common Use Cases</h4>
            <ul>
              <li><strong>Simplifying IP Management:</strong> Point multiple subdomains to a single canonical name</li>
              <li><strong>Third-Party Service Integration:</strong> Delegate subdomains to external services (CDNs, e-commerce platforms)</li>
              <li><strong>Service Flexibility:</strong> Change backend services without updating multiple records</li>
            </ul>
            
            <h4>Critical Limitations</h4>
            <div style="background: #21262d; border-left: 3px solid #f85149; padding: 12px; margin: 16px 0;">
              <p><strong>⚠️ Important Restrictions:</strong></p>
              <ul>
                <li><strong>No CNAME at Zone Apex:</strong> Cannot use CNAME for the root domain (example.com)</li>
                <li><strong>Exclusivity Rule:</strong> A hostname with a CNAME cannot have any other record types</li>
                <li><strong>Must Point to Domain:</strong> RDATA must be a domain name, never an IP address</li>
                <li><strong>Avoid Chaining:</strong> CNAME pointing to another CNAME creates performance issues</li>
              </ul>
            </div>
            
            <h4>Modern Challenges</h4>
            <p>The prohibition of CNAMEs at the zone apex presents challenges in cloud architectures. This has led to proprietary record types like ALIAS or ANAME by DNS providers, which mimic CNAME functionality at the apex by resolving targets server-side.</p>
          `,
          'MX Record': `
            <h4>MX (Mail Exchange) Records Deep Dive</h4>
            <p>An MX record specifies the mail server or servers responsible for accepting email messages on behalf of a domain name. These records are essential for email functionality, as they direct sending Mail Transfer Agents (MTAs) to the correct destination according to SMTP protocol.</p>
            
            <h4>Format and Structure</h4>
            <pre><code>example.com. 3600 IN MX 10 mail.example.com.</code></pre>
            <p><strong>Components:</strong></p>
            <ul>
              <li><strong>Name:</strong> example.com. (typically the apex domain)</li>
              <li><strong>TTL:</strong> 3600</li>
              <li><strong>Class:</strong> IN</li>
              <li><strong>Type:</strong> MX</li>
              <li><strong>Priority:</strong> 10 (16-bit integer, 0-65535)</li>
              <li><strong>Hostname:</strong> mail.example.com. (FQDN, not IP address)</li>
            </ul>
            
            <h4>Priority System</h4>
            <p>The priority number is crucial for mail flow management. Sending MTAs attempt delivery to the server with the <strong>lowest</strong> priority number first (lower number = higher priority).</p>
            
            <h4>Use Cases</h4>
            <h5>Redundancy and Failover:</h5>
            <pre><code>example.com. IN MX 10 primary.mail.example.com.
example.com. IN MX 20 backup.mail.example.com.</code></pre>
            <p>Email goes to primary server (priority 10). If unreachable, attempts backup server (priority 20).</p>
            
            <h5>Load Balancing:</h5>
            <pre><code>example.com. IN MX 10 mail1.example.com.
example.com. IN MX 10 mail2.example.com.
example.com. IN MX 10 mail3.example.com.</code></pre>
            <p>Same priority values cause MTAs to randomly distribute mail across servers.</p>
            
            <h4>Critical Requirements</h4>
            <ul>
              <li>MX records must point to hostnames, never IP addresses</li>
              <li>Target hostnames must have corresponding A or AAAA records</li>
              <li>Missing or misconfigured MX records prevent email delivery</li>
              <li>Lower priority numbers are processed first</li>
            </ul>
          `,
          'TXT Record': `
            <h4>TXT Records: The Swiss Army Knife of DNS</h4>
            <p>Originally designed to associate arbitrary, human-readable text with a domain, TXT records have evolved into the de facto standard for embedding machine-readable data for verification and policy enforcement purposes.</p>
            
            <h4>Format and Structure</h4>
            <pre><code>example.com. 3600 IN TXT "google-site-verification=AbCdEfGhIjKlMnOpQrStUvWxYz123456789"</code></pre>
            <p><strong>Components:</strong></p>
            <ul>
              <li><strong>Name:</strong> example.com.</li>
              <li><strong>TTL:</strong> 3600</li>
              <li><strong>Class:</strong> IN</li>
              <li><strong>Type:</strong> TXT</li>
              <li><strong>RDATA:</strong> Quoted text strings (max 255 bytes per string)</li>
            </ul>
            
            <h4>Modern Applications</h4>
            <h5>1. Domain Ownership Verification</h5>
            <p>Services like Google Workspace, Microsoft 365, and SSL certificate authorities require unique verification strings in TXT records to prove domain control.</p>
            
            <h5>2. Email Authentication Policies</h5>
            <p>The most critical modern use - TXT records carry SPF, DKIM, and DMARC policies essential for email security:</p>
            <ul>
              <li><strong>SPF:</strong> <code>"v=spf1 include:_spf.google.com ~all"</code></li>
              <li><strong>DMARC:</strong> <code>"v=DMARC1; p=quarantine; rua=mailto:reports@example.com"</code></li>
            </ul>
            
            <h5>3. Other Verification Uses</h5>
            <ul>
              <li>Domain validation for SSL certificates</li>
              <li>Social media platform verification</li>
              <li>Third-party service authentication</li>
              <li>Security policy declarations</li>
            </ul>
            
            <h4>Technical Limitations</h4>
            <ul>
              <li>Single strings limited to 255 bytes</li>
              <li>Longer values require multiple quoted strings</li>
              <li>Multiple TXT records allowed for same name</li>
            </ul>
            
            <h4>Evolution and Adaptability</h4>
            <p>The TXT record's lack of a strictly defined format became its greatest asset. Rather than creating new record types for emerging needs, the internet community repurposed this flexible record, allowing rapid deployment of critical security frameworks without fundamental DNS changes.</p>
          `,
          'NS Record': `
            <h4>NS (Name Server) Records Authority</h4>
            <p>The NS record is used to delegate a DNS zone to a set of authoritative name servers. These records tell the internet which servers hold the "master copy" of all DNS records for a domain and are fundamental to the DNS query resolution process.</p>
            
            <h4>Format and Example</h4>
            <pre><code>example.com. 86400 IN NS ns1.example-dns.com.</code></pre>
            <p><strong>Components:</strong></p>
            <ul>
              <li><strong>Name:</strong> example.com. (the domain being delegated)</li>
              <li><strong>TTL:</strong> 86400 (24 hours - typically longer for stability)</li>
              <li><strong>Class:</strong> IN</li>
              <li><strong>Type:</strong> NS</li>
              <li><strong>RDATA:</strong> ns1.example-dns.com. (authoritative name server hostname)</li>
            </ul>
            
            <h4>Role in DNS Delegation</h4>
            <p>Delegation is the process of handing off responsibility for a portion of the DNS namespace. This requires two sets of consistent NS records:</p>
            
            <h5>In the Parent Zone:</h5>
            <p>TLD servers (e.g., .com) contain NS records pointing to the domain's authoritative servers. This is how resolvers are referred "down" the hierarchy.</p>
            
            <h5>In the Child Zone:</h5>
            <p>The domain's zone file must also contain the same NS records, declaring its own authority. This consistency is mandatory for valid DNS configuration.</p>
            
            <h4>Glue Records: Preventing Circular Dependencies</h4>
            <div style="background: #21262d; border-left: 3px solid #f79000; padding: 12px; margin: 16px 0;">
              <p><strong>⚠️ Critical Concept:</strong></p>
              <p>When a name server for a domain is a subdomain of that domain (e.g., ns1.example.com serving example.com), a circular dependency occurs. To resolve ns1.example.com, you need to query example.com's name server - but that's ns1.example.com itself!</p>
              
              <p><strong>Solution: Glue Records</strong></p>
              <p>The parent TLD server provides A/AAAA records alongside the NS delegation, "gluing" the name server's hostname to its IP address and breaking the circular reference.</p>
            </div>
            
            <h4>Best Practices</h4>
            <ul>
              <li>Use multiple NS records for redundancy (minimum 2, recommended 3-4)</li>
              <li>Ensure NS records in parent and child zones match exactly</li>
              <li>Verify glue records are properly configured when using in-domain name servers</li>
              <li>Use longer TTL values for stability (24-48 hours typical)</li>
              <li>Distribute name servers across different networks/providers for resilience</li>
            </ul>
          `,
          'PTR Record': `
            <h4>PTR Records: Reverse DNS Explained</h4>
            <p>PTR records perform reverse DNS lookups, mapping IP addresses back to domain names. They are the inverse of A and AAAA records and are crucial for email deliverability and security applications.</p>
            
            <h4>Format and Structure</h4>
            <pre><code>1.2.0.192.in-addr.arpa. 3600 IN PTR example.com.</code></pre>
            <p><strong>IPv4 Reverse DNS:</strong></p>
            <ul>
              <li><strong>IP Address:</strong> 192.0.2.1</li>
              <li><strong>Reversed:</strong> 1.2.0.192</li>
              <li><strong>Domain:</strong> 1.2.0.192.in-addr.arpa.</li>
              <li><strong>Points to:</strong> example.com.</li>
            </ul>
            
            <h4>IPv6 Reverse DNS</h4>
            <p>IPv6 uses a different format with ip6.arpa:</p>
            <pre><code>1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.</code></pre>
            
            <h4>Critical Applications</h4>
            <h5>Email Deliverability</h5>
            <ul>
              <li>Mail servers check PTR records to verify sending server legitimacy</li>
              <li>Missing or mismatched PTR records often result in email rejection</li>
              <li>PTR should match the hostname in SMTP HELO/EHLO commands</li>
            </ul>
            
            <h5>Security and Logging</h5>
            <ul>
              <li>Security systems use PTR lookups to identify suspicious connections</li>
              <li>Log analysis tools convert IP addresses to hostnames for readability</li>
              <li>Network forensics rely on PTR records for incident investigation</li>
            </ul>
            
            <h4>Management Considerations</h4>
            <div style="background: #21262d; border-left: 3px solid #238636; padding: 12px; margin: 16px 0;">
              <p><strong>💡 Important Note:</strong></p>
              <p>PTR records are typically managed by the entity that owns the IP address space (usually your ISP or hosting provider), not the domain owner. You may need to request PTR record creation through your provider's control panel or support system.</p>
            </div>
            
            <h4>Best Practices</h4>
            <ul>
              <li>Ensure PTR records exist for all mail server IP addresses</li>
              <li>PTR should resolve to the actual hostname of the server</li>
              <li>Verify forward/reverse DNS consistency (A/AAAA ↔ PTR)</li>
              <li>Use meaningful hostnames that identify the server's purpose</li>
              <li>Keep PTR records updated when changing server configurations</li>
            </ul>
          `,
          'SRV Record': `
            <h4>SRV Records for Service Discovery</h4>
            <p>SRV records specify the hostname and port number for specific services, enabling applications to discover services automatically. They provide a standardized way to publish service location information in DNS.</p>
            
            <h4>Format and Structure</h4>
            <pre><code>_service._protocol.name. TTL IN SRV priority weight port target</code></pre>
            <pre><code>_sip._tcp.example.com. 3600 IN SRV 10 5 443 service.example.com.</code></pre>
            
            <p><strong>Components:</strong></p>
            <ul>
              <li><strong>Service:</strong> _sip (the service name, prefixed with underscore)</li>
              <li><strong>Protocol:</strong> _tcp or _udp (transport protocol)</li>
              <li><strong>Name:</strong> example.com. (the domain)</li>
              <li><strong>Priority:</strong> 10 (like MX records, lower = higher priority)</li>
              <li><strong>Weight:</strong> 5 (load balancing within same priority)</li>
              <li><strong>Port:</strong> 443 (service port number)</li>
              <li><strong>Target:</strong> service.example.com. (hostname providing the service)</li>
            </ul>
            
            <h4>Priority and Weight System</h4>
            <h5>Priority (0-65535)</h5>
            <ul>
              <li>Lower numbers indicate higher priority</li>
              <li>Clients try lowest priority servers first</li>
              <li>Provides failover capability</li>
            </ul>
            
            <h5>Weight (0-65535)</h5>
            <ul>
              <li>Used for load balancing among servers with same priority</li>
              <li>Higher weight = more likely to be selected</li>
              <li>Weight 0 = only used if all other servers fail</li>
            </ul>
            
            <h4>Common Service Examples</h4>
            <table style="border-collapse: collapse; width: 100%; margin: 16px 0;">
              <tr style="background: #21262d;">
                <th style="border: 1px solid #30363d; padding: 8px;">Service</th>
                <th style="border: 1px solid #30363d; padding: 8px;">Protocol</th>
                <th style="border: 1px solid #30363d; padding: 8px;">Purpose</th>
                <th style="border: 1px solid #30363d; padding: 8px;">Default Port</th>
              </tr>
              <tr>
                <td style="border: 1px solid #30363d; padding: 8px;">_sip</td>
                <td style="border: 1px solid #30363d; padding: 8px;">_tcp/_udp</td>
                <td style="border: 1px solid #30363d; padding: 8px;">Session Initiation Protocol (VoIP)</td>
                <td style="border: 1px solid #30363d; padding: 8px;">5060</td>
              </tr>
              <tr>
                <td style="border: 1px solid #30363d; padding: 8px;">_xmpp-server</td>
                <td style="border: 1px solid #30363d; padding: 8px;">_tcp</td>
                <td style="border: 1px solid #30363d; padding: 8px;">XMPP server-to-server</td>
                <td style="border: 1px solid #30363d; padding: 8px;">5269</td>
              </tr>
              <tr>
                <td style="border: 1px solid #30363d; padding: 8px;">_caldav</td>
                <td style="border: 1px solid #30363d; padding: 8px;">_tcp</td>
                <td style="border: 1px solid #30363d; padding: 8px;">Calendar server (CalDAV)</td>
                <td style="border: 1px solid #30363d; padding: 8px;">443</td>
              </tr>
              <tr>
                <td style="border: 1px solid #30363d; padding: 8px;">_minecraft</td>
                <td style="border: 1px solid #30363d; padding: 8px;">_tcp</td>
                <td style="border: 1px solid #30363d; padding: 8px;">Minecraft server</td>
                <td style="border: 1px solid #30363d; padding: 8px;">25565</td>
              </tr>
            </table>
            
            <h4>Use Cases</h4>
            <ul>
              <li><strong>VoIP Systems:</strong> Automatic discovery of SIP servers</li>
              <li><strong>Instant Messaging:</strong> XMPP service location</li>
              <li><strong>Gaming:</strong> Game server discovery</li>
              <li><strong>Enterprise Services:</strong> Internal service discovery and load balancing</li>
              <li><strong>Microsoft Active Directory:</strong> Domain controller and service location</li>
            </ul>
            
            <h4>Implementation Benefits</h4>
            <ul>
              <li>Eliminates hardcoded server addresses in applications</li>
              <li>Enables automatic failover and load balancing</li>
              <li>Simplifies service migration and scaling</li>
              <li>Standardizes service discovery across platforms</li>
            </ul>
          `,
          'CAA Record': `
            <h4>CAA Records: Certificate Authority Authorization</h4>
            <p>CAA records provide a way for domain owners to specify which Certificate Authorities (CAs) are allowed to issue SSL/TLS certificates for their domain. This DNS-based security mechanism helps prevent unauthorized certificate issuance.</p>
            
            <h4>Format and Structure</h4>
            <pre><code>example.com. 3600 IN CAA 0 issue "letsencrypt.org"</code></pre>
            <p><strong>Components:</strong></p>
            <ul>
              <li><strong>Name:</strong> example.com.</li>
              <li><strong>TTL:</strong> 3600</li>
              <li><strong>Class:</strong> IN</li>
              <li><strong>Type:</strong> CAA</li>
              <li><strong>Flags:</strong> 0 (typically 0, or 128 for critical)</li>
              <li><strong>Tag:</strong> issue, issuewild, or iodef</li>
              <li><strong>Value:</strong> "letsencrypt.org" (CA domain or other data)</li>
            </ul>
            
            <h4>CAA Record Tags</h4>
            <h5>issue</h5>
            <ul>
              <li>Authorizes a CA to issue certificates for the domain</li>
              <li>Example: <code>0 issue "digicert.com"</code></li>
            </ul>
            
            <h5>issuewild</h5>
            <ul>
              <li>Authorizes a CA to issue wildcard certificates</li>
              <li>Example: <code>0 issuewild "letsencrypt.org"</code></li>
            </ul>
            
            <h5>iodef</h5>
            <ul>
              <li>Specifies where to report policy violations</li>
              <li>Example: <code>0 iodef "mailto:security@example.com"</code></li>
            </ul>
            
            <h4>Security Benefits</h4>
            <div style="background: #21262d; border-left: 3px solid #238636; padding: 12px; margin: 16px 0;">
              <p><strong>🔒 Security Enhancement:</strong></p>
              <ul>
                <li><strong>Prevents Unauthorized Issuance:</strong> CAs must check CAA records before issuing certificates</li>
                <li><strong>Reduces Certificate Mis-issuance:</strong> Limits which CAs can issue for your domain</li>
                <li><strong>Compliance Requirement:</strong> Many regulations now require CAA records</li>
                <li><strong>Incident Detection:</strong> iodef tag enables violation reporting</li>
              </ul>
            </div>
            
            <h4>Common Configuration Examples</h4>
            <h5>Single CA Authorization:</h5>
            <pre><code>example.com. IN CAA 0 issue "letsencrypt.org"
example.com. IN CAA 0 iodef "mailto:security@example.com"</code></pre>
            
            <h5>Multiple CAs with Wildcard Support:</h5>
            <pre><code>example.com. IN CAA 0 issue "digicert.com"
example.com. IN CAA 0 issue "letsencrypt.org"
example.com. IN CAA 0 issuewild "letsencrypt.org"
example.com. IN CAA 0 iodef "https://security.example.com/report"</code></pre>
            
            <h5>Prohibit All Certificate Issuance:</h5>
            <pre><code>example.com. IN CAA 0 issue ";"</code></pre>
            
            <h4>Implementation Considerations</h4>
            <ul>
              <li><strong>CA Compliance:</strong> Not all CAs check CAA records, but major ones do</li>
              <li><strong>Inheritance:</strong> Subdomains inherit parent CAA records unless overridden</li>
              <li><strong>Critical Flag:</strong> Flag value 128 marks the record as critical</li>
              <li><strong>Monitoring:</strong> Set up iodef reporting to detect violations</li>
            </ul>
            
            <h4>Best Practices</h4>
            <ul>
              <li>Always include an iodef record for violation reporting</li>
              <li>Be specific about wildcard certificate permissions</li>
              <li>Regularly review and update authorized CAs</li>
              <li>Test certificate renewal before implementing restrictive CAA policies</li>
              <li>Consider organizational certificate requirements when setting policies</li>
            </ul>
          `,
          'SPF': `
            <h4>SPF (Sender Policy Framework) Comprehensive Guide</h4>
            <p>SPF is an email authentication mechanism designed to prevent sender address forgery. It allows domain owners to specify which mail servers are authorized to send email on behalf of their domain, helping combat spam and phishing.</p>
            
            <h4>How SPF Works</h4>
            <ol>
              <li>Domain owner publishes SPF policy as TXT record</li>
              <li>Receiving mail server checks sender's IP against published policy</li>
              <li>Policy evaluation determines if email should be accepted, rejected, or marked suspicious</li>
            </ol>
            
            <h4>SPF Record Structure</h4>
            <pre><code>v=spf1 ip4:198.51.100.5 include:_spf.google.com -all</code></pre>
            
            <h5>Components Breakdown:</h5>
            <ul>
              <li><strong>v=spf1:</strong> Version identifier (required, must be first)</li>
              <li><strong>Mechanisms:</strong> Rules defining authorized senders</li>
              <li><strong>Qualifiers:</strong> Actions for matches (+, -, ~, ?)</li>
              <li><strong>all:</strong> Default action for unmatched IPs</li>
            </ul>
            
            <h4>SPF Mechanisms</h4>
            <table style="border-collapse: collapse; width: 100%; margin: 16px 0;">
              <tr style="background: #21262d;">
                <th style="border: 1px solid #30363d; padding: 8px;">Mechanism</th>
                <th style="border: 1px solid #30363d; padding: 8px;">Syntax</th>
                <th style="border: 1px solid #30363d; padding: 8px;">Description</th>
              </tr>
              <tr>
                <td style="border: 1px solid #30363d; padding: 8px;"><strong>all</strong></td>
                <td style="border: 1px solid #30363d; padding: 8px;">all</td>
                <td style="border: 1px solid #30363d; padding: 8px;">Matches any IP address (default policy)</td>
              </tr>
              <tr>
                <td style="border: 1px solid #30363d; padding: 8px;"><strong>a</strong></td>
                <td style="border: 1px solid #30363d; padding: 8px;">a or a:domain.com</td>
                <td style="border: 1px solid #30363d; padding: 8px;">Matches A/AAAA records of domain</td>
              </tr>
              <tr>
                <td style="border: 1px solid #30363d; padding: 8px;"><strong>mx</strong></td>
                <td style="border: 1px solid #30363d; padding: 8px;">mx or mx:domain.com</td>
                <td style="border: 1px solid #30363d; padding: 8px;">Matches MX server IPs</td>
              </tr>
              <tr>
                <td style="border: 1px solid #30363d; padding: 8px;"><strong>ip4</strong></td>
                <td style="border: 1px solid #30363d; padding: 8px;">ip4:192.0.2.0/24</td>
                <td style="border: 1px solid #30363d; padding: 8px;">Matches IPv4 address/range</td>
              </tr>
              <tr>
                <td style="border: 1px solid #30363d; padding: 8px;"><strong>include</strong></td>
                <td style="border: 1px solid #30363d; padding: 8px;">include:domain.com</td>
                <td style="border: 1px solid #30363d; padding: 8px;">Includes another domain's SPF policy</td>
              </tr>
            </table>
            
            <h4>SPF Qualifiers</h4>
            <ul>
              <li><strong>+ (Pass):</strong> IP is authorized - default if no qualifier specified</li>
              <li><strong>- (Fail):</strong> IP is not authorized - reject the message</li>
              <li><strong>~ (SoftFail):</strong> IP is probably not authorized - accept but mark suspicious</li>
              <li><strong>? (Neutral):</strong> No assertion about IP authorization</li>
            </ul>
            
            <h4>Common SPF Examples</h4>
            <h5>Basic Google Workspace:</h5>
            <pre><code>"v=spf1 include:_spf.google.com ~all"</code></pre>
            
            <h5>Multiple Services with Dedicated IP:</h5>
            <pre><code>"v=spf1 ip4:198.51.100.5 include:_spf.google.com include:mailgun.org -all"</code></pre>
            
            <h5>Restrictive Policy (Reject All Unauthorized):</h5>
            <pre><code>"v=spf1 mx include:_spf.salesforce.com -all"</code></pre>
            
            <h4>Implementation Best Practices</h4>
            <div style="background: #21262d; border-left: 3px solid #f79000; padding: 12px; margin: 16px 0;">
              <p><strong>⚠️ Critical Limits:</strong></p>
              <ul>
                <li><strong>10 DNS Lookup Limit:</strong> Max 10 mechanisms requiring DNS lookups (include, a, mx, ptr)</li>
                <li><strong>Avoid ptr Mechanism:</strong> Deprecated and unreliable</li>
                <li><strong>Single SPF Record:</strong> Multiple SPF records invalidate all of them</li>
              </ul>
            </div>
            
            <h4>Deployment Strategy</h4>
            <ol>
              <li><strong>Start with Monitoring:</strong> Begin with ~all (soft fail)</li>
              <li><strong>Identify All Senders:</strong> Monitor email logs and DMARC reports</li>
              <li><strong>Add Missing Services:</strong> Include all legitimate sending sources</li>
              <li><strong>Gradually Enforce:</strong> Move to -all (hard fail) once confident</li>
            </ol>
            
            <h4>Testing and Validation</h4>
            <ul>
              <li>Use SPF testing tools to validate syntax</li>
              <li>Monitor email delivery after changes</li>
              <li>Check DMARC reports for SPF failures</li>
              <li>Test from all sending services before enforcing strict policies</li>
            </ul>
          `,
          'DKIM': `
            <h4>DKIM: Digital Signatures for Email</h4>
            <p>DKIM (DomainKeys Identified Mail) provides cryptographic authentication for email messages using public-key cryptography. It ensures email integrity and authenticity by digitally signing messages with a private key and publishing the corresponding public key in DNS.</p>
            
            <h4>How DKIM Works</h4>
            <ol>
              <li><strong>Key Generation:</strong> Domain owner creates a public/private key pair</li>
              <li><strong>DNS Publication:</strong> Public key is published as a TXT record</li>
              <li><strong>Signing:</strong> Sending server signs email headers/body with private key</li>
              <li><strong>Verification:</strong> Receiving server retrieves public key from DNS and verifies signature</li>
            </ol>
            
            <h4>DKIM Record Structure</h4>
            <pre><code>selector._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."</code></pre>
            
            <h5>Components:</h5>
            <ul>
              <li><strong>Selector:</strong> Unique identifier (e.g., "google", "mail", "2023") allowing multiple keys</li>
              <li><strong>v=DKIM1:</strong> Version tag</li>
              <li><strong>k=rsa:</strong> Key type (RSA is standard, Ed25519 is emerging)</li>
              <li><strong>p=...:</strong> The public key data (Base64 encoded)</li>
            </ul>
            
            <h4>Key Benefits</h4>
            <ul>
              <li><strong>Integrity:</strong> Proves message hasn't been altered in transit</li>
              <li><strong>Authenticity:</strong> Verifies the sender is truly authorized by the domain</li>
              <li><strong>Reputation:</strong> Builds domain reputation independent of IP address</li>
              <li><strong>DMARC Foundation:</strong> Essential component for DMARC implementation</li>
            </ul>
            
            <h4>Best Practices</h4>
            <ul>
              <li><strong>Key Rotation:</strong> Rotate keys periodically (every 6-12 months)</li>
              <li><strong>Key Size:</strong> Use at least 2048-bit RSA keys for security</li>
              <li><strong>Multiple Selectors:</strong> Use different selectors for different mail streams (marketing, transactional)</li>
              <li><strong>Test Mode:</strong> Use "t=y" tag during initial testing</li>
            </ul>
          `,
          'DMARC': `
            <h4>DMARC: The Ultimate Email Security Protocol</h4>
            <p>DMARC (Domain-based Message Authentication, Reporting, and Conformance) unifies SPF and DKIM mechanisms into a comprehensive policy framework. It allows domain owners to specify how receivers should handle emails that fail authentication and provides reporting on email flows.</p>
            
            <h4>How DMARC Works</h4>
            <ol>
              <li><strong>Policy Publication:</strong> Domain owner publishes DMARC record at _dmarc.example.com</li>
              <li><strong>Authentication Check:</strong> Receiver checks SPF and DKIM results</li>
              <li><strong>Alignment Check:</strong> Verifies that "From" header domain matches SPF/DKIM domains</li>
              <li><strong>Policy Enforcement:</strong> Applies policy (none, quarantine, reject) based on results</li>
              <li><strong>Reporting:</strong> Sends aggregate and forensic reports to domain owner</li>
            </ol>
            
            <h4>DMARC Record Structure</h4>
            <pre><code>_dmarc.example.com. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:forensics@example.com; sp=reject; adkim=s; aspf=s"</code></pre>
            
            <h5>Key Tags:</h5>
            <ul>
              <li><strong>v=DMARC1:</strong> Version tag (required)</li>
              <li><strong>p= (Policy):</strong> Action for failed messages (none, quarantine, reject)</li>
              <li><strong>rua=:</strong> Email address for aggregate reports (XML data)</li>
              <li><strong>ruf=:</strong> Email address for forensic reports (failure details)</li>
              <li><strong>sp=:</strong> Subdomain policy (optional override)</li>
              <li><strong>adkim/aspf:</strong> Alignment mode (s=strict, r=relaxed)</li>
            </ul>
            
            <h4>DMARC Policies</h4>
            <ul>
              <li><strong>p=none:</strong> Monitoring mode. No action taken on failures. Start here.</li>
              <li><strong>p=quarantine:</strong> Send failing messages to spam/junk folder.</li>
              <li><strong>p=reject:</strong> Block failing messages completely. Ultimate goal.</li>
            </ul>
            
            <h4>Deployment Journey</h4>
            <ol>
              <li><strong>Phase 1 (Monitor):</strong> Set p=none. Collect reports to identify all legitimate senders.</li>
              <li><strong>Phase 2 (Fix):</strong> Authenticate all legitimate sources with SPF and DKIM.</li>
              <li><strong>Phase 3 (Quarantine):</strong> Move to p=quarantine to protect against obvious abuse.</li>
              <li><strong>Phase 4 (Reject):</strong> Move to p=reject for full protection against spoofing.</li>
            </ol>
            
            <h4>Why DMARC Matters</h4>
            <div style="background: #21262d; border-left: 3px solid #238636; padding: 12px; margin: 16px 0;">
              <p><strong>🛡️ Business Impact:</strong></p>
              <ul>
                <li><strong>Stops Phishing:</strong> Prevents attackers from using your exact domain</li>
                <li><strong>Improves Deliverability:</strong> Major providers (Gmail, Yahoo) require DMARC</li>
                <li><strong>Brand Protection:</strong> Ensures only authorized emails reach customers</li>
                <li><strong>Visibility:</strong> Provides insight into shadow IT and unauthorized senders</li>
              </ul>
            </div>
          `
        };
        
        return content[conceptName] || '<p>Detailed explanation coming soon.</p>';
      }
    };
  };
