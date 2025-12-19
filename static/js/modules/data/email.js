export const EMAIL_CONCEPTS = [
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
