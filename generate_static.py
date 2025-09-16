#!/usr/bin/env python3
"""
Static Site Generator for DNSTools GitHub Pages Deployment
Converts Flask templates to static HTML files for GitHub Pages hosting
"""

import os
import shutil
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

def create_static_site():
    """Generate static HTML files from Flask templates"""
    
    # Setup paths
    base_dir = Path(__file__).parent
    templates_dir = base_dir / 'templates'
    static_dir = base_dir / 'static'
    dist_dir = base_dir / 'dist'
    
    # Clean and create dist directory
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
    dist_dir.mkdir()
    
    # Setup Jinja2 environment
    env = Environment(loader=FileSystemLoader(templates_dir))
    
    # Copy static assets
    if static_dir.exists():
        shutil.copytree(static_dir, dist_dir / 'static')
    
    # Pages to generate
    pages = {
        'index.html': 'lookup.html',  # Main page
        'lookup.html': 'lookup.html', 
        'mx.html': 'mx.html',
        'dmarc.html': 'dmarc.html', 
        'headers.html': 'headers.html',
        'history.html': 'history.html',
        'dashboard.html': 'dashboard.html',
        'resources.html': 'resources.html'
    }
    
    # Generate each page
    for output_file, template_name in pages.items():
        try:
            template = env.get_template(template_name)
            
            # Render template with context
            html = template.render(
                request={'endpoint': template_name.replace('.html', '')},
                # Add any other context variables needed
            )
            
            # Write to dist directory
            output_path = dist_dir / output_file
            output_path.write_text(html, encoding='utf-8')
            print(f"Generated: {output_file}")
            
        except Exception as e:
            print(f"Error generating {output_file}: {e}")
    
    # Create client-side API replacements
    create_client_side_apis(dist_dir)
    
    print(f"\nStatic site generated in: {dist_dir}")
    print("Ready for GitHub Pages deployment!")

def create_client_side_apis(dist_dir):
    """Create client-side replacements for Flask API endpoints"""
    
    # Create a client-side DNS lookup module
    dns_client_js = '''
// Client-side DNS lookups for GitHub Pages deployment
class DNSClient {
    constructor() {
        this.dohServers = [
            'https://dns.google/resolve',
            'https://cloudflare-dns.com/dns-query',
            'https://dns.quad9.net/dns-query'
        ];
    }
    
    async performLookup(domains, recordTypes) {
        const results = [];
        const domainsArray = domains.split('\\n').filter(d => d.trim());
        
        for (const domain of domainsArray) {
            const domainResult = {
                domain: domain.trim(),
                records: {}
            };
            
            for (const recordType of recordTypes) {
                try {
                    const records = await this.queryDNS(domain.trim(), recordType);
                    domainResult.records[recordType] = records;
                } catch (error) {
                    domainResult.records[recordType] = [];
                    console.warn(`Failed to lookup ${recordType} for ${domain}:`, error);
                }
            }
            
            results.push(domainResult);
        }
        
        return {
            results: results,
            stats: {
                domains_processed: results.length,
                lookup_time: 0.5 // Approximate time
            }
        };
    }
    
    async queryDNS(domain, recordType) {
        const dohUrl = `${this.dohServers[0]}?name=${encodeURIComponent(domain)}&type=${recordType}`;
        
        try {
            const response = await fetch(dohUrl, {
                headers: {
                    'Accept': 'application/dns-json'
                }
            });
            
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            
            const data = await response.json();
            
            if (data.Answer) {
                return data.Answer.map(answer => ({
                    name: answer.name,
                    type: recordType,
                    value: answer.data,
                    ttl: answer.TTL
                }));
            }
            
            return [];
        } catch (error) {
            console.warn(`DNS lookup failed for ${domain} ${recordType}:`, error);
            return [];
        }
    }
    
    async performMXLookup(domain) {
        try {
            const records = await this.queryDNS(domain, 'MX');
            return { records: records };
        } catch (error) {
            return { error: `Failed to lookup MX records for ${domain}` };
        }
    }
    
    async performDMARCLookup(domain) {
        try {
            const dmarcDomain = `_dmarc.${domain}`;
            const records = await this.queryDNS(dmarcDomain, 'TXT');
            
            const dmarcRecord = records.find(r => r.value.startsWith('v=DMARC1'));
            
            if (dmarcRecord) {
                return {
                    result: {
                        raw: dmarcRecord.value,
                        policy: this.parseDMARCPolicy(dmarcRecord.value)
                    }
                };
            } else {
                return { result: null };
            }
        } catch (error) {
            return { error: `Failed to lookup DMARC record for ${domain}` };
        }
    }
    
    parseDMARCPolicy(dmarcString) {
        const policy = {};
        const parts = dmarcString.split(';');
        
        parts.forEach(part => {
            const [key, value] = part.trim().split('=');
            if (key && value) {
                policy[key.trim()] = value.trim();
            }
        });
        
        return policy;
    }
}

// Make DNS client available globally
window.dnsClient = new DNSClient();
'''
    
    # Write the DNS client to static/js/
    dns_client_path = dist_dir / 'static' / 'js' / 'dns-client.js'
    dns_client_path.write_text(dns_client_js, encoding='utf-8')
    
    # Update the main app.js to use client-side lookups
    app_js_path = dist_dir / 'static' / 'js' / 'app.js'
    if app_js_path.exists():
        content = app_js_path.read_text(encoding='utf-8')
        
        # Replace Flask API calls with client-side calls
        replacements = {
            "fetch('/api/lookup'": "window.dnsClient.performLookup(this.domains, this.selectedRecordTypes).then(d => ({ json: () => Promise.resolve(d) })).then(r => r.json()).then(d",
            "fetch('/api/mx'": "window.dnsClient.performMXLookup(this.domain).then(d => ({ json: () => Promise.resolve(d) })).then(r => r.json()).then(d",
            "fetch('/api/dmarc'": "window.dnsClient.performDMARCLookup(this.domain).then(d => ({ json: () => Promise.resolve(d) })).then(r => r.json()).then(d"
        }
        
        for old, new in replacements.items():
            content = content.replace(old, new)
        
        app_js_path.write_text(content, encoding='utf-8')
    
    print("Created client-side DNS lookup functionality")

if __name__ == '__main__':
    create_static_site()