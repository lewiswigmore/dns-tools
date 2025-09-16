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
        try:
            shutil.rmtree(dist_dir)
        except PermissionError:
            print(f"Warning: Could not remove {dist_dir}. Continuing with existing directory.")
    
    if not dist_dir.exists():
        dist_dir.mkdir()
    
    # Setup Jinja2 environment with Flask-like functions
    env = Environment(loader=FileSystemLoader(templates_dir))
    
    # Add url_for function for static site
    def url_for(endpoint, **values):
        # Map Flask endpoints to static file paths
        endpoint_map = {
            'static': 'static/',
            'lookup': 'lookup.html',
            'lookup_page': 'lookup.html',
            'mx': 'mx.html',
            'mx_page': 'mx.html',
            'dmarc': 'dmarc.html', 
            'dmarc_page': 'dmarc.html',
            'headers': 'headers.html',
            'headers_page': 'headers.html',
            'history': 'history.html',
            'history_page': 'history.html',
            'dashboard': 'dashboard.html',
            'dashboard_page': 'dashboard.html',
            'resources': 'resources.html',
            'resources_page': 'resources.html',
            'index': 'index.html'
        }
        
        if endpoint == 'static':
            filename = values.get('filename', '')
            return f'static/{filename}'
        
        return endpoint_map.get(endpoint, f'{endpoint}.html')
    
    # Add the url_for function to Jinja2 environment
    env.globals['url_for'] = url_for
    
    # Copy static assets
    if static_dir.exists():
        shutil.copytree(static_dir, dist_dir / 'static', dirs_exist_ok=True)
    
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
    
    # Create .nojekyll file to disable Jekyll processing
    (dist_dir / '.nojekyll').touch()
    
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
    
    # Create GitHub Pages compatible app.js override
    github_pages_app_js = '''
/* GitHub Pages compatible app.js - Uses client-side DNS lookups */
(function(){
  const HISTORY_KEY = 'dns_history';

  function safeJSONParse(str, fallback){ try { return JSON.parse(str); } catch { return fallback; } }
  function loadHistory(){ return safeJSONParse(localStorage.getItem(HISTORY_KEY), []); }
  function saveHistory(arr){ try { localStorage.setItem(HISTORY_KEY, JSON.stringify(arr.slice(0,100))); } catch(e) { console.warn('history save failed', e); } }
  function addHistory(entry){ 
    const hist = loadHistory(); 
    hist.unshift(entry); 
    saveHistory(hist);
  }
  function exportJSON(data, filename='dns_results.json'){ const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'}); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=filename; a.click(); }
  function presetDomains(){ const params=new URLSearchParams(window.location.search); return params.get('domains')||''; }
  function autoGrow(el){ if(!el) return; el.style.height='auto'; el.style.height = (el.scrollHeight)+'px'; }

  // Lookup component - GitHub Pages version with client-side DNS
  window.LookupPage = function(){
    return {
      domains: presetDomains(),
      availableRecordTypes:['A','AAAA','CNAME','TXT','NS','MX'],
      selectedRecordTypes:['A'],
      results:[],
      loading:false,
      autoGrow,
      init(){},
      selectAllRecordTypes(){
        this.selectedRecordTypes = [...this.availableRecordTypes];
      },
      clearAllRecordTypes(){
        this.selectedRecordTypes = [];
      },
      async performLookup(){
        if(this.loading) return; 
        if(!this.domains.trim()||this.selectedRecordTypes.length===0) return;
        
        this.loading=true;
        try {
          const data = await window.dnsClient.performLookup(this.domains, this.selectedRecordTypes);
          this.results = data.results; 
          addHistory({
            query:this.domains,
            timestamp:Date.now(),
            domains:data.stats?.domains_processed||this.results.length,
            duration:data.stats?.lookup_time||0,
            success:true,
            recordTypes:this.selectedRecordTypes,
            results:data.results,
            stats:data.stats
          });
        } catch (error) {
          console.error('DNS lookup failed:', error);
          alert('DNS lookup failed: ' + error.message);
          addHistory({
            query:this.domains,
            timestamp:Date.now(),
            domains:0,
            duration:0,
            success:false,
            recordTypes:this.selectedRecordTypes
          });
        } finally {
          this.loading = false;
        }
      },
      exportResults(){ exportJSON(this.results, 'dns_lookup_results.json'); }
    };
  };

  // Simplified placeholder components for other pages
  window.MXPage = function(){ return { domain: '', results: [], loading: false, init(){} }; };
  window.DMARCPage = function(){ return { domain: '', result: null, loading: false, init(){} }; };
  window.HeadersPage = function(){ return { headers: '', result: null, loading: false, init(){} }; };
  window.HistoryPage = function(){ return { history: loadHistory(), filteredHistory: [], searchTerm: '', selectedTypes: [], loading: false, init(){ this.filteredHistory = this.history; } }; };
  window.DashboardPage = function(){ return { stats: {}, loading: false, init(){} }; };
  window.ResourcesPage = function(){ return { selectedConcept: null, loading: false, init(){} }; };

})();
'''
    
    # Write GitHub Pages compatible app.js
    app_js_path = dist_dir / 'static' / 'js' / 'app.js'
    app_js_path.write_text(github_pages_app_js, encoding='utf-8')
    
    print("Created client-side DNS lookup functionality")

if __name__ == '__main__':
    create_static_site()