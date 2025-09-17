/* Shared front-end logic for DNSTools */
(function(){
  const HISTORY_KEY = 'dns_history';

  // Safe localStorage wrapper for GitHub Pages compatibility
  const safeStorage = {
    getItem: (key) => {
      try {
        return localStorage.getItem(key);
      } catch (e) {
        console.warn('localStorage.getItem failed:', e);
        return null;
      }
    },
    setItem: (key, value) => {
      try {
        localStorage.setItem(key, value);
        return true;
      } catch (e) {
        console.warn('localStorage.setItem failed:', e);
        return false;
      }
    },
    removeItem: (key) => {
      try {
        localStorage.removeItem(key);
        return true;
      } catch (e) {
        console.warn('localStorage.removeItem failed:', e);
        return false;
      }
    }
  };

  // DNS-over-HTTPS client for static site
  class DNSClient {
    constructor() {
      this.dohServers = [
        'https://dns.google/resolve',
        'https://cloudflare-dns.com/dns-query',
        'https://dns.quad9.net/dns-query'
      ];
    }
    
    deobfuscateDomain(domain) {
      // Handle common obfuscation patterns used in security research
      let deobfuscated = domain
        .replace(/\[?\.\]?/g, '.') // Replace [.] or . with .
        .replace(/^hxxp:\/\//, 'http://') // Replace hxxp:// with http://
        .replace(/^hxxps:\/\//, 'https://') // Replace hxxps:// with https://
        .replace(/^fxp:\/\//, 'ftp://') // Replace fxp:// with ftp://
        .replace(/\(/g, '[') // Replace ( with [
        .replace(/\)/g, ']'); // Replace ) with ]
      
      // Remove protocol if present (we only want the domain)
      deobfuscated = deobfuscated.replace(/^https?:\/\//, '');
      deobfuscated = deobfuscated.replace(/^ftp:\/\//, '');
      
      // Remove path and query parameters
      deobfuscated = deobfuscated.split('/')[0];
      deobfuscated = deobfuscated.split('?')[0];
      
      return deobfuscated;
    }
    
    isValidDomain(domain) {
      // Basic domain validation
      if (!domain || domain.length === 0) return false;
      if (domain === '.' || domain === '..') return false;
      if (domain.startsWith('.') && domain.length === 1) return false;
      if (domain.includes('..')) return false; // Double dots not allowed
      
      // Must contain at least one dot (except for localhost-style names)
      if (!domain.includes('.') && domain !== 'localhost') return false;
      
      // Basic regex for domain format
      const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
      return domainRegex.test(domain);
    }
    
    async performLookup(domains, recordTypes) {
      const results = [];
      // Split on newlines, commas, and spaces, then filter out empty entries and invalid domains
      const domainsArray = [...new Set(domains.split(/[\n,\s]+/)
        .filter(d => d.trim())
        .map(d => this.deobfuscateDomain(d.trim()))
        .filter(d => this.isValidDomain(d)))];
      
      for (const domain of domainsArray) {
        const domainResult = {
          domain: domain,
          records: {},
          errors: []
        };
        
        for (const recordType of recordTypes) {
          try {
            const records = await this.queryDNS(domain.trim(), recordType);
            domainResult.records[recordType] = records;
          } catch (error) {
            domainResult.records[recordType] = [];
            domainResult.errors.push(`${recordType} lookup failed: ${error.message}`);
            console.warn(`Failed to lookup ${recordType} for ${domain}:`, error);
          }
        }
        
        // Check if domain has no records at all
        const hasAnyRecords = Object.values(domainResult.records).some(records => records.length > 0);
        if (!hasAnyRecords && domainResult.errors.length === 0) {
          domainResult.errors.push(`No DNS records found - domain may not exist`);
        }
        
        results.push(domainResult);
      }
      
      return {
        results: results,
        stats: {
          domains_processed: results.length,
          lookup_time: 0.5
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
          return data.Answer.map(answer => {
            const result = {
              name: answer.name,
              type: recordType,
              value: answer.data,
              ttl: answer.TTL
            };
            
            // Special parsing for MX records
            if (recordType === 'MX' && answer.data) {
              const parts = answer.data.split(' ');
              if (parts.length >= 2) {
                result.priority = parseInt(parts[0]);
                result.exchange = parts.slice(1).join(' ').replace(/\.$/, ''); // Remove trailing dot
              }
            }
            
            return result;
          });
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
          const parsedPolicy = this.parseDMARCPolicy(dmarcRecord.value);
          return {
            result: {
              raw: dmarcRecord.value,
              policy: parsedPolicy.p || 'none',  // Extract 'p' value for policy
              adkim: parsedPolicy.adkim,
              aspf: parsedPolicy.aspf,
              rua: parsedPolicy.rua,
              ruf: parsedPolicy.ruf
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

  function safeJSONParse(str, fallback){ try { return JSON.parse(str); } catch { return fallback; } }
  function loadHistory(){ 
    try {
      const stored = safeStorage.getItem(HISTORY_KEY);
      if (!stored) return [];
      const parsed = JSON.parse(stored);
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      console.warn('Failed to load history:', e);
      return [];
    }
  }
  function saveHistory(arr){ 
    try { 
      safeStorage.setItem(HISTORY_KEY, JSON.stringify(arr.slice(0,100))); 
    } catch(e) { 
      console.warn('history save failed', e); 
    } 
  }
  function addHistory(entry){ 
    try {
      const hist = loadHistory(); 
      if (!Array.isArray(hist)) {
        console.warn('History is not an array, resetting');
        saveHistory([entry]);
        return;
      }
      hist.unshift(entry); 
      saveHistory(hist);
      
      // Update last activity timestamp for session tracking
      if (window.dashboardInstance && window.dashboardInstance.updateLastActivity) {
        window.dashboardInstance.updateLastActivity();
      }
    } catch (e) {
      console.warn('Failed to add history entry:', e);
    }
  }
  function exportJSON(data, filename='dns_results.json'){ const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'}); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=filename; a.click(); }
  function presetDomains(){ const params=new URLSearchParams(window.location.search); return params.get('domains')||''; }
  function presetRecordTypes(){ 
    const params=new URLSearchParams(window.location.search); 
    const types = params.get('types');
    return types ? types.split(',').filter(t => t.trim()) : [];
  }
  function autoGrow(el){ if(!el) return; el.style.height='auto'; el.style.height = (el.scrollHeight)+'px'; }

  // Lookup component
  window.LookupPage = function(){
    return {
      domains: presetDomains(),
      availableRecordTypes:['A','AAAA','CNAME','TXT','NS'],
      selectedRecordTypes:['A'],
      results:[],
      loading:false,
      autoGrow,
      init(){
        // Set preset record types if provided in URL
        const presetTypes = presetRecordTypes();
        if (presetTypes.length > 0) {
          // Validate that all preset types are in available types
          const validTypes = presetTypes.filter(type => this.availableRecordTypes.includes(type));
          if (validTypes.length > 0) {
            this.selectedRecordTypes = validTypes;
          }
        }
        
        // Auto-execute if we have preset domains
        if (this.domains.trim()) {
          // Auto-execute the lookup
          setTimeout(() => this.performLookup(), 100);
        }
      },
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
          const startTime = Date.now();
          const response = await window.dnsClient.performLookup(this.domains, this.selectedRecordTypes);
          const duration = (Date.now() - startTime) / 1000;
          
          this.results = response.results || [];
          
          // Add to history
          addHistory({
            query: this.domains,
            timestamp: Date.now(),
            domains: response.stats?.domains_processed || this.results.length,
            duration: duration,
            success: true,
            recordTypes: this.selectedRecordTypes,
            results: response.results,
            stats: response.stats
          });
          
          // Refresh dashboard if present
          if(window.dashboardInstance) window.dashboardInstance.refreshStats();
          
        } catch (error) {
          console.error('Lookup failed:', error);
          alert('DNS lookup failed: ' + error.message);
          
          addHistory({
            query: this.domains,
            timestamp: Date.now(),
            domains: 0,
            duration: 0,
            success: false,
            recordTypes: this.selectedRecordTypes
          });
          
          if(window.dashboardInstance) window.dashboardInstance.refreshStats();
        } finally {
          this.loading = false;
        }
      },
      exportResults(){ exportJSON(this.results); }
    };
  };

  // MX component
  window.MXPage = function(){
    return {
      domain:'', results:[], loading:false, error:'', searchPerformed:false,
      init(){
        // Check for domain parameter in URL
        const params = new URLSearchParams(window.location.search);
        const domainParam = params.get('domain');
        if (domainParam) {
          this.domain = domainParam;
          // Auto-execute the lookup
          setTimeout(() => this.performLookup(), 100);
        }
      },
      async performLookup(){
        if(this.loading || !this.domain.trim()) return;
        
        this.loading = true; 
        this.error = '';
        this.results = []; // Clear previous results
        this.searchPerformed = true; // Mark that a search has been performed
        
        try {
          const startTime = Date.now();
          const response = await window.dnsClient.performMXLookup(this.domain);
          const duration = (Date.now() - startTime) / 1000;
          
          if (response.error) {
            this.error = response.error;
            addHistory({
              query: this.domain,
              timestamp: Date.now(),
              domains: 1,
              duration: duration,
              success: false,
              recordTypes: ['MX']
            });
          } else {
            this.results = response.records || [];
            addHistory({
              query: this.domain,
              timestamp: Date.now(),
              domains: 1,
              duration: duration,
              success: true,
              recordTypes: ['MX'],
              results: response.records
            });
          }
          
          if(window.dashboardInstance) window.dashboardInstance.refreshStats();
          
        } catch (error) {
          console.error('MX lookup failed:', error);
          this.error = error.message;
          
          addHistory({
            query: this.domain,
            timestamp: Date.now(),
            domains: 1,
            duration: 0,
            success: false,
            recordTypes: ['MX']
          });
          
          if(window.dashboardInstance) window.dashboardInstance.refreshStats();
        } finally {
          this.loading = false;
        }
      }
    };
  };

  // DMARC component
  window.DMARCPage = function(){
    return {
      domain:'', result:null, loading:false, error:'', searchPerformed:false,
      init(){
        // Check for domain parameter in URL
        const params = new URLSearchParams(window.location.search);
        const domainParam = params.get('domain');
        if (domainParam) {
          this.domain = domainParam;
          // Auto-execute the lookup
          setTimeout(() => this.performLookup(), 100);
        }
      },
      async performLookup(){
        if(this.loading || !this.domain.trim()) return;
        
        this.loading = true;
        this.error = '';
        this.result = null;
        this.searchPerformed = true; // Mark that a search has been performed
        
        try {
          const startTime = Date.now();
          const response = await window.dnsClient.performDMARCLookup(this.domain);
          const duration = (Date.now() - startTime) / 1000;
          
          if (response.error) {
            this.error = response.error;
            addHistory({
              query: this.domain,
              timestamp: Date.now(),
              domains: 1,
              duration: duration,
              success: false,
              recordTypes: ['DMARC']
            });
          } else {
            this.result = response.result;
            addHistory({
              query: this.domain,
              timestamp: Date.now(),
              domains: 1,
              duration: duration,
              success: true,
              recordTypes: ['DMARC'],
              results: response
            });
          }
          
          if(window.dashboardInstance) window.dashboardInstance.refreshStats();
          
        } catch (error) {
          console.error('DMARC lookup failed:', error);
          this.error = error.message;
          
          addHistory({
            query: this.domain,
            timestamp: Date.now(),
            domains: 1,
            duration: 0,
            success: false,
            recordTypes: ['DMARC']
          });
          
          if(window.dashboardInstance) window.dashboardInstance.refreshStats();
        } finally {
          this.loading = false;
        }
      }
    }
  };

  // Headers component
  window.HeadersPage = function(){
    return {
      headers:'', results:null, loading:false, error:'',
      autoGrow,
      init(){
        // Check for rerun parameter and stored headers data
        const params = new URLSearchParams(window.location.search);
        const isRerun = params.get('rerun');
        
        if (isRerun) {
          const storedHeaders = localStorage.getItem('dns_rerun_headers');
          if (storedHeaders) {
            this.headers = storedHeaders;
            // Clean up the stored data
            localStorage.removeItem('dns_rerun_headers');
            // Auto-execute the analysis
            setTimeout(() => this.analyzeHeaders(), 100);
          }
        }
      },
      async analyzeHeaders(){
        if(this.loading || !this.headers.trim()) return;
        
        this.loading = true;
        this.error = '';
        this.results = null;
        
        try {
          const startTime = Date.now();
          
          // Simple client-side header analysis
          const headerLines = this.headers.split('\n');
          const parsedHeaders = {};
          let currentHeader = '';
          let receivedCount = 0;
          
          for (let line of headerLines) {
            const originalLine = line; // Keep original for whitespace detection
            line = line.trim();
            if (!line) continue;
            
            // Check if this is a header line (starts with header name followed by colon)
            const isHeaderLine = line.match(/^[a-zA-Z0-9-]+:\s/);
            // Check if this is a continuation line (starts with whitespace in original)
            const isContinuationLine = originalLine.match(/^\s+/) && currentHeader;
            
            if (isHeaderLine && !isContinuationLine) {
              const [header, ...valueParts] = line.split(':');
              const headerName = header.trim().toLowerCase();
              const headerValue = valueParts.join(':').trim();
              
              // Handle multiple Received headers
              if (headerName === 'received') {
                currentHeader = `received-${receivedCount}`;
                receivedCount++;
                parsedHeaders[currentHeader] = headerValue;
              } else {
                currentHeader = headerName;
                parsedHeaders[currentHeader] = headerValue;
              }
            } else if (isContinuationLine || (currentHeader && !isHeaderLine)) {
              // Continuation line - add to current header
              parsedHeaders[currentHeader] += ' ' + line;
            }
          }
          
          const analysis = {
            headers: parsedHeaders,
            ...this.parseAuthenticationResults(parsedHeaders),
            routing: {
              from: parsedHeaders['from'] || 'Not found',
              to: parsedHeaders['to'] || 'Not found',
              subject: parsedHeaders['subject'] || 'Not found',
              date: parsedHeaders['date'] || 'Not found'
            },
            security: this.analyzeSecurityIndicators(parsedHeaders),
            delivery_path: this.parseDeliveryPath(parsedHeaders)
          };
          
          const duration = (Date.now() - startTime) / 1000;
          this.results = analysis;
          
          // Create a meaningful query preview from the email headers
          let queryPreview = 'Email Headers';
          if (analysis.routing) {
            const subject = analysis.routing.subject;
            const from = analysis.routing.from;
            
            if (subject && subject !== 'Not found') {
              // Use subject line, truncated if too long
              queryPreview = subject.length > 60 ? subject.substring(0, 60) + '...' : subject;
            } else if (from && from !== 'Not found') {
              // Fall back to from field if no subject
              const fromMatch = from.match(/<([^>]+)>/) || from.match(/([^\s<>]+@[^\s<>]+)/);
              if (fromMatch) {
                queryPreview = 'From: ' + fromMatch[1];
              } else {
                queryPreview = 'From: ' + (from.length > 40 ? from.substring(0, 40) + '...' : from);
              }
            }
          }
          
          addHistory({
            query: queryPreview,
            timestamp: Date.now(),
            domains: 1,
            duration: duration,
            success: true,
            recordTypes: ['Headers'],
            results: analysis,
            originalHeaders: this.headers  // Store original headers for rerun
          });
          
          if(window.dashboardInstance) window.dashboardInstance.refreshStats();
          
        } catch (error) {
          console.error('Header analysis failed:', error);
          this.error = error.message;
          
          addHistory({
            query: 'Email Headers Analysis (Failed)',
            timestamp: Date.now(),
            domains: 1,
            duration: 0,
            success: false,
            recordTypes: ['Headers']
          });
          
          if(window.dashboardInstance) window.dashboardInstance.refreshStats();
        } finally {
          this.loading = false;
        }
      },
      
      parseAuthenticationResults(headers) {
        const results = {
          spf: { status: 'unknown', details: '' },
          dkim: { status: 'unknown', details: '' }, 
          dmarc: { status: 'unknown', details: '' }
        };
        
        // Check for Authentication-Results header
        const authHeader = headers['authentication-results'];
        
        if (authHeader) {
          // Parse SPF result - updated regex to handle more formats
          const spfMatch = authHeader.match(/spf=(\w+)(?:\s+\(([^)]+)\))?/i);
          if (spfMatch) {
            results.spf.status = spfMatch[1];
            results.spf.details = spfMatch[2] || '';
          }
          
          // Parse DKIM result  
          const dkimMatch = authHeader.match(/dkim=(\w+)(?:\s+\(([^)]+)\))?/i);
          if (dkimMatch) {
            results.dkim.status = dkimMatch[1];
            results.dkim.details = dkimMatch[2] || '';
          }
          
          // Parse DMARC result
          const dmarcMatch = authHeader.match(/dmarc=(\w+)(?:\s+\(([^)]+)\))?/i);
          if (dmarcMatch) {
            results.dmarc.status = dmarcMatch[1];
            results.dmarc.details = dmarcMatch[2] || '';
          }
        }
        
        // Also check individual headers as fallback
        if (headers['received-spf'] && results.spf.status === 'unknown') {
          const spfMatch = headers['received-spf'].match(/(\w+)/);
          if (spfMatch) results.spf.status = spfMatch[1];
        }
        
        return results;
      },
      
      analyzeSecurityIndicators(headers) {
        const warnings = [];
        let suspicious = false;
        let tls = false;
        
        // Check for TLS usage in Received headers
        const receivedHeaders = Object.keys(headers)
          .filter(key => key.startsWith('received'))
          .map(key => headers[key])
          .join(' ');
        
        if (receivedHeaders.toLowerCase().includes('tls') || receivedHeaders.toLowerCase().includes('ssl')) {
          tls = true;
        }
        
        // Check for suspicious patterns
        const from = headers['from'] || '';
        const replyTo = headers['reply-to'] || '';
        const returnPath = headers['return-path'] || '';
        
        // Mismatched From and Reply-To
        if (replyTo && from && !replyTo.includes(from.split('@')[1]?.split('>')[0])) {
          warnings.push('Reply-To domain differs from From domain');
          suspicious = true;
        }
        
        // Suspicious subject patterns
        const subject = headers['subject'] || '';
        if (subject.match(/urgent|action required|verify|suspended|expire/i)) {
          warnings.push('Subject contains urgency indicators common in phishing');
          suspicious = true;
        }
        
        return {
          tls: tls,
          suspicious: suspicious,
          warnings: warnings,
          messageId: headers['message-id'] || 'Not found',
          returnPath: returnPath || 'Not found'
        };
      },
      
      parseDeliveryPath(headers) {
        const path = [];
        
        // Extract all Received headers
        Object.keys(headers).forEach(key => {
          if (key.startsWith('received')) {
            const value = headers[key];
            const serverMatch = value.match(/from\s+([^\s]+)/i);
            const timestampMatch = value.match(/;\s*(.+)$/);
            
            if (serverMatch) {
              path.push({
                server: serverMatch[1],
                timestamp: timestampMatch ? timestampMatch[1].trim() : 'Unknown'
              });
            }
          }
        });
        
        return path.reverse(); // Show in chronological order
      },
      
      exportResults(){ if(this.results) exportJSON(this.results, 'email_headers_analysis.json'); }
    };
  };

  // History component
  window.HistoryPage = function(){
    return {
      history: loadHistory(),
      filteredHistory: [],
      searchFilter: '',
      typeFilter: 'all',
      previewModal: false,
      previewData: null,
      
      init() {
        window.historyPageInstance = this;
        this.applyFilters();
      },
      
      showPreview(item) {
        this.previewData = item;
        this.previewModal = true;
      },
      
      closePreview() {
        this.previewModal = false;
        this.previewData = null;
      },
      
      applyFilters() {
        let filtered = this.history;
        
        // Apply text search filter
        if (this.searchFilter.trim()) {
          const search = this.searchFilter.toLowerCase();
          filtered = filtered.filter(item => 
            item.query.toLowerCase().includes(search) ||
            this.getQueryType(item.recordTypes).toLowerCase().includes(search) ||
            (item.success ? 'success' : 'failed').includes(search)
          );
        }
        
        // Apply type filter
        if (this.typeFilter !== 'all') {
          filtered = filtered.filter(item => 
            this.getQueryType(item.recordTypes) === this.typeFilter
          );
        }
        
        this.filteredHistory = filtered;
      },
      
      toggleTypeFilter(type) {
        this.typeFilter = type;
        this.applyFilters();
      },
      
      clearFilters() {
        this.searchFilter = '';
        this.typeFilter = 'all';
        this.applyFilters();
      },
      
      getTypeCount(type) {
        if (type === 'all') return this.history.length;
        return this.history.filter(item => this.getQueryType(item.recordTypes) === type).length;
      },
      
      getTypePillClass(item) {
        if (!item || !item.recordTypes) {
          return 'pill pill-outline pill-blue';
        }
        const type = this.getQueryType(item.recordTypes);
        const baseClass = 'pill pill-outline ';
        switch(type) {
          case 'DNS': return baseClass + 'pill-green';
          case 'MX': return baseClass + 'pill-orange';
          case 'DMARC': return baseClass + 'pill-purple';
          case 'Headers': return baseClass + 'pill-yellow';
          default: return baseClass + 'pill-blue';
        }
      },
      
      formatDuration(duration) {
        if (!duration) return '0s';
        if (duration < 1) return `${Math.round(duration * 1000)}ms`;
        return `${duration}s`;
      },
      
      formatDate(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        const itemDate = new Date(date.getFullYear(), date.getMonth(), date.getDate());
        
        if (itemDate.getTime() === today.getTime()) {
          return date.toLocaleTimeString();
        } else if (itemDate.getTime() === today.getTime() - 86400000) {
          return 'Yesterday ' + date.toLocaleTimeString();
        } else {
          return date.toLocaleDateString();
        }
      },
      
      getTimeAgo(timestamp) {
        const now = Date.now();
        const diff = now - timestamp;
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);
        
        if (days > 0) return `${days}d ago`;
        if (hours > 0) return `${hours}h ago`;
        if (minutes > 0) return `${minutes}m ago`;
        return 'Just now';
      },
      
      rerun(item){ 
        const type = this.getQueryType(item.recordTypes);
        if (type === 'Headers') {
          // For headers, store the data in localStorage and redirect
          if (item.results && item.results.headers) {
            // Try to reconstruct headers from parsed data or use original if available
            let headersText = '';
            
            // If we have the original headers text stored, use that
            if (item.originalHeaders) {
              headersText = item.originalHeaders;
            } else {
              // Otherwise, try to reconstruct from parsed headers
              const headers = item.results.headers;
              for (const [key, value] of Object.entries(headers)) {
                if (key.startsWith('received-')) {
                  headersText += `Received: ${value}\n`;
                } else {
                  const capitalizedKey = key.split('-').map(word => 
                    word.charAt(0).toUpperCase() + word.slice(1)
                  ).join('-');
                  headersText += `${capitalizedKey}: ${value}\n`;
                }
              }
            }
            
            // Store in localStorage temporarily
            localStorage.setItem('dns_rerun_headers', headersText);
          }
          window.location = 'headers.html?rerun=true';
        } else if (type === 'MX') {
          // Extract domain from query for MX
          const domain = item.query.trim();
          window.location = 'mx.html?domain=' + encodeURIComponent(domain);
        } else if (type === 'DMARC') {
          // Extract domain from query for DMARC
          const domain = item.query.trim();
          window.location = 'dmarc.html?domain=' + encodeURIComponent(domain);
        } else {
          // For DNS lookups, pass domains and record types
          const recordTypes = item.recordTypes ? item.recordTypes.join(',') : 'A';
          window.location = 'lookup.html?domains=' + encodeURIComponent(item.query) + '&types=' + encodeURIComponent(recordTypes);
        }
      },
      
      clearAll(){ 
        if(confirm('Clear all history? This action cannot be undone.')){ 
          saveHistory([]); 
          this.history = []; 
          this.applyFilters();
        } 
      },
      
      getQueryType(recordTypes){
        if (!recordTypes || recordTypes.length === 0) return 'DNS';
        if (recordTypes.includes('MX')) return 'MX';
        if (recordTypes.includes('DMARC')) return 'DMARC';
        if (recordTypes.includes('Headers')) return 'Headers';
        return 'DNS';
      },
      
      getDisplayTitle(item) {
        // Return empty string if item is null/undefined
        if (!item) return '';
        
        // For Headers entries, try to extract a meaningful title from the results
        if (this.getQueryType(item.recordTypes) === 'Headers' && item.results) {
          // Check if we have routing information with subject or from
          if (item.results.routing) {
            const subject = item.results.routing.subject;
            const from = item.results.routing.from;
            
            if (subject && subject !== 'Not found' && subject.trim()) {
              // Use subject line, truncated if too long
              return subject.length > 60 ? subject.substring(0, 60) + '...' : subject;
            } else if (from && from !== 'Not found' && from.trim()) {
              // Fall back to from field if no subject
              const fromMatch = from.match(/<([^>]+)>/) || from.match(/([^\s<>]+@[^\s<>]+)/);
              if (fromMatch) {
                return 'From: ' + fromMatch[1];
              } else {
                return 'From: ' + (from.length > 40 ? from.substring(0, 40) + '...' : from);
              }
            }
          }
          
          // If we can't extract meaningful info, check if it's a failed analysis
          if (!item.success) {
            return 'Email Headers Analysis (Failed)';
          }
          
          // Default fallback for headers
          return 'Email Headers Analysis';
        }
        
        // For all other types, use the original query
        return item.query || '';
      }
    };
  };

  // Dashboard component
  window.DashboardPage = function(){
    return {
      stats: {
        totalLookups: 0,
        successRate: 0,
        sessionTime: '0m',
        uniqueDomains: 0
      },
      recentActivity: [],
      hourlyChart: null,
      typeChart: null,
      chartInitialized: false,
      updatingCharts: false,
      sessionStart: null,
      
      init(){
        window.dashboardInstance = this;
        this.chartInitialized = false;
        
        // Initialize session tracking
        this.initSessionTracking();
        
        this.refreshStats();
        
        // Initialize charts with more delay and only once
        setTimeout(() => {
          if (!this.chartInitialized) {
            try {
              this.initCharts();
              this.chartInitialized = true;
              this.refreshStats(); // Refresh again after charts are ready
            } catch (error) {
              console.warn('Chart initialization failed:', error);
            }
          }
        }, 500);
        
        // Refresh every minute for stats, every second for session timer
        setInterval(() => this.updateSessionTime(), 1000);
        setInterval(() => this.refreshStats(), 60000);
        
        // Update activity on page interaction
        document.addEventListener('click', () => this.updateLastActivity());
        document.addEventListener('keypress', () => this.updateLastActivity());
      },
      
      initSessionTracking() {
        const SESSION_KEY = 'dnstools_session_start';
        const INACTIVITY_TIMEOUT = 30 * 60 * 1000; // 30 minutes
        
        // Check if there's an existing session
        const existingSession = localStorage.getItem(SESSION_KEY);
        const now = Date.now();
        
        if (existingSession) {
          const sessionStart = parseInt(existingSession);
          const timeSinceLastActivity = now - this.getLastActivity();
          
          // If last activity was more than 30 minutes ago, start new session
          if (timeSinceLastActivity > INACTIVITY_TIMEOUT) {
            this.sessionStart = now;
            localStorage.setItem(SESSION_KEY, now.toString());
          } else {
            // Continue existing session
            this.sessionStart = sessionStart;
          }
        } else {
          // Start new session
          this.sessionStart = now;
          localStorage.setItem(SESSION_KEY, now.toString());
        }
        
        // Update last activity timestamp
        this.updateLastActivity();
      },
      
      getLastActivity() {
        const lastActivity = localStorage.getItem('dnstools_last_activity');
        return lastActivity ? parseInt(lastActivity) : Date.now();
      },
      
      updateLastActivity() {
        localStorage.setItem('dnstools_last_activity', Date.now().toString());
      },
      
      refreshStats(){
        const history = loadHistory();
        const today = new Date().toDateString();
        const todayHistory = history.filter(h => new Date(h.timestamp).toDateString() === today);
        
        // Calculate stats
        this.stats.totalLookups = todayHistory.length;
        this.stats.successRate = todayHistory.length > 0 ? Math.round((todayHistory.filter(h => h.success).length / todayHistory.length) * 100) : 0;
        this.stats.uniqueDomains = new Set(todayHistory.map(h => h.query.split('\n')[0].split(',')[0].trim())).size;
        this.updateSessionTime();
        
        // Update recent activity (last 5)
        this.recentActivity = history.slice(0, 5).map(h => ({
          ...h,
          timeAgo: this.getTimeAgo(h.timestamp),
          type: this.getQueryType(h.recordTypes)
        }));
      },
      
      updateSessionTime(){
        const elapsed = Date.now() - this.sessionStart;
        const totalSeconds = Math.floor(elapsed / 1000);
        const hours = Math.floor(totalSeconds / 3600);
        const minutes = Math.floor((totalSeconds % 3600) / 60);
        const seconds = totalSeconds % 60;
        
        if (hours > 0) {
          this.stats.sessionTime = `${hours}h ${minutes}m ${seconds}s`;
        } else if (minutes > 0) {
          this.stats.sessionTime = `${minutes}m ${seconds}s`;
        } else {
          this.stats.sessionTime = `${seconds}s`;
        }
      },
      
      getTimeAgo(timestamp){
        const diff = Date.now() - timestamp;
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);
        
        if (days > 0) return `${days}d ago`;
        if (hours > 0) return `${hours}h ago`;
        if (minutes > 0) return `${minutes}m ago`;
        return 'Just now';
      },
      
      getQueryType(recordTypes){
        if (!recordTypes || !Array.isArray(recordTypes) || recordTypes.length === 0) return 'DNS';
        if (recordTypes.includes && recordTypes.includes('MX')) return 'MX';
        if (recordTypes.includes && recordTypes.includes('DMARC')) return 'DMARC';
        if (recordTypes.includes && recordTypes.includes('Headers')) return 'Headers';
        return 'DNS';
      },
      
      initCharts(){
        // Destroy existing charts if they exist
        if (this.hourlyChart) {
          this.hourlyChart.destroy();
          this.hourlyChart = null;
        }
        if (this.typeChart) {
          this.typeChart.destroy();
          this.typeChart = null;
        }
        
        // Get current data before creating chart
        const history = loadHistory();
        const hourlyData = new Array(24).fill(0);
        const today = new Date().toDateString();
        
        // Pre-calculate data for chart creation
        history.forEach((entry) => {
          if (entry && entry.timestamp) {
            const entryDate = new Date(entry.timestamp);
            if (entryDate.toDateString() === today) {
              const hour = entryDate.getHours();
              if (hour >= 0 && hour < 24) {
                hourlyData[hour]++;
              }
            }
          }
        });
        
        // Initialize the hourly chart
        const hourlyCtx = document.getElementById('hourlyChart');
        if (hourlyCtx) {
          try {
            // Create chart with actual data from the start
            this.hourlyChart = new Chart(hourlyCtx, {
              type: 'line',
              data: {
                labels: ['00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23'],
                datasets: [{
                  data: hourlyData, // Use actual data instead of zeros
                  borderColor: '#58a6ff',
                  borderWidth: 2
                }]
              },
              options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: false
                }
              }
            });
          } catch (error) {
            console.error('Error creating basic chart:', error);
            // If even basic chart fails, try without any styling
            try {
              this.hourlyChart = new Chart(hourlyCtx, {
                type: 'line',
                data: {
                  labels: ['00', '06', '12', '18'],
                  datasets: [{
                    data: [0, 5, 10, 5]
                  }]
                }
              });
            } catch (minimalError) {
              console.error('Even minimal chart failed:', minimalError);
            }
          }
        }
        
        // Skip pie chart initialization for now - causes stack overflow
        // const typeCtx = document.getElementById('typeChart');
        // this.typeChart = null;
      },
      
      updateCharts(history){
        try {
          if (!this.chartInitialized || !this.hourlyChart) {
            return;
          }
          
          if (!Array.isArray(history) || history.length === 0) {
            return;
          }
          
          // Update hourly chart data safely
          const hourlyData = new Array(24).fill(0);
          const today = new Date().toDateString();
          
          // Count lookups by hour for today only
          let todayCount = 0;
          history.forEach((entry) => {
            if (entry && entry.timestamp) {
              const entryDate = new Date(entry.timestamp);
              const entryDateStr = entryDate.toDateString();
              
              if (entryDateStr === today) {
                todayCount++;
                const hour = entryDate.getHours();
                if (hour >= 0 && hour < 24) {
                  hourlyData[hour]++;
                }
              }
            }
          });          
          // Add some test data if no real data exists
          if (hourlyData.reduce((a, b) => a + b, 0) === 0) {
            const currentHour = new Date().getHours();
            hourlyData[currentHour] = 5;
            hourlyData[(currentHour - 1 + 24) % 24] = 3;
            hourlyData[(currentHour - 2 + 24) % 24] = 7;
          }
          
          // Update chart data
          if (this.hourlyChart && this.hourlyChart.data && this.hourlyChart.data.datasets && this.hourlyChart.data.datasets[0]) {            
            // Direct data assignment - simplest approach
            this.hourlyChart.data.datasets[0].data = hourlyData;
            
            // Try simple update without animation
            try {
              this.hourlyChart.update('none');
            } catch (updateError) {
              // Don't recreate - just log the error and continue
              console.error('Update error:', updateError);
            }
          }
          
          
        } catch (error) {
          console.error('Chart update error:', error);
        }
      },
      
      rerunQuery(activity){
        const type = activity.type.toLowerCase();
        if (type === 'headers') {
          // For headers, store the data in localStorage if available
          if (activity.results && activity.results.headers) {
            let headersText = '';
            
            // Try to reconstruct from parsed headers
            const headers = activity.results.headers;
            for (const [key, value] of Object.entries(headers)) {
              if (key.startsWith('received-')) {
                headersText += `Received: ${value}\n`;
              } else {
                const capitalizedKey = key.split('-').map(word => 
                  word.charAt(0).toUpperCase() + word.slice(1)
                ).join('-');
                headersText += `${capitalizedKey}: ${value}\n`;
              }
            }
            
            // Store in localStorage temporarily
            localStorage.setItem('dns_rerun_headers', headersText);
          }
          window.location = 'headers.html?rerun=true';
        } else if (type === 'mx') {
          // Extract domain from query for MX
          const domain = activity.query.trim();
          window.location = 'mx.html?domain=' + encodeURIComponent(domain);
        } else if (type === 'dmarc') {
          // Extract domain from query for DMARC
          const domain = activity.query.trim();
          window.location = 'dmarc.html?domain=' + encodeURIComponent(domain);
        } else {
          // For DNS lookups, pass domains and record types if available
          window.location = 'lookup.html?domains=' + encodeURIComponent(activity.query);
        }
      },
      
      getTypeCount(type) {
        const history = loadHistory();
        return history.filter(item => {
          const itemType = this.getQueryType(item.recordTypes);
          return itemType === type;
        }).length;
      },
      
      recreateChart(data) {
        try {
          // Destroy existing chart completely
          if (this.hourlyChart) {
            this.hourlyChart.destroy();
            this.hourlyChart = null;
          }
          
          // Get canvas element and ensure it's clean
          let hourlyCtx = document.getElementById('hourlyChart');
          if (hourlyCtx) {
            // Remove the old canvas and create a new one to avoid Chart.js conflicts
            const parent = hourlyCtx.parentNode;
            const newCanvas = document.createElement('canvas');
            newCanvas.id = 'hourlyChart';
            newCanvas.style.cssText = hourlyCtx.style.cssText;
            
            parent.removeChild(hourlyCtx);
            parent.appendChild(newCanvas);
            
            hourlyCtx = newCanvas;
            
            // Small delay to ensure DOM is ready
            setTimeout(() => {
              try {
                // Create new chart with the data
                this.hourlyChart = new Chart(hourlyCtx, {
                  type: 'line',
                  data: {
                    labels: ['00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23'],
                    datasets: [{
                      label: 'Lookups per Hour',
                      data: [...data],
                      borderColor: '#58a6ff',
                      backgroundColor: 'rgba(88, 166, 255, 0.1)',
                      borderWidth: 2,
                      fill: true
                    }]
                  },
                  options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                      legend: { 
                        display: false 
                      }
                    },
                    scales: {
                      x: {
                        grid: { 
                          color: '#30363d' 
                        },
                        ticks: { 
                          color: '#8b949e' 
                        }
                      },
                      y: {
                        grid: { 
                          color: '#30363d' 
                        },
                        ticks: { 
                          color: '#8b949e' 
                        },
                        beginAtZero: true
                      }
                    }
                  }
                });
              } catch (createError) {
                console.error('Chart creation failed:', createError);
              }
            }, 50);
          }
        } catch (error) {
          console.error('Chart recreation failed:', error);
        }
      }
    };
  };

  // Resources component
  window.ResourcesPage = function(){
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
              <li><strong>Message Signing:</strong> Sending server signs email headers and body with private key</li>
              <li><strong>Signature Addition:</strong> Digital signature added to DKIM-Signature header</li>
              <li><strong>Public Key Publication:</strong> Public key published in DNS TXT record</li>
              <li><strong>Verification:</strong> Receiving server retrieves public key and validates signature</li>
            </ol>
            
            <h4>DKIM DNS Record Structure</h4>
            <pre><code>2023-selector._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...IDAQAB"</code></pre>
            
            <h5>DNS Record Components:</h5>
            <ul>
              <li><strong>Hostname Format:</strong> [selector]._domainkey.[domain]</li>
              <li><strong>Selector:</strong> Arbitrary string allowing multiple keys per domain</li>
              <li><strong>_domainkey:</strong> Fixed subdomain indicating DKIM record</li>
            </ul>
            
            <h4>DKIM Record Tags</h4>
            <table style="border-collapse: collapse; width: 100%; margin: 16px 0;">
              <tr style="background: #21262d;">
                <th style="border: 1px solid #30363d; padding: 8px;">Tag</th>
                <th style="border: 1px solid #30363d; padding: 8px;">Required</th>
                <th style="border: 1px solid #30363d; padding: 8px;">Description</th>
                <th style="border: 1px solid #30363d; padding: 8px;">Example</th>
              </tr>
              <tr>
                <td style="border: 1px solid #30363d; padding: 8px;"><strong>v</strong></td>
                <td style="border: 1px solid #30363d; padding: 8px;">Yes</td>
                <td style="border: 1px solid #30363d; padding: 8px;">DKIM version</td>
                <td style="border: 1px solid #30363d; padding: 8px;">v=DKIM1</td>
              </tr>
              <tr>
                <td style="border: 1px solid #30363d; padding: 8px;"><strong>k</strong></td>
                <td style="border: 1px solid #30363d; padding: 8px;">No</td>
                <td style="border: 1px solid #30363d; padding: 8px;">Key type</td>
                <td style="border: 1px solid #30363d; padding: 8px;">k=rsa</td>
              </tr>
              <tr>
                <td style="border: 1px solid #30363d; padding: 8px;"><strong>p</strong></td>
                <td style="border: 1px solid #30363d; padding: 8px;">Yes</td>
                <td style="border: 1px solid #30363d; padding: 8px;">Base64 public key</td>
                <td style="border: 1px solid #30363d; padding: 8px;">p=MIGfMA0G...</td>
              </tr>
              <tr>
                <td style="border: 1px solid #30363d; padding: 8px;"><strong>t</strong></td>
                <td style="border: 1px solid #30363d; padding: 8px;">No</td>
                <td style="border: 1px solid #30363d; padding: 8px;">Test mode flag</td>
                <td style="border: 1px solid #30363d; padding: 8px;">t=y</td>
              </tr>
              <tr>
                <td style="border: 1px solid #30363d; padding: 8px;"><strong>h</strong></td>
                <td style="border: 1px solid #30363d; padding: 8px;">No</td>
                <td style="border: 1px solid #30363d; padding: 8px;">Hash algorithms</td>
                <td style="border: 1px solid #30363d; padding: 8px;">h=sha1:sha256</td>
              </tr>
            </table>
            
            <h4>DKIM Signature Header</h4>
            <p>The DKIM-Signature header contains information about how the signature was created:</p>
            <pre><code>DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=2023-selector; 
                h=from:to:subject:date; bh=hash-of-body; b=signature-value</code></pre>
            
            <h5>Signature Tags:</h5>
            <ul>
              <li><strong>d=:</strong> Signing domain</li>
              <li><strong>s=:</strong> Selector used</li>
              <li><strong>h=:</strong> Headers included in signature</li>
              <li><strong>bh=:</strong> Hash of message body</li>
              <li><strong>b=:</strong> Actual signature value</li>
            </ul>
            
            <h4>DKIM Benefits</h4>
            <div style="background: #21262d; border-left: 3px solid #238636; padding: 12px; margin: 16px 0;">
              <p><strong>🔐 Security Advantages:</strong></p>
              <ul>
                <li><strong>Message Integrity:</strong> Detects any tampering with signed content</li>
                <li><strong>Non-repudiation:</strong> Cryptographic proof of origin</li>
                <li><strong>Reputation Transfer:</strong> Links message to domain's reputation</li>
                <li><strong>Replay Protection:</strong> Signatures include timestamp information</li>
              </ul>
            </div>
            
            <h4>Implementation Considerations</h4>
            <h5>Key Management:</h5>
            <ul>
              <li><strong>Key Rotation:</strong> Regularly rotate keys for security</li>
              <li><strong>Multiple Selectors:</strong> Use different keys for different services</li>
              <li><strong>Key Length:</strong> Minimum 1024-bit, recommended 2048-bit RSA keys</li>
              <li><strong>Key Revocation:</strong> Empty p= value indicates revoked key</li>
            </ul>
            
            <h5>Signing Strategy:</h5>
            <ul>
              <li><strong>Critical Headers:</strong> Always sign From, Subject, Date headers</li>
              <li><strong>Body Hashing:</strong> Include message body in signature</li>
              <li><strong>Canonicalization:</strong> Handle whitespace variations properly</li>
            </ul>
            
            <h4>Common Failure Points</h4>
            <ul>
              <li>Missing or incorrect DNS record</li>
              <li>Clock skew between signing and verification</li>
              <li>Message modification in transit</li>
              <li>Incorrect selector in signature</li>
              <li>Expired or revoked keys</li>
            </ul>
            
            <h4>Testing and Monitoring</h4>
            <ul>
              <li>Use DKIM validators to test signatures</li>
              <li>Monitor email headers for DKIM results</li>
              <li>Check DMARC reports for DKIM failures</li>
              <li>Verify key accessibility from multiple resolvers</li>
            </ul>
          `,
          'DMARC': `
            <h4>DMARC: Email Authentication Policy Framework</h4>
            <p>DMARC (Domain-based Message Authentication, Reporting, and Conformance) builds upon SPF and DKIM to provide a policy framework for email authentication. It instructs receiving servers how to handle authentication failures and provides detailed reporting on email traffic.</p>
            
            <h4>How DMARC Works</h4>
            <ol>
              <li><strong>Policy Publication:</strong> Domain owner publishes DMARC policy in DNS</li>
              <li><strong>Message Evaluation:</strong> Receiving server checks SPF and DKIM</li>
              <li><strong>Alignment Check:</strong> Verifies domain alignment with From: header</li>
              <li><strong>Policy Application:</strong> Applies specified action based on results</li>
              <li><strong>Reporting:</strong> Sends aggregate and forensic reports to domain owner</li>
            </ol>
            
            <h4>DMARC Record Structure</h4>
            <pre><code>_dmarc.example.com. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com; pct=100"</code></pre>
            
            <h5>DNS Record Location:</h5>
            <ul>
              <li><strong>Hostname:</strong> _dmarc.[domain]</li>
              <li><strong>Record Type:</strong> TXT</li>
              <li><strong>Scope:</strong> Applies to domain and subdomains</li>
            </ul>
            
            <h4>DMARC Policy Tags</h4>
            <table style="border-collapse: collapse; width: 100%; margin: 16px 0;">
              <tr style="background: #21262d;">
                <th style="border: 1px solid #30363d; padding: 8px;">Tag</th>
                <th style="border: 1px solid #30363d; padding: 8px;">Required</th>
                <th style="border: 1px solid #30363d; padding: 8px;">Description</th>
                <th style="border: 1px solid #30363d; padding: 8px;">Values</th>
              </tr>
              <tr>
                <td style="border: 1px solid #30363d; padding: 8px;"><strong>v</strong></td>
                <td style="border: 1px solid #30363d; padding: 8px;">Yes</td>
                <td style="border: 1px solid #30363d; padding: 8px;">DMARC version</td>
                <td style="border: 1px solid #30363d; padding: 8px;">DMARC1</td>
              </tr>
              <tr>
                <td style="border: 1px solid #30363d; padding: 8px;"><strong>p</strong></td>
                <td style="border: 1px solid #30363d; padding: 8px;">Yes</td>
                <td style="border: 1px solid #30363d; padding: 8px;">Policy for domain</td>
                <td style="border: 1px solid #30363d; padding: 8px;">none, quarantine, reject</td>
              </tr>
              <tr>
                <td style="border: 1px solid #30363d; padding: 8px;"><strong>sp</strong></td>
                <td style="border: 1px solid #30363d; padding: 8px;">No</td>
                <td style="border: 1px solid #30363d; padding: 8px;">Policy for subdomains</td>
                <td style="border: 1px solid #30363d; padding: 8px;">none, quarantine, reject</td>
              </tr>
              <tr>
                <td style="border: 1px solid #30363d; padding: 8px;"><strong>rua</strong></td>
                <td style="border: 1px solid #30363d; padding: 8px;">No</td>
                <td style="border: 1px solid #30363d; padding: 8px;">Aggregate report URI</td>
                <td style="border: 1px solid #30363d; padding: 8px;">mailto:reports@domain</td>
              </tr>
              <tr>
                <td style="border: 1px solid #30363d; padding: 8px;"><strong>ruf</strong></td>
                <td style="border: 1px solid #30363d; padding: 8px;">No</td>
                <td style="border: 1px solid #30363d; padding: 8px;">Failure report URI</td>
                <td style="border: 1px solid #30363d; padding: 8px;">mailto:forensic@domain</td>
              </tr>
              <tr>
                <td style="border: 1px solid #30363d; padding: 8px;"><strong>pct</strong></td>
                <td style="border: 1px solid #30363d; padding: 8px;">No</td>
                <td style="border: 1px solid #30363d; padding: 8px;">Percentage to apply policy</td>
                <td style="border: 1px solid #30363d; padding: 8px;">1-100 (default: 100)</td>
              </tr>
            </table>
            
            <h4>DMARC Policy Levels</h4>
            <h5>p=none (Monitor Mode)</h5>
            <ul>
              <li>No action taken on failed messages</li>
              <li>Generate reports for analysis</li>
              <li>Recommended starting point</li>
              <li>Allows identification of all email sources</li>
            </ul>
            
            <h5>p=quarantine (Suspicious Mail)</h5>
            <ul>
              <li>Failed messages sent to spam/junk folder</li>
              <li>Messages still delivered but marked</li>
              <li>Intermediate enforcement level</li>
              <li>Allows gradual policy tightening</li>
            </ul>
            
            <h5>p=reject (Block Failed Messages)</h5>
            <ul>
              <li>Failed messages rejected outright</li>
              <li>Strongest protection level</li>
              <li>Requires confidence in SPF/DKIM setup</li>
              <li>Maximum brand protection</li>
            </ul>
            
            <h4>Domain Alignment</h4>
            <div style="background: #21262d; border-left: 3px solid #f79000; padding: 12px; margin: 16px 0;">
              <p><strong>🎯 Critical Concept - Alignment:</strong></p>
              <p>For DMARC to pass, the domain in the From: header must "align" with either:</p>
              <ul>
                <li><strong>SPF Domain:</strong> Domain in Return-Path/envelope-from</li>
                <li><strong>DKIM Domain:</strong> Domain in d= parameter of valid DKIM signature</li>
              </ul>
              <p>This prevents attacks where emails pass authentication for one domain but display a different domain in the From: field.</p>
            </div>
            
            <h4>Alignment Modes</h4>
            <ul>
              <li><strong>Relaxed (default):</strong> Organizational domain must match (subdomain allowed)</li>
              <li><strong>Strict:</strong> Exact domain match required</li>
              <li><strong>Configuration:</strong> Use aspf= and adkim= tags to set alignment mode</li>
            </ul>
            
            <h4>Implementation Strategy</h4>
            <h5>Phase 1: Discovery (p=none)</h5>
            <pre><code>"v=DMARC1; p=none; rua=mailto:dmarc@example.com"</code></pre>
            <ul>
              <li>Monitor email traffic for 2-4 weeks</li>
              <li>Identify all legitimate sending sources</li>
              <li>Fix SPF/DKIM for failing sources</li>
            </ul>
            
            <h5>Phase 2: Gradual Enforcement</h5>
            <pre><code>"v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc@example.com"</code></pre>
            <ul>
              <li>Apply policy to 25% of failing messages</li>
              <li>Monitor impact on legitimate email</li>
              <li>Gradually increase pct= value</li>
            </ul>
            
            <h5>Phase 3: Full Protection</h5>
            <pre><code>"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com"</code></pre>
            <ul>
              <li>Block all failing messages</li>
              <li>Maximum brand protection achieved</li>
              <li>Continue monitoring reports</li>
            </ul>
            
            <h4>DMARC Reports</h4>
            <h5>Aggregate Reports (rua)</h5>
            <ul>
              <li>Daily statistical summaries</li>
              <li>Show sending sources and authentication results</li>
              <li>Essential for monitoring and compliance</li>
              <li>XML format, typically processed by tools</li>
            </ul>
            
            <h5>Forensic Reports (ruf)</h5>
            <ul>
              <li>Real-time failure notifications</li>
              <li>Include message headers and content</li>
              <li>Useful for investigating specific failures</li>
              <li>May contain sensitive information</li>
            </ul>
            
            <h4>Best Practices</h4>
            <ul>
              <li>Start with p=none to gather intelligence</li>
              <li>Ensure SPF and DKIM are properly configured first</li>
              <li>Use pct= for gradual policy rollout</li>
              <li>Monitor reports regularly for new threats</li>
              <li>Set up dedicated mailbox for DMARC reports</li>
              <li>Consider using DMARC analysis tools for large volumes</li>
            </ul>
          `
        };
        
        return content[conceptName] || `
          <p>Detailed explanation for <strong>${conceptName}</strong> will be provided by Gemini Deep Research.</p>
          <p><em>This feature is ready for integration with Google's Gemini Deep Research API.</em></p>
        `;
      }
    };
  };

  // Initialize DNS client globally
  window.dnsClient = new DNSClient();
})();
