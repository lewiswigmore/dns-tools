export class DNSClient {
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