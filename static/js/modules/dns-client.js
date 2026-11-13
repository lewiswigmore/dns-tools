import { loadSettings } from './utils.js';

const PROVIDER_URLS = {
  'Google': 'https://dns.google/resolve',
  'Cloudflare': 'https://cloudflare-dns.com/dns-query'
};

const MAX_CONCURRENT_DNS_REQUESTS = 6;

async function mapWithConcurrency(items, concurrency, callback) {
  const results = new Array(items.length);
  let nextIndex = 0;
  const workerCount = Math.min(concurrency, items.length);

  await Promise.all(Array.from({ length: workerCount }, async () => {
    while (nextIndex < items.length) {
      const index = nextIndex++;
      results[index] = await callback(items[index]);
    }
  }));

  return results;
}

function normalizeDMARCTxt(raw) {
  if (typeof raw !== 'string') return '';
  const text = raw.trim();
  if (!text.startsWith('"')) return raw;

  // Decode only complete DNS-quoted chunks; malformed presentation stays unmatched.
  let value = '';
  let index = 0;
  while (index < text.length) {
    if (text[index++] !== '"') return raw;
    let closed = false;

    while (index < text.length) {
      const char = text[index++];
      if (char === '"') {
        closed = true;
        break;
      }
      if (char !== '\\') {
        value += char;
        continue;
      }

      const decimal = text.slice(index, index + 3);
      if (/^\d{3}$/.test(decimal)) {
        const code = Number(decimal);
        if (code > 255) return raw;
        value += String.fromCharCode(code);
        index += 3;
      } else if (index < text.length && !/\d/.test(text[index])) {
        value += text[index++];
      } else {
        return raw;
      }
    }

    if (!closed) return raw;
    while (index < text.length && /\s/.test(text[index])) index++;
  }
  return value;
}

function findDMARCRecord(records) {
  for (const record of records) {
    const value = normalizeDMARCTxt(record.value);
    if (/^v=DMARC1(?=\s*(?:;|$))/.test(value)) {
      return { raw: record.value, value };
    }
  }
  return null;
}

export class DNSClient {
    constructor() {
      this.settings = loadSettings();
    }

    updateSettings(newSettings) {
        this.settings = newSettings;
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
    
    // Strip characters commonly left over from pasted lists (quotes, brackets,
    // list markers, trailing punctuation) so real domains embedded in that
    // kind of input are still recognized, without weakening validation itself.
    sanitizeDomainToken(token) {
      if (!token) return '';
      let value = token.trim();

      // Remove wrapping quotes/brackets/braces/parentheses, e.g. ["example.com"]
      value = value.replace(/^["'\[\]{}(),]+/, '').replace(/["'\[\]{}(),]+$/, '');

      // Trim trailing punctuation left over from prose/sentences or a
      // trailing-dot FQDN notation (e.g. "example.com.")
      value = value.replace(/[.,;:!?]+$/, '');

      return value.trim();
    }

    // If a token is an email address, resolve it to the domain the user
    // almost always actually means to look up (the part after "@").
    // Anything else is returned unchanged.
    extractDomainFromToken(token) {
      if (!token || token.indexOf('@') === -1) return token;

      const parts = token.split('@');
      // Only handle the simple "local-part@domain" shape; anything with
      // more than one "@" is ambiguous and left as-is (it will fail
      // validation and be filtered out).
      if (parts.length !== 2) return token;

      const [localPart, domainPart] = parts;
      if (!localPart || !domainPart) return token;

      return domainPart;
    }

    isValidDomain(domain) {
      // Basic domain validation
      if (!domain || typeof domain !== 'string') return false;
      const value = domain.trim();
      if (value.length === 0 || value.length > 253) return false;
      if (value === '.' || value === '..') return false;
      if (value.includes('..')) return false; // Double dots not allowed

      // Never treat email addresses (or anything containing whitespace) as domains
      if (/[@\s]/.test(value)) return false;

      if (value === 'localhost') return true;

      // Must contain at least one dot to have a valid TLD
      if (!value.includes('.')) return false;

      const labels = value.split('.');
      if (labels.length < 2) return false;

      const labelRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
      if (!labels.every(label => labelRegex.test(label))) return false;

      const tld = labels[labels.length - 1];
      if (tld.length < 2) return false;

      // A real TLD is either plain letters (no real TLD contains a digit,
      // so tokens like "6.2M" or "26.67" are rejected) or a punycode/IDN
      // TLD in "xn--..." form, which may contain digits and hyphens.
      const isPunycodeTld = /^xn--[a-z0-9-]+$/i.test(tld);
      const isAlphaTld = /^[a-zA-Z]+$/.test(tld);
      if (!isPunycodeTld && !isAlphaTld) return false;

      // Real TLDs are consistently all-lowercase or all-uppercase; mixed
      // case (e.g. "Read", "ReadWrite", "HttpLoggingMiddleware") is a
      // strong signal of a pasted identifier, filename stem, or API scope
      // rather than an actual domain, so reject it here.
      if (isAlphaTld && tld !== tld.toLowerCase() && tld !== tld.toUpperCase()) return false;

      // Common non-TLD file extensions frequently appear in bulk pastes
      // alongside real domains (e.g. attachment or screenshot names) and
      // would otherwise be treated as syntactically valid domains.
      const commonFileExtensions = new Set([
        'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'ico', 'webp',
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'csv',
        'json', 'xml', 'log', 'md', 'yml', 'yaml', 'ini', 'cfg', 'conf',
        'rar', 'tar', 'gz', '7z', 'exe', 'dll', 'msi', 'bat', 'ps1', 'sh',
        'py', 'rb', 'java', 'cs', 'cpp', 'sql', 'html', 'htm', 'css', 'js', 'ts',
        'mp3', 'wav', 'avi'
      ]);
      if (commonFileExtensions.has(tld.toLowerCase())) return false;

      return true;
    }

    // Shared parsing used by both single-provider lookups and comparisons so
    // bulk input (newline/comma/space separated, including pasted lists with
    // quotes or brackets) is handled consistently.
    parseDomainList(domains) {
      return [...new Set(
        (domains || '')
          .split(/[\n,]+|\s+/)
          .map(d => this.sanitizeDomainToken(d))
          .filter(d => d.length > 0)
          .map(d => this.extractDomainFromToken(d))
          .map(d => this.deobfuscateDomain(d))
          .filter(d => this.isValidDomain(d))
      )];
    }

    async performLookup(domains, recordTypes) {
      const domainsArray = this.parseDomainList(domains);
      const results = domainsArray.map(domain => ({
        domain,
        records: {},
        errors: []
      }));
      const tasks = domainsArray.flatMap((domain, domainIndex) =>
        recordTypes.map(recordType => ({ domain, domainIndex, recordType }))
      );

      const taskResults = await mapWithConcurrency(tasks, MAX_CONCURRENT_DNS_REQUESTS, async task => {
        try {
          return {
            task,
            records: await this.queryDNS(task.domain.trim(), task.recordType)
          };
        } catch (error) {
          return { task, error };
        }
      });

      for (const { task, records, error } of taskResults) {
        const domainResult = results[task.domainIndex];
        domainResult.records[task.recordType] = error ? [] : records;
        if (error) {
          domainResult.errors.push(`${task.recordType} lookup failed: ${error.message}`);
          console.warn(`Failed to lookup ${task.recordType} for ${task.domain}:`, error);
        }
      }

      for (const domainResult of results) {
        const hasAnyRecords = Object.values(domainResult.records).some(records => records.length > 0);
        if (!hasAnyRecords && domainResult.errors.length === 0) {
          domainResult.errors.push('No DNS records found - domain may not exist');
        }
      }
      
      return {
        results: results,
        stats: {
          domains_processed: results.length,
          lookup_time: 0.5
        }
      };
    }

    async performComparison(domains, recordTypes) {
      const domainsArray = this.parseDomainList(domains);
      const activeProviders = (this.settings.providers || ['Google', 'Cloudflare']).map(name => ({
        name: name,
        url: PROVIDER_URLS[name]
      })).filter(p => p.url);
      const results = domainsArray.map(domain => ({
        domain,
        comparisons: Object.fromEntries(recordTypes.map(recordType => [recordType, {}]))
      }));
      const tasks = domainsArray.flatMap((domain, domainIndex) =>
        recordTypes.flatMap(recordType =>
          activeProviders.map(provider => ({ domain, domainIndex, recordType, provider }))
        )
      );

      const providerResults = await mapWithConcurrency(tasks, MAX_CONCURRENT_DNS_REQUESTS, async task => {
        try {
          const start = performance.now();
          const records = await this.queryDNS(task.domain.trim(), task.recordType, task.provider.url);
          return {
            task,
            result: {
              provider: task.provider.name,
              records,
              latency: Math.round(performance.now() - start),
              status: 'success'
            }
          };
        } catch (error) {
          return {
            task,
            result: {
              provider: task.provider.name,
              records: [],
              error: error.message,
              status: 'error'
            }
          };
        }
      });

      for (const { task, result } of providerResults) {
        results[task.domainIndex].comparisons[task.recordType][task.provider.name] = result;
      }

      return { results };
    }
    
    async queryDNS(domain, recordType, providerUrl = null) {
      let url = providerUrl;
      if (!url) {
          const primary = this.settings.primaryProvider || 'Google';
          url = PROVIDER_URLS[primary] || PROVIDER_URLS['Google'];
      }
      const dohUrl = `${url}?name=${encodeURIComponent(domain)}&type=${recordType}`;
      
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
    
    async performMXComparison(domain) {
      const activeProviders = (this.settings.providers || ['Google', 'Cloudflare']).map(name => ({
        name: name,
        url: PROVIDER_URLS[name]
      })).filter(p => p.url);

      const comparison = {};
      
      const providerPromises = activeProviders.map(async (provider) => {
        try {
          const start = performance.now();
          const records = await this.queryDNS(domain.trim(), 'MX', provider.url);
          const duration = Math.round(performance.now() - start);
          return {
            provider: provider.name,
            records: records,
            latency: duration,
            status: 'success'
          };
        } catch (error) {
          return {
            provider: provider.name,
            records: [],
            error: error.message,
            status: 'error'
          };
        }
      });

      const results = await Promise.all(providerPromises);
      results.forEach(res => {
        comparison[res.provider] = res;
      });

      return { comparison };
    }

    async performDMARCComparison(domain) {
      const activeProviders = (this.settings.providers || ['Google', 'Cloudflare']).map(name => ({
        name: name,
        url: PROVIDER_URLS[name]
      })).filter(p => p.url);

      const comparison = {};
      const dmarcDomain = `_dmarc.${domain.trim()}`;
      
      const providerPromises = activeProviders.map(async (provider) => {
        try {
          const start = performance.now();
          const records = await this.queryDNS(dmarcDomain, 'TXT', provider.url);
          const duration = Math.round(performance.now() - start);
          
          const dmarcRecord = findDMARCRecord(records);
          let parsed = null;
          
          if (dmarcRecord) {
             parsed = this.parseDMARCPolicy(dmarcRecord.value);
          }

          return {
            provider: provider.name,
            records: records,
            dmarc: dmarcRecord ? { ...parsed, raw: dmarcRecord.raw } : null,
            latency: duration,
            status: 'success'
          };
        } catch (error) {
          return {
            provider: provider.name,
            dmarc: null,
            error: error.message,
            status: 'error'
          };
        }
      });

      const results = await Promise.all(providerPromises);
      results.forEach(res => {
        comparison[res.provider] = res;
      });

      return { comparison };
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
        
        const dmarcRecord = findDMARCRecord(records);
        
        if (dmarcRecord) {
          const parsedPolicy = this.parseDMARCPolicy(dmarcRecord.value);
          return {
            result: {
              raw: dmarcRecord.raw,
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