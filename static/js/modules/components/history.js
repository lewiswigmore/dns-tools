import { loadHistory, saveHistory, exportJSON } from '../utils.js';

export function HistoryPage() {
    return {
      history: [],
      filteredHistory: [],
      searchFilter: '',
      typeFilter: 'all',
      previewModal: false,
      previewData: null,
      
      init() {
        window.historyPageInstance = this;
        this.history = loadHistory() || []; // Ensure we always have an array
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
        if (!this.history || !Array.isArray(this.history)) return 0;
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
          case 'Intel': return baseClass + 'pill-red';
          case 'Concept': return baseClass + 'pill-blue';
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
        } else if (type === 'Intel') {
          // Extract target from query for Intel
          const target = item.query.trim();
          window.location = 'intel.html?q=' + encodeURIComponent(target);
        } else if (type === 'Concept') {
          // Extract concept ID from results
          const conceptId = item.results && item.results.id ? item.results.id : item.query;
          window.location = 'intel.html?concept=' + encodeURIComponent(conceptId);
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
        if (recordTypes.includes('INTEL')) return 'Intel';
        if (recordTypes.includes('CONCEPT')) return 'Concept';
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
      },

      async copyToClipboard(text) {
        try {
          await navigator.clipboard.writeText(text);
        } catch (err) {
          console.error('Failed to copy:', err);
        }
      },

      exportResults() {
        if (this.previewData && this.previewData.results) {
          exportJSON(this.previewData.results);
        }
      },

      async copyAllResults() {
        if (!this.previewData || !this.previewData.results) return;
        
        const type = this.getQueryType(this.previewData.recordTypes);
        const isComparison = this.previewData.mode === 'comparison';
        
        let text = `# ${this.getDisplayTitle(this.previewData)}\n\n`;
        text += `**Type:** ${type}\n`;
        text += `**Date:** ${new Date(this.previewData.timestamp).toLocaleString()}\n`;
        text += `**Mode:** ${isComparison ? 'Provider Comparison' : 'Standard Lookup'}\n\n`;
        text += '---\n\n';

        if (isComparison) {
          this.previewData.results.forEach(row => {
            text += `## ${row.domain}\n\n`;
            if (row.comparisons) {
              Object.keys(row.comparisons).forEach(recType => {
                text += `### ${recType} Records\n\n`;
                text += `| Provider | Status | Latency | Records |\n`;
                text += `|----------|--------|---------|---------|\n`;
                
                ['Google', 'Cloudflare'].forEach(provider => {
                  const res = row.comparisons[recType][provider];
                  if (res) {
                    const records = res.records.map(r => r.value).join(', ') || 'No records';
                    text += `| ${provider} | ${res.status === 'success' ? '✅' : '❌'} | ${res.latency}ms | \`${records}\` |\n`;
                  }
                });
                text += '\n';
              });
            }
          });
        } else if (type === 'DNS') {
          if (Array.isArray(this.previewData.results)) {
            this.previewData.results.forEach(res => {
              text += `## ${res.domain}\n\n`;
              if (res.records) {
                for (const [recType, records] of Object.entries(res.records)) {
                  if (records && records.length > 0) {
                    text += `### ${recType} Records\n`;
                    text += `| Value | TTL |\n`;
                    text += `|-------|-----|\n`;
                    records.forEach(rec => {
                      const val = typeof rec === 'object' ? (rec.data || rec.value || rec.target || JSON.stringify(rec)) : rec;
                      text += `| \`${val}\` | ${rec.ttl} |\n`;
                    });
                    text += '\n';
                  }
                }
              }
            });
          }
        } else if (type === 'MX') {
          if (Array.isArray(this.previewData.results)) {
            text += '### MX Records\n\n';
            text += `| Priority | Exchange |\n`;
            text += `|----------|----------|\n`;
            this.previewData.results.forEach(rec => {
              const priority = typeof rec === 'object' ? rec.priority : '-';
              const exchange = typeof rec === 'object' ? rec.exchange : rec;
              text += `| ${priority} | \`${exchange}\` |\n`;
            });
          }
        } else if (type === 'DMARC') {
          const res = this.previewData.results.result;
          if (res) {
            text += `### DMARC Record\n\n`;
            text += `\`${res.raw || 'None'}\`\n\n`;
            text += `**Policy:** ${res.policy}\n`;
            if (res.adkim) text += `**DKIM Alignment:** ${res.adkim}\n`;
            if (res.aspf) text += `**SPF Alignment:** ${res.aspf}\n`;
          }
        } else if (type === 'Headers') {
          const res = this.previewData.results;
          if (res.routing) {
            text += `**From:** \`${res.routing.from}\`\n`;
            text += `**To:** \`${res.routing.to}\`\n`;
            text += `**Subject:** \`${res.routing.subject}\`\n`;
            text += `**Date:** ${res.routing.date}\n\n`;
          }
          
          text += `### Authentication\n`;
          if (res.spf) text += `- **SPF:** ${res.spf.status}\n`;
          if (res.dkim) text += `- **DKIM:** ${res.dkim.status}\n`;
          if (res.dmarc) text += `- **DMARC:** ${res.dmarc.status}\n`;
          
          if (res.security) {
            text += `\n### Security\n`;
            text += `- **TLS:** ${res.security.tls ? 'Yes' : 'No'}\n`;
            if (res.security.warnings && res.security.warnings.length > 0) {
              text += `\n**Warnings:**\n${res.security.warnings.map(w => `- ${w}`).join('\n')}\n`;
            }
          }
        } else if (type === 'Intel') {
          const res = this.previewData.results;
          text += `**Target:** ${res.target}\n`;
          text += `**Type:** ${res.type}\n\n`;
          text += `### Analysis Links\n`;
          if (res.links) {
            res.links.forEach(link => {
              text += `- [${link.name}](${link.url})\n`;
            });
          }
        } else if (type === 'Concept') {
          const res = this.previewData.results;
          text += `**Concept:** ${this.previewData.query}\n\n`;
          text += `**Summary:** ${res.summary}\n`;
        }

        await this.copyToClipboard(text);
      }
    };
  };
