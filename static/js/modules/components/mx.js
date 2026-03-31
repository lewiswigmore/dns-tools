import { addHistory, exportJSON } from '../utils.js';

export function MXPage() {
    return {
      presets: [
        { label: 'google.com', value: 'google.com' },
        { label: 'microsoft.com', value: 'microsoft.com' },
        { label: 'openai.com', value: 'openai.com' },
      ],
      domain:'', results:[], comparisonResult: null, compareMode: false, loading:false, error:'', searchPerformed:false,
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
        this.comparisonResult = null;
        this.searchPerformed = true; // Mark that a search has been performed
        
        try {
          const startTime = Date.now();
          
          if (this.compareMode) {
            const response = await window.dnsClient.performMXComparison(this.domain);
            this.comparisonResult = response.comparison;
            
            const duration = (Date.now() - startTime) / 1000;
            addHistory({
              query: this.domain,
              timestamp: Date.now(),
              domains: 1,
              duration: duration,
              success: true,
              recordTypes: ['MX'],
              results: [{ domain: this.domain, comparisons: { 'MX': this.comparisonResult } }],
              mode: 'comparison'
            });
          } else {
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
      },

      applyPreset(value) {
        this.domain = value;
      },

      async copyToClipboard(text) {
        try {
          await navigator.clipboard.writeText(text);
        } catch (err) {
          console.error('Failed to copy:', err);
        }
      },

      exportResults() {
        if (this.compareMode && this.comparisonResult) {
          exportJSON(this.comparisonResult);
        } else if (this.results && this.results.length > 0) {
          exportJSON(this.results);
        }
      },

      async copyAllResults() {
        if (this.compareMode && this.comparisonResult) {
          let text = `# MX Comparison for ${this.domain}\n\n`;
          text += `**Date:** ${new Date().toLocaleString()}\n\n`;
          
          text += `| Provider | Status | Latency | Records |\n`;
          text += `|----------|--------|---------|---------|\n`;
          
          const providers = Object.keys(this.comparisonResult).sort();
          
          providers.forEach(provider => {
            const res = this.comparisonResult[provider];
            if (res) {
              const records = res.records.map(r => `${r.priority} ${r.exchange}`).join(', ') || 'No records';
              text += `| ${provider} | ${res.status === 'success' ? '✅' : '❌'} | ${res.latency}ms | \`${records}\` |\n`;
            }
          });
          
          await this.copyToClipboard(text);
          return;
        }

        if (!this.results || this.results.length === 0) return;
        
        let text = `# MX Records for ${this.domain}\n\n`;
        text += `**Date:** ${new Date().toLocaleString()}\n\n`;
        
        text += `| Priority | Mail Server |\n`;
        text += `|----------|-------------|\n`;
        
        this.results.forEach(r => {
          text += `| ${r.priority} | \`${r.exchange}\` |\n`;
        });
        
        await this.copyToClipboard(text);
      }
    };
  };
