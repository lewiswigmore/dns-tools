import { addHistory, exportJSON } from '../utils.js';

export function DMARCPage() {
    return {
      domain:'', result:null, comparisonResult: null, compareMode: false, loading:false, error:'', searchPerformed:false,
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
        this.comparisonResult = null;
        this.searchPerformed = true; // Mark that a search has been performed
        
        try {
          const startTime = Date.now();
          
          if (this.compareMode) {
            const response = await window.dnsClient.performDMARCComparison(this.domain);
            this.comparisonResult = response.comparison;
            
            const duration = (Date.now() - startTime) / 1000;
            addHistory({
              query: this.domain,
              timestamp: Date.now(),
              domains: 1,
              duration: duration,
              success: true,
              recordTypes: ['DMARC'],
              results: [{ domain: this.domain, comparisons: { 'DMARC': this.comparisonResult } }],
              mode: 'comparison'
            });
          } else {
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
        } else if (this.result) {
          exportJSON(this.result);
        }
      },

      async copyAllResults() {
        if (this.compareMode && this.comparisonResult) {
          let text = `# DMARC Comparison for ${this.domain}\n\n`;
          text += `**Date:** ${new Date().toLocaleString()}\n\n`;
          
          text += `| Provider | Status | Latency | Record |\n`;
          text += `|----------|--------|---------|--------|\n`;
          
          ['Google', 'Cloudflare'].forEach(provider => {
            const res = this.comparisonResult[provider];
            if (res) {
              const record = res.records.length > 0 ? res.records[0].value : 'No record';
              text += `| ${provider} | ${res.status === 'success' ? '✅' : '❌'} | ${res.latency}ms | \`${record}\` |\n`;
            }
          });
          
          await this.copyToClipboard(text);
          return;
        }

        if (!this.result) return;
        
        let text = `# DMARC Policy for ${this.domain}\n\n`;
        text += `**Date:** ${new Date().toLocaleString()}\n\n`;
        
        text += `- **Policy Action:** ${this.result.policy || 'none'}\n`;
        if (this.result.adkim) text += `- **DKIM Alignment:** ${this.result.adkim}\n`;
        if (this.result.aspf) text += `- **SPF Alignment:** ${this.result.aspf}\n`;
        
        if (this.result.raw) {
          text += `\n## Raw Record\n\`\`\`\n${this.result.raw}\n\`\`\`\n`;
        }
        
        await this.copyToClipboard(text);
      }
    }
  };
