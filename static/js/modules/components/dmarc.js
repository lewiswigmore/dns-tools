import { addHistory, exportJSON } from '../utils.js';

export function DMARCPage() {
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
      },

      async copyToClipboard(text) {
        try {
          await navigator.clipboard.writeText(text);
        } catch (err) {
          console.error('Failed to copy:', err);
        }
      },

      exportResults() {
        if (this.result) {
          exportJSON(this.result);
        }
      },

      async copyAllResults() {
        if (!this.result) return;
        
        let text = `DMARC Policy for ${this.domain}\n`;
        text += `Date: ${new Date().toLocaleString()}\n`;
        text += '-------------------\n\n';
        
        text += `Policy Action: ${this.result.policy || 'none'}\n`;
        if (this.result.adkim) text += `DKIM Alignment: ${this.result.adkim}\n`;
        if (this.result.aspf) text += `SPF Alignment: ${this.result.aspf}\n`;
        
        if (this.result.raw) {
          text += `\nRaw Record:\n${this.result.raw}\n`;
        }
        
        await this.copyToClipboard(text);
      }
    }
  };
