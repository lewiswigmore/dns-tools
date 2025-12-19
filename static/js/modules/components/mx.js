import { addHistory, exportJSON } from '../utils.js';

export function MXPage() {
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
      },

      async copyToClipboard(text) {
        try {
          await navigator.clipboard.writeText(text);
        } catch (err) {
          console.error('Failed to copy:', err);
        }
      },

      exportResults() {
        if (this.results && this.results.length > 0) {
          exportJSON(this.results);
        }
      },

      async copyAllResults() {
        if (!this.results || this.results.length === 0) return;
        
        let text = `MX Records for ${this.domain}\n`;
        text += `Date: ${new Date().toLocaleString()}\n`;
        text += '-------------------\n\n';
        
        this.results.forEach(r => {
          text += `Priority: ${r.priority}\n`;
          text += `Mail Server: ${r.exchange}\n`;
          text += '\n';
        });
        
        await this.copyToClipboard(text);
      }
    };
  };
