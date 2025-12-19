import { presetDomains, presetRecordTypes, addHistory, exportJSON, autoGrow } from '../utils.js';

export function LookupPage() {
    return {
      domains: presetDomains(),
      availableRecordTypes:['A','AAAA','CNAME','TXT','NS'],
      selectedRecordTypes:['A'],
      results:[],
      comparisonResults: [],
      compareMode: false,
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
        this.results = [];
        this.comparisonResults = [];
        
        try {
          const startTime = Date.now();
          
          if (this.compareMode) {
            const response = await window.dnsClient.performComparison(this.domains, this.selectedRecordTypes);
            this.comparisonResults = response.results || [];
          } else {
            const response = await window.dnsClient.performLookup(this.domains, this.selectedRecordTypes);
            this.results = response.results || [];
          }
          
          const duration = (Date.now() - startTime) / 1000;
          
          // Add to history (simplified for comparison mode)
          addHistory({
            query: this.domains,
            timestamp: Date.now(),
            domains: this.compareMode ? this.comparisonResults.length : this.results.length,
            duration: duration,
            success: true,
            recordTypes: this.selectedRecordTypes,
            results: this.compareMode ? this.comparisonResults : this.results,
            mode: this.compareMode ? 'comparison' : 'standard'
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
      exportResults(){ exportJSON(this.compareMode ? this.comparisonResults : this.results); },
      
      async copyToClipboard(text) {
        try {
          await navigator.clipboard.writeText(text);
          // Optional: Show a toast or tooltip feedback here
        } catch (err) {
          console.error('Failed to copy:', err);
        }
      },

      async copyAllResults() {
        const data = this.compareMode ? this.comparisonResults : this.results;
        if (!data || data.length === 0) return;
        
        let text = '# DNS Lookup Results\n\n';
        text += `**Date:** ${new Date().toLocaleString()}\n`;
        text += `**Mode:** ${this.compareMode ? 'Provider Comparison' : 'Standard Lookup'}\n\n`;
        
        if (this.compareMode) {
          data.forEach(row => {
            text += `## ${row.domain}\n\n`;
            this.selectedRecordTypes.forEach(type => {
              if (row.comparisons[type]) {
                text += `### ${type} Records\n\n`;
                text += `| Provider | Status | Latency | Records |\n`;
                text += `|----------|--------|---------|---------|\n`;
                
                ['Google', 'Cloudflare'].forEach(provider => {
                  const res = row.comparisons[type][provider];
                  if (res) {
                    const records = res.records.map(r => r.value).join(', ') || 'No records';
                    text += `| ${provider} | ${res.status === 'success' ? '✅' : '❌'} | ${res.latency}ms | \`${records}\` |\n`;
                  }
                });
                text += '\n';
              }
            });
          });
        } else {
          data.forEach(row => {
            text += `## ${row.domain}\n\n`;
            text += `**Status:** ${row.status === 'success' ? '✅ Success' : '❌ Error'}\n\n`;
            
            this.selectedRecordTypes.forEach(type => {
              if (row.records && row.records[type] && row.records[type].length > 0) {
                text += `### ${type} Records\n`;
                text += `| Value | TTL |\n`;
                text += `|-------|-----|\n`;
                row.records[type].forEach(rec => {
                  text += `| \`${rec.value}\` | ${rec.ttl} |\n`;
                });
                text += '\n';
              }
            });
            
            if (row.errors && row.errors.length > 0) {
              text += `**Errors:**\n${row.errors.map(e => `- ${e}`).join('\n')}\n\n`;
            }
          });
        }
        
        await this.copyToClipboard(text);
      }
    };
  };
