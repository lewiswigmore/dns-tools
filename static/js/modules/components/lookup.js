import { presetDomains, presetRecordTypes, addHistory, exportJSON, autoGrow } from '../utils.js';

export function LookupPage() {
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
      exportResults(){ exportJSON(this.results); },
      
      async copyToClipboard(text) {
        try {
          await navigator.clipboard.writeText(text);
          // Optional: Show a toast or tooltip feedback here
        } catch (err) {
          console.error('Failed to copy:', err);
        }
      },

      async copyAllResults() {
        if (!this.results || this.results.length === 0) return;
        
        // Format results as readable text
        let text = '';
        this.results.forEach(row => {
          text += `Domain: ${row.domain}\n`;
          text += `Status: ${row.status}\n`;
          
          this.selectedRecordTypes.forEach(type => {
            if (row.records && row.records[type] && row.records[type].length > 0) {
              text += `${type} Records:\n`;
              row.records[type].forEach(rec => {
                text += `  - ${rec.value} (TTL: ${rec.ttl})\n`;
              });
            }
          });
          
          if (row.errors && row.errors.length > 0) {
            text += `Errors: ${row.errors.join(', ')}\n`;
          }
          text += '\n-------------------\n\n';
        });
        
        await this.copyToClipboard(text);
      }
    };
  };
