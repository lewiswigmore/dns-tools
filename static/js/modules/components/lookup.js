import { presetDomains, presetRecordTypes, addHistory, exportJSON, autoGrow } from '../utils.js';
import { queryDomain } from '../rdap-client.js';
import { DNSClient } from '../dns-client.js';
import { buildFraudIndicators, computeRiskLevel, riskLabel, riskIcon, riskColorClass } from '../fraud-indicators.js';

export function LookupPage() {
    return {
      domains: presetDomains(),
      presets: [
        { label: 'google.com', value: 'google.com' },
        { label: 'cloudflare.com', value: 'cloudflare.com' },
        { label: 'openai.com + github.com', value: 'openai.com\ngithub.com' },
      ],
      availableRecordTypes:['A','AAAA','CNAME','TXT','NS'],
      selectedRecordTypes:['A'],
      results:[],
      comparisonResults: [],
      compareMode: false,
      maxInlineRecords: 8,
      maxCopyRecordsPerType: 50,
      expandedRecordSets: {},
      loading:false,
      autoGrow,
      // Fraud risk indicators are opt-in per row (or all at once) since each
      // check adds an RDAP lookup plus several DNS queries on top of the
      // main lookup, and bulk lists here can run into the hundreds.
      fraud: {},
      fraudCheckingAll: false,
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

        const params = new URLSearchParams(window.location.search);
        const compare = params.get('compare');
        if (compare === '1' || compare === 'true') {
          this.compareMode = true;
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
      applyPresetDomains(value){
        this.domains = value;
        if (this.autoGrow && this.$refs?.domainsBox) this.autoGrow(this.$refs.domainsBox);
      },
      async performLookup(){
        if(this.loading) return; 
        if(!this.domains.trim()||this.selectedRecordTypes.length===0) return;
        
        this.loading=true;
        this.results = [];
        this.comparisonResults = [];
        this.fraud = {};
        
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

      // --- Fraud Risk Indicators (per-row, on-demand) ---

      fraudKey(domain) {
        return (domain || '').trim().toLowerCase().replace(/\.+$/, '');
      },

      fraudState(domain) {
        return this.fraud[this.fraudKey(domain)] || null;
      },

      riskLabel, riskIcon, riskColorClass,

      async runFraudCheck(row) {
        const key = this.fraudKey(row.domain);
        if (!key) return;

        this.fraud = {
          ...this.fraud,
          [key]: { loading: true, error: null, data: this.fraud[key]?.data || null }
        };

        try {
          const dnsClient = new DNSClient();

          const [rdapResult, aRecords, aaaaRecords, mxRecords, nsRecords, txtRecords, dmarcRecords] = await Promise.all([
            queryDomain(key).then(r => r.result).catch(() => null),
            dnsClient.queryDNS(key, 'A'),
            dnsClient.queryDNS(key, 'AAAA'),
            dnsClient.queryDNS(key, 'MX'),
            dnsClient.queryDNS(key, 'NS'),
            dnsClient.queryDNS(key, 'TXT'),
            dnsClient.queryDNS(`_dmarc.${key}`, 'TXT')
          ]);

          const indicators = buildFraudIndicators({
            domain: key,
            rdap: rdapResult,
            a: aRecords,
            aaaa: aaaaRecords,
            mx: mxRecords,
            ns: nsRecords,
            txt: txtRecords,
            dmarcTxt: dmarcRecords
          });

          this.fraud = {
            ...this.fraud,
            [key]: {
              loading: false,
              error: null,
              data: { indicators, riskLevel: computeRiskLevel(indicators), checkedAt: Date.now() }
            }
          };
        } catch (error) {
          this.fraud = {
            ...this.fraud,
            [key]: { loading: false, error: 'Check failed. Please try again.', data: this.fraud[key]?.data || null }
          };
        }
      },

      async runFraudCheckAll() {
        if (this.fraudCheckingAll) return;
        this.fraudCheckingAll = true;

        try {
          const rows = this.compareMode ? [] : this.results.filter(r => r.status === 'success');
          for (const row of rows) {
            await this.runFraudCheck(row);
          }
        } finally {
          this.fraudCheckingAll = false;
        }
      },

      fraudTooltip(domain) {
        const state = this.fraudState(domain);
        if (!state?.data) return '';
        const { indicators } = state.data;
        if (!indicators.length) return 'No strong risk signals detected.';
        return indicators.map(i => `- ${i.label}`).join('\n');
      },

      getRecordSetKey(row, recordType) {
        return `${row.domain}::${recordType}`;
      },

      isRecordSetExpanded(row, recordType) {
        return !!this.expandedRecordSets[this.getRecordSetKey(row, recordType)];
      },

      toggleRecordSet(row, recordType) {
        const key = this.getRecordSetKey(row, recordType);
        this.expandedRecordSets = {
          ...this.expandedRecordSets,
          [key]: !this.expandedRecordSets[key],
        };
      },

      getVisibleRecords(row, recordType) {
        const records = row.records?.[recordType] || [];
        if (this.isRecordSetExpanded(row, recordType)) return records;
        return records.slice(0, this.maxInlineRecords);
      },

      hasHiddenRecords(row, recordType) {
        const records = row.records?.[recordType] || [];
        return records.length > this.maxInlineRecords && !this.isRecordSetExpanded(row, recordType);
      },

      getHiddenRecordCount(row, recordType) {
        const records = row.records?.[recordType] || [];
        return Math.max(0, records.length - this.maxInlineRecords);
      },

      formatRecordValue(value, maxLength = 220) {
        if (typeof value !== 'string') return value;
        if (value.length <= maxLength) return value;
        return `${value.slice(0, maxLength)}...`;
      },

      getLimitedRecords(records) {
        if (!Array.isArray(records)) return [];
        return records.slice(0, this.maxCopyRecordsPerType);
      },

      getShareUrl() {
        const url = new URL(window.location.href);
        url.searchParams.set('domains', this.domains.trim());
        url.searchParams.set('types', this.selectedRecordTypes.join(','));
        url.searchParams.set('compare', this.compareMode ? '1' : '0');

        const providers = (window?.Alpine?.store('settings')?.config?.providers || []).join(',');
        if (providers) {
          url.searchParams.set('providers', providers);
        }

        return url.toString();
      },

      async copyShareUrl() {
        const shareUrl = this.getShareUrl();
        await this.copyToClipboard(shareUrl);
      },
      
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
                
                // Get providers from the result itself to ensure we match what was returned
                const providers = Object.keys(row.comparisons[type]).sort();
                
                providers.forEach(provider => {
                  const res = row.comparisons[type][provider];
                  if (res) {
                    const limitedRecords = this.getLimitedRecords(res.records);
                    const records = limitedRecords.map(r => r.value).join(', ') || 'No records';
                    text += `| ${provider} | ${res.status === 'success' ? '✅' : '❌'} | ${res.latency}ms | \`${records}\` |\n`;
                    if (Array.isArray(res.records) && res.records.length > this.maxCopyRecordsPerType) {
                      text += `| ${provider} | ℹ️ | — | _Truncated ${res.records.length - this.maxCopyRecordsPerType} additional records in copy output_ |\n`;
                    }
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
                const limitedRecords = this.getLimitedRecords(row.records[type]);
                text += `### ${type} Records\n`;
                text += `| Value | TTL |\n`;
                text += `|-------|-----|\n`;
                limitedRecords.forEach(rec => {
                  text += `| \`${rec.value}\` | ${rec.ttl} |\n`;
                });
                if (row.records[type].length > this.maxCopyRecordsPerType) {
                  text += `\n_Truncated ${row.records[type].length - this.maxCopyRecordsPerType} additional ${type} records in copy output._\n`;
                }
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
