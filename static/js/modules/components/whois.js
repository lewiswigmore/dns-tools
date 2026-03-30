import { addHistory, exportJSON } from '../utils.js';
import { queryDomain, preloadBootstrap } from '../rdap-client.js';

export function WhoisPage() {
  return {
    domain: '',
    result: null,
    serverUrl: null,
    loading: false,
    error: '',
    searchPerformed: false,
    showRaw: false,

    init() {
      // Pre-load IANA bootstrap data in the background
      preloadBootstrap();

      const params = new URLSearchParams(window.location.search);
      const domainParam = params.get('domain');
      if (domainParam) {
        this.domain = domainParam;
        setTimeout(() => this.performLookup(), 100);
      }
    },

    async performLookup() {
      if (this.loading || !this.domain.trim()) return;

      this.loading = true;
      this.error = '';
      this.result = null;
      this.serverUrl = null;
      this.searchPerformed = true;
      this.showRaw = false;

      const startTime = Date.now();
      try {
        const { result, server } = await queryDomain(this.domain.trim().toLowerCase());
        this.result = result;
        this.serverUrl = server;

        const duration = (Date.now() - startTime) / 1000;
        addHistory({
          query: this.domain,
          timestamp: Date.now(),
          domains: 1,
          duration,
          success: true,
          recordTypes: ['WHOIS'],
          results: [{ domain: this.domain, registrar: result.registrar?.name }],
        });
      } catch (err) {
        console.error('WHOIS/RDAP lookup failed:', err);
        this.error = err.message;

        addHistory({
          query: this.domain,
          timestamp: Date.now(),
          domains: 1,
          duration: (Date.now() - startTime) / 1000,
          success: false,
          recordTypes: ['WHOIS'],
        });
      } finally {
        this.loading = false;
        if (window.dashboardInstance) window.dashboardInstance.refreshStats();
      }
    },

    /** Format an ISO date string for display. */
    formatDate(iso) {
      if (!iso) return '—';
      try {
        return new Date(iso).toLocaleDateString(undefined, {
          year: 'numeric', month: 'short', day: 'numeric',
        });
      } catch { return iso; }
    },

    /** Human-readable EPP status label. */
    statusLabel(code) {
      return code.replace(/([A-Z])/g, ' $1').trim();
    },

    /** Colour pill class for EPP status codes. */
    statusClass(code) {
      if (code.includes('prohibited')) return 'pill-orange';
      if (code === 'active' || code === 'ok') return 'pill-green';
      if (code.includes('hold') || code.includes('inactive')) return 'pill-red';
      return 'pill-blue';
    },

    async copyToClipboard(text) {
      try { await navigator.clipboard.writeText(text); } catch (e) { console.error('Copy failed:', e); }
    },

    exportResults() {
      if (this.result) exportJSON(this.result.raw, `whois_${this.domain}.json`);
    },

    async copyAllResults() {
      if (!this.result) return;
      const r = this.result;
      let text = `# WHOIS / RDAP for ${r.ldhName}\n\n`;
      text += `**Date:** ${new Date().toLocaleString()}\n\n`;
      if (r.registrar) text += `**Registrar:** ${r.registrar.name}\n`;
      if (r.events.registration) text += `**Registered:** ${this.formatDate(r.events.registration.date)}\n`;
      if (r.events.expiration) text += `**Expires:** ${this.formatDate(r.events.expiration.date)}\n`;
      if (r.events['last changed']) text += `**Updated:** ${this.formatDate(r.events['last changed'].date)}\n`;
      text += `**Status:** ${r.status.join(', ')}\n`;
      if (r.nameservers.length) {
        text += `\n**Nameservers:**\n`;
        r.nameservers.forEach(ns => { text += `- ${ns.ldhName}\n`; });
      }
      if (r.secureDNS) text += `\n**DNSSEC:** ${r.secureDNS.delegationSigned ? 'Signed' : 'Unsigned'}\n`;
      await this.copyToClipboard(text);
    },
  };
}
