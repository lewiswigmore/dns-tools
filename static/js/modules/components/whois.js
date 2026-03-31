import { addHistory, exportJSON } from '../utils.js';
import { queryTarget, preloadBootstrap } from '../rdap-client.js';
import { DNSClient } from '../dns-client.js';

export function WhoisPage() {
  return {
    domain: '',
    result: null,
    serverUrl: null,
    loading: false,
    resolvingNameservers: false,
    error: '',
    searchPerformed: false,
    showRaw: false,

    init() {
      // Pre-load IANA bootstrap data in the background
      preloadBootstrap();

      const params = new URLSearchParams(window.location.search);
      const domainParam = params.get('domain') || params.get('target') || params.get('ip');
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
        const { result, server, queryType } = await queryTarget(this.domain.trim().toLowerCase());
        this.result = result;
        this.serverUrl = server;

        // RDAP frequently omits nameserver glue addresses; enrich only for domain lookups.
        if (queryType === 'domain') {
          this.enrichNameserverIPs();
        }

        const duration = (Date.now() - startTime) / 1000;
        addHistory({
          query: this.domain,
          timestamp: Date.now(),
          domains: 1,
          duration,
          success: true,
          recordTypes: [queryType === 'ip' ? 'WHOIS-IP' : 'WHOIS'],
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

    async enrichNameserverIPs() {
      if (!this.result?.nameservers?.length) return;

      const needsFallback = this.result.nameservers.some(ns =>
        (!Array.isArray(ns.ipv4) || ns.ipv4.length === 0) &&
        (!Array.isArray(ns.ipv6) || ns.ipv6.length === 0)
      );

      if (!needsFallback) return;

      this.resolvingNameservers = true;
      const dnsClient = new DNSClient();

      try {
        await Promise.all(this.result.nameservers.map(async ns => {
          const host = this.normaliseHost(ns?.ldhName);
          if (!host) return;

          const missingV4 = !Array.isArray(ns.ipv4) || ns.ipv4.length === 0;
          const missingV6 = !Array.isArray(ns.ipv6) || ns.ipv6.length === 0;
          if (!missingV4 && !missingV6) return;

          const [aRecords, aaaaRecords] = await Promise.all([
            missingV4 ? dnsClient.queryDNS(host, 'A') : Promise.resolve([]),
            missingV6 ? dnsClient.queryDNS(host, 'AAAA') : Promise.resolve([]),
          ]);

          if (missingV4) {
            ns.ipv4 = [...new Set((aRecords || [])
              .map(r => r?.value)
              .filter(v => typeof v === 'string' && this.isIPv4(v)))];
          }

          if (missingV6) {
            ns.ipv6 = [...new Set((aaaaRecords || [])
              .map(r => r?.value)
              .filter(v => typeof v === 'string' && this.isIPv6(v)))];
          }
        }));

        // Force reactive update after nested object mutations.
        this.result = { ...this.result, nameservers: [...this.result.nameservers] };
      } catch (err) {
        console.warn('Nameserver IP enrichment failed:', err);
      } finally {
        this.resolvingNameservers = false;
      }
    },

    normaliseHost(host) {
      if (!host || typeof host !== 'string') return '';
      return host.trim().replace(/\.+$/, '').toLowerCase();
    },

    isIPv4(value) {
      return /^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$/.test(value);
    },

    isIPv6(value) {
      return value.includes(':');
    },

    isIpResult() {
      return this.result?.kind === 'ip';
    },

    isDomainResult() {
      return this.result?.kind !== 'ip';
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
      const label = r.kind === 'ip' ? (r.startAddress || this.domain) : r.ldhName;
      let text = `# WHOIS / RDAP for ${label}\n\n`;
      text += `**Date:** ${new Date().toLocaleString()}\n\n`;
      if (r.kind === 'ip') {
        if (r.networkName) text += `**Network:** ${r.networkName}\n`;
        if (r.networkType) text += `**Type:** ${r.networkType}\n`;
        if (r.ipVersion) text += `**IP Version:** ${r.ipVersion}\n`;
        if (r.startAddress) text += `**Start Address:** ${r.startAddress}\n`;
        if (r.endAddress) text += `**End Address:** ${r.endAddress}\n`;
        if (r.cidrBlocks?.length) text += `**CIDR:** ${r.cidrBlocks.join(', ')}\n`;
        if (r.country) text += `**Country:** ${r.country}\n`;
      }
      if (r.handle) text += `**Domain ID:** ${r.handle}\n`;
      if (r.registrar) text += `**Registrar:** ${r.registrar.name}\n`;
      if (r.registrar?.handle) text += `**Registrar ID:** ${r.registrar.handle}\n`;
      if (r.keyDates?.registration) text += `**Registered:** ${this.formatDate(r.keyDates.registration)}\n`;
      if (r.keyDates?.expiration) text += `**Expires:** ${this.formatDate(r.keyDates.expiration)}\n`;
      if (r.keyDates?.lastChanged) text += `**Updated:** ${this.formatDate(r.keyDates.lastChanged)}\n`;
      if (r.keyDates?.lastRdapUpdate) text += `**RDAP DB Updated:** ${this.formatDate(r.keyDates.lastRdapUpdate)}\n`;
      if (r.keyDates?.transfer) text += `**Transferred:** ${this.formatDate(r.keyDates.transfer)}\n`;
      text += `**Status:** ${r.status.join(', ')}\n`;
      if (r.nameservers.length) {
        text += `\n**Nameservers:**\n`;
        r.nameservers.forEach(ns => { text += `- ${ns.ldhName}\n`; });
      }
      if (r.secureDNS) text += `\n**DNSSEC:** ${r.secureDNS.delegationSigned ? 'Signed' : 'Unsigned'}\n`;
      if (r.rdapConformance?.length) {
        text += `\n**RDAP Profiles:** ${r.rdapConformance.join(', ')}\n`;
      }
      await this.copyToClipboard(text);
    },
  };
}
