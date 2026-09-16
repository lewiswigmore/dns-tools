import { safeStorage, addHistory } from '../utils.js';
import { KNOWLEDGE_BASE } from '../data/index.js';
import { queryDomain } from '../rdap-client.js';
import { DNSClient } from '../dns-client.js';

// Registry status codes that suggest an unstable or non-functioning domain.
const RISKY_RDAP_STATUSES = ['pendingdelete', 'redemptionperiod', 'clienthold', 'serverhold'];

export function IntelPage() {
    return {
        query: '',
        presets: [
            { label: 'Domain', value: 'google.com' },
            { label: 'IPv4', value: '8.8.8.8' },
            { label: 'SHA256 hash', value: '44d88612fea8a8f36de82e1278abb02f4e6f0af93bb43f1d3a7a6d0f5d3f5f4f' }
        ],
        results: null,
        loading: false,
        error: null,

        // Fraud Risk Indicators State
        fraud: {
            loading: false,
            error: null,
            data: null
        },

        // Knowledge Base State
        concepts: KNOWLEDGE_BASE,
        conceptSearch: '',
        conceptFilter: 'Threat Intel',
        
        // Modal State
        conceptModal: false,
        currentConcept: null,
        conceptContent: '',
        loadingConcept: false,
        conceptError: '',

        init() {
            // Check for query param
            const params = new URLSearchParams(window.location.search);
            const q = params.get('q');
            const conceptId = params.get('concept');
            
            if (q) {
                this.query = q;
                this.analyze();
            }
            
            if (conceptId) {
                const concept = this.concepts.find(c => c.id === conceptId);
                if (concept) {
                    this.showConcept(concept);
                }
            }
        },
        
        get filteredConcepts() {
            return this.concepts.filter(c => {
                const matchesSearch = c.title.toLowerCase().includes(this.conceptSearch.toLowerCase()) || 
                                      c.summary.toLowerCase().includes(this.conceptSearch.toLowerCase());
                
                // If user is searching, search the entire knowledge base
                if (this.conceptSearch) {
                    return matchesSearch;
                }

                // Default view: Show only Security/Intel related topics
                // This makes the TI Knowledge Base a "filtered version" of the global one
                if (this.conceptFilter === 'All') {
                     return c.tags.some(t => ['Threat Intel', 'Malware'].includes(t));
                } else {
                    // User selected a specific tag (e.g., "DNS")
                    return c.tags.includes(this.conceptFilter);
                }
            });
        },
        
        get allTags() {
            const tags = new Set(['All']);
            this.concepts.forEach(c => c.tags.forEach(t => tags.add(t)));
            return Array.from(tags);
        },

        // --- Investigation Logic ---

        async analyze() {
            if (!this.query.trim()) return;
            
            this.loading = true;
            this.error = null;
            this.results = null;

            const target = this.query.trim();
            const isIP = this.isValidIP(target);
            const isDomain = this.isValidDomain(target);
            const isHash = this.isValidHash(target);

            if (!isIP && !isDomain && !isHash) {
                this.error = "Invalid input. Please enter a valid Domain, IP address, or File Hash (MD5/SHA1/SHA256).";
                this.loading = false;
                return;
            }

            // Generate Deep Links
            const links = this.generateLinks(target, isIP, isDomain, isHash);
            
            this.results = {
                target: target,
                type: isIP ? 'IP Address' : (isHash ? 'File Hash' : 'Domain'),
                links: links
            };

            // Add to History
            addHistory({
                query: target,
                recordTypes: ['INTEL'],
                timestamp: Date.now(),
                success: true,
                duration: 0, // Instant
                results: this.results
            });

            this.loading = false;
        },

        applyPreset(value) {
            this.query = value;
        },

        // --- Fraud Risk Indicators ---

        async runFraudCheck() {
            if (!this.results || this.results.type !== 'Domain') return;

            const domain = this.results.target.trim().toLowerCase().replace(/\.+$/, '');

            this.fraud.loading = true;
            this.fraud.error = null;
            this.fraud.data = null;

            try {
                const dnsClient = new DNSClient();

                const [rdapResult, aRecords, aaaaRecords, mxRecords, nsRecords, txtRecords, dmarcRecords] = await Promise.all([
                    queryDomain(domain).then(r => r.result).catch(() => null),
                    dnsClient.queryDNS(domain, 'A'),
                    dnsClient.queryDNS(domain, 'AAAA'),
                    dnsClient.queryDNS(domain, 'MX'),
                    dnsClient.queryDNS(domain, 'NS'),
                    dnsClient.queryDNS(domain, 'TXT'),
                    dnsClient.queryDNS(`_dmarc.${domain}`, 'TXT')
                ]);

                const indicators = buildFraudIndicators({
                    domain,
                    rdap: rdapResult,
                    a: aRecords,
                    aaaa: aaaaRecords,
                    mx: mxRecords,
                    ns: nsRecords,
                    txt: txtRecords,
                    dmarcTxt: dmarcRecords
                });

                this.fraud.data = {
                    indicators,
                    riskLevel: computeRiskLevel(indicators),
                    checkedAt: Date.now()
                };
            } catch (error) {
                this.fraud.error = 'Fraud risk check failed. Please try again.';
            } finally {
                this.fraud.loading = false;
            }
        },

        riskLabel(level) {
            switch (level) {
                case 'high': return 'High Risk Signals Detected';
                case 'medium': return 'Some Risk Signals Detected';
                case 'low': return 'Minor Signals Detected';
                default: return 'No Strong Risk Signals Detected';
            }
        },

        riskIcon(level) {
            switch (level) {
                case 'high': return 'fa-triangle-exclamation';
                case 'medium': return 'fa-circle-exclamation';
                case 'low': return 'fa-circle-info';
                default: return 'fa-circle-check';
            }
        },

        riskBannerClass(level) {
            switch (level) {
                case 'high': return 'border border-[#f85149]/40 text-[#f85149]';
                case 'medium': return 'border border-[#d29922]/40 text-[#d29922]';
                case 'low': return 'border border-[#58a6ff]/40 text-[#58a6ff]';
                default: return 'border border-[#3fb950]/40 text-[#3fb950]';
            }
        },

        severityPillClass(severity) {
            switch (severity) {
                case 'high': return 'pill-red';
                case 'medium': return 'pill-orange';
                case 'low': return 'pill-blue';
                default: return 'pill-green';
            }
        },

        generateLinks(target, isIP, isDomain, isHash) {
            const links = [];

            if (isIP) {
                links.push({ name: 'VirusTotal', url: `https://www.virustotal.com/gui/ip-address/${target}`, icon: 'fas fa-shield-virus', color: 'text-blue-500' });
                links.push({ name: 'AbuseIPDB', url: `https://www.abuseipdb.com/check/${target}`, icon: 'fas fa-ban', color: 'text-red-500' });
                links.push({ name: 'Talos Intelligence', url: `https://talosintelligence.com/reputation_center/lookup?search=${target}`, icon: 'fas fa-crosshairs', color: 'text-green-500' });
                links.push({ name: 'GreyNoise', url: `https://viz.greynoise.io/ip/${target}`, icon: 'fas fa-wave-square', color: 'text-gray-400' });
                links.push({ name: 'Shodan', url: `https://www.shodan.io/search?query=${target}`, icon: 'fas fa-search', color: 'text-red-600' });
                links.push({ name: 'Censys', url: `https://search.censys.io/hosts/${target}`, icon: 'fas fa-database', color: 'text-orange-500' });
                links.push({ name: 'Hybrid Analysis', url: `https://www.hybrid-analysis.com/search?query=${target}`, icon: 'fas fa-microscope', color: 'text-orange-400' });
                links.push({ name: 'Any.Run', url: `https://app.any.run/submissions/#search=${target}`, icon: 'fas fa-play-circle', color: 'text-red-500' });
            } else if (isDomain) {
                links.push({ name: 'VirusTotal', url: `https://www.virustotal.com/gui/domain/${target}`, icon: 'fas fa-shield-virus', color: 'text-blue-500' });
                links.push({ name: 'Urlscan.io', url: `https://urlscan.io/domain/${target}`, icon: 'fas fa-camera', color: 'text-green-500' });
                links.push({ name: 'Talos Intelligence', url: `https://talosintelligence.com/reputation_center/lookup?search=${target}`, icon: 'fas fa-crosshairs', color: 'text-green-500' });
                links.push({ name: 'Google Transparency', url: `https://transparencyreport.google.com/safe-browsing/search?url=${target}`, icon: 'fab fa-google', color: 'text-blue-400' });
                links.push({ name: 'AlienVault OTX', url: `https://otx.alienvault.com/indicator/domain/${target}`, icon: 'fas fa-rocket', color: 'text-green-400' });
                links.push({ name: 'CRT.sh', url: `https://crt.sh/?q=${target}`, icon: 'fas fa-certificate', color: 'text-purple-500' });
                links.push({ name: 'Hybrid Analysis', url: `https://www.hybrid-analysis.com/search?query=${target}`, icon: 'fas fa-microscope', color: 'text-orange-400' });
                links.push({ name: 'Joe Sandbox', url: `https://www.joesandbox.com/search?q=${target}`, icon: 'fas fa-box-open', color: 'text-yellow-500' });
                links.push({ name: 'Any.Run', url: `https://app.any.run/submissions/#search=${target}`, icon: 'fas fa-play-circle', color: 'text-red-500' });
                links.push({ name: 'Triage', url: `https://tria.ge/s?q=${target}`, icon: 'fas fa-bug', color: 'text-yellow-400' });
            } else if (isHash) {
                links.push({ name: 'VirusTotal', url: `https://www.virustotal.com/gui/file/${target}`, icon: 'fas fa-shield-virus', color: 'text-blue-500' });
                links.push({ name: 'Hybrid Analysis', url: `https://www.hybrid-analysis.com/search?query=${target}`, icon: 'fas fa-microscope', color: 'text-orange-400' });
                links.push({ name: 'Joe Sandbox', url: `https://www.joesandbox.com/search?q=${target}`, icon: 'fas fa-box-open', color: 'text-yellow-500' });
                links.push({ name: 'AlienVault OTX', url: `https://otx.alienvault.com/indicator/file/${target}`, icon: 'fas fa-rocket', color: 'text-green-400' });
                links.push({ name: 'Any.Run', url: `https://app.any.run/submissions/#search=${target}`, icon: 'fas fa-play-circle', color: 'text-red-500' });
                links.push({ name: 'Triage', url: `https://tria.ge/s?q=${target}`, icon: 'fas fa-bug', color: 'text-yellow-400' });
            }

            return links;
        },

        isValidIP(str) {
            const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
            return ipRegex.test(str);
        },

        isValidDomain(str) {
            const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
            return domainRegex.test(str);
        },

        isValidHash(str) {
            const md5 = /^[a-f0-9]{32}$/i;
            const sha1 = /^[a-f0-9]{40}$/i;
            const sha256 = /^[a-f0-9]{64}$/i;
            return md5.test(str) || sha1.test(str) || sha256.test(str);
        },

        // --- Knowledge Base Logic ---

        showConcept(concept) {
            // Handle string input (legacy or direct call) or object
            const conceptObj = typeof concept === 'string' 
                ? this.concepts.find(c => c.title === concept || c.id === concept) 
                : concept;

            if (!conceptObj) return;

            this.currentConcept = conceptObj.title;
            this.conceptModal = true;
            this.loadConcept(conceptObj);
        },
        
        closeConcept() {
            this.conceptModal = false;
            this.conceptContent = '';
            this.conceptError = '';
            this.currentConcept = '';
        },
        
        async loadConcept(conceptObj) {
            this.loadingConcept = true;
            this.conceptError = '';
            this.conceptContent = '';
            
            try {
                // Simulate network delay for "Deep Research" feel
                await new Promise(resolve => setTimeout(resolve, 400));
                this.conceptContent = conceptObj.content;
            } catch (error) {
                this.conceptError = 'Failed to load content.';
            } finally {
                this.loadingConcept = false;
            }
        }
    };
}

// --- Fraud Indicator Helpers (pure functions, no side effects) ---

function domainAgeDays(isoDateString) {
    if (!isoDateString) return null;
    const registered = new Date(isoDateString).getTime();
    if (Number.isNaN(registered)) return null;
    return Math.floor((Date.now() - registered) / (1000 * 60 * 60 * 24));
}

function hasPunycodeLabel(domain) {
    return domain.split('.').some(label => label.startsWith('xn--'));
}

function hasSuspiciousNamingPattern(domain) {
    const label = domain.split('.')[0] || '';
    const hyphenCount = (label.match(/-/g) || []).length;
    const digitCount = (label.match(/[0-9]/g) || []).length;
    return hyphenCount >= 3 || (label.length >= 6 && digitCount / label.length > 0.5);
}

function txtValuesInclude(records, needle) {
    return (records || []).some(r => (r.value || '').toLowerCase().includes(needle));
}

function buildFraudIndicators({ domain, rdap, a, aaaa, mx, ns, txt, dmarcTxt }) {
    const indicators = [];

    // 1. Domain age (from RDAP registration date)
    if (!rdap || !rdap.keyDates || !rdap.keyDates.registration) {
        indicators.push({
            severity: 'info',
            label: 'Registration date unavailable',
            detail: 'The registry did not return a registration date for this domain via RDAP.'
        });
    } else {
        const ageDays = domainAgeDays(rdap.keyDates.registration);
        if (ageDays !== null && ageDays < 30) {
            indicators.push({
                severity: 'high',
                label: 'Recently registered domain',
                detail: `Registered ${ageDays} day(s) ago. Newly created domains are frequently used in short-lived fraud campaigns.`
            });
        } else if (ageDays !== null && ageDays < 90) {
            indicators.push({
                severity: 'medium',
                label: 'Recently registered domain',
                detail: `Registered ${ageDays} day(s) ago. Domains under 90 days old carry a higher-than-average fraud rate.`
            });
        } else if (ageDays !== null) {
            indicators.push({
                severity: 'info',
                label: 'Established registration age',
                detail: `Registered approximately ${Math.floor(ageDays / 365)} year(s) ago.`
            });
        }
    }

    // 2. Registry status flags
    const statuses = (rdap && Array.isArray(rdap.status)) ? rdap.status.map(s => s.toLowerCase()) : [];
    const riskyStatus = statuses.find(s => RISKY_RDAP_STATUSES.some(flag => s.includes(flag)));
    if (riskyStatus) {
        indicators.push({
            severity: 'medium',
            label: 'Unstable registry status',
            detail: `Registry status includes "${riskyStatus}", the domain may be expiring, suspended, or on hold.`
        });
    }

    // 3. DNS presence
    const hasAny = (a && a.length) || (aaaa && aaaa.length);
    const hasNs = ns && ns.length;
    if (!hasAny && !hasNs) {
        indicators.push({
            severity: 'medium',
            label: 'No DNS records found',
            detail: 'The domain has no A, AAAA, or NS records, it may be unregistered, parked, or inactive.'
        });
    } else if (!hasAny && hasNs) {
        indicators.push({
            severity: 'low',
            label: 'No web-hosting records',
            detail: 'The domain resolves at the registry but has no A/AAAA records, so a website may not be live.'
        });
    }

    // 4. Mail authentication (only relevant when mail is configured)
    if (mx && mx.length) {
        const hasSpf = txtValuesInclude(txt, 'v=spf1');
        const hasDmarc = txtValuesInclude(dmarcTxt, 'v=dmarc1');
        if (!hasSpf && !hasDmarc) {
            indicators.push({
                severity: 'medium',
                label: 'Mail configured without authentication',
                detail: 'Mail servers (MX) are present but no SPF or DMARC records were found, so messages cannot be authenticated. This pattern is common in spoofing setups.'
            });
        } else if (!hasDmarc) {
            indicators.push({
                severity: 'low',
                label: 'No DMARC enforcement',
                detail: 'SPF is present but no DMARC record was found, so spoofed mail is not rejected or reported.'
            });
        } else {
            indicators.push({
                severity: 'info',
                label: 'Mail authentication present',
                detail: 'SPF and DMARC records were both found for this domain.'
            });
        }
    }

    // 5. Punycode / homograph indicator
    if (hasPunycodeLabel(domain)) {
        indicators.push({
            severity: 'high',
            label: 'Punycode-encoded label',
            detail: 'The domain contains an xn-- (punycode) label, a technique often used in look-alike domains that impersonate a legitimate brand.'
        });
    }

    // 6. Naming pattern
    if (hasSuspiciousNamingPattern(domain)) {
        indicators.push({
            severity: 'low',
            label: 'Unusual naming pattern',
            detail: 'The domain label contains an unusually high number of hyphens or digits, a pattern sometimes seen in disposable or typosquatted domains.'
        });
    }

    // 7. Registrant privacy (informational, not inherently suspicious)
    if (rdap && rdap.roles && !rdap.roles.registrant) {
        indicators.push({
            severity: 'info',
            label: 'Registrant details redacted',
            detail: 'Registrant information is private or redacted. This is common for legitimate domains and is not inherently suspicious.'
        });
    }

    return indicators;
}

function computeRiskLevel(indicators) {
    const severityRank = { high: 3, medium: 2, low: 1, info: 0 };
    let topSeverity = 'info';
    for (const indicator of indicators) {
        if (severityRank[indicator.severity] > severityRank[topSeverity]) {
            topSeverity = indicator.severity;
        }
    }
    return topSeverity === 'info' ? 'none' : topSeverity;
}

