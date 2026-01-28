import { safeStorage, addHistory } from '../utils.js';
import { KNOWLEDGE_BASE } from '../data/index.js';

export function IntelPage() {
    return {
        query: '',
        results: null,
        loading: false,
        error: null,
        
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
        popstateHandler: null,

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
                    this.showConcept(concept, true);
                }
            }

            // Handle browser back/forward navigation
            this.popstateHandler = () => {
                const params = new URLSearchParams(window.location.search);
                const conceptParam = params.get('concept');
                
                if (conceptParam) {
                    const concept = this.concepts.find(c => c.id === conceptParam);
                    if (concept) {
                        this.showConcept(concept, true);
                    }
                } else if (this.conceptModal) {
                    this.closeConcept(true);
                }
            };
            window.addEventListener('popstate', this.popstateHandler);
        },

        destroy() {
            // Cleanup event listener
            if (this.popstateHandler) {
                window.removeEventListener('popstate', this.popstateHandler);
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

        showConcept(concept, skipHistoryUpdate = false) {
            // Handle string input (legacy or direct call) or object
            const conceptObj = typeof concept === 'string' 
                ? this.concepts.find(c => c.title === concept || c.id === concept) 
                : concept;

            if (!conceptObj) return;

            this.currentConcept = conceptObj.title;
            this.conceptModal = true;
            this.loadConcept(conceptObj);
            
            // Update URL with concept query parameter (unless called from popstate handler)
            if (!skipHistoryUpdate) {
                const url = new URL(window.location);
                url.searchParams.set('concept', conceptObj.id);
                window.history.pushState({}, '', url);
            }
        },
        
        closeConcept(skipHistoryUpdate = false) {
            this.conceptModal = false;
            this.conceptContent = '';
            this.conceptError = '';
            this.currentConcept = '';
            
            // Remove concept query parameter from URL (unless called from popstate handler)
            if (!skipHistoryUpdate) {
                const url = new URL(window.location);
                url.searchParams.delete('concept');
                window.history.pushState({}, '', url);
            }
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

