import { KNOWLEDGE_BASE } from '../data/index.js';

export function CommandPalette() {
    return {
        open: false,
        query: '',
        selectedIndex: 0,
        items: [],
        allActions: [],
        inactivityTimer: null,

        init() {
            // Define static navigation actions
            const navActions = [
                { id: 'nav-dash', title: 'Go to Dashboard', type: 'Navigation', icon: 'fa-chart-pie', url: '/' },
                { id: 'nav-dns', title: 'DNS Lookup', type: 'Tool', icon: 'fa-search', url: '/lookup' },
                { id: 'nav-mx', title: 'MX Lookup', type: 'Tool', icon: 'fa-envelope', url: '/mx' },
                { id: 'nav-dmarc', title: 'DMARC Lookup', type: 'Tool', icon: 'fa-shield-alt', url: '/dmarc' },
                { id: 'nav-headers', title: 'Email Headers Analysis', type: 'Tool', icon: 'fa-file-alt', url: '/headers' },
                { id: 'nav-intel', title: 'Threat Intelligence', type: 'Tool', icon: 'fa-shield-virus', url: '/intel' },
                { id: 'nav-history', title: 'History', type: 'Page', icon: 'fa-history', url: '/history' },
                { id: 'nav-resources', title: 'Resources', type: 'Page', icon: 'fa-book', url: '/resources' },
            ];

            // Define DNS Concepts
            const dnsConcepts = [
                'A Record', 'AAAA Record', 'CNAME Record', 'MX Record', 
                'TXT Record', 'NS Record', 'PTR Record', 'SRV Record', 
                'CAA Record', 'SPF', 'DKIM', 'DMARC'
            ].map(c => ({
                id: `dns-${c}`,
                title: c,
                type: 'DNS Concept',
                icon: 'fa-book',
                url: `/resources?concept=${encodeURIComponent(c)}`
            }));

            // Define Intel Concepts
            const intelConcepts = KNOWLEDGE_BASE.map(k => ({
                id: `intel-${k.id}`,
                title: k.title,
                type: 'Security Concept',
                icon: 'fa-user-shield',
                url: `/intel?concept=${k.id}`
            }));

            this.allActions = [...navActions, ...dnsConcepts, ...intelConcepts];
            
            // Listen for keyboard shortcuts
            window.addEventListener('keydown', (e) => {
                if ((e.ctrlKey || e.metaKey) && e.key === 'k' && !e.repeat) {
                    e.preventDefault();
                    this.toggle();
                }
                if (e.key === 'Escape' && this.open) {
                    this.close();
                }
                if (this.open) this.resetTimer();
            });

            // Listen for mouse movement
            window.addEventListener('mousemove', () => {
                if (this.open) this.resetTimer();
            });

            // Listen for custom open event
            window.addEventListener('open-command-palette', () => {
                this.open = true;
                this.query = '';
                this.filterItems();
                this.resetTimer();
                this.$nextTick(() => {
                    document.getElementById('cmd-palette-input').focus();
                });
            });
        },

        toggle() {
            this.open = !this.open;
            if (this.open) {
                this.query = '';
                this.filterItems();
                this.resetTimer();
                this.$nextTick(() => {
                    document.getElementById('cmd-palette-input').focus();
                });
            } else {
                this.clearTimer();
            }
        },

        close() {
            this.open = false;
            this.selectedIndex = 0;
            this.clearTimer();
        },

        resetTimer() {
            this.clearTimer();
            // Auto-close after 15 seconds of inactivity
            this.inactivityTimer = setTimeout(() => {
                this.close();
            }, 15000);
        },

        clearTimer() {
            if (this.inactivityTimer) {
                clearTimeout(this.inactivityTimer);
                this.inactivityTimer = null;
            }
        },

        filterItems() {
            if (!this.query) {
                // Show top actions by default (Navigation)
                this.items = this.allActions.slice(0, 8);
            } else {
                const q = this.query.toLowerCase();
                this.items = this.allActions.filter(item => 
                    item.title.toLowerCase().includes(q) || 
                    item.type.toLowerCase().includes(q)
                ).slice(0, 10); // Limit results
            }
            this.selectedIndex = 0;
        },

        selectNext() {
            if (this.selectedIndex < this.items.length - 1) {
                this.selectedIndex++;
                this.scrollToSelected();
            }
        },

        selectPrev() {
            if (this.selectedIndex > 0) {
                this.selectedIndex--;
                this.scrollToSelected();
            }
        },

        scrollToSelected() {
            this.$nextTick(() => {
                const el = document.getElementById(`cmd-item-${this.selectedIndex}`);
                if (el) el.scrollIntoView({ block: 'nearest' });
            });
        },

        executeSelected() {
            if (this.items[this.selectedIndex]) {
                this.execute(this.items[this.selectedIndex]);
            }
        },

        execute(item) {
            window.location.href = item.url;
            this.close();
        }
    };
}
