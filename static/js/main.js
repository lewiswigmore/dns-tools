import { DNSClient } from './modules/dns-client.js';
import { loadSettings, saveSettings } from './modules/utils.js';
import { LookupPage } from './modules/components/lookup.js';
import { MXPage } from './modules/components/mx.js';
import { DMARCPage } from './modules/components/dmarc.js';
import { HeadersPage } from './modules/components/headers.js';
import { HistoryPage } from './modules/components/history.js';
import { DashboardPage } from './modules/components/dashboard.js';
import { ResourcesPage } from './modules/components/resources.js';
import { IntelPage } from './modules/components/intel.js';
import { CommandPalette } from './modules/components/command-palette.js';

// Initialize DNS Client
window.dnsClient = new DNSClient();

// Register Components
window.LookupPage = LookupPage;
window.MXPage = MXPage;
window.DMARCPage = DMARCPage;
window.HeadersPage = HeadersPage;
window.HistoryPage = HistoryPage;
window.DashboardPage = DashboardPage;
window.ResourcesPage = ResourcesPage;
window.IntelPage = IntelPage;
window.CommandPalette = CommandPalette;

// Register with Alpine if it's already loaded, otherwise wait for alpine:init
const registerComponents = () => {
    if (window.Alpine) {
        // Register Settings Store
        window.Alpine.store('settings', {
            open: false,
            config: loadSettings(),
            toggle() { this.open = !this.open; },
            close() { this.open = false; },
            updateProvider(provider, enabled) {
                const current = new Set(this.config.providers);
                if (enabled) current.add(provider);
                else current.delete(provider);
                
                // Ensure at least one provider is selected
                if (current.size === 0) {
                    alert('At least one provider must be enabled.');
                    return;
                }
                
                this.config.providers = Array.from(current);
                
                // If primary provider is disabled, switch to the first available one
                if (!current.has(this.config.primaryProvider)) {
                    this.config.primaryProvider = this.config.providers[0];
                }
                
                this.save();
            },
            setPrimary(provider) {
                if (this.config.providers.includes(provider)) {
                    this.config.primaryProvider = provider;
                    this.save();
                }
            },
            save() {
                saveSettings(this.config);
                // Notify DNS Client of changes
                if (window.dnsClient) window.dnsClient.updateSettings(this.config);
                // Refresh dashboard if active
                if (window.dashboardInstance) window.dashboardInstance.refreshStats();
            }
        });

        window.Alpine.data('LookupPage', LookupPage);
        window.Alpine.data('MXPage', MXPage);
        window.Alpine.data('DMARCPage', DMARCPage);
        window.Alpine.data('HeadersPage', HeadersPage);
        window.Alpine.data('HistoryPage', HistoryPage);
        window.Alpine.data('DashboardPage', DashboardPage);
        window.Alpine.data('ResourcesPage', ResourcesPage);
        window.Alpine.data('IntelPage', IntelPage);
        window.Alpine.data('CommandPalette', CommandPalette);
    }
};

if (window.Alpine) {
    registerComponents();
} else {
    document.addEventListener('alpine:init', registerComponents);
}

console.log('DNS Tools modules loaded');

// Global Keyboard Shortcuts
window.addEventListener('keydown', (e) => {
    // Focus search input on '/' key
    if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
        e.preventDefault();
        const mainInput = document.querySelector('textarea, input[type="text"]');
        if (mainInput) mainInput.focus();
    }
});
