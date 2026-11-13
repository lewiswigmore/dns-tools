import { DNSClient } from './modules/dns-client.js';
import { loadSettings, saveSettings } from './modules/utils.js';
import { CommandPalette } from './modules/components/command-palette.js';

const pageComponentLoaders = {
    dashboard: () => import('./modules/components/dashboard.js').then(module => ['DashboardPage', module.DashboardPage]),
    lookup: () => import('./modules/components/lookup.js').then(module => ['LookupPage', module.LookupPage]),
    mx: () => import('./modules/components/mx.js').then(module => ['MXPage', module.MXPage]),
    dmarc: () => import('./modules/components/dmarc.js').then(module => ['DMARCPage', module.DMARCPage]),
    headers: () => import('./modules/components/headers.js').then(module => ['HeadersPage', module.HeadersPage]),
    history: () => import('./modules/components/history.js').then(module => ['HistoryPage', module.HistoryPage]),
    resources: () => import('./modules/components/resources.js').then(module => ['ResourcesPage', module.ResourcesPage]),
    intel: () => import('./modules/components/intel.js').then(module => ['IntelPage', module.IntelPage]),
    whois: () => import('./modules/components/whois.js').then(module => ['WhoisPage', module.WhoisPage])
};

const activePageComponent = await pageComponentLoaders[document.body.dataset.page]?.();

// Initialize DNS Client
window.dnsClient = new DNSClient();

const registerComponents = () => {
    const Alpine = window.Alpine;
    Alpine.store('settings', {
        open: false,
        config: loadSettings(),
        toggle() { this.open = !this.open; },
        close() { this.open = false; },
        updateProvider(provider, enabled) {
            const current = new Set(this.config.providers);
            if (enabled) current.add(provider);
            else current.delete(provider);

            if (current.size === 0) {
                alert('At least one provider must be enabled.');
                return;
            }

            this.config.providers = Array.from(current);
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
            if (window.dnsClient) window.dnsClient.updateSettings(this.config);
            if (window.dashboardInstance) window.dashboardInstance.refreshStats();
        }
    });

    if (activePageComponent) {
        const [name, component] = activePageComponent;
        window[name] = component;
        Alpine.data(name, component);
    }

    window.CommandPalette = CommandPalette;
    Alpine.data('CommandPalette', CommandPalette);
};

document.addEventListener('alpine:init', registerComponents, { once: true });

const alpineScript = document.createElement('script');
alpineScript.src = 'https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js';
alpineScript.defer = true;
alpineScript.onerror = () => console.error('Failed to load Alpine.js');
document.head.append(alpineScript);

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
