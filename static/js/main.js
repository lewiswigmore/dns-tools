import { DNSClient } from './modules/dns-client.js';
import { LookupPage } from './modules/components/lookup.js';
import { MXPage } from './modules/components/mx.js';
import { DMARCPage } from './modules/components/dmarc.js';
import { HeadersPage } from './modules/components/headers.js';
import { HistoryPage } from './modules/components/history.js';
import { DashboardPage } from './modules/components/dashboard.js';
import { ResourcesPage } from './modules/components/resources.js';

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

console.log('DNS Tools modules loaded');

// Global Keyboard Shortcuts
window.addEventListener('keydown', (e) => {
    // Focus search input on '/' key
    if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
        e.preventDefault();
        const mainInput = document.querySelector('textarea, input[type="text"]');
        if (mainInput) mainInput.focus();
    }
    
    // Clear focus on 'Escape'
    if (e.key === 'Escape') {
        if (document.activeElement) document.activeElement.blur();
    }
});
