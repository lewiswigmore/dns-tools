// Shared, client-side heuristic fraud/risk indicator logic.
// Pure functions only, no network or DOM access, safe to reuse from any page.

// Registry status codes that suggest an unstable or non-functioning domain.
const RISKY_RDAP_STATUSES = ['pendingdelete', 'redemptionperiod', 'clienthold', 'serverhold'];

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

/**
 * Builds a list of heuristic risk indicators for a single domain from its
 * RDAP and DNS lookup results. Callers are responsible for fetching the
 * inputs (RDAP record, plus A/AAAA/MX/NS/TXT and _dmarc TXT records).
 */
export function buildFraudIndicators({ domain, rdap, a, aaaa, mx, ns, txt, dmarcTxt }) {
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

/** Collapses a list of indicators down to a single top severity level. */
export function computeRiskLevel(indicators) {
    const severityRank = { high: 3, medium: 2, low: 1, info: 0 };
    let topSeverity = 'info';
    for (const indicator of indicators) {
        if (severityRank[indicator.severity] > severityRank[topSeverity]) {
            topSeverity = indicator.severity;
        }
    }
    return topSeverity === 'info' ? 'none' : topSeverity;
}

export function riskLabel(level) {
    switch (level) {
        case 'high': return 'High Risk Signals Detected';
        case 'medium': return 'Some Risk Signals Detected';
        case 'low': return 'Minor Signals Detected';
        default: return 'No Strong Risk Signals Detected';
    }
}

export function riskIcon(level) {
    switch (level) {
        case 'high': return 'fa-triangle-exclamation';
        case 'medium': return 'fa-circle-exclamation';
        case 'low': return 'fa-circle-info';
        default: return 'fa-circle-check';
    }
}

/** Text color class only, for compact inline indicators (icons, badges). */
export function riskColorClass(level) {
    switch (level) {
        case 'high': return 'text-[#f85149]';
        case 'medium': return 'text-[#d29922]';
        case 'low': return 'text-[#58a6ff]';
        default: return 'text-[#3fb950]';
    }
}

/** Text + border classes, for a full banner/panel treatment. */
export function riskBannerClass(level) {
    switch (level) {
        case 'high': return 'border border-[#f85149]/40 text-[#f85149]';
        case 'medium': return 'border border-[#d29922]/40 text-[#d29922]';
        case 'low': return 'border border-[#58a6ff]/40 text-[#58a6ff]';
        default: return 'border border-[#3fb950]/40 text-[#3fb950]';
    }
}
