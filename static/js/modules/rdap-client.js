/**
 * RDAP Client — client-side domain registration lookups via IANA bootstrap.
 *
 * Uses the IANA RDAP bootstrap registry to resolve the authoritative RDAP
 * server for any TLD and queries it directly from the browser (no proxy).
 * All gTLDs are required by ICANN to support CORS.
 */

const BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';

let bootstrapData = null;
let bootstrapLoading = null;

/**
 * Fetch and cache the IANA RDAP bootstrap registry.
 * Returns the services array from dns.json.
 */
async function loadBootstrap() {
  if (bootstrapData) return bootstrapData;
  if (bootstrapLoading) return bootstrapLoading;

  bootstrapLoading = (async () => {
    const res = await fetch(BOOTSTRAP_URL);
    if (!res.ok) throw new Error('Failed to load RDAP bootstrap registry');
    const json = await res.json();
    bootstrapData = json.services;
    bootstrapLoading = null;
    return bootstrapData;
  })();

  return bootstrapLoading;
}

/**
 * Given a domain name, extract the TLD and find the authoritative RDAP base URL.
 */
function findRDAPServer(domain, services) {
  const parts = domain.toLowerCase().split('.');
  if (parts.length < 2) return null;

  // Try progressively shorter suffixes (e.g. "co.uk" before "uk")
  for (let i = 1; i < parts.length; i++) {
    const suffix = parts.slice(i).join('.');
    for (const service of services) {
      const tlds = service[0];
      const urls = service[1];
      if (tlds.some(t => t.toLowerCase() === suffix)) {
        // Prefer HTTPS URL
        const url = urls.find(u => u.startsWith('https://')) || urls[0];
        return url.endsWith('/') ? url : url + '/';
      }
    }
  }
  return null;
}

/**
 * Parse an RDAP domain response into a normalised object.
 */
function parseResponse(json) {
  const result = {
    objectClassName: json.objectClassName,
    ldhName: json.ldhName,
    unicodeName: json.unicodeName || null,
    handle: json.handle || null,
    status: json.status || [],
    events: {},
    registrar: null,
    nameservers: [],
    secureDNS: null,
    links: json.links || [],
    rdapConformance: json.rdapConformance || [],
    port43: json.port43 || null,
    notices: json.notices || [],
    raw: json,
  };

  // Events (registration, expiration, last changed, etc.)
  if (Array.isArray(json.events)) {
    for (const ev of json.events) {
      result.events[ev.eventAction] = {
        date: ev.eventDate,
        actor: ev.eventActor || null,
      };
    }
  }

  // Entities — find registrar
  if (Array.isArray(json.entities)) {
    for (const entity of json.entities) {
      if (Array.isArray(entity.roles) && entity.roles.includes('registrar')) {
        result.registrar = {
          name: extractEntityName(entity),
          handle: entity.handle || null,
          url: extractEntityUrl(entity),
        };
      }
    }
  }

  // Nameservers
  if (Array.isArray(json.nameservers)) {
    result.nameservers = json.nameservers.map(ns => ({
      ldhName: ns.ldhName,
      ipv4: ns.ipAddresses?.v4 || [],
      ipv6: ns.ipAddresses?.v6 || [],
    }));
  }

  // DNSSEC
  if (json.secureDNS) {
    result.secureDNS = {
      delegationSigned: json.secureDNS.delegationSigned ?? false,
      zoneSigned: json.secureDNS.zoneSigned ?? null,
      dsData: json.secureDNS.dsData || [],
      keyData: json.secureDNS.keyData || [],
    };
  }

  return result;
}

function extractEntityName(entity) {
  // Try JSContact (jscard / jscard_0)
  const jscard = entity.jscard || entity.jscard_0;
  if (jscard?.fullName) return jscard.fullName;
  if (jscard?.organizations) {
    const org = Object.values(jscard.organizations)[0];
    if (org?.name) return org.name;
  }
  // Try vCard
  if (Array.isArray(entity.vcardArray?.[1])) {
    for (const prop of entity.vcardArray[1]) {
      if (prop[0] === 'fn') return prop[3];
      if (prop[0] === 'org') return Array.isArray(prop[3]) ? prop[3].join(' ') : prop[3];
    }
  }
  return entity.handle || 'Unknown';
}

function extractEntityUrl(entity) {
  if (Array.isArray(entity.links)) {
    for (const link of entity.links) {
      if (link.rel === 'self' || link.href) return link.href;
    }
  }
  return null;
}

/**
 * Main public API — query RDAP for a domain.
 * Returns { result, server } on success.
 * Throws on error with a user-friendly message.
 */
export async function queryDomain(domain) {
  const services = await loadBootstrap();
  const server = findRDAPServer(domain, services);

  if (!server) {
    throw new Error(`RDAP is not available for this TLD. The registry for "${domain.split('.').pop()}" has not deployed RDAP yet.`);
  }

  const url = `${server}domain/${encodeURIComponent(domain)}`;

  let res;
  try {
    res = await fetch(url, {
      headers: { Accept: 'application/rdap+json, application/json' },
    });
  } catch (err) {
    // Network / CORS error
    throw new Error(
      'Unable to reach the RDAP server. This may be a CORS issue — the registry may not allow browser-based queries.'
    );
  }

  if (res.status === 404) {
    throw new Error(`Domain "${domain}" was not found in the registry.`);
  }
  if (!res.ok) {
    throw new Error(`RDAP server returned ${res.status} ${res.statusText}`);
  }

  const json = await res.json();
  return { result: parseResponse(json), server };
}

/**
 * Pre-load the bootstrap data in the background.
 */
export function preloadBootstrap() {
  loadBootstrap().catch(() => {});
}
