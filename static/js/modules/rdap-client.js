/**
 * RDAP Client — client-side domain registration lookups via IANA bootstrap.
 *
 * Uses the IANA RDAP bootstrap registry to resolve the authoritative RDAP
 * server for any TLD and queries it directly from the browser (no proxy).
 * All gTLDs are required by ICANN to support CORS.
 */

const BOOTSTRAP_URLS = {
  dns: 'https://data.iana.org/rdap/dns.json',
  ipv4: 'https://data.iana.org/rdap/ipv4.json',
  ipv6: 'https://data.iana.org/rdap/ipv6.json',
};

const bootstrapData = {
  dns: null,
  ipv4: null,
  ipv6: null,
};

const bootstrapLoading = {
  dns: null,
  ipv4: null,
  ipv6: null,
};

/**
 * Fetch and cache the IANA RDAP bootstrap registry.
 * Returns the services array from dns.json.
 */
async function loadBootstrap(type = 'dns') {
  if (!BOOTSTRAP_URLS[type]) throw new Error(`Unknown bootstrap type: ${type}`);
  if (bootstrapData[type]) return bootstrapData[type];
  if (bootstrapLoading[type]) return bootstrapLoading[type];

  bootstrapLoading[type] = (async () => {
    const res = await fetch(BOOTSTRAP_URLS[type]);
    if (!res.ok) throw new Error('Failed to load RDAP bootstrap registry');
    const json = await res.json();
    bootstrapData[type] = json.services;
    bootstrapLoading[type] = null;
    return bootstrapData[type];
  })();

  return bootstrapLoading[type];
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

function findRDAPServerForIP(ip, services, version) {
  const ipValue = parseIPToBigInt(ip, version);
  if (ipValue === null) return null;

  let best = null;

  for (const service of services) {
    const prefixes = service[0];
    const urls = service[1];
    for (const prefix of prefixes) {
      const parsed = parseCIDR(prefix, version);
      if (!parsed) continue;
      if (isIPInCIDR(ipValue, parsed)) {
        if (!best || parsed.prefixLength > best.prefixLength) {
          const url = urls.find(u => u.startsWith('https://')) || urls[0];
          best = {
            prefixLength: parsed.prefixLength,
            server: url.endsWith('/') ? url : `${url}/`,
          };
        }
      }
    }
  }

  return best?.server || null;
}

function parseCIDR(cidr, version) {
  if (typeof cidr !== 'string' || !cidr.includes('/')) return null;
  const [base, prefixRaw] = cidr.split('/');
  const prefixLength = Number(prefixRaw);
  const maxBits = version === 'ipv6' ? 128 : 32;
  if (!Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > maxBits) return null;
  const value = parseIPToBigInt(base, version);
  if (value === null) return null;
  return { value, prefixLength, maxBits };
}

function isIPInCIDR(ipValue, cidr) {
  const hostBits = BigInt(cidr.maxBits - cidr.prefixLength);
  if (hostBits === 0n) return ipValue === cidr.value;
  const networkA = (cidr.value >> hostBits) << hostBits;
  const networkB = (ipValue >> hostBits) << hostBits;
  return networkA === networkB;
}

function parseIPToBigInt(ip, version) {
  if (version === 'ipv4') return parseIPv4ToBigInt(ip);
  if (version === 'ipv6') return parseIPv6ToBigInt(ip);
  return null;
}

function parseIPv4ToBigInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const octet = Number(part);
    if (octet < 0 || octet > 255) return null;
    value = (value << 8n) + BigInt(octet);
  }
  return value;
}

function parseIPv6ToBigInt(ip) {
  if (!ip.includes(':')) return null;
  const [left, right] = ip.toLowerCase().split('::');
  if (ip.split('::').length > 2) return null;

  const leftParts = left ? left.split(':').filter(Boolean) : [];
  const rightParts = right ? right.split(':').filter(Boolean) : [];

  if (leftParts.length + rightParts.length > 8) return null;
  const missing = 8 - (leftParts.length + rightParts.length);
  const full = [...leftParts, ...Array(missing).fill('0'), ...rightParts];
  if (full.length !== 8) return null;

  let value = 0n;
  for (const part of full) {
    if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
    value = (value << 16n) + BigInt(parseInt(part, 16));
  }
  return value;
}

function detectQueryType(target) {
  const input = target.trim().toLowerCase();
  if (isIPv4(input)) return 'ipv4';
  if (isIPv6(input)) return 'ipv6';
  return 'domain';
}

function isIPv4(value) {
  return /^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$/.test(value);
}

function isIPv6(value) {
  return value.includes(':') && parseIPv6ToBigInt(value) !== null;
}

/**
 * Parse an RDAP domain response into a normalised object.
 */
function parseResponse(json) {
  const isIpObject = (json.objectClassName || '').toLowerCase() === 'ip network';

  const result = {
    kind: isIpObject ? 'ip' : 'domain',
    objectClassName: json.objectClassName,
    ldhName: json.ldhName,
    unicodeName: json.unicodeName || null,
    handle: json.handle || null,
    networkName: json.name || null,
    networkType: json.type || null,
    country: json.country || null,
    ipVersion: json.ipVersion || null,
    startAddress: json.startAddress || null,
    endAddress: json.endAddress || null,
    parentHandle: json.parentHandle || null,
    cidrBlocks: Array.isArray(json.cidr0_cidrs)
      ? json.cidr0_cidrs.map(item => {
          if (item.v4prefix && Number.isInteger(item.length)) return `${item.v4prefix}/${item.length}`;
          if (item.v6prefix && Number.isInteger(item.length)) return `${item.v6prefix}/${item.length}`;
          return null;
        }).filter(Boolean)
      : [],
    status: json.status || [],
    eventActions: [],
    events: {},
    keyDates: {
      registration: null,
      expiration: null,
      lastChanged: null,
      lastRdapUpdate: null,
      transfer: null,
    },
    registrar: null,
    roles: {
      registrant: null,
      abuse: null,
      reseller: null,
      technical: null,
      administrative: null,
    },
    nameservers: [],
    secureDNS: null,
    links: json.links || [],
    rdapConformance: json.rdapConformance || [],
    port43: json.port43 || null,
    notices: normaliseTextSections(json.notices),
    remarks: normaliseTextSections(json.remarks),
    raw: json,
  };

  // Events (registration, expiration, last changed, etc.)
  if (Array.isArray(json.events)) {
    for (const ev of json.events) {
      if (ev?.eventAction) result.eventActions.push(ev.eventAction);
      result.events[ev.eventAction] = {
        date: ev.eventDate,
        actor: ev.eventActor || null,
      };
    }
  }

  result.keyDates.registration = result.events.registration?.date || null;
  result.keyDates.expiration = result.events.expiration?.date || null;
  result.keyDates.lastChanged = result.events['last changed']?.date || null;
  result.keyDates.lastRdapUpdate = result.events['last update of RDAP database']?.date || null;
  result.keyDates.transfer = result.events.transfer?.date || null;

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
      if (Array.isArray(entity.roles) && entity.roles.includes('registrant')) {
        result.roles.registrant = {
          name: extractEntityName(entity),
          handle: entity.handle || null,
          url: extractEntityUrl(entity),
        };
      }
      if (Array.isArray(entity.roles) && entity.roles.includes('abuse')) {
        result.roles.abuse = {
          name: extractEntityName(entity),
          handle: entity.handle || null,
          url: extractEntityUrl(entity),
        };
      }
      if (Array.isArray(entity.roles) && entity.roles.includes('reseller')) {
        result.roles.reseller = {
          name: extractEntityName(entity),
          handle: entity.handle || null,
          url: extractEntityUrl(entity),
        };
      }
      if (Array.isArray(entity.roles) && entity.roles.includes('technical')) {
        result.roles.technical = {
          name: extractEntityName(entity),
          handle: entity.handle || null,
          url: extractEntityUrl(entity),
        };
      }
      if (Array.isArray(entity.roles) && entity.roles.includes('administrative')) {
        result.roles.administrative = {
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

function normaliseTextSections(items) {
  if (!Array.isArray(items)) return [];
  return items.map(item => {
    const title = item?.title || 'Notice';
    const lines = Array.isArray(item?.description)
      ? item.description.filter(Boolean)
      : [];
    return {
      title,
      text: lines.length ? lines.join(' ') : null,
    };
  });
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
  const services = await loadBootstrap('dns');
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

export async function queryTarget(target) {
  const input = target.trim().toLowerCase();
  const queryType = detectQueryType(input);

  if (queryType === 'domain') {
    const data = await queryDomain(input);
    return { ...data, queryType: 'domain' };
  }

  const services = await loadBootstrap(queryType);
  const server = findRDAPServerForIP(input, services, queryType);

  if (!server) {
    throw new Error(`RDAP is not available for this IP range in IANA bootstrap (${queryType.toUpperCase()}).`);
  }

  const url = `${server}ip/${encodeURIComponent(input)}`;

  let res;
  try {
    res = await fetch(url, {
      headers: { Accept: 'application/rdap+json, application/json' },
    });
  } catch (err) {
    throw new Error('Unable to reach the RDAP server for this IP. This may be a CORS/network restriction.');
  }

  if (res.status === 404) {
    throw new Error(`IP "${input}" was not found in the registry.`);
  }
  if (!res.ok) {
    throw new Error(`RDAP server returned ${res.status} ${res.statusText}`);
  }

  const json = await res.json();
  return { result: parseResponse(json), server, queryType: 'ip' };
}

/**
 * Pre-load the bootstrap data in the background.
 */
export function preloadBootstrap() {
  loadBootstrap('dns').catch(() => {});
}
