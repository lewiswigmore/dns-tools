import { DNSClient } from './dns-client.js';
import { buildFraudIndicators, computeRiskLevel } from './fraud-indicators.js';
import { queryDomain } from './rdap-client.js';

export async function assessDomainFraudRisk(
  domain,
  {
    dnsClient = new DNSClient(),
    lookupDomain = queryDomain,
  } = {}
) {
  const [rdapResult, aRecords, aaaaRecords, mxRecords, nsRecords, txtRecords, dmarcRecords] =
    await Promise.all([
      lookupDomain(domain).then(response => response.result).catch(() => null),
      dnsClient.queryDNS(domain, 'A'),
      dnsClient.queryDNS(domain, 'AAAA'),
      dnsClient.queryDNS(domain, 'MX'),
      dnsClient.queryDNS(domain, 'NS'),
      dnsClient.queryDNS(domain, 'TXT'),
      dnsClient.queryDNS(`_dmarc.${domain}`, 'TXT'),
    ]);

  const indicators = buildFraudIndicators({
    domain,
    rdap: rdapResult,
    a: aRecords,
    aaaa: aaaaRecords,
    mx: mxRecords,
    ns: nsRecords,
    txt: txtRecords,
    dmarcTxt: dmarcRecords,
  });

  return { indicators, riskLevel: computeRiskLevel(indicators) };
}
