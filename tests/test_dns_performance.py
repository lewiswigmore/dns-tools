import asyncio

from app import DNSLookup


def test_normalize_domains_preserves_first_occurrence_when_deduplicating():
    service = DNSLookup()

    domains = service.normalize_domains('one.example,one.example,two.example')

    assert domains == [
        {'domain': 'one.example', 'original': None},
        {'domain': 'two.example', 'original': None},
    ]


def test_async_bulk_lookups_bound_parallel_requests_and_preserve_grouping():
    async def run_lookup():
        service = DNSLookup()
        active = 0
        maximum = 0

        async def fake_fetch_dns_record(session, domain, record_type='A'):
            nonlocal active, maximum
            active += 1
            maximum = max(maximum, active)
            await asyncio.sleep(0.001)
            active -= 1
            return {
                'domain': domain,
                'type': record_type,
                'status': 'success',
                'records': [f'{domain}:{record_type}'],
            }

        service.fetch_dns_record = fake_fetch_dns_record
        domain_objects = [
            {'domain': f'host{index}.example.com', 'original': None}
            for index in range(10)
        ]
        results = await service.lookup_domains_async(domain_objects, ['A', 'MX'])
        return maximum, results

    maximum, results = asyncio.run(run_lookup())

    assert maximum > 1
    assert maximum <= 6
    assert [result['domain'] for result in results] == [
        f'host{index}.example.com' for index in range(10)
    ]
    assert results[0]['records'] == {
        'A': ['host0.example.com:A'],
        'MX': ['host0.example.com:MX'],
    }
