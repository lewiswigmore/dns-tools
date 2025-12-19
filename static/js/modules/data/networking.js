export const NETWORKING_CONCEPTS = [
    {
        id: 'ip-addressing',
        title: 'IP Addressing & CIDR',
        icon: 'fas fa-network-wired',
        iconColor: 'text-[#3fb950]',
        tags: ['Networking', 'Basics'],
        complexity: 'Beginner',
        summary: 'Understanding IPv4, IPv6, Subnet Masks, and CIDR notation.',
        content: `
            <h4>IPv4 vs IPv6</h4>
            <p>IP addresses are unique identifiers for devices on a network.</p>
            <ul class="list-disc list-inside space-y-2 my-4 text-[#c9d1d9]">
                <li><strong>IPv4:</strong> 32-bit address (e.g., <code>192.168.1.1</code>). ~4.3 billion addresses.</li>
                <li><strong>IPv6:</strong> 128-bit address (e.g., <code>2001:0db8:85a3::8a2e:0370:7334</code>). Virtually infinite.</li>
            </ul>

            <h4>CIDR Notation (Classless Inter-Domain Routing)</h4>
            <p>A compact way to represent an IP address and its associated network mask.</p>
            <div class="bg-[#161b22] p-3 rounded border border-[#30363d] my-4 font-mono text-sm">
                <p>Format: IP_Address/Prefix_Length</p>
                <p class="mt-2 text-[#58a6ff]">Example: 192.168.1.0/24</p>
                <ul class="text-[#8b949e] mt-1 ml-4">
                    <li>IP Range: 192.168.1.0 - 192.168.1.255</li>
                    <li>Total IPs: 256</li>
                    <li>Subnet Mask: 255.255.255.0</li>
                </ul>
            </div>
        `
    }
];
