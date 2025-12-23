export const CLOUD_CONCEPTS = [
    {
        id: 'entra-id-iam',
        title: 'Microsoft Entra ID (IAM)',
        icon: 'fas fa-id-card',
        iconColor: 'text-[#00a4ef]',
        tags: ['Cloud Security', 'Azure'],
        complexity: 'Intermediate',
        summary: 'Identity and Access Management (IAM) is the new perimeter. Learn about Entra ID and Least Privilege.',
        content: `
            <h4>Identity is the New Perimeter</h4>
            <p>In the cloud, you can't just rely on firewalls. Microsoft Entra ID (formerly Azure AD) controls who can do what.</p>
            
            <h4>Principle of Least Privilege (PoLP)</h4>
            <p>A user or service should have only the minimum permissions necessary to perform their function.</p>
            
            <div class="bg-[#161b22] p-3 rounded border border-[#30363d] my-4">
                <h5 class="text-[#c9d1d9] font-semibold mb-2">Example: Azure Storage Access</h5>
                <div class="space-y-2">
                    <div class="flex items-center gap-2 text-xs">
                        <i class="fas fa-times-circle text-[#f85149]"></i>
                        <span class="text-[#8b949e]"><strong>Bad:</strong> Assigning "Owner" role to a developer.</span>
                    </div>
                    <div class="flex items-center gap-2 text-xs">
                        <i class="fas fa-check-circle text-[#3fb950]"></i>
                        <span class="text-[#8b949e]"><strong>Good:</strong> Assigning "Storage Blob Data Reader" role.</span>
                    </div>
                </div>
            </div>
        `
    },
    {
        id: 'azure-networking',
        title: 'Azure Networking Basics',
        icon: 'fas fa-project-diagram',
        iconColor: 'text-[#0078d4]',
        tags: ['Networking', 'Azure'],
        complexity: 'Intermediate',
        summary: 'Virtual Networks (VNet), Subnets, NSGs, and Azure Firewall.',
        content: `
            <h4>Virtual Network (VNet)</h4>
            <p>The fundamental building block for your private network in Azure. VNet enables many types of Azure resources, such as Azure Virtual Machines (VM), to securely communicate with each other, the internet, and on-premises networks.</p>

            <h4>Network Security Groups (NSG)</h4>
            <p>An NSG contains security rules that allow or deny inbound network traffic to, or outbound network traffic from, several types of Azure resources.</p>
            <ul class="list-disc list-inside space-y-2 my-4 text-[#c9d1d9]">
                <li><strong>Inbound Rules:</strong> Control traffic coming into the subnet/VM (e.g., Allow HTTPS on port 443).</li>
                <li><strong>Outbound Rules:</strong> Control traffic leaving the subnet/VM.</li>
            </ul>

            <h4>Azure Firewall</h4>
            <p>A managed, cloud-based network security service that protects your Azure Virtual Network resources. It's a fully stateful firewall as a service with built-in high availability and unrestricted cloud scalability.</p>
        `
    },
    {
        id: 'azure-app-service-dns',
        title: 'Azure App Service DNS',
        icon: 'fas fa-globe',
        iconColor: 'text-[#0078d4]',
        tags: ['Azure', 'Hosting'],
        complexity: 'Intermediate',
        summary: 'Configuring custom domains for Azure Web Apps using CNAME and TXT verification.',
        content: `
            <h4>Custom Domains in Azure App Service</h4>
            <p>To map a custom domain (e.g., <code>www.contoso.com</code>) to your Azure Web App, you typically use a CNAME record.</p>

            <h4>Verification Process</h4>
            <p>Azure needs to verify you own the domain before allowing the mapping. This is often done via a TXT record if you want to map the domain without downtime (pre-verification).</p>
            
            <div class="bg-[#161b22] p-3 rounded border border-[#30363d] my-4">
                <h5 class="text-[#c9d1d9] font-semibold mb-2">The "asuid" Record</h5>
                <p class="text-sm text-[#8b949e] mb-2">To verify ownership without pointing traffic yet, create a TXT record:</p>
                <code class="block bg-[#0d1117] p-2 rounded text-xs text-[#58a6ff]">asuid.www.contoso.com TXT "verification-hash-from-azure"</code>
            </div>

            <h4>Root Domains (Apex)</h4>
            <p>Since CNAMEs are not allowed at the root (<code>contoso.com</code>), Azure recommends using an <strong>A Record</strong> pointing to the App Service IP, or using an <strong>Alias Record</strong> if using Azure DNS.</p>
        `
    },
    {
        id: 'azure-traffic-manager',
        title: 'Azure Traffic Manager',
        icon: 'fas fa-random',
        iconColor: 'text-[#0078d4]',
        tags: ['Azure', 'Networking'],
        complexity: 'Advanced',
        summary: 'DNS-based traffic load balancer that distributes traffic across global Azure regions.',
        content: `
            <h4>What is Traffic Manager?</h4>
            <p>Azure Traffic Manager is a DNS-based traffic load balancer. It allows you to distribute traffic to your public facing applications across the global Azure regions.</p>

            <h4>How it Works</h4>
            <ol class="list-decimal list-inside space-y-2 my-4 text-[#c9d1d9]">
                <li>User queries <code>myapp.contoso.com</code>.</li>
                <li>DNS resolves to Traffic Manager profile (<code>myapp.trafficmanager.net</code>).</li>
                <li>Traffic Manager checks the <strong>Routing Method</strong> (Priority, Weighted, Performance, Geographic).</li>
                <li>Traffic Manager returns the CNAME of the best endpoint (e.g., <code>myapp-eu.azurewebsites.net</code>).</li>
                <li>User connects directly to that endpoint.</li>
            </ol>
            
            <p class="text-sm text-[#8b949e]">Note: Traffic Manager does not see the actual HTTP traffic; it only directs the DNS query.</p>
        `
    },
    {
        id: 'azure-front-door',
        title: 'Azure Front Door',
        icon: 'fas fa-door-open',
        iconColor: 'text-[#79c0ff]',
        tags: ['Azure', 'Networking'],
        complexity: 'Advanced',
        summary: 'Global CDN and Load Balancer using Anycast DNS for low-latency access.',
        content: `
            <h4>Global Entry Point</h4>
            <p>Azure Front Door is a modern Content Delivery Network (CDN) that provides fast, reliable, and secure access between your users and your applications' static and dynamic web content.</p>

            <h4>Anycast DNS</h4>
            <p>Front Door uses Anycast networking. The same IP address is advertised from hundreds of edge locations worldwide. Users connect to the closest Azure POP (Point of Presence).</p>

            <h4>CNAME Flattening</h4>
            <p>Unlike Traffic Manager, Front Door terminates the connection (Split TCP) and proxies the traffic. It supports CNAME flattening (via Alias records in Azure DNS) to allow mapping to the root domain.</p>
        `
    },
    {
        id: 'azure-private-dns',
        title: 'Azure Private DNS',
        icon: 'fas fa-lock',
        iconColor: 'text-[#3fb950]',
        tags: ['Azure', 'Networking'],
        complexity: 'Intermediate',
        summary: 'Resolving domain names in a private virtual network without adding custom DNS servers.',
        content: `
            <h4>Split-Horizon DNS</h4>
            <p>Azure Private DNS allows you to use your own domain names (e.g., <code>db.internal.contoso.com</code>) within your Virtual Networks (VNet).</p>

            <h4>Key Features</h4>
            <ul class="list-disc list-inside space-y-2 my-4 text-[#c9d1d9]">
                <li><strong>No Infrastructure:</strong> You don't need to manage VM-based DNS servers.</li>
                <li><strong>Automatic Registration:</strong> VMs in the VNet can automatically register their A records.</li>
                <li><strong>Split-Horizon:</strong> You can have a public zone <code>contoso.com</code> and a private zone <code>contoso.com</code>. Internal users see internal IPs; external users see public IPs.</li>
            </ul>
        `
    },
    {
        id: 'azure-public-ip',
        title: 'Azure Public IP Addresses',
        icon: 'fas fa-globe-americas',
        iconColor: 'text-[#58a6ff]',
        tags: ['Azure', 'Networking'],
        complexity: 'Beginner',
        summary: 'Understanding Public IP SKUs (Basic vs Standard) and allocation methods.',
        content: `
            <h4>Public IP Addresses in Azure</h4>
            <p>Public IP addresses allow Internet resources to communicate inbound to Azure resources. They also enable Azure resources to communicate outbound to the Internet.</p>

            <h4>SKUs: Basic vs. Standard</h4>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 my-4">
                <div class="bg-[#161b22] p-3 rounded border border-[#30363d]">
                    <h5 class="text-[#58a6ff] font-semibold mb-1">Standard SKU</h5>
                    <ul class="list-disc list-inside text-xs text-[#8b949e]">
                        <li><strong>Static only:</strong> IP address doesn't change.</li>
                        <li><strong>Secure by default:</strong> Closed to inbound traffic unless allowed by NSG.</li>
                        <li><strong>Zone Redundant:</strong> Can span availability zones.</li>
                    </ul>
                </div>
                <div class="bg-[#161b22] p-3 rounded border border-[#30363d]">
                    <h5 class="text-[#d29922] font-semibold mb-1">Basic SKU</h5>
                    <ul class="list-disc list-inside text-xs text-[#8b949e]">
                        <li><strong>Dynamic or Static:</strong> Dynamic IPs change on stop/start.</li>
                        <li><strong>Open by default:</strong> NSG is optional (but recommended).</li>
                        <li><strong>No Zone Redundancy.</strong></li>
                    </ul>
                </div>
            </div>
        `
    },
    {
        id: 'azure-dns-zones',
        title: 'Azure DNS Zones',
        icon: 'fas fa-sitemap',
        iconColor: 'text-[#a855f7]',
        tags: ['Azure', 'DNS'],
        complexity: 'Intermediate',
        summary: 'Hosting your domains on Azure\'s global name server network.',
        content: `
            <h4>Hosting Domains in Azure</h4>
            <p>Azure DNS allows you to host your DNS domain in Azure and manage your DNS records using the same credentials, APIs, tools, and billing as your other Azure services.</p>

            <h4>Key Benefits</h4>
            <ul class="list-disc list-inside space-y-2 my-4 text-[#c9d1d9]">
                <li><strong>Global Network:</strong> Uses Microsoft's global network of Anycast name servers for ultra-fast query responses.</li>
                <li><strong>Reliability:</strong> 100% availability SLA.</li>
                <li><strong>Security:</strong> Supports Role-Based Access Control (RBAC) to restrict who can modify records.</li>
                <li><strong>Alias Records:</strong> Can point to Azure resources (like Public IPs or Traffic Manager) directly, updating automatically if the resource IP changes.</li>
            </ul>
        `
    },
    {
        id: 'private-endpoints',
        title: 'Private Endpoints (Private Link)',
        icon: 'fas fa-network-wired',
        iconColor: 'text-[#3fb950]',
        tags: ['Azure', 'Networking', 'Security'],
        complexity: 'Advanced',
        summary: 'Accessing PaaS services (SQL, Storage) privately from your VNet.',
        content: `
            <h4>What is a Private Endpoint?</h4>
            <p>A Private Endpoint is a network interface that uses a private IP address from your virtual network. This network interface connects you privately and securely to a service powered by Azure Private Link.</p>

            <h4>How it Works</h4>
            <p>Instead of accessing Azure SQL Database via its public endpoint (<code>sql.database.windows.net</code>), you access it via a private IP (e.g., <code>10.0.1.5</code>) inside your VNet.</p>

            <h4>DNS Integration</h4>
            <p>To make this work seamlessly, you need to override DNS resolution. Azure creates a CNAME to a private link zone:</p>
            <pre class="bg-[#0d1117] p-3 rounded border border-[#30363d] text-xs font-mono text-[#c9d1d9] mt-2">
myserver.database.windows.net 
  -> myserver.privatelink.database.windows.net 
    -> 10.0.1.5</pre>
        `
    },
    {
        id: 'service-tags',
        title: 'Service Tags',
        icon: 'fas fa-tags',
        iconColor: 'text-[#79c0ff]',
        tags: ['Azure', 'Networking'],
        complexity: 'Intermediate',
        summary: 'Simplifying Network Security Group (NSG) rules for Azure services.',
        content: `
            <h4>What are Service Tags?</h4>
            <p>A service tag represents a group of IP address prefixes from a given Azure service. Microsoft manages the address prefixes encompassed by the service tag and automatically updates the service tag as addresses change.</p>

            <h4>Use Cases</h4>
            <p>Instead of manually maintaining a list of IPs for Azure SQL or Azure Storage in your firewall rules, you can simply allow traffic to the tag:</p>
            
            <div class="bg-[#161b22] p-3 rounded border border-[#30363d] my-4">
                <ul class="space-y-2 text-sm text-[#c9d1d9]">
                    <li><strong>Internet:</strong> All public IP addresses outside the VNet.</li>
                    <li><strong>AzureCloud:</strong> All public IP addresses for Azure cloud services.</li>
                    <li><strong>Sql:</strong> Azure SQL Database, MySQL, PostgreSQL, etc.</li>
                    <li><strong>Storage:</strong> Azure Storage.</li>
                </ul>
            </div>
        `
    }
];
