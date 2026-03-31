import { loadHistory } from '../utils.js';
import { KNOWLEDGE_BASE } from '../data/index.js';

export function DashboardPage() {
    // Store chart instances outside the Alpine data object to prevent reactivity issues
    let hourlyChartInstance = null;
    let typeChartInstance = null;

    return {
      stats: {
        totalLookups: 0,
        successRate: 0,
        sessionTime: '0s',
        avgResponseTime: '0ms'
      },
      quickLookupDomain: '',
      quickIntelQuery: '',
      featuredConcept: null,
      recentActivity: [],
      recentWhoisActivity: [],
      topSearches: [],
      currentTip: '',
      showSessionModal: false,
      dnsTips: [
        "DNS-over-HTTPS (DoH) encrypts your DNS queries to prevent eavesdropping and manipulation.",
        "A 'TTL' (Time to Live) tells DNS resolvers how long to cache a record before asking again.",
        "MX records with lower priority numbers are tried first for email delivery.",
        "DMARC helps prevent email spoofing by telling receivers how to handle failed SPF/DKIM checks.",
        "CNAME records cannot coexist with other record types for the same hostname.",
        "The '.' at the end of a domain name (e.g. google.com.) represents the DNS root zone."
      ],
      providerStatus: [
        { name: 'Google DNS', url: 'https://dns.google/resolve', status: 'checking', latency: 0 },
        { name: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query', status: 'checking', latency: 0 }
      ],
      chartInitialized: false,
      updatingCharts: false,
      sessionStart: null,
      
      init(){
        window.dashboardInstance = this;
        this.chartInitialized = false;
        
        // Initialize session tracking
        this.initSessionTracking();
        
        this.refreshStats();
        this.checkProviderHealth();
        this.currentTip = this.dnsTips[Math.floor(Math.random() * this.dnsTips.length)];
        
        // Pick a random concept
        if (KNOWLEDGE_BASE && KNOWLEDGE_BASE.length > 0) {
            this.featuredConcept = KNOWLEDGE_BASE[Math.floor(Math.random() * KNOWLEDGE_BASE.length)];
        }

        // Initialize charts with more delay and only once
        setTimeout(() => {
          if (!this.chartInitialized) {
            try {
              this.initCharts();
              this.chartInitialized = true;
              this.refreshStats(); // Refresh again after charts are ready
            } catch (error) {
              console.warn('Chart initialization failed:', error);
            }
          }
        }, 500);
        
        // Refresh every minute for stats, every second for session timer
        setInterval(() => this.updateSessionTime(), 1000);
        setInterval(() => {
          this.refreshStats();
          this.checkProviderHealth();
        }, 60000);
        
        // Update activity on page interaction
        document.addEventListener('click', () => this.updateLastActivity());
        document.addEventListener('keypress', () => this.updateLastActivity());
      },
      
      performQuickLookup() {
        if (!this.quickLookupDomain.trim()) return;
        window.location = 'lookup.html?domains=' + encodeURIComponent(this.quickLookupDomain.trim());
      },

      performIntelLookup() {
        if (!this.quickIntelQuery.trim()) return;
        window.location = 'intel.html?q=' + encodeURIComponent(this.quickIntelQuery.trim());
      },
      
      initSessionTracking() {
        const SESSION_KEY = 'dnstools_session_start';
        
        // Check if there's an existing session
        const existingSession = localStorage.getItem(SESSION_KEY);
        const now = Date.now();
        
        if (existingSession) {
          const sessionStart = parseInt(existingSession);
          this.sessionStart = sessionStart;
        } else {
          // Start new session
          this.sessionStart = now;
          localStorage.setItem(SESSION_KEY, now.toString());
        }
        
        // Update last activity timestamp
        this.updateLastActivity();
      },
      
      getLastActivity() {
        const lastActivity = localStorage.getItem('dnstools_last_activity');
        return lastActivity ? parseInt(lastActivity) : Date.now();
      },
      
      updateLastActivity() {
        localStorage.setItem('dnstools_last_activity', Date.now().toString());
      },
      
      refreshStats(){
        const history = loadHistory() || [];
        if (!Array.isArray(history)) {
          // Reset stats to defaults if history is invalid
          this.stats.totalLookups = 0;
          this.stats.successRate = 0;
          this.stats.avgResponseTime = '0ms';
          this.recentActivity = [];
          this.topDomains = [];
          this.updateSessionTime();
          return;
        }
        
        const today = new Date().toDateString();
        const todayHistory = history.filter(h => new Date(h.timestamp).toDateString() === today);
        
        // Calculate stats
        this.stats.totalLookups = todayHistory.length;
        this.stats.successRate = todayHistory.length > 0 ? Math.round((todayHistory.filter(h => h.success).length / todayHistory.length) * 100) : 0;
        
        // Calculate Avg Response Time
        if (todayHistory.length > 0) {
            const totalDuration = todayHistory.reduce((acc, curr) => acc + (curr.duration || 0), 0);
            const avg = totalDuration / todayHistory.length;
            this.stats.avgResponseTime = avg < 1 ? Math.round(avg * 1000) + 'ms' : avg.toFixed(2) + 's';
        } else {
            this.stats.avgResponseTime = '0ms';
        }
        
        this.updateSessionTime();
        
        // Update recent activity (last 5)
        this.recentActivity = history.slice(0, 5).map(h => ({
          ...h,
          timeAgo: this.getTimeAgo(h.timestamp),
          type: this.getQueryType(h.recordTypes)
        }));

        this.recentWhoisActivity = history
          .filter(h => {
            const t = this.getQueryType(h.recordTypes);
            return t === 'WHOIS' || t === 'WHOIS-IP';
          })
          .slice(0, 5)
          .map(h => ({
            ...h,
            timeAgo: this.getTimeAgo(h.timestamp),
            type: this.getQueryType(h.recordTypes),
          }));

        // Calculate Top Searches
        const searchCounts = {};
        history.forEach(h => {
          // Skip non-search queries (like concepts)
          if (h.recordTypes && h.recordTypes.includes('CONCEPT')) return;
          
          const query = h.query.toLowerCase().trim();
          searchCounts[query] = (searchCounts[query] || 0) + 1;
        });
        this.topSearches = Object.entries(searchCounts)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5)
          .map(([query, count]) => ({ query, count }));
        
        // Update charts if initialized
        if (this.chartInitialized) {
            this.updateCharts(history);
        }
      },

      async checkProviderHealth() {
        for (let provider of this.providerStatus) {
          provider.status = 'checking';
          const start = performance.now();
          try {
            // Use a simple query to check health
            const response = await fetch(`${provider.url}?name=google.com&type=A`, {
              headers: { 'Accept': 'application/dns-json' }
            });
            const end = performance.now();
            if (response.ok) {
              provider.status = 'online';
              provider.latency = Math.round(end - start);
              provider.message = 'Operational';
            } else {
              provider.status = 'error';
              provider.message = `HTTP ${response.status}`;
            }
          } catch (e) {
            provider.status = 'offline';
            // Check if it's likely a CSP or Block error (common with Cloudflare/Quad9 in browsers)
            provider.message = 'Blocked (CSP/Extension)';
          }
        }
      },
      
      updateSessionTime(){
        const elapsed = Date.now() - this.sessionStart;
        const totalSeconds = Math.floor(elapsed / 1000);
        
        if (totalSeconds >= 86400) {
          this.stats.sessionTime = '24h+';
          return;
        }

        const hours = Math.floor(totalSeconds / 3600);
        const minutes = Math.floor((totalSeconds % 3600) / 60);
        const seconds = totalSeconds % 60;
        
        if (hours > 0) {
          this.stats.sessionTime = `${hours}h ${minutes}m ${seconds}s`;
        } else if (minutes > 0) {
          this.stats.sessionTime = `${minutes}m ${seconds}s`;
        } else {
          this.stats.sessionTime = `${seconds}s`;
        }
      },
      
      getTimeAgo(timestamp){
        const diff = Date.now() - timestamp;
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);
        
        if (days > 0) return `${days}d ago`;
        if (hours > 0) return `${hours}h ago`;
        if (minutes > 0) return `${minutes}m ago`;
        return 'Just now';
      },
      
      getQueryType(recordTypes){
        if (!recordTypes || !Array.isArray(recordTypes) || recordTypes.length === 0) return 'DNS';
        if (recordTypes.includes && recordTypes.includes('WHOIS-IP')) return 'WHOIS-IP';
        if (recordTypes.includes && recordTypes.includes('WHOIS')) return 'WHOIS';
        if (recordTypes.includes && recordTypes.includes('MX')) return 'MX';
        if (recordTypes.includes && recordTypes.includes('DMARC')) return 'DMARC';
        if (recordTypes.includes && recordTypes.includes('Headers')) return 'Headers';
        if (recordTypes.includes && recordTypes.includes('INTEL')) return 'Intel';
        return 'DNS';
      },
      
      initCharts(){
        // Destroy existing charts if they exist
        if (hourlyChartInstance) {
          hourlyChartInstance.destroy();
          hourlyChartInstance = null;
        }
        if (typeChartInstance) {
          typeChartInstance.destroy();
          typeChartInstance = null;
        }
        
        // Check for existing Chart.js instances on the canvas elements and destroy them
        const hourlyCanvas = document.getElementById('hourlyChart');
        if (hourlyCanvas) {
            const existingChart = Chart.getChart(hourlyCanvas);
            if (existingChart) existingChart.destroy();
        }
        
        const typeCanvas = document.getElementById('typeChart');
        if (typeCanvas) {
            const existingChart = Chart.getChart(typeCanvas);
            if (existingChart) existingChart.destroy();
        }
        
        // Get current data before creating chart
        const history = loadHistory();
        const hourlyData = new Array(24).fill(0);
        const today = new Date().toDateString();
        
        // Pre-calculate data for chart creation
        history.forEach((entry) => {
          if (entry && entry.timestamp) {
            const entryDate = new Date(entry.timestamp);
            if (entryDate.toDateString() === today) {
              const hour = entryDate.getHours();
              if (hour >= 0 && hour < 24) {
                hourlyData[hour]++;
              }
            }
          }
        });
        
        // Initialize the hourly chart
        if (hourlyCanvas) {
          try {
            hourlyChartInstance = new Chart(hourlyCanvas, {
              type: 'line',
              data: {
                labels: ['00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23'],
                datasets: [{
                  data: hourlyData,
                  borderColor: '#58a6ff',
                  borderWidth: 2,
                  tension: 0.3,
                  pointRadius: 0,
                  pointHoverRadius: 4
                }]
              },
              options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: false },
                scales: {
                    x: { grid: { display: false }, ticks: { color: '#8b949e', maxTicksLimit: 8 } },
                    y: { grid: { color: '#30363d' }, ticks: { color: '#8b949e', stepSize: 1 }, beginAtZero: true }
                }
              }
            });
          } catch (error) {
            console.error('Error creating hourly chart:', error);
          }
        }
        
        // Initialize Type Chart
        if (typeCanvas) {
            try {
                typeChartInstance = new Chart(typeCanvas, {
                    type: 'doughnut',
                    data: {
                        labels: ['No Data'],
                        datasets: [{
                            data: [1],
                            backgroundColor: ['#30363d'],
                            borderColor: '#161b22',
                            borderWidth: 2
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        cutout: '70%',
                        plugins: {
                            legend: {
                                position: 'right',
                                labels: { color: '#c9d1d9', boxWidth: 12, padding: 15, font: { size: 11 } }
                            },
                            tooltip: { enabled: false }
                        }
                    }
                });
            } catch (error) {
                console.error('Error creating type chart:', error);
            }
        }
      },
      
      updateCharts(history){
        try {
          const hasHistory = Array.isArray(history) && history.length > 0;
          
          // Update Hourly Chart
          if (hourlyChartInstance) {
              const hourlyData = new Array(24).fill(0);
              
              if (hasHistory) {
                  const today = new Date().toDateString();
                  history.forEach((entry) => {
                    if (entry && entry.timestamp) {
                      const entryDate = new Date(entry.timestamp);
                      if (entryDate.toDateString() === today) {
                        const hour = entryDate.getHours();
                        if (hour >= 0 && hour < 24) hourlyData[hour]++;
                      }
                    }
                  });
              }
              
              hourlyChartInstance.data.datasets[0].data = hourlyData;
              hourlyChartInstance.update();
          }
          
          // Update Type Chart
          if (typeChartInstance) {
              const types = { 'DNS': 0, 'MX': 0, 'DMARC': 0, 'Headers': 0, 'Intel': 0, 'WHOIS': 0, 'WHOIS-IP': 0 };
              let total = 0;
              
              if (hasHistory) {
                  history.forEach(h => {
                      const type = this.getQueryType(h.recordTypes);
                      if (types[type] !== undefined) types[type]++;
                      else types['DNS']++;
                      total++;
                  });
              }
              
              // If no data, show a gray ring
              if (total === 0) {
                  typeChartInstance.data.datasets[0].data = [1];
                  typeChartInstance.data.datasets[0].backgroundColor = ['#30363d'];
                  typeChartInstance.data.labels = ['No Data'];
                  typeChartInstance.options.plugins.tooltip = { enabled: false };
              } else {
                  typeChartInstance.data.datasets[0].data = [
                      types['DNS'], types['MX'], types['DMARC'], types['Headers'], types['Intel'], types['WHOIS'], types['WHOIS-IP']
                  ];
                    typeChartInstance.data.datasets[0].backgroundColor = ['#3fb950', '#58a6ff', '#d29922', '#a855f7', '#f85149', '#bc8cff', '#79c0ff'];
                    typeChartInstance.data.labels = ['DNS', 'MX', 'DMARC', 'Headers', 'Intel', 'WHOIS', 'WHOIS-IP'];
                  typeChartInstance.options.plugins.tooltip = { enabled: true };
              }
              
              typeChartInstance.update();
          }
          
        } catch (error) {
          console.error('Chart update error:', error);
        }
      },
      
      rerunQuery(activity){
        const type = activity.type.toLowerCase();
        if (type === 'whois' || type === 'whois-ip') {
          window.location = 'whois.html?target=' + encodeURIComponent(activity.query.trim());
          return;
        }
        if (type === 'headers') {
          // For headers, store the data in localStorage if available
          if (activity.results && activity.results.headers) {
            let headersText = '';
            
            // Try to reconstruct from parsed headers
            const headers = activity.results.headers;
            for (const [key, value] of Object.entries(headers)) {
              if (key.startsWith('received-')) {
                headersText += `Received: ${value}\n`;
              } else {
                const capitalizedKey = key.split('-').map(word => 
                  word.charAt(0).toUpperCase() + word.slice(1)
                ).join('-');
                headersText += `${capitalizedKey}: ${value}\n`;
              }
            }
            
            // Store in localStorage temporarily
            localStorage.setItem('dns_rerun_headers', headersText);
          }
          window.location = 'headers.html?rerun=true';
        } else if (type === 'mx') {
          // Extract domain from query for MX
          const domain = activity.query.trim();
          window.location = 'mx.html?domain=' + encodeURIComponent(domain);
        } else if (type === 'dmarc') {
          // Extract domain from query for DMARC
          const domain = activity.query.trim();
          window.location = 'dmarc.html?domain=' + encodeURIComponent(domain);
        } else if (type === 'intel') {
          // Extract target from query for Intel
          const target = activity.query.trim();
          window.location = 'intel.html?q=' + encodeURIComponent(target);
        } else {
          // For DNS lookups, pass domains and record types if available
          window.location = 'lookup.html?domains=' + encodeURIComponent(activity.query);
        }
      },
      
      getTypeCount(type) {
        const history = loadHistory() || [];
        if (!Array.isArray(history)) return 0;
        return history.filter(item => {
          const itemType = this.getQueryType(item.recordTypes);
          return itemType === type;
        }).length;
      },
      
      recreateChart(data) {
        try {
          // Destroy existing chart completely
          if (this.hourlyChart) {
            this.hourlyChart.destroy();
            this.hourlyChart = null;
          }
          
          // Get canvas element and ensure it's clean
          let hourlyCtx = document.getElementById('hourlyChart');
          if (hourlyCtx) {
            // Remove the old canvas and create a new one to avoid Chart.js conflicts
            const parent = hourlyCtx.parentNode;
            const newCanvas = document.createElement('canvas');
            newCanvas.id = 'hourlyChart';
            newCanvas.style.cssText = hourlyCtx.style.cssText;
            
            parent.removeChild(hourlyCtx);
            parent.appendChild(newCanvas);
            
            hourlyCtx = newCanvas;
            
            // Small delay to ensure DOM is ready
            setTimeout(() => {
              try {
                // Create new chart with the data
                this.hourlyChart = new Chart(hourlyCtx, {
                  type: 'line',
                  data: {
                    labels: ['00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23'],
                    datasets: [{
                      label: 'Lookups per Hour',
                      data: [...data],
                      borderColor: '#58a6ff',
                      backgroundColor: 'rgba(88, 166, 255, 0.1)',
                      borderWidth: 2,
                      fill: true
                    }]
                  },
                  options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                      legend: { 
                        display: false 
                      }
                    },
                    scales: {
                      x: {
                        grid: { 
                          color: '#30363d' 
                        },
                        ticks: { 
                          color: '#8b949e' 
                        }
                      },
                      y: {
                        grid: { 
                          color: '#30363d' 
                        },
                        ticks: { 
                          color: '#8b949e' 
                        },
                        beginAtZero: true
                      }
                    }
                  }
                });
              } catch (createError) {
                console.error('Chart creation failed:', createError);
              }
            }, 50);
          }
        } catch (error) {
          console.error('Chart recreation failed:', error);
        }
      }
    };
  };
