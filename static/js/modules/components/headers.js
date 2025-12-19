import { addHistory, exportJSON, autoGrow } from '../utils.js';

export function HeadersPage() {
    return {
      headers:'', results:null, loading:false, error:'',
      autoGrow,
      init(){
        // Check for rerun parameter and stored headers data
        const params = new URLSearchParams(window.location.search);
        const isRerun = params.get('rerun');
        
        if (isRerun) {
          const storedHeaders = localStorage.getItem('dns_rerun_headers');
          if (storedHeaders) {
            this.headers = storedHeaders;
            // Clean up the stored data
            localStorage.removeItem('dns_rerun_headers');
            // Auto-execute the analysis
            setTimeout(() => this.analyzeHeaders(), 100);
          }
        }
      },
      async analyzeHeaders(){
        if(this.loading || !this.headers.trim()) return;
        
        this.loading = true;
        this.error = '';
        this.results = null;
        
        try {
          const startTime = Date.now();
          
          // Simple client-side header analysis
          const headerLines = this.headers.split('\n');
          const parsedHeaders = {};
          let currentHeader = '';
          let receivedCount = 0;
          
          for (let line of headerLines) {
            const originalLine = line; // Keep original for whitespace detection
            line = line.trim();
            if (!line) continue;
            
            // Check if this is a header line (starts with header name followed by colon)
            const isHeaderLine = line.match(/^[a-zA-Z0-9-]+:\s/);
            // Check if this is a continuation line (starts with whitespace in original)
            const isContinuationLine = originalLine.match(/^\s+/) && currentHeader;
            
            if (isHeaderLine && !isContinuationLine) {
              const [header, ...valueParts] = line.split(':');
              const headerName = header.trim().toLowerCase();
              const headerValue = valueParts.join(':').trim();
              
              // Handle multiple Received headers
              if (headerName === 'received') {
                currentHeader = `received-${receivedCount}`;
                receivedCount++;
                parsedHeaders[currentHeader] = headerValue;
              } else {
                currentHeader = headerName;
                parsedHeaders[currentHeader] = headerValue;
              }
            } else if (isContinuationLine || (currentHeader && !isHeaderLine)) {
              // Continuation line - add to current header
              parsedHeaders[currentHeader] += ' ' + line;
            }
          }
          
          const analysis = {
            headers: parsedHeaders,
            ...this.parseAuthenticationResults(parsedHeaders),
            routing: {
              from: parsedHeaders['from'] || 'Not found',
              to: parsedHeaders['to'] || 'Not found',
              subject: parsedHeaders['subject'] || 'Not found',
              date: parsedHeaders['date'] || 'Not found'
            },
            security: this.analyzeSecurityIndicators(parsedHeaders),
            delivery_path: this.parseDeliveryPath(parsedHeaders)
          };
          
          const duration = (Date.now() - startTime) / 1000;
          this.results = analysis;
          
          // Create a meaningful query preview from the email headers
          let queryPreview = 'Email Headers';
          if (analysis.routing) {
            const subject = analysis.routing.subject;
            const from = analysis.routing.from;
            
            if (subject && subject !== 'Not found') {
              // Use subject line, truncated if too long
              queryPreview = subject.length > 60 ? subject.substring(0, 60) + '...' : subject;
            } else if (from && from !== 'Not found') {
              // Fall back to from field if no subject
              const fromMatch = from.match(/<([^>]+)>/) || from.match(/([^\s<>]+@[^\s<>]+)/);
              if (fromMatch) {
                queryPreview = 'From: ' + fromMatch[1];
              } else {
                queryPreview = 'From: ' + (from.length > 40 ? from.substring(0, 40) + '...' : from);
              }
            }
          }
          
          addHistory({
            query: queryPreview,
            timestamp: Date.now(),
            domains: 1,
            duration: duration,
            success: true,
            recordTypes: ['Headers'],
            results: analysis,
            originalHeaders: this.headers  // Store original headers for rerun
          });
          
          if(window.dashboardInstance) window.dashboardInstance.refreshStats();
          
        } catch (error) {
          console.error('Header analysis failed:', error);
          this.error = error.message;
          
          addHistory({
            query: 'Email Headers Analysis (Failed)',
            timestamp: Date.now(),
            domains: 1,
            duration: 0,
            success: false,
            recordTypes: ['Headers']
          });
          
          if(window.dashboardInstance) window.dashboardInstance.refreshStats();
        } finally {
          this.loading = false;
        }
      },
      
      parseAuthenticationResults(headers) {
        const results = {
          spf: { status: 'unknown', details: '' },
          dkim: { status: 'unknown', details: '' }, 
          dmarc: { status: 'unknown', details: '' }
        };
        
        // Check for Authentication-Results header
        const authHeader = headers['authentication-results'];
        
        if (authHeader) {
          // Parse SPF result - updated regex to handle more formats
          const spfMatch = authHeader.match(/spf=(\w+)(?:\s+\(([^)]+)\))?/i);
          if (spfMatch) {
            results.spf.status = spfMatch[1];
            results.spf.details = spfMatch[2] || '';
          }
          
          // Parse DKIM result  
          const dkimMatch = authHeader.match(/dkim=(\w+)(?:\s+\(([^)]+)\))?/i);
          if (dkimMatch) {
            results.dkim.status = dkimMatch[1];
            results.dkim.details = dkimMatch[2] || '';
          }
          
          // Parse DMARC result
          const dmarcMatch = authHeader.match(/dmarc=(\w+)(?:\s+\(([^)]+)\))?/i);
          if (dmarcMatch) {
            results.dmarc.status = dmarcMatch[1];
            results.dmarc.details = dmarcMatch[2] || '';
          }
        }
        
        // Also check individual headers as fallback
        if (headers['received-spf'] && results.spf.status === 'unknown') {
          const spfMatch = headers['received-spf'].match(/(\w+)/);
          if (spfMatch) results.spf.status = spfMatch[1];
        }
        
        return results;
      },
      
      analyzeSecurityIndicators(headers) {
        const warnings = [];
        let suspicious = false;
        let tls = false;
        
        // Check for TLS usage in Received headers
        const receivedHeaders = Object.keys(headers)
          .filter(key => key.startsWith('received'))
          .map(key => headers[key])
          .join(' ');
        
        if (receivedHeaders.toLowerCase().includes('tls') || receivedHeaders.toLowerCase().includes('ssl')) {
          tls = true;
        }
        
        // Check for suspicious patterns
        const from = headers['from'] || '';
        const replyTo = headers['reply-to'] || '';
        const returnPath = headers['return-path'] || '';
        
        // Mismatched From and Reply-To
        if (replyTo && from && !replyTo.includes(from.split('@')[1]?.split('>')[0])) {
          warnings.push('Reply-To domain differs from From domain');
          suspicious = true;
        }
        
        // Suspicious subject patterns
        const subject = headers['subject'] || '';
        if (subject.match(/urgent|action required|verify|suspended|expire/i)) {
          warnings.push('Subject contains urgency indicators common in phishing');
          suspicious = true;
        }
        
        return {
          tls: tls,
          suspicious: suspicious,
          warnings: warnings,
          messageId: headers['message-id'] || 'Not found',
          returnPath: returnPath || 'Not found'
        };
      },
      
      parseDeliveryPath(headers) {
        const path = [];
        
        // Extract all Received headers
        Object.keys(headers).forEach(key => {
          if (key.startsWith('received')) {
            const value = headers[key];
            const serverMatch = value.match(/from\s+([^\s]+)/i);
            const timestampMatch = value.match(/;\s*(.+)$/);
            
            if (serverMatch) {
              path.push({
                server: serverMatch[1],
                timestamp: timestampMatch ? timestampMatch[1].trim() : 'Unknown'
              });
            }
          }
        });
        
        return path.reverse(); // Show in chronological order
      },
      
      exportResults(){ if(this.results) exportJSON(this.results, 'email_headers_analysis.json'); }
    };
  };
