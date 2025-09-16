import re
import json
import logging
import asyncio
import aiohttp
import os
from urllib.parse import quote
from flask import Flask, render_template, request, jsonify, session
from concurrent.futures import ThreadPoolExecutor
import time
from datetime import datetime, timedelta
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Use environment variable for secret key in production, fallback for development
app.secret_key = os.environ.get('SECRET_KEY', 'dns-intelligence-platform-secret-key-change-in-production')
if app.secret_key == 'dns-intelligence-platform-secret-key-change-in-production':
    logger.warning('Using default development SECRET_KEY; set environment variable SECRET_KEY for production security and stable sessions.')

# Security headers
@app.after_request
def after_request(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self' https://dns.google https://cdn.jsdelivr.net;"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Production configuration
if os.environ.get('FLASK_ENV') == 'production':
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Simple rate limiting without quotas (prevent spam)
def simple_rate_limit():
    """Simple rate limiting to prevent spam"""
    try:
        client_id = f"{request.remote_addr}_{session.get('client_id', 'anonymous')}"
        now = datetime.now()
        
        # Get or create rate limit data
        if 'rate_limit' not in session:
            session['rate_limit'] = {'last_request': now.isoformat(), 'count': 0}
        
        rate_data = session['rate_limit']
        last_request = datetime.fromisoformat(rate_data['last_request'])
        
        # Reset if more than 1 minute passed
        if (now - last_request).total_seconds() > 60:
            rate_data['count'] = 0
            
        rate_data['count'] += 1
        rate_data['last_request'] = now.isoformat()
        session.modified = True
        
        # Allow max 10 requests per minute
        if rate_data['count'] > 10:
            return False, "Too many requests. Please wait a moment."
            
        return True, None
    except Exception as e:
        logger.error(f"Error in rate limiting: {str(e)}")
        return True, None  # Allow request if rate limiting fails

# NOTE: Removed a duplicate 'app = Flask(__name__)' which previously overwrote the configured
# secret_key and caused session errors ("session is unavailable"), breaking quota tracking.

class DNSLookup:
    """DNS lookup service using Google DNS API"""
    
    def __init__(self):
        self.base_url = "https://dns.google/resolve"
        self.session_timeout = aiohttp.ClientTimeout(total=10)
        
    def normalize_domain(self, domain):
        """
        Normalize domain input by removing common prefixes, cleaning, and handling obfuscation
        Strict validation to prevent invalid domains and potential security issues
        """
        if not domain or not isinstance(domain, str):
            return None
            
        # Store original for reference
        original_domain = domain
        
        # Remove whitespace and convert to lowercase
        domain = domain.strip().lower()
        
        # Handle obfuscated domains first
        domain = self.deobfuscate_domain(domain)
        
        # Remove http/https prefixes
        domain = re.sub(r'^https?://', '', domain)
        
        # Remove www prefix
        domain = re.sub(r'^www\.', '', domain)
        
        # Remove trailing slashes and paths
        domain = domain.split('/')[0]
        
        # Remove port numbers
        domain = domain.split(':')[0]
        
        # Basic security checks - reject obvious non-domains
        if not domain or len(domain) < 3:
            return None
            
        # Must contain at least one dot (TLD requirement)
        if '.' not in domain:
            return None
            
        # Reject domains that are just numbers or single characters
        if domain.replace('.', '').isdigit():
            return None
            
        # Check for minimum valid domain structure (at least domain.tld)
        parts = domain.split('.')
        if len(parts) < 2:
            return None
            
        # Each part must be valid
        for part in parts:
            if not part or len(part) == 0:
                return None
            # Must start and end with alphanumeric
            if not (part[0].isalnum() and part[-1].isalnum()):
                return None
        
        # TLD (last part) must be at least 2 characters and alphabetic
        tld = parts[-1]
        if len(tld) < 2 or not tld.isalpha():
            return None
            
        # Domain name (second to last) must be at least 1 character
        if len(parts) >= 2 and len(parts[-2]) < 1:
            return None
        
        # Validate overall domain format with stricter regex
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        
        if not re.match(domain_pattern, domain):
            return None
            
        # Additional security: reject domains with suspicious patterns
        suspicious_patterns = [
            r'localhost',
            r'127\.0\.0\.1',
            r'0\.0\.0\.0',
            r'::1',
            r'file://',
            r'ftp://',
            r'javascript:',
            r'data:',
            r'vbscript:',
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain, re.IGNORECASE):
                return None
            
        return domain
    
    def deobfuscate_domain(self, domain):
        """
        Remove common obfuscation patterns used in threat intelligence
        """
        if not domain:
            return domain
            
        # Replace common obfuscation patterns
        domain = domain.replace('[.]', '.')  # Replace [.] with .
        domain = domain.replace('[dot]', '.')  # Replace [dot] with .
        domain = domain.replace('(.)', '.')  # Replace (.) with .
        domain = domain.replace('{.}', '.')  # Replace {.} with .
        domain = re.sub(r'hxxp', 'http', domain, flags=re.IGNORECASE)  # Replace hxxp with http
        domain = re.sub(r'hXXp', 'http', domain, flags=re.IGNORECASE)  # Replace hXXp with http
        domain = re.sub(r'meow://', 'http://', domain, flags=re.IGNORECASE)  # Replace meow:// with http://
        domain = domain.replace('[@]', '@')  # Replace [@] with @
        domain = re.sub(r'\[at\]', '@', domain, flags=re.IGNORECASE)  # Replace [at] with @
        domain = domain.replace('(:)', ':')  # Replace (:) with :
        domain = re.sub(r'\[colon\]', ':', domain, flags=re.IGNORECASE)  # Replace [colon] with :
        domain = domain.replace('[/]', '/')  # Replace [/] with /
        domain = domain.replace('\\/', '/')  # Replace \/ with /
        domain = domain.replace('[\\]', '\\')  # Replace [\] with \
        
        return domain
    
    def normalize_domains(self, domains_input, threat_intel_mode=False):
        """
        Parse and normalize multiple domains from various input formats
        """
        if not domains_input:
            return []
            
        # Split by common delimiters: newlines, commas, semicolons, spaces
        domains = re.split(r'[,;\n\r\s]+', domains_input)
        
        normalized = []
        for domain in domains:
            original_domain = domain.strip()
            normalized_domain = self.normalize_domain(domain)
            if normalized_domain and normalized_domain not in [d['domain'] for d in normalized]:
                normalized.append({
                    'domain': normalized_domain,
                    'original': original_domain if original_domain != normalized_domain else None
                })
                
        return normalized
    
    async def fetch_dns_record(self, session, domain, record_type='A'):
        """
        Fetch DNS record for a single domain
        """
        try:
            url = f"{self.base_url}?name={quote(domain)}&type={record_type}"
            
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'domain': domain,
                        'type': record_type,
                        'status': 'success',
                        'data': data,
                        'records': self._extract_records(data, record_type)
                    }
                else:
                    return {
                        'domain': domain,
                        'type': record_type,
                        'status': 'error',
                        'error': f"HTTP {response.status}",
                        'records': []
                    }
                    
        except Exception as e:
            logger.error(f"Error fetching DNS for {domain}: {str(e)}")
            return {
                'domain': domain,
                'type': record_type,
                'status': 'error',
                'error': str(e),
                'records': []
            }
    
    def _extract_records(self, dns_data, record_type):
        """
        Extract relevant records from DNS response
        """
        records = []
        
        if 'Answer' in dns_data:
            for answer in dns_data['Answer']:
                if answer.get('type') == self._get_record_type_number(record_type):
                    records.append({
                        'value': answer.get('data', ''),
                        'ttl': answer.get('TTL', 0)
                    })
        
        return records
    
    def _get_record_type_number(self, record_type):
        """
        Convert record type string to number
        """
        type_mapping = {
            'A': 1,
            'AAAA': 28,
            'CNAME': 5,
            'MX': 15,
            'TXT': 16,
            'NS': 2
        }
        return type_mapping.get(record_type.upper(), 1)
    
    async def lookup_domains_async(self, domain_objects, record_types=['A']):
        """
        Perform DNS lookups for multiple domains asynchronously
        """
        async with aiohttp.ClientSession(timeout=self.session_timeout) as session:
            tasks = []
            
            for domain_obj in domain_objects:
                domain = domain_obj['domain']
                for record_type in record_types:
                    task = self.fetch_dns_record(session, domain, record_type)
                    tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Group results by domain
            domain_results = {}
            for result in results:
                if isinstance(result, dict):
                    domain = result['domain']
                    if domain not in domain_results:
                        # Find original domain
                        original = None
                        for domain_obj in domain_objects:
                            if domain_obj['domain'] == domain:
                                original = domain_obj.get('original')
                                break
                        
                        domain_results[domain] = {
                            'domain': domain,
                            'original': original,
                            'records': {},
                            'status': 'success',
                            'errors': []
                        }
                    
                    record_type = result['type']
                    if result['status'] == 'success':
                        domain_results[domain]['records'][record_type] = result['records']
                    else:
                        domain_results[domain]['errors'].append(f"{record_type}: {result.get('error', 'Unknown error')}")
                        if not domain_results[domain]['records']:
                            domain_results[domain]['status'] = 'error'
            
            return list(domain_results.values())

# Initialize DNS lookup service
dns_service = DNSLookup()

@app.route('/')
def index():
    """Redirect root to dashboard page (multi-page layout)."""
    return render_template('dashboard.html', active_page='dashboard')

@app.route('/dashboard')
def dashboard_page():
    return render_template('dashboard.html', active_page='dashboard')

@app.route('/lookup')
def lookup_page():
    return render_template('lookup.html', active_page='lookup')

@app.route('/mx')
def mx_page():
    return render_template('mx.html', active_page='mx')

@app.route('/dmarc')
def dmarc_page():
    return render_template('dmarc.html', active_page='dmarc')

@app.route('/headers')
def headers_page():
    return render_template('headers.html', active_page='headers')

@app.route('/history')
def history_page():
    return render_template('history.html', active_page='history')

@app.route('/resources')
def resources_page():
    return render_template('resources.html', active_page='resources')

# SPF and Intel routes removed - locked access in navigation

@app.route('/api/test', methods=['GET'])
def test_endpoint():
    """Test endpoint to check if rate limiting works"""
    try:
        allowed, message = simple_rate_limit()
        return jsonify({'status': 'success', 'allowed': allowed, 'message': message})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/api/lookup', methods=['POST'])
def lookup_domains():
    """API endpoint for DNS lookup with simple rate limiting"""
    try:
        # Check rate limit
        allowed, message = simple_rate_limit()
        if not allowed:
            return jsonify({'error': message}), 429
            
        data = request.get_json()
        domains_input = data.get('domains', '')
        record_types = data.get('record_types', ['A'])
        threat_intel_mode = data.get('threat_intel_mode', False)
        
        if not domains_input:
            return jsonify({'error': 'No domains provided'}), 400
        
        # Normalize domains
        domain_objects = dns_service.normalize_domains(domains_input, threat_intel_mode)
        
        if not domain_objects:
            return jsonify({'error': 'No valid domains found'}), 400
        
        # Perform DNS lookups
        start_time = time.time()
        results = asyncio.run(dns_service.lookup_domains_async(domain_objects, record_types))
        end_time = time.time()
        
        return jsonify({
            'success': True,
            'results': results,
            'stats': {
                'total_domains': len(domain_objects),
                'lookup_time': round(end_time - start_time, 2),
                'domains_processed': len(results),
                'threat_intel_mode': threat_intel_mode
            }
        })
        
    except Exception as e:
        logger.error(f"Error in lookup_domains: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/quota', methods=['GET'])
def get_quota_status():
    """Removed - quota system no longer used"""
    return jsonify({'message': 'Quota system removed'}), 410

@app.route('/health')
def health_check():
    """Health check endpoint for Azure Web App"""
    return jsonify({'status': 'healthy', 'timestamp': time.time()})

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors for API routes"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'API endpoint not found'}), 404
    return render_template('dashboard.html', active_page='dashboard')

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors for API routes"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('dashboard.html', active_page='dashboard')

# --- Additional API endpoints for separated pages ---
@app.route('/api/mx', methods=['POST'])
def api_mx_lookup():
    try:
        # Check rate limit
        allowed, message = simple_rate_limit()
        if not allowed:
            return jsonify({'error': message}), 429
            
        data = request.get_json() or {}
        domain = data.get('domain','').strip()
        if not domain:
            return jsonify({'error':'Domain required'}), 400
        norm = dns_service.normalize_domain(domain)
        if not norm:
            return jsonify({'error':'Invalid domain'}), 400
            
        # Fetch MX (type 15)
        async def fetch_mx():
            async with aiohttp.ClientSession(timeout=dns_service.session_timeout) as s:
                url = f"{dns_service.base_url}?name={norm}&type=MX"
                async with s.get(url) as r:
                    if r.status!=200:
                        return []
                    jd = await r.json()
                    recs = []
                    for ans in jd.get('Answer', []) or []:
                        if ans.get('type') == 15:
                            # MX data like '10 mail.example.com.' -> split priority
                            parts = ans.get('data','').split()
                            if len(parts) >= 2:
                                priority = parts[0]
                                exchange = parts[1].rstrip('.')
                                recs.append({'priority': priority, 'exchange': exchange})
                    return recs
        records = asyncio.run(fetch_mx())
        return jsonify({'records': records})
    except Exception as e:
        logger.error(f"/api/mx error: {e}")
        return jsonify({'error': 'MX lookup failed'}), 500

@app.route('/api/dmarc', methods=['POST'])
def api_dmarc_lookup():
    try:
        # Check rate limit
        allowed, message = simple_rate_limit()
        if not allowed:
            return jsonify({'error': message}), 429
            
        data = request.get_json() or {}
        domain = data.get('domain','').strip()
        if not domain:
            return jsonify({'error':'Domain required'}), 400
        norm = dns_service.normalize_domain(domain)
        if not norm:
            return jsonify({'error':'Invalid domain'}), 400
        # DMARC record is TXT at _dmarc.domain
        dmarc_host = f"_dmarc.{norm}"
        
        async def fetch_txt():
            async with aiohttp.ClientSession(timeout=dns_service.session_timeout) as s:
                url = f"{dns_service.base_url}?name={dmarc_host}&type=TXT"
                async with s.get(url) as r:
                    if r.status!=200:
                        return None
                    jd = await r.json()
                    for ans in jd.get('Answer', []) or []:
                        if ans.get('type') == 16:  # TXT
                            raw = ans.get('data','').strip('"')
                            return raw
                    return None
        raw_record = asyncio.run(fetch_txt())
        result = None
        if raw_record and raw_record.lower().startswith('v=dmarc1'):
            # Parse policy key=value; pairs
            parts = [p.strip() for p in raw_record.split(';') if p.strip()]
            kv = {}
            for p in parts:
                if '=' in p:
                    k,v = p.split('=',1)
                    kv[k.lower()] = v
            result = {
                'raw': raw_record,
                'policy': kv.get('p'),
                'adkim': kv.get('adkim'),
                'aspf': kv.get('aspf')
            }
        return jsonify({'result': result})
    except Exception as e:
        logger.error(f"/api/dmarc error: {e}")
        return jsonify({'error': 'DMARC lookup failed'}), 500

@app.route('/api/headers', methods=['POST'])
def api_headers_analysis():
    try:
        # Check rate limit
        allowed, message = simple_rate_limit()
        if not allowed:
            return jsonify({'error': message}), 429
            
        data = request.get_json() or {}
        headers = data.get('headers','').strip()
        if not headers:
            return jsonify({'error':'Headers required'}), 400
            
        # Basic header analysis
        results = {
            'spf': {'status': 'unknown', 'details': ''},
            'dkim': {'status': 'unknown', 'details': ''},
            'dmarc': {'status': 'unknown', 'details': ''},
            'delivery_path': [],
            'security': {
                'tls': False,
                'suspicious': False,
                'delay': False,
                'warnings': []
            }
        }
        
        # Parse headers into a structured format
        header_dict = {}
        current_header = None
        current_value = ""
        
        lines = headers.split('\n')
        for line in lines:
            if line and not line[0].isspace():  # New header
                if current_header:
                    header_dict[current_header.lower()] = current_value.strip()
                if ':' in line:
                    current_header, current_value = line.split(':', 1)
                    current_header = current_header.strip()
                    current_value = current_value.strip()
                else:
                    current_header = None
                    current_value = ""
            elif current_header and line:  # Continuation line
                current_value += " " + line.strip()
        
        # Don't forget the last header
        if current_header:
            header_dict[current_header.lower()] = current_value.strip()
        
        # Parse Authentication-Results and ARC-Authentication-Results
        auth_headers = []
        for key, value in header_dict.items():
            if 'authentication-results' in key:
                auth_headers.append(value)
        
        # Extract authentication results
        for auth_result in auth_headers:
            auth_lower = auth_result.lower()
            
            # SPF parsing
            if 'spf=' in auth_lower:
                spf_match = re.search(r'spf=(\w+)', auth_lower)
                if spf_match:
                    results['spf']['status'] = spf_match.group(1)
                    # Extract additional SPF details
                    spf_details = re.search(r'spf=\w+[^;]*', auth_result, re.IGNORECASE)
                    if spf_details:
                        results['spf']['details'] = spf_details.group(0)
            
            # DKIM parsing
            if 'dkim=' in auth_lower:
                dkim_match = re.search(r'dkim=(\w+)', auth_lower)
                if dkim_match:
                    results['dkim']['status'] = dkim_match.group(1)
                    # Extract DKIM details
                    dkim_details = re.search(r'dkim=\w+[^;]*', auth_result, re.IGNORECASE)
                    if dkim_details:
                        results['dkim']['details'] = dkim_details.group(0)
            
            # DMARC parsing
            if 'dmarc=' in auth_lower:
                dmarc_match = re.search(r'dmarc=(\w+)', auth_lower)
                if dmarc_match:
                    results['dmarc']['status'] = dmarc_match.group(1)
                    # Extract DMARC details
                    dmarc_details = re.search(r'dmarc=\w+[^;)]*', auth_result, re.IGNORECASE)
                    if dmarc_details:
                        results['dmarc']['details'] = dmarc_details.group(0)
        
        # Parse delivery path from Received headers
        received_headers = []
        for key, value in header_dict.items():
            if key == 'received':
                received_headers.append(value)
            elif key.startswith('received'):
                received_headers.append(value)
        
        # Process Received headers in reverse order (latest first)
        for received in received_headers:
            server_match = re.search(r'from\s+([^\s\[\(]+)', received)
            time_match = re.search(r';\s*(.+)$', received)
            by_match = re.search(r'by\s+([^\s\[\(]+)', received)
            
            server_name = "unknown"
            if server_match:
                server_name = server_match.group(1).strip('.')
                # Clean up common patterns
                server_name = re.sub(r'^([^.]+\.)*', '', server_name)  # Remove subdomain prefixes
                if server_name == "localhost" or server_name.startswith("127."):
                    server_name = by_match.group(1).strip('.') if by_match else "localhost"
            
            results['delivery_path'].append({
                'server': server_name,
                'timestamp': time_match.group(1).strip() if time_match else 'unknown'
            })
            
            # Check for TLS/security
            if 'with esmtps' in received.lower() or 'with tls' in received.lower() or 'tls' in received.lower():
                results['security']['tls'] = True
        
        # Security analysis
        suspicious_patterns = []
        
        # Check for authentication failures
        if results['spf']['status'] == 'fail':
            suspicious_patterns.append('SPF authentication failed')
        if results['dkim']['status'] == 'fail':
            suspicious_patterns.append('DKIM authentication failed')
        if results['dmarc']['status'] == 'fail':
            suspicious_patterns.append('DMARC authentication failed')
        
        # Check for suspicious domains in delivery path
        suspicious_domains = ['.xyz', '.tk', '.ml', '.ga', '.cf']
        for hop in results['delivery_path']:
            for suspicious_tld in suspicious_domains:
                if suspicious_tld in hop['server'].lower():
                    suspicious_patterns.append(f'Suspicious domain in delivery path: {hop["server"]}')
                    break
        
        # Check for mismatched From/Reply-To
        from_header = header_dict.get('from', '')
        reply_to_header = header_dict.get('reply-to', '')
        if from_header and reply_to_header:
            from_domain = re.search(r'@([^>\s]+)', from_header)
            reply_domain = re.search(r'@([^>\s]+)', reply_to_header)
            if from_domain and reply_domain and from_domain.group(1) != reply_domain.group(1):
                suspicious_patterns.append(f'From/Reply-To domain mismatch: {from_domain.group(1)} vs {reply_domain.group(1)}')
        
        # Check for old/suspicious mailers
        x_mailer = header_dict.get('x-mailer', '').lower()
        if 'phpmailer' in x_mailer and ('5.' in x_mailer or '4.' in x_mailer):
            suspicious_patterns.append('Outdated PHPMailer version detected')
        
        results['security']['warnings'] = suspicious_patterns
        results['security']['suspicious'] = len(suspicious_patterns) > 0
        
        return jsonify({'results': results})
    except Exception as e:
        logger.error(f"/api/headers error: {e}")
        return jsonify({'error': 'Header analysis failed'}), 500

if __name__ == '__main__':
    # Development server
    app.run(debug=True, host='0.0.0.0', port=5000)