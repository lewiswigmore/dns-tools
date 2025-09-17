#!/usr/bin/env python3
"""
Modular Static Site Generator for DNSTools GitHub Pages Deployment
Converts Flask templates to static HTML files using modular content
"""

import os
import shutil
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

# No additional imports needed - using existing static files

def create_static_site():
    """Generate static HTML files from Flask templates"""
    
    # Setup paths
    base_dir = Path(__file__).parent
    templates_dir = base_dir / 'templates'
    static_dir = base_dir / 'static'
    dist_dir = base_dir / 'dist'
    
    # Clean and create dist directory (with error handling for Windows)
    if dist_dir.exists():
        try:
            shutil.rmtree(dist_dir)
            print("Cleaned existing dist directory")
        except PermissionError:
            print("Warning: Could not clean dist directory (files may be in use)")
            print("Continuing with existing directory...")
    
    if not dist_dir.exists():
        dist_dir.mkdir(parents=True)
    
    # Setup Jinja2 environment with Flask-like functions
    env = Environment(loader=FileSystemLoader(templates_dir))
    
    # Add url_for function for static site
    def url_for(endpoint, **values):
        """Map Flask endpoints to static file paths for GitHub Pages"""
        endpoint_map = {
            # Static files
            'static': 'static/',
            
            # Page endpoints (function names from Flask app)
            'index': 'index.html',
            'dashboard_page': 'dashboard.html',
            'lookup_page': 'lookup.html', 
            'mx_page': 'mx.html',
            'dmarc_page': 'dmarc.html',
            'headers_page': 'headers.html',
            'history_page': 'history.html',
            'resources_page': 'resources.html',
            
            # Route endpoints (URL paths from Flask app) 
            'dashboard': 'dashboard.html',
            'lookup': 'lookup.html',
            'mx': 'mx.html',
            'dmarc': 'dmarc.html', 
            'headers': 'headers.html',
            'history': 'history.html',
            'resources': 'resources.html',
            
            # Legacy Blueprint-style endpoints (for compatibility)
            'main.index': 'index.html',
            'main.lookup': 'lookup.html',
            'main.mx': 'mx.html',
            'main.dmarc': 'dmarc.html',
            'main.headers': 'headers.html',
            'main.history': 'history.html',
            'main.dashboard': 'dashboard.html',
            'main.resources': 'resources.html',
            
            # API endpoints (will be handled client-side)
            'api.lookup': '/api/lookup',
            'api.mx': '/api/mx',
            'api.dmarc': '/api/dmarc',
            'api.headers': '/api/headers',
        }
        
        if endpoint == 'static':
            filename = values.get('filename', '')
            return f'static/{filename}'
        
        return endpoint_map.get(endpoint, f'{endpoint}.html')
    
    # Add the url_for function to Jinja2 environment
    env.globals['url_for'] = url_for
    
    # Copy static assets
    if static_dir.exists():
        shutil.copytree(static_dir, dist_dir / 'static', dirs_exist_ok=True)
        print("Copied static assets")
    
    # Pages to generate
    pages = {
        'index.html': 'dashboard.html',  # Home page uses dashboard template (matches Flask behavior)
        'lookup.html': 'lookup.html', 
        'mx.html': 'mx.html',
        'dmarc.html': 'dmarc.html', 
        'headers.html': 'headers.html',
        'history.html': 'history.html',
        'dashboard.html': 'dashboard.html',
        'resources.html': 'resources.html'
    }
    
    # Generate each page
    for output_file, template_name in pages.items():
        try:
            template = env.get_template(template_name)
            
            # Render with any context needed
            context = {}
            if template_name == 'resources.html':
                # Add any specific context for resources page if needed
                context['resource_categories'] = [
                    'DNS Record Types',
                    'Email Security'
                ]
            
            html_content = template.render(**context)
            
            output_path = dist_dir / output_file
            output_path.write_text(html_content, encoding='utf-8')
            print(f"Generated: {output_file}")
            
        except Exception as e:
            print(f"Error generating {output_file}: {e}")
            continue
    
    # Create .nojekyll file to disable Jekyll processing
    (dist_dir / '.nojekyll').touch()
    print("Created .nojekyll file")
    
    # Create client-side API replacements
    create_client_side_apis(dist_dir)
    
    print(f"\\nStatic site generated in: {dist_dir}")
    print("Ready for GitHub Pages deployment!")

def create_client_side_apis(dist_dir):
    """Create client-side replacements for Flask API endpoints"""
    
    # The existing app.js already has all the resources content and components
    # Static files (including app.js) are already copied in the main function
    print("Using existing app.js with comprehensive resources content")
    print("Static site ready for GitHub Pages deployment")

if __name__ == '__main__':
    try:
        create_static_site()
        print("\\n✅ Static site generation completed successfully!")
    except Exception as e:
        print(f"\\n❌ Error during static site generation: {e}")
        import traceback
        traceback.print_exc()