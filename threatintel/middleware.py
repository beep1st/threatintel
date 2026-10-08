# yourproject/middleware.py
from django.utils.deprecation import MiddlewareMixin
import threading
import requests
from datetime import datetime, timedelta

# Simple cache for project-level
GITHUB_CACHE = {
    'last_check': None,
    'etag': None,
    'last_modified': None
}

def check_github_updates():
    """Check if GitHub data has been updated"""
    url = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
    
    # Skip if checked recently (last 5 minutes)
    if GITHUB_CACHE['last_check'] and \
       (datetime.now() - GITHUB_CACHE['last_check']).seconds < 300:
        return False
    
    headers = {}
    if GITHUB_CACHE['etag']:
        headers['If-None-Match'] = GITHUB_CACHE['etag']
    if GITHUB_CACHE['last_modified']:
        headers['If-Modified-Since'] = GITHUB_CACHE['last_modified']
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        GITHUB_CACHE['last_check'] = datetime.now()
        
        if response.status_code == 304:
            return False  # No change
        
        if response.status_code == 200:
            # Update cache headers
            if 'ETag' in response.headers:
                GITHUB_CACHE['etag'] = response.headers['ETag']
            if 'Last-Modified' in response.headers:
                GITHUB_CACHE['last_modified'] = response.headers['Last-Modified']
            
            # You can process the data here or just return True
            data = response.json()
            # Optional: Store in a global variable or cache
            from django.core.cache import cache
            cache.set('github_threat_actors', data, 3600)
            
            return True  # Data was updated
            
    except:
        pass
    
    return False

class AutoUpdateMiddleware(MiddlewareMixin):
    """Project-level middleware for GitHub updates"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.update_checked = False
        
    def __call__(self, request):
        # Check for updates in background on first request
        if not self.update_checked:
            def background_check():
                check_github_updates()
            
            thread = threading.Thread(target=background_check)
            thread.daemon = True
            thread.start()
            self.update_checked = True
        
        response = self.get_response(request)
        return response