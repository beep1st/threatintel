# utils.py
import requests
from django.utils import timezone
from datetime import timedelta
from .models import ThreatActor, GitHubUpdate

def check_and_update_threat_actors():
    """
    Check GitHub for updates and update if changed
    This should be called on every page load or via middleware
    """
    
    # Get last update info
    update_info, created = GitHubUpdate.objects.get_or_create(id=1)
    
    # Check if we checked recently (e.g., in last 5 minutes)
    if not created and (timezone.now() - update_info.last_check) < timedelta(minutes=5):
        return False  # Skip check, too recent
        
    url = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
    
    # Use headers to check for changes
    headers = {}
    if update_info.etag:
        headers['If-None-Match'] = update_info.etag
    if update_info.last_modified:
        headers['If-Modified-Since'] = update_info.last_modified
    
    try:
        response = requests.get(url, headers=headers)
        
        # Update last check time
        update_info.last_check = timezone.now()
        
        # If not modified (304), do nothing
        if response.status_code == 304:
            update_info.save()
            return False
            
        # If modified (200), update data
        if response.status_code == 200:
            data = response.json()
            actors = data.get('values', [])
            
            # Update or create all actors
            for actor in actors:
                ThreatActor.objects.update_or_create(
                    uuid=actor.get('uuid'),
                    defaults={
                        'name': actor.get('value', ''),
                        'description': actor.get('description', ''),
                        'data': actor
                    }
                )
            
            # Save ETag and Last-Modified for next time
            if 'ETag' in response.headers:
                update_info.etag = response.headers['ETag']
            if 'Last-Modified' in response.headers:
                update_info.last_modified = response.headers['Last-Modified']
            
            update_info.save()
            return True  # Data was updated
            
    except Exception as e:
        print(f"Error checking updates: {e}")
        return False