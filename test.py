# App/fix_duplicates.py
import os
import django
from django.conf import settings

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threatintel.settings')
django.setup()

from App.models import ThreatProfile
from django.db.models import Count

def find_and_fix_duplicates():
    print("=== FINDING AND FIXING DUPLICATE PROFILES ===")
    
    # Find duplicate profile names
    duplicates = ThreatProfile.objects.values('name').annotate(
        count=Count('id')
    ).filter(count__gt=1)
    
    print(f"Found {len(duplicates)} profiles with duplicates")
    
    fixed_count = 0
    deleted_count = 0
    
    for dup in duplicates:
        name = dup['name']
        print(f"\n Processing duplicates for: {name}")
        
        # Get all profiles with this name
        profiles = ThreatProfile.objects.filter(name=name).order_by('-id')
        
        # Keep the first one, delete the rest
        keeper = profiles[0]
        duplicates_to_delete = profiles[1:]
        
        print(f"   Keeping ID: {keeper.id} (most recent)")
        print(f"   Deleting {len(duplicates_to_delete)} duplicates")
        
        for duplicate in duplicates_to_delete:
            duplicate.delete()
            deleted_count += 1
        
        fixed_count += 1
    
    print(f"\nRESULTS:")
    print(f"Fixed {fixed_count} duplicate groups")
    print(f" Deleted {deleted_count} duplicate profiles")
    print(f"Total profiles now: {ThreatProfile.objects.count()}")
    
    return fixed_count

if __name__ == "__main__":
    find_and_fix_duplicates()