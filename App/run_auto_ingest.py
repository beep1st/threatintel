# run_auto_ingest.py (in project root)
#!/usr/bin/env python
"""
Background service to auto-update threat feeds every 5 minutes
Run this with: python run_auto_ingest.py
"""
import os
import sys
import django
import time
import schedule
from datetime import datetime

# Add project to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threadintel.settings')
django.setup()

from django.core.management import call_command
from App.models import ThreatFeed

def run_ingestion():
    """Run feed ingestion"""
    try:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting feed ingestion...")
        
        # Run the ingestion command
        call_command('ingest_feed', limit=20)
        
        # Count total feeds
        count = ThreatFeed.objects.count()
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Ingestion complete. Total feeds: {count}")
        
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Error: {e}")

def main():
    """Main function to run the scheduler"""
    print("=" * 60)
    print("ThreatCluster Auto-Ingestion Service")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Schedule ingestion every 5 minutes
    schedule.every(5).minutes.do(run_ingestion)
    
    # Run once immediately
    run_ingestion()
    
    # Keep running
    print("\nService is running. Press Ctrl+C to stop.")
    print("Next update will be in 5 minutes...\n")
    
    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n" + "=" * 60)
        print("Service stopped by user")
        print(f"Stopped at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

if __name__ == "__main__":
    main() 