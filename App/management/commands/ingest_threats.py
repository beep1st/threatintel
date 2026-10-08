# management/commands/ingest_threats.py
from django.core.management.base import BaseCommand
from App.ingest_feed import ( 
    ingest_urls,
    ingest_malware,
    ingest_ips,
    ingest_cves
    
)
from django.utils import timezone

class Command(BaseCommand):
    help = 'Ingest threat intelligence data from all sources'

    def handle(self, *args, **options):
        print("Starting threat intelligence ingestion...")
        
        # Track timing
        start_time = timezone.now()
        print(f"Start time: {start_time}")
        
        total_created = 0
        
        print("\n" + "="*60)
        print("1. INGESTING URLs (50 per refresh)")
        print("="*60)
        urls_created = ingest_urls()
        total_created += urls_created
        print(f"✅ URLs created: {urls_created}")
        
        print("\n" + "="*60)
        print("2. INGESTING MALWARE (100 max)")
        print("="*60)
        malware_created = ingest_malware()
        total_created += malware_created
        print(f"✅ Malware samples created: {malware_created}")
        
        print("\n" + "="*60)
        print("3. INGESTING IPs")
        print("="*60)
        ips_created = ingest_ips()
        total_created += ips_created
        print(f"✅ IPs created: {ips_created}")
        
        print("\n" + "="*60)
        print("4. INGESTING CVEs (2025 ONLY)")
        print("="*60)
        cves_created = ingest_cves()
        total_created += cves_created
        print(f"✅ CVEs created: {cves_created}")
        
        # REMOVED: Threat library population
        # No longer calling populate_threat_library()
        
        # Calculate time taken
        end_time = timezone.now()
        time_taken = end_time - start_time
        
        print("\n" + "="*60)
        self.stdout.write(self.style.SUCCESS(
            f'✅ INGESTION COMPLETE\n'
            f'📊 Summary:\n'
            f'   • URLs: {urls_created}\n'
            f'   • Malware: {malware_created}\n'
            f'   • IPs: {ips_created}\n'
            f'   • CVEs (2025): {cves_created}\n'
            f'   • Total: {total_created} records\n'
            f'⏱️  Time taken: {time_taken.total_seconds():.1f} seconds\n'
            f'🔄 Focused on 2025 CVEs only (no threat actors)'
        ))