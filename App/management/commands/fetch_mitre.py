# App/management/commands/fetch_mitre.py
from django.core.management.base import BaseCommand
from App.views import fetch_mitre_data

class Command(BaseCommand):
    help = 'Fetch MITRE ATT&CK data from GitHub'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--domain',
            type=str,
            default='enterprise',
            choices=['enterprise', 'mobile', 'ics'],
            help='Domain to fetch (enterprise, mobile, ics)',
        )
    
    def handle(self, *args, **options):
        domain = options['domain']
        self.stdout.write(f"Fetching MITRE {domain} data from GitHub...")
        
        if fetch_mitre_data(domain):
            self.stdout.write(self.style.SUCCESS(f"Successfully fetched {domain} data"))
        else:
            self.stdout.write(self.style.ERROR(f"Failed to fetch {domain} data"))
