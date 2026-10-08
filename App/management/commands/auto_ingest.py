# App/management/commands/auto_ingest.py
import schedule
import time
import threading
from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.utils import timezone

class Command(BaseCommand):
    help = 'Start automatic feed ingestion scheduler'
    
    def add_arguments(self, parser):
        parser.add_argument('--interval', type=int, default=5,
                          help='Update interval in minutes (default: 5)')
    
    def handle(self, *args, **options):
        interval = options['interval']
        
        self.stdout.write(self.style.SUCCESS(
            f'Starting automatic feed ingestion scheduler (interval: {interval} minutes)'
        ))
        
        # Schedule the ingestion command
        schedule.every(interval).minutes.do(self.run_ingestion)
        
        # Run once immediately
        self.run_ingestion()
        
        # Keep the scheduler running
        while True:
            try:
                schedule.run_pending()
                time.sleep(1)
            except KeyboardInterrupt:
                self.stdout.write(self.style.WARNING('Stopping scheduler...'))
                break
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'Scheduler error: {e}'))
                time.sleep(60)
    
    def run_ingestion(self):
        """Run the ingestion command"""
        try:
            self.stdout.write(f'{timezone.now().strftime("%H:%M:%S")} - Running feed ingestion...')
            call_command('ingest_feed', limit=20)
            self.stdout.write(self.style.SUCCESS(
                f'{timezone.now().strftime("%H:%M:%S")} - Ingestion completed'
            ))
        except Exception as e:
            self.stdout.write(self.style.ERROR(
                f'{timezone.now().strftime("%H:%M:%S")} - Ingestion failed: {e}'
            ))