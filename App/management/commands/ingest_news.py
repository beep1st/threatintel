# App/management/commands/ingest_feed.py (Updated)
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.conf import settings
import feedparser
import requests
from bs4 import BeautifulSoup
from App.models import ThreatFeed
import re
from dateutil import parser as date_parser
import hashlib
import json
from datetime import datetime, timedelta
import os

class FeedIngestionManager:
    """Manages automatic feed ingestion"""
    
    def __init__(self, auto_update=True):
        self.auto_update = auto_update
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.state_file = os.path.join(settings.BASE_DIR, 'feed_state.json')
        self.load_state()
    
    def load_state(self):
        """Load ingestion state from file"""
        try:
            if os.path.exists(self.state_file):
                with open(self.state_file, 'r') as f:
                    self.state = json.load(f)
            else:
                self.state = {
                    'last_run': None,
                    'feed_stats': {},
                    'last_article_times': {}
                }
        except:
            self.state = {
                'last_run': None,
                'feed_stats': {},
                'last_article_times': {}
            }
    
    def save_state(self):
        """Save ingestion state to file"""
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self.state, f, indent=2)
        except:
            pass
    
    def should_update_feed(self, feed_url, min_interval_minutes=5):
        """Check if we should update this feed based on last run time"""
        if not self.auto_update:
            return True
        
        last_run = self.state.get('last_run')
        if not last_run:
            return True
        
        last_run_time = datetime.fromisoformat(last_run)
        return (timezone.now() - last_run_time).seconds >= (min_interval_minutes * 60)
    
    def get_last_article_time(self, feed_url):
        """Get timestamp of last article from this feed"""
        return self.state.get('last_article_times', {}).get(feed_url)
    
    def update_last_article_time(self, feed_url, article_time):
        """Update timestamp of last article from this feed"""
        if 'last_article_times' not in self.state:
            self.state['last_article_times'] = {}
        self.state['last_article_times'][feed_url] = article_time.isoformat()
    
    def update_feed_stats(self, feed_url, new_count, updated_count):
        """Update statistics for this feed"""
        if 'feed_stats' not in self.state:
            self.state['feed_stats'] = {}
        
        if feed_url not in self.state['feed_stats']:
            self.state['feed_stats'][feed_url] = {'new': 0, 'updated': 0}
        
        self.state['feed_stats'][feed_url]['new'] += new_count
        self.state['feed_stats'][feed_url]['updated'] += updated_count
    
    def get_feed_stats(self, feed_url):
        """Get statistics for this feed"""
        return self.state.get('feed_stats', {}).get(feed_url, {'new': 0, 'updated': 0})

def clean_date_str(s):
    """Clean date string for storage"""
    if not s:
        return ''
    try:
        s = s.strip()
        s = ' '.join(s.split())
        return s[:200]
    except:
        return ''

def parse_to_datetime(pub_str):
    """Parse cleaned string to timezone-aware datetime"""
    if not pub_str:
        return timezone.now()
    try:
        dt = date_parser.parse(pub_str, fuzzy=True)
        if dt.tzinfo is None:
            dt = timezone.make_aware(dt)
        return dt
    except Exception:
        return timezone.now()

def generate_content_hash(entry):
    """Generate a hash from entry content to detect changes"""
    content_parts = [
        entry.get('title', ''),
        entry.get('summary', ''),
        entry.get('description', ''),
        entry.get('content', [{}])[0].get('value', '') if entry.get('content') else '',
        entry.get('author', ''),
    ]
    content_string = ''.join(str(part) for part in content_parts if part)
    return hashlib.md5(content_string.encode()).hexdigest()

class Command(BaseCommand):
    help = 'Ingest threat intelligence feeds with automatic updates'
    
    def add_arguments(self, parser):
        parser.add_argument('--interval', type=int, default=5, 
                          help='Auto-update interval in minutes (default: 5)')
        parser.add_argument('--limit', type=int, default=20, 
                          help='Max items per source (default: 20)')
        parser.add_argument('--force', action='store_true', 
                          help='Force update regardless of interval')
        parser.add_argument('--continuous', action='store_true',
                          help='Run continuously with specified interval')
    
    def handle(self, *args, **options):
        interval = options['interval']
        limit = options['limit']
        force = options['force']
        continuous = options['continuous']
        
        if continuous:
            self.stdout.write(self.style.SUCCESS(
                f'Starting continuous feed ingestion (interval: {interval} minutes)'
            ))
            self.run_continuous(interval, limit)
        else:
            self.run_once(limit, force, interval)
    
    def run_continuous(self, interval_minutes, limit):
        """Run ingestion continuously with specified interval"""
        import time
        
        while True:
            try:
                self.run_once(limit, False, interval_minutes)
                self.stdout.write(self.style.SUCCESS(
                    f'Waiting {interval_minutes} minutes before next update...'
                ))
                time.sleep(interval_minutes * 60)
            except KeyboardInterrupt:
                self.stdout.write(self.style.WARNING('Stopping continuous ingestion...'))
                break
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'Error in continuous run: {e}'))
                time.sleep(60)  # Wait 1 minute before retry
    
    def run_once(self, limit, force=False, interval_minutes=5):
        """Run a single ingestion cycle"""
        manager = FeedIngestionManager(auto_update=not force)
        
        if not force and not manager.should_update_feed('all_feeds', interval_minutes):
            self.stdout.write(self.style.WARNING(
                f'Skipping update - last run was less than {interval_minutes} minutes ago'
            ))
            return
        
        self.stdout.write(self.style.SUCCESS('Starting feed ingestion...'))
        
        # Update last run time
        manager.state['last_run'] = timezone.now().isoformat()
        
        total_new = 0
        total_updated = 0
        
        # RSS Vendors
        vendor_feeds = [
            'https://any.run/cybersecurity-blog/feed/',
            'https://www.theregister.com/headlines.atom',
            'https://www.huntress.com/blog/rss.xml',
            'https://www.nextron-systems.com/feed/',
            'https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/',
            'https://www.crowdstrike.com/en-us/blog/feed',
            'https://securelist.com/feed/',
            'https://unit42.paloaltonetworks.com/feed/',
            'https://blog.talosintelligence.com/rss/',
            'https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml',
            'https://www.malwarebytes.com/blog/feed/index.xml',
        ]
        new, updated = self._ingest_rss_batch(vendor_feeds, 'rss_vendor', limit, manager, 'Vendor Feeds')
        total_new += new
        total_updated += updated
        
        # RSS News
        news_feeds = [
            'https://linuxsecurity.com/linuxsecurity_articles.xml',
            'https://thecyberexpress.com/feed/',
            'https://www.nextgov.com/rss/cybersecurity/',
            'https://cyberscoop.com/feed/',
            'https://therecord.media/news/cybercrime/feed',
            'https://www.theregister.com/security/headlines.atom',
            'https://feeds.feedburner.com/TheHackersNews',
            'https://www.bleepingcomputer.com/feed/',
            'https://www.darkreading.com/rss.xml',
            'https://securityaffairs.com/feed',
            'https://krebsonsecurity.com/feed/',
            'https://www.securityweek.com/feed/',
            'https://hackread.com/feed/',
        ]
        new, updated = self._ingest_rss_batch(news_feeds, 'rss_news', limit, manager, 'News Feeds')
        total_new += new
        total_updated += updated
        
        # Reddit RSS
        new, updated = self._ingest_reddit_batch(limit, manager)
        total_new += new
        total_updated += updated
        
        # OTX
        new, updated = self._ingest_otx_batch(limit, manager)
        total_new += new
        total_updated += updated
        
        # Save state
        manager.save_state()
        
        self.stdout.write(self.style.SUCCESS(
            f'Ingestion complete! New: {total_new}, Updated: {total_updated}'
        ))
    
    def _ingest_rss_batch(self, feeds, feed_type, limit, manager, group_name):
        """Ingest a batch of RSS feeds"""
        self.stdout.write(f'Ingesting {group_name}...')
        total_new = 0
        total_updated = 0
        
        for url in feeds:
            try:
                # Skip if not time to update
                if not manager.should_update_feed(url, 5):
                    continue
                
                resp = requests.get(url, timeout=30, headers=manager.headers)
                resp.raise_for_status()
                parsed = feedparser.parse(resp.content)
                
                if not parsed.entries:
                    continue
                
                source_name = parsed.feed.title if hasattr(parsed.feed, 'title') else url.split('/')[-1]
                feed_new = 0
                feed_updated = 0
                
                # Get last article time to only get newer articles
                last_article_time_str = manager.get_last_article_time(url)
                last_article_time = None
                if last_article_time_str:
                    last_article_time = datetime.fromisoformat(last_article_time_str)
                
                for entry in parsed.entries[:limit]:
                    try:
                        # Parse publication date
                        pub_str = clean_date_str(entry.get('published') or entry.get('updated', ''))
                        pub_dt = parse_to_datetime(pub_str)
                        
                        # Skip if article is older than our last known article
                        if last_article_time and pub_dt <= last_article_time:
                            continue
                        
                        # Generate content hash
                        content_hash = generate_content_hash(entry)
                        
                        # Check if entry exists
                        existing = ThreatFeed.objects.filter(link=entry.link).first()
                        
                        if existing:
                            # Update if content changed
                            if hasattr(existing, 'content_hash') and existing.content_hash != content_hash:
                                existing.title = entry.title[:500]
                                existing.published = pub_dt
                                existing.feed_type = feed_type
                                existing.source = source_name
                                if hasattr(existing, 'content_hash'):
                                    existing.content_hash = content_hash
                                existing.save()
                                feed_updated += 1
                        else:
                            # Create new entry
                            ThreatFeed.objects.create(
                                title=entry.title[:500],
                                link=entry.link,
                                published=pub_dt,
                                feed_type=feed_type,
                                source=source_name,
                                content_hash=content_hash if hasattr(ThreatFeed, 'content_hash') else None
                            )
                            feed_new += 1
                        
                        # Update last article time if this is newer
                        if not last_article_time or pub_dt > last_article_time:
                            manager.update_last_article_time(url, pub_dt)
                            
                    except Exception as e:
                        self.stdout.write(self.style.WARNING(f'  Error processing entry: {e}'))
                        continue
                
                # Update statistics
                manager.update_feed_stats(url, feed_new, feed_updated)
                total_new += feed_new
                total_updated += feed_updated
                
                stats = manager.get_feed_stats(url)
                self.stdout.write(f'  - {url}: {feed_new} new, {feed_updated} updated (Total: {stats["new"]} new, {stats["updated"]} updated)')
                
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'  - Error {url}: {str(e)[:100]}'))
        
        return total_new, total_updated
    
    def _ingest_reddit_batch(self, limit, manager):
        """Ingest Reddit feeds"""
        self.stdout.write('Ingesting Reddit...')
        total_new = 0
        total_updated = 0
        
        subs = ['threatintel', 'netsec', 'Malware', 'blackhat', 'ReverseEngineering', 
               'cybersecurity', 'databreach', 'hacking']
        sub_limit = max(1, limit // len(subs))
        
        for sub in subs:
            url = f'https://reddit.com/r/{sub}/new/.rss'
            
            try:
                # Skip if not time to update
                if not manager.should_update_feed(url, 5):
                    continue
                
                resp = requests.get(url, timeout=30, headers=manager.headers)
                resp.raise_for_status()
                parsed = feedparser.parse(resp.content)
                
                if not parsed.entries:
                    continue
                
                feed_new = 0
                feed_updated = 0
                
                # Get last article time
                last_article_time_str = manager.get_last_article_time(url)
                last_article_time = None
                if last_article_time_str:
                    last_article_time = datetime.fromisoformat(last_article_time_str)
                
                for entry in parsed.entries[:sub_limit]:
                    try:
                        pub_str = clean_date_str(entry.get('published', ''))
                        pub_dt = parse_to_datetime(pub_str)
                        
                        # Skip if older
                        if last_article_time and pub_dt <= last_article_time:
                            continue
                        
                        author = getattr(entry, 'author', 'Anonymous')
                        source_name = f"r/{sub} - u/{author}"
                        
                        content_hash = generate_content_hash(entry)
                        
                        existing = ThreatFeed.objects.filter(link=entry.link).first()
                        
                        if existing:
                            if hasattr(existing, 'content_hash') and existing.content_hash != content_hash:
                                existing.title = entry.title[:500]
                                existing.published = pub_dt
                                existing.source = source_name
                                if hasattr(existing, 'content_hash'):
                                    existing.content_hash = content_hash
                                existing.save()
                                feed_updated += 1
                        else:
                            ThreatFeed.objects.create(
                                title=entry.title[:500],
                                link=entry.link,
                                published=pub_dt,
                                feed_type='reddit',
                                source=source_name,
                                content_hash=content_hash if hasattr(ThreatFeed, 'content_hash') else None
                            )
                            feed_new += 1
                        
                        if not last_article_time or pub_dt > last_article_time:
                            manager.update_last_article_time(url, pub_dt)
                            
                    except Exception:
                        continue
                
                manager.update_feed_stats(url, feed_new, feed_updated)
                total_new += feed_new
                total_updated += feed_updated
                
                self.stdout.write(f'  - r/{sub}: {feed_new} new, {feed_updated} updated')
                
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'  - Error r/{sub}: {str(e)[:100]}'))
        
        return total_new, total_updated
    
    def _ingest_otx_batch(self, limit, manager):
        """Ingest OTX feeds"""
        self.stdout.write('Ingesting OTX...')
        url = 'https://otx.alienvault.com/browse/global/pulses?include_inactive=0&sort=-modified&page=1&limit=10'
        
        try:
            if not manager.should_update_feed(url, 5):
                return 0, 0
            
            resp = requests.get(url, timeout=30, headers=manager.headers)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.content, 'html.parser')
            
            pulse_links = soup.find_all('a', href=re.compile(r'/pulse/'))
            feed_new = 0
            feed_updated = 0
            
            last_article_time_str = manager.get_last_article_time(url)
            last_article_time = None
            if last_article_time_str:
                last_article_time = datetime.fromisoformat(last_article_time_str)
            
            for link in pulse_links[:limit]:
                try:
                    title = link.text.strip()
                    if not title:
                        continue
                    
                    full_link = 'https://otx.alienvault.com' + link['href']
                    pub_dt = timezone.now()
                    
                    # Skip if we already have this (OTX doesn't have timestamps in RSS)
                    existing = ThreatFeed.objects.filter(link=full_link).first()
                    
                    if existing:
                        continue  # OTX articles don't usually update
                    else:
                        ThreatFeed.objects.create(
                            title=title,
                            link=full_link,
                            published=pub_dt,
                            feed_type='otx',
                            source='OTX AlienVault',
                            content_hash=hashlib.md5(title.encode()).hexdigest() if hasattr(ThreatFeed, 'content_hash') else None
                        )
                        feed_new += 1
                        
                except Exception:
                    continue
            
            manager.update_feed_stats(url, feed_new, feed_updated)
            self.stdout.write(f'  - OTX: {feed_new} new')
            
            return feed_new, feed_updated
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'  - OTX error: {str(e)[:100]}'))
            return 0, 0

    def _ingest_reddit(self, limit, force_update=False):
        self.stdout.write('Ingesting Reddit...')
        created_count = 0
        updated_count = 0
        
        try:
            subs = ['threatintel', 'netsec', 'Malware', 'blackhat', 'ReverseEngineering', 
                   'cybersecurity', 'databreach', 'hacking']
            sub_limit = max(1, limit // len(subs))
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            for sub in subs:
                try:
                    url = f'https://reddit.com/r/{sub}/new/.rss'
                    self.stdout.write(f'  Processing r/{sub}...')
                    
                    resp = requests.get(url, timeout=30, headers=headers)
                    resp.raise_for_status()
                    parsed = feedparser.parse(resp.content)
                    
                    if not parsed.entries:
                        self.stdout.write(f'    No entries in r/{sub}')
                        continue
                    
                    sub_created = 0
                    sub_updated = 0
                    
                    for entry in parsed.entries[:sub_limit]:
                        try:
                            # Get unique identifier
                            guid = entry.get('id') or entry.link
                            
                            # Parse date
                            pub_str = clean_date_str(entry.get('published', ''))
                            pub_dt = parse_to_datetime(pub_str)
                            
                            author = getattr(entry, 'author', 'Anonymous')
                            source_name = f"r/{sub} - u/{author}"
                            
                            # Generate content hash
                            content_hash = generate_content_hash(entry)
                            
                            # Check if exists
                            existing = ThreatFeed.objects.filter(
                                link=entry.link
                            ).first()
                            
                            if existing:
                                # Check if should update
                                content_changed = (
                                    content_hash != existing.content_hash 
                                    if hasattr(existing, 'content_hash') 
                                    else force_update
                                )
                                
                                if force_update or content_changed or pub_dt > existing.published:
                                    existing.title = entry.title[:500]
                                    existing.published = pub_dt
                                    existing.source = source_name
                                    existing.last_updated = timezone.now()
                                    
                                    if hasattr(existing, 'content_hash'):
                                        existing.content_hash = content_hash
                                    
                                    existing.save()
                                    sub_updated += 1
                                    updated_count += 1
                            else:
                                # Create new
                                threat_feed_data = {
                                    'title': entry.title[:500],
                                    'link': entry.link,
                                    'published': pub_dt,
                                    'feed_type': 'reddit',
                                    'source': source_name,
                                    'last_updated': timezone.now(),
                                }
                                
                                if hasattr(ThreatFeed, 'content_hash'):
                                    threat_feed_data['content_hash'] = content_hash
                                
                                ThreatFeed.objects.create(**threat_feed_data)
                                sub_created += 1
                                created_count += 1
                                
                        except Exception as entry_error:
                            self.stdout.write(self.style.WARNING(f'    ! Reddit entry error: {str(entry_error)[:80]}'))
                            continue
                    
                    self.stdout.write(f'    r/{sub}: {sub_created} new, {sub_updated} updated')
                    
                except Exception as sub_error:
                    self.stdout.write(self.style.ERROR(f'  - Error r/{sub}: {str(sub_error)[:100]}'))
                    continue
            
            self.stdout.write(f'  Reddit Summary: {created_count} new, {updated_count} updated')
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'  - Reddit error: {str(e)[:100]}'))
        
        return created_count, updated_count