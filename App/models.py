from django.utils import timezone
from django.db import models
from django.utils.text import slugify
import json


# -------------------------
# ThreatRecord (Indicators)
# -------------------------
from django.db import models
from django.utils import timezone


class ThreatRecord(models.Model):
    TYPE_CHOICES = [
        ('ip', 'IP Address'),
        ('url', 'URL / Domain'),
        ('malware', 'Malware Hash'),
        ('cve', 'CVE'),
        ('unknown', 'Unknown'),
    ]

    REPUTATION_CHOICES = [
        ('malicious', 'Malicious'),
        ('suspicious', 'Suspicious'),
        ('clean', 'Clean'),
        ('unknown', 'Unknown'),
    ]

    type = models.CharField(
        max_length=10,
        choices=TYPE_CHOICES,
        default='unknown',
        db_index=True
    )

    value = models.CharField(
        max_length=500,
        blank=True,
        default='',
        db_index=True
    )

    threat_score = models.FloatField(default=0.0, db_index=True)

    file_type = models.CharField(
        max_length=50,
        blank=True,
        default='unknown'
    )

    reputation = models.CharField(
        max_length=20,
        choices=REPUTATION_CHOICES,
        default='unknown'
    )

    source = models.CharField(max_length=100, default='')

    category = models.CharField(
        max_length=100,
        blank=True,
        default=''
    )

    tags = models.JSONField(default=list, blank=True)

    first_seen = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)

    description = models.TextField(blank=True, default='')

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-threat_score', '-first_seen']
        indexes = [
            models.Index(fields=['type', 'value']),
            models.Index(fields=['threat_score']),
            models.Index(fields=['created_at']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['type', 'value'],
                name='unique_threat_indicator'
            )
        ]

    def save(self, *args, **kwargs):
        """
        Ensure IP indicators always have timestamps.
        - Use feed timestamps if present
        - Otherwise default to ingestion time
        - Update last_seen on re-ingest
        """
        now = timezone.now()

        if self.type == 'ip':
            if not self.first_seen:
                self.first_seen = now
                # Optional tag for transparency
                if 'auto_timestamped' not in self.tags:
                    self.tags.append('auto_timestamped')

            # Always refresh last_seen for IPs
            self.last_seen = now

        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.type.upper()} | {self.value}"



# -------------------------
# ThreatProfile (Actors / Campaigns / Groups)
# -------------------------
class ThreatProfile(models.Model):
    INDUSTRY_CHOICES = [
        ('finance', 'Finance'),
        ('healthcare', 'Healthcare'),
        ('education', 'Education'),
        ('energy', 'Energy'),
        ('government', 'Government'),
        ('multiple', 'Multiple'),
    ]

    REGION_CHOICES = [
        ('north_america', 'North America'),
        ('europe', 'Europe'),
        ('asia_pacific', 'Asia-Pacific'),
    ]

    THREAT_FOCUS = [
        ('actors', 'Threat Actors'),
        ('malware', 'Malware'),
        ('cves', 'Vulnerabilities'),
        ('campaigns', 'Campaigns'),
    ]

    name = models.CharField(max_length=255, db_index=True)
    industry = models.CharField(max_length=50, choices=INDUSTRY_CHOICES, default='multiple')
    region = models.CharField(max_length=50, choices=REGION_CHOICES, default='north_america')
    threat_focus = models.CharField(max_length=50, choices=THREAT_FOCUS)

    description = models.TextField(default='No description')

    related_actors = models.JSONField(null=True, blank=True, default=list)
    related_malware = models.JSONField(null=True, blank=True, default=list)
    related_cves = models.JSONField(null=True, blank=True, default=list)
    related_campaigns = models.JSONField(null=True, blank=True, default=list)
    parent_group = models.CharField(max_length=255, blank=True, null=True)

    related_techniques = models.JSONField(null=True, blank=True, default=list)
    related_cwes = models.JSONField(null=True, blank=True, default=list)
    related_cpes = models.JSONField(null=True, blank=True, default=list)
    cvss_score = models.FloatField(null=True, blank=True)
    severity = models.CharField(max_length=20, null=True, blank=True)
    references = models.JSONField(null=True, blank=True, default=list)
    source = models.CharField(max_length=100, default='', blank=True)
    ai_summary = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.threat_focus}, {self.industry}, {self.region})"


# -------------------------
# ThreatFeed
# -------------------------
class ThreatFeed(models.Model):
    SOURCE_TYPES = [
        ('rss_vendor', 'RSS Vendor'),
        ('rss_news', 'RSS News'),
        ('reddit', 'Reddit'),
        ('twitter', 'Twitter (X)'),
        ('otx', 'OTX AlienVault'),
    ]

    CATEGORIES = [
        ('ransomware', 'Ransomware'),
        ('ddos', 'DDoS'),
        ('zero_day', 'Zero-Day'),
        ('vulnerability', 'Vulnerability'),
        ('breach', 'Breach'),
        ('malware', 'Malware'),
        ('phishing', 'Phishing'),
        ('apt', 'APT'),
        ('general_threat', 'General Threat'),
        ('other', 'Other'),
    ]

    title = models.CharField(max_length=500)
    content = models.TextField(blank=True)
    summary = models.TextField(blank=True)
    link = models.URLField(unique=True)
    slug = models.SlugField(max_length=600, unique=False, blank=True, null=True)
    published = models.DateTimeField(null=False, blank=False)
    feed_type = models.CharField(max_length=20, choices=SOURCE_TYPES)
    source = models.CharField(max_length=255)
    category = models.CharField(max_length=50, choices=CATEGORIES, default='general_threat')
    is_trending = models.BooleanField(default=False)
    
    # NEW: Trending metadata
    trending_score = models.FloatField(default=0.0, db_index=True)  # Score for trending calculation
    trending_position = models.IntegerField(default=0, db_index=True)  # Position in trending list (0 = not trending)
    trending_last_updated = models.DateTimeField(null=True, blank=True)  # When trending status was last updated
    
    content_hash = models.CharField(max_length=32, blank=True, null=True)
    last_updated = models.DateTimeField(auto_now=True)
    guid = models.CharField(max_length=500, blank=True, null=True)
    author = models.CharField(max_length=255, blank=True, null=True)
    thumbnail_url = models.URLField(blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-published']
        indexes = [
            models.Index(fields=['published', 'category']),
            models.Index(fields=['link']),
            models.Index(fields=['content_hash']),
            models.Index(fields=['feed_type', 'published']),
            models.Index(fields=['trending_score', 'published']),  # For trending queries
            models.Index(fields=['trending_position']),
        ]

    def __str__(self):
        return f"{self.feed_type.upper()} — {self.title} ({self.category})"

    def save(self, *args, **kwargs):
        if not self.slug and self.title:
            base_slug = slugify(self.title[:100])
            timestamp = timezone.now().strftime("%Y%m%d-%H%M%S")
            self.slug = f"{base_slug}-{timestamp}"
        
        if not self.category or self.category in ['other', 'general_threat']:
            text = (self.title or '') + ' ' + (self.content or '') + ' ' + (self.summary or '')
            self.category = self.categorize(text.lower())
        
        super().save(*args, **kwargs)

    def categorize(self, text):
        """
        Categorize a feed based on its content. PRIORITIZED: Zero-day > Malware > Breach > Vuln.
        """
        text_lower = text.lower()

        # PRIORITY 1: Strong breach indicators (unchanged)
        strong_breach_terms = [
            'data breach', 'database exposed', 'credentials leaked',
            'pii exposed', 'password leak', 'email leak', 'database dump',
            'stolen credentials', 'information leak'
        ]
        if any(term in text_lower for term in strong_breach_terms):
            return 'breach'

        # PRIORITY 2: Ransomware (with breach check, unchanged)
        ransomware_actors = [
            'akira', 'qilin', 'ransomhub', 'clop', 'cl0p', 'play',
            'lockbit', 'rhysida', 'blackcat', 'alphv', 'monti', 'lynx', 'dragonforce',
            'inc ransom', 'nightspire', 'safepay', '01flip', 'medusa', 'bianlian',
            'cactus', 'moonlock', 'ra group', 'stories', 'snatch', 'medusaLocker',
            'burncpu', 'knight', 'raccoon', 'conti', 'revil', 'hive', 'pysa'
        ]
        has_ransomware_actor = any(actor in text_lower for actor in ransomware_actors)
        has_ransomware_generic = 'ransomware' in text_lower
        has_breach_generic = any(term in text_lower for term in ['breach', 'leak', 'exposed'])

        if has_ransomware_actor and has_breach_generic:
            return 'breach'
        elif has_ransomware_actor or (has_ransomware_generic and not has_breach_generic):
            return 'ransomware'

        # PRIORITY 3: EXPANDED Zero-Day (BEFORE malware/vuln - catch blended articles)
        zero_day_terms = [
            'zero-day', 'zero day', '0day', '0-day', 'zero-day exploit',
            '0-day', 'zero-day vulnerability', 'actively exploited',
            'exploitation in the wild', 'public exploit', 'exploit available',
            'proof of concept', 'poc released', 'weaponized', 'n-day',
            'exploit chain', 'chained exploit', 'zero click', 'remote exploit',  # NEW: More synonyms
            'unpatched exploit', 'in-the-wild exploit'  # NEW: Common zero-day phrasing
        ]
        if any(term in text_lower for term in zero_day_terms):
            return 'zero_day'

        # PRIORITY 4: EXPANDED Malware (BEFORE vuln - catch exploit kits, droppers)
        malware_terms = [
            'malware', 'trojan', 'infostealer', 'stealer', 'backdoor', 'rootkit',
            'botnet', 'loader', 'dropper', 'worm', 'spyware', 'adware', 'keylogger',
            'rat', 'remote access trojan', 'banking trojan', 'coin miner',
            'cryptominer', 'miner', 'emotet', 'trickbot', 'qbot', 'icedid',
            'exploit kit', 'malware loader', 'fileless malware',  # NEW: Exploit-related malware
            'malware campaign', 'new malware variant'  # NEW: To catch before generic vuln
        ]
        if any(term in text_lower for term in malware_terms):
            return 'malware'
        apt_terms = [
            'apt', 'advanced persistent threat', 'state-sponsored', 'nation-state',
            'salt typhoon', 'scattered spider', 'volt typhoon', 'star blizzard',
            'kimsuky', 'lazarus', 'apt29', 'cozy bear', 'apt28', 'fancy bear',
            'equation group', 'sandworm', 'ta505', 'fin7', 'apt41', 'winnti',
            'turla', 'ke3chang', 'patchwork', 'charming kitten'
        ]
        if any(term in text_lower for term in apt_terms):
            return 'apt'
        # PRIORITY 5: General breach (unchanged)
        general_breach_terms = [
            'breach', 'leak', 'exposed', 'compromised', 'hacked'
        ]
        if any(term in text_lower for term in general_breach_terms):
            return 'breach'

        # PRIORITY 6: Vulnerability (MORE SPECIFIC - after zero-day/malware)
        # Only trigger if no prior matches; focus on patches/CVEs without exploit/malware
        vuln_terms = [
            'cve-', 'cvss', 'critical vulnerability', 'privilege escalation',  # Keep core
            'patch tuesday', 'microsoft patch', 'adobe patch', 'emergency patch',
            'out-of-band patch', 'ntlm relay', 'react2shell', 'toolshell',  # Keep specifics
            'security update', 'critical severity', 'high severity', 'cvss score',
            # REMOVED: Generic 'vulnerability', 'exploit', 'bug', 'weakness', 'rce' - these overlap with zero-day/malware
            # ADD: If needed, wrap in condition: if 'patch' in text_lower or 'cve-' in text_lower
        ]
        if any(term in text_lower for term in vuln_terms):
            return 'vulnerability'

        # PRIORITY 7-10: Phishing, DDoS, APT, IOCs (unchanged)
        phishing_terms = [
            'phishing', 'spoofing', 'social engineering', 'credential harvesting',
            'fake captcha', 'smishing', 'vishing', 'spear phishing',
            'whaling', 'business email compromise', 'bec', 'mfa bypass',
            'phishing campaign', 'credential theft'
        ]
        if any(term in text_lower for term in phishing_terms):
            return 'phishing'

        ddos_terms = [
            'ddos', 'distributed denial', 'denial of service', 'dos attack',
            'botnet attack', 'volumetric attack', 'application layer attack',
            'layer 7 attack', 'http flood', 'dns amplification',
            'ntp amplification', 'syn flood'
        ]
        if any(term in text_lower for term in ddos_terms):
            return 'ddos'

       
        import re
        ioc_patterns = [
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            r'\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b',
            r'\b[a-zA-Z0-9]{1,63}\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?\b',
        ]
        for pattern in ioc_patterns:
            if re.search(pattern, text_lower):
                return 'malware'  # IOCs → malware

        return 'general_threat'

    @property
    def is_recent(self):
        return (timezone.now() - self.published).days < 7
    
    @property
    def is_fresh(self):
        return (timezone.now() - self.published).days < 1
    
    @property
    def source_display(self):
        if self.feed_type == 'reddit':
            return self.source.split(' - ')[0] if ' - ' in self.source else self.source
        return self.source


# -------------------------
# NEW: TrendingData Model for storing trending analytics
# -------------------------
class TrendingData(models.Model):
    ENTITY_TYPES = [
        ('actor', 'Threat Actor'),
        ('attack', 'Attack Type'),
        ('campaign', 'Campaign'),
        ('industry', 'Industry'),
        ('country', 'Country'),
        ('cve', 'CVE'),
    ]
    
    entity_type = models.CharField(max_length=20, choices=ENTITY_TYPES, db_index=True)
    entity_name = models.CharField(max_length=255, db_index=True)
    entity_slug = models.SlugField(max_length=300, blank=True, null=True)
    
    # Trending metrics
    count = models.IntegerField(default=0)  # Number of occurrences
    percent = models.FloatField(default=0.0)  # Percentage representation
    raw_percent = models.FloatField(default=0.0)  # Raw percentage for styling
    
    # Position in trending list
    position = models.IntegerField(default=0, db_index=True)
    
    # Time-based data
    time_period = models.CharField(
        max_length=20,
        choices=[
            ('24h', '24 Hours'),
            ('1h', '1 Hour'),
            ('5h', '5 Hours'),
            ('7d', '7 Days'),
            ('30d', '30 Days'),
            ('all', 'All Time'),
        ],
        default='all',
        db_index=True
    )
    
    # Additional metadata
    risk_level = models.CharField(
        max_length=20,
        choices=[
            ('critical', 'Critical'),
            ('high', 'High'),
            ('medium', 'Medium'),
            ('low', 'Low'),
        ],
        default='low'
    )
    
    related_feed_ids = models.JSONField(default=list, blank=True)  # List of related feed IDs
    last_seen = models.DateTimeField(auto_now=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['time_period', 'position', '-count']
        indexes = [
            models.Index(fields=['entity_type', 'time_period', 'position']),
            models.Index(fields=['entity_type', 'entity_name', 'time_period']),
            models.Index(fields=['time_period', 'position']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['entity_type', 'entity_name', 'time_period'],
                name='unique_trending_entity_per_period'
            )
        ]
    
    def __str__(self):
        return f"{self.entity_name} ({self.entity_type}) - {self.percent}%"
    
    def save(self, *args, **kwargs):
        if not self.entity_slug and self.entity_name:
            from django.utils.text import slugify
            self.entity_slug = slugify(self.entity_name)
        super().save(*args, **kwargs)


# -------------------------
# NEW: FilterPreset Model for saving filter states
# -------------------------
class FilterPreset(models.Model):
    name = models.CharField(max_length=100)
    filter_type = models.CharField(
        max_length=20,
        choices=[
            ('time', 'Time Filter'),
            ('category', 'Category Filter'),
            ('combined', 'Combined Filter'),
        ],
        default='category'
    )
    
    # Filter parameters
    time_period = models.CharField(
        max_length=20,
        choices=[
            ('24h', '24 Hours'),
            ('1h', '1 Hour'),
            ('5h', '5 Hours'),
            ('7d', '7 Days'),
            ('30d', '30 Days'),
            ('all', 'All Time'),
        ],
        default='all',
        blank=True
    )
    
    # Category filter (for the enhanced filtering)
    category_filter = models.CharField(
        max_length=50,
        choices=ThreatFeed.CATEGORIES,
        blank=True
    )
    
    # For the enhanced filtering groups
    filter_group = models.CharField(
        max_length=50,
        choices=[
            ('phishing', 'Phishing/Vishing/Smishing'),
            ('zero-day', 'Zero-Day/0day'),
            ('vulnerability', 'Vulnerability/CVE/Exploit'),
            ('ransomware', 'Ransomware'),
            ('breach', 'Breach/Leak'),
            ('malware', 'Malware/Trojan/Virus'),
            ('ddos', 'DDoS'),
            ('apt', 'APT/Nation-State'),
            ('all', 'All'),
        ],
        default='all'
    )
    
    # Additional metadata
    is_default = models.BooleanField(default=False)
    usage_count = models.IntegerField(default=0)
    last_used = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-is_default', '-usage_count', 'name']
    
    def __str__(self):
        return f"{self.name} ({self.filter_group})"
    
# models.py
from django.db import models
from django.utils import timezone

class ThreatActor(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    uuid = models.CharField(max_length=50, unique=True)
    data = models.JSONField(default=dict)
    last_updated = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name

class GitHubUpdate(models.Model):
    """Track when we last checked GitHub"""
    last_check = models.DateTimeField(auto_now=True)
    etag = models.CharField(max_length=200, blank=True)
    last_modified = models.CharField(max_length=200, blank=True)
    
    


# App/models.py
from django.db import models

class Tactic(models.Model):
    external_id = models.CharField(max_length=100)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    domain = models.CharField(max_length=50, default='enterprise')
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)
    kill_chain_phases = models.JSONField(default=list, blank=True)
    stix_id = models.CharField(max_length=100, blank=True)
    
    class Meta:
        unique_together = ['external_id', 'domain']
    
    def __str__(self):
        return f"{self.domain.upper()}: {self.name}"

class Technique(models.Model):
    external_id = models.CharField(max_length=50)
    name = models.CharField(max_length=500)
    description = models.TextField()
    domain = models.CharField(max_length=50, default='enterprise')
    tactics = models.ManyToManyField(Tactic, related_name='techniques')
    platforms = models.JSONField(default=list, blank=True)
    data_sources = models.JSONField(default=list, blank=True)
    detection = models.TextField(blank=True)
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)
    stix_id = models.CharField(max_length=100, blank=True)
    is_subtechnique = models.BooleanField(default=False)
    subtechnique_of = models.ForeignKey('self', on_delete=models.SET_NULL, 
                                       null=True, blank=True, related_name='subtechniques')
    
    class Meta:
        unique_together = ['external_id', 'domain']
        ordering = ['external_id']
    
    def __str__(self):
        return f"{self.domain.upper()}: {self.external_id}: {self.name}"

# models.py
from django.db import models
from django.contrib.postgres.fields import ArrayField
from django.db import models
import json

# For SQLite (or other databases that don't support ArrayField)
# We'll use JSONField as a workaround
class ArrayField(models.JSONField):
    """Custom ArrayField for SQLite compatibility"""
    def __init__(self, base_field=None, **kwargs):
        super().__init__(**kwargs)
        self.base_field = base_field
    
    def from_db_value(self, value, expression, connection):
        if value is None:
            return []
        if isinstance(value, str):
            return json.loads(value)
        return value
    
    def get_prep_value(self, value):
        if value is None:
            return []
        return json.dumps(value)

class ThreatActors(models.Model):
    """Store threat actors from MISP Galaxy"""
    uuid = models.CharField(max_length=100, unique=True)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    meta = models.JSONField(default=dict)  # Store all metadata
    source = models.CharField(max_length=50, default='misp-galaxy')
    
    # Common fields we'll extract
    country = models.CharField(max_length=100, blank=True)
    synonyms = ArrayField(default=list, blank=True)  # Use custom ArrayField
    target_sectors = ArrayField(default=list, blank=True)
    
    # Match fields
    mitre_group_id = models.CharField(max_length=50, blank=True)
    mitre_group_name = models.CharField(max_length=200, blank=True)
    confidence_score = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name = "Threat Actor"
        verbose_name_plural = "Threat Actors"

class ActorGroupMatch(models.Model):
    """Store matches between threat actors and MITRE groups"""
    threat_actor = models.ForeignKey(ThreatActor, on_delete=models.CASCADE, related_name='matches')
    mitre_group_id = models.CharField(max_length=50)
    mitre_group_name = models.CharField(max_length=200)
    
    # Match details
    MATCH_TYPES = [
        ('exact_name', 'Exact Name Match'),
        ('alias', 'Alias Match'),
        ('description', 'Description Keyword Match'),
        ('country', 'Country Match'),
        ('sector', 'Target Sector Match'),
        ('technique', 'Common Techniques'),
        ('manual', 'Manual Match'),
    ]
    
    match_type = models.CharField(max_length=50, choices=MATCH_TYPES)
    confidence = models.IntegerField(default=0)
    evidence = models.JSONField(default=dict)
    notes = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['threat_actor', 'mitre_group_id']
        verbose_name = "Actor-Group Match"
        verbose_name_plural = "Actor-Group Matches"
    
    def __str__(self):
        return f"{self.threat_actor.name} -> {self.mitre_group_name}"