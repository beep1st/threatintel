from collections import Counter
import subprocess
import threading
import json
import os
import re
from django.utils.html import escapejs

import sys
import psutil
import ollama
from datetime import timedelta, datetime
from django.shortcuts import render, get_object_or_404, HttpResponseRedirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.contrib import messages
from django.db.models import Q, Count, F, ExpressionWrapper, FloatField
from django.db.models.functions import TruncDay, TruncHour
from django.core.paginator import Paginator
from dateutil import parser
import requests
from bs4 import BeautifulSoup
import logging
from dataclasses import dataclass
from typing import Dict, List, Callable
from .models import ThreatProfile, ThreatRecord, ThreatFeed, TrendingData, FilterPreset
# FLAN-T5 Imports
import torch
from transformers import T5ForConditionalGeneration, T5Tokenizer
# Import the new scoring engine
from .scoring_engine import RiskScoringEngine, ScoringFactor, FactorCalculators
from .ingest_feed import check_ip_reputation, save_or_update_record

logger = logging.getLogger(__name__)
ANALYSIS_CACHE = {}
# Global model cache
T5_MODEL = None
T5_TOKENIZER = None

def load_t5_model():
    """Lazy-load google/flan-t5-base (excellent for threat summaries)"""
    global T5_MODEL, T5_TOKENIZER
    if T5_MODEL is None:
        model_name = "google/flan-t5-base"
        try:
            T5_TOKENIZER = T5Tokenizer.from_pretrained(model_name)
            T5_MODEL = T5ForConditionalGeneration.from_pretrained(model_name)
            device = "cuda" if torch.cuda.is_available() else "cpu"
            T5_MODEL.to(device)
            logger.info(f"FLAN-T5-Base loaded successfully on {device}")
        except Exception as e:
            logger.error(f"Failed to load FLAN-T5-Base: {e}")
            T5_MODEL = None
    return T5_MODEL, T5_TOKENIZER

def generate_t5_summary(title: str, content: str) -> str:
    """Generate high-quality executive summary using FLAN-T5-Base"""
    try:
        model, tokenizer = load_t5_model()
        if model is None or tokenizer is None:
            return f"Executive Summary: {content[:400]}..."
        device = next(model.parameters()).device
        truncated_content = f"{title}. {content[:1200]}"
        prompt = f"""Summarize this cybersecurity threat article in 3-5 clear sentences.
Include key threats, actors, and indicators of compromise:
{truncated_content}"""
        inputs = tokenizer(prompt, return_tensors="pt", max_length=1024, truncation=True).to(device)
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_length=200,
                min_length=60,
                num_beams=6,
                temperature=0.8,
                do_sample=True,
                early_stopping=True,
                pad_token_id=tokenizer.eos_token_id
            )
        summary = tokenizer.decode(outputs[0], skip_special_tokens=True).strip()
        if summary.lower().startswith(("summarize", "summary")):
            summary = re.split(r"[:\n]", summary, 1)[-1].strip()
        return summary
    except Exception as e:
        logger.error(f"Summary generation error: {e}")
        return f"Executive Summary: {content[:400]}..."

# ========== DYNAMIC SCORING ENGINE ==========
def create_scoring_engine(use_pandas: bool = False, is_threat_actor: bool = False) -> RiskScoringEngine:
    engine = RiskScoringEngine(use_pandas=use_pandas)
  
    if is_threat_actor:
        engine.add_factor(ScoringFactor(
            name="Threat Actor Profile",
            weight=0.25,
            calculator=FactorCalculators.calculate_threat_actor_score,
            description="Threat actor notoriety and activity level"
        ))
        engine.add_factor(ScoringFactor(
            name="Keyword Threat",
            weight=0.40,
            calculator=FactorCalculators.calculate_keyword_threat_score,
            description="Presence of threat-related keywords"
        ))
        engine.add_factor(ScoringFactor(
            name="Temporal Score",
            weight=0.15,
            calculator=FactorCalculators.calculate_temporal_score,
            description="Recency of the threat"
        ))
        engine.add_factor(ScoringFactor(
            name="Entity Density",
            weight=0.10,
            calculator=FactorCalculators.calculate_entity_density,
            description="Number of detected entities (actors, CVEs, etc.)"
        ))
        engine.add_factor(ScoringFactor(
            name="Source Reputation",
            weight=0.10,
            calculator=FactorCalculators.calculate_source_reputation,
            description="Credibility of the source"
        ))
    else:
        engine.add_factor(ScoringFactor(
            name="Keyword Threat",
            weight=0.45,
            calculator=FactorCalculators.calculate_keyword_threat_score,
            description="Presence of threat-related keywords"
        ))
        engine.add_factor(ScoringFactor(
            name="Temporal Score",
            weight=0.35,
            calculator=FactorCalculators.calculate_temporal_score,
            description="Recency of the threat"
        ))
        engine.add_factor(ScoringFactor(
            name="Entity Density",
            weight=0.10,
            calculator=FactorCalculators.calculate_entity_density,
            description="Number of detected entities (actors, CVEs, etc.)"
        ))
        engine.add_factor(ScoringFactor(
            name="Source Reputation",
            weight=0.10,
            calculator=FactorCalculators.calculate_source_reputation,
            description="Credibility of the source"
        ))
    return engine

# ========== HELPER FUNCTIONS ==========
def extract_text_from_url(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, 'html.parser')
        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()
        return soup.get_text(separator=' ', strip=True)[:30000]
    except:
        return "Failed to read article."

import re

def extract_entities(text):
    """Extract entities from text with improved patterns"""
    if not text:
        return {
            'actors': [], 
            'attacks': [], 
            'campaigns': [], 
            'industries': [], 
            'countries': [], 
            'cves': []
        }
    
    text_lower = text.lower()
    
    actor_patterns = [
        # For ransomware groups and actor names
        r'\b(clop|cl0p|ransomhub|qilin|akira|play|safepay|rhysida|monti|lockbit|lockbit3\.0|lynx|dragonforce|nightspider|meow|ghostposter|burncpu|cactus|medusa|bianlian|knight|raccoon|hive|pysa|blackcat|alphv|conti|revil|sodinokibi|ryuk|wannacry|petya|notpetya|badrabbit|maze|doppelpaymer|nemty|snatch|astro|ragnar|avaddon|darkside|babuk|vice\s+society|haron|payloadbin|stormous|royal|ransomhouse|abyss|eight|everest|zeppelin)\b',
        
        # For APT groups
        r'\b(?:APT|apt)[-\s]?(37|28|29|41|10|38|33|34|35|40|1|2|3|12|16|17|18|19|20|21|22|23|24|25|26|27|30|31|32|39|43|44|45|48|74)\b',
        r'\badvanced\s+persistent\s+threat\s+(?:group\s+)?(37|28|29|41|10|38|33|34)\b',
        
        # For TA groups
        r'\b(?:TA|ta)[-\s]?(505|555|577|578|581|542|543|544|454|416|423|450|466|471|490|551|558|569|570|571|579|592|600|800|956|963|964|1013|1040|1047|1050|1055)\b',
        
        # For FIN groups
        r'\b(?:FIN|fin)[-\s]?(7|8|9|10|11|12|13|6|5|4|3)\b',
        
        # Other actor patterns
        r'\b(lazarus|equation\s+group|sandworm|turla|winnti|cozy\s+bear|fancy\s+bear|sneaky\s+panda|dragon\s+ok|muddy\s+water|tick|panda|naikon|gothic\s+panda|deep\s+panda|menupass|ke3chang|patchwork|charming\s+kitten|helix\s+kitten|magic\s+hound|sofacy|energetic\s+bear|venomous\s+bear|the\s+dukes|berserk\s+bear|blue\s+noroff|andariel|scarlet\s+mimic|hidden\s+cobra|appleworm|darkhotel)\b',
    ]
    
    attack_patterns = [
        # First pattern with word boundaries
        r'\b(ransomware|phishing|malware|ddos|breach|data\s+theft|vulnerability|zero[-\s]?day|0day|apt|extortion|backdoor|exploit|infection|payload|trojan|spyware|adware|botnet|infostealer|keylogger|rootkit|cryptominer|cryptojacking|worm|virus|spam|scam|fraud|hack|compromise|intrusion|incident)\b',
        
        # Second pattern
        r'\b(supply\s+chain\s+attack|credential\s+stuffing|man[-\s]?in[-\s]?the[-\s]?middle|sql\s+injection|xss|cross[-\s]?site\s+scripting|buffer\s+overflow|code\s+injection|remote\s+code\s+execution|privilege\s+escalation|denial[-\s]?of[-\s]?service|dos|brute\s+force|password\s+spraying|session\s+hijacking|dns\s+spoofing|arp\s+spoofing|clickjacking|formjacking|cryptojacking|fileless\s+malware|polymorphic\s+malware|metamorphic\s+malware)\b',
        
        # Third pattern with word boundaries for "bec"
        r'\b(social\s+engineering|business\s+email\s+compromise|bec\b|spear\s+phishing|whaling|smishing|vishing|pretexting|baiting|quid\s+pro\s+quo|tailgating|impersonation|water\s+holing|honey\s+pot|scareware|tech\s+support\s+scam)\b',
        
        # Fourth pattern
        r'\b(drive\-by\s+download|malvertising|watering\s+hole|credential\s+dumping|pass\s+the\s+hash|golden\s+ticket|silver\s+ticket|kerberoasting|as\-reproasting|lsass\s+dumping|ntlm\s+relay|pth|ptt)\b'
    ]
    
    campaign_patterns = [
        # Add word boundaries to all campaign patterns
        r'\b(salt\s+typhoon|toolshell|react2shell|kimsuky|operation\s+(dream\s+job|aurora|shady\s+rat|night\s+dragon|titan\s+rain|byzantine\s+rando|cloud\s+hopper|cleaver|troy|ghost|wocao|red\s+october|aurora\s+panda)|project\s+sauron|equation\s+group|wannacry|notpetya|stuxnet|flame|duqu|gauss|red\s+october|industroyer|crashoverride|triton|trisis|black\s+energy|havex|shamoon|stone\s+panda|darkhotel|cloud\s+atlas|grief\s+sword|toxic\s+storm|muddywater)\b',
        
        r'\b(operation\s+[a-z0-9]+\s*(?:campaign|attack|offensive)?|project\s+[a-z0-9]+\s*(?:campaign|operation)?|campaign\s+[a-z0-9]+)\b',
        
        r'\b(colonial\s+pipeline|solarwinds|sunburst|sunspot|teardrop|cyclops\s+blink|acidrain|acidpour|whispergate|hermeticwiper|isashell|foxblade|payloadbin|lockergoga|megacortex|maze\s+campaign|revil\s+campaign|conti\s+campaign|hive\s+campaign)\b'
    ]
    
    industry_patterns = [
        # Add word boundaries
        r'\b(manufacturing|healthcare|construction|energy|technology|finance|government|retail|education|telecom|banking|insurance|transportation|utilities|defense|aerospace|hospitality|pharmaceutical|biotech|agriculture|mining|oil\s+and\s+gas|renewable\s+energy|cybersecurity|critical\s+infrastructure|water\s+treatment|chemical|food\s+and\s+beverage|automotive|logistics|shipping|maritime|aviation|space|real\s+estate|media|entertainment|gaming|sports|nonprofit|ngo|research|development|consulting|accounting|advertising|marketing|legal|law|judicial|military|intelligence|homeland\s+security|public\s+sector|private\s+sector)\b',
        
        r'\b(health\s+care|financial\s+services|professional\s+services|public\s+health|emergency\s+services|power\s+grid|nuclear|chemical\s+plant|water\s+supply|transport\s+network|communications|internet\s+service\s+provider|cloud\s+provider|data\s+center|software\s+development|hardware\s+manufacturing|semiconductor|electronics)\b'
    ]
    
    country_patterns = [
        # Add word boundaries
        r'\b(usa|united\s+states|america|canada|uk|united\s+kingdom|britain|england|scotland|wales|northern\s+ireland|germany|france|italy|spain|portugal|poland|ukraine|russia|china|japan|south\s+korea|north\s+korea|india|pakistan|iran|iraq|syria|israel|saudi\s+arabia|uae|united\s+arab\s+emirates|turkey|egypt|brazil|argentina|chile|mexico|australia|new\s+zealand|singapore|malaysia|indonesia|vietnam|thailand|philippines|taiwan|hong\s+kong|macau|sweden|norway|denmark|finland|netherlands|belgium|switzerland|austria|czech|slovakia|hungary|romania|bulgaria|greece|serbia|croatia|slovenia|estonia|latvia|lithuania|belarus|moldova|georgia|armenia|azerbaijan|kazakhstan|uzbekistan|turkmenistan|afghanistan|bangladesh|sri\s+lanka|nepal|bhutan|mongolia|myanmar|laos|cambodia|brunei|east\s+timor|fiji|papua\s+new\s+guinea|solomon\s+islands)\b'
    ]
    
    cve_pattern = r'(CVE-\d{4}-\d{4,7})'
    
    def extract_with_patterns(text, patterns):
        """Extract entities using regex patterns"""
        entities_set = set()
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    for item in match:
                        if item and len(str(item).strip()) > 1:
                            if re.match(r'^\d+$', str(item).strip()) and 'apt' in pattern.lower():
                                entity = f"APT-{item}"
                            elif re.match(r'^\d+$', str(item).strip()) and 'ta' in pattern.lower():
                                entity = f"TA{item}"
                            elif re.match(r'^\d+$', str(item).strip()) and 'fin' in pattern.lower():
                                entity = f"FIN{item}"
                            else:
                                entity = str(item).strip()
                            entities_set.add(entity)
                else:
                    if match and len(str(match).strip()) > 1:
                        entities_set.add(str(match).strip())
        return list(entities_set)
    
    # Extract entities using patterns
    actors = extract_with_patterns(text_lower, actor_patterns)
    attacks = extract_with_patterns(text_lower, attack_patterns)
    campaigns = extract_with_patterns(text_lower, campaign_patterns)
    industries = extract_with_patterns(text_lower, industry_patterns)
    countries = extract_with_patterns(text_lower, country_patterns)
    cves = re.findall(cve_pattern, text, re.IGNORECASE)
    
    def filter_generic_entities(entities, entity_type):
        """Filter out generic terms from entities"""
        generic_terms = {
            'actors': ['group', 'gang', 'team', 'actor', 'threat', 'hacker', 'apt', 'ransomware', 'malware', 'attack', 'campaign', 'operation', 'project'],
            'attacks': ['attack', 'threat', 'incident', 'vector', 'method', 'technique', 'tactic'],
            'campaigns': ['campaign', 'operation', 'project', 'targeting', 'that', 'new', 'a', 'the', 'ongoing', 'recent', 'major', 'global'],
            'industries': ['sector', 'industry', 'field', 'domain', 'vertical', 'market'],
            'countries': [],
            'cves': []
        }
        
        filtered = []
        generic_list = generic_terms.get(entity_type, [])
        
        for entity in entities:
            if len(entity) < 3:
                continue
            
            entity_lower = entity.lower()
            is_generic = False
            
            for term in generic_list:
                if term in entity_lower and len(entity.split()) <= 3:
                    is_generic = True
                    break
            
            if not is_generic:
                filtered.append(entity)
        
        return filtered
    
    def clean_entities(entities, entity_type):
        """Clean and format extracted entities"""
        cleaned = []
        for entity in entities:
            if not entity.isupper() and not re.match(r'^CVE-', entity):
                if re.match(r'^(APT|TA|FIN|FIN)-\d+$', entity, re.IGNORECASE):
                    entity = entity.upper()
                elif re.match(r'^\d+$', entity):
                    continue
                else:
                    entity = entity.title()
            
            entity = ' '.join(entity.split())
            if entity and entity not in cleaned:
                cleaned.append(entity)
        
        return filter_generic_entities(cleaned, entity_type)
    
    # Return cleaned and filtered results
    return {
        'actors': clean_entities(actors, 'actors'),
        'attacks': clean_entities(attacks, 'attacks'),
        'campaigns': clean_entities(campaigns, 'campaigns'),
        'industries': clean_entities(industries, 'industries'),
        'countries': clean_entities(countries, 'countries'),
        'cves': list(set(cves))
    }

def get_trending_data_from_counts(entity_counts, name_map=None, total_feeds=1, limit=5,
                                  use_relative_percentage=True, include_other=True, entity_type="actors"):
    trending_items = []
    all_items = entity_counts.most_common(50)
    
    if not all_items:
        return trending_items
    
    total_mentions_for_type = sum(entity_counts.values())
    
    other_labels = {
        'actors': 'Other threat groups',
        'attacks': 'Other attack types',
        'campaigns': 'Other campaigns',
        'industries': 'Other sectors',
        'countries': 'Other regions',
        'cves': 'Other vulnerabilities',
    }
    
    other_label = other_labels.get(entity_type, 'Other')
    top_items = []
    other_items = []
    
    # RELAX for industries/countries: count >=1, higher limit
    min_count = 1 if entity_type in ['industries', 'countries'] else 2
    effective_limit = 15 if entity_type in ['industries', 'countries'] else limit  # Show more
    
    for name, count in all_items:
        if len(top_items) < effective_limit and count >= min_count:
            top_items.append((name, count))
        else:
            other_items.append((name, count))
    
    if len(top_items) < effective_limit:
        needed = effective_limit - len(top_items)
        additional_items = [item for item in all_items if item not in top_items][:needed]
        top_items.extend(additional_items)
        other_items = [item for item in other_items if item not in additional_items]
    
    for name, count in top_items:
        display_name = name_map.get(name.lower(), name) if name_map else name
      
        if not display_name.isupper() and not re.match(r'^CVE-', display_name):
            if re.match(r'^(apt|ta|fin)[-\s]?\d+', display_name.lower()):
                display_name = display_name.upper().replace(' ', '-')
            else:
                display_name = display_name.title()
      
        if use_relative_percentage:
            percent = round((count / total_mentions_for_type * 100), 1) if total_mentions_for_type > 0 else 0
            display_percent = f"{percent:.1f}%"
        else:
            percent = round((count / total_feeds * 100), 1) if total_feeds > 0 else 0
            display_percent = f"{percent:.1f}%"
      
        # FIXED: Add URL for clickable links (matches DB format)
        entity_slug = display_name.lower().replace(' ', '-')
        url = f"/entity/{entity_type}/{entity_slug}"
      
        trending_items.append({
            "name": display_name,
            "percent": display_percent,
            "count": count,
            "raw_percent": percent,
            "is_other": False,
            "url": url  # <-- NEW: Clickable URL
        })
    
    if include_other and other_items:
        other_total_count = sum(count for _, count in other_items)
        if other_total_count > 0:
            if use_relative_percentage:
                other_percent = round((other_total_count / total_mentions_for_type * 100), 1)
            else:
                other_percent = round((other_total_count / total_feeds * 100), 1) if total_feeds > 0 else 0
          
            other_actor_count = len(other_items)
            if other_actor_count > 20:
                descriptor = f"{other_label} ({other_actor_count}+)"
            elif other_actor_count > 10:
                descriptor = f"{other_label} ({other_actor_count})"
            else:
                descriptor = other_label
          
            # FIXED: Set URL to "#" for non-clickable "Other" items
            trending_items.append({
                "name": descriptor,
                "percent": f"{other_percent:.1f}%",
                "count": other_total_count,
                "raw_percent": other_percent,
                "is_other": True,
                "other_count": other_actor_count,
                "url": "#"  # <-- NEW: Non-clickable for aggregated items
            })
    
    return trending_items

# ========== ENHANCED FILTERING FUNCTIONS ==========
def get_filter_group_keywords(filter_group):
    """
    Get keywords for filter groups with related terms
    """
    keyword_groups = {
        'phishing': ['phishing', 'vishing', 'smishing', 'spear-phishing', 'whaling', 
                    'email fraud', 'business email compromise', 'bec', 
                    'social engineering', 'credential harvesting', 'fake captcha',
                    'mfa bypass', 'credential theft', 'email scam'],
        'zero-day': ['zero-day', 'zero day', '0day', '0-day', 'zero-day exploit', 
                    '0-day', 'zero-day vulnerability', 'actively exploited',
                    'exploitation in the wild', 'weaponized', 'n-day exploit'],
        'vulnerability': ['vulnerability', 'cve', 'exploit', 'security flaw', 
                         'patch', 'bug', 'weakness', 'remote code execution',
                         'rce', 'privilege escalation', 'critical vulnerability',
                         'security update', 'patch tuesday', 'cvss'],
        'ransomware': ['ransomware', 'ransom', 'cryptolocker', 'encryption malware', 
                      'file locker', 'akira', 'qilin', 'clop', 'lockbit',
                      'blackcat', 'alphv', 'conti', 'revil', 'hive'],
        'breach': ['breach', 'data breach', 'leak', 'data theft', 
                  'exfiltration', 'compromise', 'exposed', 'database exposed',
                  'credentials leaked', 'data leak', 'personal data exposed'],
        'malware': ['malware', 'trojan', 'virus', 'worm', 'spyware', 
                   'adware', 'rootkit', 'backdoor', 'infostealer', 'botnet',
                   'loader', 'dropper', 'rat', 'remote access trojan'],
        'ddos': ['ddos', 'denial of service', 'dos attack', 
                'distributed denial of service', 'flood attack', 'volumetric attack',
                'http flood', 'dns amplification', 'syn flood'],
        'apt': ['apt', 'advanced persistent threat', 'state-sponsored', 'nation-state',
               'targeted attack', 'salt typhoon', 'scattered spider', 'lazarus',
               'cozy bear', 'fancy bear', 'equation group', 'sandworm'],
    }
    
    return keyword_groups.get(filter_group, [])

def get_strict_filter_keywords(filter_group):
    """
    Get STRICT keywords that shouldn't overlap with other categories
    """
    strict_keywords = {
        'phishing': ['phishing', 'spear-phishing', 'whaling', 'business email compromise', 'bec'],
        'zero-day': ['zero-day', 'zero day', '0day', '0-day', 'zero-day exploit'],
        'vulnerability': ['cve-', 'cvss', 'remote code execution', 'rce'],
        'ransomware': ['akira', 'qilin', 'clop', 'lockbit', 'blackcat', 'alphv'],
        'breach': ['data breach', 'credentials leaked', 'database exposed', 'pii exposed'],
        'malware': ['trojan', 'infostealer', 'backdoor', 'rootkit', 'botnet'],
        'ddos': ['ddos', 'distributed denial', 'http flood', 'dns amplification'],
        'apt': ['advanced persistent threat', 'state-sponsored', 'nation-state', 'apt']
    }
    return strict_keywords.get(filter_group, [])

def filter_feeds_by_group(feeds, filter_group):
    """
    Filter feeds by filter group with CATEGORY PRIORITY + STRICT KEYWORDS.
    Exclude conflicting categories to prevent overlap.
    """
    if filter_group == 'all':
        return feeds

    # Map filter groups to actual ThreatFeed.CATEGORIES values (unchanged)
    category_map = {
        'phishing': 'phishing',
        'zero-day': 'zero_day',
        'vulnerability': 'vulnerability',
        'ransomware': 'ransomware',
        'breach': 'breach',
        'malware': 'malware',
        'ddos': 'ddos',
        'apt': 'apt',
        'general_threat': 'general_threat',
        'other': 'other'
    }

    target_category = category_map.get(filter_group)
    
    # Use STRICT keywords for fallback (less overlap)
    strict_keywords = get_strict_filter_keywords(filter_group)
    
    # EXPANDED: Conflicting categories to exclude (prevents leaks)
    conflicting_categories = {
        'phishing': ['malware', 'general_threat', 'apt'],  # Phishing terms in malware kits or general
        'apt': ['general_threat', 'malware', 'vulnerability'],  # APT mentions in general/malware
        'malware': ['vulnerability', 'zero_day'],  # Existing
        'zero-day': ['vulnerability'],  # Existing
        'vulnerability': ['zero_day', 'malware'],  # Existing
        'ransomware': ['breach'],  # Ransomware often in breaches
        'breach': ['ransomware', 'general_threat'],  # Reverse
        # Add more as needed
    }.get(filter_group, [])
    if not target_category and not strict_keywords:
        return feeds

    filtered_feeds = []

    for feed in feeds:
        if isinstance(feed, dict):
            feed_obj = feed.get('raw_item')
            if feed_obj:
                feed_category = feed_obj.category.lower()
                text_to_search = f"{feed['title']} {feed['summary']}".lower()
            else:
                feed_category = feed.get('category', '').lower()
                text_to_search = f"{feed['title']} {feed['summary']}".lower()
        else:
            feed_category = (feed.category or '').lower()
            text_to_search = f"{feed.title} {feed.summary or ''}".lower()

        # PRIORITY 1: Exact category match (always include)
        if target_category and feed_category == target_category:
            filtered_feeds.append(feed)
            continue
           
        # PRIORITY 2: NEW - Exclude conflicting categories FIRST (stricter)
        if conflicting_categories and feed_category in [c.lower() for c in conflicting_categories]:
            continue  # Skip entirely

        # PRIORITY 3: STRICT keyword search (only if no category match + no conflict)
        if strict_keywords:
            for keyword in strict_keywords:
                if keyword in text_to_search:
                    filtered_feeds.append(feed)
                    break

    return filtered_feeds

def get_time_filtered_feeds(time_period='all'):
    """
    Get feeds filtered by time period
    """
    now = timezone.now()
    
    if time_period == '24h':
        time_threshold = now - timedelta(hours=24)
    elif time_period == '1h':
        time_threshold = now - timedelta(hours=1)
    elif time_period == '5h':
        time_threshold = now - timedelta(hours=5)
    elif time_period == '7d':
        time_threshold = now - timedelta(days=7)
    elif time_period == '30d':
        time_threshold = now - timedelta(days=30)
    else:  # 'all'
        time_threshold = None
    
    if time_threshold:
        return ThreatFeed.objects.filter(published__gte=time_threshold)
    else:
        return ThreatFeed.objects.all()

def update_trending_data_in_db(time_period='all'):
    """
    Update trending data in the database for a specific time period
    """
    try:
        # Calculate time filter
        now = timezone.now()
        if time_period == '24h':
            time_threshold = now - timedelta(hours=24)
        elif time_period == '1h':
            time_threshold = now - timedelta(hours=1)
        elif time_period == '5h':
            time_threshold = now - timedelta(hours=5)
        elif time_period == '7d':
            time_threshold = now - timedelta(days=7)
        elif time_period == '30d':
            time_threshold = now - timedelta(days=30)
        else:  # 'all'
            time_threshold = None
        
        # Get feeds for the time period
        if time_threshold:
            feeds = ThreatFeed.objects.filter(published__gte=time_threshold)
        else:
            feeds = ThreatFeed.objects.all()
        
        # Calculate entity counts
        entity_feed_counts = {
            'actors': Counter(),
            'attacks': Counter(),
            'campaigns': Counter(),
            'industries': Counter(),
            'countries': Counter(),
            'cves': Counter()
        }
        
        feed_ids = []
        for feed in feeds:
            feed_ids.append(feed.id)
            full_text = f"{feed.title} {feed.content or ''} {feed.summary or ''} {feed.category} {feed.source or ''}".lower()
            entities = extract_entities(full_text)
            
            # ✅ FIXED: Count UNIQUE entities per article
            for key in entity_feed_counts:
                # Get unique entities (case-insensitive)
                unique_entities = set(e.lower() for e in entities[key])
                
                # Count each unique entity once per article
                for entity_lower in unique_entities:
                    entity_feed_counts[key][entity_lower] += 1
        
        # Save trending data for each entity type
        for entity_type, counts in entity_feed_counts.items():
            position = 1
            for entity_name, count in counts.most_common(10):  # Top 10 for each type
                if count < 2:  # Skip entities with less than 2 mentions
                    continue
                    
                total_mentions = sum(counts.values())
                percent = round((count / total_mentions * 100), 2) if total_mentions > 0 else 0
                
                # Determine risk level based on percentage
                if percent >= 30:
                    risk_level = 'critical'
                elif percent >= 20:
                    risk_level = 'high'
                elif percent >= 10:
                    risk_level = 'medium'
                else:
                    risk_level = 'low'
                
                # Format entity name
                display_name = entity_name.title()
                if re.match(r'^(apt|ta|fin)[-\s]?\d+', entity_name.lower()):
                    display_name = entity_name.upper().replace(' ', '-')
                
                # Get related feed IDs for this entity
                related_feed_ids = []
                for feed in feeds:
                    full_text = f"{feed.title} {feed.content or ''} {feed.summary or ''}".lower()
                    entities = extract_entities(full_text)
                    if entity_name in [e.lower() for e in entities.get(entity_type, [])]:
                        related_feed_ids.append(feed.id)
                
                # Update or create trending data
                TrendingData.objects.update_or_create(
                    entity_type=entity_type[:-1],  # Remove 's' for singular
                    entity_name=display_name,
                    time_period=time_period,
                    defaults={
                        'count': count,
                        'percent': f"{percent:.1f}%",
                        'raw_percent': percent,
                        'position': position,
                        'risk_level': risk_level,
                        'related_feed_ids': related_feed_ids[:10],  # Limit to 10
                    }
                )
                position += 1
        
        # Clean up old entries
        TrendingData.objects.filter(time_period=time_period, position__gt=10).delete()
        
        logger.info(f"Updated trending data for period: {time_period}")
        return True
    except Exception as e:
        logger.error(f"Error updating trending data: {e}")
        return False

def get_trending_data_from_db(entity_type, time_period='all', limit=10):
    """
    Get trending data from database
    """
    trending_items = TrendingData.objects.filter(
        entity_type=entity_type,
        time_period=time_period
    ).order_by('position')[:limit]
    
    result = []
    for item in trending_items:
        result.append({
            "name": item.entity_name,
            "percent": item.percent,
            "count": item.count,
            "raw_percent": item.raw_percent,
            "risk_level": item.risk_level,
            "url": f"/entity/{item.entity_type}/{item.entity_name.lower().replace(' ', '-')}"
        })
    
    return result

# ========== VIEWS ==========
def dashboard(request):
    now = timezone.now()
    
    # Get filter parameters from request
    time_period = request.GET.get('time', 'all')
    filter_group = request.GET.get('filter', 'all')
    
    # Get feeds filtered by time
    feeds_by_time = get_time_filtered_feeds(time_period)
    
    # Process feeds
    processed_feeds = []
    entity_feed_counts = {
        'actors': Counter(),
        'attacks': Counter(),
        'campaigns': Counter(),
        'industries': Counter(),
        'countries': Counter(),
        'cves': Counter()
    }
    
    feeds_with_entities_by_type = {
        'actors': 0,
        'attacks': 0,
        'campaigns': 0,
        'industries': 0,
        'countries': 0,
        'cves': 0
    }
    
    all_keywords_text = ""
    
    for idx, item in enumerate(feeds_by_time):
        full_text = f"{item.title} {item.content or ''} {item.summary or ''} {item.category} {item.source or ''}".lower()
        all_keywords_text += full_text + " "
        entities = extract_entities(full_text)
      
        for key in entity_feed_counts:
            if entities[key]:
                feeds_with_entities_by_type[key] += 1
            for entity_lower in set(e.lower() for e in entities[key]):
                entity_feed_counts[key][entity_lower] += 1
      
        category_display = dict(ThreatFeed.CATEGORIES).get(item.category, 'Cyber Threat')
        source_type = ('vendor' if item.feed_type == 'rss_vendor' else 'news' if item.feed_type == 'rss_news' else 'reddit' if item.feed_type == 'reddit' else 'otx' if item.feed_type == 'otx' else 'other')
        
        use_pandas = feeds_by_time.count() > 20
        scoring_engine = create_scoring_engine(use_pandas=use_pandas)
        context = {'title': item.title, 'content': item.content or '', 'published': item.published, 'source': item.source or '', 'feed_type': item.feed_type, 'entities': entities}
        threat_score_result = scoring_engine.calculate_score(context)
        risk_level = threat_score_result['risk_level']
        threat_score = threat_score_result['score']
      
        item_dict = {
            "title": item.title,
            "id": item.id,
            "summary": item.summary or ((item.content[:200] + '...') if item.content else item.title[:200] + '...'),
            "link": item.link,
            "published": item.published,
            "threat_score": threat_score,
            "risk_level": risk_level,
            "category": category_display,
            "source": item.source or 'Unknown',
            "source_type": source_type,
            "category_class": item.category.lower().replace(' ', '-'),
            "keywords": full_text,
            "raw_item": item
        }
        processed_feeds.append(item_dict)
    
    # Apply filter group if specified
    if filter_group != 'all':
        processed_feeds = filter_feeds_by_group(processed_feeds, filter_group)
    
    overview_feeds = processed_feeds
    trending_feeds = sorted(processed_feeds, key=lambda x: (x['threat_score'], x['published'] or now), reverse=True)[:50]
    
    total = len(processed_feeds)
    high = sum(1 for f in processed_feeds if f['risk_level'] in ['High', 'Critical'])
    critical = sum(1 for f in processed_feeds if f['risk_level'] == 'Critical')
    recent = sum(1 for f in processed_feeds if f['published'] and (now - f['published']).days < 1)
    
    vendor_sources = set(f['source'] for f in processed_feeds if f['source_type'] == 'vendor')
    news_sources = set(f['source'] for f in processed_feeds if f['source_type'] == 'news')
    reddit_sources = set(f['source'] for f in processed_feeds if f['source_type'] == 'reddit')
    vendors_monitored = len(vendor_sources) + len(news_sources) + len(reddit_sources)
    
    filter_options = [("ransomware", "Ransomware"), ("breach", "Breach"), ("zero-day", "Zero-Day"), ("vulnerability", "Vulnerability"), ("malware", "Malware"), ("phishing", "Phishing"), ("ddos", "DDoS"), ("apt", "APT")]
    active_filters = [{"filter": f, "name": n} for f, n in filter_options if f in all_keywords_text]
    
    has_vendor = len(vendor_sources) > 0
    has_news = len(news_sources) > 0
    has_reddit = len(reddit_sources) > 0
    
    # Get trending data from database
    trending_actors = get_trending_data_from_db('actor', time_period, 10)
    trending_attacks = get_trending_data_from_db('attack', time_period, 10)
    trending_campaigns = get_trending_data_from_db('campaign', time_period, 5)
    trending_industries = get_trending_data_from_db('industry', time_period, 10)
    trending_countries = get_trending_data_from_db('country', time_period, 10)
    trending_cves = get_trending_data_from_db('cve', time_period, 10)
    
    # If no trending data in DB, generate it on the fly
    if not trending_actors:
        trending_actors_data = get_trending_data_from_counts(
            entity_feed_counts['actors'],
            {},
            total_feeds=feeds_by_time.count(),
            limit=10,
            use_relative_percentage=True,
            include_other=True,
            entity_type='actor'
        )
        trending_actors = trending_actors_data
    
    if not trending_attacks:
        trending_attacks_data = get_trending_data_from_counts(
            entity_feed_counts['attacks'],
            None,
            total_feeds=feeds_by_time.count(),
            limit=10,
            use_relative_percentage=True,
            include_other=True,
            entity_type='attack'
        )
        trending_attacks = trending_attacks_data
    # NEW: Add these for industries and countries
        if not trending_industries:
            trending_industries_data = get_trending_data_from_counts(
                entity_feed_counts['industries'],
                None,
                total_feeds=feeds_by_time.count(),
                limit=10,
                use_relative_percentage=True,
                include_other=True,
                entity_type='industry'  # Relaxed thresholds apply here
            )
            trending_industries = trending_industries_data

        if not trending_countries:
            trending_countries_data = get_trending_data_from_counts(
                entity_feed_counts['countries'],
                None,
                total_feeds=feeds_by_time.count(),
                limit=10,
                use_relative_percentage=True,
                include_other=True,
                entity_type='country'  # Relaxed thresholds apply here
            )
            trending_countries = trending_countries_data
    # Calculate additional intelligence metrics
    def calculate_intelligence_metrics(entity_counts, entity_type):
        """Calculate professional intelligence metrics"""
        total_mentions = sum(entity_counts.values())
        if total_mentions == 0:
            return None
      
        top_5 = sum(count for _, count in entity_counts.most_common(7))
        concentration = (top_5 / total_mentions * 100)
      
        # Generate assessment
        if concentration >= 70:
            assessment = "Highly concentrated"
            color = "danger"
        elif concentration >= 50:
            assessment = "Moderately concentrated"
            color = "warning"
        elif concentration >= 30:
            assessment = "Diverse"
            color = "info"
        else:
            assessment = "Highly diverse"
            color = "success"
      
        return {
            'concentration': f"{concentration:.1f}%",
            'assessment': assessment,
            'color': color,
            'total_entities': len(entity_counts),
            'total_mentions': total_mentions
        }
  
    intelligence_metrics = {
        'actors': calculate_intelligence_metrics(entity_feed_counts['actors'], 'actors'),
        'attacks': calculate_intelligence_metrics(entity_feed_counts['attacks'], 'attacks'),
        'countries': calculate_intelligence_metrics(entity_feed_counts['countries'], 'countries'),
    }
  
    # Risk distribution
    risk_levels = [f['risk_level'] for f in processed_feeds]
    risk_distribution = Counter(risk_levels)
    total_for_dist = len(risk_levels) or 1
    risk_percentages = {}
  
    for level in ['Critical', 'High', 'Medium', 'Low']:
        count = risk_distribution.get(level, 0)
        risk_percentages[level] = (count / total_for_dist) * 100
    
    # Get filter presets
    filter_presets = FilterPreset.objects.filter(is_default=True)[:5] if hasattr(FilterPreset, 'objects') else []
    
    context = {
        "overview_feeds": overview_feeds,
        "trending_feeds": trending_feeds,
        "trending_actors": trending_actors,
        "trending_attacks": trending_attacks,
        "trending_campaigns": trending_campaigns,
        "trending_industries": trending_industries,
        "trending_countries": trending_countries,
        "trending_cves": trending_cves,
        "active_filters": active_filters,
        "active_time_period": time_period,
        "active_filter_group": filter_group,
        "filter_presets": filter_presets,
        "has_vendor": has_vendor,
        "has_news": has_news,
        "has_reddit": has_reddit,
        "risk_distribution": risk_percentages,
        "intelligence_metrics": intelligence_metrics,
        "stats": {
            "total_threats": total,
            "high_risk": high,
            "recent_threats": recent,
            "vendors_monitored": vendors_monitored,
            "critical_count": critical,
            "total_feeds": feeds_by_time.count(),
            "feeds_with_actors": feeds_with_entities_by_type['actors'],
            "attribution_rate": f"{(feeds_with_entities_by_type['actors'] / max(feeds_by_time.count(), 1) * 100):.1f}%",
        },
        "now": now,
    }
    return render(request, "dashboard.html", context)

@csrf_exempt
def update_trending_now(request):
    """
    API endpoint to manually update trending data
    """
    if request.method == 'POST':
        time_period = request.POST.get('time_period', 'all')
        success = update_trending_data_in_db(time_period)
        
        if success:
            return JsonResponse({'status': 'success', 'message': f'Trending data updated for {time_period}'})
        else:
            return JsonResponse({'status': 'error', 'message': 'Failed to update trending data'})
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

@csrf_exempt
def save_filter_preset(request):
    """
    Save a filter preset
    """
    if request.method == 'POST':
        name = request.POST.get('name')
        filter_group = request.POST.get('filter_group', 'all')
        time_period = request.POST.get('time_period', 'all')
        
        try:
            preset = FilterPreset.objects.create(
                name=name,
                filter_group=filter_group,
                time_period=time_period,
                filter_type='combined'
            )
            
            return JsonResponse({'status': 'success', 'id': preset.id, 'name': preset.name})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

def entity_detail(request, entity_type, entity_name):
    type_display_map = {'actor': 'Threat Actor', 'attack': 'Attack Type', 'campaign': 'Campaign', 'industry': 'Targeted Industry', 'country': 'Targeted Country', 'cve': 'CVE Vulnerability'}
  
    # Clean entity name
    entity_name_clean = entity_name.replace('-', ' ').title()
    entity_name_lower = entity_name_clean.lower()
  
    # FIRST: Get ALL feeds and extract entities from each
    all_feeds = ThreatFeed.objects.all()
    
    # Lists to store feeds containing the entity
    feeds_with_entity = []
    processed_feeds = []
    
    # Counters for entity occurrences
    entity_feed_counts = {
        'actors': Counter(),
        'attacks': Counter(),
        'campaigns': Counter(),
        'industries': Counter(),
        'countries': Counter(),
        'cves': Counter()
    }
    
    # Collect all related entities
    all_entities = {key: [] for key in ['actors', 'attacks', 'campaigns', 'industries', 'countries', 'cves']}
    
    # Process each feed to find if it contains the entity
    for item in all_feeds:
        full_text = f"{item.title} {item.content or ''} {item.summary or ''} {item.category} {item.source or ''}".lower()
        entities = extract_entities(full_text)
        
        # ✅ FIXED: Count each entity occurrence (UNIQUE per article)
        for key in entity_feed_counts:
            # Get unique entities (case-insensitive)
            unique_entities = set(e.lower() for e in entities[key])
            
            # Count each unique entity once per article
            for entity_lower in unique_entities:
                entity_feed_counts[key][entity_lower] += 1
            
            # Also collect all entities for the list
            all_entities[key].extend(entities[key])
        
        # Check if this feed contains the entity we're looking for
        contains_entity = False
        
        if entity_type == 'actor' and entity_name_lower in [a.lower() for a in entities['actors']]:
            contains_entity = True
        elif entity_type == 'attack' and entity_name_lower in [a.lower() for a in entities['attacks']]:
            contains_entity = True
        elif entity_type == 'campaign' and entity_name_lower in [c.lower() for c in entities['campaigns']]:
            contains_entity = True
        elif entity_type == 'industry' and entity_name_lower in [i.lower() for i in entities['industries']]:
            contains_entity = True
        elif entity_type == 'country' and entity_name_lower in [c.lower() for c in entities['countries']]:
            contains_entity = True
        elif entity_type == 'cve':
            # For CVE, check for exact match (uppercase)
            cve_pattern = entity_name.upper()
            contains_entity = cve_pattern in entities['cves']
            if contains_entity:
                entity_name_clean = cve_pattern
        
        if contains_entity:
            feeds_with_entity.append(item)
    
    # Get the ACTUAL count from entity extraction (matches dashboard)
    actual_entity_count = 0
    if entity_type == 'actor':
        actual_entity_count = entity_feed_counts['actors'].get(entity_name_lower, 0)
    elif entity_type == 'attack':
        actual_entity_count = entity_feed_counts['attacks'].get(entity_name_lower, 0)
    elif entity_type == 'campaign':
        actual_entity_count = entity_feed_counts['campaigns'].get(entity_name_lower, 0)
    elif entity_type == 'industry':
        actual_entity_count = entity_feed_counts['industries'].get(entity_name_lower, 0)
    elif entity_type == 'country':
        actual_entity_count = entity_feed_counts['countries'].get(entity_name_lower, 0)
    elif entity_type == 'cve':
        actual_entity_count = entity_feed_counts['cves'].get(entity_name.upper(), 0)
    
    # Process feeds containing the entity
    for item in feeds_with_entity:
        full_text = f"{item.title} {item.content or ''} {item.summary or ''} {item.category} {item.source or ''}".lower()
        entities = extract_entities(full_text)
        
        category_display = dict(ThreatFeed.CATEGORIES).get(item.category, 'Cyber Threat')
        source_type = ('vendor' if item.feed_type == 'rss_vendor' else 'news' if item.feed_type == 'rss_news' else 'reddit' if item.feed_type == 'reddit' else 'otx' if item.feed_type == 'otx' else 'other')
        
        # Use Pandas if many entities
        use_pandas = len(feeds_with_entity) > 15
        is_threat_actor = (entity_type == 'actor')
        scoring_engine = create_scoring_engine(use_pandas=use_pandas, is_threat_actor=is_threat_actor)
        
        context = {
            'title': item.title,
            'content': item.content or '',
            'published': item.published,
            'source': item.source or '',
            'feed_type': item.feed_type,
            'entities': entities,
            'entity_name': entity_name_clean,
            'is_threat_actor': is_threat_actor
        }
      
        threat_score_result = scoring_engine.calculate_score(context)
        risk_level = threat_score_result['risk_level']
        threat_score = threat_score_result['score']
      
        # Boost score for known threat actors
        if is_threat_actor:
            known_actors = ['play', 'lazarus', 'apt29', 'apt28', 'conti', 'revil', 'lockbit', 'clop', 'blackcat', 'alphv']
            if any(actor in entity_name_lower for actor in known_actors):
                threat_score = min(100, threat_score * 1.2) # 20% boost
      
        item_dict = {
            "title": item.title,
            "id": item.id,
            "summary": item.summary or ((item.content[:200] + '...') if item.content else item.title[:200] + '...'),
            "link": item.link,
            "published": item.published,
            "threat_score": threat_score,
            "risk_level": risk_level,
            "category": category_display,
            "source": item.source or 'Unknown',
            "source_type": source_type,
            "category_class": item.category.lower().replace(' ', '-'),
            "keywords": full_text,
            "raw_item": item
        }
        processed_feeds.append(item_dict)
    
    total_feeds = len(feeds_with_entity)  # Actual number of feeds containing the entity
    
    if total_feeds == 0:
        context = {
            'entity': {'name': entity_name_clean, 'type': type_display_map.get(entity_type, 'Entity'), 'display_type': entity_type, 'description': f'No threat intelligence data found for {entity_name_clean}.', 'feeds_count': 0, 'risk_score': 0},
            'feeds': [],
            'page_title': f'{entity_name_clean} - Threat Intelligence',
            'stats': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'now': timezone.now()
        }
        return render(request, 'entity_detail.html', context)
    
    # Sort feeds by date (most recent first) for main display
    all_feeds_sorted = sorted(processed_feeds, key=lambda x: x['published'] if x['published'] else timezone.now(), reverse=True)
    
    # Get top feeds by threat score for sidebar (limit to 10)
    top_feeds = sorted(processed_feeds, key=lambda x: x['threat_score'], reverse=True)[:10]
    
    critical_feeds = sum(1 for f in processed_feeds if f['threat_score'] >= 85)
    high_feeds = sum(1 for f in processed_feeds if f['threat_score'] >= 70 and f['threat_score'] < 85)
    medium_feeds = sum(1 for f in processed_feeds if f['threat_score'] >= 40 and f['threat_score'] < 70)
    low_feeds = sum(1 for f in processed_feeds if f['threat_score'] < 40)
    
    # SIMPLE AVERAGE CALCULATION: Sum all scores divided by number of feeds
    avg_threat_score = sum(f['threat_score'] for f in processed_feeds) / total_feeds if total_feeds > 0 else 0
    
    # Calculate time-based metrics
    now = timezone.now()
    thirty_days_ago = now - timedelta(days=30)
    fourteen_days_ago = now - timedelta(days=14)
    seven_days_ago = now - timedelta(days=7)
    
    # Count feeds by time periods
    recent_feeds_count = sum(1 for f in processed_feeds if f['published'] and f['published'] >= thirty_days_ago)
    last_7_days = sum(1 for f in processed_feeds if f['published'] and f['published'] >= seven_days_ago)
    
    # IMPROVED TREND CALCULATION
    if total_feeds > recent_feeds_count and recent_feeds_count > 0:
        # Has both recent and older feeds
        older_feeds = total_feeds - recent_feeds_count
        trend_percentage = ((recent_feeds_count - older_feeds) / older_feeds * 100) if older_feeds > 0 else 100
    elif recent_feeds_count > 0:
        # All feeds are recent (within 30 days) - this is good!
        trend_percentage = 100
    else:
        # No recent feeds
        trend_percentage = -100
    
    # Cap extreme values
    trend_percentage = max(-100, min(100, trend_percentage))
    
    # Collect related entities from feeds containing the main entity
    related_entities = {'actors': set(), 'attacks': set(), 'campaigns': set(), 'industries': set(), 'countries': set(), 'cves': set()}
    
    for feed in processed_feeds:
        if 'raw_item' in feed and feed['raw_item'].content:
            text = f"{feed['raw_item'].title} {feed['raw_item'].content}".lower()
            entities = extract_entities(text)
            
            # Add all entities except the main one we're viewing
            for key in related_entities:
                if key != f"{entity_type}s":  # Don't add entities of the same type
                    for entity in entities[key]:
                        # For case-insensitive comparison
                        if entity_type == 'cve':
                            if entity.upper() != entity_name.upper():
                                related_entities[key].add(entity)
                        elif entity.lower() != entity_name_lower:
                            related_entities[key].add(entity)
    
    # Get first and last seen dates
    feeds_with_dates = [f for f in processed_feeds if f['published']]
    first_seen = min(f['published'] for f in feeds_with_dates) if feeds_with_dates else None
    last_seen = max(f['published'] for f in feeds_with_dates) if feeds_with_dates else None
    
    # Build description
    description = f"{type_display_map.get(entity_type, 'Entity')} '{entity_name_clean}' appears in {total_feeds} threat intelligence feeds."
    
    if entity_type == 'actor':
        if first_seen:
            description += f" This threat actor has been active since {first_seen.strftime('%B %Y')}."
        description += f" Average threat score: {avg_threat_score:.1f}/100."
    elif entity_type == 'cve':
        description += f" This vulnerability affects multiple systems and has an average risk score of {avg_threat_score:.1f}/100."
    
    # Get counts for related entities
    related_actors_with_counts = []
    related_attacks_with_counts = []
    related_campaigns_with_counts = []
    related_industries_with_counts = []
    related_countries_with_counts = []
    related_cves_with_counts = []
    
    # Prepare related entities with their counts
    for actor in list(related_entities['actors'])[:10]:
        count = entity_feed_counts['actors'].get(actor.lower(), 0)
        related_actors_with_counts.append({'name': actor, 'count': count})
    
    for attack in list(related_entities['attacks'])[:10]:
        count = entity_feed_counts['attacks'].get(attack.lower(), 0)
        related_attacks_with_counts.append({'name': attack, 'count': count})
    
    for campaign in list(related_entities['campaigns'])[:10]:
        count = entity_feed_counts['campaigns'].get(campaign.lower(), 0)
        related_campaigns_with_counts.append({'name': campaign, 'count': count})
    
    for industry in list(related_entities['industries'])[:10]:
        count = entity_feed_counts['industries'].get(industry.lower(), 0)
        related_industries_with_counts.append({'name': industry, 'count': count})
    
    for country in list(related_entities['countries'])[:5]:
        count = entity_feed_counts['countries'].get(country.lower(), 0)
        related_countries_with_counts.append({'name': country, 'count': count})
    
    for cve in list(related_entities['cves'])[:10]:
        count = entity_feed_counts['cves'].get(cve.upper(), 0)
        related_cves_with_counts.append({'name': cve, 'count': count})
    
    context = {
        'entity': {
            'name': entity_name_clean,
            'type': type_display_map.get(entity_type, 'Entity'),
            'display_type': entity_type,
            'description': description,
            'feeds_count': total_feeds,  # Actual count of feeds containing the entity
            'risk_score': round(avg_threat_score, 1),
            'first_seen': first_seen,
            'last_seen': last_seen,
            'trend_percentage': round(trend_percentage, 1),
            'trend_direction': 'up' if trend_percentage > 0 else 'down',
            'related_actors': related_actors_with_counts,
            'related_attacks': related_attacks_with_counts,
            'related_campaigns': related_campaigns_with_counts,
            'related_industries': related_industries_with_counts,
            'related_countries': related_countries_with_counts,
            'related_cves': related_cves_with_counts,
            'top_feeds': top_feeds  # Top 10 feeds for sidebar
        },
        'feeds': all_feeds_sorted,  # ALL feeds containing the entity for main display
        'page_title': f'{entity_name_clean} - Threat Intelligence',
        'stats': {'total': total_feeds, 'critical': critical_feeds, 'high': high_feeds, 'medium': medium_feeds, 'low': low_feeds},
        'now': timezone.now()
    }
    return render(request, 'entity_detail.html', context)
# Add these to your views.py

def filter_view(request, filter_group):
    """
    Dedicated view for a specific filter group
    """
    # Redirect to dashboard with filter parameter
    from django.shortcuts import redirect
    return redirect(f'/?filter={filter_group}')

def time_filter_view(request, time_period):
    """
    Dedicated view for a specific time period
    """
    # Redirect to dashboard with time parameter
    from django.shortcuts import redirect
    return redirect(f'/?time={time_period}')

def combined_filter_view(request, time_period, filter_group):
    """
    Dedicated view for combined time and filter
    """
    # Redirect to dashboard with both parameters
    from django.shortcuts import redirect
    return redirect(f'/?time={time_period}&filter={filter_group}')

def read_article(request, pk):
    feed = get_object_or_404(ThreatFeed, pk=pk)
    content = feed.content or feed.summary
    if not content or len(content.strip()) < 300:
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36'}
            response = requests.get(feed.link, headers=headers, timeout=30)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            for elem in soup(['script', 'style', 'nav', 'header', 'footer', 'aside', 'iframe', 'form', 'noscript']):
                elem.decompose()
            selectors = ['article', '.article-content', '.post-content', '.entry-content', '.content', 'main', '[role="main"]', '.story-body', '.post-body', '.article-body', '.blog-post', '.news-article', '.field-body']
            article_body = None
            for sel in selectors:
                article_body = soup.select_one(sel)
                if article_body and len(article_body.get_text(strip=True)) > 500:
                    break
            if not article_body:
                paras = soup.find_all('p')
                article_body = soup.new_tag('div')
                for p in paras:
                    txt = p.get_text(strip=True)
                    if 50 < len(txt) < 2000:
                        article_body.append(p)
            content = article_body.get_text(separator='\n\n', strip=True) if article_body else "No readable content found."
            if len(content) > 60000:
                content = content[:60000] + "\n\n[Article truncated for display]"
        except Exception as e:
            logger.error(f"Scrape failed: {feed.link} | {e}")
            content = f"Could not load full article. Visit: {feed.link}"
    entities = extract_entities(f"{feed.title} {content}".lower())
    scoring_engine = create_scoring_engine(use_pandas=True) # Enable Pandas for detailed article
    risk_analysis = scoring_engine.calculate_score({'title': feed.title, 'content': content, 'published': feed.published, 'source': feed.source or '', 'feed_type': feed.feed_type, 'entities': entities})
    context = {
        'article': {
            'title': feed.title,
            'content': content,
            'source': feed.source or "Unknown Source",
            'published': feed.published.strftime("%B %d, %Y at %H:%M") if feed.published else "Unknown date",
            'source_url': feed.link,
        },
        'feed': feed,
        'risk_analysis': risk_analysis,
        'entities': entities,
        'scoring_factors': risk_analysis['factors'],
    }
    return render(request, 'read_article.html', context)
# In views.py – modify read_article_summary

@csrf_exempt
def read_article_summary(request):
    if request.method != "GET":
        return JsonResponse({"error": "GET required"}, status=400)
    text = request.GET.get("text", "")
    title = request.GET.get("title", "Article")[:100]
    clean_text = re.sub(r'\s+', ' ', text).strip()
    logger.info(f"AI summary request — text length: {len(clean_text)}")
    # Generate summary without any risk calculation
    exec_summary = generate_t5_summary(title, clean_text)
    lower_text = clean_text.lower()
    extensions = re.findall(
        r'\b(free-vpn-forever|screenshot-saved-easy|weather-best-forecast|crxmouse-gesture|cache-fast-site-loader|freemp3downloader|google-translate-right-clicks|google-traductor-esp|world-wide-vpn|dark-reader-for-ff|translator-gbbd|i-like-weather|google-translate-pro-extension|libretv-watch-free-videos|ad-stop|right-click-google-translate)\b',
        lower_text,
        re.I
    )
    domains = re.findall(
        r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]',
        lower_text
    )
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', lower_text)
    iocs_list = extensions[:3] + domains[:2] + ips[:2]
    iocs = ", ".join(iocs_list) if iocs_list else "None detected"
    return JsonResponse({
        "actor": "Unknown Threat Actor",
        "iocs": iocs,
        "executive_summary": exec_summary,
        "timestamp": timezone.now().strftime("%H:%M"),
        "extracted_info": {
            "extensions": extensions,
            "domains": domains,
            "ips": ips
        }
    })

def clean_article_content(text):
    """
    Clean article text by removing tags, metadata, and boilerplate.
    """
    if not text:
        return ""
    
    # Remove common metadata sections
    patterns_to_remove = [
        # Tags section
        r'(?i)tags?[:\s]*\n.*$',
        r'(?i)categories?[:\s]*\n.*$',
        # Social media/follow sections
        r'(?i)follow\s+(me\s+)?on[^\.]*\.?$',
        r'(?i)connect\s+with\s+us[^\.]*\.?$',
        # Author/source metadata
        r'(?i)by\s+[a-z\s]+\s*$',
        r'(?i)posted\s+by\s+[a-z\s]+\s*$',
        # Read more/related articles
        r'(?i)read\s+more[^\.]*\.?$',
        r'(?i)related\s+(articles|stories|posts)[^\.]*\.?$',
        # Comments section
        r'(?i)comments?[^\.]*\.?$',
        r'(?i)leave\s+a\s+comment[^\.]*\.?$',
        # Share buttons
        r'(?i)share\s+this[^\.]*\.?$',
        # Newsletter/subscribe
        r'(?i)subscribe[^\.]*\.?$',
        r'(?i)newsletter[^\.]*\.?$',
    ]
    
    cleaned = text
    for pattern in patterns_to_remove:
        cleaned = re.sub(pattern, '', cleaned, flags=re.MULTILINE | re.IGNORECASE)
    
    # Split by lines and filter out metadata lines
    lines = cleaned.split('\n')
    filtered_lines = []
    
    for line in lines:
        line_stripped = line.strip()
        if not line_stripped:
            continue
        
        # Skip lines that are likely metadata
        if (
            len(line_stripped) < 20 and  # Very short lines
            any(indicator in line_stripped.lower() for indicator in [
                'tags:', 'category:', 'posted in', 'follow', 'share', 'comments'
            ])
        ):
            continue
        
        # Skip social media handles
        if re.match(r'^@[a-zA-Z0-9_]+$', line_stripped):
            continue
        
        # Skip email addresses
        if '@' in line_stripped and '.' in line_stripped:
            continue
        
        # Skip URLs
        if re.match(r'^https?://', line_stripped):
            continue
        
        filtered_lines.append(line_stripped)
    
    cleaned = ' '.join(filtered_lines)
    
    # Remove extra whitespace
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    
    return cleaned


def normalize_entity_name(entity, entity_type):
    """
    Normalize entity names for consistency.
    """
    if not entity:
        return entity
    
    entity_lower = entity.lower()
    
    # Special cases for different entity types
    if entity_type == "actor":
        # APT groups
        apt_match = re.match(r'(?:apt|ta|fin)[-\s]?(\d+)', entity_lower)
        if apt_match:
            prefix = "APT" if "apt" in entity_lower else "TA" if "ta" in entity_lower else "FIN"
            return f"{prefix}-{apt_match.group(1)}"
        
        # Common ransomware groups
        ransomware_groups = {
            "lockbit": "LockBit",
            "clop": "Cl0p", 
            "conti": "Conti",
            "revil": "REvil",
            "hive": "Hive",
            "blackcat": "BlackCat",
            "alphv": "ALPHV",
            "play": "Play",
            "bianlian": "BianLian",
            "royal": "Royal",
            "medusa": "Medusa",
            "gentlemen": "Gentlemen"
        }
        
        for key, value in ransomware_groups.items():
            if key in entity_lower:
                return value
    
    elif entity_type == "attack":
        attack_map = {
            "ransomware": "Ransomware",
            "phishing": "Phishing",
            "malware": "Malware",
            "ddos": "DDoS",
            "zero-day": "Zero-day",
            "vulnerability": "Vulnerability",
            "breach": "Data Breach",
            "supply chain": "Supply Chain Attack",
            "apt": "Advanced Persistent Threat"
        }
        
        for key, value in attack_map.items():
            if key in entity_lower:
                return value
    
    elif entity_type == "cve":
        if re.match(r'^cve-\d{4}-\d+$', entity_lower):
            return entity.upper()
    
    # Default: title case for multi-word, upper for single acronyms
    if ' ' in entity or '-' in entity:
        words = []
        for word in re.split(r'[\s-]+', entity):
            if word.upper() == word:  # Already an acronym
                words.append(word)
            elif len(word) <= 3:  # Short words like "USA", "UK"
                words.append(word.upper())
            else:
                words.append(word.title())
        
        if '-' in entity:
            return '-'.join(words)
        return ' '.join(words)
    
    # Single word entities
    if len(entity) <= 3:
        return entity.upper()
    return entity.title()
@csrf_exempt
def ai_analyze_article(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=400)
    url = request.POST.get("url")
    title = request.POST.get("title", "Article").strip()[:120]
    if not url:
        return JsonResponse({"error": "No URL"}, status=400)
    cache_key = url
    if cache_key in ANALYSIS_CACHE:
        cached = ANALYSIS_CACHE[cache_key]
        if timezone.now() - cached["time"] < timedelta(hours=24):
            return JsonResponse(cached["result"])
    content = extract_text_from_url(url)
    content = content[:1200]
    if len(content) < 150:
        content = "No readable content found."
    scoring_engine = create_scoring_engine(use_pandas=True)
    context_data = {'title': title, 'content': content, 'published': None, 'source': '', 'feed_type': '', 'entities': extract_entities(f"{title} {content}".lower())}
    risk_result = scoring_engine.calculate_score(context_data)
    analysis = f"• Actor: Unknown\n• IOCs: None\n• Risk: {risk_result['risk_level']} (based on {risk_result['score']}/100)"
    result = {
        "title": title,
        "url": url,
        "analysis": analysis,
        "risk_score": risk_result['score'],
        "risk_level": risk_result['risk_level'],
        "scoring_factors": risk_result['factors'],
        "generated_at": timezone.now().strftime("%H:%M")
    }
    ANALYSIS_CACHE[cache_key] = {"time": timezone.now(), "result": result}
    return JsonResponse(result)
def profiles(request):
    try:
        from .ingest_feed import populate_threat_library, create_realistic_threat_relationships
        if not ThreatProfile.objects.exists():
            populate_threat_library()
            create_realistic_threat_relationships()
    except ImportError:
        logger.warning("Could not import ingest_feed functions")
    qs = ThreatProfile.objects.all()
    industry = request.GET.get("industry")
    region = request.GET.get("region")
    focus = request.GET.get("focus")
    if industry:
        qs = qs.filter(industry=industry)
    if region:
        qs = qs.filter(region=region)
    if focus:
        qs = qs.filter(threat_focus=focus)
    selected_id = request.GET.get("profile")
    selected = None
    if selected_id:
        try:
            selected = ThreatProfile.objects.get(id=selected_id)
        except:
            pass
    return render(request, "profiles.html", {
        "profiles": qs,
        "selected_profile": selected,
        "industry": industry,
        "region": region,
        "focus": focus,
    })
def library(request):
    tab = request.GET.get('tab', 'all')
    query = request.GET.get("q", "").strip()
  
    # Pagination parameters
    page_number = request.GET.get('page', 1)
    items_per_page = 50
  
    results = []
    profiles = []
  
    # Statistics - optimized with single queries where possible
    total_records = ThreatRecord.objects.count() if hasattr(ThreatRecord, 'objects') else 0
  
    # Use conditional aggregation for better performance
    if hasattr(ThreatRecord, 'objects') and ThreatRecord.objects.exists():
        stats = ThreatRecord.objects.aggregate(
            high_risk=Count('id', filter=Q(threat_score__gte=80)),
            cve_count=Count('id', filter=Q(type='cve')),
            critical_cve=Count('id', filter=Q(type='cve', threat_score__gte=90)),
            malicious_ip=Count('id', filter=Q(type='ip', reputation='malicious')),
            online_url=Count('id', filter=Q(type='url', reputation='malicious'))
        )
      
        high_risk = stats['high_risk']
        cve_count = stats['cve_count']
        critical_cve_count = stats['critical_cve']
        malicious_ip_count = stats['malicious_ip']
        online_count = stats['online_url']
      
        last_updated_record = ThreatRecord.objects.order_by('-last_seen').first()
        last_updated = last_updated_record.last_seen if last_updated_record else timezone.now()
    else:
        high_risk = cve_count = critical_cve_count = malicious_ip_count = online_count = 0
        last_updated = timezone.now()
  
    actor_count = ThreatProfile.objects.count() if hasattr(ThreatProfile, 'objects') else 0
  
    # Handle threat actors tab
    if tab == 'actors':
        qs = ThreatProfile.objects.all()
        if query:
            qs = qs.filter(
                Q(name__icontains=query) |
                Q(description__icontains=query) |
                Q(aliases__icontains=query)
            )
        qs = qs.order_by('name')
      
        # Pagination for actors
        paginator = Paginator(qs, items_per_page)
        page_obj = paginator.get_page(page_number)
        profiles = page_obj.object_list
      
    else:
        # Handle threat records
        qs = ThreatRecord.objects.all()
      
        if tab != 'all':
            qs = qs.filter(type=tab)
      
        # NEW: Filter IPs to malicious only (exclude clean/suspicious unless specified)
        if tab == 'ip':
            qs = qs.filter(reputation='malicious')
      
        if query:
            # Safe query construction - handle tags field appropriately
            query_filter = Q(value__icontains=query) | Q(description__icontains=query) | Q(category__icontains=query)
          
            # Check if tags field exists and handle appropriately
            try:
                # Try different approaches for tags field
                # If tags is a JSONField:
                # query_filter |= Q(tags__contains=[query])
                # If tags is a CharField or ArrayField:
                query_filter |= Q(tags__icontains=query)
            except Exception:
                # If tags query fails, just use other fields
                pass
          
            qs = qs.filter(query_filter)
        
        # ====== FIXED: SPECIAL SORTING FOR CVEs ======
        if tab == 'cve':
            # We need custom sorting for CVEs: 2026 first, then 2025
            # Get all CVEs first
            all_cves = list(qs)
            
            # Define sorting function for CVEs
            def cve_sort_key(record):
                try:
                    # Extract year and sequence from CVE-YYYY-NNNNN
                    if record.value.startswith('CVE-'):
                        parts = record.value.split('-')
                        if len(parts) >= 3:
                            year = int(parts[1])  # YYYY part
                            
                            # Extract sequence number (handle cases like "12345a")
                            seq_str = parts[2]
                            seq_num = ''
                            for char in seq_str:
                                if char.isdigit():
                                    seq_num += char
                                else:
                                    break
                            sequence = int(seq_num) if seq_num else 0
                            
                            # Return tuple: (-year, -sequence) for descending sort
                            # This will put 2026 before 2025, and higher sequences first
                            return (-year, -sequence)
                except (ValueError, IndexError, AttributeError):
                    pass
                # Default for non-CVEs or parsing errors
                return (0, 0)
            
            # Sort CVEs with custom key
            sorted_cves = sorted(all_cves, key=cve_sort_key)
            
            # Paginate the sorted list
            paginator = Paginator(sorted_cves, items_per_page)
            page_obj = paginator.get_page(page_number)
            results = page_obj.object_list
            
            # Debug output (remove in production)
            print(f"[DEBUG] CVE Sorting: Found {len(sorted_cves)} CVEs")
            for i, cve in enumerate(sorted_cves[:10]):
                try:
                    year = cve.value.split('-')[1]
                    print(f"  {i+1}. {cve.value} (Year: {year})")
                except:
                    print(f"  {i+1}. {cve.value}")
        
        else:
            # For other tabs, use normal database ordering
            qs = qs.order_by('-first_seen')
          
            # Pagination for threat records
            paginator = Paginator(qs, items_per_page)
            page_obj = paginator.get_page(page_number)
            results = page_obj.object_list
  
    return render(request, "library.html", {
        "tab": tab,
        "query": query,
        "results": results,
        "profiles": profiles,
        "total_records": total_records,
        "high_risk": high_risk,
        "cve_count": cve_count,
        "actor_count": actor_count,
        "critical_cve_count": critical_cve_count,
        "malicious_ip_count": malicious_ip_count,
        "online_count": online_count,
        "last_updated": last_updated,
        "page_obj": page_obj if tab != 'actors' else None,
        "actors_page_obj": page_obj if tab == 'actors' else None,
    })
  
@csrf_exempt
def refresh_library(request):
    if request.method != 'POST':
        return JsonResponse({"error": "POST required"}, status=400)
    try:
        try:
            from .ingest_feed import (
                ingest_urls, ingest_malware, ingest_ips, ingest_cves,
            )
            total = 0
            total += ingest_urls()
            total += ingest_malware()
            total += ingest_ips()
          
            total += ingest_cves()
       
            return JsonResponse({
                "status": "success",
                "message": f"✅ Library refreshed! Ingested/updated {total} records/profiles. (Updated: {timezone.now().strftime('%Y-%m-%d %H:%M UTC')})"
            })
        except ImportError as e:
            return JsonResponse({
                "status": "warning",
                "message": f"⚠️ Ingest functions not available: {str(e)}. Running feed ingestion only."
            })
    except Exception as e:
        return JsonResponse({
            "status": "error",
            "error": f"Refresh failed: {str(e)}"
        }, status=500)
@csrf_exempt
def update_scoring_weights(request):
    if request.method != 'POST':
        return JsonResponse({"error": "POST required"}, status=400)
    try:
        data = json.loads(request.body)
        request.session['scoring_weights'] = {
            'keyword_weight': float(data.get('keyword_weight', 0.35)),
            'temporal_weight': float(data.get('temporal_weight', 0.25)),
            'content_weight': float(data.get('content_weight', 0.15)),
            'entity_weight': float(data.get('entity_weight', 0.10)),
            'source_weight': float(data.get('source_weight', 0.10)),
            'correlation_weight': float(data.get('correlation_weight', 0.05)),
        }
        return JsonResponse({
            "status": "success",
            "message": "Scoring weights updated successfully",
            "weights": request.session['scoring_weights']
        })
    except Exception as e:
        return JsonResponse({
            "status": "error",
            "error": f"Failed to update weights: {str(e)}"
        }, status=500)
def refresh_profiles(request):
    try:
        from .ingest_feed import populate_threat_library, create_realistic_threat_relationships
        populate_threat_library()
        create_realistic_threat_relationships()
        messages.success(request, "Threat library refreshed!")
    except ImportError as e:
        messages.error(request, f"Failed to import ingest functions: {e}")
    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/profiles/'))
@csrf_exempt
def start_auto_ingestion(request):
    def run_in_background():
        try:
            subprocess.run([
                'python', 'manage.py', 'ingest_feed',
                '--continuous', '--interval', '5'
            ], cwd=os.path.dirname(os.path.abspath(__file__)))
        except Exception as e:
            print(f"Auto-ingestion error: {e}")
    thread = threading.Thread(target=run_in_background)
    thread.daemon = True
    thread.start()
    return JsonResponse({
        'status': 'success',
        'message': 'Auto-ingestion started in background'
    })
@csrf_exempt
def check_ingestion_status(request):
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = proc.info.get('cmdline', [])
            if 'ingest_feed' in str(cmdline):
                return JsonResponse({
                    'status': 'running',
                    'pid': proc.info['pid']
                })
        except:
            continue
    return JsonResponse({'status': 'stopped'})
# views.py
@csrf_exempt
def run_ingestion_command(request):
    if request.method == 'POST':
        try:
            # Run the ingestion command
            result = subprocess.run(
                [sys.executable, 'manage.py', 'ingest_news', '--force'],
                capture_output=True,
                text=True,
                cwd='.' # Adjust if your manage.py is in a different directory
            )
          
            if result.returncode == 0:
                return JsonResponse({
                    'status': 'success',
                    'output': result.stdout,
                    'error': result.stderr
                })
            else:
                return JsonResponse({
                    'status': 'error',
                    'output': result.stdout,
                    'error': result.stderr
                })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'error': str(e)
            })
    return JsonResponse({'status': 'error', 'error': 'Invalid request method'})
import random
import re
from collections import Counter
from datetime import timedelta
from django.shortcuts import render, redirect
from django.utils import timezone
from django.db.models import Count
from django.contrib import messages  # If needed for errors
from .models import ThreatFeed, TrendingData  # Ensure imports
from .views import extract_entities, get_trending_data_from_db  # Assuming these are in views.py or imported

def clear_chat(request):
    """Clear the conversation history"""
    if 'conversation_history' in request.session:
        del request.session['conversation_history']
    return redirect('chatbot')

def chatbot(request):
    # Initialize conversation history if it doesn't exist
    if 'conversation_history' not in request.session:
        request.session['conversation_history'] = []
    
    conversation = request.session['conversation_history']
    
    if request.method == "POST":
        user_message = request.POST.get("message", "").strip()
        if not user_message:
            return render(request, "chatbot.html", {'conversation': conversation})
        
        now = timezone.now()
        user_message_lower = user_message.lower()
        
        # Store original message for LLM fallback
        original_message_for_llm = user_message_lower
        
        # -------------------------------
        # GREETINGS HANDLING - IMPROVED
        # -------------------------------
        greeting_keywords = ["hello", "hi", "hey", "greetings", "good morning", 
                             "good afternoon", "good evening", "how are you"]
        
        greeting_responses = [
            "Hello! I'm TIARF AI, your cyber threat intelligence assistant. ",
            "Hi there! I'm here to help you analyze threat intelligence feeds. ",
            "Hello! How can I assist you with threat intelligence information today? ",
            "Hi! I'm ready to help you with threat feed analysis. "
        ]
        
        # Check if message starts with greeting
        has_greeting = False
        for greeting in greeting_keywords:
            if user_message_lower.startswith(greeting):
                has_greeting = True
                # Remove greeting from message for processing
                user_message_lower = user_message_lower[len(greeting):].strip()
                # Remove any punctuation after greeting
                user_message_lower = re.sub(r'^[,\s.!?]+', '', user_message_lower)
                break
        
        # If message is empty after removing greeting, it's just a greeting
        if not user_message_lower:
            ai_reply = random.choice(greeting_responses) + "Please ask me about trending threats, threat actors, or recent cybersecurity news."
            
            conversation.append({
                'sender': 'user',
                'message': user_message,
                'timestamp': now.isoformat()
            })
            conversation.append({
                'sender': 'ai',
                'message': ai_reply,
                'timestamp': now.isoformat()
            })
            
            request.session['conversation_history'] = conversation
            request.session.modified = True
            
            return render(request, "chatbot.html", {
                'conversation': conversation,
                'time_period': "today"
            })
        
        # Use the message for processing (with or without greeting)
        user_message = user_message_lower
        needs_greeting_prefix = has_greeting  # Flag for later use
        
        # -------------------------------
        # TIME SCOPE DETECTION
        # -------------------------------
        time_patterns = {
            "today": {
                "keywords": ["today", "this day", "current day", "day's"],
                "hours": 24
            },
            "last_24h": {
                "keywords": ["last 24", "24 hour", "24 hours", "past day", "last day", "recent 24"],
                "hours": 24
            },
            "this_week": {
                "keywords": ["this week", "past week", "last 7 days", "7 days", "weekly"],
                "hours": 168
            },
            "this_month": {
                "keywords": ["this month", "past month", "last 30 days", "monthly"],
                "hours": 720
            },
            "yesterday": {
                "keywords": ["yesterday", "previous day"],
                "hours": 48,
                "end_hours": 24
            }
        }
        
        time_label = "overall"
        time_filter = None
        base_qs = ThreatFeed.objects.all()
        
        # Detect time scope
        for time_scope, pattern in time_patterns.items():
            if any(keyword in user_message for keyword in pattern["keywords"]):
                hours = pattern["hours"]
                start_time = now - timedelta(hours=hours)
                if "end_hours" in pattern:
                    end_time = now - timedelta(hours=pattern["end_hours"])
                    base_qs = ThreatFeed.objects.filter(published__range=(start_time, end_time))
                    time_label = f"yesterday (last 24 hours before today)"
                else:
                    base_qs = ThreatFeed.objects.filter(published__gte=start_time)
                    if hours >= 168:  # 7 days or more
                        time_label = f"in the last {hours//24} days"
                    else:
                        time_label = f"in the last 24 hours"
                time_filter = time_scope
                break
        
        # If no specific time mentioned, check for "recent" or "latest"
        if not time_filter and any(word in user_message for word in ["recent", "latest", "new", "fresh"]):
            base_qs = ThreatFeed.objects.filter(published__gte=now - timedelta(days=7))
            time_label = "in the last 7 days"
            time_filter = "recent"
        
        # Get basic metrics
        total_feeds = base_qs.count()
        
        # -------------------------------
        # SPECIFIC QUERY HANDLERS
        # -------------------------------
        
        # 1. TRENDING ACTORS/GROUPS QUERIES - HIGHEST PRIORITY
        if any(pattern in user_message for pattern in [
            "which actor is trending", "trending actor", "top actor", "most active actor",
            "which threat actor", "what actors", "what groups", "actor trending",
            "threat actor trending", "popular actor", "active threat group", "actor is trending",
            "which actor", "actors trending", "groups trending"
        ]):
            # NEW: Try DB first for speed
            trending_actors_db = get_trending_data_from_db('actor', time_filter or 'all', 7)
            
            if trending_actors_db:
                actor_list = []
                for i, item in enumerate(trending_actors_db, 1):
                    actor_list.append(f"{i}. **{item['name']}** - {item['count']} mentions ({item['percent']}) | Risk: {item['risk_level']}")
                
                greeting_prefix = random.choice(greeting_responses) if needs_greeting_prefix else ""
                ai_reply = f"{greeting_prefix}**Top trending threat actors {time_label}:**\n\n" + "\n".join(actor_list)
                ai_reply += f"\n\n*Based on {len(trending_actors_db)} tracked entities {time_label}.*"
            else:
                # FALLBACK: On-the-fly computation
                entity_feed_counts = {'actors': Counter()}
                
                for feed in base_qs:
                    full_text = f"{feed.title} {feed.content or ''} {feed.summary or ''}".lower()
                    entities = extract_entities(full_text)
                    
                    # Count unique actors per article
                    unique_actors = set(e.lower() for e in entities['actors'])
                    for actor_lower in unique_actors:
                        entity_feed_counts['actors'][actor_lower] += 1
                
                top_actors = entity_feed_counts['actors'].most_common(7)
                
                if top_actors:
                    actor_list = []
                    for i, (actor_name, count) in enumerate(top_actors, 1):
                        # Format actor name
                        if re.match(r'^(apt|ta|fin)[-\s]?\d+', actor_name.lower()):
                            display_name = actor_name.upper().replace(' ', '-')
                        else:
                            display_name = actor_name.title()
                        
                        # Calculate percentage
                        total_feeds_for_percent = base_qs.count()
                        percentage = (count / total_feeds_for_percent * 100) if total_feeds_for_percent > 0 else 0
                        
                        actor_list.append(f"{i}. **{display_name}** - {count} mentions")
                    
                    greeting_prefix = random.choice(greeting_responses) if needs_greeting_prefix else ""
                    
                    if time_label == "overall":
                        ai_reply = f"{greeting_prefix}**Top trending threat actors:**\n\n" + "\n".join(actor_list)
                    else:
                        ai_reply = f"{greeting_prefix}**Top trending threat actors {time_label}:**\n\n" + "\n".join(actor_list)
                    
                    # Add context about total feeds
                    ai_reply += f"\n\n*Based on analysis of {total_feeds} threat feeds {time_label}.*"
                else:
                    greeting_prefix = random.choice(greeting_responses) if needs_greeting_prefix else ""
                    ai_reply = f"{greeting_prefix}No trending actors found {time_label} in the current dataset."
        
        # 2. TRENDING NEWS/THREATS QUERIES
        elif any(pattern in user_message for pattern in [
            "trending news", "trending threats", "what's trending", "latest threats",
            "new threats", "recent threats", "top threats", "critical threats",
            "emerging threats", "which threat is trending", "news trending",
            "what is trending", "show trending", "trending today"
        ]):
            # FIXED: Use 'trending_score' instead of 'threat_score'
            trending_feeds = base_qs.order_by("-trending_score", "-published")[:8]
            
            if trending_feeds:
                threat_list = []
                for i, feed in enumerate(trending_feeds, 1):
                    category = dict(ThreatFeed.CATEGORIES).get(feed.category, feed.category).title()
                    time_ago = (now - feed.published)
                    
                    if time_ago.days > 0:
                        time_text = f"{time_ago.days} days ago"
                    elif time_ago.seconds // 3600 > 0:
                        time_text = f"{time_ago.seconds // 3600} hours ago"
                    else:
                        time_text = "recently"
                    
                    # FIXED: Use 'trending_score' for risk checks
                    if feed.trending_score >= 85:
                        risk_emoji = "🔴"
                        risk_text = "Critical"
                    elif feed.trending_score >= 70:
                        risk_emoji = "🟠"
                        risk_text = "High"
                    elif feed.trending_score >= 50:
                        risk_emoji = "🟡"
                        risk_text = "Medium"
                    else:
                        risk_emoji = "🟢"
                        risk_text = "Low"
                    
                    threat_list.append(f"{i}.  **[{category}]** {feed.title}")
                
                greeting_prefix = random.choice(greeting_responses) if needs_greeting_prefix else ""
                
                if time_label == "overall":
                    ai_reply = f"{greeting_prefix}**Most critical trending threats:**\n\n" + "\n\n".join(threat_list)
                else:
                    ai_reply = f"{greeting_prefix}**Trending threats {time_label}:**\n\n" + "\n\n".join(threat_list)
                
                # Add summary
                ai_reply += f"\n\n*Showing top {len(trending_feeds)} threats*"
            else:
                greeting_prefix = random.choice(greeting_responses) if needs_greeting_prefix else ""
                ai_reply = f"{greeting_prefix}No trending threats found {time_label} in the current dataset."
        
        # 3. TODAY'S SPECIFIC QUERIES
        elif any(pattern in user_message for pattern in [
            "today's actor", "actor today", "threats today", "today's threats",
            "what happened today", "today news", "today's news", "today",
            "what's happening today", "today's cybersecurity", "today threat"
        ]):
            today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            today_feeds = ThreatFeed.objects.filter(published__gte=today_start)
            
            if today_feeds.exists():
                # Get trending actors for today
                entity_feed_counts = {'actors': Counter()}
                
                for feed in today_feeds:
                    full_text = f"{feed.title} {feed.content or ''} {feed.summary or ''}".lower()
                    entities = extract_entities(full_text)
                    
                    unique_actors = set(e.lower() for e in entities['actors'])
                    for actor_lower in unique_actors:
                        entity_feed_counts['actors'][actor_lower] += 1
                
                top_actors_today = entity_feed_counts['actors'].most_common(5)
                
                greeting_prefix = random.choice(greeting_responses) if needs_greeting_prefix else ""
                
                if top_actors_today:
                    actor_list = []
                    for i, (actor_name, count) in enumerate(top_actors_today, 1):
                        if re.match(r'^(apt|ta|fin)[-\s]?\d+', actor_name.lower()):
                            display_name = actor_name.upper().replace(' ', '-')
                        else:
                            display_name = actor_name.title()
                        actor_list.append(f"{i}. **{display_name}** ({count} mentions)")
                    
                    ai_reply = f"{greeting_prefix}**Today's trending threat actors:**\n\n" + "\n".join(actor_list)
                    ai_reply += f"\n\n**📊 Today's threat summary:**"
                    ai_reply += f"\n• **Total threats:** {today_feeds.count()}"
                    
                    # Add top categories for today
                    today_categories = today_feeds.values('category').annotate(count=Count('id')).order_by('-count')[:3]
                    if today_categories:
                        category_list = []
                        for cat in today_categories:
                            cat_name = dict(ThreatFeed.CATEGORIES).get(cat['category'], cat['category']).title()
                            category_list.append(f"{cat_name}: {cat['count']}")
                        ai_reply += f"\n• **Top categories:** " + ", ".join(category_list)
                    
                    # FIXED: Use 'trending_score' for critical count
                    critical_count = today_feeds.filter(trending_score__gte=85).count()
                    if critical_count > 0:
                        ai_reply += f"\n• **Critical threats:** {critical_count}"
                else:
                    ai_reply = f"{greeting_prefix}No specific actors identified in today's {today_feeds.count()} threat feeds."
            else:
                greeting_prefix = random.choice(greeting_responses) if needs_greeting_prefix else ""
                ai_reply = f"{greeting_prefix}No threat feeds published today yet. Check back later for updates."
        
        # 4. GENERAL DATABASE METRICS
        elif any(pattern in user_message for pattern in [
            "how many feeds", "total number", "count of feeds", "number of feeds",
            "how many threats", "total threats", "database size", "how many",
            "count", "total", "statistics", "stats"
        ]):
            total_feeds_count = base_qs.count()
            today_feeds_count = ThreatFeed.objects.filter(published__date=now.date()).count()
            
            greeting_prefix = random.choice(greeting_responses) if needs_greeting_prefix else ""
            
            if "today" in user_message:
                ai_reply = f"{greeting_prefix}There are **{today_feeds_count}** threat feeds published today."
            else:
                ai_reply = f"{greeting_prefix}There are **{total_feeds_count}** threat intelligence feeds {time_label}."
                if today_feeds_count > 0 and time_label != "today":
                    ai_reply += f" (Including **{today_feeds_count}** today)"
        
        # 5. CATEGORY-SPECIFIC QUERIES
        else:
            # Detect category
            category_map = {
                'ransomware': ['ransomware', 'ransom'],
                'malware': ['malware', 'trojan', 'virus', 'worm', 'botnet'],
                'phishing': ['phishing', 'spear phishing', 'credential theft'],
                'vulnerability': ['vulnerability', 'cve', 'cvss', 'patch', 'exploit'],
                'ddos': ['ddos', 'denial of service', 'dos'],
                'breach': ['breach', 'data leak', 'data exposure'],
                'zero_day': ['zero-day', 'zero day', '0day'],
                'apt': ['apt', 'advanced persistent threat', 'nation-state'],
                'general_threat': ['threat', 'attack', 'security']
            }
            
            detected_category = None
            for category, keywords in category_map.items():
                if any(keyword in user_message for keyword in keywords):
                    detected_category = category
                    break
            
            if detected_category:
                category_count = base_qs.filter(category=detected_category).count()
                category_name = dict(ThreatFeed.CATEGORIES).get(detected_category, detected_category).title()
                
                greeting_prefix = random.choice(greeting_responses) if needs_greeting_prefix else ""
                
                if "how many" in user_message or "count" in user_message or "number" in user_message:
                    if time_filter == "today":
                        count_today = base_qs.filter(category=detected_category, published__date=now.date()).count()
                        ai_reply = f"{greeting_prefix}There are **{count_today}** {category_name} feeds published today."
                    else:
                        ai_reply = f"{greeting_prefix}There are **{category_count}** {category_name}-related threat feeds {time_label}."
                
                # If asking about trending in a specific category
                elif "trending" in user_message and detected_category:
                    # FIXED: Use 'trending_score' for ordering
                    category_feeds = base_qs.filter(category=detected_category).order_by("-trending_score")[:5]
                    
                    if category_feeds:
                        feed_list = []
                        for i, feed in enumerate(category_feeds, 1):
                            time_ago = (now - feed.published)
                            if time_ago.days > 0:
                                time_text = f"{time_ago.days} days ago"
                            else:
                                time_text = f"{time_ago.seconds // 3600} hours ago"
                            
                            # FIXED: Use 'trending_score'
                            feed_list.append(f"{i}. {feed.title[:70]}... (Score: {feed.trending_score}, {time_text})")
                        
                        ai_reply = f"{greeting_prefix}**Top trending {category_name} threats {time_label}:**\n\n" + "\n".join(feed_list)
                    else:
                        ai_reply = f"{greeting_prefix}No trending {category_name} threats found {time_label}."
                
                else:
                    # General info about the category
                    ai_reply = f"{greeting_prefix}{category_name} threats {time_label}: **{category_count}** feeds"
            
            # 6. RECENT/NEW THREATS (general)
            elif any(pattern in user_message for pattern in [
                "latest threats", "recent threats", "new threats",
                "what's new", "latest reports", "recent alerts"
            ]):
                recent_threats = base_qs.order_by("-published")[:5]
                
                greeting_prefix = random.choice(greeting_responses) if needs_greeting_prefix else ""
                
                if recent_threats:
                    threat_lines = []
                    for threat in recent_threats:
                        time_ago = (now - threat.published)
                        if time_ago.days > 0:
                            time_text = f"{time_ago.days} days ago"
                        elif time_ago.seconds // 3600 > 0:
                            time_text = f"{time_ago.seconds // 3600} hours ago"
                        else:
                            time_text = "recently"
                        
                        category_name = dict(ThreatFeed.CATEGORIES).get(threat.category, threat.category).title()
                        # FIXED: Use 'trending_score'
                        threat_lines.append(f"• **[{category_name}]** {threat.title[:70]}... (⏱️ {time_text} | ⚠️ {threat.trending_score}/100)")
                    
                    ai_reply = f"{greeting_prefix}**Most recent threats {time_label}:**\n\n" + "\n".join(threat_lines)
                else:
                    ai_reply = f"{greeting_prefix}No recent threats found {time_label}."
            
            # 7. CATEGORY BREAKDOWN
            elif any(pattern in user_message for pattern in [
                "category breakdown", "breakdown by category", "list categories",
                "per category", "by category", "distribution", "categories"
            ]):
                category_counts = (
                    base_qs
                    .values("category")
                    .annotate(count=Count("id"))
                    .order_by("-count")
                )
                
                greeting_prefix = random.choice(greeting_responses) if needs_greeting_prefix else ""
                
                if category_counts:
                    total = sum(item['count'] for item in category_counts)
                    breakdown_lines = []
                    
                    for item in category_counts:
                        category_name = dict(ThreatFeed.CATEGORIES).get(item['category'], item['category']).title()
                        percentage = (item['count'] / total * 100) if total > 0 else 0
                        breakdown_lines.append(f"• **{category_name}**: {item['count']} feeds ({percentage:.1f}%)")
                    
                    ai_reply = f"{greeting_prefix}**Threat feed breakdown by category {time_label}:**\n\n" + "\n".join(breakdown_lines)
                    
                    top_category = category_counts.first()
                    if top_category:
                        top_name = dict(ThreatFeed.CATEGORIES).get(top_category['category'], top_category['category']).title()
                        ai_reply += f"\n\n**Most common category:** {top_name} ({top_category['count']} feeds)"
                else:
                    ai_reply = f"{greeting_prefix}No threat data available {time_label}."
            
            # 8. SOURCE/ORIGIN QUERIES
            elif any(pattern in user_message for pattern in [
                "from twitter", "reddit feeds", "which sources",
                "top sources", "where from", "source breakdown", "sources"
            ]):
                source_counts = (
                    base_qs
                    .values("source")
                    .annotate(count=Count("id"))
                    .order_by("-count")[:5]
                )
                
                greeting_prefix = random.choice(greeting_responses) if needs_greeting_prefix else ""
                
                if source_counts:
                    source_lines = []
                    for source in source_counts:
                        source_name = source['source'].split(' - ')[0] if ' - ' in source['source'] else source['source']
                        source_lines.append(f"• **{source_name}**: {source['count']} feeds")
                    
                    ai_reply = f"{greeting_prefix}**Top threat intelligence sources {time_label}:**\n\n" + "\n".join(source_lines)
                else:
                    ai_reply = f"{greeting_prefix}No source data available {time_label}."
            
            # 9. HELP/GENERAL QUERIES
            elif any(pattern in user_message for pattern in [
                "help", "what can you do", "capabilities", "how to use",
                "what questions", "support", "guide", "assist"
            ]):
                greeting_prefix = random.choice(greeting_responses) if needs_greeting_prefix else ""
                
                ai_reply = f"""{greeting_prefix}**I can help you with:**
• **Trending analysis**: "Which actor is trending today?" "Show trending threats"
• **Threat intelligence**: "Recent ransomware threats" "Latest vulnerabilities"
• **Database queries**: "How many feeds today?" "Category breakdown"
• **Time-based analysis**: "Threats this week" "Yesterday's threats"
• **Specific queries**: "APT attacks" "Phishing campaigns"
Try asking me about specific threat actors, attack types, or recent cybersecurity events!"""
            
            # 10. FALLBACK - Use LLM or general response
            else:
                # Try to extract entities for context
                try:
                    # Get recent threats for context
                    recent_threats = base_qs.order_by("-published")[:5]
                    
                    context_snippets = "Recent threats:\n"
                    for i, threat in enumerate(recent_threats, 1):
                        cat_name = dict(ThreatFeed.CATEGORIES).get(threat.category, threat.category)
                        # FIX: Corrected date format
                        context_snippets += f"{i}. {threat.title} (Category: {cat_name}, Published: {threat.published.strftime('%Y-%m-%d %H:%M')})\n"
                    
                    # Get category breakdown
                    category_counts = base_qs.values("category").annotate(count=Count("id")).order_by("-count")[:3]
                    if category_counts:
                        context_snippets += f"\nTop categories: {', '.join([dict(ThreatFeed.CATEGORIES).get(cat['category'], cat['category']) for cat in category_counts])}\n"
                    
                    system_prompt = f"""You are ThreatCluster AI, a cyber threat intelligence assistant.
NEVER greet, introduce, or ask questions—answer DIRECTLY using ONLY the context.

RULES:
- Concise: 1-3 sentences or bullets.
- For actors/trending: List top 3-5 with counts from context.
- No data? Say: "No matching threat data available."

DATABASE CONTEXT ({time_label}):
{context_snippets}

USER QUESTION: {original_message_for_llm}

Direct answer:"""
                    
                    try:
                        import ollama
                        response = ollama.chat(
                            model="llama3.2:1b",  # Upgrade to :3b if available
                            messages=[
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": original_message_for_llm},
                            ],
                            options={"temperature": 0.3, "num_predict": 150},
                        )
                        ai_reply = response["message"]["content"].strip()
                        
                        # Add greeting if needed (using flag)
                        if needs_greeting_prefix:
                            ai_reply = f"{random.choice(greeting_responses)}{ai_reply}"
                        
                    except Exception as e:
                        print(f"LLM Error: {e}")
                        greeting_prefix = random.choice(greeting_responses) if needs_greeting_prefix else ""
                        ai_reply = f"{greeting_prefix}I can help you analyze threat intelligence feeds. Try asking about trending threats, specific attack types (ransomware, phishing, APT), or recent cybersecurity events."
                
                except Exception as e:
                    print(f"Context building error: {e}")
                    greeting_prefix = random.choice(greeting_responses) if needs_greeting_prefix else ""
                    ai_reply = f"{greeting_prefix}I can help you analyze threat intelligence. Try questions like: 'Which threat actors are trending?' or 'Show me recent ransomware threats'."
        
        # -------------------------------
        # ADD TO CONVERSATION HISTORY
        # -------------------------------
        conversation.append({
            'sender': 'user',
            'message': request.POST.get("message", ""),  # Original message
            'timestamp': now.isoformat()
        })
        
        conversation.append({
            'sender': 'ai',
            'message': ai_reply,
            'timestamp': now.isoformat()
        })
        
        # Keep only last 20 messages to prevent session from getting too large
        if len(conversation) > 20:
            conversation = conversation[-20:]
        
        # Save back to session
        request.session['conversation_history'] = conversation
        request.session.modified = True
        
        return render(request, "chatbot.html", {
            'conversation': conversation,
            'time_period': time_label
        })
    
    # For GET request, show existing conversation
    return render(request, "chatbot.html", {'conversation': conversation})
@csrf_exempt
@require_http_methods(["POST"])
def check_single_ip(request):
    ip = None
    try:
        ip = request.POST.get('ip', '').strip()
        if not ip or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            logger.warning(f"Invalid IP in check_single_ip: {ip}")
            return JsonResponse({"error": "Invalid IP format"}, status=400)
      
        logger.info(f"Live check requested for IP: {ip}")
      
        # Fetch live data (may raise RequestException on network/API fail)
        data = check_ip_reputation(ip)
        logger.info(f"API response for {ip}: score={data.get('score', 'N/A')}, reports={data.get('reports', 'N/A')}")
      
        # Check if API call succeeded (data is dict with keys, even if score=0 for clean IPs)
        if not isinstance(data, dict) or 'score' not in data:
            logger.error(f"API returned invalid structure for {ip}: {data}")
            return JsonResponse({"error": "AbuseIPDB API returned invalid data"}, status=500)
      
        # Score=0 is VALID (clean IP)—do NOT treat as failure
        # Only fail on API errors (e.g., bad key, rate limit)
      
        # Update/Create in DB (always update for freshness, or only on change)
        existing = ThreatRecord.objects.filter(type='ip', value=ip).first()
        updated = False
        last_reported = data.get('last_reported', 'N/A')
      
        # Force update if existing (to refresh reports/timestamp), or create new
        save_or_update_record(
            type_='ip', value=ip, score=data['score'], reputation=data['reputation'].lower(),
            source='AbuseIPDB Live Check', category='abuse', tags=[data['country']],
            description=f"Live check: {data['reports']} reports | Last: {last_reported}"
        )
        updated = True if not existing else (existing.threat_score != data['score'])
      
        if updated and existing:
            logger.info(f"Updated score for {ip}: {existing.threat_score} → {data['score']}")
        elif not existing:
            logger.info(f"Created new record for {ip}: score={data['score']}")
        else:
            logger.info(f"No score change for {ip} (clean/low-risk): {data['score']}")
      
        return JsonResponse({
            "updated": updated,
            "score": data['score'],
            "reputation": data['reputation'],
            "reports": data['reports'],
            "country": data['country'],
            "last_reported": last_reported
        })
  
    except ImportError as e:
        logger.error(f"Import error in check_single_ip: {e} (Check ingest_feed.py path)")
        return JsonResponse({"error": "Server configuration issue (imports)"}, status=500)
    except requests.exceptions.RequestException as e:
        logger.error(f"Network/API request error in check_single_ip for {ip}: {e}")
        return JsonResponse({"error": "Network error—check connection or API availability"}, status=502)
    except Exception as e:
        logger.error(f"Unexpected error in check_single_ip for {ip}: {e}", exc_info=True)
        return JsonResponse({"error": "Internal server error—check server logs"}, status=500)
    
from django.shortcuts import render
from App.models import ThreatProfile

def apt_stats(request):
    actors = ThreatProfile.objects.filter(
        threat_focus="actors"
    ).order_by("name")

    stats = {
        "total_groups": actors.count(),
        "countries": sorted(set(a.region for a in actors if a.region)),
        "total_cves": sum(len(a.related_cves or []) for a in actors),
        "total_tools": sum(len(a.related_malware or []) for a in actors),
    }

    return render(
        request,
        "apt_stats.html",
        {
            "actors": actors,
            "stats": stats
        }
    )

# views.py
import json
from django.shortcuts import render
from django.http import JsonResponse
from datetime import datetime
import requests
from django.core.cache import cache
import threading

def fetch_threat_data():
    """Fetch data in background"""
    url = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            cache.set('threat_data', response.json(), 3600)
            cache.set('last_update_time', datetime.now(), 3600)
    except:
        pass


import json
from django.shortcuts import render
from django.http import JsonResponse
from datetime import datetime
import requests
from django.core.cache import cache
import threading

# views.py
import json
from django.shortcuts import render
from datetime import datetime
import requests
from django.core.cache import cache
import threading

def fetch_threat_data():
    """Fetch data in background"""
    url = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            cache.set('threat_data', response.json(), 3600)
            cache.set('last_update_time', datetime.now(), 3600)
    except:
        pass

def threat_dashboard(request):
    """Main dashboard view"""
    
    # Full ISO 3166-1 alpha-2 country code to name mapping
    country_names = {
        'AD': 'Andorra', 'AE': 'United Arab Emirates', 'AF': 'Afghanistan', 'AG': 'Antigua and Barbuda',
        'AI': 'Anguilla', 'AL': 'Albania', 'AM': 'Armenia', 'AO': 'Angola', 'AQ': 'Antarctica',
        'AR': 'Argentina', 'AS': 'American Samoa', 'AT': 'Austria', 'AU': 'Australia', 'AW': 'Aruba',
        'AX': 'Åland Islands', 'AZ': 'Azerbaijan', 'BA': 'Bosnia and Herzegovina', 'BB': 'Barbados',
        'BD': 'Bangladesh', 'BE': 'Belgium', 'BF': 'Burkina Faso', 'BG': 'Bulgaria', 'BH': 'Bahrain',
        'BI': 'Burundi', 'BJ': 'Benin', 'BL': 'Saint Barthélemy', 'BM': 'Bermuda', 'BN': 'Brunei Darussalam',
        'BO': 'Bolivia', 'BQ': 'Bonaire, Sint Eustatius and Saba', 'BR': 'Brazil', 'BS': 'Bahamas',
        'BT': 'Bhutan', 'BV': 'Bouvet Island', 'BW': 'Botswana', 'BY': 'Belarus', 'BZ': 'Belize',
        'CA': 'Canada', 'CC': 'Cocos (Keeling) Islands', 'CD': 'Congo (Democratic Republic)', 'CF': 'Central African Republic',
        'CG': 'Congo', 'CH': 'Switzerland', 'CI': "Côte d'Ivoire", 'CK': 'Cook Islands', 'CL': 'Chile',
        'CM': 'Cameroon', 'CN': 'China', 'CO': 'Colombia', 'CR': 'Costa Rica', 'CU': 'Cuba',
        'CV': 'Cabo Verde', 'CW': 'Curaçao', 'CX': 'Christmas Island', 'CY': 'Cyprus', 'CZ': 'Czechia',
        'DE': 'Germany', 'DJ': 'Djibouti', 'DK': 'Denmark', 'DM': 'Dominica', 'DO': 'Dominican Republic',
        'DZ': 'Algeria', 'EC': 'Ecuador', 'EE': 'Estonia', 'EG': 'Egypt', 'EH': 'Western Sahara',
        'ER': 'Eritrea', 'ES': 'Spain', 'ET': 'Ethiopia', 'FI': 'Finland', 'FJ': 'Fiji',
        'FK': 'Falkland Islands', 'FM': 'Micronesia', 'FO': 'Faroe Islands', 'FR': 'France',
        'GA': 'Gabon', 'GB': 'United Kingdom', 'GD': 'Grenada', 'GE': 'Georgia', 'GF': 'French Guiana',
        'GG': 'Guernsey', 'GH': 'Ghana', 'GI': 'Gibraltar', 'GL': 'Greenland', 'GM': 'Gambia',
        'GN': 'Guinea', 'GP': 'Guadeloupe', 'GQ': 'Equatorial Guinea', 'GR': 'Greece',
        'GS': 'South Georgia', 'GT': 'Guatemala', 'GU': 'Guam', 'GW': 'Guinea-Bissau', 'GY': 'Guyana',
        'HK': 'Hong Kong', 'HM': 'Heard Island', 'HN': 'Honduras', 'HR': 'Croatia', 'HT': 'Haiti',
        'HU': 'Hungary', 'ID': 'Indonesia', 'IE': 'Ireland', 'IL': 'Israel', 'IM': 'Isle of Man',
        'IN': 'India', 'IO': 'British Indian Ocean Territory', 'IQ': 'Iraq', 'IR': 'Iran',
        'IS': 'Iceland', 'IT': 'Italy', 'JE': 'Jersey', 'JM': 'Jamaica', 'JO': 'Jordan',
        'JP': 'Japan', 'KE': 'Kenya', 'KG': 'Kyrgyzstan', 'KH': 'Cambodia', 'KI': 'Kiribati',
        'KM': 'Comoros', 'KN': 'Saint Kitts and Nevis', 'KP': 'North Korea', 'KR': 'South Korea',
        'KW': 'Kuwait', 'KY': 'Cayman Islands', 'KZ': 'Kazakhstan', 'LA': 'Laos', 'LB': 'Lebanon',
        'LC': 'Saint Lucia', 'LI': 'Liechtenstein', 'LK': 'Sri Lanka', 'LR': 'Liberia', 'LS': 'Lesotho',
        'LT': 'Lithuania', 'LU': 'Luxembourg', 'LV': 'Latvia', 'LY': 'Libya', 'MA': 'Morocco',
        'MC': 'Monaco', 'MD': 'Moldova', 'ME': 'Montenegro', 'MF': 'Saint Martin', 'MG': 'Madagascar',
        'MH': 'Marshall Islands', 'MK': 'North Macedonia', 'ML': 'Mali', 'MM': 'Myanmar', 'MN': 'Mongolia',
        'MO': 'Macao', 'MP': 'Northern Mariana Islands', 'MQ': 'Martinique', 'MR': 'Mauritania',
        'MS': 'Montserrat', 'MT': 'Malta', 'MU': 'Mauritius', 'MV': 'Maldives', 'MW': 'Malawi',
        'MX': 'Mexico', 'MY': 'Malaysia', 'MZ': 'Mozambique', 'NA': 'Namibia', 'NC': 'New Caledonia',
        'NE': 'Niger', 'NF': 'Norfolk Island', 'NG': 'Nigeria', 'NI': 'Nicaragua', 'NL': 'Netherlands',
        'NO': 'Norway', 'NP': 'Nepal', 'NR': 'Nauru', 'NU': 'Niue', 'NZ': 'New Zealand',
        'OM': 'Oman', 'PA': 'Panama', 'PE': 'Peru', 'PF': 'French Polynesia', 'PG': 'Papua New Guinea',
        'PH': 'Philippines', 'PK': 'Pakistan', 'PL': 'Poland', 'PM': 'Saint Pierre and Miquelon',
        'PN': 'Pitcairn', 'PR': 'Puerto Rico', 'PS': 'Palestine', 'PT': 'Portugal', 'PW': 'Palau',
        'PY': 'Paraguay', 'QA': 'Qatar', 'RE': 'Réunion', 'RO': 'Romania', 'RS': 'Serbia',
        'RU': 'Russia', 'RW': 'Rwanda', 'SA': 'Saudi Arabia', 'SB': 'Solomon Islands', 'SC': 'Seychelles',
        'SD': 'Sudan', 'SE': 'Sweden', 'SG': 'Singapore', 'SH': 'Saint Helena', 'SI': 'Slovenia',
        'SJ': 'Svalbard and Jan Mayen', 'SK': 'Slovakia', 'SL': 'Sierra Leone', 'SM': 'San Marino',
        'SN': 'Senegal', 'SO': 'Somalia', 'SR': 'Suriname', 'SS': 'South Sudan', 'ST': 'Sao Tome and Principe',
        'SV': 'El Salvador', 'SX': 'Sint Maarten', 'SY': 'Syria', 'SZ': 'Eswatini', 'TC': 'Turks and Caicos Islands',
        'TD': 'Chad', 'TF': 'French Southern Territories', 'TG': 'Togo', 'TH': 'Thailand', 'TJ': 'Tajikistan',
        'TK': 'Tokelau', 'TL': 'Timor-Leste', 'TM': 'Turkmenistan', 'TN': 'Tunisia', 'TO': 'Tonga',
        'TR': 'Türkiye', 'TT': 'Trinidad and Tobago', 'TV': 'Tuvalu', 'TW': 'Taiwan', 'TZ': 'Tanzania',
        'UA': 'Ukraine', 'UG': 'Uganda', 'UM': 'U.S. Minor Outlying Islands', 'US': 'United States',
        'UY': 'Uruguay', 'UZ': 'Uzbekistan', 'VA': 'Holy See', 'VC': 'Saint Vincent and the Grenadines',
        'VE': 'Venezuela', 'VG': 'Virgin Islands (British)', 'VI': 'Virgin Islands (U.S.)', 'VN': 'Vietnam',
        'VU': 'Vanuatu', 'WF': 'Wallis and Futuna', 'WS': 'Samoa', 'YE': 'Yemen', 'YT': 'Mayotte',
        'ZA': 'South Africa', 'ZM': 'Zambia', 'ZW': 'Zimbabwe'
    }

    # Reverse mapping: full name → code (lowercase)
    country_code_reverse = {name.lower(): code.lower() for code, name in country_names.items()}

    # Start background update
    thread = threading.Thread(target=fetch_threat_data)
    thread.daemon = True
    thread.start()

    # Get cached data or fetch fresh
    data = cache.get('threat_data')
    last_update = cache.get('last_update_time')
    if not data or (last_update and (datetime.now() - last_update).total_seconds() > 300):
        url = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
        try:
            response = requests.get(url, timeout=10)
            data = response.json() if response.status_code == 200 else {'values': []}
        except:
            data = {'values': []}
        cache.set('threat_data', data, 3600)
        cache.set('last_update_time', datetime.now(), 3600)

    actors = data.get('values', [])

    # Prepare actors
    for actor in actors:
        meta = actor.setdefault('meta', {})
        actor['uuid'] = meta.get('uuid', 'N/A')
        actor['meta_json'] = json.dumps(meta)

        # Source countries (origin) - always codes
        source_country = meta.get('country')
        if isinstance(source_country, list):
            source_codes = [c.upper() for c in source_country if c]
        else:
            source_codes = [source_country.upper()] if source_country else []

        actor['source_countries_str'] = ','.join(source_codes).lower()
        actor['source_country_names'] = [country_names.get(code, code) for code in source_codes]

        # Victim countries - normalize to lowercase codes
        victims_raw = meta.get('cfr-suspected-victims', [])
        victim_codes = []

        if isinstance(victims_raw, list):
            for v in victims_raw:
                if not v:
                    continue
                v_lower = v.lower().strip()
                code = country_code_reverse.get(v_lower)
                if code:
                    victim_codes.append(code)
                else:
                    # Fallback: try direct code match
                    if len(v) == 2 and v.upper() in country_names:
                        victim_codes.append(v.upper().lower())
        elif isinstance(victims_raw, str) and victims_raw.strip():
            v_lower = victims_raw.lower().strip()
            code = country_code_reverse.get(v_lower)
            if code:
                victim_codes.append(code)

        actor['victim_countries_str'] = ','.join(victim_codes)  # lowercase codes only

        # Victim sectors - robust cleaning
        victim_sectors_raw = meta.get('cfr-target-category', [])
        victim_sectors_clean = []

        if isinstance(victim_sectors_raw, list):
            for s in victim_sectors_raw:
                if s and isinstance(s, str):
                    cleaned = s.strip()
                    if cleaned:
                        victim_sectors_clean.append(cleaned.title())
        elif isinstance(victim_sectors_raw, str) and victim_sectors_raw.strip():
            cleaned = victim_sectors_raw.strip()
            if cleaned:
                victim_sectors_clean.append(cleaned.title())

        actor['victim_sectors'] = victim_sectors_clean
        actor['victim_sectors_str'] = ','.join([s.lower() for s in victim_sectors_clean])

    # Source countries stats (for dropdown)
    source_countries = {}
    for actor in actors:
        codes = actor['source_countries_str'].split(',')
        for code in codes:
            if code:
                source_countries[code] = source_countries.get(code, 0) + 1

    source_countries_display = sorted([
        (country_names.get(code.upper(), code.upper()), code, count)
        for code, count in source_countries.items()
    ], key=lambda x: x[0])

    # Victim countries stats (for dropdown) - using codes
    victim_countries = {}
    for actor in actors:
        codes = actor['victim_countries_str'].split(',')
        for code in codes:
            if code:
                victim_countries[code] = victim_countries.get(code, 0) + 1

    victim_countries_display = sorted([
        (country_names.get(code.upper(), code.upper()), code, count)
        for code, count in victim_countries.items()
    ], key=lambda x: x[0])

    # Victim sectors stats
    victim_sectors = {}
    for actor in actors:
        for sector in actor.get('victim_sectors', []):
            if sector:
                key = sector.lower()
                victim_sectors[key] = victim_sectors.get(key, 0) + 1

    victim_sectors_for_template = sorted([
        (sector.title(), count) for sector, count in victim_sectors.items()
    ], key=lambda x: x[0])

    context = {
        'actors': actors,
        'total_actors': len(actors),
        'source_countries_display': source_countries_display,
        'victim_countries_display': victim_countries_display,  # (display_name, code, count)
        'victim_sectors': victim_sectors_for_template,         # (sector_name, count)
        'last_update': cache.get('last_update_time') or datetime.now(),
    }

    return render(request, 'threat_dashboard.html', context)
def threat_detail(request, actor_name):
    """Detail view for a specific threat actor"""
    
    # Full ISO 3166-1 alpha-2 country code to name mapping
    country_names = {
        'AD': 'Andorra', 'AE': 'United Arab Emirates', 'AF': 'Afghanistan', 'AG': 'Antigua and Barbuda',
        'AI': 'Anguilla', 'AL': 'Albania', 'AM': 'Armenia', 'AO': 'Angola', 'AQ': 'Antarctica',
        'AR': 'Argentina', 'AS': 'American Samoa', 'AT': 'Austria', 'AU': 'Australia', 'AW': 'Aruba',
        'AX': 'Åland Islands', 'AZ': 'Azerbaijan', 'BA': 'Bosnia and Herzegovina', 'BB': 'Barbados',
        'BD': 'Bangladesh', 'BE': 'Belgium', 'BF': 'Burkina Faso', 'BG': 'Bulgaria', 'BH': 'Bahrain',
        'BI': 'Burundi', 'BJ': 'Benin', 'BL': 'Saint Barthélemy', 'BM': 'Bermuda', 'BN': 'Brunei Darussalam',
        'BO': 'Bolivia', 'BQ': 'Bonaire, Sint Eustatius and Saba', 'BR': 'Brazil', 'BS': 'Bahamas',
        'BT': 'Bhutan', 'BV': 'Bouvet Island', 'BW': 'Botswana', 'BY': 'Belarus', 'BZ': 'Belize',
        'CA': 'Canada', 'CC': 'Cocos (Keeling) Islands', 'CD': 'Congo (Democratic Republic)', 'CF': 'Central African Republic',
        'CG': 'Congo', 'CH': 'Switzerland', 'CI': "Côte d'Ivoire", 'CK': 'Cook Islands', 'CL': 'Chile',
        'CM': 'Cameroon', 'CN': 'China', 'CO': 'Colombia', 'CR': 'Costa Rica', 'CU': 'Cuba',
        'CV': 'Cabo Verde', 'CW': 'Curaçao', 'CX': 'Christmas Island', 'CY': 'Cyprus', 'CZ': 'Czechia',
        'DE': 'Germany', 'DJ': 'Djibouti', 'DK': 'Denmark', 'DM': 'Dominica', 'DO': 'Dominican Republic',
        'DZ': 'Algeria', 'EC': 'Ecuador', 'EE': 'Estonia', 'EG': 'Egypt', 'EH': 'Western Sahara',
        'ER': 'Eritrea', 'ES': 'Spain', 'ET': 'Ethiopia', 'FI': 'Finland', 'FJ': 'Fiji',
        'FK': 'Falkland Islands', 'FM': 'Micronesia', 'FO': 'Faroe Islands', 'FR': 'France',
        'GA': 'Gabon', 'GB': 'United Kingdom', 'GD': 'Grenada', 'GE': 'Georgia', 'GF': 'French Guiana',
        'GG': 'Guernsey', 'GH': 'Ghana', 'GI': 'Gibraltar', 'GL': 'Greenland', 'GM': 'Gambia',
        'GN': 'Guinea', 'GP': 'Guadeloupe', 'GQ': 'Equatorial Guinea', 'GR': 'Greece',
        'GS': 'South Georgia', 'GT': 'Guatemala', 'GU': 'Guam', 'GW': 'Guinea-Bissau', 'GY': 'Guyana',
        'HK': 'Hong Kong', 'HM': 'Heard Island', 'HN': 'Honduras', 'HR': 'Croatia', 'HT': 'Haiti',
        'HU': 'Hungary', 'ID': 'Indonesia', 'IE': 'Ireland', 'IL': 'Israel', 'IM': 'Isle of Man',
        'IN': 'India', 'IO': 'British Indian Ocean Territory', 'IQ': 'Iraq', 'IR': 'Iran',
        'IS': 'Iceland', 'IT': 'Italy', 'JE': 'Jersey', 'JM': 'Jamaica', 'JO': 'Jordan',
        'JP': 'Japan', 'KE': 'Kenya', 'KG': 'Kyrgyzstan', 'KH': 'Cambodia', 'KI': 'Kiribati',
        'KM': 'Comoros', 'KN': 'Saint Kitts and Nevis', 'KP': 'North Korea', 'KR': 'South Korea',
        'KW': 'Kuwait', 'KY': 'Cayman Islands', 'KZ': 'Kazakhstan', 'LA': 'Laos', 'LB': 'Lebanon',
        'LC': 'Saint Lucia', 'LI': 'Liechtenstein', 'LK': 'Sri Lanka', 'LR': 'Liberia', 'LS': 'Lesotho',
        'LT': 'Lithuania', 'LU': 'Luxembourg', 'LV': 'Latvia', 'LY': 'Libya', 'MA': 'Morocco',
        'MC': 'Monaco', 'MD': 'Moldova', 'ME': 'Montenegro', 'MF': 'Saint Martin', 'MG': 'Madagascar',
        'MH': 'Marshall Islands', 'MK': 'North Macedonia', 'ML': 'Mali', 'MM': 'Myanmar', 'MN': 'Mongolia',
        'MO': 'Macao', 'MP': 'Northern Mariana Islands', 'MQ': 'Martinique', 'MR': 'Mauritania',
        'MS': 'Montserrat', 'MT': 'Malta', 'MU': 'Mauritius', 'MV': 'Maldives', 'MW': 'Malawi',
        'MX': 'Mexico', 'MY': 'Malaysia', 'MZ': 'Mozambique', 'NA': 'Namibia', 'NC': 'New Caledonia',
        'NE': 'Niger', 'NF': 'Norfolk Island', 'NG': 'Nigeria', 'NI': 'Nicaragua', 'NL': 'Netherlands',
        'NO': 'Norway', 'NP': 'Nepal', 'NR': 'Nauru', 'NU': 'Niue', 'NZ': 'New Zealand',
        'OM': 'Oman', 'PA': 'Panama', 'PE': 'Peru', 'PF': 'French Polynesia', 'PG': 'Papua New Guinea',
        'PH': 'Philippines', 'PK': 'Pakistan', 'PL': 'Poland', 'PM': 'Saint Pierre and Miquelon',
        'PN': 'Pitcairn', 'PR': 'Puerto Rico', 'PS': 'Palestine', 'PT': 'Portugal', 'PW': 'Palau',
        'PY': 'Paraguay', 'QA': 'Qatar', 'RE': 'Réunion', 'RO': 'Romania', 'RS': 'Serbia',
        'RU': 'Russia', 'RW': 'Rwanda', 'SA': 'Saudi Arabia', 'SB': 'Solomon Islands', 'SC': 'Seychelles',
        'SD': 'Sudan', 'SE': 'Sweden', 'SG': 'Singapore', 'SH': 'Saint Helena', 'SI': 'Slovenia',
        'SJ': 'Svalbard and Jan Mayen', 'SK': 'Slovakia', 'SL': 'Sierra Leone', 'SM': 'San Marino',
        'SN': 'Senegal', 'SO': 'Somalia', 'SR': 'Suriname', 'SS': 'South Sudan', 'ST': 'Sao Tome and Principe',
        'SV': 'El Salvador', 'SX': 'Sint Maarten', 'SY': 'Syria', 'SZ': 'Eswatini', 'TC': 'Turks and Caicos Islands',
        'TD': 'Chad', 'TF': 'French Southern Territories', 'TG': 'Togo', 'TH': 'Thailand', 'TJ': 'Tajikistan',
        'TK': 'Tokelau', 'TL': 'Timor-Leste', 'TM': 'Turkmenistan', 'TN': 'Tunisia', 'TO': 'Tonga',
        'TR': 'Türkiye', 'TT': 'Trinidad and Tobago', 'TV': 'Tuvalu', 'TW': 'Taiwan', 'TZ': 'Tanzania',
        'UA': 'Ukraine', 'UG': 'Uganda', 'UM': 'U.S. Minor Outlying Islands', 'US': 'United States',
        'UY': 'Uruguay', 'UZ': 'Uzbekistan', 'VA': 'Holy See', 'VC': 'Saint Vincent and the Grenadines',
        'VE': 'Venezuela', 'VG': 'Virgin Islands (British)', 'VI': 'Virgin Islands (U.S.)', 'VN': 'Vietnam',
        'VU': 'Vanuatu', 'WF': 'Wallis and Futuna', 'WS': 'Samoa', 'YE': 'Yemen', 'YT': 'Mayotte',
        'ZA': 'South Africa', 'ZM': 'Zambia', 'ZW': 'Zimbabwe'
    }

    # Get cached data or fetch fresh
    data = cache.get('threat_data')
    if not data:
        url = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
        try:
            response = requests.get(url, timeout=10)
            data = response.json() if response.status_code == 200 else {'values': []}
        except:
            data = {'values': []}
        cache.set('threat_data', data, 3600)

    actors = data.get('values', [])
    actor = None
    for a in actors:
        if a.get('value') == actor_name:
            actor = a
            break

    if not actor:
        return render(request, 'threat_detail.html', {
            'error': f"Threat actor '{actor_name}' not found.",
        })

    # Prepare actor details (similar to dashboard)
    meta = actor.setdefault('meta', {})
    actor['uuid'] = actor.get('uuid', 'N/A')
    actor['meta_json'] = json.dumps(meta)

    # Source countries
    source_country = meta.get('country')
    if isinstance(source_country, list):
        source_codes = [c.upper() for c in source_country if c]
    else:
        source_codes = [source_country.upper()] if source_country else []
    actor['source_countries_str'] = ','.join(source_codes).lower()
    actor['source_country_names'] = [country_names.get(code, code) for code in source_codes]

    # Victim countries
    victims_raw = meta.get('cfr-suspected-victims', [])
    victim_codes = []
    reverse_map = {name.lower(): code.lower() for code, name in country_names.items()}
    if isinstance(victims_raw, list):
        for v in victims_raw:
            if not v:
                continue
            v_lower = v.lower().strip()
            code = reverse_map.get(v_lower)
            if code:
                victim_codes.append(code)
            else:
                if len(v) == 2 and v.upper() in country_names:
                    victim_codes.append(v.upper().lower())
    elif isinstance(victims_raw, str) and victims_raw.strip():
        v_lower = victims_raw.lower().strip()
        code = reverse_map.get(v_lower)
        if code:
            victim_codes.append(code)
    actor['victim_countries_str'] = ','.join(victim_codes)
    actor['victim_country_names'] = [country_names.get(code.upper(), code.upper()) for code in victim_codes]

    # Victim sectors
    victim_sectors_raw = meta.get('cfr-target-category', [])
    victim_sectors_clean = []
    if isinstance(victim_sectors_raw, list):
        for s in victim_sectors_raw:
            if s and isinstance(s, str):
                cleaned = s.strip()
                if cleaned:
                    victim_sectors_clean.append(cleaned.title())
    elif isinstance(victim_sectors_raw, str) and victim_sectors_raw.strip():
        cleaned = victim_sectors_raw.strip()
        if cleaned:
            victim_sectors_clean.append(cleaned.title())
    actor['victim_sectors'] = victim_sectors_clean
    actor['victim_sectors_str'] = ','.join([s.lower() for s in victim_sectors_clean])

    # Last update
    last_update = cache.get('last_update_time') or datetime.now()

    context = {
        'actor': actor,
        'last_update': last_update,
    }

    return render(request, 'threat_detail.html', context)
from django.shortcuts import render
from django.http import JsonResponse
from datetime import datetime, timedelta
import requests
from django.core.cache import cache
import threading
from django.db import models
from .models import Tactic, Technique

# Realtime source for MITRE ATT&CK TTPs
MITRE_URLS = {
    'enterprise': 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
    'mobile': 'https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json',
    'ics': 'https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json',
}

def fetch_mitre_data(domain='enterprise'):
    """Fetch MITRE data in background"""
    url = MITRE_URLS.get(domain, MITRE_URLS['enterprise'])
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            cache_key = f'mitre_data_{domain}'
            cache.set(cache_key, data, 86400)  # Cache for 24 hours
            cache.set(f'mitre_last_update_{domain}', datetime.now(), 86400)
            process_mitre_data(data, domain)  # Process and save to DB
            return True
    except Exception as e:
        print(f"Error fetching MITRE data: {e}")
    return False

def process_mitre_data(data, domain):
    """Process MITRE data and save to database"""
    from django.db import transaction
    
    try:
        with transaction.atomic():
            # Clear old data for this domain
            Technique.objects.filter(domain=domain).delete()
            Tactic.objects.filter(domain=domain).delete()
            
            tactics_map = {}
            
            # First pass: Process tactics
            for obj in data.get('objects', []):
                if obj.get('type') == 'x-mitre-tactic':
                    external_id = None
                    for ref in obj.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            external_id = ref.get('external_id')
                            break
                    
                    if external_id:
                        tactic, created = Tactic.objects.update_or_create(
                            external_id=external_id,
                            domain=domain,
                            defaults={
                                'name': obj.get('name'),
                                'description': obj.get('description', ''),
                                'stix_id': obj.get('id', ''),
                                'kill_chain_phases': [
                                    phase.get('phase_name', '') 
                                    for phase in obj.get('kill_chain_phases', [])
                                ],
                            }
                        )
                        tactics_map[external_id] = tactic
            
            # Second pass: Process techniques
            for obj in data.get('objects', []):
                if obj.get('type') == 'attack-pattern':
                    external_id = None
                    for ref in obj.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            external_id = ref.get('external_id')
                            break
                    
                    if external_id:
                        # Check if subtechnique
                        is_subtechnique = '.' in external_id if external_id else False
                        subtechnique_of = None
                        
                        if is_subtechnique:
                            parent_id = external_id.split('.')[0]
                            subtechnique_of = Technique.objects.filter(
                                external_id=parent_id, domain=domain
                            ).first()
                        
                        technique, created = Technique.objects.update_or_create(
                            external_id=external_id,
                            domain=domain,
                            defaults={
                                'name': obj.get('name'),
                                'description': obj.get('description', ''),
                                'stix_id': obj.get('id', ''),
                                'domain': domain,
                                'platforms': obj.get('x_mitre_platforms', []),
                                'data_sources': [
                                    src.get('name', '') 
                                    for src in obj.get('x_mitre_data_sources', [])
                                ],
                                'detection': obj.get('x_mitre_detection', ''),
                                'is_subtechnique': is_subtechnique,
                                'subtechnique_of': subtechnique_of,
                            }
                        )
                        
                        # Add tactics to technique
                        kill_chains = obj.get('kill_chain_phases', [])
                        for phase in kill_chains:
                            tactic_id = phase.get('phase_name', '').replace('attack-', '')
                            if tactic_id in tactics_map:
                                technique.tactics.add(tactics_map[tactic_id])
        
        return True
    except Exception as e:
        print(f"Error processing MITRE data: {e}")
        return False

def mitre_dashboard(request):
    """Main dashboard view"""
    
    domain = request.GET.get('domain', 'enterprise')
    
    # Start background update if data is old (older than 24 hours)
    last_update = cache.get(f'mitre_last_update_{domain}')
    from datetime import datetime, timedelta
    
    if not last_update or datetime.now() - last_update > timedelta(hours=24):
        thread = threading.Thread(target=fetch_mitre_data, args=(domain,))
        thread.daemon = True
        thread.start()
    
    # Always get data from database (not from cache for display)
    try:
        tactics = Tactic.objects.filter(domain=domain)
        techniques = Technique.objects.filter(domain=domain)
    except Exception as e:
        # If database error, use empty querysets
        from django.db import models
        tactics = Tactic.objects.none()
        techniques = Technique.objects.none()
        print(f"Database error: {e}")
    
    # Calculate statistics
    stats = {
        'total_techniques': techniques.count(),
        'total_tactics': tactics.count(),
        'subtechniques': techniques.filter(is_subtechnique=True).count(),
        'platforms': get_platform_stats(techniques),
        'tactics_with_counts': get_tactic_stats(tactics, techniques),
    }
    
    # Get recent techniques
    recent_techniques = techniques.order_by('-created')[:10]
    
    # Get domains for dropdown
    domains = [
        {'id': 'enterprise', 'name': 'Enterprise ATT&CK'},
        {'id': 'mobile', 'name': 'Mobile ATT&CK'},
        {'id': 'ics', 'name': 'ICS ATT&CK'},
    ]
    
    context = {
        'domain': domain,
        'tactics': tactics,
        'stats': stats,
        'recent_techniques': recent_techniques,
        'last_update': cache.get(f'mitre_last_update_{domain}') or datetime.now(),
        'domains': domains,
        'total_techniques': stats['total_techniques'],
        'total_tactics': stats['total_tactics'],
    }
    
    return render(request, 'mitre_dashboard.html', context)

def get_platform_stats(techniques):
    """Calculate platform statistics"""
    platforms = {}
    for tech in techniques:
        # Handle JSONField - it's already a list
        for platform in tech.platforms or []:
            if platform:  # Skip empty strings
                platforms[platform] = platforms.get(platform, 0) + 1
    return sorted(platforms.items(), key=lambda x: x[1], reverse=True)[:10]

def get_tactic_stats(tactics, techniques):
    """Get tactics with technique counts"""
    tactic_stats = []
    for tactic in tactics:
        count = techniques.filter(tactics=tactic).count()
        tactic_stats.append({
            'id': tactic.external_id,
            'name': tactic.name,
            'count': count,
            'tactic': tactic,
        })
    return tactic_stats

def get_platform_stats(techniques):
    """Calculate platform statistics"""
    platforms = {}
    for tech in techniques:
        for platform in tech.platforms or []:
            platforms[platform] = platforms.get(platform, 0) + 1
    return sorted(platforms.items(), key=lambda x: x[1], reverse=True)[:10]

def get_tactic_stats(tactics, techniques):
    """Get tactics with technique counts"""
    tactic_stats = []
    for tactic in tactics:
        count = techniques.filter(tactics=tactic).count()
        tactic_stats.append({
            'id': tactic.external_id,
            'name': tactic.name,
            'count': count,
            'tactic': tactic,
        })
    return tactic_stats

def technique_detail(request, technique_id):
    """Detailed view for a technique"""
    domain = request.GET.get('domain', 'enterprise')
    
    technique = Technique.objects.filter(
        external_id=technique_id, domain=domain
    ).first()
    
    if not technique:
        return render(request, '404.html')
    
    # Get related techniques (same tactics)
    related_tactics = technique.tactics.all()
    related_techniques = Technique.objects.filter(
        tactics__in=related_tactics,
        domain=domain
    ).exclude(id=technique.id).distinct()[:10]
    
    # Get subtechniques
    subtechniques = Technique.objects.filter(
        subtechnique_of=technique, domain=domain
    )
    
    context = {
        'technique': technique,
        'related_techniques': related_techniques,
        'subtechniques': subtechniques,
        'tactics': technique.tactics.all(),
        'domain': domain,
    }
    
    return render(request, 'technique_detail.html', context)

def api_techniques(request):
    """API endpoint for techniques"""
    domain = request.GET.get('domain', 'enterprise')
    search = request.GET.get('search', '')
    
    techniques = Technique.objects.filter(domain=domain)
    
    if search:
        techniques = techniques.filter(
            models.Q(name__icontains=search) |
            models.Q(description__icontains=search) |
            models.Q(external_id__icontains=search)
        )
    
    data = []
    for tech in techniques[:100]:  # Limit to 100 results
        data.append({
            'id': tech.external_id,
            'name': tech.name,
            'description': tech.description[:200] + '...' if len(tech.description) > 200 else tech.description,
            'tactics': [t.name for t in tech.tactics.all()],
            'platforms': tech.platforms or [],
            'is_subtechnique': tech.is_subtechnique,
            'data_sources': tech.data_sources or [],
            'url': f"/technique/{tech.external_id}/?domain={domain}",
        })
    
    return JsonResponse({
        'count': len(data),
        'domain': domain,
        'techniques': data,
    })

def update_mitre_data(request):
    """Manual trigger to update MITRE data"""
    if request.method == 'POST':
        domain = request.POST.get('domain', 'enterprise')
        
        # Start background update
        thread = threading.Thread(target=fetch_mitre_data, args=(domain,))
        thread.daemon = True
        thread.start()
        
        return JsonResponse({
            'status': 'success',
            'message': f'MITRE {domain} data update started in background',
            'domain': domain,
        })
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)

def search_techniques(request):
    """Search techniques"""
    query = request.GET.get('q', '')
    domain = request.GET.get('domain', 'enterprise')
    
    techniques = Technique.objects.filter(domain=domain)
    
    if query:
        techniques = techniques.filter(
            models.Q(name__icontains=query) |
            models.Q(description__icontains=query) |
            models.Q(external_id__icontains=query)
        )
    
    context = {
        'techniques': techniques,
        'query': query,
        'domain': domain,
        'total_results': techniques.count(),
    }
    
    return render(request, 'search_results.html', context)
# Add this function to views.py
def clear_cache_view(request):
    """Clear cache for a specific domain"""
    domain = request.GET.get('domain', 'enterprise')
    
    # Clear cache
    cache.delete(f'mitre_data_{domain}')
    cache.delete(f'mitre_last_update_{domain}')
    
    return JsonResponse({'status': 'success', 'message': 'Cache cleared'})



from django.shortcuts import render
from django.core.cache import cache
import requests
import json
import logging

logger = logging.getLogger(__name__)

DATASETS = {
    "Enterprise": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "Mobile": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
    "ICS": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
}

def load_dataset(url, matrix_name, use_cache=True):
    """Load dataset with caching and error handling"""
    cache_key = f"mitre_dataset_{matrix_name}"
    
    if use_cache:
        cached = cache.get(cache_key)
        if cached:
            logger.info(f"Loaded {matrix_name} from cache")
            return cached
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        content_type = response.headers.get('content-type', '')
        if 'application/json' not in content_type.lower():
            if response.text.strip().startswith('<!DOCTYPE html>') or '<html>' in response.text.lower():
                logger.error(f"Got HTML instead of JSON from {url}")
                return None
        
        data = response.json()
        
        if use_cache:
            cache.set(cache_key, data, 3600)
            logger.info(f"Cached {matrix_name} dataset")
        
        return data
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch {matrix_name} dataset: {e}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {matrix_name} dataset: {e}")
        return None

def load_all_mitre_objects(force_fresh=False):
    """Shared loader for all MITRE objects across matrices."""
    if force_fresh:
        for matrix in DATASETS:
            cache.delete(f'mitre_dataset_{matrix}')
    
    all_objects = []
    loaded_matrices = []
    error_msg = None
    
    for matrix, url in DATASETS.items():
        data = load_dataset(url, matrix)
        if data is None:
            data = load_dataset(url, matrix, use_cache=False)
            if data is None:
                logger.warning(f"Could not load {matrix} dataset after retry, using empty")
                if matrix == 'Enterprise':
                    error_msg = f"Failed to load {matrix} data. Check network/logs."
                data = {"objects": []}
        
        obj_count = len(data.get("objects", []))
        logger.info(f"Loaded {matrix}: {obj_count} total objects")
        
        for obj in data.get("objects", []):
            obj["matrix"] = matrix
        all_objects.extend(data.get("objects", []))
        loaded_matrices.append(matrix)
    
    logger.info(f"Total loaded: {len(all_objects)} objects from matrices {loaded_matrices}")
    return all_objects, loaded_matrices, error_msg

def get_mitre_category(obj):
    """Extract category from MITRE object"""
    # Try multiple possible category fields
    category = obj.get("x_mitre_domains", ["Uncategorized"])[0] if obj.get("x_mitre_domains") else None
    if not category:
        category = obj.get("x_mitre_platforms", ["Uncategorized"])[0] if obj.get("x_mitre_platforms") else None
    if not category:
        category = "Uncategorized"
    return category

def get_tool_classification(name, mitre_type):
    """
    Classify tool/malware based on name and MITRE type.
    Returns: 'tool', 'malware', or 'dual-use'
    """
    if not name:
        return mitre_type
    
    name_lower = name.lower()
    
    # Pure malware (no legitimate use)
    pure_malware_keywords = [
        "emotet", "trickbot", "ryuk", "conti", "lockbit", "revil",
        "wannacry", "notpetya", "stuxnet", "zeus", "darkcomet",
        "gh0st", "blackshades", "citadel", "carberp", "tinba"
    ]
    
    # Dual-use tools (legitimate but often abused)
    dual_use_tools = [
        "cobalt strike", "metasploit", "powershell", "python",
        "net", "wmic", "sc", "reg", "certutil", "bitsadmin",
        "wget", "curl", "mimikatz", "bloodhound", "impacket",
        "nmap", "wireshark", "burp", "sqlmap", "empire",
        "psexec", "netcat", "nc", "telnet", "ftp", "tftp",
        "vnc", "teamviewer", "anydesk", "putty", "openvas",
        "nessus", "acunetix", "nikto", "dirb", "gobuster"
    ]
    
    # Check if it's pure malware
    for malware_keyword in pure_malware_keywords:
        if malware_keyword in name_lower:
            return 'malware'
    
    # Check if it's a dual-use tool
    for tool_keyword in dual_use_tools:
        if tool_keyword in name_lower:
            return 'tool'  # Show as tool even if MITRE says malware
    
    # Default to MITRE's classification
    return mitre_type

def tools(request):
    """View for displaying tools and malware with proper classification"""
    
    # Filter params
    type_filter = request.GET.get("type", "all")  # 'all', 'tool', 'malware'
    category_filter = request.GET.get("category", "all")
    
    # Use shared loader
    all_objects, loaded_matrices, error_msg = load_all_mitre_objects()
    
    # Fallback: If no data loaded, show error
    if not all_objects:
        return render(request, "tools.html", {
            "tools_list": [],
            "total_tools": 0,
            "error": "Unable to load MITRE ATT&CK data.",
            "loaded_matrices": [],
            "type_filter": type_filter,
            "category_filter": category_filter,
            "available_types": ["all", "tool", "malware", "dual-use"],
            "available_categories": ["all"],
        })

    # Lookup dictionary for fast reference
    obj_by_id = {obj["id"]: obj for obj in all_objects}
    
    # Track tools by MITRE ID
    tools_by_id = {}
    unique_categories = set()
    
    # First pass: collect all tools and malware
    for obj in all_objects:
        if obj.get("type") not in ["tool", "malware"]:
            continue

        # MITRE ID
        tool_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tool_id = ref.get("external_id")
                break

        if not tool_id:
            continue
        
        # Get category
        category = get_mitre_category(obj)
        unique_categories.add(category)
        
        # Get proper classification
        name = obj.get("name", "")
        mitre_type = obj.get("type")  # MITRE's classification
        actual_type = get_tool_classification(name, mitre_type)
        
        # Store tool info
        tools_by_id[tool_id] = {
            "id": tool_id,
            "internal_id": obj["id"],
            "name": name,
            "type": actual_type,  # Use our corrected classification
            "mitre_type": mitre_type,  # Keep original for reference
            "matrix": obj.get("matrix", "Unknown"),
            "category": category,
            "object": obj,
            "aliases": set(obj.get("aliases", [])),
            "matrices": set([obj.get("matrix", "Unknown")]),
            "is_dual_use": actual_type == 'tool' and mitre_type == 'malware',
        }
    
    # Filter tools based on type and category
    filtered_tools = tools_by_id.copy()
    
    if type_filter != "all":
        if type_filter == "dual-use":
            # Show tools that MITRE calls malware but we classify as tools
            filtered_tools = {k: v for k, v in tools_by_id.items() 
                            if v["is_dual_use"]}
        else:
            filtered_tools = {k: v for k, v in tools_by_id.items() 
                            if v["type"] == type_filter}
    
    if category_filter != "all":
        filtered_tools = {k: v for k, v in filtered_tools.items() 
                         if v["category"] == category_filter}
    
    # Build tools list for cards
    tools_list = []
    for tool_id, tool_data in sorted(filtered_tools.items(), key=lambda x: x[1]["name"].lower()):
        matrices = sorted(tool_data["matrices"])
        matrix_display = " / ".join(matrices) if len(matrices) > 1 else matrices[0]
        
        # Add classification note for dual-use tools
        description = tool_data["object"].get("description", "")
        if tool_data["is_dual_use"]:
            description = f"⚠️ <strong>Note:</strong> Legitimate tool often abused by threat actors<br><br>" + description
        
        tools_list.append({
            "id": tool_id,
            "name": tool_data["name"],
            "type": tool_data["type"],
            "mitre_type": tool_data["mitre_type"],  # For template if needed
            "matrix": matrix_display,
            "category": tool_data["category"],
            "aliases": sorted(list(tool_data["aliases"])),
            "description": description,
            "revoked": tool_data["object"].get("revoked", False),
            "is_dual_use": tool_data["is_dual_use"],
        })

    return render(request, "tools.html", {
        "tools_list": tools_list,
        "total_tools": len(filtered_tools),
        "loaded_matrices": loaded_matrices,
        "error": error_msg,
        "type_filter": type_filter,
        "category_filter": category_filter,
        "available_types": ["all", "tool", "malware", "dual-use"],
        "available_categories": sorted(list(unique_categories)) + ["all"],
    })


def tools_detail(request, tool_id):
    # Use shared loader
    all_objects, loaded_matrices, error_msg = load_all_mitre_objects()
    
    if not all_objects:
        return render(request, "tools_detail.html", {
            "tool": None,
            "error": "Unable to load MITRE ATT&CK data.",
            "loaded_matrices": [],
        })

    # Lookup dictionary for fast reference
    obj_by_id = {obj["id"]: obj for obj in all_objects}
    
    # Find the tool object by MITRE ID
    tool_obj = None
    for obj in all_objects:
        if obj.get("type") not in ["tool", "malware"]:
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id") == tool_id:
                tool_obj = obj
                break
        if tool_obj:
            break

    if not tool_obj:
        return render(request, "tools_detail.html", {
            "tool": None,
            "error": f"Tool/Malware with ID '{tool_id}' not found.",
            "loaded_matrices": [],
        })
    
    # Get proper classification using the same function as tools view
    name = tool_obj.get("name", "")
    mitre_type = tool_obj.get("type")  # MITRE's original classification
    actual_type = get_tool_classification(name, mitre_type)
    
    # Check if it's dual-use
    is_dual_use = actual_type == 'tool' and mitre_type == 'malware'
    
    # Get category
    category = get_mitre_category(tool_obj)
    
    # Get MITRE references
    mitre_refs = [ref for ref in tool_obj.get("external_references", []) 
                 if ref.get("source_name") == "mitre-attack"]
    
    # TECHNIQUES used by this tool
    techniques = []
    for rel in [r for r in all_objects if r.get("type") == "relationship"]:
        if rel.get("source_ref") != tool_obj["id"]:
            continue
        target = obj_by_id.get(rel.get("target_ref"))
        if target and target.get("type") == "attack-pattern":
            ext_id = None
            for ref in target.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id")
                    break
            
            if ext_id:
                techniques.append({
                    "id": ext_id,
                    "name": target.get("name"),
                    "description": target.get("description", ""),
                    "domain": ", ".join(target.get("x_mitre_platforms", ["Unknown"])),
                })
    
    # GROUPS that use this tool
    groups_using = []
    for rel in [r for r in all_objects if r.get("type") == "relationship"]:
        if rel.get("target_ref") != tool_obj["id"]:
            continue
        source = obj_by_id.get(rel.get("source_ref"))
        if source and source.get("type") == "intrusion-set":
            # Get MITRE group ID
            group_id = None
            for ref in source.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    group_id = ref.get("external_id")
                    break
            
            if group_id:
                groups_using.append({
                    "id": group_id,
                    "name": source.get("name"),
                    "description": source.get("description", ""),
                    "aliases": source.get("aliases", []),
                })

    # Additional metadata
    kill_chain_phases = []
    for rel in [r for r in all_objects if r.get("type") == "relationship"]:
        if rel.get("source_ref") == tool_obj["id"] and rel.get("relationship_type") == "uses":
            target = obj_by_id.get(rel.get("target_ref"))
            if target and target.get("type") == "kill-chain-phase":
                kill_chain_phases.append(target.get("phase_name", ""))

    tool_details = {
        "id": tool_id,
        "internal_id": tool_obj["id"],
        "name": tool_obj.get("name"),
        "type": actual_type,  # Use our corrected classification
        "mitre_type": mitre_type,  # Keep MITRE's original
        "category": category,
        "description": tool_obj.get("description"),
        "aliases": sorted(tool_obj.get("aliases", [])),
        "matrices": sorted([tool_obj.get("matrix", "Unknown")]),
        "revoked": tool_obj.get("revoked", False),
        "created": tool_obj.get("created"),
        "modified": tool_obj.get("modified"),
        "kill_chain_phases": kill_chain_phases,
        "external_references": mitre_refs,
        "x_mitre_platforms": tool_obj.get("x_mitre_platforms", []),
        "x_mitre_aliases": tool_obj.get("x_mitre_aliases", []),
        "techniques": techniques,
        "groups_using": groups_using,
        "is_dual_use": is_dual_use,  # Add this flag
    }

    return render(request, "tools_detail.html", {
        "tool": tool_details,
        "loaded_matrices": loaded_matrices,
        "error": error_msg,
    })

from django.shortcuts import render
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def groups(request):
    groups_list = []
    
    # Use shared loader (no force_fresh for performance; cache is fine here)
    all_objects, loaded_matrices, error_msg = load_all_mitre_objects()
    
    # Fallback: If no data loaded, show error
    if not all_objects:
        return render(request, "groups.html", {
            "groups_list": [],
            "total_groups": 0,
            "error": "Unable to load MITRE ATT&CK data. Please check your internet connection and try again.",
            "loaded_matrices": [],
            # Threat actor fallback
            "actors": [],
            "total_actors": 0,
            "source_countries_display": [],
            "victim_countries_display": [],
            "victim_sectors": [],
            "last_update": datetime.now(),
        })

    # Lookup dictionary for fast reference
    obj_by_id = {obj["id"]: obj for obj in all_objects}
    
    # Track which MITRE IDs we've already processed
    groups_by_gid = {}  # Store group info by MITRE ID
    
    # First pass: collect all groups by MITRE ID
    for obj in all_objects:
        if obj.get("type") != "intrusion-set":
            continue

        # MITRE ID
        gid = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                gid = ref.get("external_id")
                break

        if not gid:
            continue
        
        # Store group info
        if gid not in groups_by_gid:
            groups_by_gid[gid] = {
                "name": obj.get("name"),
                "matrix": obj.get("matrix", "Unknown"),
                "object": obj,
                "aliases": set(obj.get("aliases", [])),
                "matrices": set([obj.get("matrix", "Unknown")]),
            }
        else:
            # Group already exists, update aliases and matrices
            groups_by_gid[gid]["aliases"].update(obj.get("aliases", []))
            groups_by_gid[gid]["matrices"].add(obj.get("matrix", "Unknown"))
    
    # Build groups list for cards from unique groups
    for gid, group_data in sorted(groups_by_gid.items(), key=lambda x: x[1]["name"].lower()):
        # Combine matrices if group appears in multiple
        matrices = sorted(group_data["matrices"])
        matrix_display = " / ".join(matrices) if len(matrices) > 1 else matrices[0]
        
        groups_list.append({
            "id": gid,
            "name": group_data["name"],
            "matrix": matrix_display,
            "aliases": sorted(list(group_data["aliases"])),
            "description": group_data["object"].get("description", ""),
            "revoked": group_data["object"].get("revoked", False),
        })

    # Threat Actor Data (merged from threat_dashboard)
    # Full ISO 3166-1 alpha-2 country code to name mapping
    country_names = {
        'AD': 'Andorra', 'AE': 'United Arab Emirates', 'AF': 'Afghanistan', 'AG': 'Antigua and Barbuda',
        'AI': 'Anguilla', 'AL': 'Albania', 'AM': 'Armenia', 'AO': 'Angola', 'AQ': 'Antarctica',
        'AR': 'Argentina', 'AS': 'American Samoa', 'AT': 'Austria', 'AU': 'Australia', 'AW': 'Aruba',
        'AX': 'Åland Islands', 'AZ': 'Azerbaijan', 'BA': 'Bosnia and Herzegovina', 'BB': 'Barbados',
        'BD': 'Bangladesh', 'BE': 'Belgium', 'BF': 'Burkina Faso', 'BG': 'Bulgaria', 'BH': 'Bahrain',
        'BI': 'Burundi', 'BJ': 'Benin', 'BL': 'Saint Barthélemy', 'BM': 'Bermuda', 'BN': 'Brunei Darussalam',
        'BO': 'Bolivia', 'BQ': 'Bonaire, Sint Eustatius and Saba', 'BR': 'Brazil', 'BS': 'Bahamas',
        'BT': 'Bhutan', 'BV': 'Bouvet Island', 'BW': 'Botswana', 'BY': 'Belarus', 'BZ': 'Belize',
        'CA': 'Canada', 'CC': 'Cocos (Keeling) Islands', 'CD': 'Congo (Democratic Republic)', 'CF': 'Central African Republic',
        'CG': 'Congo', 'CH': 'Switzerland', 'CI': "Côte d'Ivoire", 'CK': 'Cook Islands', 'CL': 'Chile',
        'CM': 'Cameroon', 'CN': 'China', 'CO': 'Colombia', 'CR': 'Costa Rica', 'CU': 'Cuba',
        'CV': 'Cabo Verde', 'CW': 'Curaçao', 'CX': 'Christmas Island', 'CY': 'Cyprus', 'CZ': 'Czechia',
        'DE': 'Germany', 'DJ': 'Djibouti', 'DK': 'Denmark', 'DM': 'Dominica', 'DO': 'Dominican Republic',
        'DZ': 'Algeria', 'EC': 'Ecuador', 'EE': 'Estonia', 'EG': 'Egypt', 'EH': 'Western Sahara',
        'ER': 'Eritrea', 'ES': 'Spain', 'ET': 'Ethiopia', 'FI': 'Finland', 'FJ': 'Fiji',
        'FK': 'Falkland Islands', 'FM': 'Micronesia', 'FO': 'Faroe Islands', 'FR': 'France',
        'GA': 'Gabon', 'GB': 'United Kingdom', 'GD': 'Grenada', 'GE': 'Georgia', 'GF': 'French Guiana',
        'GG': 'Guernsey', 'GH': 'Ghana', 'GI': 'Gibraltar', 'GL': 'Greenland', 'GM': 'Gambia',
        'GN': 'Guinea', 'GP': 'Guadeloupe', 'GQ': 'Equatorial Guinea', 'GR': 'Greece',
        'GS': 'South Georgia', 'GT': 'Guatemala', 'GU': 'Guam', 'GW': 'Guinea-Bissau', 'GY': 'Guyana',
        'HK': 'Hong Kong', 'HM': 'Heard Island', 'HN': 'Honduras', 'HR': 'Croatia', 'HT': 'Haiti',
        'HU': 'Hungary', 'ID': 'Indonesia', 'IE': 'Ireland', 'IL': 'Israel', 'IM': 'Isle of Man',
        'IN': 'India', 'IO': 'British Indian Ocean Territory', 'IQ': 'Iraq', 'IR': 'Iran',
        'IS': 'Iceland', 'IT': 'Italy', 'JE': 'Jersey', 'JM': 'Jamaica', 'JO': 'Jordan',
        'JP': 'Japan', 'KE': 'Kenya', 'KG': 'Kyrgyzstan', 'KH': 'Cambodia', 'KI': 'Kiribati',
        'KM': 'Comoros', 'KN': 'Saint Kitts and Nevis', 'KP': 'North Korea', 'KR': 'South Korea',
        'KW': 'Kuwait', 'KY': 'Cayman Islands', 'KZ': 'Kazakhstan', 'LA': 'Laos', 'LB': 'Lebanon',
        'LC': 'Saint Lucia', 'LI': 'Liechtenstein', 'LK': 'Sri Lanka', 'LR': 'Liberia', 'LS': 'Lesotho',
        'LT': 'Lithuania', 'LU': 'Luxembourg', 'LV': 'Latvia', 'LY': 'Libya', 'MA': 'Morocco',
        'MC': 'Monaco', 'MD': 'Moldova', 'ME': 'Montenegro', 'MF': 'Saint Martin', 'MG': 'Madagascar',
        'MH': 'Marshall Islands', 'MK': 'North Macedonia', 'ML': 'Mali', 'MM': 'Myanmar', 'MN': 'Mongolia',
        'MO': 'Macao', 'MP': 'Northern Mariana Islands', 'MQ': 'Martinique', 'MR': 'Mauritania',
        'MS': 'Montserrat', 'MT': 'Malta', 'MU': 'Mauritius', 'MV': 'Maldives', 'MW': 'Malawi',
        'MX': 'Mexico', 'MY': 'Malaysia', 'MZ': 'Mozambique', 'NA': 'Namibia', 'NC': 'New Caledonia',
        'NE': 'Niger', 'NF': 'Norfolk Island', 'NG': 'Nigeria', 'NI': 'Nicaragua', 'NL': 'Netherlands',
        'NO': 'Norway', 'NP': 'Nepal', 'NR': 'Nauru', 'NU': 'Niue', 'NZ': 'New Zealand',
        'OM': 'Oman', 'PA': 'Panama', 'PE': 'Peru', 'PF': 'French Polynesia', 'PG': 'Papua New Guinea',
        'PH': 'Philippines', 'PK': 'Pakistan', 'PL': 'Poland', 'PM': 'Saint Pierre and Miquelon',
        'PN': 'Pitcairn', 'PR': 'Puerto Rico', 'PS': 'Palestine', 'PT': 'Portugal', 'PW': 'Palau',
        'PY': 'Paraguay', 'QA': 'Qatar', 'RE': 'Réunion', 'RO': 'Romania', 'RS': 'Serbia',
        'RU': 'Russia', 'RW': 'Rwanda', 'SA': 'Saudi Arabia', 'SB': 'Solomon Islands', 'SC': 'Seychelles',
        'SD': 'Sudan', 'SE': 'Sweden', 'SG': 'Singapore', 'SH': 'Saint Helena', 'SI': 'Slovenia',
        'SJ': 'Svalbard and Jan Mayen', 'SK': 'Slovakia', 'SL': 'Sierra Leone', 'SM': 'San Marino',
        'SN': 'Senegal', 'SO': 'Somalia', 'SR': 'Suriname', 'SS': 'South Sudan', 'ST': 'Sao Tome and Principe',
        'SV': 'El Salvador', 'SX': 'Sint Maarten', 'SY': 'Syria', 'SZ': 'Eswatini', 'TC': 'Turks and Caicos Islands',
        'TD': 'Chad', 'TF': 'French Southern Territories', 'TG': 'Togo', 'TH': 'Thailand', 'TJ': 'Tajikistan',
        'TK': 'Tokelau', 'TL': 'Timor-Leste', 'TM': 'Turkmenistan', 'TN': 'Tunisia', 'TO': 'Tonga',
        'TR': 'Türkiye', 'TT': 'Trinidad and Tobago', 'TV': 'Tuvalu', 'TW': 'Taiwan', 'TZ': 'Tanzania',
        'UA': 'Ukraine', 'UG': 'Uganda', 'UM': 'U.S. Minor Outlying Islands', 'US': 'United States',
        'UY': 'Uruguay', 'UZ': 'Uzbekistan', 'VA': 'Holy See', 'VC': 'Saint Vincent and the Grenadines',
        'VE': 'Venezuela', 'VG': 'Virgin Islands (British)', 'VI': 'Virgin Islands (U.S.)', 'VN': 'Vietnam',
        'VU': 'Vanuatu', 'WF': 'Wallis and Futuna', 'WS': 'Samoa', 'YE': 'Yemen', 'YT': 'Mayotte',
        'ZA': 'South Africa', 'ZM': 'Zambia', 'ZW': 'Zimbabwe'
    }

    # Reverse mapping: full name → code (lowercase)
    country_code_reverse = {name.lower(): code.lower() for code, name in country_names.items()}

    # Start background update
    thread = threading.Thread(target=fetch_threat_data)
    thread.daemon = True
    thread.start()

    # Get cached data or fetch fresh
    data = cache.get('threat_data')
    last_update = cache.get('last_update_time')
    if not data or (last_update and (datetime.now() - last_update).total_seconds() > 300):
        url = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
        try:
            response = requests.get(url, timeout=10)
            data = response.json() if response.status_code == 200 else {'values': []}
        except:
            data = {'values': []}
        cache.set('threat_data', data, 3600)
        cache.set('last_update_time', datetime.now(), 3600)

    actors = data.get('values', [])

    # Prepare actors
    for actor in actors:
        meta = actor.setdefault('meta', {})
        actor['uuid'] = meta.get('uuid', 'N/A')
        actor['meta_json'] = json.dumps(meta)

        # Source countries (origin) - always codes
        source_country = meta.get('country')
        if isinstance(source_country, list):
            source_codes = [c.upper() for c in source_country if c]
        else:
            source_codes = [source_country.upper()] if source_country else []

        actor['source_countries_str'] = ','.join(source_codes).lower()
        actor['source_country_names'] = [country_names.get(code, code) for code in source_codes]

        # Victim countries - normalize to lowercase codes
        victims_raw = meta.get('cfr-suspected-victims', [])
        victim_codes = []

        if isinstance(victims_raw, list):
            for v in victims_raw:
                if not v:
                    continue
                v_lower = v.lower().strip()
                code = country_code_reverse.get(v_lower)
                if code:
                    victim_codes.append(code)
                else:
                    # Fallback: try direct code match
                    if len(v) == 2 and v.upper() in country_names:
                        victim_codes.append(v.upper().lower())
        elif isinstance(victims_raw, str) and victims_raw.strip():
            v_lower = victims_raw.lower().strip()
            code = country_code_reverse.get(v_lower)
            if code:
                victim_codes.append(code)

        actor['victim_countries_str'] = ','.join(victim_codes)  # lowercase codes only

        # Victim sectors - robust cleaning
        victim_sectors_raw = meta.get('cfr-target-category', [])
        victim_sectors_clean = []

        if isinstance(victim_sectors_raw, list):
            for s in victim_sectors_raw:
                if s and isinstance(s, str):
                    cleaned = s.strip()
                    if cleaned:
                        victim_sectors_clean.append(cleaned.title())
        elif isinstance(victim_sectors_raw, str) and victim_sectors_raw.strip():
            cleaned = victim_sectors_raw.strip()
            if cleaned:
                victim_sectors_clean.append(cleaned.title())

        actor['victim_sectors'] = victim_sectors_clean
        actor['victim_sectors_str'] = ','.join([s.lower() for s in victim_sectors_clean])

    # Source countries stats (for dropdown)
    source_countries = {}
    for actor in actors:
        codes = actor['source_countries_str'].split(',')
        for code in codes:
            if code:
                source_countries[code] = source_countries.get(code, 0) + 1

    source_countries_display = sorted([
        (country_names.get(code.upper(), code.upper()), code, count)
        for code, count in source_countries.items()
    ], key=lambda x: x[0])

    # Victim countries stats (for dropdown) - using codes
    victim_countries = {}
    for actor in actors:
        codes = actor['victim_countries_str'].split(',')
        for code in codes:
            if code:
                victim_countries[code] = victim_countries.get(code, 0) + 1

    victim_countries_display = sorted([
        (country_names.get(code.upper(), code.upper()), code, count)
        for code, count in victim_countries.items()
    ], key=lambda x: x[0])

    # Victim sectors stats
    victim_sectors = {}
    for actor in actors:
        for sector in actor.get('victim_sectors', []):
            if sector:
                key = sector.lower()
                victim_sectors[key] = victim_sectors.get(key, 0) + 1

    victim_sectors_for_template = sorted([
        (sector.title(), count) for sector, count in victim_sectors.items()
    ], key=lambda x: x[0])

    return render(request, "groups.html", {
        "groups_list": groups_list,
        "total_groups": len(groups_by_gid),
        "loaded_matrices": loaded_matrices,  # For template debugging
        "error": error_msg,
        # Threat actor context
        "actors": actors,
        "total_actors": len(actors),
        "source_countries_display": source_countries_display,
        "victim_countries_display": victim_countries_display,
        "victim_sectors": victim_sectors_for_template,
        "last_update": cache.get('last_update_time') or datetime.now(),
    })


def groups_detail(request, group_id):
    # Use shared loader
    all_objects, loaded_matrices, error_msg = load_all_mitre_objects()
    
    if not all_objects:
        return render(request, "group_detail.html", {
            "group": None,
            "error": "Unable to load MITRE ATT&CK data.",
            "loaded_matrices": [],
        })

    # Lookup dictionary for fast reference
    obj_by_id = {obj["id"]: obj for obj in all_objects}
    obj_by_name = {obj.get("name"): obj for obj in all_objects if obj.get("type") == "intrusion-set"}
    
    # Track which MITRE IDs we've already processed
    groups_by_gid = {}  # Store group info by MITRE ID
    
    # First pass: collect all groups by MITRE ID
    for obj in all_objects:
        if obj.get("type") != "intrusion-set":
            continue

        # MITRE ID
        gid = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                gid = ref.get("external_id")
                break

        if not gid:
            continue
        
        # Store group info
        if gid not in groups_by_gid:
            groups_by_gid[gid] = {
                "name": obj.get("name"),
                "matrix": obj.get("matrix", "Unknown"),
                "object": obj,
                "aliases": set(obj.get("aliases", [])),
                "matrices": set([obj.get("matrix", "Unknown")]),
            }
        else:
            # Group already exists, update aliases and matrices
            groups_by_gid[gid]["aliases"].update(obj.get("aliases", []))
            groups_by_gid[gid]["matrices"].add(obj.get("matrix", "Unknown"))
    
    if group_id not in groups_by_gid:
        return render(request, "group_detail.html", {
            "group": None,
            "error": f"Group with ID '{group_id}' not found.",
            "loaded_matrices": [],
        })
    
    group_data = groups_by_gid[group_id]
    obj = group_data["object"]
        
    # TECHNIQUES
    techniques = []
    for rel in [r for r in all_objects if r.get("type") == "relationship"]:
        if rel.get("source_ref") != obj["id"]:
            continue
        target = obj_by_id.get(rel.get("target_ref"))
        if target and target.get("type") == "attack-pattern":
            ext_id = None
            for ref in target.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id")
                    break
            
            if ext_id:
                domain = ", ".join(target.get("x_mitre_platforms", ["Unknown"]))
                desc = target.get("description", "")
                techniques.append({
                    "id": ext_id,
                    "name": target.get("name"),
                    "domain": domain,
                    "use": desc
                })

    # SOFTWARE / TOOLS
    software = []
    for rel in [r for r in all_objects if r.get("type") == "relationship"]:
        if rel.get("source_ref") != obj["id"]:
            continue
        target = obj_by_id.get(rel.get("target_ref"))
        if target and target.get("type") in ["malware", "tool"]:
            ext_id = None
            for ref in target.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id")
                    break
            
            if ext_id:
                # Techniques used by software
                sw_techs = []
                for sw_rel in [r for r in all_objects if r.get("type") == "relationship" and r.get("source_ref") == target["id"]]:
                    t = obj_by_id.get(sw_rel.get("target_ref"))
                    if t and t.get("type") == "attack-pattern":
                        sw_techs.append(t.get("name"))
                software.append({
                    "id": ext_id,
                    "name": target.get("name"),
                    "type": target.get("type"),
                    "techniques": sw_techs
                })

    # ASSOCIATED GROUP DESCRIPTIONS
    associated_groups = []
    for alias_or_name in obj.get("aliases", []):
        assoc_obj = obj_by_name.get(alias_or_name)
        if assoc_obj:
            associated_groups.append({
                "name": assoc_obj.get("name"),
                "description": assoc_obj.get("description", "")
            })

    # MITRE references
    mitre_refs = [ref for ref in obj.get("external_references", []) 
                  if ref.get("source_name") == "mitre-attack"]

    group_details = {
        "id": group_id,
        "name": obj.get("name"),
        "description": obj.get("description"),
        "aliases": sorted(list(group_data["aliases"])),
        "matrices": sorted(list(group_data["matrices"])),
        "revoked": obj.get("revoked", False),
        "created": obj.get("created"),
        "modified": obj.get("modified"),
        "contributors": obj.get("x_mitre_contributors", []),
        "techniques": techniques,
        "software": software,
        "associated_groups": associated_groups,
        "external_references": mitre_refs,
    }

    return render(request, "group_detail.html", {
        "group": group_details,
        "loaded_matrices": loaded_matrices,
        "error": error_msg,
    })

import difflib
from django.core.cache import cache
import requests
from datetime import datetime

def match_threat_to_group(misp_actors, mitre_groups):
    if not mitre_groups:
        return {
            'matches': [],
            'only_in_mitre': [],
            'unmatched_misp': [actor['value'] for actor in misp_actors],
            'total_misp': len(misp_actors),
            'total_mitre': 0,
            'matched_misp_count': 0,
            'unique_matched_mitre_count': 0,
            'unmatched_mitre_count': 0,
        }
    
    paired_matches = []
    only_in_mitre = []
    unmatched_misp = []
    matched_mitre_ids = set()  # Track unique matched MITRE IDs

    # Collect all MITRE IDs for quick lookup
    mitre_ids = {}
    for mitre_group in mitre_groups:
        mitre_id = next((ref['external_id'] for ref in mitre_group.get('external_references', []) 
                         if ref.get('source_name') == 'mitre-attack'), None)
        if mitre_id:
            mitre_ids[mitre_id] = mitre_group['name']
            # Initially all unmatched
            only_in_mitre.append({
                'misp_name': '—',
                'mitre_name': mitre_group['name'],
                'mitre_id': mitre_id,
                'match_type': 'Only in MITRE',
                'misp_synonyms': [],
            })

    for misp_actor in misp_actors:
        misp_name = misp_actor['value']
        misp_synonyms = misp_actor.get('meta', {}).get('synonyms', [])
        # Ensure list
        if not isinstance(misp_synonyms, list):
            misp_synonyms = []
        misp_id_candidates = [s for s in misp_synonyms if s.startswith('G') and len(s) == 5]

        matched = False

        # Exact ID match (priority, one-to-one)
        for candidate_id in misp_id_candidates:
            if candidate_id in mitre_ids and candidate_id not in matched_mitre_ids:
                # Remove from only_in_mitre if present
                only_in_mitre = [m for m in only_in_mitre if m['mitre_id'] != candidate_id]
                paired_matches.append({
                    'misp_name': misp_name,
                    'mitre_name': mitre_ids[candidate_id],
                    'mitre_id': candidate_id,
                    'match_type': 'Exact ID',
                    'misp_synonyms': misp_synonyms,
                })
                matched_mitre_ids.add(candidate_id)
                matched = True
                break

        if matched:
            continue

        # Fuzzy match (one-to-one, only if not already matched)
        all_misp_terms = list(set([misp_name.lower()] + [s.lower() for s in misp_synonyms]))
        possible_matches = []
        for mitre_group in mitre_groups:
            mitre_id = next((ref['external_id'] for ref in mitre_group.get('external_references', [])
                             if ref.get('source_name') == 'mitre-attack'), None)
            if not mitre_id or mitre_id in matched_mitre_ids:
                continue

            mitre_name = mitre_group['name'].lower()
            mitre_aliases = [a.lower() for a in mitre_group.get('aliases', [])]
            all_mitre_terms = [mitre_name] + mitre_aliases

            best_ratio = max(difflib.SequenceMatcher(None, m_term, mi_term).ratio()
                             for m_term in all_misp_terms for mi_term in all_mitre_terms) if all_mitre_terms else 0

            if best_ratio > 0.85:
                possible_matches.append((best_ratio, mitre_group['name'], mitre_id))

        if possible_matches:
            possible_matches.sort(key=lambda x: x[0], reverse=True)
            best_ratio, best_name, best_id = possible_matches[0]
            if best_id not in matched_mitre_ids:
                # Remove from only_in_mitre
                only_in_mitre = [m for m in only_in_mitre if m['mitre_id'] != best_id]
                paired_matches.append({
                    'misp_name': misp_name,
                    'mitre_name': best_name,
                    'mitre_id': best_id,
                    'match_type': f'Fuzzy ({best_ratio:.2%})',
                    'misp_synonyms': misp_synonyms,
                })
                matched_mitre_ids.add(best_id)
                matched = True

        if not matched:
            unmatched_misp.append(misp_name)

    num_misp_matched = len(paired_matches)
    num_unique_mitre_matched = len(matched_mitre_ids)
    num_unmatched_mitre = len(only_in_mitre)

    return {
        'paired_matches': paired_matches,
        'only_in_mitre': only_in_mitre,
        'unmatched_misp': unmatched_misp,
        'total_misp': len(misp_actors),
        'total_mitre': len(mitre_ids),
        'matched_misp_count': num_misp_matched,
        'unique_matched_mitre_count': num_unique_mitre_matched,
        'unmatched_mitre_count': num_unmatched_mitre,
    }

def actor_matching(request):
    """Dashboard showing all threat actors and groups in card format"""
    
    # Handle refresh param
    force_fresh = request.GET.get('refresh') == 'true'
    
    # Fetch MISP threat actors (with cache)
    misp_data = cache.get('threat_data')
    if not misp_data or force_fresh:
        url = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            misp_data = response.json()
            cache.set('threat_data', misp_data, 3600)
            logger.info("Fetched and cached fresh MISP threat actors data")
        except Exception as e:
            logger.error(f"Failed to fetch MISP data: {e}")
            misp_data = {'values': []}
    
    misp_actors = misp_data.get('values', [])
    
    # Process all MISP actors
    processed_actors = {}
    for actor in misp_actors:
        actor_name = actor.get('value', '')
        if not actor_name:
            continue
            
        meta = actor.get('meta', {})
        
        # Source countries
        source_country = meta.get('country')
        source_codes = []
        if isinstance(source_country, list):
            source_codes = [str(c).strip().upper() for c in source_country if c]
        elif source_country:
            source_codes = [str(source_country).strip().upper()]
        
        # Victim sectors
        victim_sectors_raw = meta.get('cfr-target-category', [])
        victim_sectors_clean = []
        if isinstance(victim_sectors_raw, list):
            for s in victim_sectors_raw:
                if s and isinstance(s, str):
                    cleaned = s.strip()
                    if cleaned:
                        victim_sectors_clean.append(cleaned.title())
        elif isinstance(victim_sectors_raw, str) and victim_sectors_raw.strip():
            cleaned = victim_sectors_raw.strip().title()
            if cleaned:
                victim_sectors_clean.append(cleaned)
        
        processed_actors[actor_name] = {
            'name': actor_name,
            'description': actor.get('description', ''),
            'meta': meta,
            'source_countries': source_codes,
            'victim_sectors': victim_sectors_clean,
            'synonyms': meta.get('synonyms', []),
            'uuid': meta.get('uuid', ''),
        }

    # Load MITRE data
    all_objects, loaded_matrices, error_msg = load_all_mitre_objects(force_fresh=force_fresh)
    
    # Extract MITRE groups
    mitre_groups = []
    if all_objects:
        mitre_groups = [obj for obj in all_objects if obj.get("type") == "intrusion-set"]

    # Run matching logic
    results = match_threat_to_group(misp_actors, mitre_groups)
    
    # Prepare unmatched MISP actors for template
    unmatched_misp_list = []
    for actor_name in results['unmatched_misp']:
        actor = processed_actors.get(actor_name, {})
        unmatched_misp_list.append({
            'name': actor_name,
            'uuid': actor.get('uuid', ''),
            'description': actor.get('description', ''),
            'source_countries': actor.get('source_countries', []),
            'victim_sectors': actor.get('victim_sectors', []),
        })

    # Prepare only_in_mitre for template
    only_in_mitre_list = results['only_in_mitre']

    context = {
        'paired_matches': results['paired_matches'],
        'unmatched_misp': unmatched_misp_list,
        'only_in_mitre': only_in_mitre_list,
        'stats': {
            'total_misp': results['total_misp'],
            'total_mitre': results['total_mitre'],
            'matched_misp_count': results['matched_misp_count'],
            'unique_matched_mitre_count': results['unique_matched_mitre_count'],
            'unmatched_misp_count': len(results['unmatched_misp']),
            'unmatched_mitre_count': results['unmatched_mitre_count'],
        },
        'last_update': datetime.now(),
        'loaded_matrices': loaded_matrices if loaded_matrices else [],
        'error': error_msg,
    }

    return render(request, 'actor_matching.html', context)

def misp_actor_detail(request):
    """View to show details of a single MISP actor with full processing"""
    actor_name = request.GET.get("actor_name")
    
    if not actor_name:
        return render(request, "misp_actor_detail.html", {
            "error": "No actor name provided",
            "actor": None,
        })
    
    # Use the same country mapping as threat_dashboard
    country_names = {
        'AD': 'Andorra', 'AE': 'United Arab Emirates', 'AF': 'Afghanistan', 'AG': 'Antigua and Barbuda',
        'AI': 'Anguilla', 'AL': 'Albania', 'AM': 'Armenia', 'AO': 'Angola', 'AQ': 'Antarctica',
        'AR': 'Argentina', 'AS': 'American Samoa', 'AT': 'Austria', 'AU': 'Australia', 'AW': 'Aruba',
        'AX': 'Åland Islands', 'AZ': 'Azerbaijan', 'BA': 'Bosnia and Herzegovina', 'BB': 'Barbados',
        'BD': 'Bangladesh', 'BE': 'Belgium', 'BF': 'Burkina Faso', 'BG': 'Bulgaria', 'BH': 'Bahrain',
        'BI': 'Burundi', 'BJ': 'Benin', 'BL': 'Saint Barthélemy', 'BM': 'Bermuda', 'BN': 'Brunei Darussalam',
        'BO': 'Bolivia', 'BQ': 'Bonaire, Sint Eustatius and Saba', 'BR': 'Brazil', 'BS': 'Bahamas',
        'BT': 'Bhutan', 'BV': 'Bouvet Island', 'BW': 'Botswana', 'BY': 'Belarus', 'BZ': 'Belize',
        'CA': 'Canada', 'CC': 'Cocos (Keeling) Islands', 'CD': 'Congo (Democratic Republic)', 'CF': 'Central African Republic',
        'CG': 'Congo', 'CH': 'Switzerland', 'CI': "Côte d'Ivoire", 'CK': 'Cook Islands', 'CL': 'Chile',
        'CM': 'Cameroon', 'CN': 'China', 'CO': 'Colombia', 'CR': 'Costa Rica', 'CU': 'Cuba',
        'CV': 'Cabo Verde', 'CW': 'Curaçao', 'CX': 'Christmas Island', 'CY': 'Cyprus', 'CZ': 'Czechia',
        'DE': 'Germany', 'DJ': 'Djibouti', 'DK': 'Denmark', 'DM': 'Dominica', 'DO': 'Dominican Republic',
        'DZ': 'Algeria', 'EC': 'Ecuador', 'EE': 'Estonia', 'EG': 'Egypt', 'EH': 'Western Sahara',
        'ER': 'Eritrea', 'ES': 'Spain', 'ET': 'Ethiopia', 'FI': 'Finland', 'FJ': 'Fiji',
        'FK': 'Falkland Islands', 'FM': 'Micronesia', 'FO': 'Faroe Islands', 'FR': 'France',
        'GA': 'Gabon', 'GB': 'United Kingdom', 'GD': 'Grenada', 'GE': 'Georgia', 'GF': 'French Guiana',
        'GG': 'Guernsey', 'GH': 'Ghana', 'GI': 'Gibraltar', 'GL': 'Greenland', 'GM': 'Gambia',
        'GN': 'Guinea', 'GP': 'Guadeloupe', 'GQ': 'Equatorial Guinea', 'GR': 'Greece',
        'GS': 'South Georgia', 'GT': 'Guatemala', 'GU': 'Guam', 'GW': 'Guinea-Bissau', 'GY': 'Guyana',
        'HK': 'Hong Kong', 'HM': 'Heard Island', 'HN': 'Honduras', 'HR': 'Croatia', 'HT': 'Haiti',
        'HU': 'Hungary', 'ID': 'Indonesia', 'IE': 'Ireland', 'IL': 'Israel', 'IM': 'Isle of Man',
        'IN': 'India', 'IO': 'British Indian Ocean Territory', 'IQ': 'Iraq', 'IR': 'Iran',
        'IS': 'Iceland', 'IT': 'Italy', 'JE': 'Jersey', 'JM': 'Jamaica', 'JO': 'Jordan',
        'JP': 'Japan', 'KE': 'Kenya', 'KG': 'Kyrgyzstan', 'KH': 'Cambodia', 'KI': 'Kiribati',
        'KM': 'Comoros', 'KN': 'Saint Kitts and Nevis', 'KP': 'North Korea', 'KR': 'South Korea',
        'KW': 'Kuwait', 'KY': 'Cayman Islands', 'KZ': 'Kazakhstan', 'LA': 'Laos', 'LB': 'Lebanon',
        'LC': 'Saint Lucia', 'LI': 'Liechtenstein', 'LK': 'Sri Lanka', 'LR': 'Liberia', 'LS': 'Lesotho',
        'LT': 'Lithuania', 'LU': 'Luxembourg', 'LV': 'Latvia', 'LY': 'Libya', 'MA': 'Morocco',
        'MC': 'Monaco', 'MD': 'Moldova', 'ME': 'Montenegro', 'MF': 'Saint Martin', 'MG': 'Madagascar',
        'MH': 'Marshall Islands', 'MK': 'North Macedonia', 'ML': 'Mali', 'MM': 'Myanmar', 'MN': 'Mongolia',
        'MO': 'Macao', 'MP': 'Northern Mariana Islands', 'MQ': 'Martinique', 'MR': 'Mauritania',
        'MS': 'Montserrat', 'MT': 'Malta', 'MU': 'Mauritius', 'MV': 'Maldives', 'MW': 'Malawi',
        'MX': 'Mexico', 'MY': 'Malaysia', 'MZ': 'Mozambique', 'NA': 'Namibia', 'NC': 'New Caledonia',
        'NE': 'Niger', 'NF': 'Norfolk Island', 'NG': 'Nigeria', 'NI': 'Nicaragua', 'NL': 'Netherlands',
        'NO': 'Norway', 'NP': 'Nepal', 'NR': 'Nauru', 'NU': 'Niue', 'NZ': 'New Zealand',
        'OM': 'Oman', 'PA': 'Panama', 'PE': 'Peru', 'PF': 'French Polynesia', 'PG': 'Papua New Guinea',
        'PH': 'Philippines', 'PK': 'Pakistan', 'PL': 'Poland', 'PM': 'Saint Pierre and Miquelon',
        'PN': 'Pitcairn', 'PR': 'Puerto Rico', 'PS': 'Palestine', 'PT': 'Portugal', 'PW': 'Palau',
        'PY': 'Paraguay', 'QA': 'Qatar', 'RE': 'Réunion', 'RO': 'Romania', 'RS': 'Serbia',
        'RU': 'Russia', 'RW': 'Rwanda', 'SA': 'Saudi Arabia', 'SB': 'Solomon Islands', 'SC': 'Seychelles',
        'SD': 'Sudan', 'SE': 'Sweden', 'SG': 'Singapore', 'SH': 'Saint Helena', 'SI': 'Slovenia',
        'SJ': 'Svalbard and Jan Mayen', 'SK': 'Slovakia', 'SL': 'Sierra Leone', 'SM': 'San Marino',
        'SN': 'Senegal', 'SO': 'Somalia', 'SR': 'Suriname', 'SS': 'South Sudan', 'ST': 'Sao Tome and Principe',
        'SV': 'El Salvador', 'SX': 'Sint Maarten', 'SY': 'Syria', 'SZ': 'Eswatini', 'TC': 'Turks and Caicos Islands',
        'TD': 'Chad', 'TF': 'French Southern Territories', 'TG': 'Togo', 'TH': 'Thailand', 'TJ': 'Tajikistan',
        'TK': 'Tokelau', 'TL': 'Timor-Leste', 'TM': 'Turkmenistan', 'TN': 'Tunisia', 'TO': 'Tonga',
        'TR': 'Türkiye', 'TT': 'Trinidad and Tobago', 'TV': 'Tuvalu', 'TW': 'Taiwan', 'TZ': 'Tanzania',
        'UA': 'Ukraine', 'UG': 'Uganda', 'UM': 'U.S. Minor Outlying Islands', 'US': 'United States',
        'UY': 'Uruguay', 'UZ': 'Uzbekistan', 'VA': 'Holy See', 'VC': 'Saint Vincent and the Grenadines',
        'VE': 'Venezuela', 'VG': 'Virgin Islands (British)', 'VI': 'Virgin Islands (U.S.)', 'VN': 'Vietnam',
        'VU': 'Vanuatu', 'WF': 'Wallis and Futuna', 'WS': 'Samoa', 'YE': 'Yemen', 'YT': 'Mayotte',
        'ZA': 'South Africa', 'ZM': 'Zambia', 'ZW': 'Zimbabwe'
    }
    
    country_code_reverse = {name.lower(): code.lower() for code, name in country_names.items()}
    
    # Fetch MISP data
    misp_data = cache.get('threat_data')
    if not misp_data:
        url = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
        try:
            response = requests.get(url, timeout=10)
            misp_data = response.json() if response.status_code == 200 else {'values': []}
            cache.set('threat_data', misp_data, 3600)
        except:
            misp_data = {'values': []}
    
    # Find the actor - DO EXACT MATCH
    actor_data = None
    for actor in misp_data.get('values', []):
        # Check both exact match and case-insensitive match
        if actor.get('value') == actor_name:
            actor_data = actor
            break
    
    if not actor_data:
        # Try case-insensitive match
        for actor in misp_data.get('values', []):
            if actor.get('value', '').lower() == actor_name.lower():
                actor_data = actor
                break
    
    if not actor_data:
        return render(request, "misp_actor_detail.html", {
            "error": f"Actor '{actor_name}' not found",
            "actor": None,
        })
    
    # Process the actor data EXACTLY like in threat_dashboard
    meta = actor_data.setdefault('meta', {})
    
    # Basic info - match exactly what's in the modal
    actor = {
        'name': actor_data.get('value', ''),
        'description': actor_data.get('description', ''),
        'uuid': meta.get('uuid', 'N/A'),
        'meta_json': json.dumps(meta),
        'meta': meta,  # Keep the original meta for display
        'sophistication': meta.get('sophistication', ''),
        'resource_level': meta.get('resource-level', ''),
        'primary_motivation': meta.get('primary-motivation', ''),
        'refs': meta.get('refs', []),
        'synonyms': meta.get('synonyms', []),
    }
    
    # Source countries (origin) - EXACTLY like threat_dashboard
    source_country = meta.get('country')
    if isinstance(source_country, list):
        source_codes = [c.upper() for c in source_country if c]
    else:
        source_codes = [source_country.upper()] if source_country else []
    
    actor['source_countries_str'] = ','.join(source_codes).lower()
    actor['source_country_names'] = [country_names.get(code, code) for code in source_codes]
    
    # Victim countries - EXACTLY like threat_dashboard
    victims_raw = meta.get('cfr-suspected-victims', [])
    victim_codes = []
    victim_country_names = []
    
    if isinstance(victims_raw, list):
        for v in victims_raw:
            if not v:
                continue
            v_lower = v.lower().strip()
            code = country_code_reverse.get(v_lower)
            if code:
                victim_codes.append(code)
                victim_country_names.append(country_names.get(code.upper(), code.upper()))
            else:
                # Fallback: try direct code match
                if len(v) == 2 and v.upper() in country_names:
                    code = v.upper().lower()
                    victim_codes.append(code)
                    victim_country_names.append(country_names.get(v.upper(), v.upper()))
    elif isinstance(victims_raw, str) and victims_raw.strip():
        v_lower = victims_raw.lower().strip()
        code = country_code_reverse.get(v_lower)
        if code:
            victim_codes.append(code)
            victim_country_names.append(country_names.get(code.upper(), code.upper()))
    
    actor['victim_countries_str'] = ','.join(victim_codes)  # lowercase codes only
    actor['victim_countries'] = victim_country_names  # Add this for display
    
    # Victim sectors - robust cleaning - EXACTLY like threat_dashboard
    victim_sectors_raw = meta.get('cfr-target-category', [])
    victim_sectors_clean = []
    
    if isinstance(victim_sectors_raw, list):
        for s in victim_sectors_raw:
            if s and isinstance(s, str):
                cleaned = s.strip()
                if cleaned:
                    victim_sectors_clean.append(cleaned.title())
    elif isinstance(victim_sectors_raw, str) and victim_sectors_raw.strip():
        cleaned = victim_sectors_raw.strip()
        if cleaned:
            victim_sectors_clean.append(cleaned.title())
    
    actor['victim_sectors'] = victim_sectors_clean
    actor['victim_sectors_str'] = ','.join([s.lower() for s in victim_sectors_clean])
    
    # Debug: Print what we found
    print(f"DEBUG: Found actor: {actor['name']}")
    print(f"DEBUG: Target sectors raw: {victim_sectors_raw}")
    print(f"DEBUG: Target sectors cleaned: {victim_sectors_clean}")
    print(f"DEBUG: Victim countries raw: {victims_raw}")
    print(f"DEBUG: Victim countries cleaned: {victim_country_names}")
    
    # Also load MITRE data to show related groups
    all_objects, loaded_matrices, error_msg = load_all_mitre_objects()
    
    # Find related MITRE groups
    related_groups = []
    if actor.get('synonyms'):
        for synonym in actor['synonyms']:
            if isinstance(synonym, str) and synonym.startswith('G') and len(synonym) == 5:
                # This is a MITRE group ID
                for obj in all_objects:
                    if obj.get("type") != "intrusion-set":
                        continue
                    
                    # Get MITRE ID
                    ext_refs = obj.get("external_references", [])
                    mitre_id = None
                    for ref in ext_refs:
                        if ref.get("source_name") == "mitre-attack":
                            mitre_id = ref.get("external_id")
                            break
                    
                    if mitre_id == synonym:
                        related_groups.append({
                            "id": mitre_id,
                            "name": obj.get("name"),
                            "aliases": obj.get("aliases", []),
                            "description": obj.get("description", "")
                        })
                        break
    
    context = {
        "actor": actor,
        "related_groups": related_groups,
        "error": None,
    }
    
    return render(request, "misp_actor_detail.html", context)




def combined_group_detail(request):
    """View that shows combined MITRE group and MISP actor details"""
    mitre_id = request.GET.get("mitre_id")
    misp_name = request.GET.get("misp_name")
    
    if not mitre_id:
        return render(request, "combined_group_detail.html", {
            "error": "No MITRE group ID provided",
            "has_mitre_data": False,
            "has_misp_data": False,
        })
    
    # Load MITRE data
    all_objects, loaded_matrices, error_msg = load_all_mitre_objects()
    
    # Initialize data structures
    mitre_group = None
    misp_actor = None
    
    # 1. Find MITRE group
    if all_objects:
        # Look for the MITRE group
        obj_by_id = {obj["id"]: obj for obj in all_objects}
        
        for obj in all_objects:
            if obj.get("type") != "intrusion-set":
                continue
            
            # Check MITRE ID
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id") == mitre_id:
                    # Found the group, process it like in groups view
                    group_data = process_mitre_group(obj, all_objects, obj_by_id)
                    mitre_group = group_data
                    break
            if mitre_group:
                break
    
    # 2. Find MISP actor (if name provided)
    if misp_name:
        misp_data = cache.get('threat_data')
        if not misp_data:
            url = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
            try:
                response = requests.get(url, timeout=10)
                misp_data = response.json() if response.status_code == 200 else {'values': []}
                cache.set('threat_data', misp_data, 3600)
            except:
                misp_data = {'values': []}
        
        # Search for MISP actor by name or synonym
        for actor in misp_data.get('values', []):
            if actor.get('value') == misp_name:
                misp_actor = process_misp_actor(actor)
                break
            
            # Also check synonyms
            synonyms = actor.get('meta', {}).get('synonyms', [])
            if misp_name in synonyms:
                misp_actor = process_misp_actor(actor)
                break
    
    # If no MISP actor found by name, try to find by MITRE ID in synonyms
    if not misp_actor and mitre_group:
        misp_data = cache.get('threat_data')
        if misp_data:
            for actor in misp_data.get('values', []):
                synonyms = actor.get('meta', {}).get('synonyms', [])
                if mitre_id in synonyms:
                    misp_actor = process_misp_actor(actor)
                    break
    
    # Check if we have any data
    has_mitre_data = mitre_group is not None
    has_misp_data = misp_actor is not None
    
    if not has_mitre_data and not has_misp_data:
        return render(request, "combined_group_detail.html", {
            "error": f"No data found for MITRE ID: {mitre_id}",
            "has_mitre_data": False,
            "has_misp_data": False,
        })
    
    context = {
        "mitre_group": mitre_group,
        "misp_actor": misp_actor,
        "has_mitre_data": has_mitre_data,
        "has_misp_data": has_misp_data,
        "error": None,
        "loaded_matrices": loaded_matrices,
    }
    
    return render(request, "combined_group_detail.html", context)

def process_mitre_group(obj, all_objects, obj_by_id):
    """Process MITRE group data similar to groups view"""
    # TECHNIQUES
    techniques = []
    for rel in [r for r in all_objects if r.get("type") == "relationship"]:
        if rel.get("source_ref") != obj["id"]:
            continue
        target = obj_by_id.get(rel.get("target_ref"))
        if target and target.get("type") == "attack-pattern":
            ext_id = None
            for ref in target.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id")
                    break
            
            domain = ", ".join(target.get("x_mitre_platforms", ["Unknown"]))
            desc = target.get("description", "")
            techniques.append({
                "id": ext_id,
                "name": target.get("name"),
                "domain": domain,
                "use": desc
            })
    
    # SOFTWARE / TOOLS
    software = []
    for rel in [r for r in all_objects if r.get("type") == "relationship"]:
        if rel.get("source_ref") != obj["id"]:
            continue
        target = obj_by_id.get(rel.get("target_ref"))
        if target and target.get("type") in ["malware", "tool"]:
            ext_id = None
            for ref in target.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id")
                    break
            
            refs = ", ".join([r.get("url", "") for r in target.get("external_references", []) if r.get("url")])
            # Techniques used by software
            sw_techs = []
            for sw_rel in [r for r in all_objects if r.get("type") == "relationship" and r.get("source_ref") == target["id"]]:
                t = obj_by_id.get(sw_rel.get("target_ref"))
                if t and t.get("type") == "attack-pattern":
                    sw_techs.append(t.get("name"))
            software.append({
                "id": ext_id,
                "name": target.get("name"),
                "type": target.get("type"),
                "references": refs,
                "techniques": sw_techs
            })
    
    # Get MITRE ID
    mitre_id = None
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            mitre_id = ref.get("external_id")
            break
    
    # Additional fields
    target_sectors = obj.get("x_mitre_target_sectors", [])
    target_regions = obj.get("x_mitre_target_regions", [])
    motivation = obj.get("x_mitre_motivation", [])
    objectives = obj.get("x_mitre_objectives", [])
    external_references = obj.get("external_references", [])
    
    # Format dates
    created = obj.get("created", "")
    modified = obj.get("modified", "")
    if created and 'T' in created:
        created = created.split('T')[0]
    if modified and 'T' in modified:
        modified = modified.split('T')[0]
    
    return {
        "id": mitre_id,
        "name": obj.get("name"),
        "description": obj.get("description"),
        "aliases": obj.get("aliases", []),
        "matrices": [obj.get("matrix", "Unknown")],
        "revoked": obj.get("revoked", False),
        "created": created,
        "modified": modified,
        "contributors": obj.get("x_mitre_contributors", []),
        "techniques": techniques,
        "software": software,
        "target_sectors": target_sectors,
        "target_regions": target_regions,
        "motivation": motivation,
        "objectives": objectives,
        "external_references": external_references,
    }

def process_misp_actor(actor):
    """Process MISP actor data similar to threat_dashboard view"""
    meta = actor.get('meta', {})
    
    # Source countries
    source_country = meta.get('country')
    if isinstance(source_country, list):
        source_codes = [c.upper() for c in source_country if c]
    else:
        source_codes = [source_country.upper()] if source_country else []
    
    # Country name mapping (simplified - use your full mapping from threat_dashboard)
    country_names = {
        'US': 'United States', 'CN': 'China', 'RU': 'Russia', 'IR': 'Iran',
        'KP': 'North Korea', 'VN': 'Vietnam', 'IN': 'India', 'PK': 'Pakistan',
        # Add more as needed
    }
    
    source_country_names = [country_names.get(code, code) for code in source_codes]
    
    # Victim sectors
    victim_sectors_raw = meta.get('cfr-target-category', [])
    victim_sectors_clean = []
    
    if isinstance(victim_sectors_raw, list):
        for s in victim_sectors_raw:
            if s and isinstance(s, str):
                cleaned = s.strip()
                if cleaned:
                    victim_sectors_clean.append(cleaned.title())
    elif isinstance(victim_sectors_raw, str) and victim_sectors_raw.strip():
        cleaned = victim_sectors_raw.strip()
        if cleaned:
            victim_sectors_clean.append(cleaned.title())
    
    return {
        "name": actor.get('value'),
        "description": actor.get('description', ''),
        "uuid": meta.get('uuid', 'N/A'),
        "meta": meta,
        "meta_json": json.dumps(meta),
        "source_countries": source_country_names,
        "source_countries_str": ','.join(source_codes).lower(),
        "victim_sectors": victim_sectors_clean,
        "victim_sectors_str": ','.join([s.lower() for s in victim_sectors_clean]),
        "synonyms": meta.get('synonyms', []),
        "sophistication": meta.get('sophistication', ''),
        "resource_level": meta.get('resource-level', ''),
        "primary_motivation": meta.get('primary-motivation', ''),
        "refs": meta.get('refs', []),
    }