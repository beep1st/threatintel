# scoring_engine.py
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
import logging
from dataclasses import dataclass
from django.utils import timezone
from django.db.models import Q

from App.models import ThreatFeed

# Pandas integration for dynamic calculations
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

logger = logging.getLogger(__name__)

@dataclass
class ScoringFactor:
    """Represents a single scoring factor"""
    name: str
    weight: float  # 0.0 to 1.0
    calculator: Callable  # Function that returns score 0-100
    description: str = ""

class RiskScoringEngine:
    """Dynamic risk scoring engine with optional Pandas enhancements"""
    
    def __init__(self, use_pandas: bool = False):
        self.factors: List[ScoringFactor] = []
        self.thresholds = {
            'low': 30,
            'medium': 50,
            'high': 70,
            'critical': 85
        }
        self.use_pandas = use_pandas  # Flag for dynamic Pandas mode
    
    def add_factor(self, factor: ScoringFactor):
        """Add a scoring factor"""
        self.factors.append(factor)
    
    def calculate_score(self, context: Dict) -> Dict:
        """Calculate overall risk score based on all factors"""
        total_score = 0
        max_possible = 0
        factor_details = []
        
        for factor in self.factors:
            try:
                # Pass use_pandas to calculators if needed
                calc_context = context.copy()
                calc_context['use_pandas'] = self.use_pandas
                factor_score = factor.calculator(calc_context)
                weighted_score = factor_score * factor.weight
                
                total_score += weighted_score
                max_possible += 100 * factor.weight
                
                factor_details.append({
                    'name': factor.name,
                    'raw_score': factor_score,
                    'weight': factor.weight,
                    'weighted_score': weighted_score,
                    'description': factor.description
                })
            except Exception as e:
                logger.error(f"Error calculating factor {factor.name}: {e}")
                continue
        
        # Normalize to 0-100 scale
        normalized_score = (total_score / max_possible * 100) if max_possible > 0 else 0
        
        # FIX: Remove division by 100 here
        risk_level = self._get_risk_level(normalized_score)  # Removed: normalized_score / 100
        
        return {
            'score': round(normalized_score, 2),
            'risk_level': risk_level,
            'factors': factor_details,
            'max_score': round(max_possible, 2)
        }
    
    def _get_risk_level(self, score: float) -> str:
        """Map score to risk level"""
        # Now uses the updated thresholds (30, 50, 70, 85) instead of (0.3, 0.5, 0.7, 0.85)
        if score >= self.thresholds['critical']:
            return 'Critical'
        elif score >= self.thresholds['high']:
            return 'High'
        elif score >= self.thresholds['medium']:
            return 'Medium'
        else:
            return 'Low'

class FactorCalculators:
    """Collection of scoring factor calculators"""
    
    @staticmethod
    def calculate_temporal_score(context: Dict) -> float:
        """Calculate score based on recency"""
        published = context.get('published')
        if not published:
            return 30
        
        days_old = (timezone.now() - published).days
        
        # Exponential decay for recency
        if days_old == 0:
            return 95
        elif days_old <= 1:
            return 90
        elif days_old <= 3:
            return 80
        elif days_old <= 7:
            return 65
        elif days_old <= 14:
            return 50
        elif days_old <= 30:
            return 35
        else:
            return 20
    
    @staticmethod
    def calculate_content_richness(context: Dict) -> float:
        """Score based on content length and quality"""
        content = context.get('content', '')
        title = context.get('title', '')
        
        total_length = len(content) + len(title)
        
        if total_length > 5000:
            return 90
        elif total_length > 3000:
            return 80
        elif total_length > 1500:
            return 65
        elif total_length > 800:
            return 50
        elif total_length > 300:
            return 35
        else:
            return 15
    
    @staticmethod
    def calculate_keyword_threat_score(context: Dict) -> float:
        """Score based on threat keywords"""
        text = f"{context.get('title', '')} {context.get('content', '')}".lower()
        
        # Define keyword groups with scores
        keyword_groups = {
            'critical': ['zero-day', 'remote code execution', 'privilege escalation', 
                        'ransomware', 'apt', 'nation-state', 'threat actor', 'cyber attack'],
            'high': ['exploit', 'breach', 'data theft', 'backdoor', 'persistent', 'malware', 'phishing'],
            'medium': ['vulnerability', 'ddos', 'credential', 'attack', 'compromise'],
            'low': ['update', 'patch', 'advisory', 'notice', 'alert']
        }
        
        scores = {'critical': 100, 'high': 80, 'medium': 60, 'low': 30}
        max_group_score = 0
        
        for group, keywords in keyword_groups.items():
            if any(keyword in text for keyword in keywords):
                max_group_score = max(max_group_score, scores[group])
        
        return max_group_score if max_group_score > 0 else 40
    
    @staticmethod
    def calculate_entity_density(context: Dict) -> float:
        """Score based on number of entities detected"""
        entities = context.get('entities', {})
        
        total_entities = sum(len(v) for v in entities.values())
        
        if total_entities >= 10:
            return 90
        elif total_entities >= 7:
            return 75
        elif total_entities >= 5:
            return 60
        elif total_entities >= 3:
            return 45
        elif total_entities >= 1:
            return 30
        else:
            return 15
    
    @staticmethod
    def calculate_source_reputation(context: Dict) -> float:
        """Score based on source credibility"""
        source = context.get('source', '').lower()
        
        # Reputation tiers
        high_rep = ['krebsonsecurity', 'brian krebs', 'fireeye', 'mandiant', 'crowdstrike', 
                   'palo alto', 'microsoft', 'recorded future', 'unit42', 'secureworks']
        medium_rep = ['bleepingcomputer', 'securityweek', 'threatpost', 'darkreading', 
                     'the hacker news', 'security affairs', 'cyberscoop']
        low_rep = ['social media', 'reddit', 'twitter', 'forum', 'blog', 'personal site']
        
        if any(hr in source for hr in high_rep):
            return 85
        elif any(mr in source for mr in medium_rep):
            return 65
        elif any(lr in source for lr in low_rep):
            return 40
        else:
            return 50  # Default for unknown sources
    
    @staticmethod
    def calculate_correlation_score(context: Dict) -> float:
        """Score based on correlation with known threats (Pandas-enhanced if use_pandas=True)"""
        use_pandas = context.get('use_pandas', False)
        title = context.get('title', '')
        content = context.get('content', '')
        text = f"{title} {content}".lower()
        
        if len(text) < 10:
            return 50
        
        if use_pandas:
            # Pandas + TF-IDF for dynamic similarity
            try:
                # Fetch similar feeds (limit to 50 for perf)
                similar_feeds = ThreatFeed.objects.filter(
                    Q(title__icontains=title[:20]) | Q(content__icontains=title[:20])
                ).values_list('title', flat=True)[:50]
                
                if len(similar_feeds) < 2:
                    return 40
                
                # Prepare texts for TF-IDF
                texts = [text] + list(similar_feeds)
                vectorizer = TfidfVectorizer(max_features=100, stop_words='english', lowercase=True)
                tfidf_matrix = vectorizer.fit_transform(texts)
                
                # Compute cosine similarities
                similarities = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:])[0]
                avg_sim = pd.Series(similarities).mean() * 100  # Normalize to 0-100
                
                return min(85, max(40, avg_sim))  # Cap for consistency
            except Exception as e:
                logger.warning(f"Pandas correlation failed, falling back: {e}")
                # Fallback to static
                use_pandas = False
        
        if not use_pandas:
            # Original static method
            threat_feed = context.get('threat_feed')
            if not threat_feed:
                return 50
            
            # Check if similar threats exist
            similar_count = ThreatFeed.objects.filter(
                Q(title__icontains=threat_feed.title[:20]) |
                Q(content__icontains=threat_feed.title[:20])
            ).count()
            
            if similar_count > 5:
                return 85
            elif similar_count > 3:
                return 70
            elif similar_count > 1:
                return 55
            else:
                return 40
    
    @staticmethod
    def calculate_threat_actor_score(context: Dict) -> float:
        """Enhanced scoring for threat actor mentions"""
        entity_name = context.get('entity_name', '').lower()
        is_threat_actor = context.get('is_threat_actor', False)
        
        # If not a threat actor context, return moderate score
        if not is_threat_actor:
            return 40
        
        text = f"{context.get('title', '')} {context.get('content', '')}".lower()
        
        # High-profile threat actors get higher base scores
        high_profile_actors = [
            'lazarus', 'apt29', 'apt28', 'apt37', 'apt41', 'conti', 'revil', 
            'lockbit', 'play', 'clop', 'cl0p', 'blackcat', 'alphv', 'ransomhub', 
            'akira', 'rhysida', 'bianlian', 'medusa', 'qilin', 'hive', 'pysa'
        ]
        
        # Check if high-profile actor
        actor_score = 40  # Base score for any threat actor
        
        for actor in high_profile_actors:
            if actor in entity_name or actor in text:
                actor_score = 75  # High-profile actor boost
                break
        
        # Additional boosts for critical context
        critical_keywords = [
            'ransomware', 'extortion', 'data theft', 'breach', 'exploit', 
            'zero-day', 'nation-state', 'supply chain', 'critical infrastructure',
            'government', 'healthcare', 'finance', 'energy sector'
        ]
        
        keyword_boost = 0
        for keyword in critical_keywords:
            if keyword in text:
                if keyword in ['ransomware', 'extortion', 'nation-state']:
                    keyword_boost += 10
                else:
                    keyword_boost += 5
        
        actor_score = min(100, actor_score + keyword_boost)
        
        # Boost for recent activity
        published = context.get('published')
        if published:
            days_old = (timezone.now() - published).days
            if days_old <= 7:
                actor_score = min(100, actor_score + 15)
            elif days_old <= 30:
                actor_score = min(100, actor_score + 10)
        
        # Boost for entity density (more entities = more comprehensive)
        entities = context.get('entities', {})
        total_entities = sum(len(v) for v in entities.values())
        if total_entities >= 5:
            actor_score = min(100, actor_score + 10)
        elif total_entities >= 3:
            actor_score = min(100, actor_score + 5)
        
        # Source reputation boost
        source = context.get('source', '').lower()
        high_rep_sources = ['krebsonsecurity', 'fireeye', 'mandiant', 'crowdstrike', 'palo alto']
        if any(src in source for src in high_rep_sources):
            actor_score = min(100, actor_score + 10)
        
        return actor_score
    
    @staticmethod
    def calculate_threat_actor_notoriety(context: Dict) -> float:
        """Alternative: Calculate threat actor notoriety score"""
        entity_name = context.get('entity_name', '').lower()
        
        # Notoriety tiers for known threat actors
        notorious_actors = {
            # Tier 1: Nation-state actors (100)
            'lazarus': 100, 'apt29': 100, 'apt28': 100, 'apt37': 95, 'apt41': 95,
            'equation group': 100, 'sandworm': 100, 'cozy bear': 100, 'fancy bear': 100,
            
            # Tier 2: Major ransomware groups (85-95)
            'conti': 95, 'revil': 90, 'lockbit': 90, 'alphv': 90, 'blackcat': 90,
            'clop': 85, 'cl0p': 85, 'play': 85, 'akira': 85, 'hive': 85,
            
            # Tier 3: Established threat actors (75-85)
            'wizard spider': 80, 'indrik spider': 80, 'carbanak': 80,
            'fin7': 80, 'ta505': 80, 'ta577': 80,
            
            # Tier 4: Emerging/general actors (60-75)
            'ransomhub': 75, 'rhysida': 75, 'bianlian': 70, 'medusa': 70,
            'qilin': 70, 'monti': 65, 'dragonforce': 65
        }
        
        # Check for exact matches
        for actor, score in notorious_actors.items():
            if actor in entity_name:
                return score
        
        # Check for partial matches
        for actor, score in notorious_actors.items():
            if actor.split()[0] in entity_name:
                return score * 0.9  # Slightly lower for partial matches
        
        # Default for unknown threat actors
        return 60