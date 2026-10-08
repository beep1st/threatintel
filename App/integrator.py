from threatintel.env import get_env
# integrator.py - Focused data integration
import requests
import json
from datetime import datetime
import re
# config.py - API Configuration
OTX_API_KEY = get_env('OTX_API_KEY')
OTX_BASE_URL = "https://otx.alienvault.com/api/v1/"

MISP_ACTORS_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
MITRE_GROUPS_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
class ThreatIntelIntegrator:
    """Integrates MISP, MITRE, and OTX only"""
    
    def build_unified_database(self):
        """
        Main pipeline to build unified database:
        1. Fetch MISP actors
        2. Fetch MITRE groups + tools
        3. Match and merge actors
        4. Fetch OTX IoCs for matched actors
        5. Save to database
        """
        
        print("🚀 Starting unified database build...")
        
        # Step 1: Fetch all source data
        misp_data = self.fetch_misp_actors()
        mitre_data = self.fetch_mitre_enterprise()
        
        print(f"📥 Fetched: {len(misp_data)} MISP actors, {len(mitre_data['groups'])} MITRE groups")
        
        # Step 2: Match MISP ↔ MITRE
        matched_actors = self.match_actors(misp_data, mitre_data['groups'])
        
        print(f"✅ Matched: {len(matched_actors)} unified actors")
        
        # Step 3: Create database records
        self.create_actor_records(matched_actors)
        
        # Step 4: Create tool records
        self.create_tool_records(mitre_data['tools'])
        
        # Step 5: Link actors to tools
        self.link_actors_to_tools(matched_actors, mitre_data['relationships'])
        
        # Step 6: Fetch OTX IoCs for verified actors
        self.enrich_with_otx_iocs()
        
        print("🎉 Database build complete!")
        
        return self.get_statistics()
    
    def fetch_misp_actors(self):
        """Fetch 835 actors from MISP"""
        try:
            response = requests.get(MISP_ACTORS_URL, timeout=30)
            data = response.json()
            return data.get('values', [])
        except Exception as e:
            print(f"Error fetching MISP: {e}")
            return []
    
    def fetch_mitre_enterprise(self):
        """Fetch MITRE enterprise attack data"""
        try:
            response = requests.get(MITRE_GROUPS_URL, timeout=30)
            data = response.json()
            
            # Extract groups and tools
            groups = []
            tools = []
            relationships = []
            
            for obj in data.get('objects', []):
                obj_type = obj.get('type')
                
                if obj_type == 'intrusion-set':
                    groups.append(obj)
                elif obj_type in ['malware', 'tool']:
                    tools.append(obj)
                elif obj_type == 'relationship':
                    relationships.append(obj)
            
            return {
                'groups': groups,
                'tools': tools,
                'relationships': relationships,
                'techniques': [obj for obj in data.get('objects', []) 
                              if obj.get('type') == 'attack-pattern']
            }
        except Exception as e:
            print(f"Error fetching MITRE: {e}")
            return {'groups': [], 'tools': [], 'relationships': [], 'techniques': []}
    
    def match_actors(self, misp_actors, mitre_groups):
        """Match 835 MISP actors to 220 MITRE groups"""
        matched = []
        
        # Build MITRE index
        mitre_index = {}
        for group in mitre_groups:
            mitre_id = self.extract_mitre_id(group)
            if mitre_id:
                mitre_index[mitre_id] = {
                    'object': group,
                    'name': group.get('name'),
                    'aliases': group.get('aliases', []),
                }
        
        # Match each MISP actor
        for misp_actor in misp_actors:
            misp_name = misp_actor.get('value', '')
            misp_synonyms = misp_actor.get('meta', {}).get('synonyms', [])
            
            # Look for MITRE ID in synonyms
            matched_mitre = None
            for synonym in misp_synonyms:
                if isinstance(synonym, str) and synonym in mitre_index:
                    matched_mitre = mitre_index[synonym]
                    break
            
            # If no ID match, try name matching
            if not matched_mitre:
                for mitre_id, mitre_info in mitre_index.items():
                    if self.names_match(misp_name, mitre_info['name'], mitre_info['aliases']):
                        matched_mitre = mitre_info
                        break
            
            if matched_mitre:
                # Create merged record
                matched.append({
                    'merged_name': matched_mitre['name'],
                    'misp_name': misp_name,
                    'mitre_name': matched_mitre['name'],
                    'mitre_id': self.extract_mitre_id(matched_mitre['object']),
                    'misp_uuid': misp_actor.get('uuid'),
                    'aliases': list(set(
                        matched_mitre['aliases'] + 
                        misp_synonyms + 
                        [misp_name]
                    )),
                    'description': matched_mitre['object'].get('description', ''),
                    'match_confidence': 0.9 if matched_mitre else 0.5,
                    'primary_source': 'MERGED',
                })
            else:
                # MISP-only actor
                matched.append({
                    'merged_name': misp_name,
                    'misp_name': misp_name,
                    'mitre_name': None,
                    'mitre_id': None,
                    'misp_uuid': misp_actor.get('uuid'),
                    'aliases': misp_synonyms + [misp_name],
                    'description': misp_actor.get('meta', {}).get('description', ''),
                    'match_confidence': 0.3,
                    'primary_source': 'MISP',
                })
        
        return matched
    
    def extract_mitre_id(self, group):
        """Extract G00xx from MITRE group"""
        for ref in group.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                return ref.get('external_id')
        return None
    
    def names_match(self, misp_name, mitre_name, mitre_aliases):
        """Check if names are similar enough"""
        # Clean names
        def clean(name):
            name = name.lower()
            name = re.sub(r'\b(apt|group|team|crew)\b', '', name)
            name = re.sub(r'[^\w]', '', name)
            return name.strip()
        
        clean_misp = clean(misp_name)
        clean_mitre = clean(mitre_name)
        
        # Direct match
        if clean_misp == clean_mitre:
            return True
        
        # Check aliases
        for alias in mitre_aliases:
            if clean_misp == clean(alias):
                return True
        
        # Check if misp contains mitre or vice versa
        if clean_misp in clean_mitre or clean_mitre in clean_misp:
            return True
        
        return False
    
    def create_actor_records(self, matched_actors):
        """Save matched actors to database"""
        from django.db import transaction
        from .models import ThreatActor
        
        with transaction.atomic():
            for actor_data in matched_actors:
                ThreatActor.objects.update_or_create(
                    name=actor_data['merged_name'],
                    defaults={
                        'aliases': actor_data['aliases'][:50],  # Limit to 50
                        'mitre_id': actor_data['mitre_id'],
                        'misp_uuid': actor_data['misp_uuid'],
                        'primary_source': actor_data['primary_source'],
                        'description': actor_data['description'][:1000] if actor_data['description'] else '',
                        'match_confidence': actor_data['match_confidence'],
                        'is_verified': actor_data['match_confidence'] > 0.8,
                    }
                )
    
    def fetch_otx_iocs_for_actor(self, actor_name):
        """Fetch OTX IoCs for a specific actor using your API key"""
        headers = {
            'X-OTX-API-KEY': OTX_API_KEY,
        }
        
        # Search for pulses mentioning the actor
        search_url = f"{OTX_BASE_URL}search/pulses"
        params = {
            'q': actor_name,
            'limit': 50,
        }
        
        try:
            response = requests.get(search_url, headers=headers, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return data.get('results', [])
        except Exception as e:
            print(f"Error fetching OTX for {actor_name}: {e}")
        
        return []