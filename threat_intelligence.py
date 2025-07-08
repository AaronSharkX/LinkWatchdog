
#!/usr/bin/env python3
"""
Threat Intelligence Module
Integrates with external APIs for enhanced threat detection
"""

import requests
import json
import hashlib
import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class ThreatIntelligenceResult:
    """Result from threat intelligence lookup"""
    source: str
    is_malicious: bool
    categories: List[str]
    confidence: float
    last_seen: Optional[str] = None
    details: Dict[str, Any] = None

class ThreatIntelligenceEngine:
    """Enhanced threat intelligence with multiple API sources"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.api_keys = config.get('api_keys', {})
        self.session = requests.Session()
        self.cache = {}
        self.rate_limits = {}
        
    def get_url_reputation(self, url: str) -> List[ThreatIntelligenceResult]:
        """Get reputation from multiple sources"""
        results = []
        
        # Check cache first
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        if url_hash in self.cache:
            return self.cache[url_hash]
        
        # VirusTotal API
        if 'virustotal' in self.api_keys:
            vt_result = self._check_virustotal(url)
            if vt_result:
                results.append(vt_result)
        
        # Google Safe Browsing API
        if 'google_safe_browsing' in self.api_keys:
            gsb_result = self._check_google_safe_browsing(url)
            if gsb_result:
                results.append(gsb_result)
        
        # URLVoid API
        if 'urlvoid' in self.api_keys:
            urlvoid_result = self._check_urlvoid(url)
            if urlvoid_result:
                results.append(urlvoid_result)
        
        # Hybrid Analysis API
        if 'hybrid_analysis' in self.api_keys:
            ha_result = self._check_hybrid_analysis(url)
            if ha_result:
                results.append(ha_result)
        
        # Cache results for 1 hour
        self.cache[url_hash] = results
        return results
    
    def _check_virustotal(self, url: str) -> Optional[ThreatIntelligenceResult]:
        """Check URL against VirusTotal API"""
        try:
            if not self._check_rate_limit('virustotal'):
                return None
                
            headers = {'x-apikey': self.api_keys['virustotal']}
            
            # Submit URL for analysis
            data = {'url': url}
            response = self.session.post(
                'https://www.virustotal.com/vtapi/v2/url/scan',
                data=data,
                headers=headers,
                timeout=10
            )
            
            if response.status_code != 200:
                return None
            
            scan_result = response.json()
            scan_id = scan_result.get('scan_id')
            
            if not scan_id:
                return None
            
            # Get analysis results
            time.sleep(2)  # Wait for analysis
            params = {'apikey': self.api_keys['virustotal'], 'resource': scan_id}
            response = self.session.get(
                'https://www.virustotal.com/vtapi/v2/url/report',
                params=params,
                timeout=10
            )
            
            if response.status_code != 200:
                return None
            
            report = response.json()
            positives = report.get('positives', 0)
            total = report.get('total', 0)
            
            is_malicious = positives > 0
            confidence = (positives / total) if total > 0 else 0.0
            
            categories = []
            if report.get('scans'):
                for engine, result in report['scans'].items():
                    if result.get('detected'):
                        categories.append(result.get('result', 'malware'))
            
            return ThreatIntelligenceResult(
                source='VirusTotal',
                is_malicious=is_malicious,
                categories=list(set(categories)),
                confidence=confidence,
                details={
                    'positives': positives,
                    'total': total,
                    'scan_date': report.get('scan_date')
                }
            )
            
        except Exception as e:
            logger.error(f"VirusTotal API error: {e}")
            return None
    
    def _check_google_safe_browsing(self, url: str) -> Optional[ThreatIntelligenceResult]:
        """Check URL against Google Safe Browsing API"""
        try:
            if not self._check_rate_limit('google_safe_browsing'):
                return None
                
            api_key = self.api_keys['google_safe_browsing']
            api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}'
            
            payload = {
                'client': {
                    'clientId': 'url-security-analyzer',
                    'clientVersion': '2.0'
                },
                'threatInfo': {
                    'threatTypes': [
                        'MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE',
                        'POTENTIALLY_HARMFUL_APPLICATION'
                    ],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': url}]
                }
            }
            
            response = self.session.post(api_url, json=payload, timeout=10)
            
            if response.status_code != 200:
                return None
            
            result = response.json()
            matches = result.get('matches', [])
            
            is_malicious = len(matches) > 0
            categories = [match.get('threatType', 'unknown') for match in matches]
            confidence = 1.0 if is_malicious else 0.0
            
            return ThreatIntelligenceResult(
                source='Google Safe Browsing',
                is_malicious=is_malicious,
                categories=categories,
                confidence=confidence,
                details={'matches': matches}
            )
            
        except Exception as e:
            logger.error(f"Google Safe Browsing API error: {e}")
            return None
    
    def _check_urlvoid(self, url: str) -> Optional[ThreatIntelligenceResult]:
        """Check URL against URLVoid API"""
        try:
            if not self._check_rate_limit('urlvoid'):
                return None
                
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            api_url = f'http://api.urlvoid.com/v1/pay-as-you-go/{self.api_keys["urlvoid"]}/host/{domain}/'
            
            response = self.session.get(api_url, timeout=10)
            
            if response.status_code != 200:
                return None
            
            # Parse XML response (URLVoid returns XML)
            import xml.etree.ElementTree as ET
            root = ET.fromstring(response.content)
            
            detections = root.find('.//detections')
            if detections is not None:
                count = int(detections.get('count', 0))
                is_malicious = count > 0
                confidence = min(count / 10.0, 1.0)  # Normalize to 0-1
                
                categories = []
                for detection in detections.findall('detection'):
                    engine = detection.find('engine')
                    if engine is not None:
                        categories.append(engine.text)
                
                return ThreatIntelligenceResult(
                    source='URLVoid',
                    is_malicious=is_malicious,
                    categories=categories,
                    confidence=confidence,
                    details={'detection_count': count}
                )
            
        except Exception as e:
            logger.error(f"URLVoid API error: {e}")
            return None
    
    def _check_hybrid_analysis(self, url: str) -> Optional[ThreatIntelligenceResult]:
        """Check URL against Hybrid Analysis API"""
        try:
            if not self._check_rate_limit('hybrid_analysis'):
                return None
                
            headers = {
                'api-key': self.api_keys['hybrid_analysis'],
                'user-agent': 'URL Security Analyzer 2.0'
            }
            
            # Submit URL for analysis
            data = {'url': url}
            response = self.session.post(
                'https://www.hybrid-analysis.com/api/v2/submit/url',
                data=data,
                headers=headers,
                timeout=10
            )
            
            if response.status_code != 200:
                return None
            
            result = response.json()
            job_id = result.get('job_id')
            
            if not job_id:
                return None
            
            # Get analysis results (simplified for demo)
            time.sleep(5)  # Wait for analysis
            response = self.session.get(
                f'https://www.hybrid-analysis.com/api/v2/report/{job_id}/summary',
                headers=headers,
                timeout=10
            )
            
            if response.status_code != 200:
                return None
            
            report = response.json()
            verdict = report.get('verdict', 'no specific threat')
            threat_score = report.get('threat_score', 0)
            
            is_malicious = threat_score > 50
            confidence = threat_score / 100.0
            categories = [verdict] if verdict != 'no specific threat' else []
            
            return ThreatIntelligenceResult(
                source='Hybrid Analysis',
                is_malicious=is_malicious,
                categories=categories,
                confidence=confidence,
                details={
                    'threat_score': threat_score,
                    'verdict': verdict
                }
            )
            
        except Exception as e:
            logger.error(f"Hybrid Analysis API error: {e}")
            return None
    
    def _check_rate_limit(self, service: str) -> bool:
        """Check if we're within rate limits for a service"""
        now = time.time()
        
        if service not in self.rate_limits:
            self.rate_limits[service] = {'count': 0, 'reset_time': now + 60}
            return True
        
        rate_limit = self.rate_limits[service]
        
        # Reset counter if minute has passed
        if now > rate_limit['reset_time']:
            rate_limit['count'] = 0
            rate_limit['reset_time'] = now + 60
        
        # Check limits (adjust based on API limits)
        limits = {
            'virustotal': 4,  # 4 requests per minute for free tier
            'google_safe_browsing': 100,
            'urlvoid': 1000,
            'hybrid_analysis': 100
        }
        
        if rate_limit['count'] >= limits.get(service, 10):
            return False
        
        rate_limit['count'] += 1
        return True
    
    def get_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Get comprehensive domain reputation"""
        reputation = {
            'domain': domain,
            'age': None,
            'registrar': None,
            'country': None,
            'risk_score': 0,
            'categories': [],
            'threat_sources': []
        }
        
        try:
            # WHOIS lookup
            import whois
            w = whois.whois(domain)
            if w:
                reputation['age'] = str(w.creation_date) if w.creation_date else None
                reputation['registrar'] = w.registrar
                
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
        
        return reputation
