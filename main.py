
#!/usr/bin/env python3
"""
Advanced URL Security Analyzer v2.0
A comprehensive tool for detecting phishing, malware, and suspicious URLs
with advanced link type detection, behavioral analysis, and security features.
"""

import re
import json
import csv
import math
import argparse
import logging
import requests
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set
from urllib.parse import urlparse, parse_qs, unquote
import tldextract
import base64
from dataclasses import dataclass, asdict
from flask import Flask, request, jsonify, render_template_string
import threading
import time
import hashlib
import socket
from collections import Counter
import mimetypes
import whois
from urllib.robotparser import RobotFileParser

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

@dataclass
class LinkClassification:
    """Classification of link types and purposes"""
    primary_type: str
    secondary_types: List[str]
    file_type: Optional[str] = None
    platform: Optional[str] = None
    content_category: Optional[str] = None
    safety_level: str = "UNKNOWN"
    
@dataclass
class AdvancedAnalysisResult:
    """Enhanced data class for comprehensive URL analysis results"""
    url: str
    status: str
    risk_score: int
    risk_level: str
    factors: List[str]
    emoji: str
    entropy_score: float = 0.0
    redirect_chain: List[str] = None
    analysis_time: str = ""
    link_classification: LinkClassification = None
    behavioral_indicators: Dict[str, Any] = None
    technical_details: Dict[str, Any] = None
    reputation_score: int = 0
    threat_indicators: List[str] = None
    
    def __post_init__(self):
        if self.redirect_chain is None:
            self.redirect_chain = []
        if self.behavioral_indicators is None:
            self.behavioral_indicators = {}
        if self.technical_details is None:
            self.technical_details = {}
        if self.threat_indicators is None:
            self.threat_indicators = []
        if not self.analysis_time:
            self.analysis_time = datetime.now().isoformat()

class AdvancedURLSecurityAnalyzer:
    """Enhanced URL Security Analyzer with comprehensive threat detection and link classification"""
    
    def __init__(self, config_path: Optional[str] = None, enable_network: bool = True):
        self.enable_network = enable_network
        self.config = self._load_config(config_path)
        self.session = requests.Session() if enable_network else None
        self.link_patterns = self._initialize_link_patterns()
        self.threat_intelligence = self._load_threat_intelligence()
        self.file_extensions = self._initialize_file_extensions()
        
        if self.session:
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            })
        
        logger.info("Advanced URL Security Analyzer v2.0 initialized")

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load enhanced configuration"""
        default_config = {
            "weights": {
                "ip_address": 35, "no_https": 25, "suspicious_words": 15, "long_url": 10,
                "suspicious_tld": 25, "url_shortener": 15, "encoded_content": 30,
                "homograph_attack": 40, "typosquatting": 35, "high_entropy": 20,
                "redirect_chain": 15, "malware_extension": 50, "suspicious_port": 30,
                "dynamic_dns": 25, "temporary_email": 20, "suspicious_path": 15,
                "credential_harvesting": 45, "fake_update": 40, "scam_keywords": 35,
                "suspicious_parameters": 20, "obfuscated_url": 30, "fake_ssl": 25,
                "suspicious_subdomain": 20, "malicious_tld": 30, "phishing_kit": 45,
                "brand_abuse": 35, "social_engineering": 30, "cryptocurrency_scam": 40,
                "tech_support_scam": 35, "romance_scam": 30, "investment_scam": 40,
                "fake_news": 25, "clickbait": 20, "adult_content": 15, "gambling": 20,
                "suspicious_download": 35, "app_impersonation": 40, "streaming_piracy": 30,
                "software_piracy": 35, "fake_antivirus": 45, "browser_hijacker": 40,
                "adware": 25, "spyware": 45, "trojan": 50, "ransomware": 50,
                "botnet": 45, "cryptominer": 35, "keylogger": 50, "rootkit": 50
            },
            "thresholds": {
                "critical": 70, "high": 50, "medium": 25, "low": 10
            },
            "whitelist": [
                "google.com", "microsoft.com", "apple.com", "amazon.com", "meta.com",
                "facebook.com", "twitter.com", "x.com", "linkedin.com", "instagram.com",
                "youtube.com", "netflix.com", "github.com", "gitlab.com", "stackoverflow.com",
                "replit.com", "codepen.io", "npmjs.com", "pypi.org", "docker.com",
                "steam.com", "steamcommunity.com", "epicgames.com", "paypal.com",
                "stripe.com", "visa.com", "mastercard.com", "reddit.com", "wikipedia.org",
                "discord.com", "slack.com", "zoom.us", "whatsapp.com", "telegram.org",
                "signal.org", "dropbox.com", "drive.google.com", "onedrive.live.com",
                "icloud.com", "box.com", "mega.nz", "mediafire.com", "4shared.com",
                "sendspace.com", "zippyshare.com", "rapidgator.net", "uploaded.net"
            ],
            "suspicious_words": [
                "login", "verify", "secure", "update", "confirm", "account", "suspend",
                "limited", "expired", "urgent", "immediately", "click", "winner",
                "congratulations", "free", "prize", "gift", "bonus", "reward", "claim",
                "activate", "validate", "unlock", "restore", "recover", "alert", "warning",
                "security", "breach", "violation", "suspended", "blocked", "frozen",
                "cancelled", "refund", "cashback", "bitcoin", "crypto", "investment",
                "profit", "earnings", "money", "cash", "rich", "wealthy", "millionaire",
                "download", "install", "setup", "update", "patch", "fix", "repair",
                "clean", "optimize", "speed", "boost", "enhance", "improve", "protect",
                "antivirus", "malware", "virus", "infected", "scan", "remove", "delete",
                "adult", "xxx", "porn", "sex", "dating", "singles", "hookup", "affair",
                "casino", "poker", "betting", "lottery", "jackpot", "slots", "roulette",
                "pharmacy", "pills", "drugs", "medication", "prescription", "doctor",
                "weight", "diet", "fitness", "muscle", "supplement", "viagra", "cialis"
            ],
            "suspicious_tlds": [
                "tk", "ml", "ga", "cf", "pw", "top", "click", "download", "stream",
                "loan", "men", "date", "racing", "review", "science", "work", "party",
                "trade", "accountant", "cricket", "faith", "win", "bid", "country"
            ],
            "url_shorteners": [
                "bit.ly", "tinyurl.com", "t.co", "goo.gl", "short.link", "ow.ly",
                "buff.ly", "is.gd", "tiny.cc", "lnkd.in", "cutt.ly", "rebrand.ly",
                "clck.ru", "v.gd", "trib.al", "linktr.ee", "bio.link", "soo.gd"
            ],
            "malware_extensions": [
                "exe", "bat", "cmd", "com", "scr", "pif", "vbs", "js", "jar",
                "msi", "deb", "rpm", "dmg", "pkg", "app", "apk", "ipa", "xap",
                "cab", "msp", "msu", "hta", "cpl", "dll", "sys", "drv", "ocx"
            ],
            "suspicious_ports": [
                1080, 1337, 1433, 1521, 2049, 3389, 4444, 5432, 5900, 6000,
                6667, 6697, 8080, 8888, 9999, 31337, 12345, 54321, 65535
            ],
            "dynamic_dns_providers": [
                "dyndns.org", "no-ip.com", "ddns.net", "freedns.afraid.org",
                "duckdns.org", "changeip.com", "dnsdynamic.org", "dynu.com"
            ],
            "temporary_email_providers": [
                "10minutemail.com", "guerrillamail.com", "mailinator.com",
                "tempmail.org", "yopmail.com", "maildrop.cc", "throwaway.email"
            ],
            "cryptocurrency_keywords": [
                "bitcoin", "btc", "ethereum", "eth", "crypto", "mining", "wallet",
                "blockchain", "ico", "defi", "nft", "altcoin", "dogecoin", "litecoin"
            ],
            "phishing_indicators": [
                "account-suspended", "verify-account", "security-alert", "login-required",
                "update-payment", "confirm-identity", "urgent-action", "immediate-response"
            ],
            "max_redirects": 5,
            "request_timeout": 15,
            "enable_whois": True,
            "enable_reputation_check": True,
            "enable_content_analysis": True
        }
        
        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
                    logger.info(f"Loaded configuration from {config_path}")
            except Exception as e:
                logger.warning(f"Failed to load config: {e}. Using defaults.")
        
        return default_config

    def _initialize_link_patterns(self) -> Dict[str, List[str]]:
        """Initialize patterns for link type detection"""
        return {
            "download_links": [
                r'/download/', r'/dl/', r'/get/', r'/files/', r'/software/',
                r'\.zip$', r'\.rar$', r'\.7z$', r'\.tar\.gz$', r'\.exe$',
                r'\.dmg$', r'\.pkg$', r'\.deb$', r'\.rpm$', r'\.msi$',
                r'\.apk$', r'\.ipa$', r'\.xap$', r'\.cab$', r'\.iso$'
            ],
            "app_links": [
                r'play\.google\.com/store/apps',
                r'apps\.apple\.com/',
                r'microsoft\.com/.*store/',
                r'chrome\.google\.com/webstore/',
                r'addons\.mozilla\.org/',
                r'marketplace\.visualstudio\.com/',
                r'f-droid\.org/packages/',
                r'github\.com/.*/releases/',
                r'sourceforge\.net/projects/'
            ],
            "streaming_links": [
                r'youtube\.com/watch', r'youtu\.be/', r'vimeo\.com/',
                r'twitch\.tv/', r'netflix\.com/', r'hulu\.com/',
                r'primevideo\.com/', r'disney\.com/', r'hbo\.com/',
                r'spotify\.com/', r'soundcloud\.com/', r'pandora\.com/',
                r'stream', r'watch', r'live', r'video', r'movie', r'tv'
            ],
            "social_media": [
                r'facebook\.com/', r'twitter\.com/', r'instagram\.com/',
                r'linkedin\.com/', r'snapchat\.com/', r'tiktok\.com/',
                r'pinterest\.com/', r'reddit\.com/', r'discord\.com/',
                r'telegram\.org/', r'whatsapp\.com/', r'signal\.org/'
            ],
            "financial_services": [
                r'paypal\.com/', r'stripe\.com/', r'square\.com/',
                r'venmo\.com/', r'cashapp\.com/', r'zelle\.com/',
                r'bank', r'credit', r'loan', r'mortgage', r'insurance',
                r'investment', r'trading', r'crypto', r'bitcoin'
            ],
            "cloud_storage": [
                r'drive\.google\.com/', r'dropbox\.com/', r'onedrive\.live\.com/',
                r'icloud\.com/', r'box\.com/', r'mega\.nz/',
                r'mediafire\.com/', r'4shared\.com/', r'sendspace\.com/'
            ],
            "gaming_platforms": [
                r'steam\.com/', r'epicgames\.com/', r'origin\.com/',
                r'battle\.net/', r'ubisoft\.com/', r'ea\.com/',
                r'playstation\.com/', r'xbox\.com/', r'nintendo\.com/',
                r'roblox\.com/', r'minecraft\.net/', r'fortnite\.com/'
            ],
            "educational": [
                r'coursera\.org/', r'edx\.org/', r'udemy\.com/',
                r'khanacademy\.org/', r'mit\.edu/', r'stanford\.edu/',
                r'harvard\.edu/', r'wikipedia\.org/', r'stackoverflow\.com/'
            ],
            "news_media": [
                r'cnn\.com/', r'bbc\.com/', r'reuters\.com/',
                r'ap\.org/', r'nytimes\.com/', r'washingtonpost\.com/',
                r'theguardian\.com/', r'wsj\.com/', r'bloomberg\.com/'
            ],
            "shopping": [
                r'amazon\.com/', r'ebay\.com/', r'alibaba\.com/',
                r'etsy\.com/', r'shopify\.com/', r'walmart\.com/',
                r'target\.com/', r'bestbuy\.com/', r'store', r'shop'
            ],
            "adult_content": [
                r'xxx', r'porn', r'sex', r'adult', r'nsfw', r'erotic',
                r'cam', r'webcam', r'live.*chat', r'dating.*hookup'
            ],
            "gambling": [
                r'casino', r'poker', r'betting', r'lottery', r'jackpot',
                r'slots', r'roulette', r'blackjack', r'baccarat', r'dice'
            ],
            "phishing_targets": [
                r'paypal.*login', r'amazon.*signin', r'google.*accounts',
                r'microsoft.*login', r'apple.*id', r'facebook.*login',
                r'twitter.*login', r'instagram.*login', r'linkedin.*login'
            ]
        }

    def _initialize_file_extensions(self) -> Dict[str, str]:
        """Initialize file extension mapping"""
        return {
            # Executables
            'exe': 'Windows Executable', 'msi': 'Windows Installer', 'bat': 'Batch File',
            'cmd': 'Command File', 'com': 'DOS Command', 'scr': 'Screen Saver',
            'pif': 'Program Information File', 'vbs': 'Visual Basic Script',
            'js': 'JavaScript File', 'jar': 'Java Archive', 'app': 'macOS Application',
            'dmg': 'macOS Disk Image', 'pkg': 'macOS Package', 'deb': 'Debian Package',
            'rpm': 'Red Hat Package', 'apk': 'Android Package', 'ipa': 'iOS App',
            'xap': 'Windows Phone App', 'cab': 'Cabinet File', 'msp': 'Windows Patch',
            'msu': 'Windows Update', 'hta': 'HTML Application', 'cpl': 'Control Panel',
            'dll': 'Dynamic Link Library', 'sys': 'System File', 'drv': 'Driver File',
            'ocx': 'ActiveX Control',
            
            # Archives
            'zip': 'ZIP Archive', 'rar': 'RAR Archive', '7z': '7-Zip Archive',
            'tar': 'TAR Archive', 'gz': 'GZIP Archive', 'bz2': 'BZIP2 Archive',
            'xz': 'XZ Archive', 'iso': 'ISO Image', 'img': 'Disk Image',
            
            # Documents
            'pdf': 'PDF Document', 'doc': 'Word Document', 'docx': 'Word Document',
            'xls': 'Excel Spreadsheet', 'xlsx': 'Excel Spreadsheet',
            'ppt': 'PowerPoint Presentation', 'pptx': 'PowerPoint Presentation',
            'rtf': 'Rich Text Format', 'txt': 'Text File', 'csv': 'CSV File',
            
            # Media
            'mp3': 'MP3 Audio', 'wav': 'WAV Audio', 'flac': 'FLAC Audio',
            'mp4': 'MP4 Video', 'avi': 'AVI Video', 'mkv': 'MKV Video',
            'mov': 'QuickTime Video', 'wmv': 'Windows Media Video',
            'jpg': 'JPEG Image', 'jpeg': 'JPEG Image', 'png': 'PNG Image',
            'gif': 'GIF Image', 'bmp': 'Bitmap Image', 'svg': 'SVG Image',
            
            # Programming
            'py': 'Python Script', 'java': 'Java Source', 'cpp': 'C++ Source',
            'c': 'C Source', 'cs': 'C# Source', 'php': 'PHP Script',
            'html': 'HTML File', 'css': 'CSS File', 'json': 'JSON File',
            'xml': 'XML File', 'sql': 'SQL Script'
        }

    def _load_threat_intelligence(self) -> Dict[str, Set[str]]:
        """Load threat intelligence data"""
        return {
            "known_malware_domains": set(),
            "known_phishing_domains": set(),
            "known_scam_domains": set(),
            "suspicious_ips": set(),
            "malicious_file_hashes": set(),
            "blacklisted_urls": set()
        }

    def classify_link_type(self, url: str, parsed_url: urlparse) -> LinkClassification:
        """Classify the type and purpose of a link"""
        url_lower = url.lower()
        path_lower = parsed_url.path.lower()
        domain_lower = parsed_url.netloc.lower()
        
        primary_type = "UNKNOWN"
        secondary_types = []
        file_type = None
        platform = None
        content_category = None
        safety_level = "UNKNOWN"
        
        # Check for file extensions
        file_extension = None
        if '.' in path_lower:
            potential_ext = path_lower.split('.')[-1].split('?')[0].split('#')[0]
            if potential_ext in self.file_extensions:
                file_extension = potential_ext
                file_type = self.file_extensions[potential_ext]
        
        # Classify based on patterns
        for category, patterns in self.link_patterns.items():
            for pattern in patterns:
                if re.search(pattern, url_lower):
                    if primary_type == "UNKNOWN":
                        primary_type = category.upper().replace('_', ' ')
                    else:
                        secondary_types.append(category.upper().replace('_', ' '))
        
        # Determine platform
        if 'google.com' in domain_lower:
            platform = "Google"
        elif 'microsoft.com' in domain_lower or 'live.com' in domain_lower:
            platform = "Microsoft"
        elif 'apple.com' in domain_lower or 'icloud.com' in domain_lower:
            platform = "Apple"
        elif 'amazon.com' in domain_lower:
            platform = "Amazon"
        elif 'facebook.com' in domain_lower or 'meta.com' in domain_lower:
            platform = "Meta/Facebook"
        elif 'github.com' in domain_lower:
            platform = "GitHub"
        elif 'steam.com' in domain_lower:
            platform = "Steam"
        elif 'discord.com' in domain_lower:
            platform = "Discord"
        elif 'youtube.com' in domain_lower or 'youtu.be' in domain_lower:
            platform = "YouTube"
        elif 'netflix.com' in domain_lower:
            platform = "Netflix"
        elif 'spotify.com' in domain_lower:
            platform = "Spotify"
        elif 'twitter.com' in domain_lower or 'x.com' in domain_lower:
            platform = "Twitter/X"
        elif 'instagram.com' in domain_lower:
            platform = "Instagram"
        elif 'linkedin.com' in domain_lower:
            platform = "LinkedIn"
        elif 'tiktok.com' in domain_lower:
            platform = "TikTok"
        elif 'reddit.com' in domain_lower:
            platform = "Reddit"
        elif 'paypal.com' in domain_lower:
            platform = "PayPal"
        elif 'dropbox.com' in domain_lower:
            platform = "Dropbox"
        elif 'mediafire.com' in domain_lower:
            platform = "MediaFire"
        elif 'mega.nz' in domain_lower:
            platform = "MEGA"
        elif 'sourceforge.net' in domain_lower:
            platform = "SourceForge"
        elif 'replit.com' in domain_lower:
            platform = "Replit"
        
        # Determine content category
        if any(word in url_lower for word in ['download', 'software', 'app', 'program']):
            content_category = "SOFTWARE"
        elif any(word in url_lower for word in ['video', 'movie', 'stream', 'watch']):
            content_category = "MEDIA"
        elif any(word in url_lower for word in ['game', 'gaming', 'play']):
            content_category = "GAMING"
        elif any(word in url_lower for word in ['shop', 'store', 'buy', 'product']):
            content_category = "SHOPPING"
        elif any(word in url_lower for word in ['news', 'article', 'blog']):
            content_category = "NEWS"
        elif any(word in url_lower for word in ['education', 'learn', 'course', 'tutorial']):
            content_category = "EDUCATION"
        elif any(word in url_lower for word in ['social', 'chat', 'message', 'post']):
            content_category = "SOCIAL"
        elif any(word in url_lower for word in ['finance', 'bank', 'payment', 'money']):
            content_category = "FINANCIAL"
        elif any(word in url_lower for word in ['health', 'medical', 'doctor', 'pharmacy']):
            content_category = "HEALTH"
        elif any(word in url_lower for word in ['work', 'job', 'career', 'employment']):
            content_category = "EMPLOYMENT"
        elif any(word in url_lower for word in ['travel', 'hotel', 'flight', 'vacation']):
            content_category = "TRAVEL"
        elif any(word in url_lower for word in ['food', 'restaurant', 'recipe', 'cooking']):
            content_category = "FOOD"
        elif any(word in url_lower for word in ['sports', 'fitness', 'exercise', 'gym']):
            content_category = "SPORTS"
        elif any(word in url_lower for word in ['tech', 'technology', 'computer', 'software']):
            content_category = "TECHNOLOGY"
        elif any(word in url_lower for word in ['art', 'music', 'creative', 'design']):
            content_category = "ARTS"
        elif any(word in url_lower for word in ['adult', 'xxx', 'porn', 'sex']):
            content_category = "ADULT"
        elif any(word in url_lower for word in ['casino', 'poker', 'betting', 'gambling']):
            content_category = "GAMBLING"
        
        # Determine safety level
        if domain_lower in [d.lower() for d in self.config['whitelist']]:
            safety_level = "SAFE"
        elif any(word in url_lower for word in self.config['suspicious_words']):
            safety_level = "SUSPICIOUS"
        elif any(word in url_lower for word in ['malware', 'virus', 'trojan', 'hack']):
            safety_level = "DANGEROUS"
        elif file_extension in self.config['malware_extensions']:
            safety_level = "POTENTIALLY_DANGEROUS"
        elif content_category in ["ADULT", "GAMBLING"]:
            safety_level = "RESTRICTED"
        else:
            safety_level = "UNKNOWN"
        
        return LinkClassification(
            primary_type=primary_type,
            secondary_types=secondary_types,
            file_type=file_type,
            platform=platform,
            content_category=content_category,
            safety_level=safety_level
        )

    def analyze_behavioral_indicators(self, url: str, parsed_url: urlparse) -> Dict[str, Any]:
        """Analyze behavioral indicators and suspicious patterns"""
        indicators = {
            "suspicious_parameters": [],
            "obfuscation_detected": False,
            "credential_harvesting": False,
            "social_engineering": False,
            "urgency_indicators": False,
            "brand_impersonation": False,
            "technical_deception": False,
            "financial_lure": False,
            "fake_security_warnings": False,
            "romance_scam_indicators": False,
            "tech_support_scam": False,
            "cryptocurrency_scam": False,
            "investment_scam": False,
            "fake_software": False,
            "survey_scam": False,
            "prize_scam": False,
            "charity_scam": False,
            "employment_scam": False,
            "academic_scam": False,
            "travel_scam": False,
            "health_scam": False,
            "government_impersonation": False,
            "shipping_scam": False,
            "tax_scam": False,
            "insurance_scam": False,
            "subscription_trap": False,
            "fake_reviews": False,
            "clickbait": False,
            "misleading_content": False,
            "aggressive_advertising": False,
            "data_harvesting": False,
            "privacy_violation": False,
            "malicious_redirect": False,
            "drive_by_download": False,
            "browser_exploitation": False,
            "plugin_exploitation": False,
            "zero_day_exploit": False,
            "watering_hole_attack": False,
            "typosquatting_attack": False,
            "homograph_attack": False,
            "subdomain_takeover": False,
            "dns_hijacking": False,
            "bgp_hijacking": False,
            "ssl_stripping": False,
            "certificate_pinning_bypass": False,
            "content_injection": False,
            "iframe_injection": False,
            "javascript_injection": False,
            "sql_injection": False,
            "xss_attack": False,
            "csrf_attack": False,
            "session_hijacking": False,
            "man_in_the_middle": False,
            "dns_spoofing": False,
            "arp_spoofing": False,
            "evil_twin": False,
            "rogue_access_point": False,
            "captive_portal_attack": False,
            "bluetooth_attack": False,
            "nfc_attack": False,
            "rfid_attack": False,
            "side_channel_attack": False,
            "timing_attack": False,
            "power_analysis": False,
            "electromagnetic_attack": False,
            "acoustic_attack": False,
            "cold_boot_attack": False,
            "rubber_hose_attack": False,
            "social_media_manipulation": False,
            "fake_news_propagation": False,
            "disinformation_campaign": False,
            "propaganda_distribution": False,
            "hate_speech_promotion": False,
            "extremist_content": False,
            "terrorist_recruitment": False,
            "cult_recruitment": False,
            "human_trafficking": False,
            "child_exploitation": False,
            "drug_trafficking": False,
            "weapon_trafficking": False,
            "money_laundering": False,
            "tax_evasion": False,
            "fraud_scheme": False,
            "ponzi_scheme": False,
            "pyramid_scheme": False,
            "advance_fee_fraud": False,
            "lottery_scam": False,
            "inheritance_scam": False,
            "dating_scam": False,
            "pet_scam": False,
            "rental_scam": False,
            "auction_scam": False,
            "fake_charity": False,
            "disaster_relief_scam": False,
            "medical_scam": False,
            "diet_scam": False,
            "weight_loss_scam": False,
            "anti_aging_scam": False,
            "miracle_cure_scam": False,
            "fake_medication": False,
            "counterfeit_goods": False,
            "intellectual_property_theft": False,
            "copyright_infringement": False,
            "trademark_violation": False,
            "patent_infringement": False,
            "trade_secret_theft": False,
            "industrial_espionage": False,
            "corporate_espionage": False,
            "government_espionage": False,
            "military_espionage": False,
            "cyber_espionage": False,
            "economic_espionage": False,
            "political_espionage": False,
            "academic_espionage": False,
            "research_theft": False,
            "data_breach": False,
            "privacy_breach": False,
            "identity_theft": False,
            "financial_fraud": False,
            "credit_card_fraud": False,
            "bank_fraud": False,
            "wire_fraud": False,
            "check_fraud": False,
            "mortgage_fraud": False,
            "insurance_fraud": False,
            "healthcare_fraud": False,
            "tax_fraud": False,
            "welfare_fraud": False,
            "voter_fraud": False,
            "election_fraud": False,
            "campaign_finance_violation": False,
            "bribery": False,
            "corruption": False,
            "extortion": False,
            "blackmail": False,
            "kidnapping": False,
            "ransom": False,
            "hostage_taking": False,
            "terrorism": False,
            "cyber_terrorism": False,
            "bio_terrorism": False,
            "chemical_terrorism": False,
            "nuclear_terrorism": False,
            "radiological_terrorism": False,
            "environmental_terrorism": False,
            "agricultural_terrorism": False,
            "food_terrorism": False,
            "water_terrorism": False,
            "cyber_warfare": False,
            "information_warfare": False,
            "psychological_warfare": False,
            "electronic_warfare": False,
            "biological_warfare": False,
            "chemical_warfare": False,
            "nuclear_warfare": False,
            "radiological_warfare": False,
            "space_warfare": False,
            "submarine_warfare": False,
            "aerial_warfare": False,
            "ground_warfare": False,
            "naval_warfare": False,
            "guerrilla_warfare": False,
            "asymmetric_warfare": False,
            "hybrid_warfare": False,
            "proxy_warfare": False,
            "irregular_warfare": False,
            "unconventional_warfare": False,
            "special_operations": False,
            "covert_operations": False,
            "black_operations": False,
            "psychological_operations": False,
            "information_operations": False,
            "influence_operations": False,
            "deception_operations": False,
            "disinformation_operations": False,
            "propaganda_operations": False,
            "subversion_operations": False,
            "sabotage_operations": False,
            "assassination_operations": False,
            "kidnapping_operations": False,
            "hostage_operations": False,
            "ransom_operations": False,
            "extortion_operations": False,
            "blackmail_operations": False,
            "bribery_operations": False,
            "corruption_operations": False
        }
        
        url_lower = url.lower()
        query_params = parse_qs(parsed_url.query)
        
        # Check for suspicious parameters
        suspicious_params = ['redirect', 'next', 'return', 'callback', 'continue', 'goto', 'url', 'link', 'src', 'ref']
        for param in query_params:
            if param.lower() in suspicious_params:
                indicators["suspicious_parameters"].append(param)
        
        # Check for obfuscation
        if re.search(r'[%][0-9a-fA-F]{2}', url) or 'xn--' in url:
            indicators["obfuscation_detected"] = True
        
        # Check for credential harvesting patterns
        if any(word in url_lower for word in ['login', 'signin', 'password', 'username', 'email', 'account']):
            indicators["credential_harvesting"] = True
        
        # Check for social engineering
        if any(word in url_lower for word in ['urgent', 'immediate', 'expire', 'suspend', 'verify', 'confirm']):
            indicators["social_engineering"] = True
        
        # Check for urgency indicators
        if any(word in url_lower for word in ['urgent', 'immediate', 'expire', 'limited', 'deadline', 'act now']):
            indicators["urgency_indicators"] = True
        
        # Check for brand impersonation
        popular_brands = ['google', 'microsoft', 'apple', 'amazon', 'facebook', 'paypal', 'netflix', 'spotify']
        for brand in popular_brands:
            if brand in url_lower and not parsed_url.netloc.endswith(f'{brand}.com'):
                indicators["brand_impersonation"] = True
                break
        
        # Check for technical deception
        if any(word in url_lower for word in ['secure', 'ssl', 'https', 'encrypted', 'protected', 'safe']):
            indicators["technical_deception"] = True
        
        # Check for financial lures
        if any(word in url_lower for word in ['money', 'cash', 'profit', 'earn', 'rich', 'wealthy', 'million']):
            indicators["financial_lure"] = True
        
        # Check for fake security warnings
        if any(word in url_lower for word in ['virus', 'malware', 'infected', 'security', 'warning', 'alert']):
            indicators["fake_security_warnings"] = True
        
        # Check for romance scam indicators
        if any(word in url_lower for word in ['dating', 'love', 'romance', 'heart', 'soul', 'marriage']):
            indicators["romance_scam_indicators"] = True
        
        # Check for tech support scam
        if any(word in url_lower for word in ['support', 'help', 'fix', 'repair', 'clean', 'optimize']):
            indicators["tech_support_scam"] = True
        
        # Check for cryptocurrency scam
        if any(word in url_lower for word in self.config['cryptocurrency_keywords']):
            indicators["cryptocurrency_scam"] = True
        
        # Check for investment scam
        if any(word in url_lower for word in ['investment', 'trading', 'forex', 'stock', 'profit', 'returns']):
            indicators["investment_scam"] = True
        
        # Check for fake software
        if any(word in url_lower for word in ['crack', 'keygen', 'patch', 'serial', 'activation']):
            indicators["fake_software"] = True
        
        # Check for survey scam
        if any(word in url_lower for word in ['survey', 'questionnaire', 'feedback', 'opinion', 'review']):
            indicators["survey_scam"] = True
        
        # Check for prize scam
        if any(word in url_lower for word in ['prize', 'winner', 'congratulations', 'lottery', 'jackpot']):
            indicators["prize_scam"] = True
        
        return indicators

    def get_technical_details(self, url: str, parsed_url: urlparse) -> Dict[str, Any]:
        """Extract technical details about the URL"""
        details = {
            "domain_age": None,
            "ssl_certificate": None,
            "ip_address": None,
            "geolocation": None,
            "server_info": None,
            "response_headers": None,
            "content_type": None,
            "content_length": None,
            "robots_txt": None,
            "sitemap": None,
            "whois_info": None,
            "dns_records": None,
            "port_scan": None,
            "vulnerability_scan": None,
            "reputation_sources": []
        }
        
        if not self.enable_network or not self.session:
            return details
        
        try:
            # Get IP address
            ip_address = socket.gethostbyname(parsed_url.netloc)
            details["ip_address"] = ip_address
            
            # Make HEAD request for headers
            try:
                response = self.session.head(url, timeout=self.config["request_timeout"], allow_redirects=False)
                details["response_headers"] = dict(response.headers)
                details["content_type"] = response.headers.get('content-type', '')
                details["content_length"] = response.headers.get('content-length', '')
                details["server_info"] = response.headers.get('server', '')
            except:
                pass
            
            # Check robots.txt
            try:
                robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
                robots_response = self.session.get(robots_url, timeout=5)
                if robots_response.status_code == 200:
                    details["robots_txt"] = robots_response.text[:1000]  # Limit size
            except:
                pass
            
            # WHOIS information (if enabled)
            if self.config.get("enable_whois", False):
                try:
                    whois_info = whois.whois(parsed_url.netloc)
                    details["whois_info"] = {
                        "creation_date": str(whois_info.creation_date) if whois_info.creation_date else None,
                        "expiration_date": str(whois_info.expiration_date) if whois_info.expiration_date else None,
                        "registrar": whois_info.registrar,
                        "name_servers": whois_info.name_servers
                    }
                except:
                    pass
            
        except Exception as e:
            logger.debug(f"Error getting technical details for {url}: {e}")
        
        return details

    def calculate_reputation_score(self, url: str, parsed_url: urlparse) -> int:
        """Calculate reputation score based on various factors"""
        score = 50  # Neutral starting point
        
        # Domain age bonus
        if self.config.get("enable_whois", False):
            try:
                whois_info = whois.whois(parsed_url.netloc)
                if whois_info.creation_date:
                    # Older domains get higher scores
                    from datetime import datetime
                    age_days = (datetime.now() - whois_info.creation_date).days
                    if age_days > 365:
                        score += min(20, age_days // 365)
            except:
                pass
        
        # SSL certificate bonus
        if url.startswith('https://'):
            score += 10
        
        # Whitelist bonus
        if parsed_url.netloc.lower() in [d.lower() for d in self.config['whitelist']]:
            score += 30
        
        # Suspicious TLD penalty
        domain_parts = parsed_url.netloc.split('.')
        if len(domain_parts) > 1 and domain_parts[-1].lower() in self.config['suspicious_tlds']:
            score -= 20
        
        # URL shortener penalty
        if any(shortener in parsed_url.netloc.lower() for shortener in self.config['url_shorteners']):
            score -= 10
        
        # Suspicious words penalty
        url_lower = url.lower()
        suspicious_count = sum(1 for word in self.config['suspicious_words'] if word in url_lower)
        score -= suspicious_count * 5
        
        # Ensure score is within bounds
        return max(0, min(100, score))

    def analyze_url(self, url: str) -> AdvancedAnalysisResult:
        """Perform comprehensive analysis of a single URL"""
        logger.debug(f"Analyzing URL: {url}")
        
        parsed_url = urlparse(url)
        features = self.extract_features(url)
        weights = self.config["weights"]
        
        # Classify link type
        link_classification = self.classify_link_type(url, parsed_url)
        
        # Analyze behavioral indicators
        behavioral_indicators = self.analyze_behavioral_indicators(url, parsed_url)
        
        # Get technical details
        technical_details = self.get_technical_details(url, parsed_url)
        
        # Calculate reputation score
        reputation_score = self.calculate_reputation_score(url, parsed_url)
        
        # Check whitelist first
        if features['domain'] in self.config["whitelist"]:
            return AdvancedAnalysisResult(
                url=url,
                status='SAFE',
                risk_score=0,
                risk_level='WHITELISTED',
                factors=['Trusted domain'],
                emoji='✅',
                entropy_score=features['total_entropy'],
                redirect_chain=features['redirect_chain'],
                link_classification=link_classification,
                behavioral_indicators=behavioral_indicators,
                technical_details=technical_details,
                reputation_score=reputation_score,
                threat_indicators=[]
            )
        
        # Calculate comprehensive risk score
        risk_score = 0
        risk_factors = []
        threat_indicators = []
        
        # Basic security checks
        if features['has_ip']:
            risk_score += weights["ip_address"]
            risk_factors.append("Uses IP address instead of domain")
            threat_indicators.append("DIRECT_IP_ACCESS")
        
        if not features['has_https']:
            risk_score += weights["no_https"]
            risk_factors.append("No HTTPS encryption")
            threat_indicators.append("UNENCRYPTED_CONNECTION")
        
        if features['suspicious_words'] > 0:
            points = features['suspicious_words'] * weights["suspicious_words"]
            risk_score += points
            risk_factors.append(f"{features['suspicious_words']} suspicious keywords")
            threat_indicators.append("SUSPICIOUS_KEYWORDS")
        
        # File and download analysis
        if link_classification.file_type:
            file_ext = url.split('.')[-1].lower().split('?')[0].split('#')[0]
            if file_ext in self.config['malware_extensions']:
                risk_score += weights["malware_extension"]
                risk_factors.append(f"Potentially dangerous file type: {link_classification.file_type}")
                threat_indicators.append("MALWARE_EXTENSION")
        
        # Behavioral analysis scoring
        if behavioral_indicators['credential_harvesting']:
            risk_score += weights["credential_harvesting"]
            risk_factors.append("Credential harvesting indicators")
            threat_indicators.append("CREDENTIAL_HARVESTING")
        
        if behavioral_indicators['social_engineering']:
            risk_score += weights["social_engineering"]
            risk_factors.append("Social engineering tactics detected")
            threat_indicators.append("SOCIAL_ENGINEERING")
        
        if behavioral_indicators['brand_impersonation']:
            risk_score += weights["brand_abuse"]
            risk_factors.append("Brand impersonation detected")
            threat_indicators.append("BRAND_IMPERSONATION")
        
        if behavioral_indicators['cryptocurrency_scam']:
            risk_score += weights["cryptocurrency_scam"]
            risk_factors.append("Cryptocurrency scam indicators")
            threat_indicators.append("CRYPTOCURRENCY_SCAM")
        
        if behavioral_indicators['investment_scam']:
            risk_score += weights["investment_scam"]
            risk_factors.append("Investment scam indicators")
            threat_indicators.append("INVESTMENT_SCAM")
        
        if behavioral_indicators['romance_scam_indicators']:
            risk_score += weights["romance_scam"]
            risk_factors.append("Romance scam indicators")
            threat_indicators.append("ROMANCE_SCAM")
        
        if behavioral_indicators['tech_support_scam']:
            risk_score += weights["tech_support_scam"]
            risk_factors.append("Tech support scam indicators")
            threat_indicators.append("TECH_SUPPORT_SCAM")
        
        if behavioral_indicators['fake_security_warnings']:
            risk_score += weights["fake_antivirus"]
            risk_factors.append("Fake security warnings")
            threat_indicators.append("FAKE_SECURITY_WARNINGS")
        
        if behavioral_indicators['fake_software']:
            risk_score += weights["software_piracy"]
            risk_factors.append("Fake/pirated software indicators")
            threat_indicators.append("FAKE_SOFTWARE")
        
        # Advanced threat detection
        if features['has_suspicious_tld']:
            risk_score += weights["suspicious_tld"]
            risk_factors.append("Suspicious top-level domain")
            threat_indicators.append("SUSPICIOUS_TLD")
        
        if features['has_shortener']:
            risk_score += weights["url_shortener"]
            risk_factors.append("URL shortener detected")
            threat_indicators.append("URL_SHORTENER")
        
        if features['encoded_content']:
            risk_score += weights["encoded_content"]
            risk_factors.append("Suspicious encoded content")
            threat_indicators.append("ENCODED_CONTENT")
        
        if features['homograph_attack']:
            risk_score += weights["homograph_attack"]
            risk_factors.append("Homograph attack detected")
            threat_indicators.append("HOMOGRAPH_ATTACK")
        
        if features['typosquatting']:
            risk_score += weights["typosquatting"]
            risk_factors.append(f"Typosquatting: mimics {', '.join(features['typosquatting'])}")
            threat_indicators.append("TYPOSQUATTING")
        
        # Entropy analysis
        if features['total_entropy'] > 4.5:
            risk_score += weights["high_entropy"]
            risk_factors.append(f"High entropy ({features['total_entropy']:.2f}) - possibly random")
            threat_indicators.append("HIGH_ENTROPY")
        
        # Redirect chain analysis
        if features['redirect_count'] > 2:
            risk_score += weights["redirect_chain"]
            risk_factors.append(f"Multiple redirects ({features['redirect_count']})")
            threat_indicators.append("MULTIPLE_REDIRECTS")
        
        # URL length analysis
        if features['length'] > 200:
            risk_score += weights["long_url"] + 10
            risk_factors.append("Extremely long URL")
            threat_indicators.append("EXTREMELY_LONG_URL")
        elif features['length'] > 100:
            risk_score += weights["long_url"]
            risk_factors.append("Very long URL")
            threat_indicators.append("LONG_URL")
        
        # Suspicious parameters
        if behavioral_indicators['suspicious_parameters']:
            risk_score += weights["suspicious_parameters"]
            risk_factors.append(f"Suspicious parameters: {', '.join(behavioral_indicators['suspicious_parameters'])}")
            threat_indicators.append("SUSPICIOUS_PARAMETERS")
        
        # Content category risks
        if link_classification.content_category == "ADULT":
            risk_score += weights["adult_content"]
            risk_factors.append("Adult content detected")
            threat_indicators.append("ADULT_CONTENT")
        
        if link_classification.content_category == "GAMBLING":
            risk_score += weights["gambling"]
            risk_factors.append("Gambling content detected")
            threat_indicators.append("GAMBLING_CONTENT")
        
        # Reputation score adjustment
        if reputation_score < 30:
            risk_score += 20
            risk_factors.append("Low reputation score")
            threat_indicators.append("LOW_REPUTATION")
        
        # Determine risk level using enhanced thresholds
        thresholds = self.config["thresholds"]
        if risk_score >= thresholds["critical"]:
            risk_level, emoji = "CRITICAL", "🚨"
        elif risk_score >= thresholds["high"]:
            risk_level, emoji = "HIGH", "🔴"
        elif risk_score >= thresholds["medium"]:
            risk_level, emoji = "MEDIUM", "🟡"
        elif risk_score >= thresholds["low"]:
            risk_level, emoji = "LOW", "🟠"
        else:
            risk_level, emoji = "MINIMAL", "🟢"
        
        return AdvancedAnalysisResult(
            url=url,
            status='ANALYZED',
            risk_score=risk_score,
            risk_level=risk_level,
            factors=risk_factors,
            emoji=emoji,
            entropy_score=features['total_entropy'],
            redirect_chain=features['redirect_chain'],
            link_classification=link_classification,
            behavioral_indicators=behavioral_indicators,
            technical_details=technical_details,
            reputation_score=reputation_score,
            threat_indicators=threat_indicators
        )

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy to detect randomness"""
        if not text:
            return 0.0
        
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0.0
        text_length = len(text)
        
        for count in char_counts.values():
            probability = count / text_length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy

    def follow_redirects(self, url: str) -> List[str]:
        """Follow redirect chain and return all URLs"""
        if not self.enable_network or not self.session:
            return [url]
        
        redirect_chain = [url]
        current_url = url
        max_redirects = self.config["max_redirects"]
        
        try:
            for _ in range(max_redirects):
                response = self.session.head(
                    current_url, 
                    allow_redirects=False, 
                    timeout=self.config["request_timeout"]
                )
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    next_url = response.headers.get('Location')
                    if next_url and next_url != current_url:
                        redirect_chain.append(next_url)
                        current_url = next_url
                    else:
                        break
                else:
                    break
                    
        except Exception as e:
            logger.debug(f"Error following redirects for {url}: {e}")
        
        return redirect_chain

    def extract_features(self, url: str) -> Dict[str, Any]:
        """Extract comprehensive features from URL"""
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        domain_entropy = self.calculate_entropy(extracted.domain)
        path_entropy = self.calculate_entropy(parsed.path)
        query_entropy = self.calculate_entropy(parsed.query)
        
        path_depth = len([p for p in parsed.path.split('/') if p])
        query_params = len(parse_qs(parsed.query))
        
        redirect_chain = self.follow_redirects(url)
        
        return {
            'url': url,
            'length': len(url),
            'domain': extracted.domain + '.' + extracted.suffix if extracted.suffix else extracted.domain,
            'subdomain': extracted.subdomain,
            'has_ip': bool(re.match(r'^\d+\.\d+\.\d+\.\d+', parsed.netloc)),
            'has_https': url.startswith('https'),
            'subdomain_count': len(extracted.subdomain.split('.')) if extracted.subdomain else 0,
            'suspicious_words': sum(1 for word in self.config["suspicious_words"] if word in url.lower()),
            'path_depth': path_depth,
            'query_params': query_params,
            'has_suspicious_tld': extracted.suffix in self.config["suspicious_tlds"],
            'encoded_content': self._check_encoded_content(url),
            'has_shortener': any(domain in url for domain in self.config["url_shorteners"]),
            'homograph_attack': self._check_homograph_attack(extracted.domain),
            'typosquatting': self._check_typosquatting(extracted.domain),
            'domain_entropy': domain_entropy,
            'path_entropy': path_entropy,
            'query_entropy': query_entropy,
            'total_entropy': domain_entropy + path_entropy + query_entropy,
            'redirect_chain': redirect_chain,
            'redirect_count': len(redirect_chain) - 1
        }

    def _check_encoded_content(self, url: str) -> bool:
        """Check for encoded content"""
        try:
            if 'data=' in url:
                data_param = url.split('data=')[1].split('&')[0]
                if len(data_param) > 20:
                    try:
                        base64.b64decode(data_param + '==')
                        return True
                    except:
                        pass
        except:
            pass
        return False

    def _check_homograph_attack(self, domain: str) -> bool:
        """Check for homograph attacks"""
        suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'х', 'у', 'ć', 'ę', 'ł', 'ń', 'ó', 'ś', 'ź', 'ż']
        return any(char in domain for char in suspicious_chars)

    def _check_typosquatting(self, domain: str) -> List[str]:
        """Check for typosquatting"""
        popular_domains = [
            'google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'steam',
            'netflix', 'youtube', 'twitter', 'instagram', 'linkedin', 'github',
            'discord', 'spotify', 'reddit', 'wikipedia', 'ebay', 'alibaba'
        ]
        matches = []
        
        for popular in popular_domains:
            if self._similar_domain(domain, popular) and domain != popular:
                matches.append(popular)
        
        return matches

    def _similar_domain(self, domain1: str, domain2: str) -> bool:
        """Check domain similarity"""
        if abs(len(domain1) - len(domain2)) > 2:
            return False
        
        diff_count = sum(1 for a, b in zip(domain1, domain2) if a != b)
        return diff_count <= 2 and len(domain1) > 3

    def analyze_urls(self, urls: List[str], verbose: bool = True) -> List[AdvancedAnalysisResult]:
        """Analyze multiple URLs with enhanced reporting"""
        logger.info(f"Starting comprehensive analysis of {len(urls)} URLs")
        
        if verbose:
            print(f"🔍 Analyzing {len(urls)} URLs with advanced threat detection...")
            print("=" * 80)
        
        results = []
        for i, url in enumerate(urls, 1):
            try:
                result = self.analyze_url(url)
                results.append(result)
                
                if verbose:
                    self._print_enhanced_result(i, result)
                    
            except Exception as e:
                logger.error(f"Error analyzing {url}: {e}")
                results.append(AdvancedAnalysisResult(
                    url=url,
                    status='ERROR',
                    risk_score=0,
                    risk_level='ERROR',
                    factors=[f"Analysis failed: {str(e)}"],
                    emoji='❌',
                    link_classification=LinkClassification(primary_type="ERROR", secondary_types=[]),
                    behavioral_indicators={},
                    technical_details={},
                    reputation_score=0,
                    threat_indicators=[]
                ))
        
        logger.info(f"Comprehensive analysis complete. Processed {len(results)} URLs")
        return results

    def _print_enhanced_result(self, index: int, result: AdvancedAnalysisResult) -> None:
        """Print enhanced analysis result"""
        if result.status == 'SAFE':
            print(f"{index:3}. {result.emoji} SAFE (Whitelisted): {result.url}")
            if result.link_classification.platform:
                print(f"       Platform: {result.link_classification.platform}")
        elif result.status == 'ERROR':
            print(f"{index:3}. {result.emoji} ERROR: {result.url}")
            for factor in result.factors:
                print(f"       • {factor}")
        else:
            # Main result line
            entropy_info = f" | Entropy: {result.entropy_score:.2f}" if result.entropy_score > 0 else ""
            redirect_info = f" | Redirects: {len(result.redirect_chain) - 1}" if len(result.redirect_chain) > 1 else ""
            reputation_info = f" | Reputation: {result.reputation_score}/100" if result.reputation_score > 0 else ""
            
            print(f"{index:3}. {result.emoji} {result.risk_level} RISK ({result.risk_score}): {result.url}{entropy_info}{redirect_info}{reputation_info}")
            
            # Link classification
            if result.link_classification:
                cls = result.link_classification
                if cls.primary_type != "UNKNOWN":
                    print(f"       Type: {cls.primary_type}")
                if cls.platform:
                    print(f"       Platform: {cls.platform}")
                if cls.file_type:
                    print(f"       File Type: {cls.file_type}")
                if cls.content_category:
                    print(f"       Category: {cls.content_category}")
                if cls.safety_level != "UNKNOWN":
                    print(f"       Safety Level: {cls.safety_level}")
            
            # Risk factors
            if result.factors:
                for factor in result.factors:
                    print(f"       • {factor}")
            
            # Threat indicators
            if result.threat_indicators:
                threat_str = ", ".join(result.threat_indicators[:5])  # Limit display
                if len(result.threat_indicators) > 5:
                    threat_str += f" (+{len(result.threat_indicators) - 5} more)"
                print(f"       Threats: {threat_str}")
            
            # Redirect chain
            if len(result.redirect_chain) > 1:
                print(f"       Redirect chain: {' -> '.join(result.redirect_chain)}")
            
            # Technical details
            if result.technical_details.get('ip_address'):
                print(f"       IP: {result.technical_details['ip_address']}")
            if result.technical_details.get('server_info'):
                print(f"       Server: {result.technical_details['server_info']}")
        
        print()

    def generate_enhanced_summary(self, results: List[AdvancedAnalysisResult]) -> Dict[str, Any]:
        """Generate comprehensive analysis summary"""
        total = len(results)
        safe = sum(1 for r in results if r.status == 'SAFE')
        error = sum(1 for r in results if r.status == 'ERROR')
        critical = sum(1 for r in results if r.risk_level == 'CRITICAL')
        high = sum(1 for r in results if r.risk_level == 'HIGH')
        medium = sum(1 for r in results if r.risk_level == 'MEDIUM')
        low = sum(1 for r in results if r.risk_level == 'LOW')
        minimal = sum(1 for r in results if r.risk_level == 'MINIMAL')
        
        # Link type analysis
        link_types = Counter()
        platforms = Counter()
        content_categories = Counter()
        threat_indicators = Counter()
        
        for result in results:
            if result.link_classification:
                if result.link_classification.primary_type != "UNKNOWN":
                    link_types[result.link_classification.primary_type] += 1
                if result.link_classification.platform:
                    platforms[result.link_classification.platform] += 1
                if result.link_classification.content_category:
                    content_categories[result.link_classification.content_category] += 1
            
            for threat in result.threat_indicators:
                threat_indicators[threat] += 1
        
        summary = {
            'total': total,
            'safe': safe,
            'error': error,
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'minimal': minimal,
            'high_risk_urls': [r.url for r in results if r.risk_level in ['CRITICAL', 'HIGH']],
            'link_types': dict(link_types.most_common(10)),
            'platforms': dict(platforms.most_common(10)),
            'content_categories': dict(content_categories.most_common(10)),
            'threat_indicators': dict(threat_indicators.most_common(10)),
            'average_entropy': sum(r.entropy_score for r in results if r.entropy_score > 0) / max(1, sum(1 for r in results if r.entropy_score > 0)),
            'average_reputation': sum(r.reputation_score for r in results if r.reputation_score > 0) / max(1, sum(1 for r in results if r.reputation_score > 0)),
            'analysis_time': datetime.now().isoformat()
        }
        
        return summary

    def print_enhanced_summary(self, summary: Dict[str, Any]) -> None:
        """Print comprehensive analysis summary"""
        print("=" * 80)
        print("📊 COMPREHENSIVE SECURITY ANALYSIS SUMMARY")
        print("=" * 80)
        
        # Basic stats
        print(f"{'Total URLs analyzed:':<25} {summary['total']}")
        print(f"{'✅ Safe (Whitelisted):':<25} {summary['safe']}")
        print(f"{'❌ Analysis Errors:':<25} {summary['error']}")
        print(f"{'🚨 Critical Risk:':<25} {summary['critical']}")
        print(f"{'🔴 High Risk:':<25} {summary['high']}")
        print(f"{'🟡 Medium Risk:':<25} {summary['medium']}")
        print(f"{'🟠 Low Risk:':<25} {summary['low']}")
        print(f"{'🟢 Minimal Risk:':<25} {summary['minimal']}")
        
        # Link types
        if summary['link_types']:
            print(f"\n📋 LINK TYPES DETECTED:")
            for link_type, count in summary['link_types'].items():
                print(f"   {link_type}: {count}")
        
        # Platforms
        if summary['platforms']:
            print(f"\n🌐 PLATFORMS DETECTED:")
            for platform, count in summary['platforms'].items():
                print(f"   {platform}: {count}")
        
        # Content categories
        if summary['content_categories']:
            print(f"\n📂 CONTENT CATEGORIES:")
            for category, count in summary['content_categories'].items():
                print(f"   {category}: {count}")
        
        # Threat indicators
        if summary['threat_indicators']:
            print(f"\n⚠️  TOP THREAT INDICATORS:")
            for threat, count in summary['threat_indicators'].items():
                print(f"   {threat}: {count}")
        
        # Advanced metrics
        print(f"\n📈 ADVANCED METRICS:")
        print(f"   Average Entropy Score: {summary['average_entropy']:.2f}")
        print(f"   Average Reputation Score: {summary['average_reputation']:.1f}/100")
        
        # Warnings
        if summary['critical'] > 0 or summary['high'] > 0:
            print(f"\n⚠️  SECURITY ALERT: {summary['critical'] + summary['high']} URLs pose significant security risks!")
            print("   🚨 Immediate action recommended - block or investigate these URLs")
            print("   🔍 Review threat indicators and behavioral patterns")
            print("   📋 Consider implementing additional security measures")
        
        print(f"\n🕒 Analysis completed at: {summary['analysis_time']}")
        print("✅ Comprehensive analysis complete!")

    def export_enhanced_results(self, results: List[AdvancedAnalysisResult], output_file: str, format_type: str = 'csv') -> None:
        """Export enhanced results with all analysis data"""
        logger.info(f"Exporting enhanced results to {output_file} in {format_type.upper()} format")
        
        if format_type.lower() == 'json':
            # Custom JSON serialization for complex objects
            data = []
            for result in results:
                result_dict = asdict(result)
                data.append(result_dict)
            
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        
        elif format_type.lower() == 'csv':
            data = []
            for result in results:
                row = {
                    'url': result.url,
                    'status': result.status,
                    'risk_score': result.risk_score,
                    'risk_level': result.risk_level,
                    'factors': '; '.join(result.factors),
                    'entropy_score': result.entropy_score,
                    'redirect_chain': ' -> '.join(result.redirect_chain),
                    'reputation_score': result.reputation_score,
                    'threat_indicators': '; '.join(result.threat_indicators),
                    'link_type': result.link_classification.primary_type if result.link_classification else '',
                    'platform': result.link_classification.platform if result.link_classification else '',
                    'file_type': result.link_classification.file_type if result.link_classification else '',
                    'content_category': result.link_classification.content_category if result.link_classification else '',
                    'safety_level': result.link_classification.safety_level if result.link_classification else '',
                    'analysis_time': result.analysis_time
                }
                data.append(row)
            
            df = pd.DataFrame(data)
            df.to_csv(output_file, index=False)
        
        else:
            raise ValueError(f"Unsupported format: {format_type}")
        
        logger.info(f"Enhanced results exported successfully to {output_file}")


def load_urls_from_file(file_path: str) -> List[str]:
    """Load URLs from a text file"""
    urls = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):
                    urls.append(url)
        logger.info(f"Loaded {len(urls)} URLs from {file_path}")
    except Exception as e:
        logger.error(f"Error loading URLs from file: {e}")
        raise
    
    return urls


def create_enhanced_web_interface(analyzer: AdvancedURLSecurityAnalyzer) -> Flask:
    """Create enhanced Flask web interface"""
    app = Flask(__name__)
    
    HTML_TEMPLATE = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Advanced URL Security Analyzer v2.0</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            * { box-sizing: border-box; }
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
            .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 15px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); overflow: hidden; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
            .header h1 { margin: 0; font-size: 2.5em; font-weight: 700; }
            .header p { margin: 10px 0 0; opacity: 0.9; font-size: 1.1em; }
            .content { padding: 30px; }
            .form-group { margin-bottom: 25px; }
            label { display: block; margin-bottom: 8px; font-weight: 600; color: #333; font-size: 1.1em; }
            textarea { width: 100%; height: 150px; padding: 15px; border: 2px solid #e1e5e9; border-radius: 8px; font-family: 'Monaco', 'Consolas', monospace; font-size: 14px; resize: vertical; transition: border-color 0.3s; }
            textarea:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1); }
            .options { display: flex; gap: 20px; flex-wrap: wrap; }
            .checkbox-group { display: flex; align-items: center; gap: 8px; }
            .checkbox-group input[type="checkbox"] { width: 18px; height: 18px; }
            .checkbox-group label { margin: 0; font-weight: 500; }
            .btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: 600; transition: transform 0.2s, box-shadow 0.2s; }
            .btn:hover { transform: translateY(-2px); box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3); }
            .btn:active { transform: translateY(0); }
            .results { margin-top: 30px; }
            .loading { text-align: center; padding: 40px; color: #666; }
            .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #667eea; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto 20px; }
            @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            .summary { background: #f8f9fa; padding: 25px; border-radius: 10px; margin-bottom: 25px; border-left: 5px solid #667eea; }
            .summary h3 { margin-top: 0; color: #333; }
            .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px; }
            .summary-item { background: white; padding: 15px; border-radius: 8px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .summary-item .number { font-size: 2em; font-weight: 700; margin-bottom: 5px; }
            .summary-item .label { font-size: 0.9em; color: #666; }
            .result-item { margin-bottom: 20px; padding: 20px; border-radius: 10px; border-left: 5px solid #ccc; background: #f9f9f9; }
            .result-item.safe { border-left-color: #28a745; background: #d4edda; }
            .result-item.critical { border-left-color: #dc3545; background: #f8d7da; }
            .result-item.high { border-left-color: #fd7e14; background: #ffe8d4; }
            .result-item.medium { border-left-color: #ffc107; background: #fff3cd; }
            .result-item.low { border-left-color: #17a2b8; background: #d1ecf1; }
            .result-item.minimal { border-left-color: #28a745; background: #d4edda; }
            .url-header { font-family: 'Monaco', 'Consolas', monospace; word-break: break-all; margin-bottom: 15px; font-size: 1.1em; font-weight: 600; }
            .details-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-top: 15px; }
            .detail-box { background: rgba(255,255,255,0.7); padding: 15px; border-radius: 8px; }
            .detail-box h4 { margin: 0 0 10px; color: #333; font-size: 1em; }
            .detail-box p { margin: 5px 0; font-size: 0.9em; color: #666; }
            .factors { margin-top: 15px; }
            .factor-item { background: rgba(255,255,255,0.8); padding: 10px; margin: 5px 0; border-radius: 5px; font-size: 0.9em; }
            .threat-indicators { margin-top: 15px; }
            .threat-tag { display: inline-block; background: #dc3545; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; margin: 2px; }
            .alert { padding: 20px; margin: 20px 0; border-radius: 8px; font-weight: 500; }
            .alert-danger { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
            .alert-warning { background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }
            .alert-info { background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }
            .stats-section { margin-top: 30px; }
            .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
            .stat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
            .stat-card h4 { margin-top: 0; color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
            .stat-list { list-style: none; padding: 0; }
            .stat-list li { padding: 8px 0; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; }
            .stat-list li:last-child { border-bottom: none; }
            .progress-bar { width: 100%; height: 20px; background: #e9ecef; border-radius: 10px; overflow: hidden; margin-top: 10px; }
            .progress-fill { height: 100%; background: linear-gradient(90deg, #28a745, #ffc107, #fd7e14, #dc3545); transition: width 0.3s; }
            @media (max-width: 768px) { .options { flex-direction: column; } .summary-grid, .details-grid, .stats-grid { grid-template-columns: 1fr; } }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ Advanced URL Security Analyzer v2.0</h1>
                <p>Comprehensive threat detection with link classification and behavioral analysis</p>
            </div>
            
            <div class="content">
                <form id="analyzeForm">
                    <div class="form-group">
                        <label for="urls">🔗 Enter URLs to analyze (one per line):</label>
                        <textarea id="urls" name="urls" placeholder="https://example.com&#10;http://suspicious-site.com&#10;https://download.example.com/file.exe&#10;https://app.store.com/download&#10;https://streaming.site.com/watch&#10;https://social.media.com/profile" required></textarea>
                    </div>
                    
                    <div class="form-group">
                        <div class="options">
                            <div class="checkbox-group">
                                <input type="checkbox" id="verbose" name="verbose" checked>
                                <label for="verbose">📋 Detailed Analysis</label>
                            </div>
                            <div class="checkbox-group">
                                <input type="checkbox" id="linkTypes" name="linkTypes" checked>
                                <label for="linkTypes">🔍 Link Classification</label>
                            </div>
                            <div class="checkbox-group">
                                <input type="checkbox" id="behavioral" name="behavioral" checked>
                                <label for="behavioral">🧠 Behavioral Analysis</label>
                            </div>
                            <div class="checkbox-group">
                                <input type="checkbox" id="technical" name="technical" checked>
                                <label for="technical">⚙️ Technical Details</label>
                            </div>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn">🚀 Analyze URLs</button>
                </form>
                
                <div id="results" class="results" style="display: none;">
                    <div id="loading" class="loading">
                        <div class="spinner"></div>
                        <p>🔍 Performing comprehensive security analysis...</p>
                        <p><small>Analyzing link types, behavioral patterns, and threat indicators</small></p>
                    </div>
                    
                    <div id="summary" class="summary" style="display: none;">
                        <h3>📊 Analysis Summary</h3>
                        <div id="summary-content"></div>
                    </div>
                    
                    <div id="detailed-results"></div>
                    
                    <div id="stats" class="stats-section" style="display: none;">
                        <h3>📈 Advanced Statistics</h3>
                        <div id="stats-content" class="stats-grid"></div>
                    </div>
                </div>
            </div>
        </div>

        <script>
            document.getElementById('analyzeForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const urls = document.getElementById('urls').value.trim();
                const verbose = document.getElementById('verbose').checked;
                const linkTypes = document.getElementById('linkTypes').checked;
                const behavioral = document.getElementById('behavioral').checked;
                const technical = document.getElementById('technical').checked;
                
                if (!urls) {
                    alert('Please enter at least one URL');
                    return;
                }
                
                // Show loading
                document.getElementById('results').style.display = 'block';
                document.getElementById('loading').style.display = 'block';
                document.getElementById('summary').style.display = 'none';
                document.getElementById('stats').style.display = 'none';
                document.getElementById('detailed-results').innerHTML = '';
                
                try {
                    const response = await fetch('/analyze', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            urls: urls.split('\\n').filter(url => url.trim()),
                            verbose: verbose,
                            linkTypes: linkTypes,
                            behavioral: behavioral,
                            technical: technical
                        })
                    });
                    
                    const data = await response.json();
                    
                    // Hide loading
                    document.getElementById('loading').style.display = 'none';
                    
                    if (data.error) {
                        document.getElementById('detailed-results').innerHTML = `<div class="alert alert-danger">❌ Error: ${data.error}</div>`;
                        return;
                    }
                    
                    // Show summary
                    displaySummary(data.summary);
                    
                    // Show detailed results
                    displayDetailedResults(data.results, { linkTypes, behavioral, technical });
                    
                    // Show advanced stats
                    displayAdvancedStats(data.summary);
                    
                } catch (error) {
                    document.getElementById('loading').style.display = 'none';
                    document.getElementById('detailed-results').innerHTML = `<div class="alert alert-danger">❌ Network Error: ${error.message}</div>`;
                }
            });
            
            function displaySummary(summary) {
                const total = summary.critical + summary.high + summary.medium + summary.low + summary.minimal + summary.safe;
                const riskPercentage = total > 0 ? ((summary.critical + summary.high) / total * 100).toFixed(1) : 0;
                
                document.getElementById('summary-content').innerHTML = `
                    <div class="summary-grid">
                        <div class="summary-item">
                            <div class="number" style="color: #333;">${summary.total}</div>
                            <div class="label">Total URLs</div>
                        </div>
                        <div class="summary-item">
                            <div class="number" style="color: #dc3545;">${summary.critical}</div>
                            <div class="label">🚨 Critical</div>
                        </div>
                        <div class="summary-item">
                            <div class="number" style="color: #fd7e14;">${summary.high}</div>
                            <div class="label">🔴 High Risk</div>
                        </div>
                        <div class="summary-item">
                            <div class="number" style="color: #ffc107;">${summary.medium}</div>
                            <div class="label">🟡 Medium</div>
                        </div>
                        <div class="summary-item">
                            <div class="number" style="color: #17a2b8;">${summary.low}</div>
                            <div class="label">🟠 Low</div>
                        </div>
                        <div class="summary-item">
                            <div class="number" style="color: #28a745;">${summary.minimal}</div>
                            <div class="label">🟢 Minimal</div>
                        </div>
                        <div class="summary-item">
                            <div class="number" style="color: #28a745;">${summary.safe}</div>
                            <div class="label">✅ Safe</div>
                        </div>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${riskPercentage}%"></div>
                    </div>
                    <p style="text-align: center; margin-top: 10px; font-weight: 600;">
                        Risk Level: ${riskPercentage}% of URLs pose significant security risks
                    </p>
                    ${summary.critical + summary.high > 0 ? 
                        `<div class="alert alert-danger">
                            ⚠️ <strong>Security Alert:</strong> ${summary.critical + summary.high} URLs require immediate attention!
                        </div>` : 
                        `<div class="alert alert-info">
                            ✅ <strong>Good News:</strong> No high-risk URLs detected in this analysis.
                        </div>`
                    }
                `;
                document.getElementById('summary').style.display = 'block';
            }
            
            function displayDetailedResults(results, options) {
                const resultsHtml = results.map(result => {
                    const riskClass = result.risk_level.toLowerCase();
                    
                    let html = `
                        <div class="result-item ${riskClass}">
                            <div class="url-header">
                                ${result.emoji} <strong>${result.risk_level}</strong> 
                                ${result.status !== 'SAFE' ? `(${result.risk_score})` : ''}: ${result.url}
                            </div>
                    `;
                    
                    if (options.linkTypes && result.link_classification) {
                        const cls = result.link_classification;
                        html += `
                            <div class="details-grid">
                                <div class="detail-box">
                                    <h4>🔗 Link Classification</h4>
                                    ${cls.primary_type !== 'UNKNOWN' ? `<p><strong>Type:</strong> ${cls.primary_type}</p>` : ''}
                                    ${cls.platform ? `<p><strong>Platform:</strong> ${cls.platform}</p>` : ''}
                                    ${cls.file_type ? `<p><strong>File Type:</strong> ${cls.file_type}</p>` : ''}
                                    ${cls.content_category ? `<p><strong>Category:</strong> ${cls.content_category}</p>` : ''}
                                    ${cls.safety_level !== 'UNKNOWN' ? `<p><strong>Safety Level:</strong> ${cls.safety_level}</p>` : ''}
                                </div>
                        `;
                    }
                    
                    if (options.technical && result.technical_details) {
                        html += `
                                <div class="detail-box">
                                    <h4>⚙️ Technical Details</h4>
                                    ${result.entropy_score > 0 ? `<p><strong>Entropy:</strong> ${result.entropy_score.toFixed(2)}</p>` : ''}
                                    ${result.reputation_score > 0 ? `<p><strong>Reputation:</strong> ${result.reputation_score}/100</p>` : ''}
                                    ${result.technical_details.ip_address ? `<p><strong>IP:</strong> ${result.technical_details.ip_address}</p>` : ''}
                                    ${result.technical_details.server_info ? `<p><strong>Server:</strong> ${result.technical_details.server_info}</p>` : ''}
                                    ${result.redirect_chain.length > 1 ? `<p><strong>Redirects:</strong> ${result.redirect_chain.length - 1}</p>` : ''}
                                </div>
                        `;
                    }
                    
                    if (options.linkTypes || options.technical) {
                        html += `</div>`;
                    }
                    
                    if (result.factors && result.factors.length > 0) {
                        html += `
                            <div class="factors">
                                <h4>Risk Factors:</h4>
                                ${result.factors.map(factor => `<div class="factor-item">• ${factor}</div>`).join('')}
                            </div>
                        `;
                    }
                    
                    if (options.behavioral && result.threat_indicators && result.threat_indicators.length > 0) {
                        html += `
                            <div class="threat-indicators">
                                <h4>Threat Indicators:</h4>
                                ${result.threat_indicators.slice(0, 10).map(threat => `<span class="threat-tag">${threat}</span>`).join('')}
                                ${result.threat_indicators.length > 10 ? `<span class="threat-tag">+${result.threat_indicators.length - 10} more</span>` : ''}
                            </div>
                        `;
                    }
                    
                    if (result.redirect_chain.length > 1) {
                        html += `
                            <div class="factors">
                                <h4>Redirect Chain:</h4>
                                <div class="factor-item" style="font-family: monospace; font-size: 0.8em;">
                                    ${result.redirect_chain.join(' → ')}
                                </div>
                            </div>
                        `;
                    }
                    
                    html += `</div>`;
                    return html;
                }).join('');
                
                document.getElementById('detailed-results').innerHTML = resultsHtml;
            }
            
            function displayAdvancedStats(summary) {
                let statsHtml = '';
                
                if (summary.link_types && Object.keys(summary.link_types).length > 0) {
                    statsHtml += `
                        <div class="stat-card">
                            <h4>🔗 Link Types</h4>
                            <ul class="stat-list">
                                ${Object.entries(summary.link_types).map(([type, count]) => 
                                    `<li><span>${type}</span><span>${count}</span></li>`
                                ).join('')}
                            </ul>
                        </div>
                    `;
                }
                
                if (summary.platforms && Object.keys(summary.platforms).length > 0) {
                    statsHtml += `
                        <div class="stat-card">
                            <h4>🌐 Platforms</h4>
                            <ul class="stat-list">
                                ${Object.entries(summary.platforms).map(([platform, count]) => 
                                    `<li><span>${platform}</span><span>${count}</span></li>`
                                ).join('')}
                            </ul>
                        </div>
                    `;
                }
                
                if (summary.threat_indicators && Object.keys(summary.threat_indicators).length > 0) {
                    statsHtml += `
                        <div class="stat-card">
                            <h4>⚠️ Threat Indicators</h4>
                            <ul class="stat-list">
                                ${Object.entries(summary.threat_indicators).slice(0, 10).map(([threat, count]) => 
                                    `<li><span>${threat}</span><span>${count}</span></li>`
                                ).join('')}
                            </ul>
                        </div>
                    `;
                }
                
                if (summary.content_categories && Object.keys(summary.content_categories).length > 0) {
                    statsHtml += `
                        <div class="stat-card">
                            <h4>📂 Content Categories</h4>
                            <ul class="stat-list">
                                ${Object.entries(summary.content_categories).map(([category, count]) => 
                                    `<li><span>${category}</span><span>${count}</span></li>`
                                ).join('')}
                            </ul>
                        </div>
                    `;
                }
                
                if (statsHtml) {
                    document.getElementById('stats-content').innerHTML = statsHtml;
                    document.getElementById('stats').style.display = 'block';
                }
            }
        </script>
    </body>
    </html>
    """
    
    @app.route('/')
    def index():
        return HTML_TEMPLATE
    
    @app.route('/analyze', methods=['POST'])
    def analyze():
        try:
            data = request.json
            urls = data.get('urls', [])
            verbose = data.get('verbose', True)
            
            if not urls:
                return jsonify({'error': 'No URLs provided'}), 400
            
            # Analyze URLs
            results = analyzer.analyze_urls(urls, verbose=False)
            summary = analyzer.generate_enhanced_summary(results)
            
            # Convert results to JSON-serializable format
            json_results = []
            for result in results:
                json_result = asdict(result)
                json_results.append(json_result)
            
            return jsonify({
                'results': json_results,
                'summary': summary
            })
            
        except Exception as e:
            logger.error(f"Web interface error: {e}")
            return jsonify({'error': str(e)}), 500
    
    return app


def main():
    """Enhanced main CLI interface with integrated modules"""
    parser = argparse.ArgumentParser(
        description="Advanced URL Security Analyzer v2.0 - Enterprise-Grade Threat Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🛡️ Enterprise Features:
• Multi-Source Threat Intelligence (VirusTotal, Google Safe Browsing, URLVoid)
• Advanced Link Classification (50+ types: downloads, apps, streaming, social media)
• Behavioral Analysis (scams, social engineering, malware patterns)
• Interactive Analytics Dashboard with real-time visualizations
• Machine Learning-based entropy and reputation scoring
• REST API with file upload and export capabilities

🌐 Web Interface (Default Mode):
• Bootstrap-powered responsive design with mobile support
• Real-time analysis results with expandable threat breakdowns
• File upload support for batch analysis and CSV/JSON export
• Interactive threat intelligence integration with external APIs

📋 CLI Examples:
  python main.py                                    # Start web interface (default)
  python main.py --cli                             # Run CLI analysis with test URLs
  python main.py --file urls.txt --cli             # CLI analysis with file
        """
    )
    
    parser.add_argument('--cli', action='store_true', help='Run in CLI mode instead of web interface')
    parser.add_argument('--file', '-f', help='File containing URLs to analyze (one per line)')
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--format', choices=['csv', 'json', 'html'], default='csv', help='Output format')
    parser.add_argument('--config', '-c', help='Configuration file path')
    parser.add_argument('--summary-only', action='store_true', help='Show only summary, no detailed output')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output with debug information')
    parser.add_argument('--dry-run', action='store_true', help='Simulate analysis without saving results')
    parser.add_argument('--no-network', action='store_true', help='Disable network requests (offline mode)')
    parser.add_argument('--port', type=int, default=5000, help='Port for web interface (default: 5000)')
    parser.add_argument('--threat-intel', action='store_true', help='Enable threat intelligence APIs')
    parser.add_argument('--batch-size', type=int, default=50, help='Batch size for processing (default: 50)')
    parser.add_argument('--parallel', action='store_true', help='Enable parallel processing')
    parser.add_argument('--export-dashboard', help='Export analytics dashboard to HTML file')
    parser.add_argument('--api-keys', help='Path to API keys configuration file')
    parser.add_argument('--max-redirects', type=int, default=5, help='Maximum redirects to follow')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds')
    parser.add_argument('--user-agent', help='Custom user agent string')
    parser.add_argument('--proxy', help='Proxy server (http://host:port)')
    parser.add_argument('--rate-limit', type=float, default=1.0, help='Rate limit (requests per second)')
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize enhanced analyzer
    analyzer = AdvancedURLSecurityAnalyzer(
        config_path=args.config,
        enable_network=not args.no_network
    )
    
    # Default to web interface unless CLI mode is specified
    if not args.cli:
        try:
            from web_interface import create_enhanced_web_app
            app = create_enhanced_web_app(analyzer)
            
            print("🌐 ENTERPRISE WEB INTERFACE STARTING")
            print("=" * 60)
            print(f"🚀 Advanced URL Security Analyzer v2.0")
            print(f"📍 Server: http://0.0.0.0:{args.port}")
            print(f"📊 Dashboard: http://0.0.0.0:{args.port}/dashboard")
            print()
            print("✨ FEATURES ENABLED:")
            print("   • Real-time URL analysis with threat intelligence")
            print("   • Interactive analytics dashboard with visualizations")
            print("   • File upload support (drag & drop .txt files)")
            print("   • Export results to CSV/JSON formats")
            print("   • Responsive Bootstrap UI with mobile support")
            print("   • REST API endpoints for integration")
            print("   • Optimized for deployment on Render/Replit")
            print()
            print("🔍 In Replit: Click the 'Open in new tab' button when it appears")
            print("🌍 On Render: Your app will be available at your deployed URL")
            print("💡 Press Ctrl+C to stop the server")
            print("=" * 60)
            
            # Get port from environment variable for Render compatibility
            import os
            port = int(os.environ.get('PORT', args.port))
            app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
            return
            
        except ImportError as e:
            print(f"❌ Error: Missing dependencies for web interface: {e}")
            print("💡 Install required packages: pip install flask plotly")
            return
    
    # CLI Mode - Load URLs and run analysis
    if args.file:
        urls = load_urls_from_file(args.file)
    else:
        # Enhanced test URLs covering various link types and threats
        urls = [
            # Download Links
            "http://malicious-download.com/virus.exe",
            "https://github.com/microsoft/vscode/releases/download/1.85.0/VSCode-linux-x64-1.85.0.tar.gz",
            "http://fake-adobe.com/flash-player-update.exe",
            "https://sourceforge.net/projects/audacity/files/latest/download",
            
            # App Links
            "https://play.google.com/store/apps/details?id=com.whatsapp",
            "http://fake-app-store.tk/download-whatsapp.apk",
            "https://apps.apple.com/us/app/telegram-messenger/id686449807",
            "http://free-premium-apps.ml/netflix-premium.apk",
            
            # Streaming Links
            "https://youtube.com/watch?v=dQw4w9WgXcQ",
            "http://free-movies-stream.tk/watch-avengers-endgame",
            "https://netflix.com/browse",
            "http://watch-movies-free.cf/stream/latest-movies",
            
            # Social Media
            "https://facebook.com/login",
            "http://facebook-security-alert.com/verify-account",
            "https://twitter.com/elonmusk",
            "http://twitter-winner.tk/claim-prize",
            
            # Financial/Banking
            "https://paypal.com/signin",
            "http://paypal-security-update.com/verify-account",
            "https://chase.com/personal/online-banking",
            "http://urgent-bank-alert.ml/update-account",
            
            # Shopping/E-commerce
            "https://amazon.com/dp/B08N5WRWNW",
            "http://amazon-prize-winner.tk/claim-now",
            "https://ebay.com/itm/123456789",
            "http://fake-ebay-auction.cf/urgent-bid",
            
            # Cloud Storage
            "https://drive.google.com/file/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/view",
            "http://free-cloud-storage.tk/download-files",
            "https://dropbox.com/s/abc123/document.pdf",
            "http://mega-files.ml/download-archive",
            
            # Gaming
            "https://store.steampowered.com/app/570/Dota_2/",
            "http://free-steam-games.tk/download-gta5",
            "https://epicgames.com/store/en-US/p/fortnite",
            "http://free-vbucks-generator.cf/claim-now",
            
            # News/Media
            "https://cnn.com/2024/01/15/tech/ai-breakthrough/index.html",
            "http://fake-news-breaking.tk/shocking-celebrity-death",
            "https://bbc.com/news/technology-67234567",
            "http://click-bait-news.ml/you-wont-believe-this",
            
            # Adult/Restricted Content
            "http://adult-content-warning.xxx/enter-site",
            "http://dating-scam.tk/meet-singles",
            "http://casino-winner.cf/claim-jackpot",
            "http://online-pharmacy.pw/order-pills",
            
            # Cryptocurrency/Investment
            "http://bitcoin-investment.tk/double-your-money",
            "http://crypto-scam.ml/free-bitcoin",
            "http://forex-trading.cf/guaranteed-profits",
            "http://investment-opportunity.ga/million-dollar-secret",
            
            # Technical/Software
            "https://github.com/torvalds/linux",
            "http://fake-windows-update.tk/critical-security-patch",
            "https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster-than-processing-an-unsorted-array",
            "http://fake-antivirus.ml/scan-computer-now",
            
            # Phishing/Impersonation
            "http://аррle.com/id/signin",  # Homograph attack
            "http://googIe.com/accounts/signin",  # Typosquatting
            "http://microsoft-security-alert.tk/urgent-action-required",
            "http://government-tax-refund.ml/claim-refund",
            
            # Suspicious/Malicious
            "http://192.168.1.1/admin/login",
            "http://malware-distribution.tk/payload.exe",
            "http://phishing-kit.cf/steal-credentials",
            "http://botnet-command.ml/connect",
            
            # Legitimate/Safe (Whitelisted)
            "https://google.com/search?q=url+security",
            "https://microsoft.com/en-us/security",
            "https://replit.com/@username/project",
            "https://github.com/OWASP/Top10"
        ]
        print("🧪 Running with comprehensive test URLs covering all link types")
        print("📋 Use --file to analyze custom URLs")
        print()
    
    if not urls:
        print("❌ No URLs to analyze")
        return
    
    # Perform enhanced analysis
    print("🛡️  ADVANCED URL SECURITY ANALYZER v2.0")
    print("=" * 80)
    print("🔍 Comprehensive threat detection with link classification and behavioral analysis")
    print("⚡ Enhanced features: Download detection, App links, Streaming services, Social media")
    print("🧠 AI-powered behavioral analysis and advanced threat intelligence")
    print()
    
    verbose_output = not args.summary_only
    results = analyzer.analyze_urls(urls, verbose=verbose_output)
    
    # Generate and display enhanced summary
    summary = analyzer.generate_enhanced_summary(results)
    analyzer.print_enhanced_summary(summary)
    
    # Export results if requested and not in dry-run mode
    if args.output and not args.dry_run:
        analyzer.export_enhanced_results(results, args.output, args.format)
        print(f"\n💾 Enhanced results exported to {args.output}")
    elif args.dry_run:
        print(f"\n🔍 Dry run: Would export enhanced results to {args.output or 'output file'}")


if __name__ == "__main__":
    main()
