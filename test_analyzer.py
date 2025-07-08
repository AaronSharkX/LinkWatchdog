
#!/usr/bin/env python3
"""
Unit tests for URL Security Analyzer
"""

import unittest
import tempfile
import os
import json
from main import URLSecurityAnalyzer, load_urls_from_file


class TestURLSecurityAnalyzer(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures"""
        self.analyzer = URLSecurityAnalyzer(enable_network=False)  # Disable network for tests
    
    def test_entropy_calculation(self):
        """Test Shannon entropy calculation"""
        # Test with random string (high entropy)
        random_text = "xK9mP2vL8qR4"
        entropy = self.analyzer.calculate_entropy(random_text)
        self.assertGreater(entropy, 3.0)
        
        # Test with repeated pattern (low entropy)
        pattern_text = "aaaaaaaaaa"
        entropy = self.analyzer.calculate_entropy(pattern_text)
        self.assertEqual(entropy, 0.0)
        
        # Test empty string
        empty_entropy = self.analyzer.calculate_entropy("")
        self.assertEqual(empty_entropy, 0.0)
    
    def test_ip_detection(self):
        """Test IP address detection"""
        features = self.analyzer.extract_features("http://192.168.1.1/login")
        self.assertTrue(features['has_ip'])
        
        features = self.analyzer.extract_features("https://google.com/search")
        self.assertFalse(features['has_ip'])
    
    def test_https_detection(self):
        """Test HTTPS detection"""
        features = self.analyzer.extract_features("https://secure.com")
        self.assertTrue(features['has_https'])
        
        features = self.analyzer.extract_features("http://insecure.com")
        self.assertFalse(features['has_https'])
    
    def test_suspicious_words(self):
        """Test suspicious word detection"""
        url = "http://example.com/login/verify/urgent"
        features = self.analyzer.extract_features(url)
        self.assertGreater(features['suspicious_words'], 0)
        
        url = "https://google.com/search"
        features = self.analyzer.extract_features(url)
        self.assertEqual(features['suspicious_words'], 0)
    
    def test_homograph_attack(self):
        """Test homograph attack detection"""
        # Cyrillic 'a' that looks like Latin 'a'
        features = self.analyzer.extract_features("http://аррle.com")
        self.assertTrue(features['homograph_attack'])
        
        features = self.analyzer.extract_features("http://apple.com")
        self.assertFalse(features['homograph_attack'])
    
    def test_typosquatting(self):
        """Test typosquatting detection"""
        features = self.analyzer.extract_features("http://googel.com")
        self.assertGreater(len(features['typosquatting']), 0)
        
        features = self.analyzer.extract_features("http://example.com")
        self.assertEqual(len(features['typosquatting']), 0)
    
    def test_whitelist(self):
        """Test whitelist functionality"""
        result = self.analyzer.analyze_url("https://google.com")
        self.assertEqual(result.status, 'SAFE')
        self.assertEqual(result.risk_level, 'WHITELISTED')
    
    def test_risk_scoring(self):
        """Test risk scoring system"""
        # High-risk URL
        result = self.analyzer.analyze_url("http://192.168.1.1/login/verify")
        self.assertGreater(result.risk_score, 50)
        
        # Low-risk URL
        result = self.analyzer.analyze_url("https://example.com")
        self.assertLess(result.risk_score, 30)
    
    def test_encoded_content_detection(self):
        """Test base64 encoded content detection"""
        url = "http://example.com?data=aGVsbG8gd29ybGQ="  # "hello world" in base64
        features = self.analyzer.extract_features(url)
        self.assertTrue(features['encoded_content'])
        
        url = "http://example.com?data=short"
        features = self.analyzer.extract_features(url)
        self.assertFalse(features['encoded_content'])


class TestUtilityFunctions(unittest.TestCase):
    
    def test_load_urls_from_file(self):
        """Test loading URLs from file"""
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("https://google.com\n")
            f.write("# This is a comment\n")
            f.write("https://github.com\n")
            f.write("\n")  # Empty line
            f.write("http://example.com\n")
            temp_file = f.name
        
        try:
            urls = load_urls_from_file(temp_file)
            self.assertEqual(len(urls), 3)
            self.assertIn("https://google.com", urls)
            self.assertIn("https://github.com", urls)
            self.assertIn("http://example.com", urls)
        finally:
            os.unlink(temp_file)


class TestConfigurationLoading(unittest.TestCase):
    
    def test_default_config(self):
        """Test default configuration loading"""
        analyzer = URLSecurityAnalyzer()
        self.assertIsInstance(analyzer.config, dict)
        self.assertIn('weights', analyzer.config)
        self.assertIn('thresholds', analyzer.config)
        self.assertIn('whitelist', analyzer.config)
    
    def test_custom_config(self):
        """Test custom configuration loading"""
        custom_config = {
            "weights": {"ip_address": 50},
            "thresholds": {"critical": 80},
            "whitelist": ["custom.com"]
        }
        
        # Create temporary config file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(custom_config, f)
            temp_config = f.name
        
        try:
            analyzer = URLSecurityAnalyzer(config_path=temp_config)
            self.assertEqual(analyzer.config['weights']['ip_address'], 50)
            self.assertEqual(analyzer.config['thresholds']['critical'], 80)
            self.assertIn('custom.com', analyzer.config['whitelist'])
        finally:
            os.unlink(temp_config)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
