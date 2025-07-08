
# 🛡️ Advanced URL Security Analyzer

A comprehensive Python tool for detecting phishing, malware, and suspicious URLs with advanced features including entropy scoring, redirect chain analysis, and multiple output formats.

## ✨ Features

### Core Security Detection
- **Phishing Detection**: Identifies suspicious domains, typosquatting, and homograph attacks
- **Entropy Analysis**: Uses Shannon entropy to detect randomly generated URLs
- **Redirect Chain Analysis**: Follows and analyzes URL redirects
- **IP Address Detection**: Flags URLs using IP addresses instead of domains
- **Suspicious Content**: Detects encoded content and suspicious keywords
- **TLD Analysis**: Identifies suspicious top-level domains

### Advanced Capabilities
- **Configurable Scoring**: Customizable weights and thresholds via JSON config
- **Multiple Output Formats**: Export to CSV, JSON
- **Web Interface**: Browser-based analysis with Flask
- **CLI Interface**: Full command-line support with extensive options
- **Whitelist Management**: Configurable trusted domain list
- **Logging**: Comprehensive logging with timestamps and severity levels

## 🚀 Quick Start

### Basic Usage
```bash
# Run with default test URLs
python main.py

# Analyze URLs from a file
python main.py --file test_urls.txt

# Start web interface
python main.py --web
```

### Web Interface
```bash
python main.py --web --port 5000
```
Then open your browser to `http://localhost:5000`

## 📋 Command Line Options

```bash
python main.py [OPTIONS]

Options:
  -f, --file FILE         File containing URLs (one per line)
  -o, --output FILE       Output file for results
  --format {csv,json}     Output format (default: csv)
  -c, --config FILE       Configuration file path
  --summary-only          Show only summary, no detailed output
  -v, --verbose           Verbose output with debug information
  --dry-run              Simulate analysis without saving results
  --no-network           Disable network requests (offline mode)
  --web                  Start web interface
  --port PORT            Port for web interface (default: 5000)
```

### Examples

```bash
# Analyze URLs from file and export to CSV
python main.py --file urls.txt --output results.csv --format csv

# Summary only mode
python main.py --file urls.txt --summary-only

# Use custom configuration
python main.py --config my_config.json --verbose

# Dry run mode (test without saving)
python main.py --file urls.txt --output test.csv --dry-run

# Offline analysis (no network requests)
python main.py --file urls.txt --no-network
```

## ⚙️ Configuration

Create a `config.json` file to customize the analyzer:

```json
{
  "weights": {
    "ip_address": 35,
    "no_https": 25,
    "suspicious_words": 15,
    "high_entropy": 20
  },
  "thresholds": {
    "critical": 70,
    "high": 50,
    "medium": 25,
    "low": 10
  },
  "whitelist": [
    "google.com",
    "github.com",
    "your-trusted-domain.com"
  ],
  "suspicious_words": [
    "login", "verify", "urgent", "winner"
  ]
}
```

### Configuration Options

- **weights**: Risk score multipliers for different threat types
- **thresholds**: Risk level boundaries
- **whitelist**: Trusted domains that bypass analysis
- **suspicious_words**: Keywords that increase risk scores
- **suspicious_tlds**: Suspicious top-level domains
- **url_shorteners**: Known URL shortening services
- **max_redirects**: Maximum redirects to follow
- **request_timeout**: Network request timeout in seconds

## 📁 Input File Format

Create a text file with URLs (one per line):

```text
# Comments start with #
https://google.com
http://suspicious-site.com
https://github.com/user/repo
```

## 📊 Output Formats

### CSV Output
```csv
url,status,risk_score,risk_level,factors,entropy_score,redirect_chain
http://example.com,ANALYZED,25,MEDIUM,"No HTTPS; 1 suspicious keywords",2.34,http://example.com
```

### JSON Output
```json
[
  {
    "url": "http://example.com",
    "status": "ANALYZED",
    "risk_score": 25,
    "risk_level": "MEDIUM",
    "factors": ["No HTTPS", "1 suspicious keywords"],
    "entropy_score": 2.34,
    "redirect_chain": ["http://example.com"]
  }
]
```

## 🌐 Web Interface

The web interface provides:
- **Simple URL Input**: Paste URLs directly in the browser
- **Real-time Analysis**: Instant results with visual indicators
- **Risk Categorization**: Color-coded results by risk level
- **Detailed Reports**: Factor breakdown and redirect chains
- **Summary Statistics**: Overview of analysis results

### Starting the Web Interface
```bash
python main.py --web --port 5000
```

## 🧪 Testing

Run the unit tests:
```bash
python test_analyzer.py
```

### Test Coverage
- Entropy calculation
- IP address detection
- HTTPS validation
- Suspicious word detection
- Homograph attack detection
- Typosquatting detection
- Configuration loading
- File input/output

## 📈 Risk Scoring System

### Risk Levels
- 🚨 **CRITICAL** (70+): Immediate threat, block immediately
- 🔴 **HIGH** (50-69): Significant risk, investigate
- 🟡 **MEDIUM** (25-49): Moderate risk, use caution
- 🟠 **LOW** (10-24): Minor risk, monitor
- 🟢 **MINIMAL** (0-9): Low risk, likely safe
- ✅ **WHITELISTED**: Trusted domain

### Scoring Factors
- **IP Address Usage** (+35): Using IP instead of domain
- **No HTTPS** (+25): Unencrypted connection
- **Suspicious Keywords** (+15 each): Phishing-related words
- **High Entropy** (+20): Random/generated URLs
- **Homograph Attack** (+40): Look-alike characters
- **Typosquatting** (+35): Similar to popular domains
- **Suspicious TLD** (+25): High-risk domain extensions
- **URL Shorteners** (+15): Obscured destinations
- **Encoded Content** (+30): Base64 or other encoding
- **Multiple Redirects** (+15): Long redirect chains

## 🔧 Dependencies

Install required packages:
```bash
pip install requests pandas tldextract flask
```

Or use the included `pyproject.toml`:
```bash
# Replit automatically installs dependencies
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📝 License

This project is open source and available under the MIT License.

## 🆘 Support

For issues, questions, or feature requests:
1. Check the documentation above
2. Run with `--verbose` for detailed logging
3. Test with `--dry-run` to verify configuration
4. Use the web interface for easier debugging

---

**Example Output:**
```
🛡️  ADVANCED URL SECURITY ANALYZER
================================================================================
Detecting phishing, malware, and suspicious URLs...

🔍 Analyzing 5 URLs...
================================================================================
  1. 🔴 HIGH RISK (55): http://paypal-login.com/verify | Entropy: 3.25
       • No HTTPS encryption
       • 2 suspicious keywords

  2. ✅ SAFE (Whitelisted): https://google.com

  3. 🚨 CRITICAL RISK (75): http://192.168.1.1/login | Entropy: 2.81
       • Uses IP address instead of domain
       • No HTTPS encryption
       • 1 suspicious keywords

================================================================================
📊 SECURITY ANALYSIS SUMMARY
================================================================================
Total URLs analyzed:      5
✅ Safe (Whitelisted):   1
🚨 Critical Risk:        1
🔴 High Risk:           1
🟡 Medium Risk:         0
🟠 Low Risk:            0
🟢 Minimal Risk:        0

⚠️  WARNING: 2 URLs pose significant security risks!
   Recommend blocking or investigating these URLs immediately.

✅ Analysis complete!
```
