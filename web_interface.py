
#!/usr/bin/env python3
"""
Enhanced Web Interface with Dashboard and Advanced Features
"""

from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for
import json
import os
import tempfile
import pandas as pd
from werkzeug.utils import secure_filename
from datetime import datetime
import plotly.utils
from main import AdvancedURLSecurityAnalyzer
from analytics_dashboard import SecurityAnalyticsDashboard
from threat_intelligence import ThreatIntelligenceEngine

def create_enhanced_web_app(analyzer: AdvancedURLSecurityAnalyzer) -> Flask:
    """Create enhanced Flask web application"""
    app = Flask(__name__)
    app.secret_key = 'your-secret-key-change-this'
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
    
    # Initialize components
    dashboard = SecurityAnalyticsDashboard()
    threat_intel = ThreatIntelligenceEngine(analyzer.config)
    
    @app.route('/')
    def index():
        """Main analysis page"""
        return render_template('index.html')
    
    @app.route('/dashboard')
    def dashboard_page():
        """Analytics dashboard page"""
        stats = dashboard.get_summary_stats()
        return render_template('dashboard.html', stats=stats)
    
    @app.route('/api/dashboard/risk-distribution')
    def api_risk_distribution():
        """API endpoint for risk distribution chart"""
        chart_json = dashboard.generate_risk_distribution_chart()
        return jsonify(json.loads(chart_json))
    
    @app.route('/api/dashboard/threat-trends')
    def api_threat_trends():
        """API endpoint for threat trends chart"""
        chart_json = dashboard.generate_threat_trends_chart()
        return jsonify(json.loads(chart_json))
    
    @app.route('/api/dashboard/platform-analysis')
    def api_platform_analysis():
        """API endpoint for platform analysis chart"""
        chart_json = dashboard.generate_platform_analysis_chart()
        return jsonify(json.loads(chart_json))
    
    @app.route('/api/dashboard/entropy-analysis')
    def api_entropy_analysis():
        """API endpoint for entropy analysis chart"""
        chart_json = dashboard.generate_entropy_analysis_chart()
        return jsonify(json.loads(chart_json))
    
    @app.route('/api/dashboard/threat-indicators')
    def api_threat_indicators():
        """API endpoint for threat indicators chart"""
        chart_json = dashboard.generate_threat_indicators_chart()
        return jsonify(json.loads(chart_json))
    
    @app.route('/api/dashboard/content-categories')
    def api_content_categories():
        """API endpoint for content categories chart"""
        chart_json = dashboard.generate_content_category_chart()
        return jsonify(json.loads(chart_json))
    
    @app.route('/analyze', methods=['POST'])
    def analyze_urls():
        """Analyze URLs endpoint with enhanced features"""
        try:
            data = request.json or {}
            urls = data.get('urls', [])
            enable_threat_intel = data.get('threatIntel', False)
            
            if not urls:
                return jsonify({'error': 'No URLs provided'}), 400
            
            # Perform analysis
            results = analyzer.analyze_urls(urls, verbose=False)
            
            # Add threat intelligence if enabled
            if enable_threat_intel:
                for result in results:
                    if result.status != 'SAFE':
                        threat_intel_results = threat_intel.get_url_reputation(result.url)
                        result.threat_intelligence = threat_intel_results
            
            # Generate summary
            summary = analyzer.generate_enhanced_summary(results)
            
            # Save to dashboard history
            dashboard.add_analysis_batch(results, summary)
            
            # Convert to JSON-serializable format
            json_results = []
            for result in results:
                json_result = {
                    'url': result.url,
                    'status': result.status,
                    'risk_score': result.risk_score,
                    'risk_level': result.risk_level,
                    'factors': result.factors,
                    'emoji': result.emoji,
                    'entropy_score': result.entropy_score,
                    'redirect_chain': result.redirect_chain,
                    'reputation_score': result.reputation_score,
                    'threat_indicators': result.threat_indicators,
                    'analysis_time': result.analysis_time,
                    'link_classification': {
                        'primary_type': result.link_classification.primary_type if result.link_classification else None,
                        'platform': result.link_classification.platform if result.link_classification else None,
                        'file_type': result.link_classification.file_type if result.link_classification else None,
                        'content_category': result.link_classification.content_category if result.link_classification else None,
                        'safety_level': result.link_classification.safety_level if result.link_classification else None
                    },
                    'threat_intelligence': getattr(result, 'threat_intelligence', [])
                }
                json_results.append(json_result)
            
            return jsonify({
                'results': json_results,
                'summary': summary,
                'analysis_id': datetime.now().isoformat()
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/upload', methods=['POST'])
    def upload_file():
        """Upload and analyze file"""
        try:
            if 'file' not in request.files:
                return jsonify({'error': 'No file uploaded'}), 400
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400
            
            if file and file.filename.endswith('.txt'):
                # Read URLs from file
                content = file.read().decode('utf-8')
                urls = [line.strip() for line in content.split('\n') if line.strip() and not line.startswith('#')]
                
                if not urls:
                    return jsonify({'error': 'No valid URLs found in file'}), 400
                
                # Analyze URLs
                results = analyzer.analyze_urls(urls, verbose=False)
                summary = analyzer.generate_enhanced_summary(results)
                
                # Save to dashboard
                dashboard.add_analysis_batch(results, summary)
                
                # Convert to JSON
                json_results = []
                for result in results:
                    json_result = {
                        'url': result.url,
                        'status': result.status,
                        'risk_score': result.risk_score,
                        'risk_level': result.risk_level,
                        'factors': result.factors,
                        'emoji': result.emoji,
                        'entropy_score': result.entropy_score,
                        'threat_indicators': result.threat_indicators
                    }
                    json_results.append(json_result)
                
                return jsonify({
                    'results': json_results,
                    'summary': summary,
                    'filename': secure_filename(file.filename)
                })
            else:
                return jsonify({'error': 'Only .txt files are supported'}), 400
                
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/export/<format>')
    def export_results(format):
        """Export analysis results"""
        try:
            if format not in ['csv', 'json']:
                return jsonify({'error': 'Invalid format'}), 400
            
            # Get recent results from dashboard
            if not dashboard.analysis_history:
                return jsonify({'error': 'No analysis data to export'}), 400
            
            latest_batch = dashboard.analysis_history[-1]
            results = latest_batch.get('results', [])
            
            if format == 'csv':
                # Create CSV
                df = pd.DataFrame(results)
                
                # Create temporary file
                with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                    df.to_csv(f.name, index=False)
                    temp_filename = f.name
                
                return send_file(
                    temp_filename,
                    as_attachment=True,
                    download_name=f'url_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
                    mimetype='text/csv'
                )
            
            elif format == 'json':
                # Create JSON
                export_data = {
                    'timestamp': latest_batch['timestamp'],
                    'summary': latest_batch.get('summary', {}),
                    'results': results
                }
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                    json.dump(export_data, f, indent=2, default=str)
                    temp_filename = f.name
                
                return send_file(
                    temp_filename,
                    as_attachment=True,
                    download_name=f'url_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json',
                    mimetype='application/json'
                )
                
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/threat-intelligence/<path:url>')
    def get_threat_intelligence(url):
        """Get threat intelligence for specific URL"""
        try:
            results = threat_intel.get_url_reputation(url)
            return jsonify([{
                'source': r.source,
                'is_malicious': r.is_malicious,
                'categories': r.categories,
                'confidence': r.confidence,
                'details': r.details
            } for r in results])
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.errorhandler(413)
    def too_large(e):
        return jsonify({'error': 'File too large. Maximum size is 16MB.'}), 413
    
    return app

# HTML Templates (you would normally put these in templates/ folder)
INDEX_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Advanced URL Security Analyzer v2.0</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        .gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .card-hover { transition: transform 0.2s, box-shadow 0.2s; }
        .card-hover:hover { transform: translateY(-5px); box-shadow: 0 10px 25px rgba(0,0,0,0.15); }
        .risk-critical { border-left: 5px solid #dc3545; background: rgba(220, 53, 69, 0.1); }
        .risk-high { border-left: 5px solid #fd7e14; background: rgba(253, 126, 20, 0.1); }
        .risk-medium { border-left: 5px solid #ffc107; background: rgba(255, 193, 7, 0.1); }
        .risk-low { border-left: 5px solid #17a2b8; background: rgba(23, 162, 184, 0.1); }
        .risk-minimal { border-left: 5px solid #28a745; background: rgba(40, 167, 69, 0.1); }
        .risk-safe { border-left: 5px solid #6c757d; background: rgba(108, 117, 125, 0.1); }
        .threat-tag { font-size: 0.75rem; margin: 2px; }
        .loading-spinner { animation: spin 1s linear infinite; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark gradient-bg">
        <div class="container">
            <a class="navbar-brand fw-bold" href="/">🛡️ URL Security Analyzer v2.0</a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="/dashboard"><i class="bi bi-graph-up"></i> Dashboard</a>
            </div>
        </div>
    </nav>

    <div class="container py-4">
        <div class="row">
            <div class="col-lg-8 mx-auto">
                <div class="card shadow-lg card-hover">
                    <div class="card-header gradient-bg text-white">
                        <h5 class="mb-0"><i class="bi bi-shield-check"></i> Advanced URL Analysis</h5>
                    </div>
                    <div class="card-body">
                        <form id="analyzeForm">
                            <div class="mb-3">
                                <label for="urls" class="form-label">URLs to Analyze</label>
                                <textarea class="form-control" id="urls" rows="6" 
                                    placeholder="Enter URLs (one per line):&#10;https://example.com&#10;http://suspicious-site.com&#10;https://download.example.com/file.exe"></textarea>
                            </div>
                            
                            <div class="row mb-3">
                                <div class="col-md-6">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="threatIntel" checked>
                                        <label class="form-check-label" for="threatIntel">
                                            <i class="bi bi-shield-exclamation"></i> Threat Intelligence
                                        </label>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="advancedAnalysis" checked>
                                        <label class="form-check-label" for="advancedAnalysis">
                                            <i class="bi bi-cpu"></i> Advanced Analysis
                                        </label>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                <button type="button" class="btn btn-outline-primary" onclick="loadSampleUrls()">
                                    <i class="bi bi-file-earmark-text"></i> Load Samples
                                </button>
                                <button type="submit" class="btn btn-primary">
                                    <i class="bi bi-search"></i> Analyze URLs
                                </button>
                            </div>
                        </form>
                        
                        <hr>
                        
                        <div class="mb-3">
                            <label for="fileUpload" class="form-label">Upload URL File</label>
                            <input class="form-control" type="file" id="fileUpload" accept=".txt">
                            <div class="form-text">Upload a .txt file with URLs (one per line)</div>
                        </div>
                    </div>
                </div>
                
                <div id="results" class="mt-4" style="display: none;">
                    <div id="loading" class="text-center py-5">
                        <div class="spinner-border text-primary loading-spinner" role="status">
                            <span class="visually-hidden">Loading...</span>
                        </div>
                        <p class="mt-3">🔍 Performing comprehensive security analysis...</p>
                    </div>
                    
                    <div id="summary" class="card shadow-lg mb-4" style="display: none;">
                        <div class="card-header bg-info text-white">
                            <h5 class="mb-0"><i class="bi bi-graph-up"></i> Analysis Summary</h5>
                        </div>
                        <div class="card-body" id="summary-content"></div>
                    </div>
                    
                    <div id="detailed-results"></div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.getElementById('analyzeForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const urls = document.getElementById('urls').value.trim().split('\\n').filter(url => url.trim());
            if (!urls.length) {
                alert('Please enter at least one URL');
                return;
            }
            
            showLoading();
            
            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        urls: urls,
                        threatIntel: document.getElementById('threatIntel').checked,
                        advancedAnalysis: document.getElementById('advancedAnalysis').checked
                    })
                });
                
                const data = await response.json();
                hideLoading();
                
                if (data.error) {
                    showError(data.error);
                    return;
                }
                
                displayResults(data);
                
            } catch (error) {
                hideLoading();
                showError('Network error: ' + error.message);
            }
        });
        
        document.getElementById('fileUpload').addEventListener('change', async function(e) {
            const file = e.target.files[0];
            if (!file) return;
            
            const formData = new FormData();
            formData.append('file', file);
            
            showLoading();
            
            try {
                const response = await fetch('/upload', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                hideLoading();
                
                if (data.error) {
                    showError(data.error);
                    return;
                }
                
                displayResults(data);
                
            } catch (error) {
                hideLoading();
                showError('Upload error: ' + error.message);
            }
        });
        
        function showLoading() {
            document.getElementById('results').style.display = 'block';
            document.getElementById('loading').style.display = 'block';
            document.getElementById('summary').style.display = 'none';
            document.getElementById('detailed-results').innerHTML = '';
        }
        
        function hideLoading() {
            document.getElementById('loading').style.display = 'none';
        }
        
        function showError(message) {
            document.getElementById('detailed-results').innerHTML = 
                `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle"></i> ${message}</div>`;
        }
        
        function displayResults(data) {
            displaySummary(data.summary);
            displayDetailedResults(data.results);
        }
        
        function displaySummary(summary) {
            const total = summary.total || 0;
            const critical = summary.critical || 0;
            const high = summary.high || 0;
            
            document.getElementById('summary-content').innerHTML = `
                <div class="row text-center mb-3">
                    <div class="col-md-2"><h4 class="text-muted">${total}</h4><small>Total</small></div>
                    <div class="col-md-2"><h4 class="text-danger">${critical}</h4><small>Critical</small></div>
                    <div class="col-md-2"><h4 class="text-warning">${high}</h4><small>High</small></div>
                    <div class="col-md-2"><h4 class="text-info">${summary.medium || 0}</h4><small>Medium</small></div>
                    <div class="col-md-2"><h4 class="text-success">${summary.low || 0}</h4><small>Low</small></div>
                    <div class="col-md-2"><h4 class="text-secondary">${summary.safe || 0}</h4><small>Safe</small></div>
                </div>
                ${critical + high > 0 ? 
                    `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle"></i> 
                     <strong>Security Alert:</strong> ${critical + high} URLs require immediate attention!</div>` : 
                    `<div class="alert alert-success"><i class="bi bi-check-circle"></i> 
                     <strong>All Clear:</strong> No high-risk URLs detected.</div>`
                }
                <div class="d-flex gap-2 justify-content-end">
                    <a href="/export/csv" class="btn btn-outline-primary btn-sm">
                        <i class="bi bi-download"></i> Export CSV
                    </a>
                    <a href="/export/json" class="btn btn-outline-primary btn-sm">
                        <i class="bi bi-download"></i> Export JSON
                    </a>
                </div>
            `;
            document.getElementById('summary').style.display = 'block';
        }
        
        function displayDetailedResults(results) {
            const html = results.map(result => {
                const riskClass = `risk-${result.risk_level.toLowerCase()}`;
                return `
                    <div class="card mb-3 ${riskClass}">
                        <div class="card-body">
                            <h6 class="card-title">
                                ${result.emoji} <strong>${result.risk_level}</strong>
                                ${result.status !== 'SAFE' ? `(${result.risk_score})` : ''}: 
                                <code>${result.url}</code>
                            </h6>
                            ${result.link_classification && result.link_classification.platform ? 
                                `<p class="mb-1"><strong>Platform:</strong> ${result.link_classification.platform}</p>` : ''}
                            ${result.factors && result.factors.length > 0 ? 
                                `<div class="mb-2">
                                    <strong>Risk Factors:</strong>
                                    <ul class="mb-0">
                                        ${result.factors.map(factor => `<li>${factor}</li>`).join('')}
                                    </ul>
                                </div>` : ''}
                            ${result.threat_indicators && result.threat_indicators.length > 0 ? 
                                `<div class="mb-2">
                                    <strong>Threats:</strong>
                                    ${result.threat_indicators.slice(0, 5).map(threat => 
                                        `<span class="badge bg-danger threat-tag">${threat}</span>`
                                    ).join('')}
                                    ${result.threat_indicators.length > 5 ? 
                                        `<span class="badge bg-secondary threat-tag">+${result.threat_indicators.length - 5} more</span>` : ''}
                                </div>` : ''}
                        </div>
                    </div>
                `;
            }).join('');
            
            document.getElementById('detailed-results').innerHTML = html;
        }
        
        function loadSampleUrls() {
            document.getElementById('urls').value = `https://google.com
http://paypal-login.com/verify
https://github.com/microsoft/vscode/releases
http://fake-download.tk/virus.exe
https://youtube.com/watch?v=dQw4w9WgXcQ
http://cryptocurrency-scam.ml/free-bitcoin`;
        }
    </script>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Security Analytics Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        .gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .stat-card { transition: transform 0.2s; }
        .stat-card:hover { transform: translateY(-3px); }
        .chart-container { min-height: 400px; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark gradient-bg">
        <div class="container">
            <a class="navbar-brand fw-bold" href="/">🛡️ URL Security Analyzer v2.0</a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="/"><i class="bi bi-shield-check"></i> Analyzer</a>
                <a class="nav-link active" href="/dashboard"><i class="bi bi-graph-up"></i> Dashboard</a>
            </div>
        </div>
    </nav>

    <div class="container py-4">
        <h2 class="mb-4"><i class="bi bi-graph-up"></i> Security Analytics Dashboard</h2>
        
        <!-- Summary Statistics -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card stat-card bg-primary text-white">
                    <div class="card-body text-center">
                        <h3>{{ stats.total_urls_analyzed or 0 }}</h3>
                        <p class="mb-0">Total URLs Analyzed</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card bg-warning text-white">
                    <div class="card-body text-center">
                        <h3>{{ stats.recent_urls_week or 0 }}</h3>
                        <p class="mb-0">This Week</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card bg-danger text-white">
                    <div class="card-body text-center">
                        <h3>{{ stats.recent_critical_week or 0 }}</h3>
                        <p class="mb-0">Critical Threats</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card stat-card bg-info text-white">
                    <div class="card-body text-center">
                        <h3>{{ stats.total_analysis_batches or 0 }}</h3>
                        <p class="mb-0">Analysis Sessions</p>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Charts Row 1 -->
        <div class="row mb-4">
            <div class="col-lg-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="bi bi-pie-chart"></i> Risk Distribution</h5>
                    </div>
                    <div class="card-body">
                        <div id="riskChart" class="chart-container"></div>
                    </div>
                </div>
            </div>
            <div class="col-lg-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="bi bi-graph-up-arrow"></i> Threat Trends</h5>
                    </div>
                    <div class="card-body">
                        <div id="trendsChart" class="chart-container"></div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Charts Row 2 -->
        <div class="row mb-4">
            <div class="col-lg-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="bi bi-platform"></i> Platform Analysis</h5>
                    </div>
                    <div class="card-body">
                        <div id="platformChart" class="chart-container"></div>
                    </div>
                </div>
            </div>
            <div class="col-lg-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="bi bi-scatter-plot"></i> Entropy Analysis</h5>
                    </div>
                    <div class="card-body">
                        <div id="entropyChart" class="chart-container"></div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Charts Row 3 -->
        <div class="row">
            <div class="col-lg-8">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="bi bi-exclamation-triangle"></i> Top Threat Indicators</h5>
                    </div>
                    <div class="card-body">
                        <div id="threatChart" class="chart-container"></div>
                    </div>
                </div>
            </div>
            <div class="col-lg-4">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="bi bi-folder"></i> Content Categories</h5>
                    </div>
                    <div class="card-body">
                        <div id="categoryChart" class="chart-container"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Load all charts
        Promise.all([
            fetch('/api/dashboard/risk-distribution').then(r => r.json()),
            fetch('/api/dashboard/threat-trends').then(r => r.json()),
            fetch('/api/dashboard/platform-analysis').then(r => r.json()),
            fetch('/api/dashboard/entropy-analysis').then(r => r.json()),
            fetch('/api/dashboard/threat-indicators').then(r => r.json()),
            fetch('/api/dashboard/content-categories').then(r => r.json())
        ]).then(([risk, trends, platform, entropy, threats, categories]) => {
            Plotly.newPlot('riskChart', risk.data, risk.layout, {responsive: true});
            Plotly.newPlot('trendsChart', trends.data, trends.layout, {responsive: true});
            Plotly.newPlot('platformChart', platform.data, platform.layout, {responsive: true});
            Plotly.newPlot('entropyChart', entropy.data, entropy.layout, {responsive: true});
            Plotly.newPlot('threatChart', threats.data, threats.layout, {responsive: true});
            Plotly.newPlot('categoryChart', categories.data, categories.layout, {responsive: true});
        }).catch(error => {
            console.error('Error loading charts:', error);
        });
        
        // Auto-refresh every 5 minutes
        setInterval(() => {
            location.reload();
        }, 5 * 60 * 1000);
    </script>
</body>
</html>
"""

# Save templates to files (Flask expects them in templates/ folder)
def setup_templates():
    """Setup Flask templates"""
    import os
    
    templates_dir = 'templates'
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)
    
    try:
        with open(os.path.join(templates_dir, 'index.html'), 'w', encoding='utf-8') as f:
            f.write(INDEX_TEMPLATE)
        
        with open(os.path.join(templates_dir, 'dashboard.html'), 'w', encoding='utf-8') as f:
            f.write(DASHBOARD_TEMPLATE)
    except Exception as e:
        print(f"Warning: Could not setup templates: {e}")

# Auto-setup templates when module is imported
try:
    setup_templates()
except Exception as e:
    print(f"Warning: Template setup failed: {e}")
