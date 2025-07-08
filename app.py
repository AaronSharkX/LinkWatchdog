
#!/usr/bin/env python3
"""
Simple startup file for deployment
"""
import os
import sys
from main import AdvancedURLSecurityAnalyzer

def create_app():
    """Create Flask app for deployment"""
    try:
        from web_interface import create_enhanced_web_app
        analyzer = AdvancedURLSecurityAnalyzer(enable_network=True)
        app = create_enhanced_web_app(analyzer)
        return app
    except ImportError as e:
        print(f"Error importing web interface: {e}")
        return None

app = create_app()

if __name__ == '__main__':
    if app:
        port = int(os.environ.get('PORT', 5000))
        print(f"🚀 Starting URL Security Analyzer on port {port}")
        app.run(host='0.0.0.0', port=port, debug=False)
    else:
        print("❌ Failed to create app")
        sys.exit(1)
