
#!/usr/bin/env python3
"""
Setup script for Advanced URL Security Analyzer v2.0
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open('README.md', 'r', encoding='utf-8') as f:
        return f.read()

# Read requirements
def read_requirements():
    with open('requirements.txt', 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="advanced-url-security-analyzer",
    version="2.0.0",
    author="Security Research Team",
    author_email="security@example.com",
    description="Enterprise-grade URL security analysis with AI-powered threat detection",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/username/advanced-url-security-analyzer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "full": [
            "cryptography>=41.0.0",
            "maxminddb>=2.4.0", 
            "yara-python>=4.3.0",
            "selenium>=4.15.0",
            "beautifulsoup4>=4.12.0"
        ],
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.7.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0"
        ]
    },
    entry_points={
        "console_scripts": [
            "url-analyzer=main:main",
            "url-security-analyzer=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.json", "*.txt", "*.md", "templates/*.html", "static/*"],
    },
    keywords="security, url-analysis, phishing-detection, malware-detection, threat-intelligence, cybersecurity",
    project_urls={
        "Bug Reports": "https://github.com/username/advanced-url-security-analyzer/issues",
        "Source": "https://github.com/username/advanced-url-security-analyzer",
        "Documentation": "https://github.com/username/advanced-url-security-analyzer/wiki",
    },
)
