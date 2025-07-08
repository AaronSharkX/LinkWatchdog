
#!/usr/bin/env python3
"""
Analytics Dashboard Module
Provides interactive visualizations and trend analysis
"""

import json
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any
from collections import Counter
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import plotly.utils

class SecurityAnalyticsDashboard:
    """Interactive analytics dashboard for security analysis results"""
    
    def __init__(self):
        self.analysis_history = []
        self.load_history()
    
    def load_history(self):
        """Load historical analysis data"""
        try:
            with open('analysis_history.json', 'r') as f:
                self.analysis_history = json.load(f)
        except FileNotFoundError:
            self.analysis_history = []
    
    def save_history(self):
        """Save analysis history to file"""
        with open('analysis_history.json', 'w') as f:
            json.dump(self.analysis_history, f, indent=2, default=str)
    
    def add_analysis_batch(self, results: List[Any], summary: Dict[str, Any]):
        """Add a batch of analysis results to history"""
        batch_data = {
            'timestamp': datetime.now().isoformat(),
            'total_urls': len(results),
            'summary': summary,
            'results': [self._serialize_result(r) for r in results]
        }
        
        self.analysis_history.append(batch_data)
        self.save_history()
    
    def _serialize_result(self, result) -> Dict[str, Any]:
        """Serialize analysis result for storage"""
        return {
            'url': result.url,
            'risk_score': result.risk_score,
            'risk_level': result.risk_level,
            'status': result.status,
            'entropy_score': result.entropy_score,
            'reputation_score': result.reputation_score,
            'link_type': result.link_classification.primary_type if result.link_classification else None,
            'platform': result.link_classification.platform if result.link_classification else None,
            'content_category': result.link_classification.content_category if result.link_classification else None,
            'threat_indicators': result.threat_indicators,
            'analysis_time': result.analysis_time
        }
    
    def generate_risk_distribution_chart(self) -> str:
        """Generate risk level distribution chart"""
        if not self.analysis_history:
            return self._empty_chart("No analysis data available")
        
        # Aggregate risk levels across all batches
        risk_counts = Counter()
        for batch in self.analysis_history[-10:]:  # Last 10 batches
            summary = batch.get('summary', {})
            risk_counts['Critical'] += summary.get('critical', 0)
            risk_counts['High'] += summary.get('high', 0)
            risk_counts['Medium'] += summary.get('medium', 0)
            risk_counts['Low'] += summary.get('low', 0)
            risk_counts['Minimal'] += summary.get('minimal', 0)
            risk_counts['Safe'] += summary.get('safe', 0)
        
        colors = ['#dc3545', '#fd7e14', '#ffc107', '#17a2b8', '#28a745', '#6c757d']
        
        fig = go.Figure(data=[
            go.Pie(
                labels=list(risk_counts.keys()),
                values=list(risk_counts.values()),
                marker_colors=colors,
                textinfo='label+percent+value',
                textposition='auto',
                hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
            )
        ])
        
        fig.update_layout(
            title="Risk Level Distribution",
            font=dict(size=14),
            showlegend=True,
            height=400
        )
        
        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    
    def generate_threat_trends_chart(self) -> str:
        """Generate threat trends over time"""
        if not self.analysis_history:
            return self._empty_chart("No analysis data available")
        
        # Prepare data for time series
        dates = []
        critical_counts = []
        high_counts = []
        medium_counts = []
        
        for batch in self.analysis_history[-30:]:  # Last 30 batches
            date = datetime.fromisoformat(batch['timestamp']).date()
            summary = batch.get('summary', {})
            
            dates.append(date)
            critical_counts.append(summary.get('critical', 0))
            high_counts.append(summary.get('high', 0))
            medium_counts.append(summary.get('medium', 0))
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=dates, y=critical_counts,
            mode='lines+markers',
            name='Critical',
            line=dict(color='#dc3545', width=3),
            marker=dict(size=8)
        ))
        
        fig.add_trace(go.Scatter(
            x=dates, y=high_counts,
            mode='lines+markers',
            name='High Risk',
            line=dict(color='#fd7e14', width=3),
            marker=dict(size=8)
        ))
        
        fig.add_trace(go.Scatter(
            x=dates, y=medium_counts,
            mode='lines+markers',
            name='Medium Risk',
            line=dict(color='#ffc107', width=3),
            marker=dict(size=8)
        ))
        
        fig.update_layout(
            title="Threat Trends Over Time",
            xaxis_title="Date",
            yaxis_title="Number of URLs",
            font=dict(size=14),
            hovermode='x unified',
            height=400
        )
        
        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    
    def generate_platform_analysis_chart(self) -> str:
        """Generate platform distribution analysis"""
        if not self.analysis_history:
            return self._empty_chart("No analysis data available")
        
        platform_risks = {}
        
        for batch in self.analysis_history[-10:]:
            for result in batch.get('results', []):
                platform = result.get('platform', 'Unknown')
                risk_score = result.get('risk_score', 0)
                
                if platform not in platform_risks:
                    platform_risks[platform] = []
                platform_risks[platform].append(risk_score)
        
        # Calculate average risk score per platform
        platform_avg_risk = {}
        platform_counts = {}
        
        for platform, scores in platform_risks.items():
            if platform != 'Unknown' and scores:
                platform_avg_risk[platform] = sum(scores) / len(scores)
                platform_counts[platform] = len(scores)
        
        if not platform_avg_risk:
            return self._empty_chart("No platform data available")
        
        # Sort by risk score
        sorted_platforms = sorted(platform_avg_risk.items(), key=lambda x: x[1], reverse=True)
        platforms, avg_risks = zip(*sorted_platforms)
        counts = [platform_counts[p] for p in platforms]
        
        # Create color scale based on risk
        colors = ['#dc3545' if r >= 50 else '#ffc107' if r >= 25 else '#28a745' for r in avg_risks]
        
        fig = go.Figure(data=[
            go.Bar(
                x=list(platforms),
                y=list(avg_risks),
                marker_color=colors,
                text=[f'{r:.1f} ({c} URLs)' for r, c in zip(avg_risks, counts)],
                textposition='auto',
                hovertemplate='<b>%{x}</b><br>Avg Risk: %{y:.1f}<br>URLs Analyzed: %{text}<extra></extra>'
            )
        ])
        
        fig.update_layout(
            title="Average Risk Score by Platform",
            xaxis_title="Platform",
            yaxis_title="Average Risk Score",
            font=dict(size=14),
            height=400,
            xaxis_tickangle=-45
        )
        
        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    
    def generate_entropy_analysis_chart(self) -> str:
        """Generate entropy vs risk score correlation"""
        if not self.analysis_history:
            return self._empty_chart("No analysis data available")
        
        entropy_scores = []
        risk_scores = []
        risk_levels = []
        
        for batch in self.analysis_history[-5:]:  # Last 5 batches
            for result in batch.get('results', []):
                entropy = result.get('entropy_score', 0)
                risk = result.get('risk_score', 0)
                level = result.get('risk_level', 'Unknown')
                
                if entropy > 0 and level != 'WHITELISTED':
                    entropy_scores.append(entropy)
                    risk_scores.append(risk)
                    risk_levels.append(level)
        
        if not entropy_scores:
            return self._empty_chart("No entropy data available")
        
        # Color mapping for risk levels
        color_map = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#17a2b8',
            'MINIMAL': '#28a745'
        }
        
        colors = [color_map.get(level, '#6c757d') for level in risk_levels]
        
        fig = go.Figure(data=[
            go.Scatter(
                x=entropy_scores,
                y=risk_scores,
                mode='markers',
                marker=dict(
                    color=colors,
                    size=8,
                    opacity=0.7,
                    line=dict(width=1, color='white')
                ),
                text=risk_levels,
                hovertemplate='<b>Entropy:</b> %{x:.2f}<br><b>Risk Score:</b> %{y}<br><b>Level:</b> %{text}<extra></extra>'
            )
        ])
        
        fig.update_layout(
            title="Entropy vs Risk Score Correlation",
            xaxis_title="Entropy Score",
            yaxis_title="Risk Score",
            font=dict(size=14),
            height=400
        )
        
        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    
    def generate_threat_indicators_chart(self) -> str:
        """Generate top threat indicators chart"""
        if not self.analysis_history:
            return self._empty_chart("No analysis data available")
        
        threat_counter = Counter()
        
        for batch in self.analysis_history[-10:]:
            for result in batch.get('results', []):
                threats = result.get('threat_indicators', [])
                threat_counter.update(threats)
        
        if not threat_counter:
            return self._empty_chart("No threat indicator data available")
        
        # Get top 15 threats
        top_threats = threat_counter.most_common(15)
        threats, counts = zip(*top_threats)
        
        fig = go.Figure(data=[
            go.Bar(
                y=list(threats),
                x=list(counts),
                orientation='h',
                marker_color='#dc3545',
                hovertemplate='<b>%{y}</b><br>Count: %{x}<extra></extra>'
            )
        ])
        
        fig.update_layout(
            title="Top Threat Indicators",
            xaxis_title="Frequency",
            yaxis_title="Threat Type",
            font=dict(size=14),
            height=600,
            margin=dict(l=200)
        )
        
        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    
    def generate_content_category_chart(self) -> str:
        """Generate content category distribution"""
        if not self.analysis_history:
            return self._empty_chart("No analysis data available")
        
        category_risks = {}
        
        for batch in self.analysis_history[-10:]:
            for result in batch.get('results', []):
                category = result.get('content_category', 'Unknown')
                risk_score = result.get('risk_score', 0)
                
                if category and category != 'Unknown':
                    if category not in category_risks:
                        category_risks[category] = []
                    category_risks[category].append(risk_score)
        
        if not category_risks:
            return self._empty_chart("No content category data available")
        
        categories = list(category_risks.keys())
        avg_risks = [sum(scores) / len(scores) for scores in category_risks.values()]
        counts = [len(scores) for scores in category_risks.values()]
        
        # Create subplot with bar chart and box plot
        fig = make_subplots(
            rows=1, cols=2,
            subplot_titles=("Average Risk by Category", "Risk Distribution"),
            specs=[[{"type": "bar"}, {"type": "box"}]]
        )
        
        # Bar chart
        fig.add_trace(
            go.Bar(
                x=categories,
                y=avg_risks,
                name="Average Risk",
                marker_color='#fd7e14',
                text=[f'{r:.1f}' for r in avg_risks],
                textposition='auto'
            ),
            row=1, col=1
        )
        
        # Box plot for risk distribution
        for i, (category, scores) in enumerate(category_risks.items()):
            fig.add_trace(
                go.Box(
                    y=scores,
                    name=category,
                    boxpoints='outliers',
                    marker_color='#17a2b8'
                ),
                row=1, col=2
            )
        
        fig.update_layout(
            title="Content Category Risk Analysis",
            font=dict(size=14),
            height=500,
            showlegend=False
        )
        
        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    
    def _empty_chart(self, message: str) -> str:
        """Generate empty chart with message"""
        fig = go.Figure()
        fig.add_annotation(
            text=message,
            xref="paper", yref="paper",
            x=0.5, y=0.5,
            xanchor='center', yanchor='middle',
            font=dict(size=16, color="gray")
        )
        fig.update_layout(
            xaxis=dict(visible=False),
            yaxis=dict(visible=False),
            height=300
        )
        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics for dashboard"""
        if not self.analysis_history:
            return {}
        
        total_urls = sum(batch.get('total_urls', 0) for batch in self.analysis_history)
        total_batches = len(self.analysis_history)
        
        # Recent activity (last 7 days)
        week_ago = datetime.now() - timedelta(days=7)
        recent_batches = [
            batch for batch in self.analysis_history
            if datetime.fromisoformat(batch['timestamp']) > week_ago
        ]
        
        recent_urls = sum(batch.get('total_urls', 0) for batch in recent_batches)
        recent_critical = sum(batch.get('summary', {}).get('critical', 0) for batch in recent_batches)
        
        # Calculate trends
        if len(self.analysis_history) >= 2:
            current_batch = self.analysis_history[-1].get('summary', {})
            previous_batch = self.analysis_history[-2].get('summary', {})
            
            current_critical = current_batch.get('critical', 0)
            previous_critical = previous_batch.get('critical', 0)
            
            critical_trend = current_critical - previous_critical
        else:
            critical_trend = 0
        
        return {
            'total_urls_analyzed': total_urls,
            'total_analysis_batches': total_batches,
            'recent_urls_week': recent_urls,
            'recent_critical_week': recent_critical,
            'critical_trend': critical_trend,
            'last_analysis': self.analysis_history[-1]['timestamp'] if self.analysis_history else None
        }
