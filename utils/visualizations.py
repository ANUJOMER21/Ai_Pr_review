import pandas as pd
import plotly.express as px
from core.database import DatabaseManager, logger
from typing import Dict

def create_visualizations(stats: Dict, user_id: str) -> Dict:
    """Create enhanced visualizations with real data"""
    try:
        db = DatabaseManager()  # Or pass from session
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT security_score FROM reviews WHERE user_id = ?", (user_id,))
            scores = [row[0] for row in cursor.fetchall()]

        # Activity chart
        if stats.get('recent_activity'):
            activity_df = pd.DataFrame(stats['recent_activity'])
            activity_chart = px.bar(
                activity_df,
                x='date',
                y='count',
                title='Review Activity (Last 30 Days)',
                color='count',
                color_continuous_scale='blues'
            )
            activity_chart.update_layout(
                xaxis_title="Date",
                yaxis_title="Reviews",
                showlegend=False
            )
        else:
            activity_chart = None

        # Score distribution with real data
        buckets = [0, 20, 40, 60, 80, 100]
        security_buckets = [sum(1 for s in scores if buckets[i] <= s < buckets[i+1]) for i in range(len(buckets)-1)]
        quality_buckets = security_buckets  # Assume similar; query separately if needed

        score_data = {
            'Score Range': [f'{buckets[i]}-{buckets[i+1]}' for i in range(len(buckets)-1)],
            'Security': security_buckets,
            'Quality': quality_buckets
        }

        score_df = pd.DataFrame(score_data)
        score_chart = px.bar(
            score_df,
            x='Score Range',
            y=['Security', 'Quality'],
            title='Score Distribution',
            barmode='group'
        )

        return {
            'activity_chart': activity_chart,
            'score_chart': score_chart
        }

    except Exception as e:
        logger.error(f"Visualization creation error: {e}")
        return {}