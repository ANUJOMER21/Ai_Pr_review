from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import io
from typing import List, Dict
from datetime import datetime

def generate_review_report(reviews: List[Dict], user: Dict) -> bytes:
    """Generate a PDF report of reviews"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    title = Paragraph(f"AI PR Review Report for {user['username']}", styles['Title'])
    story.append(title)

    # Summary stats
    stats = {}  # Assume get_review_statistics(user['id']) - pass if needed
    summary_data = [
        ['Metric', 'Value'],
        ['Total Reviews', len(reviews)],
        ['Avg Security Score', 'N/A'],  # Compute if stats passed
        ['Avg Quality Score', 'N/A'],
        ['Total Vulnerabilities', sum(r['vulnerabilities_count'] for r in reviews)]
    ]
    summary_table = Table(summary_data)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(summary_table)

    # Reviews table
    review_data = [['Repo/PR', 'Title', 'Security', 'Quality', 'Vulns', 'Issues']]
    for r in reviews[:20]:  # Limit to 20
        review_data.append([
            f"{r['repo_name']} #{r['pr_number']}",
            r['pr_title'][:50] + '...' if len(r['pr_title']) > 50 else r['pr_title'],
            r['security_score'],
            r['quality_score'],
            r['vulnerabilities_count'],
            r['issues_count']
        ])
    reviews_table = Table(review_data)
    reviews_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(reviews_table)

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()