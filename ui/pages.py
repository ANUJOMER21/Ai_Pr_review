import anthropic
import streamlit as st
import pandas as pd
import plotly.express as px
import asyncio
import concurrent.futures
from datetime import datetime
from typing import Dict, List

from core.models import User
from services.ai_reviewer import EnhancedAIReviewer
from services.github_manager import EnhancedGitHubManager, logger
from ui.components import format_review_text, show_review_modal
from utils.report import generate_review_report
from utils.visualizations import create_visualizations


def main_pages(user: User):
    """Main navigation and page rendering"""
    # Sidebar
    with st.sidebar:
        st.markdown('<div class="sidebar-logo"><h2>🤖 AI PR Dashboard</h2></div>', unsafe_allow_html=True)

        # User info
        st.markdown(f"**Welcome, {user.username}!** 👋")
        st.markdown(f"*{user.role.title()}*")

        # Notifications
        notifications = st.session_state.notification_manager.get_user_notifications(user.id, unread_only=True)
        if notifications:
            st.markdown(f'**Notifications** <span class="notification-badge">{len(notifications)}</span>',
                        unsafe_allow_html=True)

            with st.expander("View Notifications"):
                for notif in notifications[:5]:
                    st.markdown(f"**{notif['title']}**")
                    st.markdown(notif['message'])
                    if st.button(f"Mark Read", key=f"notif_{notif['id']}"):
                        st.session_state.notification_manager.mark_notification_read(notif['id'])
                        st.session_state.notifications = st.session_state.notification_manager.get_user_notifications(user.id, unread_only=True)  # Reload
                        st.rerun()
                    st.markdown("---")

        # Navigation
        st.markdown("### Navigation")
        pages = [
            "🏠 Dashboard",
            "📁 Repositories",
            "🔄 Pull Requests",
            "📋 Reviews",
            "📊 Analytics",
            "👥 Team",
            "⚙️ Settings"
        ]

        selected_page = st.selectbox("Go to:", pages, index=pages.index(st.session_state.selected_page), key="navigation")
        st.session_state.selected_page = selected_page

        # Quick stats
        user_stats = st.session_state.review_manager.get_review_statistics(user.id)
        if user_stats.get('total_reviews', 0) > 0:
            st.markdown("### Quick Stats")
            st.metric("Reviews", user_stats['total_reviews'])
            st.metric("Avg Security", f"{user_stats['avg_security_score']}/100")
            st.metric("Repositories", user_stats['total_repos'])

        # Logout
        if st.button("🚪 Logout"):
            st.session_state.user_manager.logout_user(st.session_state.session_id)
            for key in list(st.session_state.keys()):
                if key not in ['db_manager', 'user_manager', 'auth_manager', 'notification_manager', 'review_manager']:
                    del st.session_state[key]
            st.rerun()

    # Main content
    if selected_page == "🏠 Dashboard":
        show_dashboard_page(user)
    elif selected_page == "📁 Repositories":
        show_repositories_page(user)
    elif selected_page == "🔄 Pull Requests":
        show_pull_requests_page(user)
    elif selected_page == "📋 Reviews":
        show_reviews_page(user)
    elif selected_page == "📊 Analytics":
        show_analytics_page(user)
    elif selected_page == "👥 Team":
        show_team_page(user)
    elif selected_page == "⚙️ Settings":
        show_settings_page(user)

def show_dashboard_page(user: User):
    """Enhanced dashboard page"""
    st.markdown(
        '<div class="main-header"><h1>🤖 AI-Powered PR Review Dashboard</h1><p>Welcome back! Here\'s your overview.</p></div>',
        unsafe_allow_html=True)

    # Get user statistics
    stats = st.session_state.review_manager.get_review_statistics(user.id)

    if stats.get('total_reviews', 0) > 0:
        # Key metrics
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric(
                "Total Reviews",
                stats['total_reviews'],
                delta=f"Since {stats.get('first_review', 'N/A')[:10] if stats.get('first_review') else 'N/A'}"
            )

        with col2:
            st.metric(
                "Security Score",
                f"{stats['avg_security_score']}/100",
                delta=f"{stats['total_vulnerabilities']} vulnerabilities found"
            )

        with col3:
            st.metric(
                "Quality Score",
                f"{stats['avg_quality_score']}/100",
                delta=f"{stats['total_issues']} issues identified"
            )

        with col4:
            st.metric(
                "AI Confidence",
                f"{int(stats['avg_confidence'] * 100)}%",
                delta=f"{stats['total_repos']} repositories"
            )

        # Visualizations (with real data)
        charts = create_visualizations(stats, user.id)

        if charts.get('activity_chart'):
            st.plotly_chart(charts['activity_chart'], use_container_width=True)

        if charts.get('score_chart'):
            st.plotly_chart(charts['score_chart'], use_container_width=True)

        # Recent reviews
        st.subheader("📈 Recent Activity")
        recent_reviews = st.session_state.review_manager.get_user_reviews(user.id, limit=5)

        for review in recent_reviews:
            with st.container():
                col1, col2, col3, col4 = st.columns([3, 1, 1, 1])

                with col1:
                    st.markdown(f"**[{review['repo_name']}]({review['pr_url']})** - PR #{review['pr_number']}")
                    st.markdown(f"_{review['pr_title']}_")
                    st.markdown(f"👤 {review['pr_author']} • 📅 {review['updated_at'][:10]}")

                with col2:
                    security_color = "success" if review['security_score'] >= 80 else "warning" if review['security_score'] >= 60 else "danger"
                    st.markdown(f'<span class="{security_color}-badge">🔒 {review["security_score"]}/100</span>',
                                unsafe_allow_html=True)

                with col3:
                    quality_color = "success" if review['quality_score'] >= 80 else "warning" if review['quality_score'] >= 60 else "danger"
                    st.markdown(f'<span class="{quality_color}-badge">⚡ {review["quality_score"]}/100</span>',
                                unsafe_allow_html=True)

                with col4:
                    confidence_color = "success" if review['ai_confidence'] >= 0.8 else "warning" if review['ai_confidence'] >= 0.6 else "danger"
                    st.markdown(
                        f'<span class="{confidence_color}-badge">🤖 {int(review["ai_confidence"] * 100)}%</span>',
                        unsafe_allow_html=True)

                st.markdown("---")

        # Quick actions
        st.subheader("🚀 Quick Actions")
        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button("🔄 Review Latest PRs", type="primary"):
                st.session_state.selected_page = "🔄 Pull Requests"
                st.rerun()

        with col2:
            if st.button("📊 View Analytics"):
                st.session_state.selected_page = "📊 Analytics"
                st.rerun()

        with col3:
            if st.button("⚙️ Configure APIs"):
                st.session_state.selected_page = "⚙️ Settings"
                st.rerun()

    else:
        st.info("👋 Welcome! Let's get started by configuring your GitHub and Claude API keys in Settings.")
        if st.button("⚙️ Go to Settings", type="primary"):
            st.session_state.selected_page = "⚙️ Settings"
            st.rerun()

def show_repositories_page(user: User):
    """Enhanced repositories page"""
    st.header("📁 Your Repositories")

    # Check if GitHub token is configured
    github_token = st.session_state.auth_manager.get_api_key(user.id, 'github')

    if not github_token:
        st.warning("⚠️ Please configure your GitHub token in Settings to view repositories.")
        if st.button("⚙️ Go to Settings"):
            st.session_state.selected_page = "⚙️ Settings"
            st.rerun()
        return

    try:
        github_manager = EnhancedGitHubManager(github_token)

        # Filters and options
        col1, col2, col3, col4 = st.columns([3, 1, 1, 1])

        with col1:
            search_term = st.text_input("🔍 Search repositories", placeholder="Enter repository name...")

        with col2:
            include_private = st.checkbox("Private repos", value=False)

        with col3:
            include_forks = st.checkbox("Include forks", value=False)

        with col4:
            sort_by = st.selectbox("Sort by", ["Updated", "Stars", "Name"])

        # Fetch repositories
        cache_key = f'repos_{user.id}_{include_private}_{include_forks}'
        if st.button("🔄 Refresh Repositories") or cache_key not in st.session_state:
            with st.spinner("Fetching repositories..."):
                try:
                    repos = github_manager.fetch_repositories(include_private, include_forks)
                    st.session_state[cache_key] = repos
                    st.success(f"✅ Found {len(repos)} repositories")
                except Exception as e:
                    st.error(f"❌ Error fetching repositories: {str(e)}")
                    return

        if cache_key in st.session_state:
            repos = st.session_state[cache_key]

            # Apply filters
            if search_term:
                repos = [repo for repo in repos if search_term.lower() in repo['name'].lower()]

            # Apply sorting
            if sort_by == "Stars":
                repos = sorted(repos, key=lambda x: x['stars'], reverse=True)
            elif sort_by == "Name":
                repos = sorted(repos, key=lambda x: x['name'].lower())

            if repos:
                # Repository grid
                for i in range(0, len(repos), 2):
                    col1, col2 = st.columns(2)

                    for j, col in enumerate([col1, col2]):
                        if i + j < len(repos):
                            repo = repos[i + j]

                            with col:
                                with st.container():
                                    st.markdown(f"""
                                    <div class="pr-card">
                                        <h4>📁 <a href="{repo['url']}" target="_blank">{repo['name']}</a></h4>
                                        <p>{repo['description'][:100]}{'...' if len(repo['description']) > 100 else ''}</p>
                                        <div style="display: flex; gap: 10px; margin: 10px 0;">
                                            <span class="success-badge">⭐ {repo['stars']}</span>
                                            <span class="warning-badge">🍴 {repo['forks']}</span>
                                            <span class="danger-badge">🐛 {repo['open_issues']}</span>
                                        </div>
                                        <p><strong>Language:</strong> {repo['language']}</p>
                                        <p><strong>Updated:</strong> {repo['updated_at'][:10]}</p>
                                    </div>
                                    """, unsafe_allow_html=True)

                                    if st.button(f"🔄 View PRs", key=f"view_prs_{repo['full_name']}"):
                                        st.session_state.selected_repo = repo['full_name']
                                        st.session_state.selected_page = "🔄 Pull Requests"
                                        st.rerun()
            else:
                st.info("No repositories found matching your criteria.")

    except Exception as e:
        st.error(f"❌ Error: {str(e)}")
        logger.error(f"Repository page error: {e}")

def show_pull_requests_page(user: User):
    """Enhanced pull requests page"""
    st.header("🔄 Pull Requests")

    # Check API keys
    github_token = st.session_state.auth_manager.get_api_key(user.id, 'github')
    claude_key = st.session_state.auth_manager.get_api_key(user.id, 'claude')

    if not github_token or not claude_key:
        st.warning("⚠️ Please configure your GitHub and Claude API keys in Settings.")
        if st.button("⚙️ Go to Settings"):
            st.session_state.selected_page = "⚙️ Settings"
            st.rerun()
        return

    try:
        github_manager = EnhancedGitHubManager(github_token)
        ai_reviewer = EnhancedAIReviewer(claude_key)

        # Repository selection
        if f'repos_{user.id}' not in st.session_state:
            with st.spinner("Loading repositories..."):
                st.session_state[f'repos_{user.id}'] = github_manager.fetch_repositories()

        if st.session_state[f'repos_{user.id}']:
            repo_names = [repo['full_name'] for repo in st.session_state[f'repos_{user.id}']]

            col1, col2, col3 = st.columns([2, 1, 1])

            with col1:
                selected_repo = st.selectbox(
                    "Select Repository",
                    repo_names,
                    index=repo_names.index(st.session_state.get('selected_repo', repo_names[0]))
                    if st.session_state.get('selected_repo') in repo_names else 0
                )

            with col2:
                pr_state = st.selectbox("PR State", ["open", "closed", "all"], index=0)

            with col3:
                auto_review = st.checkbox("Auto-review new PRs", value=False)

            # Fetch PRs (handle "all")
            cache_key = f'prs_{selected_repo}_{pr_state}'
            if st.button("🔄 Fetch Pull Requests") or cache_key not in st.session_state:
                with st.spinner("Fetching pull requests..."):
                    try:
                        if pr_state == "all":
                            open_prs = github_manager.fetch_pull_requests(selected_repo, "open")
                            closed_prs = github_manager.fetch_pull_requests(selected_repo, "closed")
                            prs = open_prs + closed_prs
                        else:
                            prs = github_manager.fetch_pull_requests(selected_repo, pr_state)
                        st.session_state[cache_key] = prs
                        st.success(f"✅ Found {len(prs)} pull requests")

                        # Create notification
                        st.session_state.notification_manager.create_notification(
                            user.id, "PRs Fetched", f"Found {len(prs)} PRs in {selected_repo}"
                        )

                    except Exception as e:
                        st.error(f"❌ Error fetching PRs: {str(e)}")
                        return

            if cache_key in st.session_state:
                prs = st.session_state[cache_key]

                if prs:
                    # PR filters
                    col1, col2, col3 = st.columns(3)

                    with col1:
                        author_filter = st.multiselect(
                            "Filter by Author",
                            list(set(pr['author'] for pr in prs))
                        )

                    with col2:
                        size_filter = st.selectbox(
                            "Size Filter",
                            ["All", "Small (<100 changes)", "Medium (100-500)", "Large (>500)"]
                        )

                    with col3:
                        review_status_filter = st.selectbox(
                            "Review Status",
                            ["All", "Needs Review", "Reviewed", "Approved"]
                        )

                    # Apply filters
                    filtered_prs = prs

                    if author_filter:
                        filtered_prs = [pr for pr in filtered_prs if pr['author'] in author_filter]

                    if size_filter != "All":
                        total_changes = [pr['additions'] + pr['deletions'] for pr in filtered_prs]
                        if size_filter == "Small (<100 changes)":
                            filtered_prs = [pr for pr in filtered_prs if total_changes[filtered_prs.index(pr)] < 100]
                        elif size_filter == "Medium (100-500)":
                            filtered_prs = [pr for pr in filtered_prs if 100 <= total_changes[filtered_prs.index(pr)] <= 500]
                        elif size_filter == "Large (>500)":
                            filtered_prs = [pr for pr in filtered_prs if total_changes[filtered_prs.index(pr)] > 500]

                    st.write(f"📋 Showing {len(filtered_prs)} pull requests")

                    # Display PRs
                    for pr in filtered_prs:
                        with st.expander(f"PR #{pr['number']}: {pr['title']}", expanded=False):
                            col1, col2 = st.columns([2, 1])

                            with col1:
                                st.markdown(f"**👤 Author:** {pr['author']}")
                                st.markdown(f"**📅 Created:** {pr['created_at']}")
                                st.markdown(f"**🔄 Updated:** {pr['updated_at']}")
                                st.markdown(f"**🔀 Branch:** `{pr['head_branch']}` → `{pr['base_branch']}`")
                                st.markdown(
                                    f"**📊 Changes:** +{pr['additions']} -{pr['deletions']} ({pr['changed_files']} files)")

                                # Labels and assignees
                                if pr.get('labels'):
                                    st.markdown("**🏷️ Labels:** " + ", ".join([f"`{label}`" for label in pr['labels']]))

                                if pr.get('assignees'):
                                    st.markdown("**👥 Assignees:** " + ", ".join(pr['assignees']))

                                if pr['body']:
                                    with st.expander("📄 Description"):
                                        st.markdown(pr['body'])

                            with col2:
                                # Status badges
                                state_color = "success" if pr['state'] == "open" else "secondary"
                                st.markdown(f'<span class="{state_color}-badge">{pr["state"].upper()}</span>',
                                            unsafe_allow_html=True)

                                if pr.get('draft'):
                                    st.markdown('<span class="warning-badge">DRAFT</span>', unsafe_allow_html=True)

                                # Review status
                                review_color = "success" if pr['review_status'] == "approved" else "warning" if pr['review_status'] == "changes_requested" else "secondary"
                                st.markdown(f'<span class="{review_color}-badge">{pr["review_status"].upper()}</span>',
                                            unsafe_allow_html=True)

                                # Links
                                st.markdown(f"[🔗 View on GitHub]({pr['url']})")

                                # Check if review exists
                                existing_reviews = st.session_state.review_manager.get_user_reviews(
                                    user.id, selected_repo
                                )
                                existing_review = next((r for r in existing_reviews if r['pr_number'] == pr['number']),
                                                       None)

                                if existing_review:
                                    st.success("✅ Reviewed")
                                    confidence = existing_review.get('ai_confidence', 0)
                                    st.markdown(f"🤖 Confidence: {int(confidence * 100)}%")

                                    if st.button(f"👀 View Review", key=f"view_review_{pr['number']}"):
                                        st.session_state.selected_review = existing_review
                                        st.session_state.show_review_modal = True
                                        st.rerun()
                                else:
                                    if st.button(f"🤖 Generate AI Review", key=f"review_{pr['number']}", type="primary"):
                                        with st.spinner("🔍 Analyzing pull request..."):
                                            try:
                                                # Get PR files
                                                files = github_manager.get_pr_files(selected_repo, pr['number'])

                                                # Generate review asynchronously with ThreadPoolExecutor
                                                def run_async_review():
                                                    loop = asyncio.new_event_loop()
                                                    asyncio.set_event_loop(loop)
                                                    try:
                                                        review_result = loop.run_until_complete(
                                                            ai_reviewer.generate_review_async(
                                                                pr['title'], pr['body'], files, user.preferences
                                                            )
                                                        )
                                                    finally:
                                                        loop.close()
                                                    return review_result

                                                with concurrent.futures.ThreadPoolExecutor() as executor:
                                                    future = executor.submit(run_async_review)
                                                    review_result = future.result()

                                                # Format review text (with truncation note)
                                                review_text = format_review_text(pr, review_result, files)

                                                # Save review
                                                success = st.session_state.review_manager.save_review(
                                                    user.id, selected_repo, pr['number'], pr['title'],
                                                    pr['author'], pr['url'], review_result, review_text
                                                )

                                                if success:
                                                    st.success("✅ Review generated and saved!")

                                                    # Create notification
                                                    st.session_state.notification_manager.create_notification(
                                                        user.id, "Review Completed",
                                                        f"AI review completed for PR #{pr['number']} in {selected_repo}"
                                                    )

                                                    st.rerun()
                                                else:
                                                    st.error("❌ Failed to save review")

                                            except Exception as e:
                                                st.error(f"❌ Review generation failed: {str(e)}")
                                                logger.error(f"Review generation error: {e}")

                else:
                    st.info("No pull requests found.")

    except Exception as e:
        st.error(f"❌ Error: {str(e)}")
        logger.error(f"Pull requests page error: {e}")

    # Show review modal if requested
    if st.session_state.get('show_review_modal', False):
        show_review_modal(st.session_state.selected_review)

def show_reviews_page(user: User):
    """Enhanced reviews page"""
    st.header("📋 Your Reviews")

    # Filters
    col1, col2, col3 = st.columns(3)

    with col1:
        repo_filter = st.text_input("🔍 Filter by repository", placeholder="e.g., username/repo-name")

    with col2:
        score_filter = st.selectbox("Score Range", ["All", "High (80-100)", "Medium (60-79)", "Low (0-59)"])

    with col3:
        sort_by = st.selectbox("Sort by", ["Recent", "Security Score", "Quality Score", "Repository"])

    # Get reviews
    reviews = st.session_state.review_manager.get_user_reviews(user.id, repo_filter if repo_filter else None)

    # Apply filters
    if score_filter != "All":
        if score_filter == "High (80-100)":
            reviews = [r for r in reviews if r['security_score'] >= 80 or r['quality_score'] >= 80]
        elif score_filter == "Medium (60-79)":
            reviews = [r for r in reviews if 60 <= r['security_score'] < 80 or 60 <= r['quality_score'] < 80]
        elif score_filter == "Low (0-59)":
            reviews = [r for r in reviews if r['security_score'] < 60 or r['quality_score'] < 60]

    # Sort reviews
    if sort_by == "Security Score":
        reviews = sorted(reviews, key=lambda x: x['security_score'], reverse=True)
    elif sort_by == "Quality Score":
        reviews = sorted(reviews, key=lambda x: x['quality_score'], reverse=True)
    elif sort_by == "Repository":
        reviews = sorted(reviews, key=lambda x: x['repo_name'])

    if reviews:
        st.success(f"📊 Found {len(reviews)} reviews")

        # Bulk actions
        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button("📤 Export All"):
                csv = pd.DataFrame(reviews).to_csv(index=False)
                st.download_button(
                    label="📥 Download CSV",
                    data=csv,
                    file_name=f"reviews_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )

        with col2:
            if st.button("📊 Generate Report"):
                report_data = generate_review_report(reviews, {'username': user.username, 'id': user.id})
                st.download_button(
                    label="📥 Download PDF",
                    data=report_data,
                    file_name=f"review_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf"
                )

        with col3:
            if st.button("🗑️ Clear All", type="secondary"):
                if st.button("⚠️ Confirm Delete", type="secondary"):
                    selected_ids = [r['id'] for r in reviews]
                    success = st.session_state.review_manager.delete_reviews_bulk(user.id, selected_ids)
                    if success:
                        st.success("✅ All reviews deleted!")
                        st.rerun()
                    else:
                        st.error("❌ Delete failed")

        # Display reviews
        for review in reviews:
            with st.container():
                st.markdown(f"""
                <div class="pr-card">
                    <h4>📁 {review['repo_name']} - PR #{review['pr_number']}</h4>
                    <h5>{review['pr_title']}</h5>
                    <p><strong>👤 Author:</strong> {review['pr_author']} • 
                       <strong>📅 Reviewed:</strong> {review['updated_at'][:16]}</p>
                </div>
                """, unsafe_allow_html=True)

                col1, col2, col3, col4, col5 = st.columns(5)

                with col1:
                    st.metric("🔒 Security", f"{review['security_score']}/100")

                with col2:
                    st.metric("⚡ Quality", f"{review['quality_score']}/100")

                with col3:
                    st.metric("🚨 Vulnerabilities", review['vulnerabilities_count'])

                with col4:
                    st.metric("⚠️ Issues", review['issues_count'])

                with col5:
                    st.metric("🤖 Confidence", f"{int(review['ai_confidence'] * 100)}%")

                # Action buttons
                col1, col2, col3 = st.columns([1, 1, 2])

                with col1:
                    if st.button(f"👀 View", key=f"view_{review['id']}"):
                        st.session_state.selected_review = review
                        st.session_state.show_review_modal = True
                        st.rerun()

                with col2:
                    if st.button(f"🔗 Open PR", key=f"open_{review['id']}"):
                        st.markdown(f"[Open PR]({review['pr_url']})")

                with col3:
                    if st.button(f"📤 Export", key=f"export_{review['id']}"):
                        st.download_button(
                            label="📥 Download MD",
                            data=review['review_text'],
                            file_name=f"review_{review['repo_name'].replace('/', '_')}_PR_{review['pr_number']}.md",
                            mime="text/markdown",
                            key=f"download_{review['id']}"
                        )

                st.markdown("---")

    else:
        st.info("📝 No reviews found. Start by reviewing some pull requests!")

def show_analytics_page(user: User):
    """Analytics and insights page"""
    st.header("📊 Analytics & Insights")

    # Get statistics
    stats = st.session_state.review_manager.get_review_statistics(user.id)

    if stats.get('total_reviews', 0) == 0:
        st.info("📈 No data available yet. Complete some reviews to see analytics!")
        return

    # Key insights
    st.subheader("🎯 Key Insights")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Most Secure Repos",
            "Above 80 avg",
            delta="Security focused"
        )

    with col2:
        st.metric(
            "Review Velocity",
            f"{stats.get('total_reviews', 0)} reviews",
            delta="This month"
        )

    with col3:
        st.metric(
            "AI Accuracy",
            f"{int(stats.get('avg_confidence', 0) * 100)}%",
            delta="Confidence score"
        )

    # Create visualizations (real data)
    charts = create_visualizations(stats, user.id)

    # Activity timeline
    if charts.get('activity_chart'):
        st.subheader("📈 Review Activity Timeline")
        st.plotly_chart(charts['activity_chart'], use_container_width=True)

    # Score distribution
    if charts.get('score_chart'):
        st.subheader("📊 Score Distribution")
        st.plotly_chart(charts['score_chart'], use_container_width=True)

    # Repository analysis
    st.subheader("📁 Repository Analysis")
    reviews = st.session_state.review_manager.get_user_reviews(user.id, limit=100)

    if reviews:
        # Group by repository
        repo_stats = {}
        for review in reviews:
            repo = review['repo_name']
            if repo not in repo_stats:
                repo_stats[repo] = {
                    'count': 0,
                    'avg_security': 0,
                    'avg_quality': 0,
                    'total_vulns': 0,
                    'total_issues': 0
                }

            repo_stats[repo]['count'] += 1
            repo_stats[repo]['avg_security'] += review['security_score']
            repo_stats[repo]['avg_quality'] += review['quality_score']
            repo_stats[repo]['total_vulns'] += review['vulnerabilities_count']
            repo_stats[repo]['total_issues'] += review['issues_count']

        # Calculate averages
        for repo in repo_stats:
            count = repo_stats[repo]['count']
            repo_stats[repo]['avg_security'] = round(repo_stats[repo]['avg_security'] / count, 1)
            repo_stats[repo]['avg_quality'] = round(repo_stats[repo]['avg_quality'] / count, 1)

        # Display repository table
        repo_data = []
        for repo, stats_data in repo_stats.items():
            repo_data.append({
                'Repository': repo,
                'Reviews': stats_data['count'],
                'Avg Security': stats_data['avg_security'],
                'Avg Quality': stats_data['avg_quality'],
                'Vulnerabilities': stats_data['total_vulns'],
                'Issues': stats_data['total_issues']
            })

        df = pd.DataFrame(repo_data)
        st.dataframe(df, use_container_width=True)

    # Trends and recommendations
    st.subheader("🔮 Trends & Recommendations")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 📈 Positive Trends")
        st.success("✅ Security scores improving over time")
        st.success("✅ Consistent review activity")
        st.success("✅ High AI confidence levels")

    with col2:
        st.markdown("### ⚠️ Areas for Improvement")
        st.warning("⚠️ Focus on repositories with lower scores")
        st.warning("⚠️ Address recurring vulnerability patterns")
        st.warning("⚠️ Increase review frequency for critical repos")

def show_team_page(user: User):
    """Team collaboration page"""
    st.header("👥 Team Collaboration")

    # Check if user has team access (admin/manager role)
    if user.role not in ['admin', 'manager']:
        st.warning("🔒 Team features require manager or admin privileges.")
        st.info("Contact your administrator to upgrade your account.")
        return

    # Team overview
    st.subheader("👥 Team Overview")

    # Real stats from DB
    with st.session_state.db_manager.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = TRUE")
        total_members = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(DISTINCT user_id) FROM reviews WHERE user_id IN (SELECT id FROM users WHERE role IN ('user', 'developer'))")
        active_reviewers = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM reviews")
        total_team_reviews = cursor.fetchone()[0]
        cursor.execute("SELECT AVG(security_score), AVG(quality_score) FROM reviews")
        result = cursor.fetchone()
        avg_sec, avg_qual = (result[0] or 0, result[1] or 0)
        team_stats = {
            'total_members': total_members or 0,
            'active_reviewers': active_reviewers or 0,
            'total_team_reviews': total_team_reviews or 0,
            'avg_team_security': round(avg_sec, 1),
            'avg_team_quality': round(avg_qual, 1)
        }

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric("👥 Team Size", team_stats['total_members'])

    with col2:
        st.metric("🔄 Active Reviewers", team_stats['active_reviewers'])

    with col3:
        st.metric("📋 Team Reviews", team_stats['total_team_reviews'])

    with col4:
        st.metric("🔒 Team Security Avg", f"{team_stats['avg_team_security']}/100")

    with col5:
        st.metric("⚡ Team Quality Avg", f"{team_stats['avg_team_quality']}/100")

    # Team members management
    st.subheader("👤 Team Members")

    # Fetch real members
    with st.session_state.db_manager.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT username, email, role, 
                   (SELECT COUNT(*) FROM reviews WHERE user_id = u.id) as reviews,
                   AVG(r.security_score) as avg_score,
                   CASE WHEN last_login > date('now', '-7 days') THEN 'active' ELSE 'inactive' END as status
            FROM users u LEFT JOIN reviews r ON u.id = r.user_id
            GROUP BY u.id ORDER BY reviews DESC
        """)
        columns = [desc[0] for desc in cursor.description]
        team_members = [dict(zip(columns, row)) for row in cursor.fetchall()]

    st.dataframe(pd.DataFrame(team_members), use_container_width=True)

    # Add new member
    with st.expander("➕ Add New Team Member"):
        col1, col2, col3 = st.columns(3)

        with col1:
            new_username = st.text_input("Username")

        with col2:
            new_email = st.text_input("Email")

        with col3:
            new_role = st.selectbox("Role", ["user", "developer", "senior", "manager", "admin"])
            new_password = st.text_input("Password", type="password")  # Added password prompt

        if st.button("Add Member"):
            if not new_password or len(new_password) < 8:
                st.error("Password must be at least 8 characters")
            else:
                success, msg = st.session_state.user_manager.create_user(new_username, new_email, new_password, new_role)
                if success:
                    st.success(f"✅ {msg}")
                    st.session_state.notification_manager.create_notification(
                        user.id, "Team Updated", f"Added {new_username} to team"
                    )
                    st.rerun()
                else:
                    st.error(msg)

    # Bulk actions
    if st.button("🔄 Refresh Team Data"):
        st.rerun()

def show_settings_page(user: User):
    """Settings page for API keys and preferences"""
    st.header("⚙️ Settings")

    tab1, tab2, tab3 = st.tabs(["🔑 API Keys", "🎯 Preferences", "📧 Email Notifications"])

    with tab1:
        st.subheader("API Integrations")
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### GitHub Token")
            github_key = st.text_input("GitHub Personal Access Token", type="password", value="")
            if st.button("Save GitHub Key"):
                if github_key:
                    success = st.session_state.auth_manager.save_api_key(user.id, 'github', github_key)
                    if success:
                        st.success("✅ GitHub key saved!")
                        st.session_state.notification_manager.create_notification(
                            user.id, "API Updated", "GitHub token configured successfully"
                        )
                    else:
                        st.error("❌ Failed to save GitHub key")
                else:
                    st.error("Please enter a token")

        with col2:
            st.markdown("### Claude API Key")
            claude_key = st.text_input("Anthropic Claude API Key", type="password", value="")
            if st.button("Save Claude Key"):
                if claude_key:
                    success = st.session_state.auth_manager.save_api_key(user.id, 'claude', claude_key)
                    if success:
                        st.success("✅ Claude key saved!")
                        st.session_state.notification_manager.create_notification(
                            user.id, "API Updated", "Claude API key configured successfully"
                        )
                    else:
                        st.error("❌ Failed to save Claude key")
                else:
                    st.error("Please enter a key")

        # Test connections
        if st.button("🧪 Test Connections"):
            github_token = st.session_state.auth_manager.get_api_key(user.id, 'github')
            claude_key = st.session_state.auth_manager.get_api_key(user.id, 'claude')
            if github_token:
                try:
                    gh = EnhancedGitHubManager(github_token)
                    st.success("✅ GitHub connected!")
                except:
                    st.error("❌ GitHub test failed")
            if claude_key:
                try:
                    client = anthropic.Anthropic(api_key=claude_key)
                    client.messages.create(model="claude-3-5-sonnet-20241022", max_tokens=1, messages=[{"role": "user", "content": "test"}])
                    st.success("✅ Claude connected!")
                except:
                    st.error("❌ Claude test failed")

    with tab2:
        st.subheader("Review Preferences")
        user_prefs = st.session_state.user_manager.get_preferences(user.id)  # Reload

        focus_security = st.checkbox("Focus on Security", value=user_prefs.get('focus_security', True))
        focus_performance = st.checkbox("Focus on Performance", value=user_prefs.get('focus_performance', False))
        strict_style = st.checkbox("Strict Code Style Checks", value=user_prefs.get('strict_style', False))

        if st.button("Save Preferences"):
            new_prefs = {
                'focus_security': focus_security,
                'focus_performance': focus_performance,
                'strict_style': strict_style
            }
            success = st.session_state.user_manager.update_preferences(user.id, new_prefs)
            if success:
                st.session_state.user = st.session_state.user_manager.get_user_by_session(st.session_state.session_id)  # Reload user
                st.success("✅ Preferences saved!")
                st.session_state.notification_manager.create_notification(
                    user.id, "Preferences Updated", "Review preferences configured"
                )
            else:
                st.error("❌ Failed to save preferences")

    with tab3:
        st.subheader("Email Notifications")
        email_prefs = user_prefs.get('email', {})  # From preferences
        smtp_server = st.text_input("SMTP Server", value=email_prefs.get('smtp_server', ''))
        smtp_port = st.number_input("SMTP Port", value=email_prefs.get('smtp_port', 587))
        smtp_user = st.text_input("SMTP Username", type="password", value=email_prefs.get('smtp_user', ''))
        smtp_pass = st.text_input("SMTP Password", type="password", value="")  # Don't prefill

        if st.button("Save Email Config"):
            email_config = {
                'smtp_server': smtp_server,
                'smtp_port': smtp_port,
                'smtp_user': smtp_user,
                'smtp_pass': smtp_pass  # In prod, encrypt this
            }
            updated_prefs = {**user_prefs, 'email': email_config}
            success = st.session_state.user_manager.update_preferences(user.id, updated_prefs)
            if success:
                st.success("✅ Email config saved!")
            else:
                st.error("❌ Failed to save email config")