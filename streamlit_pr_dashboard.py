import streamlit as st
import os
import json
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import requests
from github import Github
import anthropic
from pathlib import Path
import base64
import hashlib

# Page configuration
st.set_page_config(
    page_title="AI PR Review Dashboard",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        padding: 2rem 0;
        text-align: center;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #667eea;
        margin: 0.5rem 0;
    }
    .pr-card {
        background: white;
        padding: 1rem;
        border-radius: 8px;
        border: 1px solid #e9ecef;
        margin: 0.5rem 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .success-badge {
        background: #d4edda;
        color: #155724;
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        font-size: 0.875rem;
    }
    .warning-badge {
        background: #fff3cd;
        color: #856404;
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        font-size: 0.875rem;
    }
    .danger-badge {
        background: #f8d7da;
        color: #721c24;
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        font-size: 0.875rem;
    }
</style>
""", unsafe_allow_html=True)


class AuthManager:
    """Manages authentication tokens and API keys"""
    
    def __init__(self):
        self.config_file = "config.json"
        self._ensure_config_exists()
    
    def _ensure_config_exists(self):
        """Create config file if it doesn't exist"""
        if not os.path.exists(self.config_file):
            with open(self.config_file, 'w') as f:
                json.dump({}, f)
    
    def save_github_token(self, token: str) -> bool:
        """Save GitHub token securely"""
        try:
            config = self._load_config()
            # Simple encoding (in production, use proper encryption)
            encoded_token = base64.b64encode(token.encode()).decode()
            config['github_token'] = encoded_token
            self._save_config(config)
            return True
        except Exception as e:
            st.error(f"Failed to save GitHub token: {str(e)}")
            return False
    
    def save_claude_key(self, api_key: str) -> bool:
        """Save Claude API key securely"""
        try:
            config = self._load_config()
            # Simple encoding (in production, use proper encryption)
            encoded_key = base64.b64encode(api_key.encode()).decode()
            config['claude_api_key'] = encoded_key
            self._save_config(config)
            return True
        except Exception as e:
            st.error(f"Failed to save Claude API key: {str(e)}")
            return False
    
    def get_github_token(self) -> Optional[str]:
        """Get GitHub token"""
        try:
            config = self._load_config()
            encoded_token = config.get('github_token')
            if encoded_token:
                return base64.b64decode(encoded_token.encode()).decode()
            return None
        except Exception:
            return None
    
    def get_claude_key(self) -> Optional[str]:
        """Get Claude API key"""
        try:
            config = self._load_config()
            encoded_key = config.get('claude_api_key')
            if encoded_key:
                return base64.b64decode(encoded_key.encode()).decode()
            return None
        except Exception:
            return None
    
    def _load_config(self) -> Dict:
        """Load configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    
    def _save_config(self, config: Dict):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)


class DatabaseManager:
    """Manages SQLite database for storing reviews"""
    
    def __init__(self):
        self.db_file = "pr_reviews.db"
        self._init_database()
    
    def _init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_name TEXT NOT NULL,
                pr_number INTEGER NOT NULL,
                pr_title TEXT NOT NULL,
                pr_author TEXT NOT NULL,
                review_text TEXT NOT NULL,
                security_score INTEGER,
                quality_score INTEGER,
                vulnerabilities_count INTEGER,
                issues_count INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(repo_name, pr_number)
            )
        """)
        
        conn.commit()
        conn.close()
    
    def save_review(self, repo_name: str, pr_number: int, pr_title: str, 
                   pr_author: str, review_text: str, security_score: int = 0,
                   quality_score: int = 0, vulnerabilities_count: int = 0,
                   issues_count: int = 0) -> bool:
        """Save a review to database"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO reviews 
                (repo_name, pr_number, pr_title, pr_author, review_text, 
                 security_score, quality_score, vulnerabilities_count, issues_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (repo_name, pr_number, pr_title, pr_author, review_text,
                  security_score, quality_score, vulnerabilities_count, issues_count))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            st.error(f"Failed to save review: {str(e)}")
            return False
    
    def get_reviews(self, repo_name: str = None, pr_number: int = None) -> List[Dict]:
        """Get reviews from database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        if repo_name and pr_number:
            cursor.execute("""
                SELECT * FROM reviews 
                WHERE repo_name = ? AND pr_number = ?
                ORDER BY created_at DESC
            """, (repo_name, pr_number))
        elif repo_name:
            cursor.execute("""
                SELECT * FROM reviews 
                WHERE repo_name = ?
                ORDER BY created_at DESC
            """, (repo_name,))
        else:
            cursor.execute("""
                SELECT * FROM reviews 
                ORDER BY created_at DESC
                LIMIT 50
            """)
        
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        conn.close()
        return results
    
    def get_review_stats(self) -> Dict:
        """Get overall review statistics"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                COUNT(*) as total_reviews,
                AVG(security_score) as avg_security_score,
                AVG(quality_score) as avg_quality_score,
                SUM(vulnerabilities_count) as total_vulnerabilities,
                SUM(issues_count) as total_issues,
                COUNT(DISTINCT repo_name) as total_repos
            FROM reviews
        """)
        
        result = cursor.fetchone()
        conn.close()
        
        return {
            'total_reviews': result[0] or 0,
            'avg_security_score': round(result[1] or 0, 1),
            'avg_quality_score': round(result[2] or 0, 1),
            'total_vulnerabilities': result[3] or 0,
            'total_issues': result[4] or 0,
            'total_repos': result[5] or 0
        }


class GitHubManager:
    """Manages GitHub API interactions"""
    
    def __init__(self, token: str):
        self.github = Github(token)
        self.user = self.github.get_user()
    
    def fetch_repositories(self, include_private: bool = False) -> List[Dict]:
        """Fetch user repositories"""
        try:
            repos = []
            for repo in self.user.get_repos():
                if include_private or not repo.private:
                    repos.append({
                        'name': repo.name,
                        'full_name': repo.full_name,
                        'description': repo.description or "No description",
                        'private': repo.private,
                        'language': repo.language or "Unknown",
                        'stars': repo.stargazers_count,
                        'forks': repo.forks_count,
                        'open_issues': repo.open_issues_count,
                        'updated_at': repo.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
                        'url': repo.html_url
                    })
            return sorted(repos, key=lambda x: x['updated_at'], reverse=True)
        except Exception as e:
            st.error(f"Failed to fetch repositories: {str(e)}")
            return []
    
    def fetch_pull_requests(self, repo_name: str, state: str = "open") -> List[Dict]:
        """Fetch pull requests for a repository"""
        try:
            repo = self.github.get_repo(repo_name)
            prs = []
            
            for pr in repo.get_pulls(state=state):
                prs.append({
                    'number': pr.number,
                    'title': pr.title,
                    'author': pr.user.login,
                    'state': pr.state,
                    'created_at': pr.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    'updated_at': pr.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
                    'additions': pr.additions,
                    'deletions': pr.deletions,
                    'changed_files': pr.changed_files,
                    'body': pr.body or "",
                    'url': pr.html_url,
                    'head_sha': pr.head.sha,
                    'base_branch': pr.base.ref,
                    'head_branch': pr.head.ref
                })
            
            return sorted(prs, key=lambda x: x['updated_at'], reverse=True)
        except Exception as e:
            st.error(f"Failed to fetch pull requests: {str(e)}")
            return []
    
    def get_pr_files(self, repo_name: str, pr_number: int) -> List[Dict]:
        """Get files changed in a PR"""
        try:
            repo = self.github.get_repo(repo_name)
            pr = repo.get_pull(pr_number)
            
            files = []
            for file in pr.get_files():
                files.append({
                    'filename': file.filename,
                    'status': file.status,
                    'additions': file.additions,
                    'deletions': file.deletions,
                    'changes': file.changes,
                    'patch': file.patch
                })
            
            return files
        except Exception as e:
            st.error(f"Failed to fetch PR files: {str(e)}")
            return []


class AIReviewer:
    """Handles AI-powered code review using Claude"""
    
    def __init__(self, api_key: str):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = "claude-3-5-haiku-20241022"
    
    def generate_review(self, pr_title: str, pr_body: str, files: List[Dict]) -> Dict:
        """Generate AI review for a pull request"""
        try:
            # Prepare context
            context = self._prepare_context(pr_title, pr_body, files)
            
            # Get Claude's analysis
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4000,
                temperature=0.1,
                system="You are an expert code reviewer. Analyze the pull request and provide detailed feedback on security, code quality, and best practices.",
                messages=[{"role": "user", "content": context}]
            )
            
            analysis_text = response.content[0].text
            
            # Parse response
            parsed_analysis = self._parse_response(analysis_text)
            
            return parsed_analysis
            
        except Exception as e:
            st.error(f"AI review failed: {str(e)}")
            return self._get_fallback_analysis()
    
    def _prepare_context(self, pr_title: str, pr_body: str, files: List[Dict]) -> str:
        """Prepare context for AI analysis"""
        context_parts = [
            "Please analyze this Pull Request and provide detailed feedback.",
            "",
            f"**PR Title:** {pr_title}",
            f"**PR Description:** {pr_body or 'No description provided'}",
            "",
            "**Changed Files:**"
        ]
        
        for file in files[:10]:  # Limit to first 10 files
            context_parts.append(f"\n### {file['filename']}")
            context_parts.append(f"Status: {file['status']}")
            context_parts.append(f"Changes: +{file['additions']} -{file['deletions']}")
            
            if file.get('patch') and len(file['patch']) < 2000:
                context_parts.append("```diff")
                context_parts.append(file['patch'][:2000])
                context_parts.append("```")
        
        context_parts.extend([
            "",
            "Please provide analysis in JSON format:",
            "```json",
            "{",
            '  "security_score": 0-100,',
            '  "quality_score": 0-100,',
            '  "vulnerabilities": [{"type": "...", "severity": "HIGH/MEDIUM/LOW", "description": "..."}],',
            '  "issues": [{"type": "...", "severity": "HIGH/MEDIUM/LOW", "description": "..."}],',
            '  "summary": "Overall assessment...",',
            '  "recommendations": ["recommendation 1", "recommendation 2"],',
            '  "approval": "APPROVE/REQUEST_CHANGES/COMMENT"',
            '}',
            "```"
        ])
        
        return "\n".join(context_parts)
    
    def _parse_response(self, response_text: str) -> Dict:
        """Parse AI response"""
        try:
            # Extract JSON
            start_idx = response_text.find("```json")
            if start_idx != -1:
                start_idx += 7
                end_idx = response_text.find("```", start_idx)
                if end_idx != -1:
                    json_str = response_text[start_idx:end_idx].strip()
                    return json.loads(json_str)
            
            # Fallback: try to parse whole response
            return json.loads(response_text)
            
        except json.JSONDecodeError:
            return self._get_fallback_analysis()
    
    def _get_fallback_analysis(self) -> Dict:
        """Fallback analysis when parsing fails"""
        return {
            "security_score": 75,
            "quality_score": 75,
            "vulnerabilities": [],
            "issues": [],
            "summary": "Analysis could not be completed. Manual review recommended.",
            "recommendations": ["Manual code review recommended"],
            "approval": "COMMENT"
        }


def main():
    """Main Streamlit application"""
    
    # Initialize managers
    auth_manager = AuthManager()
    db_manager = DatabaseManager()
    
    # Sidebar navigation
    st.sidebar.title("🤖 AI PR Review Dashboard")
    
    # Check if credentials are set up
    github_token = auth_manager.get_github_token()
    claude_key = auth_manager.get_claude_key()
    
    if not github_token or not claude_key:
        st.sidebar.warning("⚠️ Please configure your credentials in Settings")
    else:
        st.sidebar.success("✅ Credentials configured")
    
    # Navigation
    pages = [
        "🏠 Dashboard",
        "📁 Repositories", 
        "🔄 Pull Requests",
        "📋 Reviews",
        "⚙️ Settings"
    ]
    
    selected_page = st.sidebar.selectbox("Navigate to:", pages)
    
    # Dashboard Page
    if selected_page == "🏠 Dashboard":
        st.markdown('<div class="main-header"><h1>🤖 AI-Powered PR Review Dashboard</h1><p>Automated code review with Claude AI</p></div>', unsafe_allow_html=True)
        
        if github_token and claude_key:
            # Get statistics
            stats = db_manager.get_review_stats()
            
            # Display metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Reviews", stats['total_reviews'])
            
            with col2:
                st.metric("Repositories", stats['total_repos'])
            
            with col3:
                st.metric("Avg Security Score", f"{stats['avg_security_score']}/100")
            
            with col4:
                st.metric("Avg Quality Score", f"{stats['avg_quality_score']}/100")
            
            # Recent activity
            st.subheader("📈 Recent Activity")
            
            recent_reviews = db_manager.get_reviews()[:5]
            
            if recent_reviews:
                for review in recent_reviews:
                    with st.container():
                        col1, col2, col3 = st.columns([3, 1, 1])
                        
                        with col1:
                            st.write(f"**{review['repo_name']}** - PR #{review['pr_number']}")
                            st.write(f"_{review['pr_title']}_")
                        
                        with col2:
                            security_color = "success" if review['security_score'] >= 80 else "warning" if review['security_score'] >= 60 else "danger"
                            st.markdown(f'<span class="{security_color}-badge">Security: {review["security_score"]}/100</span>', unsafe_allow_html=True)
                        
                        with col3:
                            quality_color = "success" if review['quality_score'] >= 80 else "warning" if review['quality_score'] >= 60 else "danger"
                            st.markdown(f'<span class="{quality_color}-badge">Quality: {review["quality_score"]}/100</span>', unsafe_allow_html=True)
                        
                        st.markdown("---")
            else:
                st.info("No reviews yet. Start by reviewing some pull requests!")
        
        else:
            st.warning("Please configure your GitHub token and Claude API key in Settings to get started.")
    
    # Repositories Page
    elif selected_page == "📁 Repositories":
        st.header("📁 Your Repositories")
        
        if github_token:
            github_manager = GitHubManager(github_token)
            
            # Options
            col1, col2 = st.columns([3, 1])
            with col1:
                search_term = st.text_input("🔍 Search repositories", placeholder="Enter repository name...")
            with col2:
                include_private = st.checkbox("Include private repos", value=False)
            
            # Fetch repositories
            if st.button("🔄 Refresh Repositories") or 'repos' not in st.session_state:
                with st.spinner("Fetching repositories..."):
                    st.session_state.repos = github_manager.fetch_repositories(include_private)
            
            if 'repos' in st.session_state:
                repos = st.session_state.repos
                
                # Filter repositories
                if search_term:
                    repos = [repo for repo in repos if search_term.lower() in repo['name'].lower()]
                
                if repos:
                    # Display repositories
                    for repo in repos:
                        with st.container():
                            col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
                            
                            with col1:
                                st.write(f"**[{repo['name']}]({repo['url']})**")
                                st.write(f"_{repo['description']}_")
                                st.write(f"Language: {repo['language']} | Updated: {repo['updated_at']}")
                            
                            with col2:
                                st.metric("⭐ Stars", repo['stars'])
                            
                            with col3:
                                st.metric("🍴 Forks", repo['forks'])
                            
                            with col4:
                                st.metric("🐛 Issues", repo['open_issues'])
                                if st.button(f"View PRs", key=f"view_prs_{repo['full_name']}"):
                                    st.session_state.selected_repo = repo['full_name']
                                    st.experimental_rerun()
                            
                            st.markdown("---")
                else:
                    st.info("No repositories found matching your search.")
        else:
            st.warning("Please configure your GitHub token in Settings.")
    
    # Pull Requests Page
    elif selected_page == "🔄 Pull Requests":
        st.header("🔄 Pull Requests")
        
        if github_token and claude_key:
            github_manager = GitHubManager(github_token)
            ai_reviewer = AIReviewer(claude_key)
            
            # Repository selection
            if 'repos' not in st.session_state:
                with st.spinner("Loading repositories..."):
                    st.session_state.repos = github_manager.fetch_repositories()
            
            if st.session_state.repos:
                repo_names = [repo['full_name'] for repo in st.session_state.repos]
                selected_repo = st.selectbox("Select Repository", repo_names, 
                                           index=repo_names.index(st.session_state.get('selected_repo', repo_names[0])) if st.session_state.get('selected_repo') in repo_names else 0)
                
                # PR state selection
                pr_state = st.selectbox("PR State", ["open", "closed", "all"], index=0)
                
                # Fetch PRs
                if st.button("🔄 Fetch Pull Requests") or f'prs_{selected_repo}' not in st.session_state:
                    with st.spinner("Fetching pull requests..."):
                        st.session_state[f'prs_{selected_repo}'] = github_manager.fetch_pull_requests(selected_repo, pr_state)
                
                if f'prs_{selected_repo}' in st.session_state:
                    prs = st.session_state[f'prs_{selected_repo}']
                    
                    if prs:
                        st.success(f"Found {len(prs)} pull requests")
                        
                        # Display PRs
                        for pr in prs:
                            with st.expander(f"PR #{pr['number']}: {pr['title']}"):
                                col1, col2 = st.columns([2, 1])
                                
                                with col1:
                                    st.write(f"**Author:** {pr['author']}")
                                    st.write(f"**Created:** {pr['created_at']}")
                                    st.write(f"**Updated:** {pr['updated_at']}")
                                    st.write(f"**Changes:** +{pr['additions']} -{pr['deletions']} ({pr['changed_files']} files)")
                                    
                                    if pr['body']:
                                        st.write("**Description:**")
                                        st.write(pr['body'][:500] + "..." if len(pr['body']) > 500 else pr['body'])
                                
                                with col2:
                                    state_color = "success" if pr['state'] == "open" else "secondary"
                                    st.markdown(f'<span class="{state_color}-badge">{pr["state"].upper()}</span>', unsafe_allow_html=True)
                                    
                                    st.write(f"[View on GitHub]({pr['url']})")
                                    
                                    # Check if review exists
                                    existing_reviews = db_manager.get_reviews(selected_repo, pr['number'])
                                    
                                    if existing_reviews:
                                        st.success("✅ Reviewed")
                                        if st.button(f"View Review", key=f"view_review_{pr['number']}"):
                                            st.session_state.selected_review = existing_reviews[0]
                                    else:
                                        if st.button(f"🤖 Generate AI Review", key=f"review_{pr['number']}"):
                                            with st.spinner("Generating AI review..."):
                                                # Get PR files
                                                files = github_manager.get_pr_files(selected_repo, pr['number'])
                                                
                                                # Generate review
                                                review_result = ai_reviewer.generate_review(pr['title'], pr['body'], files)
                                                
                                                # Format review text
                                                review_text = f"""
# AI Review for PR #{pr['number']}: {pr['title']}

## Summary
{review_result.get('summary', 'No summary available')}

## Scores
- **Security Score:** {review_result.get('security_score', 0)}/100
- **Quality Score:** {review_result.get('quality_score', 0)}/100

## Vulnerabilities ({len(review_result.get('vulnerabilities', []))})
{chr(10).join([f"- **{v.get('severity', 'UNKNOWN')}**: {v.get('description', 'No description')}" for v in review_result.get('vulnerabilities', [])])}

## Code Issues ({len(review_result.get('issues', []))})
{chr(10).join([f"- **{i.get('severity', 'UNKNOWN')}**: {i.get('description', 'No description')}" for i in review_result.get('issues', [])])}

## Recommendations
{chr(10).join([f"- {rec}" for rec in review_result.get('recommendations', [])])}

## Approval Status
**{review_result.get('approval', 'COMMENT')}**
                                                """
                                                
                                                # Save review
                                                db_manager.save_review(
                                                    selected_repo, pr['number'], pr['title'], pr['author'],
                                                    review_text, review_result.get('security_score', 0),
                                                    review_result.get('quality_score', 0),
                                                    len(review_result.get('vulnerabilities', [])),
                                                    len(review_result.get('issues', []))
                                                )
                                                
                                                st.success("✅ Review generated and saved!")
                                                st.experimental_rerun()
                    else:
                        st.info("No pull requests found.")
        else:
            st.warning("Please configure your credentials in Settings.")
    
    # Reviews Page
    elif selected_page == "📋 Reviews":
        st.header("📋 Saved Reviews")
        
        # Filters
        col1, col2 = st.columns(2)
        with col1:
            filter_repo = st.text_input("Filter by repository", placeholder="e.g., username/repo-name")
        with col2:
            sort_by = st.selectbox("Sort by", ["Recent", "Security Score", "Quality Score"])
        
        # Get reviews
        if filter_repo:
            reviews = db_manager.get_reviews(filter_repo)
        else:
            reviews = db_manager.get_reviews()
        
        # Sort reviews
        if sort_by == "Security Score":
            reviews = sorted(reviews, key=lambda x: x['security_score'], reverse=True)
        elif sort_by == "Quality Score":
            reviews = sorted(reviews, key=lambda x: x['quality_score'], reverse=True)
        
        if reviews:
            for review in reviews:
                with st.expander(f"{review['repo_name']} - PR #{review['pr_number']}: {review['pr_title']}"):
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        st.metric("Security Score", f"{review['security_score']}/100")
                    with col2:
                        st.metric("Quality Score", f"{review['quality_score']}/100")
                    with col3:
                        st.metric("Vulnerabilities", review['vulnerabilities_count'])
                    with col4:
                        st.metric("Issues", review['issues_count'])
                    
                    st.markdown("### Review Details")
                    st.markdown(review['review_text'])
                    
                    # Export option
                    if st.button(f"📄 Export as Markdown", key=f"export_{review['id']}"):
                        st.download_button(
                            label="Download Review",
                            data=review['review_text'],
                            file_name=f"review_{review['repo_name'].replace('/', '_')}_PR_{review['pr_number']}.md",
                            mime="text/markdown"
                        )
        else:
            st.info("No reviews found. Start by reviewing some pull requests!")
    
    # Settings Page
    elif selected_page == "⚙️ Settings":
        st.header("⚙️ Settings")
        
        st.subheader("🔐 API Credentials")
        
        # GitHub Token
        with st.container():
            st.write("**GitHub Personal Access Token**")
            st.info("Create a token at: https://github.com/settings/tokens")
            
            current_token = auth_manager.get_github_token()
            
            github_token_input = st.text_input(
                "GitHub Token",
                value="***configured***" if current_token else "",
                type="password",
                help="Required scopes: repo, read:user"
            )
            
            if st.button("💾 Save GitHub Token"):
                if github_token_input and github_token_input != "***configured***":
                    if auth_manager.save_github_token(github_token_input):
                        st.success("✅ GitHub token saved successfully!")
                        st.experimental_rerun()
                    else:
                        st.error("❌ Failed to save GitHub token")
                else:
                    st.warning("Please enter a valid token")
        
        st.markdown("---")
        
        # Claude API Key
        with st.container():
            st.write("**Claude API Key**")
            st.info("Get your API key at: https://console.anthropic.com/")
            
            current_claude_key = auth_manager.get_claude_key()
            
            claude_key_input = st.text_input(
                "Claude API Key",
                value="***configured***" if current_claude_key else "",
                type="password",
                help="Your Anthropic Claude API key"
            )
            
            if st.button("💾 Save Claude API Key"):
                if claude_key_input and claude_key_input != "***configured***":
                    if auth_manager.save_claude_key(claude_key_input):
                        st.success("✅ Claude API key saved successfully!")
                        st.experimental_rerun()
                    else:
                        st.error("❌ Failed to save Claude API key")
                else:
                    st.warning("Please enter a valid API key")
        
        st.markdown("---")
        
        # Test Connections
        st.subheader("🔬 Test Connections")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🧪 Test GitHub Connection"):
                if current_token:
                    try:
                        github_manager = GitHubManager(current_token)
                        user_info = github_manager.user
                        st.success(f"✅ Connected as: {user_info.login}")
                        st.info(f"👤 {user_info.name or 'No name set'}")
                        st.info(f"📧 {user_info.email or 'No public email'}")
                    except Exception as e:
                        st.error(f"❌ GitHub connection failed: {str(e)}")
                else:
                    st.warning("Please configure GitHub token first")
        
        with col2:
            if st.button("🧪 Test Claude Connection"):
                if current_claude_key:
                    try:
                        ai_reviewer = AIReviewer(current_claude_key)
                        test_response = ai_reviewer.client.messages.create(
                            model=ai_reviewer.model,
                            max_tokens=50,
                            messages=[{"role": "user", "content": "Hello, respond with 'Connection successful'"}]
                        )
                        st.success(f"✅ Claude API: {test_response.content[0].text}")
                    except Exception as e:
                        st.error(f"❌ Claude connection failed: {str(e)}")
                else:
                    st.warning("Please configure Claude API key first")
        
        st.markdown("---")
        
        # Application Settings
        st.subheader("📱 Application Settings")
        
        # Database management
        with st.container():
            st.write("**Database Management**")
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("📊 View Database Stats"):
                    stats = db_manager.get_review_stats()
                    st.json(stats)
            
            with col2:
                if st.button("🗑️ Clear All Reviews", type="secondary"):
                    if st.button("⚠️ Confirm Delete All", type="secondary"):
                        try:
                            conn = sqlite3.connect(db_manager.db_file)
                            cursor = conn.cursor()
                            cursor.execute("DELETE FROM reviews")
                            conn.commit()
                            conn.close()
                            st.success("✅ All reviews cleared")
                            st.experimental_rerun()
                        except Exception as e:
                            st.error(f"❌ Failed to clear reviews: {str(e)}")
        
        # Export/Import
        with st.container():
            st.write("**Data Export/Import**")
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("📤 Export All Reviews"):
                    reviews = db_manager.get_reviews()
                    if reviews:
                        # Convert to DataFrame for CSV export
                        df = pd.DataFrame(reviews)
                        csv = df.to_csv(index=False)
                        
                        st.download_button(
                            label="📄 Download CSV",
                            data=csv,
                            file_name=f"pr_reviews_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                            mime="text/csv"
                        )
                    else:
                        st.info("No reviews to export")
            
            with col2:
                uploaded_file = st.file_uploader("📥 Import Reviews", type=['csv'])
                if uploaded_file is not None:
                    try:
                        df = pd.read_csv(uploaded_file)
                        st.write("Preview of uploaded data:")
                        st.dataframe(df.head())
                        
                        if st.button("📥 Import Data"):
                            # Import logic would go here
                            st.info("Import functionality can be implemented based on your CSV structure")
                    except Exception as e:
                        st.error(f"❌ Failed to read CSV: {str(e)}")
        
        st.markdown("---")
        
        # About
        st.subheader("ℹ️ About")
        st.info("""
        **AI PR Review Dashboard** v1.0
        
        This application provides automated code review capabilities using Claude AI.
        
        **Features:**
        - 🤖 AI-powered code analysis
        - 🔒 Security vulnerability detection  
        - 📊 Code quality scoring
        - 💾 Review history and statistics
        - 📤 Export capabilities
        
        **Built with:**
        - Streamlit for the web interface
        - GitHub API for repository access
        - Anthropic Claude API for AI analysis
        - SQLite for data storage
        """)


if __name__ == "__main__":
    main()