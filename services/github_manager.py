from github import Github, GithubException
from typing import List, Dict
import os
import logging

logger = logging.getLogger(__name__)

class EnhancedGitHubManager:
    """Enhanced GitHub manager with better error handling"""

    def __init__(self, token: str):
        self.github = Github(token, timeout=30)
        self.user = None
        self._validate_connection()

    def _validate_connection(self):
        """Validate GitHub connection"""
        try:
            self.user = self.github.get_user()
            logger.info(f"GitHub connected for user: {self.user.login}")
        except GithubException as e:
            logger.error(f"GitHub connection failed: {e}")
            raise Exception(f"GitHub authentication failed: {e}")

    def fetch_repositories(self, include_private: bool = False,
                           include_forks: bool = False) -> List[Dict]:
        """Enhanced repository fetching with filters"""
        try:
            repos = []
            for repo in self.user.get_repos(type="all" if include_private else "public"):
                if not include_forks and repo.fork:
                    continue

                # Get additional repo stats
                try:
                    languages = repo.get_languages()
                    primary_language = max(languages.keys(), key=languages.get) if languages else "Unknown"
                except:
                    primary_language = repo.language or "Unknown"

                repos.append({
                    'name': repo.name,
                    'full_name': repo.full_name,
                    'description': repo.description or "No description",
                    'private': repo.private,
                    'language': primary_language,
                    'languages': list(languages.keys()) if 'languages' in locals() else [],
                    'stars': repo.stargazers_count,
                    'forks': repo.forks_count,
                    'open_issues': repo.open_issues_count,
                    'size': repo.size,
                    'created_at': repo.created_at.strftime("%Y-%m-%d"),
                    'updated_at': repo.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
                    'pushed_at': repo.pushed_at.strftime("%Y-%m-%d %H:%M:%S") if repo.pushed_at else None,
                    'url': repo.html_url,
                    'clone_url': repo.clone_url,
                    'is_fork': repo.fork,
                    'default_branch': repo.default_branch
                })

            return sorted(repos, key=lambda x: x['updated_at'], reverse=True)

        except Exception as e:
            logger.error(f"Repository fetch error: {e}")
            raise Exception(f"Failed to fetch repositories: {e}")

    def fetch_pull_requests(self, repo_name: str, state: str = "open",
                            limit: int = 50) -> List[Dict]:
        """Enhanced PR fetching with more details"""
        try:
            repo = self.github.get_repo(repo_name)
            prs = []

            for i, pr in enumerate(repo.get_pulls(state=state)):
                if i >= limit:
                    break

                # Get PR labels
                labels = [label.name for label in pr.labels]

                # Get review status
                reviews = list(pr.get_reviews())
                review_status = "pending"
                if reviews:
                    latest_review = reviews[-1]
                    review_status = latest_review.state.lower()

                prs.append({
                    'number': pr.number,
                    'title': pr.title,
                    'author': pr.user.login,
                    'author_avatar': pr.user.avatar_url,
                    'state': pr.state,
                    'draft': pr.draft,
                    'mergeable': pr.mergeable,
                    'mergeable_state': pr.mergeable_state,
                    'review_status': review_status,
                    'labels': labels,
                    'created_at': pr.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    'updated_at': pr.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
                    'merged_at': pr.merged_at.strftime("%Y-%m-%d %H:%M:%S") if pr.merged_at else None,
                    'additions': pr.additions,
                    'deletions': pr.deletions,
                    'changed_files': pr.changed_files,
                    'commits': pr.commits,
                    'comments': pr.comments,
                    'review_comments': pr.review_comments,
                    'body': pr.body or "",
                    'url': pr.html_url,
                    'head_sha': pr.head.sha,
                    'base_branch': pr.base.ref,
                    'head_branch': pr.head.ref,
                    'milestone': pr.milestone.title if pr.milestone else None,
                    'assignees': [assignee.login for assignee in pr.assignees]
                })

            return sorted(prs, key=lambda x: x['updated_at'], reverse=True)

        except Exception as e:
            logger.error(f"PR fetch error: {e}")
            raise Exception(f"Failed to fetch pull requests: {e}")

    def get_pr_files(self, repo_name: str, pr_number: int) -> List[Dict]:
        """Enhanced PR file fetching"""
        try:
            repo = self.github.get_repo(repo_name)
            pr = repo.get_pull(pr_number)

            files = []
            for file in pr.get_files():
                # Determine file type
                file_ext = os.path.splitext(file.filename)[1].lower()
                file_type = self._get_file_type(file_ext)

                files.append({
                    'filename': file.filename,
                    'status': file.status,
                    'additions': file.additions,
                    'deletions': file.deletions,
                    'changes': file.changes,
                    'patch': file.patch,
                    'raw_url': file.raw_url,
                    'blob_url': file.blob_url,
                    'file_type': file_type,
                    'is_binary': self._is_binary_file(file.filename),
                    'size': len(file.patch) if file.patch else 0
                })

            return files

        except Exception as e:
            logger.error(f"PR files fetch error: {e}")
            raise Exception(f"Failed to fetch PR files: {e}")

    def _get_file_type(self, extension: str) -> str:
        """Determine file type from extension"""
        type_mapping = {
            '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
            '.java': 'java', '.cpp': 'cpp', '.c': 'c', '.cs': 'csharp',
            '.go': 'go', '.rs': 'rust', '.rb': 'ruby', '.php': 'php',
            '.html': 'html', '.css': 'css', '.scss': 'scss', '.sass': 'sass',
            '.json': 'json', '.xml': 'xml', '.yml': 'yaml', '.yaml': 'yaml',
            '.md': 'markdown', '.txt': 'text', '.sql': 'sql',
            '.dockerfile': 'docker', '.sh': 'shell', '.bash': 'bash'
        }
        return type_mapping.get(extension, 'unknown')

    def _is_binary_file(self, filename: str) -> bool:
        """Check if file is binary"""
        binary_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
            '.pdf', '.doc', '.docx', '.zip', '.tar', '.gz', '.rar',
            '.exe', '.dll', '.so', '.dylib', '.bin'
        }
        return os.path.splitext(filename)[1].lower() in binary_extensions