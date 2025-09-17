# AI PR Review Dashboard

[![Streamlit](https://img.shields.io/badge/Streamlit-FF6B35?logo=streamlit)](https://streamlit.io/) [![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python)](https://www.python.org/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**🤖 An AI-Powered Pull Request Review Dashboard**  
A modern Streamlit web application that integrates GitHub for repository management and Anthropic's Claude AI for automated code reviews. It analyzes PRs for security vulnerabilities, code quality, and provides actionable recommendations. Built with SQLite for persistence, it's lightweight and easy to deploy.

- **Current Version**: 1.0.0 (Released: September 18, 2025)
- **Author**: Anuj omer
- **Demo**: 

---

## ✨ Features

- **User Authentication**: Secure login/register with bcrypt-hashed passwords and session management.
- **GitHub Integration**: Fetch repositories, pull requests, and files with PyGitHub.
- **AI-Powered Reviews**: Use Claude (Sonnet 3.5) to generate comprehensive PR reviews, including security scans (SQLi, XSS patterns) and quality scores.
- **Dashboard & Analytics**: Interactive charts (Plotly) for review stats, activity timelines, and repository insights.
- **Notifications & Audit Logs**: In-app alerts and full audit trail for actions.
- **Export & Reports**: Download reviews as Markdown/CSV/PDF; bulk actions for management.
- **Team Collaboration**: Role-based access (admin/manager) for multi-user teams.
- **Preferences & Settings**: Customizable review focus (security/performance) and API key management.
- **Responsive UI**: Custom CSS with dark mode support, badges, and modals.

---

## 📋 Project Structure

The project is modular for easy maintenance:

```
ai_pr_review_dashboard/
├── app.py                          # Main Streamlit entrypoint
├── config/
│   ├── __init__.py                 # Package init
│   └── settings.py                 # Page config & CSS
├── core/                           # Core business logic
│   ├── __init__.py
│   ├── database.py                 # SQLite manager with WAL & retry locking
│   ├── models.py                   # Dataclasses (User, ReviewResult)
│   ├── managers.py                 # UserManager, ReviewManager
│   └── notifications.py            # NotificationManager
├── services/                       # External integrations
│   ├── __init__.py
│   ├── github_manager.py           # EnhancedGitHubManager
│   ├── ai_reviewer.py              # EnhancedAIReviewer (Claude)
│   └── auth_manager.py             # EnhancedAuthManager (API keys)
├── ui/                             # User interface components
│   ├── __init__.py
│   ├── pages.py                    # Page functions (dashboard, repos, etc.)
│   └── components.py               # Auth, modals, formatters
├── utils/                          # Helpers
│   ├── __init__.py
│   ├── logger.py                   # Logging setup
│   ├── report.py                   # PDF report generation
│   └── visualizations.py           # Plotly charts
├── requirements.txt                # Dependencies
└── README.md                       # This file
```

- **Generated Files** (not in Git): `pr_reviews_multi.db` (SQLite DB), `pr_dashboard.log` (logs), `encryption.key` (API key encryption).

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+ (tested on 3.12)
- Git (optional, for cloning)
- GitHub Personal Access Token ([generate here](https://github.com/settings/tokens) – scopes: `repo`)
- Anthropic Claude API Key ([get here](https://console.anthropic.com) – free tier OK)

### Installation
1. **Clone/Setup Project**:
   ```
   git clone <your-repo-url> ai_pr_review_dashboard
   cd ai_pr_review_dashboard
   ```

2. **Virtual Environment**:
   ```
   python -m venv venv
   # Windows:
   venv\Scripts\activate
   # macOS/Linux:
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```
   pip install -r requirements.txt
   ```

### Running the App
```
streamlit run app.py
```
- Opens at http://localhost:8501.
- First run creates the DB automatically.

### First-Time Setup
1. **Register**: Use the login tab (e.g., username: `admin`, password: `securepass123`).
2. **Settings Page** (⚙️):
   - Paste GitHub token and Claude key.
   - Test connections.
   - Set preferences (e.g., focus on security).
3. **Usage**:
   - **Repositories**: Fetch your GitHub repos.
   - **Pull Requests**: Select a repo, fetch PRs, click "Generate AI Review" (uses Claude – ~30s).
   - **Dashboard/Reviews**: View stats, export reports.

---

## ⚙️ Configuration

### API Keys
- Stored encrypted in DB (base64; upgrade to Fernet in prod).
- Managed via Settings tab—no env vars needed, but for deployment:
  ```
  # .env (optional)
  GITHUB_TOKEN=ghp_...
  CLAUDE_API_KEY=sk-ant-...
  ```
  - Load in `services/auth_manager.py`: `api_key = os.getenv('GITHUB_TOKEN', user_input)`.

### Database
- SQLite (`pr_reviews_multi.db`) with WAL mode for concurrency.
- Backups: Copy the DB file; for prod, use PostgreSQL.

### Customization
- **CSS**: Edit `config/settings.py` for themes.
- **AI Prompts**: Tweak `_prepare_enhanced_context` in `services/ai_reviewer.py`.
- **Vuln Patterns**: Update `vulnerability_patterns` dict.

### Environment Variables (Optional)
Add to `.env` and load with `python-dotenv` (add to requirements):
```
DATABASE_URL=sqlite:///pr_reviews_multi.db  # For SQLAlchemy upgrade
LOG_LEVEL=DEBUG
```

---

## 📖 Usage Guide

### Key Pages
| Page | Description | Key Actions |
|------|-------------|-------------|
| **🏠 Dashboard** | Overview with metrics, recent activity, charts. | Quick stats, jump to PRs/Analytics. |
| **📁 Repositories** | List/filters for your GitHub repos. | Search, sort, view PRs per repo. |
| **🔄 Pull Requests** | Fetch/browse PRs, generate AI reviews. | Filter by state/author/size; auto-review toggle. |
| **📋 Reviews** | Saved reviews with bulk export/delete. | View details, download MD/PDF. |
| **📊 Analytics** | Charts, trends, repo breakdowns. | Activity timeline, score distribution. |
| **👥 Team** (Admin) | Manage users/roles, team stats. | Add members, view activity. |
| **⚙️ Settings** | API keys, prefs, email config. | Test connections, save prefs. |

### Example Workflow
1. Login → Settings → Add GitHub/Claude keys.
2. Repositories → Select repo → Pull Requests → Fetch open PRs.
3. Click "Generate AI Review" → Get scores, vulns, recommendations.
4. Reviews → Export as PDF → Share with team.

### Screenshots

- ![Dashboard](screenshots/dashboard.png)
- ![Report](screenshots/report.png)
- ![PR Review](screenshots/pull_request.png)
- ![Screen Recording](screenshots/recodring.mov)

---

## 🛠️ Development

### Contributing
1. Fork the repo.
2. Create a feature branch: `git checkout -b feature/amazing-feature`.
3. Commit changes: `git commit -m 'Add some amazing feature'`.
4. Push: `git push origin feature/amazing-feature`.
5. Open a Pull Request.

### Local Development
- **Hot Reload**: Streamlit auto-reloads on file changes.
- **Testing**: Add unit tests in `tests/` (e.g., `pytest` for managers).
- **Linting**: Run `black .` (add to requirements: `black==24.8.0`).
- **Debugging**: Set `LOG_LEVEL=DEBUG` in env; check `pr_dashboard.log`.

### Building/Deployment
- **Streamlit Cloud**: Connect GitHub repo, add `requirements.txt`.
- **Docker** (Optional Dockerfile):
  ```dockerfile
  FROM python:3.12-slim
  WORKDIR /app
  COPY . .
  RUN pip install -r requirements.txt
  EXPOSE 8501
  CMD ["streamlit", "run", "app.py", "--server.port=8501"]
  ```
  - Build/Run: `docker build -t pr-review . && docker run -p 8501:8501 pr-review`.

---

## 🔧 Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| **Database Locked** | Concurrent writes during rerun. | Updated `DatabaseManager` with retries/locks (see code). Delete DB and restart. |
| **ImportError (Relative)** | Streamlit script mode. | Use absolute imports (fixed in code). |
| **API Errors** | Invalid tokens. | Regenerate keys; check scopes (GitHub: `repo`; Claude: `messages`). |
| **No Repos/PRs** | Token permissions. | Ensure token has `repo` scope; test in Settings. |
| **Claude Review Fails** | Rate limit/token expiry. | Check Anthropic console; fallback analysis activates. |
| **Charts Empty** | No data. | Generate a few reviews first. |
| **PDF Export Blank** | Reportlab issue. | Ensure `reportlab` installed; test with sample data. |

- **Logs**: `tail -f pr_dashboard.log` for details.
- **Common Fixes**: Restart Streamlit, clear browser cache, check Python version.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Streamlit**: Amazing for rapid prototyping.
- **PyGitHub & Anthropic**: Robust APIs.
- **xAI Grok**: Assisted in code generation and debugging.

**Stars/Forks Welcome!** ⭐ If this helps, give it a star. Questions? Open an issue.

---

*Last Updated: September 18, 2025*