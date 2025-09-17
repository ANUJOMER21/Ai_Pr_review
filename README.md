# 🤖 AI-Powered GitHub PR Review Dashboard

A lightweight Streamlit web application that provides automated code review capabilities using Claude AI. Connect your GitHub account, view repositories, fetch pull requests, and generate intelligent AI-powered reviews.

## ✨ Features

- **🔐 Secure Authentication**: Store GitHub tokens and Claude API keys securely
- **📁 Repository Management**: Browse your GitHub repositories with search and filtering
- **🔄 Pull Request Viewer**: View and manage pull requests across repositories
- **🤖 AI-Powered Reviews**: Generate comprehensive code reviews using Claude Haiku 3.5
- **📊 Analytics Dashboard**: Track review statistics and quality metrics
- **💾 Review History**: Save and retrieve past reviews with SQLite database
- **📤 Export Capabilities**: Export reviews as Markdown or CSV files
- **🎨 Clean UI**: Modern, responsive interface built with Streamlit

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- GitHub Personal Access Token ([Create one here](https://github.com/settings/tokens))
- Claude API Key ([Get it here](https://console.anthropic.com/))

### Installation

1. **Clone or download the application files**

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   streamlit run streamlit_pr_dashboard.py
   ```

4. **Open your browser** and navigate to `http://localhost:8501`

### Initial Setup

1. **Configure Credentials**:
   - Go to "⚙️ Settings" in the sidebar
   - Enter your GitHub Personal Access Token (required scopes: `repo`, `read:user`)
   - Enter your Claude API Key
   - Test both connections to ensure they work

2. **Start Reviewing**:
   - Visit "📁 Repositories" to browse your repos
   - Go to "🔄 Pull Requests" to view and review PRs
   - Click "🤖 Generate AI Review" to create automated reviews

## 📋 Pages Overview

### 🏠 Dashboard
- Overview of review statistics
- Recent activity feed
- Quick metrics (total reviews, repositories, average scores)

### 📁 Repositories
- Browse your GitHub repositories
- Search and filter functionality
- View repository statistics (stars, forks, issues)
- Direct navigation to pull requests

### 🔄 Pull Requests
- View pull requests for selected repositories
- Filter by state (open, closed, all)
- Generate AI-powered reviews with one click
- View file changes and PR details

### 📋 Reviews
- Browse all saved reviews
- Filter by repository
- Sort by recency, security score, or quality score
- Export individual reviews as Markdown

### ⚙️ Settings
- Manage API credentials
- Test GitHub and Claude connections
- Database management tools
- Export/import functionality

## 🤖 AI Review Features

The AI reviewer provides:

- **🔒 Security Analysis**: Identifies potential vulnerabilities and security issues
- **📊 Quality Scoring**: Rates code quality and security on a 0-100 scale
- **🐛 Issue Detection**: Finds code quality problems and suggests improvements
- **💡 Recommendations**: Provides actionable suggestions for improvement
- **✅ Approval Status**: Suggests whether to approve, request changes, or comment

## 💾 Data Storage

- **Local SQLite Database**: All reviews are stored in `pr_reviews.db`
- **Secure Credentials**: API keys stored in encoded format in `config.json`
- **Review Archives**: Generated reviews saved in structured format
- **Export Options**: CSV and Markdown export capabilities

## 🔧 Configuration

### GitHub Token Scopes
Your GitHub token needs these scopes:
- `repo` - Access repositories
- `read:user` - Read user profile information

### Claude API
- Uses Claude Haiku 3.5 model (`claude-3-5-haiku-20241022`)
- Optimized for code analysis and review generation
- Configurable analysis depth and formatting

## 📊 Database Schema

The SQLite database stores:
- Repository information
- Pull request metadata
- AI-generated review content
- Security and quality scores
- Vulnerability and issue counts
- Timestamps and author information

## 🛠️ Customization

You can extend the application by:

1. **Adding New Review Criteria**: Modify the AI prompt in `AIReviewer._prepare_context()`
2. **Custom Scoring**: Adjust scoring algorithms in the review analysis
3. **Additional Exports**: Add new export formats (PDF, HTML, etc.)
4. **Webhooks**: Integrate with the existing webhook functionality from your base code
5. **Team Features**: Add user management and team review capabilities

## 🔒 Security Notes

- API keys are base64 encoded (implement proper encryption for production use)
- GitHub tokens are stored locally and never transmitted to third parties
- All API calls go directly to GitHub and Anthropic services
- No data is sent to external servers beyond the official APIs

## 🐛 Troubleshooting

### Common Issues

**"Please configure your credentials"**
- Ensure you've entered valid GitHub token and Claude API key in Settings
- Test connections using the test buttons in Settings

**"Failed to fetch repositories"**
- Check your GitHub token has correct scopes
- Verify your internet connection
- Ensure the token hasn't expired

**"AI review failed"**
- Verify your Claude API key is correct
- Check you have sufficient API credits
- Large PRs may hit token limits - try smaller changes first

**Database errors**
- The app creates `pr_reviews.db` automatically
- If corrupted, delete the file and restart the app
- Use the database management tools in Settings

### Performance Tips

- Large repositories may take time to load
- AI reviews work best on PRs with < 20 files
- Use the search and filter features to find specific items quickly
- Export reviews regularly to avoid database size issues

## 📈 Future Enhancements

Potential improvements:
- Real-time webhook integration
- Team collaboration features
- Advanced analytics and reporting
- Integration with more AI models
- Code diff visualization
- Automated PR commenting
- Custom review templates
- Integration with CI/CD pipelines

## 📄 License

This project is open source. Feel free to modify and distribute as needed.

## 🤝 Contributing

Contributions are welcome! Areas for improvement:
- UI/UX enhancements
- Additional AI models
- Performance optimizations
- Security improvements
- New export formats
- Integration capabilities

---

**Built with ❤️ using Streamlit, GitHub API, and Claude AI**