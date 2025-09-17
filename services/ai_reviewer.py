import json
import re
from typing import List, Dict
from datetime import datetime
import anthropic
import logging
import asyncio

logger = logging.getLogger(__name__)


class EnhancedAIReviewer:
    """Enhanced AI reviewer with better analysis"""

    def __init__(self, api_key: str):
        self.client = anthropic.Anthropic(api_key=api_key)
        # FIXED: Use correct model name
        self.model = "claude-sonnet-4-20250514"  # or "claude-3-5-sonnet-latest"
        self.max_file_size = 50000
        self.vulnerability_patterns = self._load_vulnerability_patterns()

    def _load_vulnerability_patterns(self) -> Dict:
        """Load common vulnerability patterns"""
        return {
            'sql_injection': [
                r'execute\s*\([\'"].*\+.*[\'"]',
                r'query\s*\([\'"].*\+.*[\'"]',
                r'format.*%.*%'
            ],
            'xss': [
                r'innerHTML\s*=.*\+',
                r'document\.write\s*\(.*\+',
                r'eval\s*\('
            ],
            'hardcoded_secrets': [
                r'password\s*=\s*[\'"][^\'"]+[\'"]',
                r'api[_-]?key\s*=\s*[\'"][^\'"]+[\'"]',
                r'secret\s*=\s*[\'"][^\'"]+[\'"]'
            ],
            'insecure_random': [
                r'Math\.random\(\)',
                r'random\.random\(\)',
                r'Random\(\)'
            ]
        }

    async def generate_review_async(self, pr_title: str, pr_body: str,
                                    files: List[Dict], user_preferences: Dict = None) -> 'ReviewResult':
        """Generate AI review asynchronously"""
        try:
            # Pre-filter and prepare files
            filtered_files = self._filter_files_for_analysis(files)

            # Create analysis context
            context = self._prepare_enhanced_context(pr_title, pr_body, filtered_files)

            # Run security scan first
            security_issues = await self._run_security_scan(filtered_files)

            # Get Claude's analysis
            response = await self._get_claude_analysis(context, user_preferences)

            # Parse and enhance response
            analysis = self._parse_enhanced_response(response, security_issues)

            # Calculate confidence score
            confidence = self._calculate_confidence(analysis, filtered_files)

            from core.models import ReviewResult
            return ReviewResult(
                security_score=analysis.get('security_score', 0),
                quality_score=analysis.get('quality_score', 0),
                vulnerabilities=analysis.get('vulnerabilities', []),
                issues=analysis.get('issues', []),
                summary=analysis.get('summary', ''),
                recommendations=analysis.get('recommendations', []),
                approval=analysis.get('approval', 'COMMENT'),
                ai_confidence=confidence
            )

        except Exception as e:
            logger.error(f"AI review generation error: {e}")
            # FIXED: Return ReviewResult object, not dict
            return self._get_fallback_review_result()

    def _filter_files_for_analysis(self, files: List[Dict]) -> List[Dict]:
        """Filter and prioritize files for analysis"""
        # Skip binary files and very large files
        filtered = []
        for file in files:
            if file.get('is_binary', False):
                continue

            if file.get('size', 0) > self.max_file_size:
                # Truncate large files
                if file.get('patch'):
                    file['patch'] = file['patch'][:self.max_file_size]
                    file['truncated'] = True

            filtered.append(file)

        # Prioritize important files
        priority_files = []
        regular_files = []

        for file in filtered:
            filename = file['filename'].lower()
            if any(important in filename for important in [
                'security', 'auth', 'login', 'password', 'secret', 'key',
                'config', 'env', 'dockerfile', 'requirements', 'package.json'
            ]):
                priority_files.append(file)
            else:
                regular_files.append(file)

        # Return prioritized files (max 20 files total)
        return (priority_files + regular_files)[:20]

    async def _run_security_scan(self, files: List[Dict]) -> List[Dict]:
        """Run basic security pattern matching"""
        security_issues = []

        for file in files:
            if not file.get('patch'):
                continue

            for vuln_type, patterns in self.vulnerability_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, file['patch'], re.IGNORECASE | re.MULTILINE)
                    if matches:
                        security_issues.append({
                            'type': vuln_type,
                            'severity': 'HIGH' if vuln_type in ['sql_injection', 'xss'] else 'MEDIUM',
                            'file': file['filename'],
                            'description': f"Potential {vuln_type.replace('_', ' ')} vulnerability detected",
                            'matches': matches[:3]  # Limit matches
                        })

        return security_issues

    def _prepare_enhanced_context(self, pr_title: str, pr_body: str,
                                  files: List[Dict]) -> str:
        """Prepare enhanced context for AI analysis"""
        context_parts = [
            "You are an expert senior software engineer and security researcher. Analyze this Pull Request comprehensively.",
            "",
            f"**PR Title:** {pr_title}",
            f"**PR Description:** {pr_body or 'No description provided'}",
            "",
            f"**Files Changed ({len(files)}):**"
        ]

        # Group files by type
        file_types = {}
        for file in files:
            file_type = file.get('file_type', 'unknown')
            if file_type not in file_types:
                file_types[file_type] = []
            file_types[file_type].append(file)

        # Add file analysis by type
        for file_type, type_files in file_types.items():
            context_parts.append(f"\n**{file_type.upper()} Files:**")

            for file in type_files[:5]:  # Limit files per type
                context_parts.append(f"\n### 📄 {file['filename']}")
                context_parts.append(f"Status: {file['status']} | Changes: +{file['additions']} -{file['deletions']}")

                if file.get('truncated'):
                    context_parts.append("⚠️ *File truncated due to size*")

                if file.get('patch') and len(file['patch']) < 3000:
                    context_parts.append("```diff")
                    context_parts.append(file['patch'])
                    context_parts.append("```")
                elif file.get('patch'):
                    # Show only key parts for large patches
                    lines = file['patch'].split('\n')
                    important_lines = [line for line in lines if
                                       line.startswith('+') or line.startswith('-') or
                                       any(keyword in line.lower() for keyword in
                                           ['password', 'secret', 'key', 'auth', 'security', 'sql', 'query'])]

                    if important_lines:
                        context_parts.append("```diff")
                        context_parts.append('\n'.join(important_lines[:50]))
                        context_parts.append("```")
                    else:
                        context_parts.append("```diff")
                        context_parts.append('\n'.join(lines[:20]))
                        context_parts.append("...")
                        context_parts.append('\n'.join(lines[-10:]))
                        context_parts.append("```")

        context_parts.extend([
            "",
            "**Analysis Requirements:**",
            "1. Security vulnerabilities (SQL injection, XSS, authentication flaws, etc.)",
            "2. Code quality issues (complexity, maintainability, performance)",
            "3. Best practices violations",
            "4. Architecture and design concerns",
            "5. Testing coverage and quality",
            "",
            "Please provide detailed analysis in this JSON format:",
            "```json",
            "{",
            '  "security_score": 0-100,',
            '  "quality_score": 0-100,',
            '  "vulnerabilities": [',
            '    {',
            '      "type": "vulnerability_type",',
            '      "severity": "CRITICAL|HIGH|MEDIUM|LOW",',
            '      "file": "filename",',
            '      "line": "line_number_if_applicable",',
            '      "description": "detailed_description",',
            '      "recommendation": "fix_suggestion"',
            '    }',
            '  ],',
            '  "issues": [',
            '    {',
            '      "type": "code_quality|performance|maintainability|testing",',
            '      "severity": "HIGH|MEDIUM|LOW",',
            '      "file": "filename",',
            '      "description": "detailed_description",',
            '      "recommendation": "improvement_suggestion"',
            '    }',
            '  ],',
            '  "summary": "comprehensive_summary_of_changes_and_impact",',
            '  "recommendations": [',
            '    "prioritized_recommendation_1",',
            '    "prioritized_recommendation_2"',
            '  ],',
            '  "approval": "APPROVE|REQUEST_CHANGES|COMMENT",',
            '  "complexity_analysis": {',
            '    "cognitive_complexity": "LOW|MEDIUM|HIGH",',
            '    "maintainability_impact": "POSITIVE|NEUTRAL|NEGATIVE",',
            '    "testing_adequacy": "SUFFICIENT|NEEDS_IMPROVEMENT|INSUFFICIENT"',
            '  }',
            '}',
            "```"
        ])

        return "\n".join(context_parts)

    async def _get_claude_analysis(self, context: str, user_preferences: Dict = None) -> str:
        """Get analysis from Claude with user preferences"""
        system_prompt = """You are a senior software engineer and security expert with 15+ years of experience. 
        Provide thorough, actionable code reviews focusing on security, maintainability, and best practices.
        Be specific with line numbers and exact issues. Prioritize critical security vulnerabilities."""

        # Adjust prompt based on user preferences
        if user_preferences:
            if user_preferences.get('focus_security', True):
                system_prompt += " Pay extra attention to security vulnerabilities and potential exploits."
            if user_preferences.get('focus_performance', False):
                system_prompt += " Include detailed performance analysis and optimization suggestions."
            if user_preferences.get('strict_style', False):
                system_prompt += " Be strict about code style and formatting issues."

        try:
            # IMPROVED: Add retry logic and better error handling
            response = self.client.messages.create(
                model=self.model,
                max_tokens=8000,
                temperature=0.1,
                system=system_prompt,
                messages=[{"role": "user", "content": context}]
            )

            return response.content[0].text

        except anthropic.APIError as e:
            logger.error(f"Anthropic API error: {e}")
            if "not_found_error" in str(e):
                logger.error(f"Model {self.model} not found. Please check available models.")
                # Try fallback model
                try:
                    self.model = "claude-sonnet-4-20250514"
                    response = self.client.messages.create(
                        model=self.model,
                        max_tokens=8000,
                        temperature=0.1,
                        system=system_prompt,
                        messages=[{"role": "user", "content": context}]
                    )
                    return response.content[0].text
                except Exception as fallback_error:
                    logger.error(f"Fallback model also failed: {fallback_error}")
                    raise Exception(f"AI analysis failed: {e}")
            else:
                raise Exception(f"AI analysis failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in Claude analysis: {e}")
            raise Exception(f"AI analysis failed: {e}")

    def _parse_enhanced_response(self, response_text: str, security_issues: List[Dict]) -> Dict:
        """Parse AI response with fallback handling"""
        try:
            # Extract JSON from response
            json_start = response_text.find("```json")
            if json_start != -1:
                json_start += 7
                json_end = response_text.find("```", json_start)
                if json_end != -1:
                    json_str = response_text[json_start:json_end].strip()
                    analysis = json.loads(json_str)
                else:
                    # Try to find JSON without closing ```
                    json_str = response_text[json_start:].strip()
                    analysis = json.loads(json_str)
            else:
                # Try to parse entire response as JSON
                analysis = json.loads(response_text)

            # Merge with security scan results
            if security_issues:
                existing_vulns = analysis.get('vulnerabilities', [])
                analysis['vulnerabilities'] = security_issues + existing_vulns

            # Validate and sanitize
            analysis = self._validate_analysis(analysis)

            return analysis

        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error: {e}")
            logger.debug(f"Response text: {response_text[:500]}...")
            return self._get_fallback_analysis()
        except Exception as e:
            logger.error(f"Response parsing error: {e}")
            return self._get_fallback_analysis()

    def _validate_analysis(self, analysis: Dict) -> Dict:
        """Validate and sanitize analysis results"""
        # Ensure required fields
        analysis.setdefault('security_score', 75)
        analysis.setdefault('quality_score', 75)
        analysis.setdefault('vulnerabilities', [])
        analysis.setdefault('issues', [])
        analysis.setdefault('summary', 'Analysis completed')
        analysis.setdefault('recommendations', [])
        analysis.setdefault('approval', 'COMMENT')

        # Validate scores
        analysis['security_score'] = max(0, min(100, analysis['security_score']))
        analysis['quality_score'] = max(0, min(100, analysis['quality_score']))

        # Validate approval
        valid_approvals = ['APPROVE', 'REQUEST_CHANGES', 'COMMENT']
        if analysis['approval'] not in valid_approvals:
            analysis['approval'] = 'COMMENT'

        # Limit lists to prevent overflow
        analysis['vulnerabilities'] = analysis['vulnerabilities'][:20]
        analysis['issues'] = analysis['issues'][:20]
        analysis['recommendations'] = analysis['recommendations'][:10]

        return analysis

    def _calculate_confidence(self, analysis: Dict, files: List[Dict]) -> float:
        """Calculate confidence score based on analysis quality"""
        confidence = 0.5  # Base confidence

        # Increase confidence based on analysis completeness
        if analysis.get('summary') and len(analysis['summary']) > 50:
            confidence += 0.1

        if analysis.get('vulnerabilities') or analysis.get('issues'):
            confidence += 0.1

        if analysis.get('recommendations'):
            confidence += 0.1

        # Decrease confidence for large/complex PRs
        total_changes = sum(f.get('changes', 0) for f in files)
        if total_changes > 1000:
            confidence -= 0.1

        if len(files) > 15:
            confidence -= 0.1

        return max(0.1, min(1.0, confidence))

    def _get_fallback_analysis(self) -> Dict:
        """Fallback analysis when AI fails (returns dict for internal use)"""
        return {
            'security_score': 75,
            'quality_score': 75,
            'vulnerabilities': [],
            'issues': [{
                'type': 'system',
                'severity': 'LOW',
                'description': 'Automated analysis unavailable. Manual review recommended.',
                'recommendation': 'Please review this PR manually for security and quality issues.'
            }],
            'summary': "Automated analysis could not be completed. This PR requires manual review.",
            'recommendations': ["Conduct manual code review", "Run additional security scans"],
            'approval': "COMMENT"
        }

    def _get_fallback_review_result(self) -> 'ReviewResult':
        """FIXED: Return ReviewResult object for fallback case"""
        from core.models import ReviewResult
        fallback_data = self._get_fallback_analysis()

        return ReviewResult(
            security_score=fallback_data['security_score'],
            quality_score=fallback_data['quality_score'],
            vulnerabilities=fallback_data['vulnerabilities'],
            issues=fallback_data['issues'],
            summary=fallback_data['summary'],
            recommendations=fallback_data['recommendations'],
            approval=fallback_data['approval'],
            ai_confidence=0.1  # Low confidence for fallback
        )