import base64
import os
import sqlite3
from pathlib import Path

import bcrypt
import json
import uuid
from datetime import datetime, timedelta
from typing import Tuple, Optional, Dict, List
import logging
import re  # For validation

from .database import DatabaseManager
from .models import User

logger = logging.getLogger(__name__)

class UserManager:
    """Manages user authentication and sessions"""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.session_duration = timedelta(days=7)

    def create_user(self, username: str, email: str, password: str, role: str = 'user') -> Tuple[bool, str]:
        """Create a new user"""
        with self.db.lock:  # Acquire lock for writes
            try:
                # Validate input
                if len(username) < 3:
                    return False, "Username must be at least 3 characters"
                if len(password) < 8:
                    return False, "Password must be at least 8 characters"
                if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                    return False, "Invalid email format"

                # Generate password hash
                salt = bcrypt.gensalt()
                password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)

                user_id = str(uuid.uuid4())

                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO users (id, username, email, password_hash, salt, role)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (user_id, username, email, password_hash, salt, role))
                    conn.commit()

                self._log_audit("user_created", "user", user_id, {"username": username, "email": email})
                logger.info(f"User created: {username}")
                return True, "User created successfully"

            except sqlite3.IntegrityError as e:
                if "username" in str(e):
                    return False, "Username already exists"
                elif "email" in str(e):
                    return False, "Email already exists"
                else:
                    return False, "User creation failed"
            except Exception as e:
                logger.error(f"User creation error: {e}")
                return False, "User creation failed"

    def authenticate_user(self, username: str, password: str) -> Tuple[bool, Optional[str]]:
        """Authenticate user and create session"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, password_hash, is_active FROM users 
                    WHERE username = ? OR email = ?
                """, (username, username))

                result = cursor.fetchone()
                if not result:
                    return False, None

                user_id, stored_hash, is_active = result

                if not is_active:
                    return False, None

                if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                    # Update last login
                    cursor.execute("""
                        UPDATE users SET last_login = CURRENT_TIMESTAMP 
                        WHERE id = ?
                    """, (user_id,))

                    # Create session
                    session_id = self._create_session(user_id)
                    conn.commit()

                    self._log_audit("user_login", "user", user_id, {"username": username}, user_id)
                    logger.info(f"User authenticated: {username}")
                    return True, session_id

            return False, None

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False, None

    def _create_session(self, user_id: str) -> str:
        """Create a new user session"""
        session_id = str(uuid.uuid4())
        expires_at = datetime.now() + self.session_duration

        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO user_sessions (session_id, user_id, expires_at)
                VALUES (?, ?, ?)
            """, (session_id, user_id, expires_at))
            conn.commit()

        return session_id

    def get_user_by_session(self, session_id: str) -> Optional[User]:
        """Get user by session ID"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT u.id, u.username, u.email, u.role, u.created_at, u.last_login, u.preferences
                    FROM users u
                    JOIN user_sessions s ON u.id = s.user_id
                    WHERE s.session_id = ? AND s.is_active = TRUE AND s.expires_at > CURRENT_TIMESTAMP
                """, (session_id,))

                result = cursor.fetchone()
                if result:
                    return User(
                        id=result[0],
                        username=result[1],
                        email=result[2],
                        role=result[3],
                        created_at=datetime.fromisoformat(result[4].replace('Z', '+00:00')),  # Handle ISO
                        last_login=datetime.fromisoformat(result[5].replace('Z', '+00:00')) if result[5] else None,
                        preferences=json.loads(result[6]) if result[6] else {}
                    )
            return None

        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return None

    def logout_user(self, session_id: str) -> bool:
        """Logout user by invalidating session"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE user_sessions SET is_active = FALSE 
                    WHERE session_id = ?
                """, (session_id,))
                conn.commit()

            logger.info(f"User logged out: {session_id}")
            return True

        except Exception as e:
            logger.error(f"Logout error: {e}")
            return False

    def update_preferences(self, user_id: str, preferences: Dict) -> bool:
        """Update user preferences"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE users SET preferences = ? WHERE id = ?
                """, (json.dumps(preferences), user_id))
                conn.commit()
            self._log_audit("preferences_updated", "user", user_id, {"preferences": preferences})
            logger.info(f"Preferences updated for user: {user_id}")
            return True
        except Exception as e:
            logger.error(f"Preferences update error: {e}")
            return False

    def get_preferences(self, user_id: str) -> Dict:
        """Get user preferences"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT preferences FROM users WHERE id = ?", (user_id,))
                result = cursor.fetchone()
                return json.loads(result[0]) if result and result[0] else {}
        except Exception as e:
            logger.error(f"Preferences retrieval error: {e}")
            return {}

    def _log_audit(self, action: str, resource_type: str = None, resource_id: str = None,
                   details: Dict = None, user_id: str = None):
        """Log audit events"""
        try:
            audit_id = str(uuid.uuid4())
            ip_address = "streamlit-local"  # Mock for Streamlit
            user_agent = "Streamlit/1.0"
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO audit_log (id, user_id, action, resource_type, resource_id, details, ip_address, user_agent)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (audit_id, user_id, action, resource_type, resource_id,
                      json.dumps(details) if details else None, ip_address, user_agent))
                conn.commit()

        except Exception as e:
            logger.error(f"Audit logging error: {e}")



class EnhancedAuthManager:
    """Enhanced authentication with encryption"""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.encryption_key = self._get_or_create_encryption_key()

    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key"""
        key_file = "encryption.key"
        if Path(key_file).exists():
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # In production, use proper key management
            key = os.urandom(32)
            with open(key_file, 'wb') as f:
                f.write(key)
            return key

    def save_api_key(self, user_id: str, service_name: str, api_key: str) -> bool:
        """Save encrypted API key for user"""
        try:
            # Simple encryption (use proper encryption in production)
            encrypted_key = base64.b64encode(api_key.encode()).decode()

            key_id = str(uuid.uuid4())
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO user_api_keys (id, user_id, service_name, encrypted_key)
                    VALUES (?, ?, ?, ?)
                """, (key_id, user_id, service_name, encrypted_key))
                conn.commit()

            return True

        except sqlite3.IntegrityError as e:
            logger.error(f"API key integrity error (e.g., duplicate): {e}")
            return False
        except Exception as e:
            logger.error(f"API key save error: {e}")
            return False

    def get_api_key(self, user_id: str, service_name: str) -> Optional[str]:
        """Get decrypted API key for user"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT encrypted_key FROM user_api_keys
                    WHERE user_id = ? AND service_name = ? AND is_active = TRUE
                """, (user_id, service_name))

                result = cursor.fetchone()
                if result:
                    # Update last used
                    cursor.execute("""
                        UPDATE user_api_keys SET last_used = CURRENT_TIMESTAMP
                        WHERE user_id = ? AND service_name = ?
                    """, (user_id, service_name))
                    conn.commit()

                    # Decrypt
                    return base64.b64decode(result[0].encode()).decode()

            return None

        except Exception as e:
            logger.error(f"API key retrieval error: {e}")
            return None
# ReviewManager (renamed from ReviewManager for file)
class ReviewManager:
    """Manages reviews with enhanced features"""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def save_review(self, user_id: str, repo_name: str, pr_number: int,
                    pr_title: str, pr_author: str, pr_url: str,
                    review_result, review_text: str) -> bool:
        """Save a review with enhanced data"""
        try:
            review_id = str(uuid.uuid4())

            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO reviews 
                    (id, user_id, repo_name, pr_number, pr_title, pr_author, pr_url,
                     review_text, security_score, quality_score, vulnerabilities_count, 
                     issues_count, ai_confidence, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (review_id, user_id, repo_name, pr_number, pr_title, pr_author,
                      pr_url, review_text, review_result.security_score,
                      review_result.quality_score, len(review_result.vulnerabilities),
                      len(review_result.issues), review_result.ai_confidence))

                conn.commit()

            return True

        except Exception as e:
            logger.error(f"Review save error: {e}")
            return False

    def get_user_reviews(self, user_id: str, repo_name: str = None,
                         limit: int = 50) -> List[Dict]:
        """Get reviews for a user"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()

                if repo_name:
                    cursor.execute("""
                        SELECT * FROM reviews 
                        WHERE user_id = ? AND repo_name = ?
                        ORDER BY updated_at DESC LIMIT ?
                    """, (user_id, repo_name, limit))
                else:
                    cursor.execute("""
                        SELECT * FROM reviews 
                        WHERE user_id = ?
                        ORDER BY updated_at DESC LIMIT ?
                    """, (user_id, limit))

                columns = [desc[0] for desc in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]

        except Exception as e:
            logger.error(f"Review retrieval error: {e}")
            return []

    def get_review_statistics(self, user_id: str) -> Dict:
        """Get comprehensive review statistics"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()

                # Basic stats
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_reviews,
                        AVG(security_score) as avg_security_score,
                        AVG(quality_score) as avg_quality_score,
                        AVG(ai_confidence) as avg_confidence,
                        SUM(vulnerabilities_count) as total_vulnerabilities,
                        SUM(issues_count) as total_issues,
                        COUNT(DISTINCT repo_name) as total_repos,
                        MIN(created_at) as first_review,
                        MAX(updated_at) as last_review
                    FROM reviews WHERE user_id = ?
                """, (user_id,))

                result = cursor.fetchone()

                # Recent activity
                cursor.execute("""
                    SELECT DATE(created_at) as review_date, COUNT(*) as count
                    FROM reviews 
                    WHERE user_id = ? AND created_at >= date('now', '-30 days')
                    GROUP BY DATE(created_at)
                    ORDER BY review_date DESC
                """, (user_id,))

                activity = cursor.fetchall()

                return {
                    'total_reviews': result[0] or 0,
                    'avg_security_score': round(result[1] or 0, 1),
                    'avg_quality_score': round(result[2] or 0, 1),
                    'avg_confidence': round(result[3] or 0, 2),
                    'total_vulnerabilities': result[4] or 0,
                    'total_issues': result[5] or 0,
                    'total_repos': result[6] or 0,
                    'first_review': result[7],
                    'last_review': result[8],
                    'recent_activity': [{'date': row[0], 'count': row[1]} for row in activity]
                }

        except Exception as e:
            logger.error(f"Statistics retrieval error: {e}")
            return {}

    def delete_reviews_bulk(self, user_id: str, review_ids: List[str]) -> bool:
        """Bulk delete reviews"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                placeholders = ','.join('?' * len(review_ids))
                cursor.execute(f"DELETE FROM review_comments WHERE review_id IN ({placeholders})", review_ids)
                cursor.execute(f"DELETE FROM reviews WHERE id IN ({placeholders}) AND user_id = ?", review_ids + [user_id])
                conn.commit()
            logger.info(f"Bulk deleted {len(review_ids)} reviews for user {user_id}")
            return True
        except Exception as e:
            logger.error(f"Bulk delete error: {e}")
            return False


