import sqlite3
import json
import time
import threading
from contextlib import contextmanager
from typing import List, Dict, Optional
from datetime import datetime
import uuid
import logging
from functools import wraps
import queue
import atexit

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Enhanced database manager with improved concurrency and error handling"""

    def __init__(self, db_file: str = "pr_reviews_multi.db", max_connections: int = 10):
        self.db_file = db_file
        self.max_connections = max_connections
        self._connection_pool = queue.Queue(maxsize=max_connections)
        self._pool_lock = threading.Lock()
        self._write_lock = threading.RLock()  # Use RLock for nested operations
        self._initialized = False

        # Initialize connection pool
        self._init_connection_pool()
        self._init_database()
        self._create_indexes()

        # Register cleanup
        atexit.register(self._cleanup_connections)

    def _init_connection_pool(self):
        """Initialize connection pool with pre-configured connections"""
        for _ in range(self.max_connections):
            conn = self._create_connection()
            self._connection_pool.put(conn)

    def _create_connection(self) -> sqlite3.Connection:
        """Create a properly configured SQLite connection"""
        conn = sqlite3.connect(
            self.db_file,
            timeout=60.0,
            check_same_thread=False,  # Allow sharing between threads
            isolation_level=None  # Autocommit mode
        )

        # Configure connection for better concurrency
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=60000")  # 60s busy timeout
        conn.execute("PRAGMA synchronous=NORMAL")  # Better performance
        conn.execute("PRAGMA cache_size=10000")  # Larger cache
        conn.execute("PRAGMA temp_store=MEMORY")  # Use memory for temp storage

        return conn

    @contextmanager
    def get_connection(self, for_write: bool = False, timeout: float = 30.0):
        """
        Get a database connection from the pool

        Args:
            for_write: Whether this connection will be used for write operations
            timeout: Maximum time to wait for a connection
        """
        conn = None
        start_time = time.time()

        try:
            # For write operations, acquire write lock
            if for_write:
                acquired = self._write_lock.acquire(timeout=timeout)
                if not acquired:
                    raise sqlite3.OperationalError("Could not acquire write lock within timeout")

            # Get connection from pool with timeout
            while time.time() - start_time < timeout:
                try:
                    conn = self._connection_pool.get(timeout=1.0)
                    break
                except queue.Empty:
                    continue

            if conn is None:
                raise sqlite3.OperationalError("Could not get connection from pool within timeout")

            # Test connection health
            try:
                conn.execute("SELECT 1").fetchone()
            except sqlite3.Error:
                # Connection is dead, create a new one
                conn.close()
                conn = self._create_connection()

            yield conn

        except Exception as e:
            logger.error(f"Database connection error: {e}")
            if conn:
                try:
                    conn.rollback()
                except:
                    pass
            raise
        finally:
            # Return connection to pool
            if conn:
                try:
                    # Ensure no active transaction
                    if conn.in_transaction:
                        conn.rollback()
                    self._connection_pool.put(conn, timeout=1.0)
                except queue.Full:
                    # Pool is full, close this connection
                    conn.close()
                except Exception as e:
                    logger.warning(f"Error returning connection to pool: {e}")
                    try:
                        conn.close()
                    except:
                        pass

            # Release write lock if acquired
            if for_write:
                try:
                    self._write_lock.release()
                except:
                    pass

    def _cleanup_connections(self):
        """Clean up all connections in the pool"""
        while not self._connection_pool.empty():
            try:
                conn = self._connection_pool.get_nowait()
                conn.close()
            except (queue.Empty, Exception):
                break

    def _init_database(self):
        """Initialize database tables with enhanced schema"""
        if self._initialized:
            return

        with self.get_connection(for_write=True) as conn:
            cursor = conn.cursor()

            # Enable foreign keys
            cursor.execute("PRAGMA foreign_keys=ON")

            # Users table with additional fields
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT DEFAULT 'user' CHECK (role IN ('user', 'admin', 'reviewer')),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    login_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP,
                    preferences TEXT DEFAULT '{}',
                    is_active BOOLEAN DEFAULT TRUE,
                    email_verified BOOLEAN DEFAULT FALSE,
                    two_factor_enabled BOOLEAN DEFAULT FALSE
                )
            """)

            # User sessions with better tracking
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    user_agent TEXT,
                    is_active BOOLEAN DEFAULT TRUE,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            """)

            # Enhanced reviews table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS reviews (
                    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
                    user_id TEXT NOT NULL,
                    repo_name TEXT NOT NULL,
                    pr_number INTEGER NOT NULL,
                    pr_title TEXT NOT NULL,
                    pr_author TEXT NOT NULL,
                    pr_url TEXT NOT NULL,
                    pr_description TEXT,
                    review_text TEXT NOT NULL,
                    security_score INTEGER DEFAULT 0 CHECK (security_score BETWEEN 0 AND 100),
                    quality_score INTEGER DEFAULT 0 CHECK (quality_score BETWEEN 0 AND 100),
                    vulnerabilities_count INTEGER DEFAULT 0,
                    issues_count INTEGER DEFAULT 0,
                    suggestions_count INTEGER DEFAULT 0,
                    ai_confidence REAL DEFAULT 0.0 CHECK (ai_confidence BETWEEN 0.0 AND 1.0),
                    review_status TEXT DEFAULT 'pending' CHECK (review_status IN ('pending', 'completed', 'failed', 'cancelled')),
                    processing_time_ms INTEGER DEFAULT 0,
                    model_used TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                    UNIQUE(user_id, repo_name, pr_number)
                )
            """)

            # Review details for structured data
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS review_details (
                    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
                    review_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT DEFAULT 'info' CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    file_path TEXT,
                    line_number INTEGER,
                    suggestion TEXT,
                    confidence REAL DEFAULT 0.0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (review_id) REFERENCES reviews (id) ON DELETE CASCADE
                )
            """)

            # Review comments/feedback
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS review_comments (
                    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
                    review_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    parent_id TEXT,
                    comment TEXT NOT NULL,
                    is_resolved BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (review_id) REFERENCES reviews (id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                    FOREIGN KEY (parent_id) REFERENCES review_comments (id)
                )
            """)

            # User API keys (encrypted)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_api_keys (
                    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
                    user_id TEXT NOT NULL,
                    service_name TEXT NOT NULL CHECK (service_name IN ('github', 'gitlab', 'bitbucket', 'openai', 'anthropic')),
                    encrypted_key TEXT NOT NULL,
                    key_name TEXT,
                    permissions TEXT DEFAULT '{}',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used TIMESTAMP,
                    expires_at TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                    UNIQUE(user_id, service_name, key_name)
                )
            """)

            # Notifications with better categorization
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS notifications (
                    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
                    user_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    type TEXT DEFAULT 'info' CHECK (type IN ('success', 'info', 'warning', 'error')),
                    category TEXT DEFAULT 'general',
                    action_url TEXT,
                    is_read BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    read_at TIMESTAMP,
                    expires_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            """)

            # Enhanced audit log
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
                    user_id TEXT,
                    session_id TEXT,
                    action TEXT NOT NULL,
                    resource_type TEXT,
                    resource_id TEXT,
                    old_values TEXT,
                    new_values TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    result TEXT DEFAULT 'success' CHECK (result IN ('success', 'failure', 'error')),
                    error_message TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
                )
            """)

            # User preferences table for complex settings
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_preferences (
                    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
                    user_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                    UNIQUE(user_id, category, key)
                )
            """)

            conn.commit()
            self._initialized = True

    def _create_indexes(self):
        """Create database indexes for performance"""
        with self.get_connection(for_write=True) as conn:
            cursor = conn.cursor()

            indexes = [
                # User indexes
                "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
                "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
                "CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at)",
                "CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login)",
                "CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active)",

                # Session indexes
                "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id)",
                "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON user_sessions(expires_at)",
                "CREATE INDEX IF NOT EXISTS idx_sessions_is_active ON user_sessions(is_active)",
                "CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON user_sessions(last_activity)",

                # Review indexes
                "CREATE INDEX IF NOT EXISTS idx_reviews_user_id ON reviews(user_id)",
                "CREATE INDEX IF NOT EXISTS idx_reviews_repo_name ON reviews(repo_name)",
                "CREATE INDEX IF NOT EXISTS idx_reviews_pr_number ON reviews(pr_number)",
                "CREATE INDEX IF NOT EXISTS idx_reviews_status ON reviews(review_status)",
                "CREATE INDEX IF NOT EXISTS idx_reviews_created_at ON reviews(created_at)",
                "CREATE INDEX IF NOT EXISTS idx_reviews_updated_at ON reviews(updated_at)",
                "CREATE INDEX IF NOT EXISTS idx_reviews_user_repo ON reviews(user_id, repo_name)",

                # Review details indexes
                "CREATE INDEX IF NOT EXISTS idx_review_details_review_id ON review_details(review_id)",
                "CREATE INDEX IF NOT EXISTS idx_review_details_category ON review_details(category)",
                "CREATE INDEX IF NOT EXISTS idx_review_details_severity ON review_details(severity)",

                # Comment indexes
                "CREATE INDEX IF NOT EXISTS idx_comments_review_id ON review_comments(review_id)",
                "CREATE INDEX IF NOT EXISTS idx_comments_user_id ON review_comments(user_id)",
                "CREATE INDEX IF NOT EXISTS idx_comments_created_at ON review_comments(created_at)",

                # API key indexes
                "CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON user_api_keys(user_id)",
                "CREATE INDEX IF NOT EXISTS idx_api_keys_service ON user_api_keys(service_name)",
                "CREATE INDEX IF NOT EXISTS idx_api_keys_is_active ON user_api_keys(is_active)",

                # Notification indexes
                "CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id)",
                "CREATE INDEX IF NOT EXISTS idx_notifications_is_read ON notifications(is_read)",
                "CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at)",
                "CREATE INDEX IF NOT EXISTS idx_notifications_type ON notifications(type)",

                # Audit log indexes
                "CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id)",
                "CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action)",
                "CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON audit_log(resource_type, resource_id)",
                "CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at)",

                # Preference indexes
                "CREATE INDEX IF NOT EXISTS idx_preferences_user_id ON user_preferences(user_id)",
                "CREATE INDEX IF NOT EXISTS idx_preferences_category ON user_preferences(category)"
            ]

            for index in indexes:
                try:
                    cursor.execute(index)
                except sqlite3.Error as e:
                    logger.warning(f"Could not create index: {e}")

            conn.commit()

    # Utility methods for common operations
    def create_user(self, username: str, email: str, password_hash: str, salt: str, **kwargs) -> str:
        """Create a new user with proper error handling"""
        user_id = str(uuid.uuid4())

        with self.get_connection(for_write=True) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO users (id, username, email, password_hash, salt, role, preferences)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    user_id, username, email, password_hash, salt,
                    kwargs.get('role', 'user'),
                    json.dumps(kwargs.get('preferences', {}))
                ))
                conn.execute("COMMIT")
                return user_id
            except Exception as e:
                conn.execute("ROLLBACK")
                logger.error(f"Failed to create user: {e}")
                raise

    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Get user by email with proper connection handling"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, username, email, password_hash, salt, role, created_at,
                       last_login, preferences, is_active, login_attempts, locked_until
                FROM users WHERE email = ? AND is_active = TRUE
            """, (email,))

            row = cursor.fetchone()
            if row:
                return {
                    'id': row[0], 'username': row[1], 'email': row[2],
                    'password_hash': row[3], 'salt': row[4], 'role': row[5],
                    'created_at': row[6], 'last_login': row[7],
                    'preferences': json.loads(row[8] or '{}'),
                    'is_active': row[9], 'login_attempts': row[10],
                    'locked_until': row[11]
                }
            return None

    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Get user by username"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, username, email, password_hash, salt, role, created_at,
                       last_login, preferences, is_active, login_attempts, locked_until
                FROM users WHERE username = ? AND is_active = TRUE
            """, (username,))

            row = cursor.fetchone()
            if row:
                return {
                    'id': row[0], 'username': row[1], 'email': row[2],
                    'password_hash': row[3], 'salt': row[4], 'role': row[5],
                    'created_at': row[6], 'last_login': row[7],
                    'preferences': json.loads(row[8] or '{}'),
                    'is_active': row[9], 'login_attempts': row[10],
                    'locked_until': row[11]
                }
            return None

    def update_user_login(self, user_id: str, reset_attempts: bool = False) -> bool:
        """Update user's last login time and optionally reset login attempts"""
        with self.get_connection(for_write=True) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()

                if reset_attempts:
                    cursor.execute("""
                        UPDATE users 
                        SET last_login = CURRENT_TIMESTAMP, login_attempts = 0, locked_until = NULL
                        WHERE id = ?
                    """, (user_id,))
                else:
                    cursor.execute("""
                        UPDATE users 
                        SET last_login = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (user_id,))

                conn.execute("COMMIT")
                return cursor.rowcount > 0
            except Exception as e:
                conn.execute("ROLLBACK")
                logger.error(f"Failed to update user login: {e}")
                return False

    def create_session(self, user_id: str, expires_at: datetime, **kwargs) -> str:
        """Create a new user session"""
        session_id = str(uuid.uuid4())

        with self.get_connection(for_write=True) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO user_sessions (session_id, user_id, expires_at, ip_address, user_agent)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    session_id, user_id, expires_at.isoformat(),
                    kwargs.get('ip_address'),
                    kwargs.get('user_agent')
                ))
                conn.execute("COMMIT")
                return session_id
            except Exception as e:
                conn.execute("ROLLBACK")
                logger.error(f"Failed to create session: {e}")
                raise

    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session by ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT session_id, user_id, created_at, expires_at, last_activity, 
                       ip_address, user_agent, is_active
                FROM user_sessions 
                WHERE session_id = ? AND is_active = TRUE
            """, (session_id,))

            row = cursor.fetchone()
            if row:
                return {
                    'session_id': row[0], 'user_id': row[1], 'created_at': row[2],
                    'expires_at': row[3], 'last_activity': row[4],
                    'ip_address': row[5], 'user_agent': row[6], 'is_active': row[7]
                }
            return None

    def create_review(self, user_id: str, repo_name: str, pr_number: int,
                      pr_title: str, pr_author: str, pr_url: str,
                      review_text: str, **kwargs) -> str:
        """Create a new PR review"""
        review_id = str(uuid.uuid4())

        with self.get_connection(for_write=True) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO reviews (
                        id, user_id, repo_name, pr_number, pr_title, pr_author, 
                        pr_url, pr_description, review_text, security_score, 
                        quality_score, vulnerabilities_count, issues_count,
                        ai_confidence, review_status, model_used
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    review_id, user_id, repo_name, pr_number, pr_title, pr_author,
                    pr_url, kwargs.get('pr_description'), review_text,
                    kwargs.get('security_score', 0), kwargs.get('quality_score', 0),
                    kwargs.get('vulnerabilities_count', 0), kwargs.get('issues_count', 0),
                    kwargs.get('ai_confidence', 0.0), kwargs.get('review_status', 'pending'),
                    kwargs.get('model_used')
                ))
                conn.execute("COMMIT")
                return review_id
            except Exception as e:
                conn.execute("ROLLBACK")
                logger.error(f"Failed to create review: {e}")
                raise

    def get_user_reviews(self, user_id: str, limit: int = 50, offset: int = 0) -> List[Dict]:
        """Get reviews for a user"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, repo_name, pr_number, pr_title, pr_author, pr_url,
                       security_score, quality_score, vulnerabilities_count,
                       issues_count, review_status, created_at, updated_at
                FROM reviews 
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """, (user_id, limit, offset))

            rows = cursor.fetchall()
            return [
                {
                    'id': row[0], 'repo_name': row[1], 'pr_number': row[2],
                    'pr_title': row[3], 'pr_author': row[4], 'pr_url': row[5],
                    'security_score': row[6], 'quality_score': row[7],
                    'vulnerabilities_count': row[8], 'issues_count': row[9],
                    'review_status': row[10], 'created_at': row[11], 'updated_at': row[12]
                }
                for row in rows
            ]

    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions"""
        with self.get_connection(for_write=True) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE user_sessions 
                    SET is_active = FALSE 
                    WHERE expires_at < CURRENT_TIMESTAMP AND is_active = TRUE
                """)
                conn.execute("COMMIT")
                return cursor.rowcount
            except Exception as e:
                conn.execute("ROLLBACK")
                logger.error(f"Failed to cleanup sessions: {e}")
                return 0

    def get_review_by_id(self, review_id: str) -> Optional[Dict]:
        """Get a specific review by ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT r.*, u.username as reviewer_username
                FROM reviews r
                JOIN users u ON r.user_id = u.id
                WHERE r.id = ?
            """, (review_id,))

            row = cursor.fetchone()
            if row:
                columns = [description[0] for description in cursor.description]
                return dict(zip(columns, row))
            return None

    def update_review_status(self, review_id: str, status: str, **kwargs) -> bool:
        """Update review status and other fields"""
        with self.get_connection(for_write=True) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()

                # Build dynamic update query
                update_fields = ['review_status = ?']
                params = [status]

                if 'completed_at' in kwargs:
                    update_fields.append('completed_at = ?')
                    params.append(kwargs['completed_at'])

                if 'processing_time_ms' in kwargs:
                    update_fields.append('processing_time_ms = ?')
                    params.append(kwargs['processing_time_ms'])

                update_fields.append('updated_at = CURRENT_TIMESTAMP')
                params.append(review_id)

                cursor.execute(f"""
                    UPDATE reviews 
                    SET {', '.join(update_fields)}
                    WHERE id = ?
                """, params)

                conn.execute("COMMIT")
                return cursor.rowcount > 0
            except Exception as e:
                conn.execute("ROLLBACK")
                logger.error(f"Failed to update review status: {e}")
                return False

    def search_reviews(self, user_id: str = None, repo_name: str = None,
                       status: str = None, limit: int = 50) -> List[Dict]:
        """Search reviews with filters"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            where_clauses = []
            params = []

            if user_id:
                where_clauses.append("r.user_id = ?")
                params.append(user_id)

            if repo_name:
                where_clauses.append("r.repo_name LIKE ?")
                params.append(f"%{repo_name}%")

            if status:
                where_clauses.append("r.review_status = ?")
                params.append(status)

            where_clause = " AND ".join(where_clauses) if where_clauses else "1=1"
            params.append(limit)

            cursor.execute(f"""
                SELECT r.id, r.repo_name, r.pr_number, r.pr_title, r.pr_author,
                       r.security_score, r.quality_score, r.review_status,
                       r.created_at, r.updated_at, u.username as reviewer_username
                FROM reviews r
                JOIN users u ON r.user_id = u.id
                WHERE {where_clause}
                ORDER BY r.created_at DESC
                LIMIT ?
            """, params)

            rows = cursor.fetchall()
            columns = [description[0] for description in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

    def get_user_stats(self, user_id: str) -> Dict:
        """Get user statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Total reviews
            cursor.execute("SELECT COUNT(*) FROM reviews WHERE user_id = ?", (user_id,))
            total_reviews = cursor.fetchone()[0]

            # Reviews by status
            cursor.execute("""
                SELECT review_status, COUNT(*) 
                FROM reviews 
                WHERE user_id = ? 
                GROUP BY review_status
            """, (user_id,))
            reviews_by_status = dict(cursor.fetchall())

            # Average scores
            cursor.execute("""
                SELECT AVG(security_score) as avg_security,
                       AVG(quality_score) as avg_quality,
                       AVG(vulnerabilities_count) as avg_vulns,
                       AVG(issues_count) as avg_issues
                FROM reviews 
                WHERE user_id = ? AND review_status = 'completed'
            """, (user_id,))
            avg_row = cursor.fetchone()

            # Recent activity
            cursor.execute("""
                SELECT DATE(created_at) as date, COUNT(*) as count
                FROM reviews 
                WHERE user_id = ? AND created_at >= date('now', '-30 days')
                GROUP BY DATE(created_at)
                ORDER BY date DESC
            """, (user_id,))
            recent_activity = dict(cursor.fetchall())

            return {
                'total_reviews': total_reviews,
                'reviews_by_status': reviews_by_status,
                'averages': {
                    'security_score': avg_row[0] or 0,
                    'quality_score': avg_row[1] or 0,
                    'vulnerabilities_count': avg_row[2] or 0,
                    'issues_count': avg_row[3] or 0
                },
                'recent_activity': recent_activity
            }

    def create_notification(self, user_id: str, title: str, message: str,
                            notification_type: str = 'info', **kwargs) -> str:
        """Create a user notification"""
        notification_id = str(uuid.uuid4())

        with self.get_connection(for_write=True) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO notifications (
                        id, user_id, title, message, type, category, action_url, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    notification_id, user_id, title, message, notification_type,
                    kwargs.get('category', 'general'),
                    kwargs.get('action_url'),
                    kwargs.get('expires_at')
                ))
                conn.execute("COMMIT")
                return notification_id
            except Exception as e:
                conn.execute("ROLLBACK")
                logger.error(f"Failed to create notification: {e}")
                raise

    def get_user_notifications(self, user_id: str, unread_only: bool = False,
                               limit: int = 20) -> List[Dict]:
        """Get user notifications"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            where_clause = "user_id = ?"
            params = [user_id]

            if unread_only:
                where_clause += " AND is_read = FALSE"

            where_clause += " AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)"
            params.append(limit)

            cursor.execute(f"""
                SELECT id, title, message, type, category, action_url, 
                       is_read, created_at, read_at
                FROM notifications 
                WHERE {where_clause}
                ORDER BY created_at DESC
                LIMIT ?
            """, params)

            rows = cursor.fetchall()
            return [
                {
                    'id': row[0], 'title': row[1], 'message': row[2],
                    'type': row[3], 'category': row[4], 'action_url': row[5],
                    'is_read': row[6], 'created_at': row[7], 'read_at': row[8]
                }
                for row in rows
            ]

    def log_audit_event(self, action: str, user_id: str = None,
                        resource_type: str = None, resource_id: str = None,
                        **kwargs) -> str:
        """Log an audit event"""
        audit_id = str(uuid.uuid4())

        with self.get_connection(for_write=True) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO audit_log (
                        id, user_id, session_id, action, resource_type, resource_id,
                        old_values, new_values, ip_address, user_agent, result, error_message
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    audit_id, user_id, kwargs.get('session_id'), action,
                    resource_type, resource_id,
                    json.dumps(kwargs.get('old_values', {})),
                    json.dumps(kwargs.get('new_values', {})),
                    kwargs.get('ip_address'), kwargs.get('user_agent'),
                    kwargs.get('result', 'success'), kwargs.get('error_message')
                ))
                conn.execute("COMMIT")
                return audit_id
            except Exception as e:
                conn.execute("ROLLBACK")
                logger.error(f"Failed to log audit event: {e}")
                raise

    def health_check(self) -> Dict:
        """Check database health and return statistics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Basic connectivity test
                cursor.execute("SELECT 1")

                # Get table counts
                stats = {}
                tables = ['users', 'reviews', 'user_sessions', 'notifications']

                for table in tables:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    stats[f"{table}_count"] = cursor.fetchone()[0]

                # Check WAL mode
                cursor.execute("PRAGMA journal_mode")
                wal_mode = cursor.fetchone()[0]

                return {
                    'status': 'healthy',
                    'database_file': self.db_file,
                    'journal_mode': wal_mode,
                    'connection_pool_size': self._connection_pool.qsize(),
                    'max_connections': self.max_connections,
                    'statistics': stats,
                    'timestamp': datetime.utcnow().isoformat()
                }

        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return {
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }