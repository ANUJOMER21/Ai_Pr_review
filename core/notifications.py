import uuid
from typing import List, Dict
import logging
import sqlite3  # For error handling

from .database import DatabaseManager

logger = logging.getLogger(__name__)

class NotificationManager:
    """Manages user notifications"""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def create_notification(self, user_id: str, title: str, message: str,
                            notification_type: str = 'info') -> bool:
        """Create a new notification"""
        try:
            notification_id = str(uuid.uuid4())
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO notifications (id, user_id, title, message, type)
                    VALUES (?, ?, ?, ?, ?)
                """, (notification_id, user_id, title, message, notification_type))
                conn.commit()

            return True

        except Exception as e:
            logger.error(f"Notification creation error: {e}")
            return False

    def get_user_notifications(self, user_id: str, unread_only: bool = False) -> List[Dict]:
        """Get notifications for user"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()

                query = """
                    SELECT id, title, message, type, is_read, created_at
                    FROM notifications WHERE user_id = ?
                """

                if unread_only:
                    query += " AND is_read = FALSE"

                query += " ORDER BY created_at DESC LIMIT 50"

                cursor.execute(query, (user_id,))

                columns = [desc[0] for desc in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]

        except Exception as e:
            logger.error(f"Notification retrieval error: {e}")
            return []

    def mark_notification_read(self, notification_id: str) -> bool:
        """Mark notification as read"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE notifications SET is_read = TRUE WHERE id = ?
                """, (notification_id,))
                conn.commit()

            return True

        except Exception as e:
            logger.error(f"Notification mark read error: {e}")
            return False