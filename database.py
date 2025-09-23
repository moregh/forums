# type: ignore
import sqlite3
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone
from functools import lru_cache, wraps


def timestamp() -> float:
    return datetime.now(timezone.utc).timestamp()


def ttl_cache(maxsize: int, ttl: int):
    """
    Decorator to add TTL to lru_cache. Entries expire after ttl seconds.
    maxsize: Maximum number of cache entries (from lru_cache).
    ttl: Time-to-live in seconds.
    """
    def decorator(func):
        @lru_cache(maxsize=maxsize)
        def cached_func(*args, **kwargs):
            return func(*args, **kwargs)
        
        cache_times = {}
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache_key = cached_func.__wrapped__.__code__.co_varnames[1:][:len(args)] + tuple(args) + tuple(sorted(kwargs.items()))
            current_time = timestamp()
            
            if cache_key in cache_times:
                if current_time - cache_times[cache_key] < ttl:
                    return cached_func(*args, **kwargs)
                else:
                    cached_func.cache_clear()  # Clear the specific entry
                    del cache_times[cache_key]
            
            result = cached_func(*args, **kwargs)
            cache_times[cache_key] = current_time
            return result
        
        wrapper.cache_clear = cached_func.cache_clear  # type: ignore
        return wrapper
    return decorator


class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def execute_query(self, query: str, params: tuple = (), fetch_one: bool = False):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            if fetch_one:
                return cursor.fetchone()
            return cursor.fetchall()
    
    def execute_insert(self, query: str, params: tuple = ()) -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor.lastrowid  # type: ignore

    
    @lru_cache(maxsize=512)
    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Get user by username"""
        user = self.execute_query(
            "SELECT * FROM users WHERE username = ?",
            (username,),
            fetch_one=True
        )
        return dict(user) if user else None
    
    @lru_cache(maxsize=512)
    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """Get user by ID"""
        user = self.execute_query(
            "SELECT * FROM users WHERE user_id = ?",
            (user_id,),
            fetch_one=True
        )
        return dict(user) if user else None
    
    @ttl_cache(maxsize=1024, ttl=60)
    def check_user_exists(self, username: str, email: str) -> bool:
        """Check if username or email already exists"""
        existing = self.execute_query(
            "SELECT user_id FROM users WHERE username = ? OR email = ?",
            (username, email),
            fetch_one=True
        )
        return existing is not None
    
    def create_user(self, username: str, email: str, password_hash: str, password_salt: str) -> int:
        """Create a new user"""
        current_time = timestamp()
        return self.execute_insert("""
            INSERT INTO users (username, email, password_hash, password_salt, 
                              password_changed_at, join_date, last_activity)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username, email, password_hash, password_salt, current_time, current_time, current_time))
    
    def update_user_login(self, user_id: int, client_ip: str):
        """Update user login information"""
        current_time = timestamp()
        self.execute_query("""
            UPDATE users 
            SET failed_login_attempts = 0, 
                locked_until = NULL,
                last_activity = ?,
                last_login_at = ?,
                last_login_ip = ?
            WHERE user_id = ?
        """, (current_time, current_time, client_ip, user_id))
    
    def increment_failed_login(self, user_id: int, client_ip: str):
        """Increment failed login attempts"""
        self.execute_query("""
            UPDATE users 
            SET failed_login_attempts = failed_login_attempts + 1,
                last_login_ip = ?
            WHERE user_id = ?
        """, (client_ip, user_id))
    
    def ban_user(self, user_id: int) -> bool:
        """Ban a user"""
        self.execute_query(
            "UPDATE users SET is_banned = TRUE, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
            (user_id,)
        )
        return True
    
    def unban_user(self, user_id: int) -> bool:
        """Unban a user"""
        self.execute_query(
            "UPDATE users SET is_banned = FALSE, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
            (user_id,)
        )
        return True
    
    def promote_user_to_admin(self, user_id: int) -> bool:
        """Promote user to admin"""
        self.execute_query(
            "UPDATE users SET is_admin = TRUE, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
            (user_id,)
        )
        return True
    
    def demote_user_from_admin(self, user_id: int) -> bool:
        """Remove admin privileges"""
        self.execute_query(
            "UPDATE users SET is_admin = FALSE, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
            (user_id,)
        )
        return True
    
    @ttl_cache(maxsize=50, ttl=300)
    def get_all_users(self, page: int = 1, per_page: int = 20) -> List[Dict]:
        """Get all users with pagination"""
        offset = (page - 1) * per_page
        users = self.execute_query("""
            SELECT * FROM user_activity 
            ORDER BY last_activity DESC
            LIMIT ? OFFSET ?
        """, (per_page, offset))
        return [dict(user) for user in users]
    
    def update_user_profile(self, user_id: int, update_fields: Dict[str, Any]):
        """Update user profile fields"""
        if not update_fields:
            return

        field_updates = []
        values = []

        for field, value in update_fields.items():
            field_updates.append(f"{field} = ?")
            values.append(value)

        values.append(user_id)

        self.execute_query(
            f"UPDATE users SET {', '.join(field_updates)}, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
            tuple(values)
        )

    @ttl_cache(maxsize=1024, ttl=600)
    def get_user_info(self, user_id: int) -> Optional[Dict]:
        """Get user info with statistics for display in info cards"""
        user = self.execute_query("""
            SELECT
                u.user_id,
                u.username,
                u.email,
                u.is_admin,
                u.is_banned,
                u.join_date,
                u.last_activity,
                u.post_count,
                u.avatar_url,
                COUNT(DISTINCT t.thread_id) as thread_count,
                COALESCE(MAX(p.timestamp), 0) as last_post_at,
                CASE
                    WHEN u.last_activity > ? THEN 'online'
                    WHEN u.last_activity > ? THEN 'recently_active'
                    ELSE 'offline'
                END as activity_status,
                CASE
                    WHEN u.post_count >= 1000 THEN 'veteran'
                    WHEN u.post_count >= 500 THEN 'active'
                    WHEN u.post_count >= 100 THEN 'regular'
                    WHEN u.post_count >= 10 THEN 'member'
                    ELSE 'newcomer'
                END as user_rank,
                ROUND(
                    CASE
                        WHEN (? - u.join_date) > 0
                        THEN u.post_count / ((? - u.join_date) / 86400.0)
                        ELSE 0
                    END, 2
                ) as posts_per_day
            FROM users u
            LEFT JOIN threads t ON u.user_id = t.user_id AND t.deleted = FALSE
            LEFT JOIN posts p ON u.user_id = p.user_id AND p.deleted = FALSE
            WHERE u.user_id = ?
            GROUP BY u.user_id
        """, (
            timestamp() - 900,    # 15 minutes ago for online status
            timestamp() - 3600,   # 1 hour ago for recently active
            timestamp(),          # current time for posts per day calculation
            timestamp(),          # current time for posts per day calculation
            user_id
        ), fetch_one=True)

        if not user:
            return None

        user_dict = dict(user)

        recent_posts = self.execute_query("""
            SELECT p.timestamp, t.title as thread_title, t.thread_id
            FROM posts p
            JOIN threads t ON p.thread_id = t.thread_id
            WHERE p.user_id = ? AND p.deleted = FALSE AND t.deleted = FALSE
            ORDER BY p.timestamp DESC
            LIMIT 3
        """, (user_id,))

        user_dict['recent_posts'] = [dict(post) for post in recent_posts]

        days_since_join = max(1, (timestamp() - user_dict['join_date']) / 86400.0)
        user_dict['days_since_join'] = int(days_since_join)

        rank_descriptions = {
            'veteran': 'Forum Veteran',
            'active': 'Active Member',
            'regular': 'Regular Member',
            'member': 'Member',
            'newcomer': 'New Member'
        }
        user_dict['rank_description'] = rank_descriptions.get(user_dict['user_rank'], 'Member')

        return user_dict

    
    @ttl_cache(maxsize=256, ttl=60)
    def get_user_preferences(self, user_id: int) -> Optional[Dict]:
        """Get user preferences"""
        prefs = self.execute_query(
            "SELECT * FROM user_preferences WHERE user_id = ?",
            (user_id,),
            fetch_one=True
        )
        return dict(prefs) if prefs else None
    
    def update_user_preferences(self, user_id: int, preferences: Dict[str, Any]):
        """Update user preferences"""
        existing = self.execute_query(
            "SELECT user_id FROM user_preferences WHERE user_id = ?",
            (user_id,),
            fetch_one=True
        )
        
        if existing:
            field_updates = []
            values = []
            
            for field, value in preferences.items():
                field_updates.append(f"{field} = ?")
                values.append(value)
            
            if field_updates:
                values.append(user_id)
                self.execute_query(
                    f"UPDATE user_preferences SET {', '.join(field_updates)}, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                    tuple(values)
                )
        else:
            self.execute_insert(
                "INSERT INTO user_preferences (user_id) VALUES (?)",
                (user_id,)
            )

    @ttl_cache(maxsize=10, ttl=3600)
    def get_all_boards(self) -> List[Dict]:
        """Get all visible boards"""
        boards = self.execute_query("SELECT * FROM board_summary ORDER BY name")
        return [dict(board) for board in boards]
    
    def create_board(self, name: str, description: str, creator_id: int) -> int:
        """Create a new board"""
        board_id = self.execute_insert(
            "INSERT INTO boards (name, description, creator_id) VALUES (?, ?, ?)",
            (name, description, creator_id)
        )
        
        self.execute_insert(
            "INSERT INTO board_moderators (board_id, user_id, assigned_by) VALUES (?, ?, ?)",
            (board_id, creator_id, creator_id)
        )
        
        self.execute_insert(
            "INSERT INTO board_stats (board_id, thread_count, post_count) VALUES (?, 0, 0)",
            (board_id,)
        )
        return board_id
    
    @lru_cache(maxsize=128)
    def get_board_by_id(self, board_id: int) -> Optional[Dict]:
        """Get board by ID"""
        board = self.execute_query(
            "SELECT * FROM board_summary WHERE board_id = ?",
            (board_id,),
            fetch_one=True
        )
        return dict(board) if board else None
    
    @lru_cache(maxsize=128)
    def board_exists(self, board_id: int) -> bool:
        """Check if board exists and is not deleted"""
        board = self.execute_query(
            "SELECT board_id FROM boards WHERE board_id = ? AND deleted = FALSE",
            (board_id,),
            fetch_one=True
        )
        return board is not None

    
    @ttl_cache(maxsize=128, ttl=60)
    def get_threads_by_board(self, board_id: int, page: int = 1, per_page: int = 20) -> List[Dict]:
        """Get threads in a board with pagination"""
        offset = (page - 1) * per_page
        threads = self.execute_query("""
            SELECT * FROM active_threads 
            WHERE board_id = ?
            ORDER BY sticky DESC, last_post_at DESC
            LIMIT ? OFFSET ?
        """, (board_id, per_page, offset))
        
        mapped_threads = []
        for thread in threads:
            thread_dict = dict(thread)
            thread_dict['user_id'] = thread_dict['author_id']
            thread_dict['username'] = thread_dict['author_name'] 
            thread_dict['timestamp'] = thread_dict['created_at']
            mapped_threads.append(thread_dict)
        
        return mapped_threads
    
    @ttl_cache(maxsize=256, ttl=60)
    def get_thread_by_id(self, thread_id: int) -> Optional[Dict]:
        """Get thread by ID"""
        thread = self.execute_query("""
            SELECT * FROM active_threads 
            WHERE thread_id = ?
        """, (thread_id,), fetch_one=True)
        
        if not thread:
            return None
            
        thread_dict = dict(thread)
        thread_dict['user_id'] = thread_dict['author_id']
        thread_dict['username'] = thread_dict['author_name'] 
        thread_dict['timestamp'] = thread_dict['created_at']
        
        return thread_dict
    
    def create_thread(self, board_id: int, user_id: int, title: str, content: str) -> int:
        """Create a new thread with initial post"""
        current_time = timestamp()
        
        thread_id = self.execute_insert("""
            INSERT INTO threads (board_id, user_id, title, timestamp, last_post_at, last_post_user_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (board_id, user_id, title, current_time, current_time, user_id))
        
        self.execute_insert("""
            INSERT INTO posts (thread_id, user_id, content, timestamp)
            VALUES (?, ?, ?, ?)
        """, (thread_id, user_id, content, current_time))
        
        return thread_id
    
    @ttl_cache(maxsize=256, ttl=60)
    def thread_exists_and_accessible(self, thread_id: int) -> Optional[Dict]:
        """Check if thread exists and is accessible (not deleted, board not deleted)"""
        thread = self.execute_query("""
            SELECT t.thread_id, t.locked, t.user_id, b.deleted as board_deleted
            FROM threads t
            JOIN boards b ON t.board_id = b.board_id
            WHERE t.thread_id = ? AND t.deleted = FALSE
        """, (thread_id,), fetch_one=True)
        
        return dict(thread) if thread else None
    
    def delete_thread(self, thread_id: int):
        """Mark thread as deleted"""
        self.execute_query(
            "UPDATE threads SET deleted = TRUE, updated_at = CURRENT_TIMESTAMP WHERE thread_id = ?",
            (thread_id,)
        )
    
    def update_thread_lock_status(self, thread_id: int, locked: bool):
        """Lock or unlock a thread"""
        self.execute_query(
            "UPDATE threads SET locked = ?, updated_at = CURRENT_TIMESTAMP WHERE thread_id = ?",
            (locked, thread_id)
        )
    
    def update_thread_sticky_status(self, thread_id: int, sticky: bool):
        """Make thread sticky or unsticky"""
        self.execute_query(
            "UPDATE threads SET sticky = ?, updated_at = CURRENT_TIMESTAMP WHERE thread_id = ?",
            (sticky, thread_id)
        )
    
    def increment_thread_view_count(self, thread_id: int):
        """Increment thread view count"""
        self.execute_query(
            "UPDATE threads SET view_count = view_count + 1 WHERE thread_id = ?",
            (thread_id,)
        )

    @ttl_cache(maxsize=256, ttl=60)
    def get_posts_by_thread(self, thread_id: int, page: int = 1, per_page: int = 20) -> List[Dict]:
        """Get posts in a thread with pagination"""
        offset = (page - 1) * per_page
        posts = self.execute_query("""
            SELECT p.*, u.username 
            FROM posts p
            JOIN users u ON p.user_id = u.user_id
            WHERE p.thread_id = ? AND p.deleted = FALSE
            ORDER BY p.timestamp ASC
            LIMIT ? OFFSET ?
        """, (thread_id, per_page, offset))
        
        return [dict(post) for post in posts]
    
    @ttl_cache(maxsize=512, ttl=300)
    def get_post_by_id(self, post_id: int) -> Optional[Dict]:
        """Get post by ID"""
        post = self.execute_query("""
            SELECT p.*, u.username 
            FROM posts p
            JOIN users u ON p.user_id = u.user_id
            WHERE p.post_id = ? AND p.deleted = FALSE
        """, (post_id,), fetch_one=True)
        
        return dict(post) if post else None
    
    @ttl_cache(maxsize=512, ttl=300)
    def get_post_with_context(self, post_id: int) -> Optional[Dict]:
        """Get post with thread and board context for permission checking"""
        post = self.execute_query("""
            SELECT p.*, t.locked, t.deleted as thread_deleted, b.deleted as board_deleted
            FROM posts p
            JOIN threads t ON p.thread_id = t.thread_id
            JOIN boards b ON t.board_id = b.board_id
            WHERE p.post_id = ? AND p.deleted = FALSE
        """, (post_id,), fetch_one=True)
        
        return dict(post) if post else None
    
    def create_post(self, thread_id: int, user_id: int, content: str) -> int:
        """Create a new post"""
        current_time = timestamp()
        return self.execute_insert("""
            INSERT INTO posts (thread_id, user_id, content, timestamp)
            VALUES (?, ?, ?, ?)
        """, (thread_id, user_id, content, current_time))
    
    def update_post(self, post_id: int, content: str, editor_id: int):
        """Update post content and track edit history"""
        current_time = timestamp()
        
        current_post = self.execute_query(
            "SELECT content FROM posts WHERE post_id = ?",
            (post_id,),
            fetch_one=True
        )
        
        if current_post:
            self.execute_insert("""
                INSERT INTO post_edits (post_id, editor_id, old_content, new_content, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (post_id, editor_id, current_post["content"], content, current_time))
        
        self.execute_query("""
            UPDATE posts 
            SET content = ?, 
                edited = TRUE, 
                edit_count = edit_count + 1,
                edited_at = ?,
                edited_by = ?
            WHERE post_id = ?
        """, (content, current_time, editor_id, post_id))
    
    def delete_post(self, post_id: int):
        """Mark post as deleted"""
        self.execute_query(
            "UPDATE posts SET deleted = TRUE WHERE post_id = ?",
            (post_id,)
        )
    
    def restore_post(self, post_id: int):
        """Restore a deleted post"""
        post = self.execute_query("""
            SELECT p.*, t.deleted as thread_deleted, b.deleted as board_deleted
            FROM posts p
            JOIN threads t ON p.thread_id = t.thread_id
            JOIN boards b ON t.board_id = b.board_id
            WHERE p.post_id = ? AND p.deleted = TRUE
        """, (post_id,), fetch_one=True)
        
        if not post:
            return False
            
        if post["thread_deleted"] or post["board_deleted"]:
            return False
        
        self.execute_query(
            "UPDATE posts SET deleted = FALSE WHERE post_id = ?",
            (post_id,)
        )
        return True
    
    @ttl_cache(maxsize=128, ttl=300)
    def get_post_edit_history(self, post_id: int) -> List[Dict]:
        """Get edit history for a post"""
        edits = self.execute_query("""
            SELECT pe.*, u.username as editor_name
            FROM post_edits pe
            JOIN users u ON pe.editor_id = u.user_id
            WHERE pe.post_id = ?
            ORDER BY pe.timestamp DESC
        """, (post_id,))
        
        return [dict(edit) for edit in edits]

    
    def search_forum_content(self, query: str, search_type: str = "all", page: int = 1, per_page: int = 20) -> Dict:
        """Search across forum content"""
        offset = (page - 1) * per_page
        search_term = f"%{query}%"
        results = {"threads": [], "posts": [], "users": []}
        
        if search_type in ["all", "threads"]:
            threads = self.execute_query("""
                SELECT * FROM active_threads 
                WHERE title LIKE ? 
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """, (search_term, per_page, offset))
            results["threads"] = [dict(thread) for thread in threads]
        
        if search_type in ["all", "posts"]:
            posts = self.execute_query("""
                SELECT p.*, u.username, t.title as thread_title
                FROM posts p
                JOIN users u ON p.user_id = u.user_id
                JOIN threads t ON p.thread_id = t.thread_id
                WHERE p.content LIKE ? AND p.deleted = FALSE AND t.deleted = FALSE
                ORDER BY p.timestamp DESC
                LIMIT ? OFFSET ?
            """, (search_term, per_page, offset))
            results["posts"] = [dict(post) for post in posts]
        
        if search_type in ["all", "users"]:
            users = self.execute_query("""
                SELECT user_id, username, join_date, post_count, is_admin
                FROM users 
                WHERE username LIKE ? AND is_banned = FALSE
                ORDER BY post_count DESC
                LIMIT ? OFFSET ?
            """, (search_term, per_page, offset))
            results["users"] = [dict(user) for user in users]
        
        return results

    
    def log_security_audit(self, user_id: int, event_type: str, ip_address: str, 
                          user_agent: str = "", event_data: str = ""):
        """Log security audit event"""
        self.execute_insert("""
            INSERT INTO security_audit_log (user_id, event_type, ip_address, user_agent, event_data, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, event_type, ip_address, user_agent, event_data, timestamp()))
    
    def log_moderation_action(self, moderator_id: int, target_type: str, target_id: int, 
                             action: str, reason: str = ""):
        """Log moderation action"""
        self.execute_insert("""
            INSERT INTO moderation_log (moderator_id, target_type, target_id, action, reason, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (moderator_id, target_type, target_id, action, reason, timestamp()))
    
    def get_moderation_log(self, page: int = 1, per_page: int = 50) -> List[Dict]:
        """Get moderation log with pagination"""
        offset = (page - 1) * per_page
        logs = self.execute_query("""
            SELECT ml.*, u.username as moderator_name
            FROM moderation_log ml
            JOIN users u ON ml.moderator_id = u.user_id
            ORDER BY ml.timestamp DESC
            LIMIT ? OFFSET ?
        """, (per_page, offset))
        
        return [dict(log) for log in logs]

    
    @ttl_cache(maxsize=1, ttl=600)
    def get_forum_statistics(self) -> Dict:
        """Get comprehensive forum statistics"""
        stats = {}
        
        stats["total_users"] = self.execute_query(
            "SELECT COUNT(*) as count FROM users", fetch_one=True
        )["count"]
        
        stats["total_threads"] = self.execute_query(
            "SELECT COUNT(*) as count FROM threads WHERE deleted = FALSE", fetch_one=True
        )["count"]
        
        stats["total_posts"] = self.execute_query(
            "SELECT COUNT(*) as count FROM posts WHERE deleted = FALSE", fetch_one=True
        )["count"]
        
        stats["total_boards"] = self.execute_query(
            "SELECT COUNT(*) as count FROM boards WHERE deleted = FALSE", fetch_one=True
        )["count"]
        
        stats["users_online"] = self.execute_query("""
            SELECT COUNT(DISTINCT user_id) as count 
            FROM user_sessions 
            WHERE is_active = TRUE AND last_activity > ?
        """, (timestamp() - 900,), fetch_one=True)["count"]  # Last 15 minutes
        
        stats["posts_today"] = self.execute_query("""
            SELECT COUNT(*) as count 
            FROM posts 
            WHERE timestamp > ? AND deleted = FALSE
        """, (timestamp() - 86400,), fetch_one=True)["count"]  # Last 24 hours
        
        top_posters = self.execute_query("""
            SELECT username, post_count 
            FROM users 
            WHERE is_banned = FALSE
            ORDER BY post_count DESC 
            LIMIT 5
        """)
        stats["top_posters"] = [dict(poster) for poster in top_posters]
        
        return stats

    
    def check_rate_limit(self, identifier: str, action: str, limit: int, window_minutes: int = 60) -> bool:
        """Check if action is within rate limits"""
        window_start = timestamp() - (window_minutes * 60)
        
        self.execute_query(
            "DELETE FROM rate_limits WHERE window_start < ? AND identifier = ? AND action_type = ?",
            (window_start, identifier, action)
        )
        
        result = self.execute_query(
            "SELECT attempt_count FROM rate_limits WHERE identifier = ? AND action_type = ?",
            (identifier, action),
            fetch_one=True
        )
        
        current_count = result["attempt_count"] if result else 0
        
        if current_count >= limit:
            return False
        
        self.execute_query("""
            INSERT OR REPLACE INTO rate_limits
            (identifier, action_type, attempt_count, window_start)
            VALUES (?, ?, ?, ?)
        """, (identifier, action, current_count + 1, timestamp()))

        return True

    def create_user_session(self, user_id: int, csrf_token: str, client_ip: str, user_agent: str) -> str:
        """Create a new user session with CSRF token"""
        import secrets
        session_id = secrets.token_urlsafe(64)
        current_time = timestamp()
        expires_at = current_time + (24 * 3600)  # 24 hours

        self.execute_insert("""
            INSERT INTO user_sessions
            (session_id, user_id, csrf_token, ip_address, user_agent, created_at, expires_at, last_activity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (session_id, user_id, csrf_token, client_ip, user_agent, current_time, expires_at, current_time))

        return session_id

    def get_session_csrf_token(self, session_id: str) -> Optional[str]:
        """Get CSRF token for a session"""
        result = self.execute_query("""
            SELECT csrf_token FROM user_sessions
            WHERE session_id = ? AND expires_at > ? AND is_active = TRUE AND revoked = FALSE
        """, (session_id, timestamp()), fetch_one=True)

        return result["csrf_token"] if result else None

    def update_session_activity(self, session_id: str):
        """Update session last activity timestamp"""
        self.execute_query("""
            UPDATE user_sessions
            SET last_activity = ?
            WHERE session_id = ? AND expires_at > ? AND is_active = TRUE
        """, (timestamp(), session_id, timestamp()))

    def invalidate_user_sessions(self, user_id: int):
        """Invalidate all sessions for a user"""
        self.execute_query("""
            UPDATE user_sessions
            SET revoked = TRUE, is_active = FALSE
            WHERE user_id = ?
        """, (user_id,))