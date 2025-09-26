# type: ignore
import aiosqlite
import asyncio
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone
from functools import wraps
import hashlib
import json
from config import (DEFAULT_CACHE_TTL, CACHE_CLEANUP_INTERVAL, CACHE_EXPIRE_TIME,
                   USER_CACHE_TTL, BOARD_CACHE_TTL, THREAD_CACHE_TTL,
                   DEFAULT_PAGE_SIZE, ADMIN_PAGE_SIZE, RECENT_POSTS_LIMIT,
                   RANK_VETERAN_POSTS, RANK_ACTIVE_POSTS, RANK_REGULAR_POSTS, RANK_MEMBER_POSTS,
                   SECONDS_PER_DAY, MINUTES_15, SECONDS_PER_HOUR, TOP_BOARDS_LIMIT)


def timestamp() -> float:
    return datetime.now(timezone.utc).timestamp()


class AsyncTTLCache:
    """Async-compatible TTL cache for database operations"""

    def __init__(self):
        self.cache = {}
        self.timestamps = {}

    def _make_key(self, func_name: str, args: tuple, kwargs: dict) -> str:
        """Create a cache key from function name and arguments"""
        key_data = {
            'func': func_name,
            'args': args,
            'kwargs': sorted(kwargs.items()) if kwargs else []
        }
        key_str = json.dumps(key_data, sort_keys=True, default=str)
        return hashlib.md5(key_str.encode()).hexdigest()

    def get(self, key: str, ttl: int) -> Optional[Any]:
        """Get cached value if not expired"""
        if key not in self.cache:
            return None

        if timestamp() - self.timestamps[key] > ttl:
            del self.cache[key]
            del self.timestamps[key]
            return None

        return self.cache[key]

    def set(self, key: str, value: Any):
        """Set cached value with current timestamp"""
        self.cache[key] = value
        self.timestamps[key] = timestamp()

    def clear_expired(self, ttl: int):
        """Remove expired entries"""
        current_time = timestamp()
        expired_keys = [
            key for key, ts in self.timestamps.items()
            if current_time - ts > ttl
        ]
        for key in expired_keys:
            if key in self.cache:
                del self.cache[key]
            if key in self.timestamps:
                del self.timestamps[key]

# Global cache instance
db_cache = AsyncTTLCache()

def async_ttl_cache(ttl: int = DEFAULT_CACHE_TTL):
    """
    Async-compatible TTL cache decorator
    ttl: Time-to-live in seconds (default 5 minutes)
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Skip caching for self parameter and generate key
            cache_args = args[1:] if args and hasattr(args[0], '__class__') else args
            cache_key = db_cache._make_key(func.__name__, cache_args, kwargs)

            # Try to get from cache
            cached_result = db_cache.get(cache_key, ttl)
            if cached_result is not None:
                return cached_result

            # Execute function and cache result
            result = await func(*args, **kwargs)
            db_cache.set(cache_key, result)
            return result

        wrapper.cache_clear = lambda: db_cache.cache.clear()
        return wrapper
    return decorator


class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._cache_cleanup_task = None

    async def start_cache_cleanup(self):
        """Start background cache cleanup task"""
        if self._cache_cleanup_task is None:
            self._cache_cleanup_task = asyncio.create_task(self._periodic_cache_cleanup())

    async def _periodic_cache_cleanup(self):
        """Periodically clean up expired cache entries"""
        while True:
            await asyncio.sleep(CACHE_CLEANUP_INTERVAL)  # Every 10 minutes
            db_cache.clear_expired(ttl=CACHE_EXPIRE_TIME)  # Remove entries older than 30 minutes

    async def stop_cache_cleanup(self):
        """Stop background cache cleanup task"""
        if self._cache_cleanup_task:
            self._cache_cleanup_task.cancel()
            self._cache_cleanup_task = None

    def invalidate_user_cache(self, user_id: int = None, username: str = None):
        """Invalidate user-related cache entries"""
        # Clear specific user caches
        if user_id:
            cache_keys = [key for key in db_cache.cache.keys() if f'get_user_by_id' in key and str(user_id) in key]
            for key in cache_keys:
                if key in db_cache.cache:
                    del db_cache.cache[key]
                if key in db_cache.timestamps:
                    del db_cache.timestamps[key]

        if username:
            cache_keys = [key for key in db_cache.cache.keys() if f'get_user_by_username' in key and username in key]
            for key in cache_keys:
                if key in db_cache.cache:
                    del db_cache.cache[key]
                if key in db_cache.timestamps:
                    del db_cache.timestamps[key]

    def invalidate_board_cache(self, board_id: int = None):
        """Invalidate board-related cache entries"""
        patterns = ['get_all_boards', 'get_board_by_id']
        if board_id:
            patterns.append(str(board_id))

        for pattern in patterns:
            cache_keys = [key for key in db_cache.cache.keys() if pattern in key]
            for key in cache_keys:
                if key in db_cache.cache:
                    del db_cache.cache[key]
                if key in db_cache.timestamps:
                    del db_cache.timestamps[key]

    def invalidate_thread_cache(self, thread_id: int = None, board_id: int = None):
        """Invalidate thread-related cache entries"""
        patterns = ['get_thread']
        if thread_id:
            patterns.append(str(thread_id))
        if board_id:
            patterns.append(str(board_id))

        for pattern in patterns:
            cache_keys = [key for key in db_cache.cache.keys() if pattern in key]
            for key in cache_keys:
                if key in db_cache.cache:
                    del db_cache.cache[key]
                if key in db_cache.timestamps:
                    del db_cache.timestamps[key]

    async def get_connection(self):
        conn = await aiosqlite.connect(self.db_path)
        conn.row_factory = aiosqlite.Row
        return conn

    async def execute_query(self, query: str, params: tuple = (), fetch_one: bool = False):
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.cursor()
            await cursor.execute(query, params)

            # Commit if this is a write operation (INSERT, UPDATE, DELETE)
            if query.strip().upper().startswith(('INSERT', 'UPDATE', 'DELETE')):
                await conn.commit()

            if fetch_one:
                result = await cursor.fetchone()
            else:
                result = await cursor.fetchall()
            await cursor.close()
            return result

    async def execute_insert(self, query: str, params: tuple = ()) -> int:
        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.cursor()
            await cursor.execute(query, params)
            await conn.commit()
            lastrowid = cursor.lastrowid
            await cursor.close()
            return lastrowid  # type: ignore

    
    @async_ttl_cache(ttl=USER_CACHE_TTL)  # Cache for 5 minutes
    async def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Get user by username"""
        user = await self.execute_query(
            "SELECT * FROM users WHERE username = ?",
            (username,),
            fetch_one=True
        )
        return dict(user) if user else None
    
    @async_ttl_cache(ttl=USER_CACHE_TTL)  # Cache for 5 minutes
    async def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """Get user by ID"""
        user = await self.execute_query(
            "SELECT * FROM users WHERE user_id = ?",
            (user_id,),
            fetch_one=True
        )
        return dict(user) if user else None
    
    async def check_user_exists(self, username: str, email: str) -> bool:
        """Check if username or email already exists"""
        existing = await self.execute_query(
            "SELECT user_id FROM users WHERE username = ? OR email = ?",
            (username, email),
            fetch_one=True
        )
        return existing is not None
    
    async def create_user(self, username: str, email: str, password_hash: str, password_salt: str) -> int:
        """Create a new user"""
        current_time = timestamp()
        return await self.execute_insert("""
            INSERT INTO users (username, email, password_hash, password_salt, 
                              password_changed_at, join_date, last_activity)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username, email, password_hash, password_salt, current_time, current_time, current_time))
    
    async def update_user_login(self, user_id: int, client_ip: str):
        """Update user login information"""
        current_time = timestamp()
        await self.execute_query("""
            UPDATE users
            SET failed_login_attempts = 0,
                locked_until = NULL,
                last_activity = ?,
                last_login_at = ?,
                last_login_ip = ?
            WHERE user_id = ?
        """, (current_time, current_time, client_ip, user_id))

        # Invalidate user cache after update
        self.invalidate_user_cache(user_id=user_id)
    
    async def increment_failed_login(self, user_id: int, client_ip: str):
        """Increment failed login attempts"""
        await self.execute_query("""
            UPDATE users 
            SET failed_login_attempts = failed_login_attempts + 1,
                last_login_ip = ?
            WHERE user_id = ?
        """, (client_ip, user_id))
    
    async def ban_user(self, user_id: int) -> bool:
        """Ban a user"""
        await self.execute_query(
            "UPDATE users SET is_banned = TRUE, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
            (user_id,)
        )
        return True
    
    async def unban_user(self, user_id: int) -> bool:
        """Unban a user"""
        await self.execute_query(
            "UPDATE users SET is_banned = FALSE, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
            (user_id,)
        )
        return True
    
    async def promote_user_to_admin(self, user_id: int) -> bool:
        """Promote user to admin"""
        await self.execute_query(
            "UPDATE users SET is_admin = TRUE, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
            (user_id,)
        )
        return True
    
    async def demote_user_from_admin(self, user_id: int) -> bool:
        """Remove admin privileges"""
        await self.execute_query(
            "UPDATE users SET is_admin = FALSE, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
            (user_id,)
        )
        return True
    
    
    async def get_all_users(self, page: int = 1, per_page: int = DEFAULT_PAGE_SIZE) -> List[Dict]:
        """Get all users with pagination"""
        offset = (page - 1) * per_page
        users = await self.execute_query("""
            SELECT * FROM user_activity 
            ORDER BY last_activity DESC
            LIMIT ? OFFSET ?
        """, (per_page, offset))
        return [dict(user) for user in users]
    
    async def update_user_profile(self, user_id: int, update_fields: Dict[str, Any]):
        """Update user profile fields"""
        if not update_fields:
            return

        field_updates = []
        values = []

        for field, value in update_fields.items():
            field_updates.append(f"{field} = ?")
            values.append(value)

        values.append(user_id)

        await self.execute_query(
            f"UPDATE users SET {', '.join(field_updates)}, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
            tuple(values)
        )

    
    async def get_user_info(self, user_id: int) -> Optional[Dict]:
        """Get user info with statistics for display in info cards"""
        user = await self.execute_query("""
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
                    WHEN u.post_count >= ? THEN 'veteran'
                    WHEN u.post_count >= ? THEN 'active'
                    WHEN u.post_count >= ? THEN 'regular'
                    WHEN u.post_count >= ? THEN 'member'
                    ELSE 'newcomer'
                END as user_rank,
                ROUND(
                    CASE
                        WHEN (? - u.join_date) > 0
                        THEN u.post_count / ((? - u.join_date) / ?)
                        ELSE 0
                    END, 2
                ) as posts_per_day
            FROM users u
            LEFT JOIN threads t ON u.user_id = t.user_id AND t.deleted = FALSE
            LEFT JOIN posts p ON u.user_id = p.user_id AND p.deleted = FALSE
            WHERE u.user_id = ?
            GROUP BY u.user_id
        """, (
            timestamp() - MINUTES_15,    # 15 minutes ago for online status
            timestamp() - SECONDS_PER_HOUR,   # 1 hour ago for recently active
            RANK_VETERAN_POSTS,       # veteran rank threshold
            RANK_ACTIVE_POSTS,        # active rank threshold
            RANK_REGULAR_POSTS,       # regular rank threshold
            RANK_MEMBER_POSTS,        # member rank threshold
            timestamp(),              # current time for posts per day calculation
            timestamp(),              # current time for posts per day calculation
            SECONDS_PER_DAY,          # seconds per day for posts per day calculation
            user_id
        ), fetch_one=True)

        if not user:
            return None

        user_dict = dict(user)

        recent_posts = await self.execute_query("""
            SELECT p.timestamp, t.title as thread_title, t.thread_id
            FROM posts p
            JOIN threads t ON p.thread_id = t.thread_id
            WHERE p.user_id = ? AND p.deleted = FALSE AND t.deleted = FALSE
            ORDER BY p.timestamp DESC
            LIMIT ?
        """, (user_id, RECENT_POSTS_LIMIT))

        user_dict['recent_posts'] = [dict(post) for post in recent_posts]

        days_since_join = max(1, (timestamp() - user_dict['join_date']) / SECONDS_PER_DAY)
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

    
    
    async def get_user_preferences(self, user_id: int) -> Optional[Dict]:
        """Get user preferences"""
        prefs = await self.execute_query(
            "SELECT * FROM user_preferences WHERE user_id = ?",
            (user_id,),
            fetch_one=True
        )
        return dict(prefs) if prefs else None
    
    async def update_user_preferences(self, user_id: int, preferences: Dict[str, Any]):
        """Update user preferences"""
        existing = await self.execute_query(
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
                await self.execute_query(
                    f"UPDATE user_preferences SET {', '.join(field_updates)}, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                    tuple(values)
                )
        else:
            await self.execute_insert(
                "INSERT INTO user_preferences (user_id) VALUES (?)",
                (user_id,)
            )

    
    @async_ttl_cache(ttl=BOARD_CACHE_TTL)  # Cache for 10 minutes (boards change rarely)
    async def get_all_boards(self) -> List[Dict]:
        """Get all visible boards"""
        boards = await self.execute_query("SELECT * FROM board_summary ORDER BY name")
        return [dict(board) for board in boards]
    
    async def create_board(self, name: str, description: str, creator_id: int) -> int:
        """Create a new board"""
        board_id = await self.execute_insert(
            "INSERT INTO boards (name, description, creator_id) VALUES (?, ?, ?)",
            (name, description, creator_id)
        )

        await self.execute_insert(
            "INSERT INTO board_moderators (board_id, user_id, assigned_by) VALUES (?, ?, ?)",
            (board_id, creator_id, creator_id)
        )

        await self.execute_insert(
            "INSERT INTO board_stats (board_id, thread_count, post_count) VALUES (?, 0, 0)",
            (board_id,)
        )

        # Invalidate board cache after creation
        self.invalidate_board_cache()

        return board_id
    
    
    @async_ttl_cache(ttl=BOARD_CACHE_TTL)  # Cache for 10 minutes
    async def get_board_by_id(self, board_id: int) -> Optional[Dict]:
        """Get board by ID"""
        board = await self.execute_query(
            "SELECT * FROM board_summary WHERE board_id = ?",
            (board_id,),
            fetch_one=True
        )
        return dict(board) if board else None
    
    
    async def board_exists(self, board_id: int) -> bool:
        """Check if board exists and is not deleted"""
        board = await self.execute_query(
            "SELECT board_id FROM boards WHERE board_id = ? AND deleted = FALSE",
            (board_id,),
            fetch_one=True
        )
        return board is not None

    
    
    async def get_threads_by_board(self, board_id: int, page: int = 1, per_page: int = DEFAULT_PAGE_SIZE) -> List[Dict]:
        """Get threads in a board with pagination"""
        offset = (page - 1) * per_page
        threads = await self.execute_query("""
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
    
    
    @async_ttl_cache(ttl=THREAD_CACHE_TTL)  # Cache for 3 minutes (threads change more frequently)
    async def get_thread_by_id(self, thread_id: int) -> Optional[Dict]:
        """Get thread by ID"""
        thread = await self.execute_query("""
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
    
    async def create_thread(self, board_id: int, user_id: int, title: str, content: str) -> int:
        """Create a new thread with initial post"""
        current_time = timestamp()
        
        thread_id = await self.execute_insert("""
            INSERT INTO threads (board_id, user_id, title, timestamp, last_post_at, last_post_user_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (board_id, user_id, title, current_time, current_time, user_id))
        
        await self.execute_insert("""
            INSERT INTO posts (thread_id, user_id, content, timestamp)
            VALUES (?, ?, ?, ?)
        """, (thread_id, user_id, content, current_time))
        
        return thread_id
    
    
    async def thread_exists_and_accessible(self, thread_id: int) -> Optional[Dict]:
        """Check if thread exists and is accessible (not deleted, board not deleted)"""
        thread = await self.execute_query("""
            SELECT t.thread_id, t.locked, t.user_id, b.deleted as board_deleted
            FROM threads t
            JOIN boards b ON t.board_id = b.board_id
            WHERE t.thread_id = ? AND t.deleted = FALSE
        """, (thread_id,), fetch_one=True)
        
        return dict(thread) if thread else None
    
    async def delete_thread(self, thread_id: int):
        """Mark thread as deleted"""
        await self.execute_query(
            "UPDATE threads SET deleted = TRUE, updated_at = CURRENT_TIMESTAMP WHERE thread_id = ?",
            (thread_id,)
        )
    
    async def update_thread_lock_status(self, thread_id: int, locked: bool):
        """Lock or unlock a thread"""
        await self.execute_query(
            "UPDATE threads SET locked = ?, updated_at = CURRENT_TIMESTAMP WHERE thread_id = ?",
            (locked, thread_id)
        )
    
    async def update_thread_sticky_status(self, thread_id: int, sticky: bool):
        """Make thread sticky or unsticky"""
        await self.execute_query(
            "UPDATE threads SET sticky = ?, updated_at = CURRENT_TIMESTAMP WHERE thread_id = ?",
            (sticky, thread_id)
        )
    
    async def increment_thread_view_count(self, thread_id: int):
        """Increment thread view count"""
        await self.execute_query(
            "UPDATE threads SET view_count = view_count + 1 WHERE thread_id = ?",
            (thread_id,)
        )

    
    async def get_posts_by_thread(self, thread_id: int, page: int = 1, per_page: int = DEFAULT_PAGE_SIZE) -> List[Dict]:
        """Get posts in a thread with pagination"""
        offset = (page - 1) * per_page
        posts = await self.execute_query("""
            SELECT p.*, u.username 
            FROM posts p
            JOIN users u ON p.user_id = u.user_id
            WHERE p.thread_id = ? AND p.deleted = FALSE
            ORDER BY p.timestamp ASC
            LIMIT ? OFFSET ?
        """, (thread_id, per_page, offset))
        
        return [dict(post) for post in posts]
    
    
    async def get_post_by_id(self, post_id: int) -> Optional[Dict]:
        """Get post by ID"""
        post = await self.execute_query("""
            SELECT p.*, u.username 
            FROM posts p
            JOIN users u ON p.user_id = u.user_id
            WHERE p.post_id = ? AND p.deleted = FALSE
        """, (post_id,), fetch_one=True)
        
        return dict(post) if post else None
    
    
    async def get_post_with_context(self, post_id: int) -> Optional[Dict]:
        """Get post with thread and board context for permission checking"""
        post = await self.execute_query("""
            SELECT p.*, t.locked, t.deleted as thread_deleted, b.deleted as board_deleted
            FROM posts p
            JOIN threads t ON p.thread_id = t.thread_id
            JOIN boards b ON t.board_id = b.board_id
            WHERE p.post_id = ? AND p.deleted = FALSE
        """, (post_id,), fetch_one=True)
        
        return dict(post) if post else None

    async def check_post_exists(self, post_id: int) -> Optional[Dict]:
        """Check if post exists (including deleted posts) for better error messages"""
        post = await self.execute_query("""
            SELECT p.post_id, p.deleted, p.user_id, t.locked, t.deleted as thread_deleted, b.deleted as board_deleted
            FROM posts p
            JOIN threads t ON p.thread_id = t.thread_id
            JOIN boards b ON t.board_id = b.board_id
            WHERE p.post_id = ?
        """, (post_id,), fetch_one=True)

        return dict(post) if post else None

    async def create_post(self, thread_id: int, user_id: int, content: str) -> int:
        """Create a new post"""
        current_time = timestamp()
        return await self.execute_insert("""
            INSERT INTO posts (thread_id, user_id, content, timestamp)
            VALUES (?, ?, ?, ?)
        """, (thread_id, user_id, content, current_time))
    
    async def update_post(self, post_id: int, content: str, editor_id: int):
        """Update post content and track edit history"""
        current_time = timestamp()
        
        current_post = await self.execute_query(
            "SELECT content FROM posts WHERE post_id = ?",
            (post_id,),
            fetch_one=True
        )
        
        if current_post:
            await self.execute_insert("""
                INSERT INTO post_edits (post_id, editor_id, old_content, new_content, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (post_id, editor_id, current_post["content"], content, current_time))
        
        await self.execute_query("""
            UPDATE posts 
            SET content = ?, 
                edited = TRUE, 
                edit_count = edit_count + 1,
                edited_at = ?,
                edited_by = ?
            WHERE post_id = ?
        """, (content, current_time, editor_id, post_id))
    
    async def delete_post(self, post_id: int):
        """Mark post as deleted"""
        await self.execute_query(
            "UPDATE posts SET deleted = TRUE WHERE post_id = ?",
            (post_id,)
        )
    
    async def restore_post(self, post_id: int):
        """Restore a deleted post"""
        post = await self.execute_query("""
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
        
        await self.execute_query(
            "UPDATE posts SET deleted = FALSE WHERE post_id = ?",
            (post_id,)
        )
        return True
    
    
    async def get_post_edit_history(self, post_id: int) -> List[Dict]:
        """Get edit history for a post"""
        edits = await self.execute_query("""
            SELECT pe.*, u.username as editor_name
            FROM post_edits pe
            JOIN users u ON pe.editor_id = u.user_id
            WHERE pe.post_id = ?
            ORDER BY pe.timestamp DESC
        """, (post_id,))
        
        return [dict(edit) for edit in edits]

    
    async def search_forum_content(self, query: str, search_type: str = "all", page: int = 1, per_page: int = DEFAULT_PAGE_SIZE) -> Dict:
        """Search across forum content"""
        offset = (page - 1) * per_page
        search_term = f"%{query}%"
        results = {"threads": [], "posts": [], "users": []}
        
        if search_type in ["all", "threads"]:
            threads = await self.execute_query("""
                SELECT * FROM active_threads 
                WHERE title LIKE ? 
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """, (search_term, per_page, offset))
            results["threads"] = [dict(thread) for thread in threads]
        
        if search_type in ["all", "posts"]:
            posts = await self.execute_query("""
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
            users = await self.execute_query("""
                SELECT user_id, username, join_date, post_count, is_admin
                FROM users 
                WHERE username LIKE ? AND is_banned = FALSE
                ORDER BY post_count DESC
                LIMIT ? OFFSET ?
            """, (search_term, per_page, offset))
            results["users"] = [dict(user) for user in users]
        
        return results

    
    async def log_security_audit(self, user_id: int, event_type: str, ip_address: str, 
                          user_agent: str = "", event_data: str = ""):
        """Log security audit event"""
        await self.execute_insert("""
            INSERT INTO security_audit_log (user_id, event_type, ip_address, user_agent, event_data, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, event_type, ip_address, user_agent, event_data, timestamp()))
    
    async def log_moderation_action(self, moderator_id: int, target_type: str, target_id: int, 
                             action: str, reason: str = ""):
        """Log moderation action"""
        await self.execute_insert("""
            INSERT INTO moderation_log (moderator_id, target_type, target_id, action, reason, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (moderator_id, target_type, target_id, action, reason, timestamp()))
    
    async def get_moderation_log(self, page: int = 1, per_page: int = ADMIN_PAGE_SIZE) -> List[Dict]:
        """Get moderation log with pagination"""
        offset = (page - 1) * per_page
        logs = await self.execute_query("""
            SELECT ml.*, u.username as moderator_name
            FROM moderation_log ml
            JOIN users u ON ml.moderator_id = u.user_id
            ORDER BY ml.timestamp DESC
            LIMIT ? OFFSET ?
        """, (per_page, offset))
        
        return [dict(log) for log in logs]

    
    
    async def get_forum_statistics(self) -> Dict:
        """Get comprehensive forum statistics"""
        stats = {}
        
        result = await self.execute_query(
            "SELECT COUNT(*) as count FROM users", fetch_one=True
        )
        stats["total_users"] = result["count"]
        
        result = await self.execute_query(
            "SELECT COUNT(*) as count FROM threads WHERE deleted = FALSE", fetch_one=True
        )
        stats["total_threads"] = result["count"]
        
        result = await self.execute_query(
            "SELECT COUNT(*) as count FROM posts WHERE deleted = FALSE", fetch_one=True
        )
        stats["total_posts"] = result["count"]
        
        result = await self.execute_query(
            "SELECT COUNT(*) as count FROM boards WHERE deleted = FALSE", fetch_one=True
        )
        stats["total_boards"] = result["count"]
        
        result = await self.execute_query("""
            SELECT COUNT(DISTINCT user_id) as count
            FROM user_sessions
            WHERE is_active = TRUE AND last_activity > ?
        """, (timestamp() - 900,), fetch_one=True)  # Last 15 minutes
        stats["users_online"] = result["count"]
        
        result = await self.execute_query("""
            SELECT COUNT(*) as count
            FROM posts
            WHERE timestamp > ? AND deleted = FALSE
        """, (timestamp() - 86400,), fetch_one=True)  # Last 24 hours
        stats["posts_today"] = result["count"]
        
        top_posters = await self.execute_query("""
            SELECT username, post_count
            FROM users
            WHERE is_banned = FALSE
            ORDER BY post_count DESC
            LIMIT ?
        """, (TOP_BOARDS_LIMIT,))
        stats["top_posters"] = [dict(poster) for poster in top_posters]
        
        return stats

    
    async def check_rate_limit(self, identifier: str, action: str, limit: int, window_minutes: int = 60) -> bool:
        """Check if action is within rate limits"""
        window_start = timestamp() - (window_minutes * 60)
        
        await self.execute_query(
            "DELETE FROM rate_limits WHERE window_start < ? AND identifier = ? AND action_type = ?",
            (window_start, identifier, action)
        )
        
        result = await self.execute_query(
            "SELECT attempt_count FROM rate_limits WHERE identifier = ? AND action_type = ?",
            (identifier, action),
            fetch_one=True
        )
        
        current_count = result["attempt_count"] if result else 0
        
        if current_count >= limit:
            return False
        
        await self.execute_query("""
            INSERT OR REPLACE INTO rate_limits
            (identifier, action_type, attempt_count, window_start)
            VALUES (?, ?, ?, ?)
        """, (identifier, action, current_count + 1, timestamp()))

        return True

    async def create_user_session(self, user_id: int, csrf_token: str, client_ip: str, user_agent: str) -> str:
        """Create a new user session with CSRF token"""
        import secrets
        session_id = secrets.token_urlsafe(64)
        current_time = timestamp()
        expires_at = current_time + (24 * 3600)  # 24 hours

        await self.execute_insert("""
            INSERT INTO user_sessions
            (session_id, user_id, csrf_token, ip_address, user_agent, created_at, expires_at, last_activity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (session_id, user_id, csrf_token, client_ip, user_agent, current_time, expires_at, current_time))

        return session_id

    async def get_session_csrf_token(self, session_id: str) -> Optional[str]:
        """Get CSRF token for a session"""
        result = await self.execute_query("""
            SELECT csrf_token FROM user_sessions
            WHERE session_id = ? AND expires_at > ? AND is_active = TRUE AND revoked = FALSE
        """, (session_id, timestamp()), fetch_one=True)

        return result["csrf_token"] if result else None

    async def update_session_csrf_token(self, session_id: str, csrf_token: str):
        """Update CSRF token for a session"""
        await self.execute_query("""
            UPDATE user_sessions
            SET csrf_token = ?
            WHERE session_id = ? AND expires_at > ? AND is_active = TRUE AND revoked = FALSE
        """, (csrf_token, session_id, timestamp()))

    async def update_session_activity(self, session_id: str):
        """Update session last activity timestamp"""
        await self.execute_query("""
            UPDATE user_sessions
            SET last_activity = ?
            WHERE session_id = ? AND expires_at > ? AND is_active = TRUE
        """, (timestamp(), session_id, timestamp()))

    async def invalidate_user_sessions(self, user_id: int):
        """Invalidate all sessions for a user"""
        await self.execute_query("""
            UPDATE user_sessions
            SET revoked = TRUE, is_active = FALSE
            WHERE user_id = ?
        """, (user_id,))