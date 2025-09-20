from fastapi import HTTPException, Depends, status, Request
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import validator
from typing import List


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """Validate JWT token and return current user"""
    try:
        payload = security_manager.verify_token(credentials.credentials)
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        # Get user from database
        user = db.execute_query(
            "SELECT * FROM users WHERE user_id = ? AND is_banned = FALSE",
            (user_id,),
            fetch_one=True
        )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or banned"
            )
        
        return dict(user)
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

async def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """Require admin privileges"""
    if not current_user.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user

# =============================================================================
# AUTHENTICATION ENDPOINTS
# =============================================================================

def create_auth_router() -> APIRouter:
    router = APIRouter(prefix="/api/auth", tags=["authentication"])

    @router.post("/register", response_model=TokenResponse)
    async def register(user_data: UserRegister, request: Request):
        """Register a new user"""
        client_ip = await get_client_ip(request)
        
        # Rate limiting
        if not rate_limiter.check_rate_limit(client_ip, "register", 5, 60):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many registration attempts"
            )
        
        # Check if user exists
        existing = db.execute_query(
            "SELECT user_id FROM users WHERE username = ? OR email = ?",
            (user_data.username, user_data.email),
            fetch_one=True
        )
        
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username or email already exists"
            )
        
        # Create user
        password_hash, password_salt = security_manager.hash_password(user_data.password)
        current_time = time.time()
        
        user_id = db.execute_insert("""
            INSERT INTO users (username, email, password_hash, password_salt, 
                              password_changed_at, join_date, last_activity)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_data.username, user_data.email, password_hash, password_salt,
              current_time, current_time, current_time))
        
        # Log registration
        audit_logger.log_event(user_id, "user_registered", client_ip)
        
        # Create access token
        access_token = security_manager.create_access_token({"sub": str(user_id)})
        
        # Get user data for response
        user = db.execute_query(
            "SELECT * FROM users WHERE user_id = ?",
            (user_id,),
            fetch_one=True
        )
        
        return TokenResponse(
            access_token=access_token,
            expires_in=security_manager.access_token_expire_minutes * 60,
            user=UserResponse(**dict(user))
        )

    @router.post("/login", response_model=TokenResponse)
    async def login(login_data: UserLogin, request: Request):
        """Authenticate user and return token"""
        client_ip = await get_client_ip(request)
        
        # Rate limiting
        if not rate_limiter.check_rate_limit(client_ip, "login", 10, 60):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts"
            )
        
        # Get user
        user: dict = db.execute_query(
            "SELECT * FROM users WHERE username = ?",
            (login_data.username,),
            fetch_one=True
        )

        if not user:
            audit_logger.log_event(None, "login_failed", client_ip, 
                                 event_data=f"username: {login_data.username}", risk_score=3)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        if not security_manager.verify_password(login_data.password, user["password_hash"]):
            # Log failed attempt
            db.execute_query("""
                UPDATE users 
                SET failed_login_attempts = failed_login_attempts + 1,
                    last_login_ip = ?
                WHERE user_id = ?
            """, (client_ip, user["user_id"]))
            
            audit_logger.log_event(user["user_id"], "login_failed", client_ip, risk_score=5)
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Check if account is locked
        if user["locked_until"] and user["locked_until"] > time.time():
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account temporarily locked"
            )
        
        # Check if banned
        if user["is_banned"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account banned"
            )
        
        # Reset failed attempts and update login info
        db.execute_query("""
            UPDATE users 
            SET failed_login_attempts = 0, 
                locked_until = NULL,
                last_activity = ?,
                last_login_at = ?,
                last_login_ip = ?
            WHERE user_id = ?
        """, (time.time(), time.time(), client_ip, user["user_id"]))
        
        # Log successful login
        audit_logger.log_event(user["user_id"], "login_success", client_ip)
        
        # Create access token
        access_token = security_manager.create_access_token({"sub": str(user["user_id"])})
        
        return TokenResponse(
            access_token=access_token,
            expires_in=security_manager.access_token_expire_minutes * 60,
            user=UserResponse(**dict(user))
        )

    @router.post("/refresh", response_model=TokenResponse)
    async def refresh_token(current_user: dict = Depends(get_current_user)):
        """Refresh access token"""
        access_token = security_manager.create_access_token({"sub": str(current_user["user_id"])})
        
        return TokenResponse(
            access_token=access_token,
            expires_in=security_manager.access_token_expire_minutes * 60,
            user=UserResponse(**current_user)
        )

    return router

# =============================================================================
# BOARD ENDPOINTS
# =============================================================================

def create_board_router() -> APIRouter:
    router = APIRouter(prefix="/api/boards", tags=["boards"])

    @router.get("", response_model=List[BoardResponse])
    async def get_boards():
        """Get all visible boards"""
        boards = db.execute_query("SELECT * FROM board_summary ORDER BY name")
        return [BoardResponse(**dict(board)) for board in boards]

    @router.post("", response_model=BoardResponse)
    async def create_board(
        board_data: BoardCreate,
        current_user: dict = Depends(require_admin)
    ):
        """Create a new board (admin only)"""
        board_id = db.execute_insert(
            "INSERT INTO boards (name, description, creator_id) VALUES (?, ?, ?)",
            (board_data.name, board_data.description, current_user["user_id"])
        )
        
        # Add creator as moderator
        db.execute_insert(
            "INSERT INTO board_moderators (board_id, user_id, assigned_by) VALUES (?, ?, ?)",
            (board_id, current_user["user_id"], current_user["user_id"])
        )
        
        # Initialize board stats
        db.execute_insert(
            "INSERT INTO board_stats (board_id, thread_count, post_count) VALUES (?, 0, 0)",
            (board_id,)
        )
        
        # Log moderation action
        db.execute_insert("""
            INSERT INTO moderation_log (moderator_id, target_type, target_id, action, timestamp)
            VALUES (?, 'user', ?, 'demote_admin', ?)
        """, (current_user["user_id"], user_id, time.time()))
        
        return {"message": "Admin privileges removed successfully"}

    @router.get("/users")
    async def get_all_users(
        current_user: dict = Depends(require_admin),
        page: int = 1,
        per_page: int = 50
    ):
        """Get all users for admin panel"""
        offset = (page - 1) * per_page
        
        users = db.execute_query("""
            SELECT user_id, username, email, is_admin, is_banned, 
                   join_date, last_activity, post_count
            FROM users 
            ORDER BY join_date DESC
            LIMIT ? OFFSET ?
        """, (per_page, offset))
        
        return [dict(user) for user in users]

    @router.get("/moderation-log")
    async def get_moderation_log(
        current_user: dict = Depends(require_admin),
        page: int = 1,
        per_page: int = 50
    ):
        """Get moderation log for admin panel"""
        offset = (page - 1) * per_page
        
        logs = db.execute_query("""
            SELECT ml.*, u1.username as moderator_name, u2.username as target_name
            FROM moderation_log ml
            JOIN users u1 ON ml.moderator_id = u1.user_id
            LEFT JOIN users u2 ON ml.target_id = u2.user_id AND ml.target_type = 'user'
            ORDER BY ml.timestamp DESC
            LIMIT ? OFFSET ?
        """, (per_page, offset))
        
        return [dict(log) for log in logs]

    @router.get("/stats")
    async def get_admin_stats(current_user: dict = Depends(require_admin)):
        """Get forum statistics for admin dashboard"""
        
        # Get user stats
        user_stats = db.execute_query("""
            SELECT 
                COUNT(*) as total_users,
                COUNT(CASE WHEN is_admin THEN 1 END) as admin_count,
                COUNT(CASE WHEN is_banned THEN 1 END) as banned_count,
                COUNT(CASE WHEN last_activity > ? THEN 1 END) as active_users_24h
            FROM users
        """, (time.time() - 86400,), fetch_one=True)  # 24 hours ago
        
        # Get content stats
        content_stats = db.execute_query("""
            SELECT 
                (SELECT COUNT(*) FROM boards WHERE deleted = FALSE) as total_boards,
                (SELECT COUNT(*) FROM threads WHERE deleted = FALSE) as total_threads,
                (SELECT COUNT(*) FROM posts WHERE deleted = FALSE) as total_posts
        """, fetch_one=True)
        
        # Get recent activity
        recent_registrations = db.execute_query("""
            SELECT COUNT(*) as count
            FROM users 
            WHERE join_date > ?
        """, (time.time() - 86400,), fetch_one=True)  # Last 24 hours
        
        recent_posts = db.execute_query("""
            SELECT COUNT(*) as count
            FROM posts 
            WHERE timestamp > ? AND deleted = FALSE
        """, (time.time() - 86400,), fetch_one=True)  # Last 24 hours
        
        return {
            "users": dict(user_stats),
            "content": dict(content_stats),
            "recent_activity": {
                "new_registrations_24h": recent_registrations["count"],
                "new_posts_24h": recent_posts["count"]
            }
        }

    return router

# =============================================================================
# USER PROFILE ENDPOINTS
# =============================================================================

def create_user_router() -> APIRouter:
    router = APIRouter(prefix="/api/users", tags=["users"])

    @router.get("/{user_id}")
    async def get_user_profile(user_id: int):
        """Get public user profile"""
        user = db.execute_query("""
            SELECT user_id, username, join_date, last_activity, post_count, avatar_url
            FROM users 
            WHERE user_id = ? AND is_banned = FALSE
        """, (user_id,), fetch_one=True)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return dict(user)

    @router.get("/{user_id}/posts")
    async def get_user_posts(
        user_id: int, 
        page: int = 1, 
        per_page: int = 20
    ):
        """Get user's recent posts"""
        offset = (page - 1) * per_page
        
        posts = db.execute_query("""
            SELECT p.post_id, p.content, p.timestamp, p.edited,
                   t.thread_id, t.title as thread_title,
                   b.board_id, b.name as board_name
            FROM posts p
            JOIN threads t ON p.thread_id = t.thread_id
            JOIN boards b ON t.board_id = b.board_id
            WHERE p.user_id = ? AND p.deleted = FALSE 
                  AND t.deleted = FALSE AND b.deleted = FALSE
            ORDER BY p.timestamp DESC
            LIMIT ? OFFSET ?
        """, (user_id, per_page, offset))
        
        return [dict(post) for post in posts]

    return router

# =============================================================================
# SEARCH ENDPOINTS
# =============================================================================

def create_search_router() -> APIRouter:
    router = APIRouter(prefix="/api/search", tags=["search"])

    @router.get("")
    async def search_forum(
        q: str,
        type: str = "all",  # all, threads, posts, users
        page: int = 1,
        per_page: int = 20
    ):
        """Search forum content"""
        if len(q.strip()) < 3:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Search query must be at least 3 characters"
            )
        
        offset = (page - 1) * per_page
        search_term = f"%{q}%"
        results = {"threads": [], "posts": [], "users": []}
        
        if type in ["all", "threads"]:
            threads = db.execute_query("""
                SELECT t.thread_id, t.title, t.timestamp, u.username,
                       b.board_id, b.name as board_name
                FROM threads t
                JOIN users u ON t.user_id = u.user_id
                JOIN boards b ON t.board_id = b.board_id
                WHERE t.title LIKE ? AND t.deleted = FALSE 
                      AND b.deleted = FALSE
                ORDER BY t.timestamp DESC
                LIMIT ? OFFSET ?
            """, (search_term, per_page, offset))
            results["threads"] = [dict(thread) for thread in threads]
        
        if type in ["all", "posts"]:
            posts = db.execute_query("""
                SELECT p.post_id, p.content, p.timestamp, u.username,
                       t.thread_id, t.title as thread_title,
                       b.board_id, b.name as board_name
                FROM posts p
                JOIN users u ON p.user_id = u.user_id
                JOIN threads t ON p.thread_id = t.thread_id
                JOIN boards b ON t.board_id = b.board_id
                WHERE p.content LIKE ? AND p.deleted = FALSE 
                      AND t.deleted = FALSE AND b.deleted = FALSE
                ORDER BY p.timestamp DESC
                LIMIT ? OFFSET ?
            """, (search_term, per_page, offset))
            results["posts"] = [dict(post) for post in posts]
        
        if type in ["all", "users"]:
            users = db.execute_query("""
                SELECT user_id, username, join_date, post_count
                FROM users
                WHERE username LIKE ? AND is_banned = FALSE
                ORDER BY post_count DESC
                LIMIT ? OFFSET ?
            """, (search_term, per_page, offset))
            results["users"] = [dict(user) for user in users]
        
        return results

    return router

# =============================================================================
# UTILITY ENDPOINTS
# =============================================================================

def create_utility_router() -> APIRouter:
    router = APIRouter(prefix="/api", tags=["utilities"])

    @router.get("/stats")
    async def get_forum_stats():
        """Get public forum statistics"""
        stats = db.execute_query("""
            SELECT 
                (SELECT COUNT(*) FROM users WHERE is_banned = FALSE) as total_users,
                (SELECT COUNT(*) FROM boards WHERE deleted = FALSE) as total_boards,
                (SELECT COUNT(*) FROM threads WHERE deleted = FALSE) as total_threads,
                (SELECT COUNT(*) FROM posts WHERE deleted = FALSE) as total_posts,
                (SELECT username FROM users ORDER BY join_date DESC LIMIT 1) as newest_user
        """, fetch_one=True)
        
        return dict(stats)

    @router.get("/recent-activity")
    async def get_recent_activity(limit: int = 10):
        """Get recent forum activity"""
        recent_posts = db.execute_query("""
            SELECT p.post_id, p.timestamp, u.username,
                   t.thread_id, t.title as thread_title,
                   b.board_id, b.name as board_name
            FROM posts p
            JOIN users u ON p.user_id = u.user_id
            JOIN threads t ON p.thread_id = t.thread_id
            JOIN boards b ON t.board_id = b.board_id
            WHERE p.deleted = FALSE AND t.deleted = FALSE AND b.deleted = FALSE
            ORDER BY p.timestamp DESC
            LIMIT ?
        """, (limit,))
        
        return [dict(post) for post in recent_posts]

    @router.get("/system/info")
    async def get_system_info(current_user: dict = Depends(require_admin)):
        """Get system information (admin only)"""
        
        # Database size and performance info
        db_info = db.execute_query("""
            SELECT 
                (SELECT COUNT(*) FROM sqlite_master WHERE type='table') as table_count,
                (SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()) as db_size_bytes
        """, fetch_one=True)
        
        # Recent error logs (if any)
        recent_errors = db.execute_query("""
            SELECT event_type, COUNT(*) as count
            FROM security_audit_log 
            WHERE timestamp > ? AND risk_score > 5
            GROUP BY event_type
            ORDER BY count DESC
        """, (time.time() - 86400,))  # Last 24 hours
        
        return {
            "database": dict(db_info),
            "recent_security_events": [dict(error) for error in recent_errors],
            "api_version": "1.0.0",
            "python_version": "3.11+",
            "framework": "FastAPI"
        }

    @router.get("/health")
    async def health_check():
        """Health check endpoint"""
        return {"status": "healthy", "timestamp": time.time()}

    return router

# =============================================================================
# ROUTER FACTORY FUNCTIONS
# =============================================================================

def get_all_routers() -> List[APIRouter]:
    """Get all API routers"""
    return [
        create_auth_router(),
        create_board_router(),
        create_thread_router(),
        create_post_router(),
        create_admin_router(),
        create_user_router(),
        create_search_router(),
        create_utility_router(),
    ]

# =============================================================================
# INITIALIZATION FUNCTION
# =============================================================================

def initialize_endpoints(
    database: DatabaseManager,
    security_mgr: SecurityManager,
    rate_limiter_mgr: RateLimiter,
    audit_log_mgr: AuditLogManager,
    ip_mgr: IPReputationManager
):
    """Initialize global dependencies for endpoints"""
    global db, security_manager, rate_limiter, audit_logger, ip_manager
    
    db = database
    security_manager = security_mgr
    rate_limiter = rate_limiter_mgr
    audit_logger = audit_log_mgr
    ip_manager = ip_mgr INTO moderation_log (moderator_id, target_type, target_id, action, timestamp)
            VALUES (?, 'board', ?, 'create', ?)
        """, (current_user["user_id"], board_id, time.time()))
        
        # Get created board
        board = db.execute_query(
            "SELECT * FROM board_summary WHERE board_id = ?",
            (board_id,),
            fetch_one=True
        )
        
        return BoardResponse(**dict(board))

    return router

# =============================================================================
# THREAD ENDPOINTS
# =============================================================================

def create_thread_router() -> APIRouter:
    router = APIRouter(prefix="/api", tags=["threads"])

    @router.get("/threads/{thread_id}")
    async def get_thread_info(thread_id: int):
        """Get thread information"""
        thread = db.execute_query("""
            SELECT t.*, u.username, b.name as board_name
            FROM threads t
            JOIN users u ON t.user_id = u.user_id
            JOIN boards b ON t.board_id = b.board_id
            WHERE t.thread_id = ? AND t.deleted = FALSE
        """, (thread_id,), fetch_one=True)
        
        if not thread:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Thread not found"
            )
        
        return dict(thread)

    @router.get("/boards/{board_id}/threads", response_model=List[ThreadResponse])
    async def get_threads(board_id: int, page: int = 1, per_page: int = 20):
        """Get threads in a board with pagination"""
        offset = (page - 1) * per_page
        
        threads = db.execute_query("""
            SELECT * FROM active_threads 
            WHERE board_id = ?
            ORDER BY sticky DESC, last_post_at DESC
            LIMIT ? OFFSET ?
        """, (board_id, per_page, offset))
        
        # Map the view fields to the expected model fields
        mapped_threads = []
        for thread in threads:
            thread_dict = dict(thread)
            thread_dict['user_id'] = thread_dict['author_id']
            thread_dict['username'] = thread_dict['author_name'] 
            thread_dict['timestamp'] = thread_dict['created_at']
            mapped_threads.append(thread_dict)
        
        return [ThreadResponse(**thread) for thread in mapped_threads]

    @router.post("/boards/{board_id}/threads", response_model=ThreadResponse)
    async def create_thread(
        board_id: int,
        thread_data: ThreadCreate,
        request: Request,
        current_user: dict = Depends(get_current_user),
    ):
        """Create a new thread"""
        client_ip = await get_client_ip(request)
        
        # Rate limiting
        if not rate_limiter.check_rate_limit(str(current_user["user_id"]), "post", 10, 60):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many posts"
            )
        
        # Check board exists
        board = db.execute_query(
            "SELECT board_id FROM boards WHERE board_id = ? AND deleted = FALSE",
            (board_id,),
            fetch_one=True
        )
        
        if not board:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Board not found"
            )
        
        current_time = time.time()
        
        # Create thread
        thread_id = db.execute_insert("""
            INSERT INTO threads (board_id, user_id, title, timestamp, last_post_at, last_post_user_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (board_id, current_user["user_id"], thread_data.title, current_time, current_time, current_user["user_id"]))
        
        # Create initial post
        db.execute_insert("""
            INSERT INTO posts (thread_id, user_id, content, timestamp)
            VALUES (?, ?, ?, ?)
        """, (thread_id, current_user["user_id"], thread_data.content, current_time))
        
        # Get created thread
        thread = db.execute_query(
            "SELECT * FROM active_threads WHERE thread_id = ?",
            (thread_id,),
            fetch_one=True
        )
        thread_dict = dict(thread)
        thread_dict['user_id'] = thread_dict['author_id']
        thread_dict['username'] = thread_dict['author_name'] 
        thread_dict['timestamp'] = thread_dict['created_at']

        return ThreadResponse(**thread_dict)

    @router.delete("/threads/{thread_id}")
    async def delete_thread(
        thread_id: int,
        current_user: dict = Depends(get_current_user)
    ):
        """Delete a thread (admin or thread creator only)"""
        # Get thread
        thread = db.execute_query(
            "SELECT * FROM threads WHERE thread_id = ? AND deleted = FALSE",
            (thread_id,),
            fetch_one=True
        )
        
        if not thread:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Thread not found"
            )
        
        # Check permissions
        if not current_user.get("is_admin") and thread["user_id"] != current_user["user_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        # Delete thread
        db.execute_query(
            "UPDATE threads SET deleted = TRUE WHERE thread_id = ?",
            (thread_id,)
        )
        
        # Log moderation action
        db.execute_insert("""
            INSERT INTO moderation_log (moderator_id, target_type, target_id, action, timestamp)
            VALUES (?, 'thread', ?, 'delete', ?)
        """, (current_user["user_id"], thread_id, time.time()))
        
        return {"message": "Thread deleted successfully"}

    @router.patch("/threads/{thread_id}/lock")
    async def lock_thread(
        thread_id: int,
        update_data: ThreadUpdate,
        current_user: dict = Depends(require_admin)
    ):
        """Lock/unlock a thread (admin only)"""
        # Check thread exists
        thread = db.execute_query(
            "SELECT thread_id FROM threads WHERE thread_id = ? AND deleted = FALSE",
            (thread_id,),
            fetch_one=True
        )
        
        if not thread:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Thread not found"
            )
        
        # Update lock status
        if update_data.locked is not None:
            db.execute_query(
                "UPDATE threads SET locked = ? WHERE thread_id = ?",
                (update_data.locked, thread_id)
            )
            
            # Log moderation action
            action = "lock" if update_data.locked else "unlock"
            db.execute_insert("""
                INSERT INTO moderation_log (moderator_id, target_type, target_id, action, timestamp)
                VALUES (?, 'thread', ?, ?, ?)
            """, (current_user["user_id"], thread_id, action, time.time()))
        
        return {"message": f"Thread {'locked' if update_data.locked else 'unlocked'} successfully"}

    @router.patch("/threads/{thread_id}/sticky")
    async def sticky_thread(
        thread_id: int,
        update_data: ThreadUpdate,
        current_user: dict = Depends(require_admin)
    ):
        """Sticky/unsticky a thread (admin only)"""
        # Check thread exists
        thread = db.execute_query(
            "SELECT thread_id FROM threads WHERE thread_id = ? AND deleted = FALSE",
            (thread_id,),
            fetch_one=True
        )
        
        if not thread:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Thread not found"
            )
        
        # Update sticky status
        if update_data.sticky is not None:
            db.execute_query(
                "UPDATE threads SET sticky = ? WHERE thread_id = ?",
                (update_data.sticky, thread_id)
            )
            
            # Log moderation action
            action = "sticky" if update_data.sticky else "unsticky"
            db.execute_insert("""
                INSERT INTO moderation_log (moderator_id, target_type, target_id, action, timestamp)
                VALUES (?, 'thread', ?, ?, ?)
            """, (current_user["user_id"], thread_id, action, time.time()))
        
        return {"message": f"Thread {'stickied' if update_data.sticky else 'unstickied'} successfully"}

    return router

# =============================================================================
# POST ENDPOINTS
# =============================================================================

def create_post_router() -> APIRouter:
    router = APIRouter(prefix="/api", tags=["posts"])

    @router.get("/threads/{thread_id}/posts", response_model=List[PostResponse])
    async def get_posts(thread_id: int, page: int = 1, per_page: int = 20):
        """Get posts in a thread with pagination"""
        offset = (page - 1) * per_page
        
        # Increment view count
        db.execute_query(
            "UPDATE threads SET view_count = view_count + 1 WHERE thread_id = ?",
            (thread_id,)
        )
        
        posts = db.execute_query("""
            SELECT p.*, u.username 
            FROM posts p
            JOIN users u ON p.user_id = u.user_id
            WHERE p.thread_id = ? AND p.deleted = FALSE
            ORDER BY p.timestamp ASC
            LIMIT ? OFFSET ?
        """, (thread_id, per_page, offset))
        
        return [PostResponse(**dict(post)) for post in posts]

    @router.post("/threads/{thread_id}/posts", response_model=PostResponse)
    async def create_post(
        thread_id: int,
        post_data: PostCreate,
        request: Request,
        current_user: dict = Depends(get_current_user)
    ):
        """Reply to a thread"""
        client_ip = await get_client_ip(request)
        
        # Rate limiting
        if not rate_limiter.check_rate_limit(str(current_user["user_id"]), "post", 20, 60):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many posts"
            )
        
        # Check thread exists and isn't locked
        thread = db.execute_query("""
            SELECT t.thread_id, t.locked, b.deleted as board_deleted
            FROM threads t
            JOIN boards b ON t.board_id = b.board_id
            WHERE t.thread_id = ? AND t.deleted = FALSE
        """, (thread_id,), fetch_one=True)
        
        if not thread:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Thread not found"
            )
        
        if thread["locked"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Thread is locked"
            )
        
        if thread["board_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Board not found"
            )
        
        current_time = time.time()
        
        # Create post
        post_id = db.execute_insert("""
            INSERT INTO posts (thread_id, user_id, content, timestamp)
            VALUES (?, ?, ?, ?)
        """, (thread_id, current_user["user_id"], post_data.content, current_time))
        
        # Get created post
        post = db.execute_query("""
            SELECT p.*, u.username 
            FROM posts p
            JOIN users u ON p.user_id = u.user_id
            WHERE p.post_id = ?
        """, (post_id,), fetch_one=True)
        
        return PostResponse(**dict(post))

    @router.patch("/posts/{post_id}", response_model=PostResponse)
    async def edit_post(
        post_id: int,
        edit_data: PostEdit,
        current_user: dict = Depends(get_current_user)
    ):
        """Edit a post"""
        # Get post
        post = db.execute_query("""
            SELECT p.*, u.username 
            FROM posts p
            JOIN users u ON p.user_id = u.user_id
            WHERE p.post_id = ? AND p.deleted = FALSE
        """, (post_id,), fetch_one=True)
        
        if not post:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Post not found"
            )
        
        # Check permissions
        if not current_user.get("is_admin") and post["user_id"] != current_user["user_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        # Save edit to history
        db.execute_insert("""
            INSERT INTO post_edits (post_id, editor_id, old_content, new_content, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (post_id, current_user["user_id"], post["content"], edit_data.content, time.time()))
        
        # Update post
        db.execute_query("""
            UPDATE posts 
            SET content = ?, edited = TRUE, edit_count = edit_count + 1, 
                edited_at = ?, edited_by = ?
            WHERE post_id = ?
        """, (edit_data.content, time.time(), current_user["user_id"], post_id))
        
        # Log moderation action if done by admin on another user's post
        if current_user.get("is_admin") and post["user_id"] != current_user["user_id"]:
            db.execute_insert("""
                INSERT INTO moderation_log (moderator_id, target_type, target_id, action, timestamp)
                VALUES (?, 'post', ?, 'edit', ?)
            """, (current_user["user_id"], post_id, time.time()))
        
        # Get updated post
        updated_post = db.execute_query("""
            SELECT p.*, u.username 
            FROM posts p
            JOIN users u ON p.user_id = u.user_id
            WHERE p.post_id = ?
        """, (post_id,), fetch_one=True)
        
        return PostResponse(**dict(updated_post))

    @router.delete("/posts/{post_id}")
    async def delete_post(
        post_id: int,
        current_user: dict = Depends(get_current_user)
    ):
        """Delete a post"""
        # Get post
        post = db.execute_query(
            "SELECT * FROM posts WHERE post_id = ? AND deleted = FALSE",
            (post_id,),
            fetch_one=True
        )
        
        if not post:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Post not found"
            )
        
        # Check permissions
        if not current_user.get("is_admin") and post["user_id"] != current_user["user_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        # Delete post
        db.execute_query(
            "UPDATE posts SET deleted = TRUE WHERE post_id = ?",
            (post_id,)
        )
        
        # Log moderation action
        db.execute_insert("""
            INSERT INTO moderation_log (moderator_id, target_type, target_id, action, timestamp)
            VALUES (?, 'post', ?, 'delete', ?)
        """, (current_user["user_id"], post_id, time.time()))
        
        return {"message": "Post deleted successfully"}

    @router.patch("/posts/{post_id}/restore")
    async def restore_post(
        post_id: int,
        current_user: dict = Depends(require_admin)
    ):
        """Restore a deleted post (admin only)"""
        # Get post
        post = db.execute_query(
            "SELECT post_id FROM posts WHERE post_id = ? AND deleted = TRUE",
            (post_id,),
            fetch_one=True
        )
        
        if not post:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Deleted post not found"
            )
        
        # Restore post
        db.execute_query(
            "UPDATE posts SET deleted = FALSE WHERE post_id = ?",
            (post_id,)
        )
        
        # Log moderation action
        db.execute_insert("""
            INSERT INTO moderation_log (moderator_id, target_type, target_id, action, timestamp)
            VALUES (?, 'post', ?, 'restore', ?)
        """, (current_user["user_id"], post_id, time.time()))
        
        return {"message": "Post restored successfully"}

    return router

# =============================================================================
# ADMIN ENDPOINTS
# =============================================================================

def create_admin_router() -> APIRouter:
    router = APIRouter(prefix="/api/admin", tags=["admin"])

    @router.post("/users/{user_id}/ban")
    async def ban_user(
        user_id: int,
        current_user: dict = Depends(require_admin)
    ):
        """Ban a user (admin only)"""
        # Check if user exists
        user = db.execute_query(
            "SELECT user_id FROM users WHERE user_id = ?",
            (user_id,),
            fetch_one=True
        )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Don't allow banning yourself
        if user_id == current_user["user_id"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot ban yourself"
            )
        
        # Ban user
        db.execute_query(
            "UPDATE users SET is_banned = TRUE WHERE user_id = ?",
            (user_id,)
        )
        
        # Log moderation action
        db.execute_insert("""
            INSERT INTO moderation_log (moderator_id, target_type, target_id, action, timestamp)
            VALUES (?, 'user', ?, 'ban', ?)
        """, (current_user["user_id"], user_id, time.time()))
        
        return {"message": "User banned successfully"}

    @router.post("/users/{user_id}/unban")
    async def unban_user(
        user_id: int,
        current_user: dict = Depends(require_admin)
    ):
        """Unban a user (admin only)"""
        # Check if user exists
        user = db.execute_query(
            "SELECT user_id FROM users WHERE user_id = ?",
            (user_id,),
            fetch_one=True
        )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Unban user
        db.execute_query(
            "UPDATE users SET is_banned = FALSE WHERE user_id = ?",
            (user_id,)
        )
        
        # Log moderation action
        db.execute_insert("""
            INSERT INTO moderation_log (moderator_id, target_type, target_id, action, timestamp)
            VALUES (?, 'user', ?, 'unban', ?)
        """, (current_user["user_id"], user_id, time.time()))
        
        return {"message": "User unbanned successfully"}

    @router.post("/users/{user_id}/promote")
    async def promote_user_to_admin(
        user_id: int,
        current_user: dict = Depends(require_admin)
    ):
        """Promote a user to admin (admin only)"""
        # Check if user exists
        user = db.execute_query(
            "SELECT user_id, is_admin FROM users WHERE user_id = ?",
            (user_id,),
            fetch_one=True
        )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if user["is_admin"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User is already an admin"
            )
        
        # Promote user
        db.execute_query(
            "UPDATE users SET is_admin = TRUE WHERE user_id = ?",
            (user_id,)
        )
        
        # Log moderation action
        db.execute_insert("""
            INSERT INTO moderation_log (moderator_id, target_type, target_id, action, timestamp)
            VALUES (?, 'user', ?, 'promote_admin', ?)
        """, (current_user["user_id"], user_id, time.time()))
        
        return {"message": "User promoted to admin successfully"}

    @router.post("/users/{user_id}/demote")
    async def demote_admin_user(
        user_id: int,
        current_user: dict = Depends(require_admin)
    ):
        """Demote an admin user (admin only)"""
        # Check if user exists
        user = db.execute_query(
            "SELECT user_id, is_admin FROM users WHERE user_id = ?",
            (user_id,),
            fetch_one=True
        )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if not user["is_admin"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User is not an admin"
            )
        
        # Don't allow demoting yourself
        if user_id == current_user["user_id"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot demote yourself"
            )
        
        # Demote user
        db.execute_query(
            "UPDATE users SET is_admin = FALSE WHERE user_id = ?",
            (user_id,)
        )
        
        # Log moderation action
        db.execute_insert("""
            INSERT#!/usr/bin/env python3
# Forum API Endpoints
# All API route handlers for the forum system

from fastapi import HTTPException, Depends, status, Request, APIRouter
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, validator
from typing import Optional, List, Dict, Any
import time
from database import DatabaseManager
from managers import SecurityManager, RateLimiter, AuditLogManager, IPReputationManager

# =============================================================================
# API MODELS (Request/Response Schemas)
# =============================================================================

class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    
    @validator('username')
    def validate_username(cls, v):
        if len(v) < 3 or len(v) > 50:
            raise ValueError('Username must be 3-50 characters')
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username can only contain letters, numbers, hyphens, and underscores')
        return v
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    user_id: int
    username: str
    email: str
    is_admin: bool
    is_banned: bool
    email_verified: bool
    join_date: float
    last_activity: float
    post_count: int
    avatar_url: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse

class BoardCreate(BaseModel):
    name: str
    description: str
    
    @validator('name')
    def validate_name(cls, v):
        if len(v) < 2 or len(v) > 100:
            raise ValueError('Board name must be 2-100 characters')
        return v

class BoardResponse(BaseModel):
    board_id: int
    name: str
    description: str
    creator_id: int
    creator_name: str
    thread_count: int
    post_count: int
    last_post_at: Optional[float]
    last_post_username: Optional[str]

class ThreadCreate(BaseModel):
    title: str
    content: str
    
    @validator('title')
    def validate_title(cls, v):
        if len(v) < 3 or len(v) > 255:
            raise ValueError('Thread title must be 3-255 characters')
        return v
    
    @validator('content')
    def validate_content(cls, v):
        if len(v) < 1 or len(v) > 50000:
            raise ValueError('Content must be 1-50000 characters')
        return v

class PostCreate(BaseModel):
    content: str
    
    @validator('content')
    def validate_content(cls, v):
        if len(v) < 1 or len(v) > 50000:
            raise ValueError('Content must be 1-50000 characters')
        return v

class PostEdit(BaseModel):
    content: str
    
    @validator('content')
    def validate_content(cls, v):
        if len(v) < 1 or len(v) > 50000:
            raise ValueError('Content must be 1-50000 characters')
        return v

class ThreadUpdate(BaseModel):
    locked: Optional[bool] = None
    sticky: Optional[bool] = None

class ThreadResponse(BaseModel):
    thread_id: int
    board_id: int
    title: str
    user_id: int
    username: str
    reply_count: int
    view_count: int
    sticky: bool
    locked: bool
    timestamp: float
    last_post_at: Optional[float]
    last_post_username: Optional[str]

class PostResponse(BaseModel):
    post_id: int
    thread_id: int
    user_id: int
    username: str
    content: str
    edited: bool
    edit_count: int
    timestamp: float

class ErrorResponse(BaseModel):
    error: str
    message: str
    details: Optional[Dict[str, Any]] = None

# =============================================================================
# DEPENDENCY INJECTION
# =============================================================================

# Global instances - these will be initialized in app.py
db: DatabaseManager = None
security_manager: SecurityManager = None
rate_limiter: RateLimiter = None
audit_logger: AuditLogManager = None
ip_manager: IPReputationManager = None

# Security
security = HTTPBearer()

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

async def get_client_ip(request: Request) -> str:
    """Extract client IP for rate limiting"""
    if request.client:
        return request.client.host
    return "[unknown]"

async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """Validate JWT token and return current user"""
    try:
        payload = security_manager.verify_token(credentials.credentials)
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_