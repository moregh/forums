#!/usr/bin/env python3
from typing import List
from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from database import DatabaseManager
from models import TokenResponse, UserLogin, UserRegister, UserResponse, BoardResponse
from models import BoardCreate, ThreadCreate, ThreadResponse, PostCreate, PostResponse, ErrorResponse
from security import SecurityManager
from functools import wraps
from datetime import datetime, timezone


def timestamp() -> float:
    return datetime.now(timezone.utc).timestamp()


def audit_action(action_type: str, target_type: str = "user"):
    """Decorator to automatically audit administrative actions"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract common parameters that should be in all admin endpoints
            user_id = kwargs.get('user_id')
            request = kwargs.get('request') 
            current_user = kwargs.get('current_user')
            
            if not all([user_id, request, current_user]):
                # If we can't audit, just run the function
                return await func(*args, **kwargs)
            
            client_ip = await get_client_ip(request) # pyright: ignore[reportArgumentType]
            user_agent = request.headers.get("user-agent", "") # pyright: ignore[reportOptionalMemberAccess]
            
            try:
                # Execute the original function
                result = await func(*args, **kwargs)
                
                # Log successful action
                db.log_security_audit(
                    user_id=user_id, # pyright: ignore[reportArgumentType]
                    event_type=action_type,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    event_data=f'{{"moderator_id": {current_user["user_id"]}, "target_type": "{target_type}", "action": "{action_type}"}}' # pyright: ignore[reportOptionalSubscript]
                )
                
                return result
                
            except Exception as e:
                # Log failed action
                db.log_security_audit(
                    user_id=user_id, # type: ignore
                    event_type=f"{action_type}_failed",
                    ip_address=client_ip,
                    user_agent=user_agent,
                    event_data=f'{{"moderator_id": {current_user["user_id"]}, "error": "{str(e)}", "action": "{action_type}"}}' # pyright: ignore[reportOptionalSubscript]
                )
                raise
                
        return wrapper
    return decorator

# =============================================================================
# API ENDPOINTS
# =============================================================================

# Initialize FastAPI app
app = FastAPI(
    title="Forum API",
    description="RESTful API for forum system",
    version="1.0.0"
)

# Security and middleware setup
security = HTTPBearer()
security_manager = SecurityManager(secret_key="your-secret-key-change-this")
db = DatabaseManager("forum.db")

# CORS middleware for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8080", "https://yourforum.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "yourapi.com"]
)

# =============================================================================
# AUTHENTICATION DEPENDENCIES
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
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        # Get user from database
        user = db.get_user_by_id(int(user_id))
        
        if not user or user.get("is_banned"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or banned"
            )
        
        return user
    
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

@app.post("/api/auth/register", response_model=TokenResponse)
async def register(user_data: UserRegister, request: Request):
    """Register a new user"""
    client_ip = await get_client_ip(request)
    
    # Rate limiting
    if not db.check_rate_limit(client_ip, "register", 5, 60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts"
        )
    
    # Check if user exists
    if db.check_user_exists(user_data.username, user_data.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already exists"
        )
    
    # Create user
    password_hash, password_salt = security_manager.hash_password(user_data.password)
    user_id = db.create_user(user_data.username, user_data.email, password_hash, password_salt)
    
    # Create access token
    access_token = security_manager.create_access_token({"sub": str(user_id)})
    
    # Get user data for response
    user = db.get_user_by_id(user_id)
    
    return TokenResponse(
        access_token=access_token,
        expires_in=security_manager.access_token_expire_minutes * 60,
        user=UserResponse(**user) # pyright: ignore[reportCallIssue]
    )

@app.post("/api/auth/login", response_model=TokenResponse)
async def login(login_data: UserLogin, request: Request):
    """Authenticate user and return token"""
    client_ip = await get_client_ip(request)
    
    # Rate limiting
    if not db.check_rate_limit(client_ip, "login", 10, 60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts"
        )
    
    # Get user
    user = db.get_user_by_username(login_data.username)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    if not security_manager.verify_password(login_data.password, user["password_hash"]):
        # Log failed attempt
        db.increment_failed_login(user["user_id"], client_ip)
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Check if account is locked
    if user["locked_until"] and user["locked_until"] > timestamp():
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account temporarily locked"
        )
    
    # Check if banned
    if user["is_banned"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Banned"
        )
    
    # Reset failed attempts and update login info
    db.update_user_login(user["user_id"], client_ip)
    
    # Create access token
    access_token = security_manager.create_access_token({"sub": str(user["user_id"])})
    
    return TokenResponse(
        access_token=access_token,
        expires_in=security_manager.access_token_expire_minutes * 60,
        user=UserResponse(**user)
    )

@app.post("/api/auth/refresh", response_model=TokenResponse)
async def refresh_token(current_user: dict = Depends(get_current_user)):
    """Refresh access token"""
    access_token = security_manager.create_access_token({"sub": str(current_user["user_id"])})
    
    return TokenResponse(
        access_token=access_token,
        expires_in=security_manager.access_token_expire_minutes * 60,
        user=UserResponse(**current_user)
    )

# =============================================================================
# POST ENDPOINTS
# =============================================================================

@app.get("/api/posts/{post_id}", response_model=PostResponse)
async def get_post(post_id: int):
    """Get a specific post by ID"""
    post = db.get_post_by_id(post_id)
    
    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post not found"
        )
    
    return PostResponse(**post)

@app.patch("/api/posts/{post_id}", response_model=PostResponse)
async def edit_post(
    post_id: int,
    post_data: PostCreate,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Edit a specific post"""
    client_ip = await get_client_ip(request)
    
    # Rate limiting
    if not db.check_rate_limit(str(current_user["user_id"]), "edit", 30, 60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many edit attempts"
        )
    
    # Get the post with context
    post = db.get_post_with_context(post_id)
    
    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post not found"
        )
    
    # Check permissions - user can edit their own posts, admins can edit any
    if post["user_id"] != current_user["user_id"] and not current_user.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to edit this post"
        )
    
    # Check if thread is locked (only admins can edit in locked threads)
    if post["locked"] and not current_user.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot edit posts in locked thread"
        )
    
    # Check if thread/board is deleted
    if post["thread_deleted"] or post["board_deleted"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Thread or board not found"
        )
    
    # If admin/moderator editing someone else's post, log it
    if current_user["user_id"] != post["user_id"] and current_user.get("is_admin"):
        db.log_security_audit(
            user_id=post["user_id"],
            event_type="post_edited_by_admin",
            ip_address=client_ip,
            user_agent=request.headers.get("user-agent", ""),
            event_data=f'{{"moderator_id": {current_user["user_id"]}, "post_id": {post_id}}}'
        )
    
    # Update the post
    db.update_post(post_id, post_data.content, current_user["user_id"])
    
    # Get updated post
    updated_post = db.get_post_by_id(post_id)
    
    return PostResponse(**updated_post) # pyright: ignore[reportCallIssue]

@app.get("/api/threads/{thread_id}", response_model=ThreadResponse)
async def get_thread(thread_id: int):
    """Get a specific thread by ID"""
    thread = db.get_thread_by_id(thread_id)
    
    if not thread:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Thread not found"
        )
    
    return ThreadResponse(**thread)

@app.delete("/api/posts/{post_id}")
@audit_action("post_deleted", "post")
async def delete_post(
    post_id: int,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Delete a specific post"""
    # Get the post with context
    post = db.get_post_with_context(post_id)
    
    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post not found"
        )
    
    # Check permissions - user can delete their own posts, admins can delete any
    if post["user_id"] != current_user["user_id"] and not current_user.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this post"
        )
    
    # Check if thread is locked (only admins can delete in locked threads)
    if post["locked"] and not current_user.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot delete posts in locked thread"
        )
    
    # Mark post as deleted
    db.delete_post(post_id)
    
    # Log moderation action if done by admin
    if current_user.get("is_admin"):
        db.log_moderation_action(
            moderator_id=current_user["user_id"],
            target_type="post",
            target_id=post_id,
            action="delete"
        )
    
    return {"message": "Post deleted successfully"}

@app.patch("/api/posts/{post_id}/restore")
@audit_action("post_restored", "post")
async def restore_post(
    post_id: int,
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """Restore a deleted post (admin only)"""
    if not db.restore_post(post_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Deleted post not found or cannot be restored"
        )
    
    # Log moderation action
    db.log_moderation_action(
        moderator_id=current_user["user_id"],
        target_type="post",
        target_id=post_id,
        action="restore"
    )
    
    return {"message": "Post restored successfully"}

@app.get("/api/posts/{post_id}/history")
async def get_post_edit_history(
    post_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Get edit history for a post"""
    # Get the post to check permissions
    post = db.get_post_with_context(post_id)
    
    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post not found"
        )
    
    # Only post author or admins can view edit history
    if (post["user_id"] != current_user["user_id"] and 
        not current_user.get("is_admin")):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view edit history"
        )
    
    # Get edit history
    edits = db.get_post_edit_history(post_id)
    
    return edits

# =============================================================================
# USER MANAGEMENT ENDPOINTS
# =============================================================================

@app.get("/api/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: int):
    """Get user profile by ID"""
    user = db.get_user_by_id(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserResponse(**user)

@app.put("/api/users/{user_id}", response_model=UserResponse)
async def update_user_profile(
    user_id: int,
    update_data: dict,
    current_user: dict = Depends(get_current_user)
):
    """Update user profile (users can only update their own profile, admins can update any)"""
    # Check permissions
    if user_id != current_user["user_id"] and not current_user.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this profile"
        )
    
    # Check if user exists
    user = db.get_user_by_id(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Build allowed fields
    allowed_fields = ["avatar_url"]  # Only allow safe fields for regular users
    if current_user.get("is_admin"):
        allowed_fields.extend(["email", "is_banned"])  # Admins can update more
    
    # Filter update data to only allowed fields
    filtered_updates = {k: v for k, v in update_data.items() if k in allowed_fields}
    
    if not filtered_updates:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid fields to update"
        )
    
    # Update user profile
    db.update_user_profile(user_id, filtered_updates)
    
    # Return updated user
    updated_user = db.get_user_by_id(user_id)
    
    return UserResponse(**updated_user) # pyright: ignore[reportCallIssue]

# =============================================================================
# USER PREFERENCES ENDPOINTS
# =============================================================================

@app.get("/api/users/{user_id}/preferences")
async def get_user_preferences(
    user_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Get user preferences"""
    # Users can only view their own preferences
    if user_id != current_user["user_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view these preferences"
        )
    
    preferences = db.get_user_preferences(user_id)
    
    if not preferences:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User preferences not found"
        )
    
    return preferences

@app.put("/api/users/{user_id}/preferences")
async def update_user_preferences(
    user_id: int,
    preferences_data: dict,
    current_user: dict = Depends(get_current_user)
):
    """Update user preferences"""
    # Users can only update their own preferences
    if user_id != current_user["user_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update these preferences"
        )
    
    allowed_fields = [
        "email_notifications", "theme", "timezone", "posts_per_page",
        "signature", "show_avatars", "show_signatures"
    ]
    
    # Filter to allowed fields
    filtered_prefs = {k: v for k, v in preferences_data.items() if k in allowed_fields}
    
    # Update preferences
    db.update_user_preferences(user_id, filtered_prefs)
    
    # Return updated preferences
    updated_preferences = db.get_user_preferences(user_id)
    
    return updated_preferences

# =============================================================================
# ADMIN USER MANAGEMENT ENDPOINTS
# =============================================================================

@app.get("/api/admin/users")
async def get_all_users(
    page: int = 1,
    per_page: int = 20,
    current_user: dict = Depends(require_admin)
):
    """Get all users (admin only)"""
    users = db.get_all_users(page, per_page)
    return users

@app.post("/api/admin/users/{user_id}/ban")
@audit_action("user_banned")
async def ban_user(
    user_id: int,
    ban_data: dict,
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """Ban a user (admin only)"""
    # Check if user exists
    user = db.get_user_by_id(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if user["is_admin"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot ban admin users"
        )
    
    # Ban the user
    db.ban_user(user_id)
    
    # Log moderation action
    reason = ban_data.get("reason", "No reason provided")
    db.log_moderation_action(
        moderator_id=current_user["user_id"],
        target_type="user",
        target_id=user_id,
        action="ban",
        reason=reason
    )

    return {"message": "User banned successfully"}

@app.post("/api/admin/users/{user_id}/unban")
@audit_action("user_unbanned") 
async def unban_user(
    user_id: int,
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """Unban a user (admin only)"""
    # Check if user exists
    user = db.get_user_by_id(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Unban the user
    db.unban_user(user_id)
    
    # Log moderation action
    db.log_moderation_action(
        moderator_id=current_user["user_id"],
        target_type="user",
        target_id=user_id,
        action="unban"
    )
    
    return {"message": "User unbanned successfully"}

@app.post("/api/admin/users/{user_id}/promote")
@audit_action("admin_granted")
async def make_user_admin(
    user_id: int,
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """Promote user to admin (admin only)"""
    # Check if user exists
    user = db.get_user_by_id(user_id)
    
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
    
    # Promote to admin
    db.promote_user_to_admin(user_id)
    
    # Log moderation action
    db.log_moderation_action(
        moderator_id=current_user["user_id"],
        target_type="user",
        target_id=user_id,
        action="promote_admin"
    )
    
    return {"message": "User promoted to admin successfully"}

@app.post("/api/admin/users/{user_id}/demote")
@audit_action("admin_revoked")
async def remove_user_admin(
    user_id: int,
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """Remove admin privileges from user (admin only)"""
    # Check if user exists
    user = db.get_user_by_id(user_id)
    
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
    
    # Don't allow self-demotion
    if user_id == current_user["user_id"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot demote yourself"
        )
    
    # Remove admin privileges
    db.demote_user_from_admin(user_id)
    
    # Log moderation action
    db.log_moderation_action(
        moderator_id=current_user["user_id"],
        target_type="user",
        target_id=user_id,
        action="demote_admin"
    )
    
    return {"message": "Admin privileges removed successfully"}

# =============================================================================
# THREAD MANAGEMENT ENDPOINTS
# =============================================================================

@app.patch("/api/threads/{thread_id}/lock")
@audit_action("thread_locked", "thread")
async def toggle_thread_lock(
    thread_id: int,
    lock_data: dict,
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """Lock or unlock a thread (admin only)"""
    # Check if thread exists
    thread = db.thread_exists_and_accessible(thread_id)
    
    if not thread:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Thread not found"
        )
    
    locked = lock_data.get("locked", True)
    
    # Update thread lock status
    db.update_thread_lock_status(thread_id, locked)
    
    # Log moderation action
    action = "lock" if locked else "unlock"
    db.log_moderation_action(
        moderator_id=current_user["user_id"],
        target_type="thread",
        target_id=thread_id,
        action=action
    )
    
    return {"message": f"Thread {'locked' if locked else 'unlocked'} successfully"}

@app.patch("/api/threads/{thread_id}/sticky")
@audit_action("thread_stickied", "thread")
async def toggle_thread_sticky(
    thread_id: int,
    sticky_data: dict,
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """Make thread sticky or unsticky (admin only)"""
    # Check if thread exists
    thread = db.thread_exists_and_accessible(thread_id)
    
    if not thread:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Thread not found"
        )
    
    sticky = sticky_data.get("sticky", True)
    
    # Update thread sticky status
    db.update_thread_sticky_status(thread_id, sticky)
    
    # Log moderation action
    action = "sticky" if sticky else "unsticky"
    db.log_moderation_action(
        moderator_id=current_user["user_id"],
        target_type="thread",
        target_id=thread_id,
        action=action
    )
    
    return {"message": f"Thread {'stickied' if sticky else 'unstickied'} successfully"}

@app.delete("/api/threads/{thread_id}")
@audit_action("thread_deleted", "thread")
async def delete_thread(
    thread_id: int,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Delete a thread (admin or thread author only)"""
    # Check if thread exists
    thread = db.thread_exists_and_accessible(thread_id)
    
    if not thread:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Thread not found"
        )
    
    # Check permissions - thread author or admin can delete
    if thread["user_id"] != current_user["user_id"] and not current_user.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this thread"
        )
    
    # Mark thread as deleted
    db.delete_thread(thread_id)
    
    # Log moderation action
    db.log_moderation_action(
        moderator_id=current_user["user_id"],
        target_type="thread",
        target_id=thread_id,
        action="delete"
    )
    
    return {"message": "Thread deleted successfully"}

# =============================================================================
# SEARCH ENDPOINTS
# =============================================================================

@app.get("/api/search")
async def search_forum(
    q: str,
    type: str = "all",  # "threads", "posts", "users", or "all"
    page: int = 1,
    per_page: int = 20
):
    """Search across forum content"""
    if len(q.strip()) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Search query must be at least 3 characters"
        )
    
    results = db.search_forum_content(q, type, page, per_page)
    return results

# =============================================================================
# MODERATION LOG ENDPOINTS
# =============================================================================

@app.get("/api/admin/moderation-log")
async def get_moderation_log(
    page: int = 1,
    per_page: int = 50,
    current_user: dict = Depends(require_admin)
):
    """Get moderation log (admin only)"""
    logs = db.get_moderation_log(page, per_page)
    return logs

# =============================================================================
# STATISTICS ENDPOINTS
# =============================================================================

@app.get("/api/stats")
async def get_forum_statistics():
    """Get general forum statistics"""
    stats = db.get_forum_statistics()
    return stats

# =============================================================================
# BOARD ENDPOINTS
# =============================================================================

@app.get("/api/boards", response_model=List[BoardResponse])
async def get_boards():
    """Get all visible boards"""
    boards = db.get_all_boards()
    return [BoardResponse(**board) for board in boards]

@app.post("/api/boards", response_model=BoardResponse)
@audit_action("board_created", "board")
async def create_board(
    board_data: BoardCreate,
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """Create a new board (admin only)"""
    board_id = db.create_board(board_data.name, board_data.description, current_user["user_id"])
    
    # Log moderation action
    db.log_moderation_action(
        moderator_id=current_user["user_id"],
        target_type="board",
        target_id=board_id,
        action="create"
    )
    
    # Get created board
    board = db.get_board_by_id(board_id)
    
    return BoardResponse(**board) # pyright: ignore[reportCallIssue]

# =============================================================================
# THREAD ENDPOINTS
# =============================================================================

@app.get("/api/boards/{board_id}/threads", response_model=List[ThreadResponse])
async def get_threads(board_id: int, page: int = 1, per_page: int = 20):
    """Get threads in a board with pagination"""
    threads = db.get_threads_by_board(board_id, page, per_page)
    return [ThreadResponse(**thread) for thread in threads]

@app.post("/api/boards/{board_id}/threads", response_model=ThreadResponse)
async def create_thread(
    board_id: int,
    thread_data: ThreadCreate,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """Create a new thread"""
    client_ip = await get_client_ip(request)
    
    # Rate limiting
    if not db.check_rate_limit(str(current_user["user_id"]), "post", 10, 60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many posts"
        )
    
    # Check board exists
    if not db.board_exists(board_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Board not found"
        )
    
    # Create thread
    thread_id = db.create_thread(board_id, current_user["user_id"], thread_data.title, thread_data.content)
    
    # Get created thread
    thread = db.get_thread_by_id(thread_id)

    return ThreadResponse(**thread) # type: ignore

# =============================================================================
# POST ENDPOINTS
# =============================================================================

@app.get("/api/threads/{thread_id}/posts", response_model=List[PostResponse])
async def get_posts(thread_id: int, page: int = 1, per_page: int = 20):
    """Get posts in a thread with pagination"""
    # Increment view count
    db.increment_thread_view_count(thread_id)
    
    posts = db.get_posts_by_thread(thread_id, page, per_page)
    
    return [PostResponse(**post) for post in posts]

@app.post("/api/threads/{thread_id}/posts", response_model=PostResponse)
async def create_post(
    thread_id: int,
    post_data: PostCreate,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Reply to a thread"""
    client_ip = await get_client_ip(request)
    
    # Rate limiting
    if not db.check_rate_limit(str(current_user["user_id"]), "post", 20, 60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many posts"
        )
    
    # Check thread exists and isn't locked
    thread = db.thread_exists_and_accessible(thread_id)
    
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
    
    # Create post
    post_id = db.create_post(thread_id, current_user["user_id"], post_data.content)
    
    # Get created post
    post = db.get_post_by_id(post_id)
    
    return PostResponse(**post) # type: ignore

# =============================================================================
# ERROR HANDLING
# =============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=exc.__class__.__name__,
            message=exc.detail
        ).dict()
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="InternalServerError",
            message="An unexpected error occurred"
        ).dict()
    )

# =============================================================================
# HEALTH CHECK
# =============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": timestamp()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)