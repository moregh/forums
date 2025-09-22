#!/usr/bin/env python3
# type: ignore  -- have to add this because pylance is fucking abysmal
from typing import List
from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from database import DatabaseManager
from exceptions import Exceptions
from models import TokenResponse, UserLogin, UserRegister, UserResponse, BoardResponse
from models import BoardCreate, ThreadCreate, ThreadResponse, PostCreate, PostResponse, ErrorResponse, UserInfo, PublicUserInfo
from security import SecurityManager
from functools import wraps
from utils import timestamp
from config import *



def audit_action(action_type: str, target_type: str = "user"):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            user_id = kwargs.get('user_id')
            request = kwargs.get('request') 
            current_user = kwargs.get('current_user')
            
            if not request:
                for arg in args:
                    if hasattr(arg, 'client'):
                        request = arg
                        break

            if not all([user_id, request, current_user]):
                return await func(*args, **kwargs)
            
            client_ip = await get_client_ip(request)
            user_agent = request.headers.get("user-agent", "")
            
            try:
                result = await func(*args, **kwargs)
                
                db.log_security_audit(
                    user_id=user_id, # type: ignore
                    event_type=action_type,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    event_data=f'{{"moderator_id": {current_user["user_id"]}, "target_type": "{target_type}", "action": "{action_type}"}}'
                )
                
                return result
                
            except Exception as e:
                db.log_security_audit(
                    user_id=user_id, # type: ignore
                    event_type=f"{action_type}_failed",
                    ip_address=client_ip,
                    user_agent=user_agent,
                    event_data=f'{{"moderator_id": {current_user["user_id"]}, "error": "{str(e)}", "action": "{action_type}"}}'
                )
                raise
                
        return wrapper
    return decorator



app = FastAPI(title="Forum API", description="RESTful API for forum system", version="1.0.0")

security = HTTPBearer()
security_manager = SecurityManager(secret_key=SECRET_KEY)
db = DatabaseManager(DB_PATH)

app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

async def get_client_ip(request: Request) -> str:
    return request.client.host if request.client else "[unknown]"

async def get_current_user(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    try:
        payload = security_manager.verify_token(credentials.credentials)
        user_id = payload.get("sub")
        if not user_id:
            raise Exceptions.UNAUTHORIZED
        
        user = db.get_user_by_id(int(user_id))
        if not user or user.get("is_banned"):
            raise Exceptions.UNAUTHORIZED
        
        return user
    except:
        raise Exceptions.UNAUTHORIZED

async def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if not current_user.get("is_admin"):
        raise Exceptions.ADMIN_REQUIRED
    return current_user

def check_rate_limit(identifier: str, action: str):
    limit, window = RATE_LIMITS[action]
    if not db.check_rate_limit(identifier, action, limit, window):
        raise Exceptions.TOO_MANY_REQUESTS

def validate_user_exists(user_id: int) -> dict:
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return user

def validate_user_permissions(target_user_id: int, current_user: dict, allow_self: bool = True):
    if allow_self and target_user_id == current_user["user_id"]:
        return
    if not current_user.get("is_admin"):
        raise Exceptions.FORBIDDEN

def validate_admin_action(target_user: dict, current_user: dict, action: str):
    if target_user["is_admin"] and action in ["ban", "demote"]:
        message = "Cannot ban admin users" if action == "ban" else "Cannot demote yourself"
        if action == "demote" and target_user["user_id"] == current_user["user_id"]:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, message)
        if action == "ban":
            raise HTTPException(status.HTTP_400_BAD_REQUEST, message)

@app.post("/api/auth/register", response_model=TokenResponse)
async def register(user_data: UserRegister, request: Request):
    client_ip = await get_client_ip(request)
    check_rate_limit(client_ip, "register")
    
    if db.check_user_exists(user_data.username, user_data.email):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Username or email already exists")
    
    password_hash, password_salt = security_manager.hash_password(user_data.password)
    user_id = db.create_user(user_data.username, user_data.email, password_hash, password_salt)
    access_token = security_manager.create_access_token({"sub": str(user_id)})
    user = db.get_user_by_id(user_id)
    
    return TokenResponse(
        access_token=access_token,
        expires_in=security_manager.access_token_expire_minutes * 60,
        user=UserResponse(**user)
    )

@app.post("/api/auth/login", response_model=TokenResponse)
async def login(login_data: UserLogin, request: Request):
    client_ip = await get_client_ip(request)
    check_rate_limit(client_ip, "login")
    
    user = db.get_user_by_username(login_data.username)
    if not user:
        raise Exceptions.UNAUTHORIZED
    
    if not security_manager.verify_password(login_data.password, user["password_hash"]):
        db.increment_failed_login(user["user_id"], client_ip)
        raise Exceptions.UNAUTHORIZED
    
    if user["locked_until"] and user["locked_until"] > timestamp():
        raise Exceptions.ACCOUNT_LOCKED
    
    if user["is_banned"]:
        raise Exceptions.BANNED
    
    db.update_user_login(user["user_id"], client_ip)
    access_token = security_manager.create_access_token({"sub": str(user["user_id"])})
    
    return TokenResponse(
        access_token=access_token,
        expires_in=security_manager.access_token_expire_minutes * 60,
        user=UserResponse(**user)
    )

@app.post("/api/auth/refresh", response_model=TokenResponse)
async def refresh_token(current_user: dict = Depends(get_current_user)):
    access_token = security_manager.create_access_token({"sub": str(current_user["user_id"])})
    return TokenResponse(
        access_token=access_token,
        expires_in=security_manager.access_token_expire_minutes * 60,
        user=UserResponse(**current_user)
    )

@app.get("/api/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: int):
    user = validate_user_exists(user_id)
    return UserResponse(**user)

@app.put("/api/users/{user_id}", response_model=UserResponse)
async def update_user_profile(user_id: int, update_data: dict, current_user: dict = Depends(get_current_user)):
    validate_user_exists(user_id)
    validate_user_permissions(user_id, current_user)
    
    allowed_fields = ["avatar_url"]
    if current_user.get("is_admin"):
        allowed_fields.extend(["email", "is_banned"])
    
    filtered_updates = {k: v for k, v in update_data.items() if k in allowed_fields}
    if not filtered_updates:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No valid fields to update")
    
    db.update_user_profile(user_id, filtered_updates)
    updated_user = db.get_user_by_id(user_id)
    return UserResponse(**updated_user) # type: ignore

@app.get("/api/users/{user_id}/info")
async def get_user_info(user_id: int, current_user: dict = Depends(get_current_user)):
    validate_user_permissions(user_id, current_user, allow_self=True)
    validate_user_exists(user_id)
    user_info = db.get_user_info(user_id)
    return UserInfo(**user_info)

@app.get("/api/users/{user_id}/public", response_model=PublicUserInfo)
async def get_public_user_info(user_id: int):
    validate_user_exists(user_id)
    user_info = db.get_user_info(user_id)
    if not user_info:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return PublicUserInfo(**user_info)

@app.get("/api/users/{user_id}/preferences")
async def get_user_preferences(user_id: int, current_user: dict = Depends(get_current_user)):
    validate_user_permissions(user_id, current_user, allow_self=True)
    preferences = db.get_user_preferences(user_id)
    if not preferences:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User preferences not found")
    return preferences

@app.put("/api/users/{user_id}/preferences")
async def update_user_preferences(user_id: int, preferences_data: dict, current_user: dict = Depends(get_current_user)):
    validate_user_permissions(user_id, current_user, allow_self=True)
    
    allowed_fields = ["email_notifications", "theme", "timezone", "posts_per_page", "signature", "show_avatars", "show_signatures"]
    filtered_prefs = {k: v for k, v in preferences_data.items() if k in allowed_fields}
    
    db.update_user_preferences(user_id, filtered_prefs)
    return db.get_user_preferences(user_id)

@app.get("/api/admin/users")
async def get_all_users(page: int = 1, per_page: int = 20, current_user: dict = Depends(require_admin)):
    return db.get_all_users(page, per_page)

@app.post("/api/admin/users/{user_id}/ban")
@audit_action("user_banned")
async def ban_user(user_id: int, ban_data: dict, request: Request, current_user: dict = Depends(require_admin)):
    user = validate_user_exists(user_id)
    validate_admin_action(user, current_user, "ban")
    
    db.ban_user(user_id)
    db.log_moderation_action(current_user["user_id"], "user", user_id, "ban", ban_data.get("reason", "No reason provided"))
    return {"message": "User banned successfully"}

@app.post("/api/admin/users/{user_id}/unban")
@audit_action("user_unbanned")
async def unban_user(user_id: int, request: Request, current_user: dict = Depends(require_admin)):
    validate_user_exists(user_id)
    db.unban_user(user_id)
    db.log_moderation_action(current_user["user_id"], "user", user_id, "unban")
    return {"message": "User unbanned successfully"}

@app.post("/api/admin/users/{user_id}/promote")
@audit_action("admin_granted")
async def make_user_admin(user_id: int, request: Request, current_user: dict = Depends(require_admin)):
    user = validate_user_exists(user_id)
    if user["is_admin"]:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "User is already an admin")
    
    db.promote_user_to_admin(user_id)
    db.log_moderation_action(current_user["user_id"], "user", user_id, "promote_admin")
    return {"message": "User promoted to admin successfully"}

@app.post("/api/admin/users/{user_id}/demote")
@audit_action("admin_revoked")
async def remove_user_admin(user_id: int, request: Request, current_user: dict = Depends(require_admin)):
    user = validate_user_exists(user_id)
    if not user["is_admin"]:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "User is not an admin")
    validate_admin_action(user, current_user, "demote")
    
    db.demote_user_from_admin(user_id)
    db.log_moderation_action(current_user["user_id"], "user", user_id, "demote_admin")
    return {"message": "Admin privileges removed successfully"}

@app.get("/api/boards", response_model=List[BoardResponse])
async def get_boards():
    boards = db.get_all_boards()
    return [BoardResponse(**board) for board in boards]

@app.post("/api/boards", response_model=BoardResponse)
@audit_action("board_created", "board")
async def create_board(board_data: BoardCreate, request: Request, current_user: dict = Depends(require_admin)):
    board_id = db.create_board(board_data.name, board_data.description, current_user["user_id"])
    db.log_moderation_action(current_user["user_id"], "board", board_id, "create")
    board = db.get_board_by_id(board_id)
    return BoardResponse(**board) # type: ignore

@app.get("/api/boards/{board_id}/threads", response_model=List[ThreadResponse])
async def get_threads(board_id: int, page: int = 1, per_page: int = 20):
    threads = db.get_threads_by_board(board_id, page, per_page)
    return [ThreadResponse(**thread) for thread in threads]

@app.post("/api/boards/{board_id}/threads", response_model=ThreadResponse)
async def create_thread(board_id: int, thread_data: ThreadCreate, request: Request, current_user: dict = Depends(get_current_user)):
    check_rate_limit(str(current_user["user_id"]), "thread")
    
    if not db.board_exists(board_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Board not found")
    
    thread_id = db.create_thread(board_id, current_user["user_id"], thread_data.title, thread_data.content)
    thread = db.get_thread_by_id(thread_id)
    return ThreadResponse(**thread) # type: ignore

@app.get("/api/threads/{thread_id}", response_model=ThreadResponse)
async def get_thread(thread_id: int):
    thread = db.get_thread_by_id(thread_id)
    if not thread:
        raise Exceptions.NOT_FOUND
    return ThreadResponse(**thread)

@app.delete("/api/threads/{thread_id}")
@audit_action("thread_deleted", "thread")
async def delete_thread(thread_id: int, request: Request, current_user: dict = Depends(get_current_user)):
    thread = db.thread_exists_and_accessible(thread_id)
    if not thread:
        raise Exceptions.NOT_FOUND
    
    if thread["user_id"] != current_user["user_id"] and not current_user.get("is_admin"):
        raise Exceptions.FORBIDDEN
    
    db.delete_thread(thread_id)
    db.log_moderation_action(current_user["user_id"], "thread", thread_id, "delete")
    return {"message": "Thread deleted successfully"}

@app.patch("/api/threads/{thread_id}/lock")
@audit_action("thread_locked", "thread")
async def toggle_thread_lock(thread_id: int, lock_data: dict, request: Request, current_user: dict = Depends(require_admin)):
    if not db.thread_exists_and_accessible(thread_id):
        raise Exceptions.NOT_FOUND
    
    locked = lock_data.get("locked", True)
    db.update_thread_lock_status(thread_id, locked)
    db.log_moderation_action(current_user["user_id"], "thread", thread_id, "lock" if locked else "unlock")
    return {"message": f"Thread {'locked' if locked else 'unlocked'} successfully"}

@app.patch("/api/threads/{thread_id}/sticky")
@audit_action("thread_stickied", "thread")
async def toggle_thread_sticky(thread_id: int, sticky_data: dict, request: Request, current_user: dict = Depends(require_admin)):
    if not db.thread_exists_and_accessible(thread_id):
        raise Exceptions.NOT_FOUND
    
    sticky = sticky_data.get("sticky", True)
    db.update_thread_sticky_status(thread_id, sticky)
    db.log_moderation_action(current_user["user_id"], "thread", thread_id, "sticky" if sticky else "unsticky")
    return {"message": f"Thread {'stickied' if sticky else 'unstickied'} successfully"}

@app.get("/api/threads/{thread_id}/posts", response_model=List[PostResponse])
async def get_posts(thread_id: int, page: int = 1, per_page: int = 20):
    db.increment_thread_view_count(thread_id)
    posts = db.get_posts_by_thread(thread_id, page, per_page)
    return [PostResponse(**post) for post in posts]

@app.post("/api/threads/{thread_id}/posts", response_model=PostResponse)
async def create_post(thread_id: int, post_data: PostCreate, request: Request, current_user: dict = Depends(get_current_user)):
    check_rate_limit(str(current_user["user_id"]), "post")
    
    thread = db.thread_exists_and_accessible(thread_id)
    if not thread:
        raise Exceptions.NOT_FOUND
    if thread["locked"]:
        raise Exceptions.THREAD_LOCKED
    if thread["board_deleted"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Board not found")
    
    post_id = db.create_post(thread_id, current_user["user_id"], post_data.content)
    post = db.get_post_by_id(post_id)
    return PostResponse(**post) # type: ignore

@app.get("/api/posts/{post_id}", response_model=PostResponse)
async def get_post(post_id: int):
    post = db.get_post_by_id(post_id)
    if not post:
        raise Exceptions.NOT_FOUND
    return PostResponse(**post)

@app.patch("/api/posts/{post_id}", response_model=PostResponse)
async def edit_post(post_id: int, post_data: PostCreate, request: Request, current_user: dict = Depends(get_current_user)):
    check_rate_limit(str(current_user["user_id"]), "edit")
    
    post = db.get_post_with_context(post_id)
    if not post:
        raise Exceptions.NOT_FOUND
    
    if post["user_id"] != current_user["user_id"] and not current_user.get("is_admin"):
        raise Exceptions.FORBIDDEN
    
    if post["locked"] and not current_user.get("is_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot edit posts in locked thread")
    
    if post["thread_deleted"] or post["board_deleted"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Thread or board not found")
    
    if current_user["user_id"] != post["user_id"] and current_user.get("is_admin"):
        client_ip = await get_client_ip(request)
        db.log_security_audit(
            user_id=post["user_id"],
            event_type="post_edited_by_admin",
            ip_address=client_ip,
            user_agent=request.headers.get("user-agent", ""),
            event_data=f'{{"moderator_id": {current_user["user_id"]}, "post_id": {post_id}}}'
        )
    
    db.update_post(post_id, post_data.content, current_user["user_id"])
    updated_post = db.get_post_by_id(post_id)
    return PostResponse(**updated_post) # type: ignore

@app.delete("/api/posts/{post_id}")
@audit_action("post_deleted", "post")
async def delete_post(post_id: int, request: Request, current_user: dict = Depends(get_current_user)):
    post = db.get_post_with_context(post_id)
    if not post:
        raise Exceptions.NOT_FOUND
    
    if post["user_id"] != current_user["user_id"] and not current_user.get("is_admin"):
        raise Exceptions.FORBIDDEN
    
    if post["locked"] and not current_user.get("is_admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot delete posts in locked thread")
    
    db.delete_post(post_id)
    
    if current_user.get("is_admin"):
        db.log_moderation_action(current_user["user_id"], "post", post_id, "delete")
    
    return {"message": "Post deleted successfully"}

@app.patch("/api/posts/{post_id}/restore")
@audit_action("post_restored", "post")
async def restore_post(post_id: int, request: Request, current_user: dict = Depends(require_admin)):
    if not db.restore_post(post_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Deleted post not found or cannot be restored")
    
    db.log_moderation_action(current_user["user_id"], "post", post_id, "restore")
    return {"message": "Post restored successfully"}

@app.get("/api/posts/{post_id}/history")
async def get_post_edit_history(post_id: int, current_user: dict = Depends(get_current_user)):
    post = db.get_post_with_context(post_id)
    if not post:
        raise Exceptions.NOT_FOUND
    
    if post["user_id"] != current_user["user_id"] and not current_user.get("is_admin"):
        raise Exceptions.FORBIDDEN
    
    return db.get_post_edit_history(post_id)

@app.get("/api/search")
async def search_forum(q: str, type: str = "all", page: int = 1, per_page: int = 20):
    if len(q.strip()) < 3:
        raise Exceptions.SEARCH_TOO_SHORT
    return db.search_forum_content(q, type, page, per_page)

@app.get("/api/stats")
async def get_forum_statistics():
    return db.get_forum_statistics()

@app.get("/api/admin/moderation-log")
async def get_moderation_log(page: int = 1, per_page: int = 50, current_user: dict = Depends(require_admin)):
    return db.get_moderation_log(page, per_page)

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(error=exc.__class__.__name__, message=exc.detail).dict()
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(error="InternalServerError", message="An unexpected error occurred").dict()
    )

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": timestamp()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)