#!/usr/bin/env python3
# Forum API Design & Architecture
# RESTful API with JWT authentication for decoupled frontend

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, validator
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import jwt
import bcrypt
import sqlite3
import secrets
import time
from contextlib import asynccontextmanager
from database import DatabaseManager
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
# SECURITY & AUTHENTICATION
# =============================================================================

class SecurityManager:
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.algorithm = "HS256"
        self.access_token_expire_minutes = 30
        
    def hash_password(self, password: str) -> tuple[str, str]:
        """Generate password hash and salt"""
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
        return password_hash.decode('utf-8'), salt.decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def create_access_token(self, data: dict) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str) -> dict:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

# =============================================================================
# RATE LIMITING & SECURITY MIDDLEWARE
# =============================================================================

class RateLimiter:
    def __init__(self, db_path: str):
        self.db_path = db_path
        
    def check_rate_limit(self, identifier: str, action: str, limit: int, window_minutes: int = 60) -> bool:
        """Check if action is within rate limits"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Clean up old records
            window_start = time.time() - (window_minutes * 60)
            cursor.execute(
                "DELETE FROM rate_limits WHERE window_start < ? AND identifier = ? AND action_type = ?",
                (window_start, identifier, action)
            )
            
            # Check current count
            cursor.execute(
                "SELECT attempt_count FROM rate_limits WHERE identifier = ? AND action_type = ?",
                (identifier, action)
            )
            
            result = cursor.fetchone()
            current_count = result[0] if result else 0
            
            if current_count >= limit:
                return False
            
            # Increment counter
            cursor.execute("""
                INSERT OR REPLACE INTO rate_limits 
                (identifier, action_type, attempt_count, window_start)
                VALUES (?, ?, ?, ?)
            """, (identifier, action, current_count + 1, time.time()))
            
            conn.commit()
            return True


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
rate_limiter = RateLimiter("forum.db")
db = DatabaseManager("forum.db")

# CORS middleware for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8080", "https://yourforum.com"],  # Update with your frontend URLs
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

@app.post("/api/auth/register", response_model=TokenResponse)
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

@app.post("/api/auth/login", response_model=TokenResponse)
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
    )  # type: ignore

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    if not security_manager.verify_password(login_data.password, user["password_hash"]):
        # Log failed attempt
        if user:
            db.execute_query("""
                UPDATE users 
                SET failed_login_attempts = failed_login_attempts + 1,
                    last_login_ip = ?
                WHERE user_id = ?
            """, (client_ip, user["user_id"]))
        
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
            detail="Banned"
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
    
    # Create access token
    access_token = security_manager.create_access_token({"sub": str(user["user_id"])})
    
    return TokenResponse(
        access_token=access_token,
        expires_in=security_manager.access_token_expire_minutes * 60,
        user=UserResponse(**dict(user))
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
# BOARD ENDPOINTS
# =============================================================================

@app.get("/api/boards", response_model=List[BoardResponse])
async def get_boards():
    """Get all visible boards"""
    boards = db.execute_query("SELECT * FROM board_summary ORDER BY name")
    return [BoardResponse(**dict(board)) for board in boards]

@app.post("/api/boards", response_model=BoardResponse)
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
    
    # Get created board
    board = db.execute_query(
        "SELECT * FROM board_summary WHERE board_id = ?",
        (board_id,),
        fetch_one=True
    )
    
    return BoardResponse(**dict(board))

# =============================================================================
# THREAD ENDPOINTS
# =============================================================================

@app.get("/api/boards/{board_id}/threads", response_model=List[ThreadResponse])
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


# =============================================================================
# POST ENDPOINTS
# =============================================================================

@app.get("/api/threads/{thread_id}/posts", response_model=List[PostResponse])
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
    
    if thread["locked"]:  # type: ignore
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Thread is locked"
        )
    
    if thread["board_deleted"]:  # type: ignore
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
    return {"status": "healthy", "timestamp": time.time()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)