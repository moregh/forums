from pydantic import BaseModel, EmailStr, validator
from typing import Optional, Dict, Any, List
import re


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
        if len(v) < 10:
            raise ValueError('Password must be at least 12 characters')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one number')
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', v):
            raise ValueError('Password must contain at least one special character')        
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

class PostEdit(BaseModel):
    content: str
    
    @validator('content')
    def validate_content(cls, v):
        if len(v) < 1 or len(v) > 50000:
            raise ValueError('Content must be 1-50000 characters')
        return v

class PostEditHistory(BaseModel):
    edit_id: int
    post_id: int
    editor_id: int
    editor_name: str
    old_content: str
    new_content: str
    edit_reason: Optional[str]
    edit_type: str
    timestamp: float

class PostDetailResponse(PostResponse):
    """Extended post response with edit history"""
    edit_history: Optional[List[PostEditHistory]] = None


