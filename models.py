from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional, Dict, Any, List
import re
from config import (USERNAME_MIN_LENGTH, USERNAME_MAX_LENGTH, PASSWORD_MIN_LENGTH,
                   BOARD_NAME_MIN_LENGTH, BOARD_NAME_MAX_LENGTH, THREAD_TITLE_MIN_LENGTH,
                   THREAD_TITLE_MAX_LENGTH, POST_CONTENT_MIN_LENGTH, POST_CONTENT_MAX_LENGTH)


class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if len(v) < USERNAME_MIN_LENGTH or len(v) > USERNAME_MAX_LENGTH:
            raise ValueError(f'Username must be {USERNAME_MIN_LENGTH}-{USERNAME_MAX_LENGTH} characters')
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username can only contain letters, numbers, hyphens, and underscores')
        return v
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < PASSWORD_MIN_LENGTH:
            raise ValueError(f'Password must be at least {PASSWORD_MIN_LENGTH} characters')
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

class UserInfo(BaseModel):
    user_id: int
    username: str
    email: str
    is_admin: bool
    is_banned: bool
    join_date: float
    last_activity: float
    post_count: int
    avatar_url: str
    thread_count: int
    last_post_at: float
    activity_status: str
    user_rank: str
    posts_per_day: float
    recent_posts: List[Dict[str, Any]]
    days_since_join: int
    rank_description: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse
    csrf_token: Optional[str] = None

class BoardCreate(BaseModel):
    name: str
    description: str
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if len(v) < BOARD_NAME_MIN_LENGTH or len(v) > BOARD_NAME_MAX_LENGTH:
            raise ValueError(f'Board name must be {BOARD_NAME_MIN_LENGTH}-{BOARD_NAME_MAX_LENGTH} characters')
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
    
    @field_validator('title')
    @classmethod
    def validate_title(cls, v):
        if len(v) < THREAD_TITLE_MIN_LENGTH or len(v) > THREAD_TITLE_MAX_LENGTH:
            raise ValueError(f'Thread title must be {THREAD_TITLE_MIN_LENGTH}-{THREAD_TITLE_MAX_LENGTH} characters')
        return v
    
    @field_validator('content')
    @classmethod
    def validate_content(cls, v):
        if len(v) < POST_CONTENT_MIN_LENGTH or len(v) > POST_CONTENT_MAX_LENGTH:
            raise ValueError(f'Content must be {POST_CONTENT_MIN_LENGTH}-{POST_CONTENT_MAX_LENGTH} characters')
        return v

class PostCreate(BaseModel):
    content: str
    
    @field_validator('content')
    @classmethod
    def validate_content(cls, v):
        if len(v) < POST_CONTENT_MIN_LENGTH or len(v) > POST_CONTENT_MAX_LENGTH:
            raise ValueError(f'Content must be {POST_CONTENT_MIN_LENGTH}-{POST_CONTENT_MAX_LENGTH} characters')
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
    
    @field_validator('content')
    @classmethod
    def validate_content(cls, v):
        if len(v) < POST_CONTENT_MIN_LENGTH or len(v) > POST_CONTENT_MAX_LENGTH:
            raise ValueError(f'Content must be {POST_CONTENT_MIN_LENGTH}-{POST_CONTENT_MAX_LENGTH} characters')
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

class PublicUserInfo(BaseModel):
    """Public user info without sensitive data"""
    user_id: int
    username: str
    is_admin: bool
    is_banned: bool
    join_date: float
    last_activity: float
    post_count: int
    avatar_url: str
    thread_count: int
    last_post_at: float
    activity_status: str
    user_rank: str
    posts_per_day: float
    recent_posts: List[Dict[str, Any]]
    days_since_join: int
    rank_description: str

class UserProfileUpdate(BaseModel):
    avatar_url: Optional[str] = None
    email: Optional[EmailStr] = None
    is_banned: Optional[bool] = None

    @field_validator('avatar_url')
    @classmethod
    def validate_avatar_url(cls, v):
        if v is not None and len(v) > 500:
            raise ValueError('Avatar URL must be less than 500 characters')
        return v

class UserPreferencesUpdate(BaseModel):
    email_notifications: Optional[bool] = None
    theme: Optional[str] = None
    timezone: Optional[str] = None
    posts_per_page: Optional[int] = None
    signature: Optional[str] = None
    show_avatars: Optional[bool] = None
    show_signatures: Optional[bool] = None

    @field_validator('theme')
    @classmethod
    def validate_theme(cls, v):
        if v is not None and v not in ['light', 'dark', 'auto']:
            raise ValueError('Theme must be light, dark, or auto')
        return v

    @field_validator('posts_per_page')
    @classmethod
    def validate_posts_per_page(cls, v):
        if v is not None and (v < 5 or v > 100):
            raise ValueError('Posts per page must be between 5 and 100')
        return v

    @field_validator('signature')
    @classmethod
    def validate_signature(cls, v):
        if v is not None and len(v) > 500:
            raise ValueError('Signature must be less than 500 characters')
        return v

class UserBan(BaseModel):
    reason: Optional[str] = None
    duration: Optional[int] = None  # Duration in days, None for permanent

    @field_validator('reason')
    @classmethod
    def validate_reason(cls, v):
        if v is not None and len(v) > 1000:
            raise ValueError('Ban reason must be less than 1000 characters')
        return v

    @field_validator('duration')
    @classmethod
    def validate_duration(cls, v):
        if v is not None and (v < 1 or v > 3650):  # Max 10 years
            raise ValueError('Ban duration must be between 1 and 3650 days')
        return v

class ThreadLockUpdate(BaseModel):
    locked: bool
    reason: Optional[str] = None

    @field_validator('reason')
    @classmethod
    def validate_reason(cls, v):
        if v is not None and len(v) > 500:
            raise ValueError('Lock reason must be less than 500 characters')
        return v

class ThreadStickyUpdate(BaseModel):
    sticky: bool
    reason: Optional[str] = None

    @field_validator('reason')
    @classmethod
    def validate_reason(cls, v):
        if v is not None and len(v) > 500:
            raise ValueError('Sticky reason must be less than 500 characters')
        return v


