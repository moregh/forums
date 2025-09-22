import sqlite3
import bcrypt
from datetime import datetime, timedelta
from fastapi import HTTPException, status
import jwt
import time


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


class RateLimiter:
    def __init__(self, db_path: str):
        self.db_path = db_path
        
    def check_rate_limit(self, identifier: str, action: str, limit: int, window_minutes: int = 60) -> bool:
        """Check if action is within rate limits"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            window_start = time.time() - (window_minutes * 60)
            cursor.execute(
                "DELETE FROM rate_limits WHERE window_start < ? AND identifier = ? AND action_type = ?",
                (window_start, identifier, action)
            )
            
            cursor.execute(
                "SELECT attempt_count FROM rate_limits WHERE identifier = ? AND action_type = ?",
                (identifier, action)
            )
            
            result = cursor.fetchone()
            current_count = result[0] if result else 0
            
            if current_count >= limit:
                return False
            
            cursor.execute("""
                INSERT OR REPLACE INTO rate_limits 
                (identifier, action_type, attempt_count, window_start)
                VALUES (?, ?, ?, ?)
            """, (identifier, action, current_count + 1, time.time()))
            
            conn.commit()
            return True

