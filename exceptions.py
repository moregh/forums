from fastapi import HTTPException, status
from config import SEARCH_QUERY_MIN_LENGTH


class Exceptions:
    UNAUTHORIZED = HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    FORBIDDEN = HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
    NOT_FOUND = HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    ALREADY_EXISTS = HTTPException(status.HTTP_400_BAD_REQUEST, "Resource already exists")
    ACCOUNT_LOCKED = HTTPException(status.HTTP_423_LOCKED, "Account temporarily locked")
    BANNED = HTTPException(status.HTTP_403_FORBIDDEN, "Account banned")
    TOO_MANY_REQUESTS = HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded")
    ADMIN_REQUIRED = HTTPException(status.HTTP_403_FORBIDDEN, "Admin privileges required")
    THREAD_LOCKED = HTTPException(status.HTTP_403_FORBIDDEN, "Thread is locked")
    SEARCH_TOO_SHORT = HTTPException(status.HTTP_400_BAD_REQUEST, f"Search query must be at least {SEARCH_QUERY_MIN_LENGTH} characters")