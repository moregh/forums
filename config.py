SECRET_KEY = "your-secret-key-change-this"
DB_PATH = "forum.db"
ALLOWED_ORIGINS = ["http://localhost:3000", "http://localhost:8080", "https://yourforum.com", "http://10.0.1.251:8080"]
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "yourapi.com", "10.0.1.251"]
ACCESS_TOKEN_EXPIRE_MINUTES = 30

RATE_LIMITS = {
    "register": (5, 60),
    "login": (10, 60),
    "edit": (30, 60),
    "post": (20, 60),
    "thread": (10, 60)
}

# Server Configuration
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8000

# Validation Constants
USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 50
PASSWORD_MIN_LENGTH = 10
BOARD_NAME_MIN_LENGTH = 2
BOARD_NAME_MAX_LENGTH = 100
THREAD_TITLE_MIN_LENGTH = 3
THREAD_TITLE_MAX_LENGTH = 255
POST_CONTENT_MIN_LENGTH = 1
POST_CONTENT_MAX_LENGTH = 50000
SEARCH_QUERY_MIN_LENGTH = 3

# Cache TTL Settings (in seconds)
DEFAULT_CACHE_TTL = 300  # 5 minutes
USER_CACHE_TTL = 300     # 5 minutes
BOARD_CACHE_TTL = 600    # 10 minutes
THREAD_CACHE_TTL = 180   # 3 minutes
USER_INFO_CACHE_TTL = 120  # 2 minutes
PUBLIC_USER_INFO_CACHE_TTL = 300  # 5 minutes
STATS_CACHE_TTL = 300    # 5 minutes

# Cache Cleanup Settings
CACHE_CLEANUP_INTERVAL = 600  # 10 minutes
CACHE_EXPIRE_TIME = 1800      # 30 minutes

# Session Settings
SESSION_EXPIRE_HOURS = 24
SESSION_TOKEN_BYTES = 64

# Pagination Defaults
DEFAULT_PAGE_SIZE = 20
ADMIN_PAGE_SIZE = 50
RECENT_POSTS_LIMIT = 3
TOP_BOARDS_LIMIT = 5

# Security Settings
MAX_REQUEST_SIZE_MB = 1
GZIP_MIN_SIZE = 1000
FAILED_LOGIN_RESET = 0
ONLINE_STATUS_MINUTES = 15    # Last 15 minutes for online status
RECENT_ACTIVITY_HOURS = 1     # Last hour for recent activity
RATE_LIMIT_WINDOW_DEFAULT = 60  # Default rate limit window in minutes

# Time Constants (in seconds)
SECONDS_PER_DAY = 86400
SECONDS_PER_HOUR = 3600
MINUTES_15 = 900

# User Rank Thresholds
RANK_VETERAN_POSTS = 1000
RANK_ACTIVE_POSTS = 500
RANK_REGULAR_POSTS = 100
RANK_MEMBER_POSTS = 10

# HTTP Status Codes
HTTP_REQUEST_ENTITY_TOO_LARGE = 413
HTTP_NOT_FOUND = 404
HTTP_INTERNAL_SERVER_ERROR = 500

# CSRF Token Settings
CSRF_TOKEN_BYTES = 32

# Cache Control Settings
CACHE_MAX_AGE_24H = 86400  # 24 hours for static files