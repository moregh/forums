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