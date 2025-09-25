# API Fuzzing Script

This comprehensive fuzzing script tests all API endpoints with various attack vectors and edge cases.

## ⚠️ WARNING

**This script is DESTRUCTIVE and will corrupt/modify database data!**
**Only run this against test environments!**

## Features

### Authentication Testing
- Valid/invalid JWT tokens
- Missing authentication
- Expired tokens
- Mixed authentication scenarios
- Token manipulation

### CSRF Protection Testing
- Valid/invalid CSRF tokens
- Missing CSRF tokens
- Cross-scenario token reuse
- Token manipulation

### Permission Level Testing
- Regular user permissions
- Admin-only endpoints
- Banned user access
- Permission escalation attempts

### Input Validation Testing
- XSS payloads (`<script>alert('xss')</script>`)
- SQL injection (`'; DROP TABLE users; --`)
- Path traversal (`../../../etc/passwd`)
- Buffer overflow attempts (very long strings)
- Null byte injection
- Template injection
- LDAP injection
- JavaScript injection
- Data URI attacks

### Database Integrity Verification
- Checks for XSS in stored data
- Detects SQL injection artifacts
- Identifies encoding issues
- Finds null byte pollution

## Usage

### 1. Install Dependencies
```bash
pip install -r fuzzer_requirements.txt
```

### 2. Start the Forum Application
Make sure your forum application is running on `http://localhost:8000`

### 3. Run the Fuzzer
```bash
python api_fuzzer.py --confirm-destructive
```

### 4. Configuration
Edit the script to change:
- `API_BASE_URL`: Default is `http://localhost:8000`
- `DATABASE_PATH`: Default is `forum.db`

## Test Categories

### Authentication Endpoints
- `/api/auth/register` - User registration with malicious payloads
- `/api/auth/login` - Login with various inputs
- `/api/auth/refresh` - Token refresh scenarios

### User Management
- `/api/users/{id}` - User profile access
- `/api/users/{id}/info` - User information
- `/api/users/{id}/preferences` - User preferences

### Board Management
- `/api/boards` - Board creation and listing
- `/api/boards/{id}/threads` - Thread management

### Content Management
- `/api/threads/{id}` - Thread operations
- `/api/threads/{id}/posts` - Post creation/management
- `/api/posts/{id}` - Post editing/deletion

### Admin Endpoints
- `/api/admin/users/{id}/ban` - User banning
- `/api/admin/users/{id}/promote` - Permission changes
- `/api/admin/moderation-log` - Admin logging

## Test Scenarios

The fuzzer runs each test case with multiple authentication scenarios:

1. **No Authentication** - Tests unauthenticated access
2. **Invalid Tokens** - Uses malformed/fake tokens
3. **Regular User** - Normal user permissions
4. **Admin User** - Administrative permissions
5. **Banned User** - Banned user access attempts
6. **Mixed Tokens** - Mismatched auth/CSRF tokens
7. **Expired Session** - Missing session cookies

## Output

### Console Output
- Real-time progress updates
- Immediate vulnerability alerts
- Error summaries
- Performance issues

### JSON Report
Creates detailed JSON report: `fuzz_report_{timestamp}.json` containing:
- Test execution summary
- Vulnerability details
- Database integrity issues
- Performance metrics
- Full response data

### Report Categories
- ✅ **PASS** - Expected behavior
- ❌ **FAIL** - Expected failure
- 🔥 **ERROR** - Server errors (500s)
- ⚠️ **UNEXPECTED** - Unexpected responses
- 🚨 **VULNERABILITIES** - Security issues found
- 🗄️ **DATABASE ISSUES** - Data corruption detected

## Common Vulnerability Patterns

### Authentication Bypass
```
GET /api/admin/users HTTP/1.1
# No Authorization header
# Expected: 401, Actual: 200 ← VULNERABILITY
```

### CSRF Bypass
```
POST /api/users/1 HTTP/1.1
Authorization: Bearer valid_token
# No X-CSRF-Token header
# Expected: 403, Actual: 200 ← VULNERABILITY
```

### XSS Storage
```
POST /api/threads/1/posts HTTP/1.1
{"content": "<script>alert('xss')</script>"}
# Check database for unsanitized storage
```

### SQL Injection
```
POST /api/auth/register HTTP/1.1
{"username": "'; DROP TABLE users; --"}
# Monitor for database errors/changes
```

## Security Checklist

After running the fuzzer, verify:

- [ ] No authentication bypasses
- [ ] CSRF protection working
- [ ] Input sanitization effective
- [ ] No SQL injection possible
- [ ] XSS prevention working
- [ ] Permission controls enforced
- [ ] Rate limiting active
- [ ] Error handling secure
- [ ] Database integrity maintained

## Extending the Fuzzer

### Add New Test Cases
```python
cases.append(FuzzCase(
    name="custom_test",
    method="POST",
    endpoint="/api/custom",
    requires_auth=True,
    requires_csrf=True,
    body={"malicious": "payload"},
    expected_status=400,
    description="Custom vulnerability test"
))
```

### Add New Payloads
```python
def generate_custom_payloads(self):
    return [
        "custom_payload_1",
        "custom_payload_2",
        # ... more payloads
    ]
```

### Add Database Checks
```python
# Add to verify_database_integrity()
async with self.db.execute("SELECT * FROM custom_table") as cursor:
    # Custom integrity checks
```

## Troubleshooting

### Common Issues

**Connection Refused**
- Ensure forum application is running
- Check API_BASE_URL in script

**Database Access Denied**
- Ensure DATABASE_PATH is correct
- Check file permissions

**Memory Issues**
- Reduce test case count
- Limit concurrent requests

**Rate Limiting**
- Add delays between requests
- Reduce test frequency

## Legal Notice

This tool is for security testing authorized systems only.
Unauthorized use may violate laws and regulations.
Use responsibly and only on systems you own or have permission to test.