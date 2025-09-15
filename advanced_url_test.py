#!/usr/bin/env python3
import urllib.request
import urllib.error
import urllib.parse
import time
import base64
import hashlib
import hmac
import json
import socket
import ssl
from urllib.parse import urlparse, parse_qs, urlencode

# The URL to test
original_url = "https://static-trans-v2.appx.co.in/videos/parmaracademy-data/266114-1741590819/encrypted-c833af/720p.zip?URLPrefix=aHR0cHM6Ly9zdGF0aWMtdHJhbnMtdjIuYXBweC5jby5pbi92aWRlb3MvcGFybWFyYWNhZGVteS1kYXRhLzI2NjExNC0xNzQxNTkwODE5L2VuY3J5cHRlZC1jODMzYWYvNzIwcC56aXA&Expires=1757939393&KeyName=appx-pdf-keyset&Signature=3U3pN6ta7sCW9A0_uPghlXTugzHmTUfhFLjeMeLXv9XXWdB_7sZYCyha3lxTIU95ioEejTcStJyWl6_"

def try_signature_variants(base_url, parsed_params):
    """Try different signature variations"""
    print("=== TRYING SIGNATURE VARIANTS ===")
    original_sig = parsed_params['Signature'][0]
    
    variants = [
        original_sig,
        original_sig + "=",
        original_sig + "==", 
        original_sig + "===",
        original_sig.replace("-", "+").replace("_", "/"),
        original_sig.replace("-", "+").replace("_", "/") + "=",
        original_sig.replace("-", "+").replace("_", "/") + "==",
        # Try removing last few characters in case of truncation
        original_sig[:-1],
        original_sig[:-2],
        original_sig[:-3],
        original_sig[:-4],
        original_sig[:-5],
    ]
    
    for i, sig_variant in enumerate(variants):
        print(f"Variant {i+1}: {sig_variant[:20]}...")
        test_params = parsed_params.copy()
        test_params['Signature'] = [sig_variant]
        test_url = base_url + "?" + urlencode({k: v[0] for k, v in test_params.items()})
        
        if test_request(test_url, f"Signature variant {i+1}"):
            return True
    return False

def try_parameter_variations(base_url, parsed_params):
    """Try different parameter combinations"""
    print("=== TRYING PARAMETER VARIATIONS ===")
    
    # Try without each parameter
    param_combinations = [
        # Remove URLPrefix
        {k: v for k, v in parsed_params.items() if k != 'URLPrefix'},
        # Remove Expires
        {k: v for k, v in parsed_params.items() if k != 'Expires'},
        # Remove KeyName
        {k: v for k, v in parsed_params.items() if k != 'KeyName'},
        # Only Signature
        {'Signature': parsed_params['Signature']},
        # Only Expires and Signature
        {'Expires': parsed_params['Expires'], 'Signature': parsed_params['Signature']},
        # Different expires values
        dict(parsed_params, Expires=['9999999999']),  # Far future
        dict(parsed_params, Expires=[str(int(time.time()) + 3600)]),  # 1 hour from now
    ]
    
    for i, params in enumerate(param_combinations):
        print(f"Parameter combination {i+1}: {list(params.keys())}")
        if params:
            test_url = base_url + "?" + urlencode({k: v[0] for k, v in params.items()})
        else:
            test_url = base_url
        
        if test_request(test_url, f"Parameter combination {i+1}"):
            return True
    return False

def try_path_variations():
    """Try different path variations"""
    print("=== TRYING PATH VARIATIONS ===")
    
    base_paths = [
        "https://static-trans-v2.appx.co.in/videos/parmaracademy-data/266114-1741590819/encrypted-c833af/720p.zip",
        "https://static-trans-v2.appx.co.in/videos/parmaracademy-data/266114-1741590819/encrypted-c833af/720p.mp4",
        "https://static-trans-v2.appx.co.in/videos/parmaracademy-data/266114-1741590819/encrypted-c833af/index.m3u8",
        "https://static-trans-v2.appx.co.in/videos/parmaracademy-data/266114-1741590819/encrypted-c833af/playlist.m3u8",
        "https://static-trans-v2.appx.co.in/videos/parmaracademy-data/266114-1741590819/720p.zip",
        "https://static-trans-v2.appx.co.in/videos/parmaracademy-data/266114-1741590819/720p.mp4",
        "https://appx.co.in/videos/parmaracademy-data/266114-1741590819/encrypted-c833af/720p.zip",
        "https://cdn.appx.co.in/videos/parmaracademy-data/266114-1741590819/encrypted-c833af/720p.zip",
    ]
    
    for i, path in enumerate(base_paths):
        print(f"Path variant {i+1}: {path}")
        if test_request(path, f"Path variant {i+1}"):
            return True
    return False

def try_different_methods():
    """Try different HTTP methods and approaches"""
    print("=== TRYING DIFFERENT HTTP METHODS ===")
    
    methods = ['GET', 'HEAD', 'POST', 'OPTIONS']
    
    for method in methods:
        print(f"Trying {method} method...")
        if test_request_with_method(original_url, method):
            return True
    return False

def test_request_with_method(url, method):
    """Test request with specific HTTP method"""
    try:
        req = urllib.request.Request(url)
        req.get_method = lambda: method
        
        # Add comprehensive headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Sec-Fetch-Dest': 'video',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'cross-site',
        }
        
        for key, value in headers.items():
            req.add_header(key, value)
        
        with urllib.request.urlopen(req, timeout=15) as response:
            status = response.getcode()
            print(f"✅ SUCCESS! {method} method returned {status}")
            print(f"Headers: {dict(response.headers)}")
            if method == 'GET' and hasattr(response, 'read'):
                content = response.read(100)  # Read first 100 bytes
                print(f"Content preview: {content}")
            return True
            
    except urllib.error.HTTPError as e:
        print(f"❌ {method} failed with HTTP {e.code}: {e.reason}")
        return False
    except Exception as e:
        print(f"❌ {method} failed with error: {e}")
        return False

def test_request(url, description=""):
    """Test a single URL request"""
    try:
        req = urllib.request.Request(url)
        
        # Rotate through different user agents
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
            'curl/8.12.1',
        ]
        
        for ua in user_agents:
            req.add_header('User-Agent', ua)
            req.add_header('Accept', '*/*')
            req.add_header('Accept-Language', 'en-US,en;q=0.9')
            
            try:
                with urllib.request.urlopen(req, timeout=10) as response:
                    status = response.getcode()
                    if status == 200:
                        print(f"✅ SUCCESS! {description} - Status: {status}")
                        print(f"URL: {url}")
                        print(f"User-Agent: {ua}")
                        print(f"Headers: {dict(response.headers)}")
                        return True
                    else:
                        print(f"⚠️  {description} - Status: {status}")
                        
            except urllib.error.HTTPError as e:
                if e.code != 404:  # Only report non-404 errors
                    print(f"❌ {description} - HTTP {e.code}: {e.reason}")
            except Exception as e:
                print(f"❌ {description} - Error: {e}")
    
    except Exception as e:
        print(f"❌ {description} - Setup error: {e}")
    
    return False

def try_raw_socket_connection():
    """Try raw socket connection to bypass HTTP libraries"""
    print("=== TRYING RAW SOCKET CONNECTION ===")
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect to server
        with socket.create_connection(('static-trans-v2.appx.co.in', 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname='static-trans-v2.appx.co.in') as ssock:
                # Send raw HTTP request
                parsed = urlparse(original_url)
                request = f"GET {parsed.path}?{parsed.query} HTTP/1.1\r\n"
                request += f"Host: {parsed.netloc}\r\n"
                request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                request += "Accept: */*\r\n"
                request += "Connection: close\r\n"
                request += "\r\n"
                
                ssock.send(request.encode())
                response = ssock.recv(4096).decode('utf-8', errors='ignore')
                
                print("Raw socket response:")
                print(response[:500])
                
                if "200 OK" in response:
                    print("✅ SUCCESS with raw socket!")
                    return True
                elif "404" not in response:
                    print(f"⚠️  Unexpected response with raw socket")
                    
    except Exception as e:
        print(f"❌ Raw socket failed: {e}")
    
    return False

def main():
    print("🔍 COMPREHENSIVE URL TESTING - TRYING ALL APPROACHES")
    print("=" * 60)
    print(f"Original URL: {original_url}")
    print("=" * 60)
    
    # Parse URL
    parsed_url = urlparse(original_url)
    parsed_params = parse_qs(parsed_url.query)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    
    print(f"Base URL: {base_url}")
    print(f"Parameters: {list(parsed_params.keys())}")
    print()
    
    # Try all approaches
    approaches = [
        ("Original URL", lambda: test_request(original_url, "Original URL")),
        ("Signature Variants", lambda: try_signature_variants(base_url, parsed_params)),
        ("Parameter Variations", lambda: try_parameter_variations(base_url, parsed_params)),
        ("Path Variations", lambda: try_path_variations()),
        ("Different HTTP Methods", lambda: try_different_methods()),
        ("Raw Socket Connection", lambda: try_raw_socket_connection()),
    ]
    
    success_count = 0
    for name, func in approaches:
        print(f"\n{'='*20} {name.upper()} {'='*20}")
        try:
            if func():
                success_count += 1
                print(f"✅ {name} SUCCEEDED!")
                break  # Stop on first success
            else:
                print(f"❌ {name} failed")
        except Exception as e:
            print(f"❌ {name} crashed: {e}")
    
    print(f"\n{'='*60}")
    if success_count > 0:
        print(f"🎉 SUCCESS! Found {success_count} working approach(es)!")
    else:
        print("❌ ALL APPROACHES FAILED")
        print("\nPOSSIBLE REASONS:")
        print("1. URL signature is genuinely invalid/truncated")
        print("2. File has been moved or deleted from server")
        print("3. Server requires authentication not present in URL")
        print("4. URL has expired (despite timestamp check)")
        print("5. Server-side access control blocking requests")
        print("6. Content is behind additional authorization layer")
    print("=" * 60)

if __name__ == "__main__":
    main()