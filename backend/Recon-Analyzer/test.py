#!/usr/bin/env python3
"""
ReconGraph API Test Suite
Tests all endpoints of the ReconGraph API
Can run standalone (starts its own server) or against an existing server.
"""
import json
import sys
import threading
import time

import requests

BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 30


def start_server():
    """Start the Flask server in a background thread."""
    import os
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # Add src to path for imports
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))
    
    from src.main import app
    
    # Run Flask in a separate thread
    server_thread = threading.Thread(
        target=lambda: app.run(host='127.0.0.1', port=8000, debug=False, use_reloader=False),
        daemon=True
    )
    server_thread.start()
    
    # Wait for server to start
    max_retries = 10
    for i in range(max_retries):
        try:
            requests.get(f"{BASE_URL}/health", timeout=2)
            print("✓ Server started successfully\n")
            return True
        except requests.exceptions.ConnectionError:
            time.sleep(0.5)
    
    print("✗ Failed to start server")
    return False


def pretty(resp):
    """Pretty print JSON response."""
    try:
        return json.dumps(resp.json(), indent=2)
    except Exception:
        return resp.text


def test_endpoint(name, method, endpoint, payload=None, expected_status=200):
    """Generic test function for endpoints."""
    print(f"\n{'='*60}")
    print(f"[TEST] {name}")
    print(f"{'='*60}")
    
    url = f"{BASE_URL}{endpoint}"
    print(f"URL: {method} {url}")
    if payload:
        print(f"Payload: {json.dumps(payload)}")
    
    try:
        if method == "GET":
            r = requests.get(url, timeout=TIMEOUT)
        else:
            r = requests.post(url, json=payload, timeout=TIMEOUT)
        
        status_ok = r.status_code == expected_status
        status_symbol = "✓" if status_ok else "✗"
        
        print(f"Status: {r.status_code} {status_symbol}")
        print(f"Response:\n{pretty(r)}")
        
        return status_ok, r
    except requests.exceptions.ConnectionError:
        print("✗ ERROR: Could not connect to server. Is it running?")
        return False, None
    except requests.exceptions.Timeout:
        print("✗ ERROR: Request timed out")
        return False, None
    except Exception as e:
        print(f"✗ ERROR: {e}")
        return False, None


def run_tests():
    """Run all API tests."""
    print("\n" + "="*60)
    print("         ReconGraph API Test Suite")
    print("="*60)
    print(f"Base URL: {BASE_URL}")
    print(f"Timeout: {TIMEOUT}s")
    
    results = []
    
    # Test 1: Home endpoint
    ok, _ = test_endpoint(
        "Home / Info Endpoint",
        "GET", "/"
    )
    results.append(("Home", ok))
    
    # Test 2: Health check
    ok, _ = test_endpoint(
        "Health Check",
        "GET", "/health"
    )
    results.append(("Health", ok))
    
    # Test 3: Scan IP
    ok, _ = test_endpoint(
        "Scan IP Address (8.8.8.8)",
        "POST", "/scan",
        {"query": "8.8.8.8"}
    )
    results.append(("Scan IP", ok))
    
    # Test 4: Scan Domain
    ok, _ = test_endpoint(
        "Scan Domain (google.com)",
        "POST", "/scan",
        {"query": "google.com"}
    )
    results.append(("Scan Domain", ok))
    
    # Test 5: Scan Invalid Input
    ok, _ = test_endpoint(
        "Scan Invalid Input",
        "POST", "/scan",
        {"query": "not-valid!!!"},
        expected_status=400
    )
    results.append(("Scan Invalid", ok))
    
    # Test 6: Scan Empty
    ok, _ = test_endpoint(
        "Scan Empty Query",
        "POST", "/scan",
        {},
        expected_status=400
    )
    results.append(("Scan Empty", ok))
    
    # Test 7: Footprint Email
    ok, _ = test_endpoint(
        "Footprint Email",
        "POST", "/footprint",
        {"query": "test@example.com"}
    )
    results.append(("Footprint Email", ok))
    
    # Test 8: Footprint Phone
    ok, _ = test_endpoint(
        "Footprint Phone",
        "POST", "/footprint",
        {"query": "+14155552671"}
    )
    results.append(("Footprint Phone", ok))
    
    # Test 9: Footprint Username (generic)
    ok, _ = test_endpoint(
        "Footprint Username (generic)",
        "POST", "/footprint",
        {"query": "john_doe_test_user"}
    )
    results.append(("Footprint Username", ok))
    
    # Test 10: Footprint Username (ClstDegen)
    ok, _ = test_endpoint(
        "Footprint Username (ClstDegen)",
        "POST", "/footprint",
        {"query": "ClstDegen"}
    )
    results.append(("Footprint ClstDegen", ok))
    
    # Test 11: Footprint Empty
    ok, _ = test_endpoint(
        "Footprint Empty Query",
        "POST", "/footprint",
        {},
        expected_status=400
    )
    results.append(("Footprint Empty", ok))
    
    # Summary
    print("\n" + "="*60)
    print("                 TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, ok in results if ok)
    failed = sum(1 for _, ok in results if not ok)
    
    for name, ok in results:
        symbol = "✓ PASS" if ok else "✗ FAIL"
        print(f"  {name:20s} : {symbol}")
    
    print("-"*60)
    print(f"  Total: {len(results)} | Passed: {passed} | Failed: {failed}")
    print("="*60)
    
    return failed == 0


if __name__ == "__main__":
    print("\n" + "="*60)
    print("       ReconGraph API Test Suite")
    print("="*60)
    
    # Check if server is already running
    try:
        requests.get(f"{BASE_URL}/health", timeout=2)
        print("Using existing server at", BASE_URL)
    except requests.exceptions.ConnectionError:
        print("Starting embedded server...")
        if not start_server():
            print("ERROR: Could not start server")
            sys.exit(1)
    
    success = run_tests()
    sys.exit(0 if success else 1)
