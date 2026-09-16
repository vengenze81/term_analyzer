import subprocess
import time
import sys
import os

def test_help_command():
    """Ensure the script runs and displays help without errors."""
    result = subprocess.run([sys.executable, "term_analyzer.py", "--help"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "Async Terminal Analyzer" in result.stdout

def test_integration_audit():
    """Spin up the test server locally and run an audit test."""
    # Start server in background
    server_process = subprocess.Popen([sys.executable, "server.py"])
    time.sleep(1.5) # Give the server a moment to boot
    
    try:
        # Run term_analyzer against the local test server
        cmd = [
            sys.executable, "term_analyzer.py", 
            "--url", "http://127.0.0.1:8080/login",
            "-u", "usernames.txt",
            "-p", "passwords.txt",
            "--success-str", "Authentication successful",
            "--crawl",
            "--paths", "paths.txt",
            "-o", "test_results.json"
        ]
        audit_process = subprocess.run(cmd, capture_output=True, text=True)
        
        # Verify execution
        assert audit_process.returncode == 0
        assert "SUCCESS: admin:password123" in audit_process.stdout
        assert os.path.exists("test_results.json")
        
    finally:
        # Cleanup server and test output
        server_process.terminate()
        server_process.wait()
        if os.path.exists("test_results.json"):
            os.remove("test_results.json")
