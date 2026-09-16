from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class MockServer(BaseHTTPRequestHandler):
    request_count = 0

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        params = urllib.parse.parse_qs(body)
        
        username = params.get('username', [''])[0]
        password = params.get('password', [''])[0]

        MockServer.request_count += 1
        
        # Trigger an intentional rate limit every 5 requests to test --smart-pause
        if MockServer.request_count % 5 == 0:
            self.send_response(429)
            self.end_headers()
            self.wfile.write(b"Rate limited! Too many requests.")
            return

        if username == "admin" and password == "secret123":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Login successful! Welcome admin. SECRET_TOKEN: jwt_eyJhbGciOiJIUzI1NiJ9...")
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Invalid username or password.")

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        query = urllib.parse.parse_qs(parsed_path.query)

        if path in ["/dashboard", "/admin"]:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"Protected page {path}. API_KEY=sk_live_987654321ABC".encode())
        elif path == "/search":
            q = query.get('q', [''])[0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"Search results for query: {q}. Found 0 items.".encode())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format, *args):
        # Suppress default noisy logs to keep the terminal clean
        return

if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8080), MockServer)
    print("[*] Mock test server started on http://127.0.0.1:8080")
    server.serve_forever()
