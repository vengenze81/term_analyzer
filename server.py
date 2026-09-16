from flask import Flask, request, jsonify, make_response, render_template_string, session

app = Flask(__name__)

USERS = {
    "admin": "password123"
}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return "Login Portal"
    
    data = request.get_json() if request.is_json else request.form
    username = data.get("username")
    password = data.get("password")
        
    if username in USERS and USERS[username] == password:
        resp = make_response(jsonify({"status": "success", "message": "Authentication successful"}))
        resp.set_cookie("session_id", "secret_session_token_xyz123")
        return resp, 200
    
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401

@app.route('/dashboard', methods=['GET'])
def dashboard():
    cookie = request.cookies.get("session_id")
    if cookie == "secret_session_token_xyz123":
        return jsonify({"status": "success", "page": "dashboard", "data": "Welcome to the admin dashboard!"}), 200
    return jsonify({"status": "unauthorized", "message": "Access denied"}), 403

@app.route('/admin', methods=['GET'])
def admin():
    cookie = request.cookies.get("session_id")
    if cookie == "secret_session_token_xyz123":
        return jsonify({"status": "success", "page": "admin", "data": "Confidential admin panel data."}), 200
    return jsonify({"status": "unauthorized", "message": "Access denied"}), 403

@app.route('/settings', methods=['GET'])
def settings():
    # Public or unauthenticated check
    return jsonify({"status": "public", "page": "settings"}), 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080)
