from flask import Flask, request, jsonify, make_response, render_template_string

app = Flask(__name__)

USERS = {
    "admin": "password123"
}

LOGIN_TEMPLATE = """
<!doctype html>
<html>
<head><title>Login Test Target</title></head>
<body>
    <h2>Login Portal</h2>
    <form method="POST" action="/login">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
"""

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template_string(LOGIN_TEMPLATE)
    
    if request.is_json:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        
    if username in USERS and USERS[username] == password:
        resp = make_response(jsonify({"status": "success", "message": "Authentication successful"}))
        resp.set_cookie("session_id", "secret_session_token_xyz123")
        return resp, 200
    
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080)
