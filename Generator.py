from http.server import BaseHTTPRequestHandler, HTTPServer
import sqlite3
import datetime
import urllib.parse
import bcrypt

def db_create():
    con_db = sqlite3.connect('DATA.db')
    cursor = con_db.cursor()
    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS users(
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_last_name TEXT NOT NULL,
            user_first_name TEXT NOT NULL,
            user_email TEXT NOT NULL UNIQUE,
            user_password TEXT NOT NULL,
            user_created_at TEXT,
            user_roles INTEGER DEFAULT 0,
            user_valid INTEGER
        );
        CREATE TABLE IF NOT EXISTS logs(
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_user_id INTEGER NOT NULL,
            log_at TEXT,
            FOREIGN KEY (log_user_id) REFERENCES users(user_id)
        );
    ''')
    con_db.commit()
    con_db.close()

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        if path == '/':
            self.serve_global_list()
        elif path == '/auth.html':
            self.serve_page('templates/auth.html')
        elif path == '/admin-page.html':
            self.serve_admin_page()
        elif path == '/modify.html':
            self.serve_page('templates/modify.html')
        elif path == '/add-user.html':
            self.serve_page('templates/add-user.html')
        elif path == '/add-admin.html':
            self.serve_page('templates/add-admin.html')
        elif path.startswith('/verify'):
            self.serve_verify_page()
        elif path.startswith('/user-page.html'):
            user_id = self.get_user_id_from_request()
            self.serve_user_page(user_id)

    def do_POST(self):
        if self.path == '/auth':
            self.handle_auth()
        elif self.path == '/add-user':
            self.handle_add_user()
        elif self.path == '/add-admin':
            self.handle_add_admin()
        elif self.path == '/modify':
            self.handle_modify()

    def get_user_id_from_request(self):
        cookies = self.headers.get('Cookie')
        if cookies:
            for cookie in cookies.split(';'):
                if 'user_id=' in cookie:
                    return int(cookie.split('=')[1])
        return None

    def serve_page(self, template_path, user_data=None, log_data=None):
        with open(template_path, 'r') as file:
            html_template = file.read()
        if user_data:
            user_name = ''.join(f'<h1>{emp[0]} {emp[1]}</h1>' for emp in user_data)
            html_template = html_template.replace("<!-- USER_NAMES -->", user_name)
        if log_data:
            user_rows = ''.join(f'''
            <tr>
                <td>{log[0]}</td>
                <td>{log[1]}</td>
            </tr>
            ''' for log in log_data)
            html_template = html_template.replace("<!-- DATA_ROWS -->", user_rows)
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html_template.encode())

    def serve_global_list(self):
        conn = sqlite3.connect('DATA.db')
        cursor = conn.cursor()
        cursor.execute("SELECT ROWID, user_last_name, user_first_name, user_email FROM users")
        global_list = cursor.fetchall()
        conn.close()
        with open('templates/index.html', 'r') as file:
            html_template = file.read()
        global_rows = ''.join(f'''
        <tr>
            <td>{emp[0]}</td>
            <td>{emp[1]}</td>
            <td>{emp[2]}</td>
            <td>{emp[3]}</td>
        </tr>
        ''' for emp in global_list)
        html = html_template.replace("<!-- DATA_ROWS -->", global_rows)
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def serve_user_page(self, user_id):
        conn = sqlite3.connect('DATA.db')
        cursor = conn.cursor()
        cursor.execute('SELECT user_first_name, user_last_name FROM users WHERE user_id = ?', (user_id,))
        user = cursor.fetchall()
        cursor.execute('SELECT logs.ROWID, logs.log_at FROM logs WHERE logs.log_user_id = ? ORDER BY log_at', (user_id,))
        logs = cursor.fetchall()
        conn.close()
        self.serve_page('templates/user-page.html', user, logs)

    def serve_admin_page(self):
        conn = sqlite3.connect('DATA.db')
        cursor = conn.cursor()
        cursor.execute('''SELECT logs.ROWID, users.user_last_name, users.user_first_name, users.user_email, logs.log_at, users.user_id
                        FROM users
                        JOIN logs ON logs.log_user_id = users.user_id
                        WHERE DATE(logs.log_at) = DATE('now');
                    ''')
        admin_list = cursor.fetchall()
        conn.close()
        with open('templates/admin-page.html', 'r') as file:
            html_template = file.read()
        admin_rows = ''.join(f'''
        <tr>
            <td>{emp[0]}</td>
            <td>{emp[1]}</td>
            <td>{emp[2]}</td>
            <td>{emp[3]}</td>
            <td>{emp[4]}</td>
            <td><a href="/verify?user_id={emp[5]}" class="button"><button type="submit">Vérifier</button></a></td>
        </tr>
        ''' for emp in admin_list)
        html = html_template.replace("<!-- DATA_ROWS -->", admin_rows)
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def serve_verify_page(self):
        query_components = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        user_id = query_components.get('user_id', [None])[0]
        conn = sqlite3.connect('DATA.db')
        cursor = conn.cursor()
        cursor.execute('SELECT logs.ROWID, logs.log_at FROM logs WHERE logs.log_user_id = ? ORDER BY log_at', (user_id,))
        logs = cursor.fetchall()
        conn.close()
        with open('templates/verify.html', 'r') as file:
            html_template = file.read()
        verify_rows = ''.join(f'''
        <tr>
            <td>{log[0]}</td>
            <td>{log[1]}</td>
        </tr>
        ''' for log in logs)
        html_content = html_template.replace("<!-- DATA_ROWS -->", verify_rows)
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode())

    def handle_auth(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        post_data = urllib.parse.parse_qs(post_data.decode())
        email = post_data.get('email', [''])[0]
        password = post_data.get('password', [''])[0]
        if not email or not password:
            self.send_response(400)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'Email and password are required.')
            return
        conn = sqlite3.connect('DATA.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT user_id, user_password, user_valid, user_roles
            FROM users
            WHERE user_email = ?
        ''', (email,))
        user = cursor.fetchone()
        if user and bcrypt.checkpw(password.encode(), user[1].encode()):
            user_id = user[0]
            today = datetime.datetime.now().date()
            now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute('''
                SELECT COUNT(*) FROM logs
                WHERE log_user_id = ? AND DATE(log_at) = ?
            ''', (user_id, today))
            if cursor.fetchone()[0] == 0:
                cursor.execute('INSERT INTO logs (log_user_id, log_at) VALUES (?, ?)', (user_id, now))
                conn.commit()
            self.send_response(302)
            if user[3] == 1:
                self.send_header('Location', '/admin-page.html')
            else:
                self.send_header('Location', f'/user-page.html?user_id={user_id}')
            self.send_header('Set-Cookie', f'user_id={user_id}')
            self.end_headers()
        else:
            self.send_response(401)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'Invalid email or password.')
        conn.close()

    def handle_add_user(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        post_data = urllib.parse.parse_qs(post_data.decode())
        user_last_name = post_data.get('user_last_name', [''])[0]
        user_first_name = post_data.get('user_first_name', [''])[0]
        user_email = post_data.get('user_email', [''])[0]
        user_password = post_data.get('user_password', [''])[0]
        if not user_last_name or not user_first_name or not user_email or not user_password:
            self.send_response(400)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'All fields are required.')
            return
        hashed_password = bcrypt.hashpw(user_password.encode(), bcrypt.gensalt())
        conn = sqlite3.connect('DATA.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (user_last_name, user_first_name, user_email, user_password, user_created_at, user_roles, user_valid)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_last_name, user_first_name, user_email, hashed_password.decode(), datetime.datetime.now(), 0, 1))
        conn.commit()
        conn.close()
        self.send_response(302)
        self.send_header('Location', '/')
        self.end_headers()

    def handle_add_admin(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        post_data = urllib.parse.parse_qs(post_data.decode())
        user_last_name = post_data.get('user_last_name', [''])[0]
        user_first_name = post_data.get('user_first_name', [''])[0]
        user_email = post_data.get('user_email', [''])[0]
        user_password = post_data.get('user_password', [''])[0]
        if not user_last_name or not user_first_name or not user_email or not user_password:
            self.send_response(400)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'All fields are required.')
            return
        hashed_password = bcrypt.hashpw(user_password.encode(), bcrypt.gensalt())
        conn = sqlite3.connect('DATA.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (user_last_name, user_first_name, user_email, user_password, user_created_at, user_roles, user_valid)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_last_name, user_first_name, user_email, hashed_password.decode(), datetime.datetime.now(), 1, 1))
        conn.commit()
        conn.close()
        self.send_response(302)
        self.send_header('Location', '/')
        self.end_headers()

if __name__ == "__main__":
    db_create()
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, RequestHandler)
    print("Starting httpd server on port 8000")
    httpd.serve_forever()
