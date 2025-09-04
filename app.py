import sqlite3
import bcrypt
import jwt
import datetime
import base64
from flask import Flask, request, jsonify, g, render_template, redirect, url_for, session
from functools import wraps
import uuid
import random
import string
from config import SECRET_KEY, ADMIN_USERNAME, ADMIN_PASS

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = SECRET_KEY

# Database setup
def init_db():
    conn = sqlite3.connect('sociafam.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        real_name TEXT,
        profile_pic TEXT,
        is_admin BOOLEAN DEFAULT 0
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS recovery_keys (
        user_id INTEGER,
        recovery_key TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS stories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        image_url TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        description TEXT,
        post_image TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        views INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS friendships (
        user_id INTEGER,
        friend_id INTEGER,
        status TEXT DEFAULT 'pending',
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (friend_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS likes (
        user_id INTEGER,
        post_id INTEGER,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (post_id) REFERENCES posts(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        post_id INTEGER,
        comment_text TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (post_id) REFERENCES posts(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS saved_posts (
        user_id INTEGER,
        post_id INTEGER,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (post_id) REFERENCES posts(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        post_id INTEGER,
        type TEXT NOT NULL,
        enabled BOOLEAN DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (post_id) REFERENCES posts(id)
    )''')
    conn.commit()
    # Initialize admin user
    hashed_admin_pass = bcrypt.hashpw(ADMIN_PASS.encode('utf-8'), bcrypt.gensalt())
    c.execute('INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)',
              (ADMIN_USERNAME, hashed_admin_pass, 1))
    conn.commit()
    conn.close()

init_db()

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('sociafam.db')
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# JWT Authentication
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        try:
            data = jwt.decode(token.replace('Bearer ', ''), app.config['SECRET_KEY'], algorithms=["HS256"])
            g.user_id = data['user_id']
        except:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

# Generate recovery key
def generate_recovery_key():
    letters = ''.join(random.choices(string.ascii_letters, k=2))
    numbers = ''.join(random.choices(string.digits, k=2))
    return ''.join(random.sample(letters + numbers, 4))

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    data = request.get_json()
    identifier = data.get('identifier')
    password = data.get('password')
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ? OR email = ?', (identifier, identifier))
    user = c.fetchone()
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        token = jwt.encode({
            'user_id': user['id'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'])
        return jsonify({'token': token, 'is_admin': user['is_admin']})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if len(password) < 6 or not any(c.isalpha() for c in password) or \
       not any(c.isdigit() for c in password) or not any(not c.isalnum() for c in password):
        return jsonify({'error': 'Password must be 6+ characters with at least one letter, number, and special character'}), 400
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    recovery_key = generate_recovery_key()
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        user_id = c.lastrowid
        c.execute('INSERT INTO recovery_keys (user_id, recovery_key) VALUES (?, ?)', (user_id, recovery_key))
        conn.commit()
        return jsonify({'message': 'Registration successful', 'recovery_key': recovery_key})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template('forgot.html')
    data = request.get_json()
    username = data.get('username')
    recovery_key = data.get('unique_key')
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT u.id FROM users u JOIN recovery_keys rk ON u.id = rk.user_id WHERE u.username = ? AND rk.recovery_key = ?', (username, recovery_key))
    user = c.fetchone()
    if user:
        session['reset_user_id'] = user['id']
        return jsonify({'message': 'Verification successful'})
    return jsonify({'error': 'Invalid username or recovery key'}), 401

@app.route('/set_new_password', methods=['GET', 'POST'])
def set_new_password():
    if request.method == 'GET':
        if 'reset_user_id' not in session:
            return redirect(url_for('forgot_password'))
        return render_template('set_new.html')
    data = request.get_json()
    new_password = data.get('new_password')
    if len(new_password) < 6 or not any(c.isalpha() for c in new_password) or \
       not any(c.isdigit() for c in new_password) or not any(not c.isalnum() for c in new_password):
        return jsonify({'error': 'Password must be 6+ characters with at least one letter, number, and special character'}), 400
    user_id = session.get('reset_user_id')
    if not user_id:
        return jsonify({'error': 'Invalid session'}), 401
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, user_id))
    conn.commit()
    session.pop('reset_user_id', None)
    return jsonify({'message': 'Password updated successfully'})

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/api/stories')
@login_required
def get_stories():
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT s.id, s.user_id, s.image_url, u.username, u.profile_pic
                 FROM stories s JOIN users u ON s.user_id = u.id
                 JOIN friendships f ON f.friend_id = u.id
                 WHERE f.user_id = ? AND f.status = 'accepted'
                 AND s.created_at > datetime('now', '-24 hours')''', (g.user_id,))
    stories = c.fetchall()
    result = {}
    for story in stories:
        user_id = story['user_id']
        if user_id not in result:
            result[user_id] = {'username': story['username'], 'profilePic': story['profile_pic'] or '', 'stories': []}
        result[user_id]['stories'].append({'id': story['id'], 'imageUrl': story['image_url']})
    return jsonify(list(result.values()))

@app.route('/api/posts')
@login_required
def get_posts():
    conn = get_db()
    c = conn.cursor()
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    c.execute('''SELECT p.id, p.user_id, p.description, p.post_image, p.created_at, p.views,
                        u.username, u.real_name, u.profile_pic,
                        (p.user_id = ?) as is_owner
                 FROM posts p JOIN users u ON p.user_id = u.id
                 JOIN friendships f ON f.friend_id = u.id
                 WHERE f.user_id = ? AND f.status = 'accepted'
                 ORDER BY p.created_at DESC LIMIT ? OFFSET ?''',
              (g.user_id, g.user_id, per_page, offset))
    posts = c.fetchall()
    c.execute('SELECT COUNT(*) FROM posts p JOIN friendships f ON f.friend_id = p.user_id WHERE f.user_id = ? AND f.status = "accepted"', (g.user_id,))
    total = c.fetchone()[0]
    posts_data = [{
        'id': post['id'],
        'userId': post['user_id'],
        'username': post['username'],
        'realName': post['real_name'] or '',
        'profilePic': post['profile_pic'] or '',
        'description': post['description'],
        'postImage': post['post_image'],
        'postedDate': post['created_at'],
        'views': post['views'],
        'isOwner': bool(post['is_owner'])
    } for post in posts]
    c.execute('UPDATE posts SET views = views + 1 WHERE id IN (%s)' % ','.join('?'*len(posts)), [p['id'] for p in posts])
    conn.commit()
    return jsonify({'posts': posts_data, 'hasMore': offset + per_page < total})

@app.route('/api/posts/<int:post_id>/like', methods=['POST'])
@login_required
def like_post(post_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT OR IGNORE INTO likes (user_id, post_id) VALUES (?, ?)', (g.user_id, post_id))
    conn.commit()
    return jsonify({'message': 'Post liked'})

@app.route('/api/posts/<int:post_id>/comment', methods=['POST'])
@login_required
def comment_post(post_id):
    data = request.get_json()
    comment_text = data.get('comment_text')
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT INTO comments (user_id, post_id, comment_text) VALUES (?, ?, ?)', (g.user_id, post_id, comment_text))
    conn.commit()
    return jsonify({'message': 'Comment added'})

@app.route('/api/posts/<int:post_id>/share', methods=['POST'])
@login_required
def share_post(post_id):
    # Implement sharing logic (e.g., create a new post referencing the original)
    return jsonify({'message': 'Post shared'})

@app.route('/api/posts/<int:post_id>/save', methods=['POST'])
@login_required
def save_post(post_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT OR IGNORE INTO saved_posts (user_id, post_id) VALUES (?, ?)', (g.user_id, post_id))
    conn.commit()
    return jsonify({'message': 'Post saved'})

@app.route('/api/posts/<int:post_id>/report', methods=['POST'])
@login_required
def report_post(post_id):
    # Implement reporting logic (e.g., flag post for admin review)
    return jsonify({'message': 'Post reported'})

@app.route('/api/posts/<int:post_id>/hide', methods=['POST'])
@login_required
def hide_post(post_id):
    # Implement hiding logic (e.g., mark post as hidden for user)
    return jsonify({'message': 'Post hidden'})

@app.route('/api/posts/<int:post_id>/notifications', methods=['POST'])
@login_required
def toggle_notifications(post_id):
    conn = get_db()
    c = conn.cursor()
    data = request.get_json()
    enabled = data.get('enabled', True)
    c.execute('INSERT OR REPLACE INTO notifications (user_id, post_id, type, enabled) VALUES (?, ?, ?, ?)',
              (g.user_id, post_id, 'post', enabled))
    conn.commit()
    return jsonify({'message': 'Notifications updated'})

@app.route('/api/users/<int:user_id>/follow', methods=['POST'])
@login_required
def follow_user(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT OR IGNORE INTO friendships (user_id, friend_id, status) VALUES (?, ?, ?)',
              (g.user_id, user_id, 'pending'))
    conn.commit()
    return jsonify({'message': 'Follow request sent'})

@app.route('/api/users/<int:user_id>/block', methods=['POST'])
@login_required
def block_user(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM friendships WHERE user_id = ? AND friend_id = ? OR user_id = ? AND friend_id = ?',
              (g.user_id, user_id, user_id, g.user_id))
    conn.commit()
    return jsonify({'message': 'User blocked'})

@app.route('/api/is_admin')
@login_required
def is_admin():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT is_admin FROM users WHERE id = ?', (g.user_id,))
    user = c.fetchone()
    return jsonify({'is_admin': bool(user['is_admin'])})

if __name__ == '__main__':
    app.run(debug=True)
