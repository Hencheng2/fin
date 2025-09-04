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
        biography TEXT,
        dob_day INTEGER,
        dob_month INTEGER,
        dob_year INTEGER,
        gender TEXT,
        pronouns TEXT,
        work_info TEXT,
        university TEXT,
        secondary_school TEXT,
        other_education TEXT,
        location TEXT,
        phone_number TEXT,
        social_link TEXT,
        website_link TEXT,
        other_contact TEXT,
        relationship_status TEXT,
        partner_username TEXT,
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
        is_locked BOOLEAN DEFAULT 0,
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
    c.execute('''CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        profile_pic TEXT,
        creator_id INTEGER,
        description TEXT,
        group_link TEXT UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (creator_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS group_members (
        group_id INTEGER,
        user_id INTEGER,
        is_admin BOOLEAN DEFAULT 0,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (group_id) REFERENCES groups(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS group_permissions (
        group_id INTEGER,
        allow_non_admin_edit BOOLEAN DEFAULT 0,
        allow_non_admin_messages BOOLEAN DEFAULT 1,
        allow_non_admin_add_members BOOLEAN DEFAULT 1,
        require_approval BOOLEAN DEFAULT 0,
        FOREIGN KEY (group_id) REFERENCES groups(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS group_media (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER,
        user_id INTEGER,
        media_url TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (group_id) REFERENCES groups(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS group_links (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER,
        user_id INTEGER,
        link_url TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (group_id) REFERENCES groups(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS group_documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER,
        user_id INTEGER,
        document_url TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (group_id) REFERENCES groups(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS reposts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        original_post_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (original_post_id) REFERENCES posts(id)
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

# Generate group link
def generate_group_link():
    return str(uuid.uuid4())

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

@app.route('/my_profile')
@login_required
def my_profile():
    return render_template('my_profile.html')

@app.route('/api/my_profile')
@login_required
def get_my_profile():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (g.user_id,))
    user = c.fetchone()
    c.execute('SELECT COUNT(*) FROM friendships WHERE user_id = ? AND status = "accepted"', (g.user_id,))
    friends_count = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM friendships WHERE friend_id = ? AND status = "accepted"', (g.user_id,))
    followers_count = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM friendships WHERE user_id = ? AND status = "accepted"', (g.user_id,))
    following_count = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM likes WHERE user_id = ?', (g.user_id,))
    likes_count = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM posts WHERE user_id = ?', (g.user_id,))
    posts_count = c.fetchone()[0]
    c.execute('SELECT recovery_key FROM recovery_keys WHERE user_id = ?', (g.user_id,))
    recovery_key = c.fetchone()['recovery_key']
    profile_data = {
        'real_name': user['real_name'] or '',
        'username': user['username'],
        'profile_pic': user['profile_pic'] or '',
        'biography': user['biography'] or '',
        'unique_key': recovery_key,
        'friends_count': friends_count,
        'followers_count': followers_count,
        'following_count': following_count,
        'likes_count': likes_count,
        'posts_count': posts_count,
        'user_info': {
            'date_of_birth': f"{user['dob_day'] or ''}/{user['dob_month'] or ''}/{user['dob_year'] or ''}",
            'gender': user['gender'] or '',
            'pronouns': user['pronouns'] or '',
            'work_info': user['work_info'] or '',
            'university': user['university'] or '',
            'secondary_school': user['secondary_school'] or '',
            'other_education': user['other_education'] or '',
            'location': user['location'] or '',
            'phone_number': user['phone_number'] or '',
            'email': user['email'] or '',
            'social_link': user['social_link'] or '',
            'website_link': user['website_link'] or '',
            'other_contact': user['other_contact'] or '',
            'relationship_status': user['relationship_status'] or '',
            'partner_username': user['partner_username'] or ''
        }
    }
    return jsonify(profile_data)

@app.route('/api/my_profile/posts')
@login_required
def get_my_posts():
    conn = get_db()
    c = conn.cursor()
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    c.execute('''SELECT p.id, p.description, p.post_image, p.created_at, p.views
                 FROM posts p WHERE p.user_id = ? AND p.is_locked = 0
                 ORDER BY p.created_at DESC LIMIT ? OFFSET ?''',
              (g.user_id, per_page, offset))
    posts = c.fetchall()
    posts_data = [{
        'id': post['id'],
        'description': post['description'],
        'post_image': post['post_image'],
        'created_at': post['created_at'],
        'views': post['views']
    } for post in posts]
    return jsonify({'posts': posts_data})

@app.route('/api/my_profile/locked_posts')
@login_required
def get_locked_posts():
    conn = get_db()
    c = conn.cursor()
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    c.execute('''SELECT p.id, p.description, p.post_image, p.created_at, p.views
                 FROM posts p WHERE p.user_id = ? AND p.is_locked = 1
                 ORDER BY p.created_at DESC LIMIT ? OFFSET ?''',
              (g.user_id, per_page, offset))
    posts = c.fetchall()
    posts_data = [{
        'id': post['id'],
        'description': post['description'],
        'post_image': post['post_image'],
        'created_at': post['created_at'],
        'views': post['views']
    } for post in posts]
    return jsonify({'posts': posts_data})

@app.route('/api/my_profile/saved')
@login_required
def get_saved_posts():
    conn = get_db()
    c = conn.cursor()
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    c.execute('''SELECT p.id, p.description, p.post_image, p.created_at, p.views
                 FROM posts p JOIN saved_posts sp ON p.id = sp.post_id
                 WHERE sp.user_id = ? ORDER BY p.created_at DESC LIMIT ? OFFSET ?''',
              (g.user_id, per_page, offset))
    posts = c.fetchall()
    posts_data = [{
        'id': post['id'],
        'description': post['description'],
        'post_image': post['post_image'],
        'created_at': post['created_at'],
        'views': post['views']
    } for post in posts]
    return jsonify({'posts': posts_data})

@app.route('/api/my_profile/reposts')
@login_required
def get_reposts():
    conn = get_db()
    c = conn.cursor()
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    c.execute('''SELECT p.id, p.description, p.post_image, p.created_at, p.views
                 FROM posts p JOIN reposts r ON p.id = r.original_post_id
                 WHERE r.user_id = ? ORDER BY r.created_at DESC LIMIT ? OFFSET ?''',
              (g.user_id, per_page, offset))
    posts = c.fetchall()
    posts_data = [{
        'id': post['id'],
        'description': post['description'],
        'post_image': post['post_image'],
        'created_at': post['created_at'],
        'views': post['views']
    } for post in posts]
    return jsonify({'posts': posts_data})

@app.route('/api/my_profile/liked')
@login_required
def get_liked_posts():
    conn = get_db()
    c = conn.cursor()
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    c.execute('''SELECT p.id, p.description, p.post_image, p.created_at, p.views
                 FROM posts p JOIN likes l ON p.id = l.post_id
                 WHERE l.user_id = ? ORDER BY p.created_at DESC LIMIT ? OFFSET ?''',
              (g.user_id, per_page, offset))
    posts = c.fetchall()
    posts_data = [{
        'id': post['id'],
        'description': post['description'],
        'post_image': post['post_image'],
        'created_at': post['created_at'],
        'views': post['views']
    } for post in posts]
    return jsonify({'posts': posts_data})

@app.route('/api/my_profile/reels')
@login_required
def get_reels():
    conn = get_db()
    c = conn.cursor()
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    c.execute('''SELECT p.id, p.description, p.post_image, p.created_at, p.views
                 FROM posts p WHERE p.user_id = ? AND p.post_image LIKE '%.mp4'
                 ORDER BY p.created_at DESC LIMIT ? OFFSET ?''',
              (g.user_id, per_page, offset))
    reels = c.fetchall()
    reels_data = [{
        'id': reel['id'],
        'description': reel['description'],
        'post_image': reel['post_image'],
        'created_at': reel['created_at'],
        'views': reel['views']
    } for reel in reels]
    return jsonify({'reels': reels_data})

@app.route('/api/my_profile/update_profile_pic', methods=['POST'])
@login_required
def update_profile_pic():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    file = request.files['file']
    if file:
        profile_pic = base64.b64encode(file.read()).decode('utf-8')
        conn = get_db()
        c = conn.cursor()
        c.execute('UPDATE users SET profile_pic = ? WHERE id = ?', (profile_pic, g.user_id))
        conn.commit()
        return jsonify({'message': 'Profile picture updated'})
    return jsonify({'error': 'Invalid file'}), 400

@app.route('/api/my_profile/share', methods=['POST'])
@login_required
def share_profile():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT username FROM users WHERE id = ?', (g.user_id,))
    username = c.fetchone()['username']
    profile_link = f"https://sociafam.com/profile/{username}"
    c.execute('SELECT u.id, u.username FROM users u JOIN friendships f ON f.friend_id = u.id WHERE f.user_id = ? AND f.status = "accepted"', (g.user_id,))
    friends = [{'id': friend['id'], 'username': friend['username']} for friend in c.fetchall()]
    return jsonify({'profile_link': profile_link, 'friends': friends})

@app.route('/other_profile/<username>')
@login_required
def other_profile(username):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    if not user:
        return redirect(url_for('home'))
    return render_template('other_profile.html', username=username)

@app.route('/api/other_profile/<username>')
@login_required
def get_other_profile(username):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    c.execute('SELECT COUNT(*) FROM friendships WHERE user_id = ? AND status = "accepted"', (user['id'],))
    friends_count = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM friendships WHERE friend_id = ? AND status = "accepted"', (user['id'],))
    followers_count = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM friendships WHERE user_id = ? AND status = "accepted"', (user['id'],))
    following_count = c.fetchone()[0]
    c.execute('''SELECT u.id, u.username FROM users u
                 JOIN friendships f1 ON f1.friend_id = u.id
                 JOIN friendships f2 ON f2.friend_id = u.id
                 WHERE f1.user_id = ? AND f2.user_id = ? AND f1.status = "accepted" AND f2.status = "accepted"
                 LIMIT 3''', (g.user_id, user['id']))
    mutual_friends = [{'id': friend['id'], 'username': friend['username']} for friend in c.fetchall()]
    profile_data = {
        'real_name': user['real_name'] or '',
        'username': user['username'],
        'profile_pic': user['profile_pic'] or '',
        'biography': user['biography'] or '',
        'friends_count': friends_count,
        'followers_count': followers_count,
        'following_count': following_count,
        'mutual_friends': mutual_friends
    }
    return jsonify(profile_data)

@app.route('/api/other_profile/<username>/posts')
@login_required
def get_other_posts(username):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    c.execute('''SELECT p.id, p.description, p.post_image, p.created_at, p.views
                 FROM posts p WHERE p.user_id = ? AND p.is_locked = 0
                 ORDER BY p.created_at DESC LIMIT ? OFFSET ?''',
              (user['id'], per_page, offset))
    posts = c.fetchall()
    posts_data = [{
        'id': post['id'],
        'description': post['description'],
        'post_image': post['post_image'],
        'created_at': post['created_at'],
        'views': post['views']
    } for post in posts]
    return jsonify({'posts': posts_data})

@app.route('/api/other_profile/<username>/reels')
@login_required
def get_other_reels(username):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    c.execute('''SELECT p.id, p.description, p.post_image, p.created_at, p.views
                 FROM posts p WHERE p.user_id = ? AND p.post_image LIKE '%.mp4' AND p.is_locked = 0
                 ORDER BY p.created_at DESC LIMIT ? OFFSET ?''',
              (user['id'], per_page, offset))
    reels = c.fetchall()
    reels_data = [{
        'id': reel['id'],
        'description': reel['description'],
        'post_image': reel['post_image'],
        'created_at': reel['created_at'],
        'views': reel['views']
    } for reel in reels]
    return jsonify({'reels': reels_data})

@app.route('/group_profile/<group_link>')
@login_required
def group_profile(group_link):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id FROM groups WHERE group_link = ?', (group_link,))
    group = c.fetchone()
    if not group:
        return redirect(url_for('home'))
    return render_template('group_profile.html', group_link=group_link)

@app.route('/api/group_profile/<group_link>')
@login_required
def get_group_profile(group_link):
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT g.*, u.username as creator_name
                 FROM groups g JOIN users u ON g.creator_id = u.id
                 WHERE g.group_link = ?''', (group_link,))
    group = c.fetchone()
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    c.execute('SELECT COUNT(*) FROM group_members WHERE group_id = ?', (group['id'],))
    members_count = c.fetchone()[0]
    c.execute('SELECT is_admin FROM group_members WHERE group_id = ? AND user_id = ?', (group['id'], g.user_id))
    is_admin = c.fetchone()['is_admin'] if c.fetchone() else False
    c.execute('SELECT * FROM group_permissions WHERE group_id = ?', (group['id'],))
    permissions = c.fetchone()
    group_data = {
        'name': group['name'],
        'profile_pic': group['profile_pic'] or '',
        'description': group['description'] or '',
        'group_link': group['group_link'],
        'creator_name': group['creator_name'],
        'created_at': group['created_at'],
        'members_count': members_count,
        'is_admin': is_admin,
        'permissions': {
            'allow_non_admin_edit': permissions['allow_non_admin_edit'],
            'allow_non_admin_messages': permissions['allow_non_admin_messages'],
            'allow_non_admin_add_members': permissions['allow_non_admin_add_members'],
            'require_approval': permissions['require_approval']
        }
    }
    return jsonify(group_data)

@app.route('/api/group_profile/<group_link>/media')
@login_required
def get_group_media(group_link):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id FROM groups WHERE group_link = ?', (group_link,))
    group = c.fetchone()
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    c.execute('''SELECT gm.id, gm.media_url, gm.created_at, u.username
                 FROM group_media gm JOIN users u ON gm.user_id = u.id
                 WHERE gm.group_id = ? ORDER BY gm.created_at DESC LIMIT ? OFFSET ?''',
              (group['id'], per_page, offset))
    media = c.fetchall()
    media_data = [{
        'id': item['id'],
        'media_url': item['media_url'],
        'created_at': item['created_at'],
        'username': item['username']
    } for item in media]
    return jsonify({'media': media_data})

@app.route('/api/group_profile/<group_link>/links')
@login_required
def get_group_links(group_link):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id FROM groups WHERE group_link = ?', (group_link,))
    group = c.fetchone()
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    c.execute('''SELECT gl.id, gl.link_url, gl.created_at, u.username
                 FROM group_links gl JOIN users u ON gl.user_id = u.id
                 WHERE gl.group_id = ? ORDER BY gl.created_at DESC LIMIT ? OFFSET ?''',
              (group['id'], per_page, offset))
    links = c.fetchall()
    links_data = [{
        'id': item['id'],
        'link_url': item['link_url'],
        'created_at': item['created_at'],
        'username': item['username']
    } for item in links]
    return jsonify({'links': links_data})

@app.route('/api/group_profile/<group_link>/documents')
@login_required
def get_group_documents(group_link):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id FROM groups WHERE group_link = ?', (group_link,))
    group = c.fetchone()
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    c.execute('''SELECT gd.id, gd.document_url, gd.created_at, u.username
                 FROM group_documents gd JOIN users u ON gd.user_id = u.id
                 WHERE gd.group_id = ? ORDER BY gd.created_at DESC LIMIT ? OFFSET ?''',
              (group['id'], per_page, offset))
    documents = c.fetchall()
    documents_data = [{
        'id': item['id'],
        'document_url': item['document_url'],
        'created_at': item['created_at'],
        'username': item['username']
    } for item in documents]
    return jsonify({'documents': documents_data})

@app.route('/api/group_profile/<group_link>/members')
@login_required
def get_group_members(group_link):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id FROM groups WHERE group_link = ?', (group_link,))
    group = c.fetchone()
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    c.execute('''SELECT u.id, u.username, u.profile_pic, gm.is_admin
                 FROM group_members gm JOIN users u ON gm.user_id = u.id
                 WHERE gm.group_id = ? ORDER BY gm.joined_at DESC LIMIT ? OFFSET ?''',
              (group['id'], per_page, offset))
    members = c.fetchall()
    members_data = [{
        'id': member['id'],
        'username': member['username'],
        'profile_pic': member['profile_pic'] or '',
        'is_admin': member['is_admin']
    } for member in members]
    c.execute('SELECT COUNT(*) FROM group_members WHERE group_id = ?', (group['id'],))
    total_members = c.fetchone()[0]
    return jsonify({'members': members_data, 'has_more': offset + per_page < total_members})

@app.route('/api/group_profile/<group_link>/add_members', methods=['POST'])
@login_required
def add_group_members(group_link):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id FROM groups WHERE group_link = ?', (group_link,))
    group = c.fetchone()
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    c.execute('SELECT is_admin, user_id FROM group_members WHERE group_id = ? AND user_id = ?', (group['id'], g.user_id))
    member = c.fetchone()
    if not member or not member['is_admin']:
        c.execute('SELECT allow_non_admin_add_members FROM group_permissions WHERE group_id = ?', (group['id'],))
        if not c.fetchone()['allow_non_admin_add_members']:
            return jsonify({'error': 'Permission denied'}), 403
    data = request.get_json()
    member_ids = data.get('member_ids', [])
    for member_id in member_ids:
        c.execute('INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)', (group['id'], member_id))
    conn.commit()
    return jsonify({'message': 'Members added'})

@app.route('/api/group_profile/<group_link>/remove_member/<int:user_id>', methods=['POST'])
@login_required
def remove_group_member(group_link, user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, creator_id FROM groups WHERE group_link = ?', (group_link,))
    group = c.fetchone()
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    if user_id == group['creator_id']:
        return jsonify({'error': 'Cannot remove group creator'}), 403
    c.execute('SELECT is_admin FROM group_members WHERE group_id = ? AND user_id = ?', (group['id'], g.user_id))
    member = c.fetchone()
    if not member or not member['is_admin']:
        return jsonify({'error': 'Permission denied'}), 403
    c.execute('DELETE FROM group_members WHERE group_id = ? AND user_id = ?', (group['id'], user_id))
    conn.commit()
    return jsonify({'message': 'Member removed'})

@app.route('/api/group_profile/<group_link>/exit', methods=['POST'])
@login_required
def exit_group(group_link):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, creator_id FROM groups WHERE group_link = ?', (group_link,))
    group = c.fetchone()
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    if group['creator_id'] == g.user_id:
        c.execute('SELECT user_id FROM group_members WHERE group_id = ? AND is_admin = 1 AND user_id != ?', (group['id'], g.user_id))
        other_admins = c.fetchall()
        if other_admins:
            new_creator = other_admins[0]['user_id']
            c.execute('UPDATE groups SET creator_id = ? WHERE id = ?', (new_creator, group['id']))
        else:
            c.execute('SELECT user_id FROM group_members WHERE group_id = ? AND user_id != ?', (group['id'], g.user_id))
            other_members = c.fetchall()
            if other_members:
                new_creator = other_members[0]['user_id']
                c.execute('UPDATE groups SET creator_id = ? WHERE id = ?', (new_creator, group['id']))
                c.execute('UPDATE group_members SET is_admin = 1 WHERE group_id = ? AND user_id = ?', (group['id'], new_creator))
            else:
                c.execute('DELETE FROM groups WHERE id = ?', (group['id']))
    c.execute('DELETE FROM group_members WHERE group_id = ? AND user_id = ?', (group['id'], g.user_id))
    conn.commit()
    return jsonify({'message': 'Exited group'})

@app.route('/api/group_profile/<group_link>/report_exit', methods=['POST'])
@login_required
def report_and_exit_group(group_link):
    # Implement reporting logic (e.g., flag group for admin review)
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, creator_id FROM groups WHERE group_link = ?', (group_link,))
    group = c.fetchone()
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    # Placeholder for reporting logic
    if group['creator_id'] == g.user_id:
        c.execute('SELECT user_id FROM group_members WHERE group_id = ? AND is_admin = 1 AND user_id != ?', (group['id'], g.user_id))
        other_admins = c.fetchall()
        if other_admins:
            new_creator = other_admins[0]['user_id']
            c.execute('UPDATE groups SET creator_id = ? WHERE id = ?', (new_creator, group['id']))
        else:
            c.execute('SELECT user_id FROM group_members WHERE group_id = ? AND user_id != ?', (group['id'], g.user_id))
            other_members = c.fetchall()
            if other_members:
                new_creator = other_members[0]['user_id']
                c.execute('UPDATE groups SET creator_id = ? WHERE id = ?', (new_creator, group['id']))
                c.execute('UPDATE group_members SET is_admin = 1 WHERE group_id = ? AND user_id = ?', (group['id'], new_creator))
            else:
                c.execute('DELETE FROM groups WHERE id = ?', (group['id']))
    c.execute('DELETE FROM group_members WHERE group_id = ? AND user_id = ?', (group['id'], g.user_id))
    conn.commit()
    return jsonify({'message': 'Reported and exited group'})

@app.route('/edit_profile')
@login_required
def edit_profile():
    return render_template('edit_profile.html')

@app.route('/api/edit_profile', methods=['POST'])
@login_required
def update_profile():
    data = request.get_json()
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute('''UPDATE users SET
                     username = ?, biography = ?, dob_day = ?, dob_month = ?, dob_year = ?,
                     gender = ?, pronouns = ?, work_info = ?, university = ?, secondary_school = ?,
                     other_education = ?, location = ?, phone_number = ?, email = ?,
                     social_link = ?, website_link = ?, other_contact = ?, relationship_status = ?,
                     partner_username = ?
                     WHERE id = ?''',
                  (data.get('username'), data.get('biography'), data.get('dob_day'), data.get('dob_month'),
                   data.get('dob_year'), data.get('gender'), data.get('pronouns'), data.get('work_info'),
                   data.get('education_university'), data.get('education_secondary'), data.get('education_other'),
                   data.get('location'), data.get('phone'), data.get('email'), data.get('social'),
                   data.get('website'), data.get('other_contact'), data.get('relationship'),
                   data.get('partner'), g.user_id))
        conn.commit()
        return jsonify({'message': 'Profile updated'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400

@app.route('/create_group')
@login_required
def create_group():
    return render_template('create_group.html')

@app.route('/api/create_group', methods=['POST'])
@login_required
def api_create_group():
    data = request.get_json()
    group_name = data.get('group_name')
    edit_permissions = data.get('edit_permissions') == 'allow'
    message_permissions = data.get('message_permissions') == 'allow'
    add_member_permissions = data.get('add_member_permissions') == 'allow'
    member_ids = data.get('member_ids', [])
    profile_pic = data.get('profile_pic')
    if not group_name:
        return jsonify({'error': 'Group name is required'}), 400
    if not member_ids:
        return jsonify({'error': 'At least one member is required'}), 400
    group_link = generate_group_link()
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT INTO groups (name, profile_pic, creator_id, group_link, description) VALUES (?, ?, ?, ?, ?)',
              (group_name, profile_pic, g.user_id, group_link, data.get('description')))
    group_id = c.lastrowid
    c.execute('INSERT INTO group_permissions (group_id, allow_non_admin_edit, allow_non_admin_messages, allow_non_admin_add_members, require_approval) VALUES (?, ?, ?, ?, ?)',
              (group_id, edit_permissions, message_permissions, add_member_permissions, False))
    c.execute('INSERT INTO group_members (group_id, user_id, is_admin) VALUES (?, ?, ?)', (group_id, g.user_id, True))
    for member_id in member_ids:
        c.execute('INSERT INTO group_members (group_id, user_id) VALUES (?, ?)', (group_id, member_id))
    conn.commit()
    return jsonify({'message': 'Group created', 'group_link': group_link})

@app.route('/edit_group/<group_link>')
@login_required
def edit_group(group_link):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id FROM groups WHERE group_link = ?', (group_link,))
    group = c.fetchone()
    if not group:
        return redirect(url_for('home'))
    c.execute('SELECT is_admin FROM group_members WHERE group_id = ? AND user_id = ?', (group['id'], g.user_id))
    member = c.fetchone()
    if not member or not member['is_admin']:
        c.execute('SELECT allow_non_admin_edit FROM group_permissions WHERE group_id = ?', (group['id'],))
        if not c.fetchone()['allow_non_admin_edit']:
            return redirect(url_for('group_profile', group_link=group_link))
    return render_template('edit_group.html', group_link=group_link)

@app.route('/api/edit_group/<group_link>', methods=['POST'])
@login_required
def api_edit_group(group_link):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id FROM groups WHERE group_link = ?', (group_link,))
    group = c.fetchone()
    if not group:
        return jsonify({'error': 'Group not found'}), 404
    c.execute('SELECT is_admin FROM group_members WHERE group_id = ? AND user_id = ?', (group['id'], g.user_id))
    member = c.fetchone()
    if not member or not member['is_admin']:
        c.execute('SELECT allow_non_admin_edit FROM group_permissions WHERE group_id = ?', (group['id'],))
        if not c.fetchone()['allow_non_admin_edit']:
            return jsonify({'error': 'Permission denied'}), 403
    data = request.get_json()
    group_name = data.get('group_name')
    profile_pic = data.get('profile_pic')
    edit_permissions = data.get('edit_permissions') == 'allow'
    message_permissions = data.get('message_permissions') == 'allow'
    add_member_permissions = data.get('add_member_permissions') == 'allow'
    c.execute('UPDATE groups SET name = ?, profile_pic = ? WHERE id = ?', (group_name, profile_pic, group['id']))
    c.execute('UPDATE group_permissions SET allow_non_admin_edit = ?, allow_non_admin_messages = ?, allow_non_admin_add_members = ? WHERE group_id = ?',
              (edit_permissions, message_permissions, add_member_permissions, group['id']))
    conn.commit()
    return jsonify({'message': 'Group updated'})

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
                 WHERE f.user_id = ? AND f.status = 'accepted' AND p.is_locked = 0
                 ORDER BY p.created_at DESC LIMIT ? OFFSET ?''',
              (g.user_id, g.user_id, per_page, offset))
    posts = c.fetchall()
    c.execute('SELECT COUNT(*) FROM posts p JOIN friendships f ON f.friend_id = p.user_id WHERE f.user_id = ? AND f.status = "accepted" AND p.is_locked = 0', (g.user_id,))
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
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT INTO reposts (user_id, original_post_id) VALUES (?, ?)', (g.user_id, post_id))
    conn.commit()
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
