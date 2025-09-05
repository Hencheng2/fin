import os
import sqlite3
import uuid
import json
import datetime
import random
import string
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_from_directory
import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database initialization
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  email TEXT,
                  unique_key TEXT NOT NULL,
                  profile_pic TEXT DEFAULT 'default_profile.jpg',
                  real_name TEXT,
                  biography TEXT,
                  date_of_birth TEXT,
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
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Posts table
    c.execute('''CREATE TABLE IF NOT EXISTS posts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  description TEXT,
                  image_url TEXT,
                  video_url TEXT,
                  views INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  is_locked BOOLEAN DEFAULT 0,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Stories table
    c.execute('''CREATE TABLE IF NOT EXISTS stories
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  image_url TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  expires_at TIMESTAMP DEFAULT (datetime('now', '+24 hours')),
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Likes table
    c.execute('''CREATE TABLE IF NOT EXISTS likes
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  post_id INTEGER NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  FOREIGN KEY (post_id) REFERENCES posts (id))''')
    
    # Comments table
    c.execute('''CREATE TABLE IF NOT EXISTS comments
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  post_id INTEGER NOT NULL,
                  comment TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  FOREIGN KEY (post_id) REFERENCES posts (id))''')
    
    # Follows table
    c.execute('''CREATE TABLE IF NOT EXISTS follows
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  follower_id INTEGER NOT NULL,
                  following_id INTEGER NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (follower_id) REFERENCES users (id),
                  FOREIGN KEY (following_id) REFERENCES users (id))''')
    
    # Friends table
    c.execute('''CREATE TABLE IF NOT EXISTS friends
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user1_id INTEGER NOT NULL,
                  user2_id INTEGER NOT NULL,
                  status TEXT DEFAULT 'pending',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user1_id) REFERENCES users (id),
                  FOREIGN KEY (user2_id) REFERENCES users (id))''')
    
    # Groups table
    c.execute('''CREATE TABLE IF NOT EXISTS groups
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  description TEXT,
                  profile_pic TEXT DEFAULT 'default_group.jpg',
                  unique_link TEXT UNIQUE NOT NULL,
                  creator_id INTEGER NOT NULL,
                  allow_non_admins_edit BOOLEAN DEFAULT 0,
                  allow_non_admins_message BOOLEAN DEFAULT 1,
                  allow_non_admins_add_members BOOLEAN DEFAULT 1,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (creator_id) REFERENCES users (id))''')
    
    # Group members table
    c.execute('''CREATE TABLE IF NOT EXISTS group_members
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  group_id INTEGER NOT NULL,
                  user_id INTEGER NOT NULL,
                  is_admin BOOLEAN DEFAULT 0,
                  joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (group_id) REFERENCES groups (id),
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Group messages table
    c.execute('''CREATE TABLE IF NOT EXISTS group_messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  group_id INTEGER NOT NULL,
                  user_id INTEGER NOT NULL,
                  message TEXT NOT NULL,
                  media_url TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (group_id) REFERENCES groups (id),
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Saved posts table
    c.execute('''CREATE TABLE IF NOT EXISTS saved_posts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  post_id INTEGER NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  FOREIGN KEY (post_id) REFERENCES posts (id))''')
    
    # Notifications table
    c.execute('''CREATE TABLE IF NOT EXISTS notifications
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  type TEXT NOT NULL,
                  content TEXT NOT NULL,
                  is_read BOOLEAN DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Create admin user if not exists
    admin_exists = c.execute("SELECT * FROM users WHERE username = ?", (config.ADMIN_USERNAME,)).fetchone()
    if not admin_exists:
        hashed_password = generate_password_hash(config.ADMIN_PASS)
        unique_key = generate_unique_key()
        c.execute("INSERT INTO users (username, password, unique_key, real_name) VALUES (?, ?, ?, ?)",
                 (config.ADMIN_USERNAME, hashed_password, unique_key, "Admin User"))
    
    conn.commit()
    conn.close()

# Helper functions
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def generate_unique_key():
    """Generate a 4-character unique key (2 letters + 2 numbers)"""
    letters = ''.join(random.choices(string.ascii_uppercase, k=2))
    numbers = ''.join(random.choices(string.digits, k=2))
    return letters + numbers

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov'}

def save_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        return unique_filename
    return None

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if not user or user['username'] != config.ADMIN_USERNAME:
            flash('Admin access required')
            return redirect(url_for('home'))
        
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['username_email'].strip()
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ? OR email = ?', 
            (identifier, identifier)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('home'))
        else:
            flash('Invalid username/email or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm-password']
        
        # Password validation
        if len(password) < 6 or not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password) or not any(not c.isalnum() for c in password):
            flash('Password must be 6+ characters with at least one number, one letter, and one special character')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match')
            return render_template('register.html')
        
        # Check if username exists
        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if existing_user:
            flash('Username already exists')
            conn.close()
            return render_template('register.html')
        
        # Create user
        hashed_password = generate_password_hash(password)
        unique_key = generate_unique_key()
        
        conn.execute(
            'INSERT INTO users (username, password, unique_key) VALUES (?, ?, ?)',
            (username, hashed_password, unique_key)
        )
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username'].strip()
        unique_key = request.form['unique_key'].strip()
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ? AND unique_key = ?', 
            (username, unique_key)
        ).fetchone()
        conn.close()
        
        if user:
            session['reset_user_id'] = user['id']
            return redirect(url_for('set_new_password'))
        else:
            flash('Invalid username or unique key')
    
    return render_template('forgot.html')

@app.route('/set_new', methods=['GET', 'POST'])
def set_new_password():
    if 'reset_user_id' not in session:
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('Passwords do not match')
            return render_template('set_new.html')
        
        # Password validation
        if len(new_password) < 6 or not any(c.isalpha() for c in new_password) or not any(c.isdigit() for c in new_password) or not any(not c.isalnum() for c in new_password):
            flash('Password must be 6+ characters with at least one number, one letter, and one special character')
            return render_template('set_new.html')
        
        # Update password
        hashed_password = generate_password_hash(new_password)
        conn = get_db_connection()
        conn.execute(
            'UPDATE users SET password = ? WHERE id = ?',
            (hashed_password, session['reset_user_id'])
        )
        conn.commit()
        conn.close()
        
        session.pop('reset_user_id', None)
        flash('Password updated successfully! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('set_new.html')

@app.route('/home')
@login_required
def home():
    # Get stories from friends
    conn = get_db_connection()
    
    # Get user's friends
    friends = conn.execute('''
        SELECT u.id, u.username, u.profile_pic 
        FROM users u 
        JOIN friends f ON (f.user1_id = u.id OR f.user2_id = u.id) 
        WHERE (f.user1_id = ? OR f.user2_id = ?) AND f.status = 'accepted' AND u.id != ?
    ''', (session['user_id'], session['user_id'], session['user_id'])).fetchall()
    
    friend_ids = [friend['id'] for friend in friends]
    friend_ids.append(session['user_id'])  # Include own stories
    
    # Get stories from friends
    stories_data = []
    for friend in friends:
        friend_stories = conn.execute('''
            SELECT * FROM stories 
            WHERE user_id = ? AND expires_at > datetime('now')
            ORDER BY created_at DESC
        ''', (friend['id'],)).fetchall()
        
        if friend_stories:
            stories_data.append({
                'id': friend['id'],
                'username': friend['username'],
                'profilePic': url_for('static', filename=f"uploads/{friend['profile_pic']}"),
                'stories': [{'imageUrl': url_for('static', filename=f"uploads/{story['image_url']}")} for story in friend_stories]
            })
    
    # Get posts (from friends and own posts)
    posts = conn.execute('''
        SELECT p.*, u.username, u.profile_pic, u.real_name,
               COUNT(DISTINCT l.id) as likes_count,
               COUNT(DISTINCT c.id) as comments_count,
               EXISTS(SELECT 1 FROM likes WHERE post_id = p.id AND user_id = ?) as is_liked,
               EXISTS(SELECT 1 FROM saved_posts WHERE post_id = p.id AND user_id = ?) as is_saved,
               (p.user_id = ?) as is_owner
        FROM posts p
        JOIN users u ON p.user_id = u.id
        LEFT JOIN likes l ON p.id = l.post_id
        LEFT JOIN comments c ON p.id = c.post_id
        WHERE p.user_id IN (SELECT user2_id FROM friends WHERE user1_id = ? AND status = 'accepted'
                           UNION
                           SELECT user1_id FROM friends WHERE user2_id = ? AND status = 'accepted'
                           UNION
                           SELECT ?)
        GROUP BY p.id
        ORDER BY p.created_at DESC
        LIMIT 20
    ''', (session['user_id'], session['user_id'], session['user_id'], session['user_id'], session['user_id'], session['user_id'])).fetchall()
    
    posts_data = []
    for post in posts:
        posts_data.append({
            'id': post['id'],
            'username': post['username'],
            'realName': post['real_name'] or post['username'],
            'profilePic': url_for('static', filename=f"uploads/{post['profile_pic']}"),
            'postedDate': datetime.datetime.strptime(post['created_at'], '%Y-%m-%d %H:%M:%S').strftime('%b %d, %Y'),
            'description': post['description'],
            'postImage': url_for('static', filename=f"uploads/{post['image_url']}") if post['image_url'] else None,
            'views': post['views'],
            'likesCount': post['likes_count'],
            'commentsCount': post['comments_count'],
            'isLiked': bool(post['is_liked']),
            'isSaved': bool(post['is_saved']),
            'isOwner': bool(post['is_owner'])
        })
    
    conn.close()
    
    return render_template('home.html', stories=stories_data, posts=posts_data)

@app.route('/my_profile')
@login_required
def my_profile():
    conn = get_db_connection()
    
    # Get user data
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    # Get counts
    friends_count = conn.execute('''
        SELECT COUNT(*) as count FROM friends 
        WHERE (user1_id = ? OR user2_id = ?) AND status = 'accepted'
    ''', (session['user_id'], session['user_id'])).fetchone()['count']
    
    followers_count = conn.execute('''
        SELECT COUNT(*) as count FROM follows WHERE following_id = ?
    ''', (session['user_id'],)).fetchone()['count']
    
    following_count = conn.execute('''
        SELECT COUNT(*) as count FROM follows WHERE follower_id = ?
    ''', (session['user_id'],)).fetchone()['count']
    
    likes_count = conn.execute('''
        SELECT COUNT(*) as count FROM likes 
        WHERE post_id IN (SELECT id FROM posts WHERE user_id = ?)
    ''', (session['user_id'],)).fetchone()['count']
    
    posts_count = conn.execute('''
        SELECT COUNT(*) as count FROM posts WHERE user_id = ?
    ''', (session['user_id'],)).fetchone()['count']
    
    # Get user info for display
    user_info = []
    if user['date_of_birth']:
        user_info.append({'label': 'Date of Birth', 'value': user['date_of_birth']})
    if user['gender']:
        user_info.append({'label': 'Gender', 'value': user['gender']})
    if user['pronouns']:
        user_info.append({'label': 'Pronouns', 'value': user['pronouns']})
    if user['work_info']:
        user_info.append({'label': 'Work', 'value': user['work_info']})
    if user['location']:
        user_info.append({'label': 'Location', 'value': user['location']})
    
    # Get posts for gallery
    posts = conn.execute('''
        SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC LIMIT 12
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    
    return render_template('my_profile.html', 
                         user=user,
                         friends_count=friends_count,
                         followers_count=followers_count,
                         following_count=following_count,
                         likes_count=likes_count,
                         posts_count=posts_count,
                         user_info=user_info,
                         posts=posts)

@app.route('/other_profile/<username>')
@login_required
def other_profile(username):
    conn = get_db_connection()
    
    # Get user data
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    
    if not user:
        flash('User not found')
        return redirect(url_for('home'))
    
    # Check if current user follows this user
    is_following = conn.execute('''
        SELECT 1 FROM follows WHERE follower_id = ? AND following_id = ?
    ''', (session['user_id'], user['id'])).fetchone() is not None
    
    # Check if users are friends
    are_friends = conn.execute('''
        SELECT 1 FROM friends 
        WHERE ((user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)) 
        AND status = 'accepted'
    ''', (session['user_id'], user['id'], user['id'], session['user_id'])).fetchone() is not None
    
    # Get mutual friends
    mutual_friends = conn.execute('''
        SELECT u.username FROM users u
        JOIN friends f1 ON (f1.user1_id = u.id OR f1.user2_id = u.id)
        JOIN friends f2 ON (f2.user1_id = u.id OR f2.user2_id = u.id)
        WHERE f1.user1_id = ? AND f2.user1_id = ? AND u.id != ? AND u.id != ?
        AND f1.status = 'accepted' AND f2.status = 'accepted'
        LIMIT 3
    ''', (session['user_id'], user['id'], session['user_id'], user['id'])).fetchall()
    
    # Get counts
    friends_count = conn.execute('''
        SELECT COUNT(*) as count FROM friends 
        WHERE (user1_id = ? OR user2_id = ?) AND status = 'accepted'
    ''', (user['id'], user['id'])).fetchone()['count']
    
    followers_count = conn.execute('''
        SELECT COUNT(*) as count FROM follows WHERE following_id = ?
    ''', (user['id'],)).fetchone()['count']
    
    following_count = conn.execute('''
        SELECT COUNT(*) as count FROM follows WHERE follower_id = ?
    ''', (user['id'],)).fetchone()['count']
    
    # Get posts for gallery
    posts = conn.execute('''
        SELECT * FROM posts WHERE user_id = ? AND is_locked = 0 ORDER BY created_at DESC LIMIT 12
    ''', (user['id'],)).fetchall()
    
    conn.close()
    
    return render_template('other_profile.html', 
                         user=user,
                         is_following=is_following,
                         are_friends=are_friends,
                         mutual_friends=mutual_friends,
                         friends_count=friends_count,
                         followers_count=followers_count,
                         following_count=following_count,
                         posts=posts)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if request.method == 'POST':
        # Handle profile picture upload
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and allowed_file(file.filename):
                filename = save_file(file)
                if filename:
                    conn.execute('UPDATE users SET profile_pic = ? WHERE id = ?', 
                               (filename, session['user_id']))
        
        # Update other fields
        username = request.form.get('username')
        biography = request.form.get('biography')
        dob_day = request.form.get('dob_day')
        dob_month = request.form.get('dob_month')
        dob_year = request.form.get('dob_year')
        gender = request.form.get('gender')
        pronouns = request.form.get('pronouns')
        work_info = request.form.get('work_info')
        university = request.form.get('university')
        secondary_school = request.form.get('secondary')
        other_education = request.form.get('other_education')
        location = request.form.get('location')
        phone_number = request.form.get('phone_number')
        email = request.form.get('email')
        social_link = request.form.get('social_link')
        website_link = request.form.get('website_link')
        other_contact = request.form.get('other_contact')
        relationship_status = request.form.get('relationship')
        partner_username = request.form.get('partner_name')
        
        # Check if username is available (if changed)
        if username != user['username']:
            existing_user = conn.execute('SELECT id FROM users WHERE username = ? AND id != ?', 
                                       (username, session['user_id'])).fetchone()
            if existing_user:
                flash('Username already taken')
                conn.close()
                return redirect(url_for('edit_profile'))
        
        # Format date of birth
        date_of_birth = None
        if dob_day and dob_month and dob_year:
            date_of_birth = f"{dob_year}-{dob_month}-{dob_day}"
        
        # Update user in database
        conn.execute('''
            UPDATE users SET 
            username = ?, biography = ?, date_of_birth = ?, gender = ?, pronouns = ?,
            work_info = ?, university = ?, secondary_school = ?, other_education = ?,
            location = ?, phone_number = ?, email = ?, social_link = ?, website_link = ?,
            other_contact = ?, relationship_status = ?, partner_username = ?
            WHERE id = ?
        ''', (username, biography, date_of_birth, gender, pronouns, work_info, university,
             secondary_school, other_education, location, phone_number, email, social_link,
             website_link, other_contact, relationship_status, partner_username, session['user_id']))
        
        conn.commit()
        conn.close()
        
        session['username'] = username
        flash('Profile updated successfully')
        return redirect(url_for('my_profile'))
    
    conn.close()
    return render_template('edit_profile.html', user=user)

@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        name = request.form.get('group_name')
        description = request.form.get('description')
        
        # Handle group picture upload
        profile_pic = 'default_group.jpg'
        if 'group_photo' in request.files:
            file = request.files['group_photo']
            if file and allowed_file(file.filename):
                filename = save_file(file)
                if filename:
                    profile_pic = filename
        
        # Generate unique link
        unique_link = str(uuid.uuid4())[:8]
        
        # Get permissions
        allow_non_admins_edit = 1 if request.form.get('edit-permissions') == 'allow' else 0
        allow_non_admins_message = 1 if request.form.get('message-permissions') == 'allow' else 0
        allow_non_admins_add_members = 1 if request.form.get('add-member-permissions') == 'allow' else 0
        
        # Create group
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO groups (name, description, profile_pic, unique_link, creator_id,
                              allow_non_admins_edit, allow_non_admins_message, allow_non_admins_add_members)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (name, description, profile_pic, unique_link, session['user_id'],
             allow_non_admins_edit, allow_non_admins_message, allow_non_admins_add_members))
        
        group_id = cursor.lastrowid
        
        # Add creator as admin member
        cursor.execute('''
            INSERT INTO group_members (group_id, user_id, is_admin)
            VALUES (?, ?, 1)
        ''', (group_id, session['user_id']))
        
        conn.commit()
        conn.close()
        
        flash('Group created successfully')
        return redirect(url_for('group_profile', group_link=unique_link))
    
    return render_template('create_group.html')

@app.route('/group/<group_link>')
@login_required
def group_profile(group_link):
    conn = get_db_connection()
    
    # Get group data
    group = conn.execute('''
        SELECT g.*, u.username as creator_name 
        FROM groups g 
        JOIN users u ON g.creator_id = u.id 
        WHERE g.unique_link = ?
    ''', (group_link,)).fetchone()
    
    if not group:
        flash('Group not found')
        return redirect(url_for('home'))
    
    # Check if user is member
    is_member = conn.execute('''
        SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?
    ''', (group['id'], session['user_id'])).fetchone() is not None
    
    # Check if user is admin
    is_admin = conn.execute('''
        SELECT is_admin FROM group_members WHERE group_id = ? AND user_id = ?
    ''', (group['id'], session['user_id'])).fetchone()
    is_admin = is_admin['is_admin'] if is_admin else 0
    
    # Get member count
    member_count = conn.execute('''
        SELECT COUNT(*) as count FROM group_members WHERE group_id = ?
    ''', (group['id'],)).fetchone()['count']
    
    # Get members (first 10)
    members = conn.execute('''
        SELECT u.id, u.username, u.profile_pic, gm.is_admin
        FROM group_members gm
        JOIN users u ON gm.user_id = u.id
        WHERE gm.group_id = ?
        ORDER BY gm.joined_at DESC
        LIMIT 10
    ''', (group['id'],)).fetchall()
    
    # Get media for gallery
    media = conn.execute('''
        SELECT media_url FROM group_messages 
        WHERE group_id = ? AND media_url IS NOT NULL
        ORDER BY created_at DESC
        LIMIT 12
    ''', (group['id'],)).fetchall()
    
    conn.close()
    
    return render_template('group_profile.html', 
                         group=group,
                         is_member=is_member,
                         is_admin=is_admin,
                         member_count=member_count,
                         members=members,
                         media=media)

@app.route('/edit_group/<group_link>', methods=['GET', 'POST'])
@login_required
def edit_group(group_link):
    conn = get_db_connection()
    
    # Get group data
    group = conn.execute('SELECT * FROM groups WHERE unique_link = ?', (group_link,)).fetchone()
    
    if not group:
        flash('Group not found')
        return redirect(url_for('home'))
    
    # Check if user is admin
    is_admin = conn.execute('''
        SELECT is_admin FROM group_members WHERE group_id = ? AND user_id = ?
    ''', (group['id'], session['user_id'])).fetchone()
    
    if not is_admin or not is_admin['is_admin']:
        flash('Admin access required')
        return redirect(url_for('group_profile', group_link=group_link))
    
    if request.method == 'POST':
        name = request.form.get('group_name')
        
        # Handle group picture upload
        if 'group_photo' in request.files:
            file = request.files['group_photo']
            if file and allowed_file(file.filename):
                filename = save_file(file)
                if filename:
                    conn.execute('UPDATE groups SET profile_pic = ? WHERE id = ?', 
                               (filename, group['id']))
        
        # Update permissions
        allow_non_admins_edit = 1 if request.form.get('edit-group') == 'allow' else 0
        allow_non_admins_message = 1 if request.form.get('send-messages') == 'allow' else 0
        allow_non_admins_add_members = 1 if request.form.get('add-members') == 'allow' else 0
        
        # Update group
        conn.execute('''
            UPDATE groups SET name = ?, allow_non_admins_edit = ?, 
            allow_non_admins_message = ?, allow_non_admins_add_members = ?
            WHERE id = ?
        ''', (name, allow_non_admins_edit, allow_non_admins_message, 
             allow_non_admins_add_members, group['id']))
        
        conn.commit()
        conn.close()
        
        flash('Group updated successfully')
        return redirect(url_for('group_profile', group_link=group_link))
    
    conn.close()
    return render_template('edit_group.html', group=group)

# API Routes
@app.route('/api/like_post/<int:post_id>', methods=['POST'])
@login_required
def api_like_post(post_id):
    conn = get_db_connection()
    
    # Check if already liked
    existing_like = conn.execute('''
        SELECT id FROM likes WHERE post_id = ? AND user_id = ?
    ''', (post_id, session['user_id'])).fetchone()
    
    if existing_like:
        # Unlike
        conn.execute('DELETE FROM likes WHERE id = ?', (existing_like['id'],))
        liked = False
    else:
        # Like
        conn.execute('INSERT INTO likes (post_id, user_id) VALUES (?, ?)', 
                   (post_id, session['user_id']))
        liked = True
    
    # Get updated like count
    like_count = conn.execute('''
        SELECT COUNT(*) as count FROM likes WHERE post_id = ?
    ''', (post_id,)).fetchone()['count']
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'liked': liked, 'like_count': like_count})

@app.route('/api/save_post/<int:post_id>', methods=['POST'])
@login_required
def api_save_post(post_id):
    conn = get_db_connection()
    
    # Check if already saved
    existing_save = conn.execute('''
        SELECT id FROM saved_posts WHERE post_id = ? AND user_id = ?
    ''', (post_id, session['user_id'])).fetchone()
    
    if existing_save:
        # Unsave
        conn.execute('DELETE FROM saved_posts WHERE id = ?', (existing_save['id'],))
        saved = False
    else:
        # Save
        conn.execute('INSERT INTO saved_posts (post_id, user_id) VALUES (?, ?)', 
                   (post_id, session['user_id']))
        saved = True
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'saved': saved})

@app.route('/api/follow_user/<int:user_id>', methods=['POST'])
@login_required
def api_follow_user(user_id):
    conn = get_db_connection()
    
    # Check if already following
    existing_follow = conn.execute('''
        SELECT id FROM follows WHERE follower_id = ? AND following_id = ?
    ''', (session['user_id'], user_id)).fetchone()
    
    if existing_follow:
        # Unfollow
        conn.execute('DELETE FROM follows WHERE id = ?', (existing_follow['id'],))
        following = False
    else:
        # Follow
        conn.execute('INSERT INTO follows (follower_id, following_id) VALUES (?, ?)', 
                   (session['user_id'], user_id))
        following = True
        
        # Create notification
        conn.execute('''
            INSERT INTO notifications (user_id, type, content)
            VALUES (?, 'follow', ?)
        ''', (user_id, f"{session['username']} started following you"))
    
    # Get updated follower count
    follower_count = conn.execute('''
        SELECT COUNT(*) as count FROM follows WHERE following_id = ?
    ''', (user_id,)).fetchone()['count']
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'following': following, 'follower_count': follower_count})

@app.route('/api/create_post', methods=['POST'])
@login_required
def api_create_post():
    description = request.form.get('description')
    image_file = request.files.get('image')
    is_locked = request.form.get('is_locked', 0)
    
    image_url = None
    if image_file and allowed_file(image_file.filename):
        image_url = save_file(image_file)
    
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO posts (user_id, description, image_url, is_locked)
        VALUES (?, ?, ?, ?)
    ''', (session['user_id'], description, image_url, is_locked))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Post created successfully'})

@app.route('/api/create_story', methods=['POST'])
@login_required
def api_create_story():
    image_file = request.files.get('image')
    
    if not image_file or not allowed_file(image_file.filename):
        return jsonify({'success': False, 'message': 'Invalid image file'})
    
    image_url = save_file(image_file)
    if not image_url:
        return jsonify({'success': False, 'message': 'Failed to upload image'})
    
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO stories (user_id, image_url)
        VALUES (?, ?)
    ''', (session['user_id'], image_url))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Story created successfully'})

@app.route('/api/join_group/<group_link>', methods=['POST'])
@login_required
def api_join_group(group_link):
    conn = get_db_connection()
    
    # Get group
    group = conn.execute('SELECT * FROM groups WHERE unique_link = ?', (group_link,)).fetchone()
    if not group:
        return jsonify({'success': False, 'message': 'Group not found'})
    
    # Check if already member
    existing_member = conn.execute('''
        SELECT id FROM group_members WHERE group_id = ? AND user_id = ?
    ''', (group['id'], session['user_id'])).fetchone()
    
    if existing_member:
        return jsonify({'success': False, 'message': 'Already a member'})
    
    # Join group
    conn.execute('''
        INSERT INTO group_members (group_id, user_id)
        VALUES (?, ?)
    ''', (group['id'], session['user_id']))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Joined group successfully'})

@app.route('/api/leave_group/<group_link>', methods=['POST'])
@login_required
def api_leave_group(group_link):
    conn = get_db_connection()
    
    # Get group
    group = conn.execute('SELECT * FROM groups WHERE unique_link = ?', (group_link,)).fetchone()
    if not group:
        return jsonify({'success': False, 'message': 'Group not found'})
    
    # Leave group
    conn.execute('''
        DELETE FROM group_members WHERE group_id = ? AND user_id = ?
    ''', (group['id'], session['user_id']))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Left group successfully'})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
