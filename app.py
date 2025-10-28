from flask import Flask, render_template, request, redirect, url_for, flash, Response, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import json
from datetime import datetime
import csv
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sacramento-standdown-secret-key-2024'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, email, role, display_name):
        self.id = id
        self.username = username
        self.email = email
        self.role = role
        self.display_name = display_name

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        return User(user['id'], user['username'], user['email'], user['role'], user['display_name'])
    return None

def get_db_connection():
    conn = sqlite3.connect('veterans.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    
    # Users table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            display_name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Veterans table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS veterans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            service_branch TEXT,
            phone_number TEXT,
            email TEXT,
            gender TEXT,
            full_ssn TEXT,
            date_of_birth TEXT,
            housing_status TEXT,
            housing_notes TEXT,
            service_component TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_blocked BOOLEAN DEFAULT 0,
            block_reason TEXT,
            blocked_at TIMESTAMP,
            blocked_by TEXT,
            printed BOOLEAN DEFAULT 0,
            printed_at TIMESTAMP,
            printed_by TEXT
        )
    ''')
    
    # Inventory table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_name TEXT NOT NULL,
            category TEXT,
            size TEXT,
            color TEXT,
            quantity INTEGER DEFAULT 0,
            min_stock_level INTEGER DEFAULT 5,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Notifications table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user_id INTEGER NOT NULL,
            to_user_id INTEGER,
            message_type TEXT NOT NULL,
            reason TEXT NOT NULL,
            location TEXT NOT NULL,
            priority TEXT DEFAULT 'Normal',
            status TEXT DEFAULT 'pending',
            response TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (from_user_id) REFERENCES users (id),
            FOREIGN KEY (to_user_id) REFERENCES users (id)
        )
    ''')
    
    # Create default admin user if not exists
    admin_exists = conn.execute('SELECT * FROM users WHERE username = ?', ('admin',)).fetchone()
    if not admin_exists:
        password_hash = generate_password_hash('admin123')
        conn.execute(
            'INSERT INTO users (username, email, password_hash, role, display_name) VALUES (?, ?, ?, ?, ?)',
            ('admin', 'admin@standdown.org', password_hash, 'admin', 'Administrator')
        )
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            user_obj = User(user['id'], user['username'], user['email'], user['role'], user['display_name'])
            login_user(user_obj)
            flash(f'Welcome back, {user["display_name"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    
    # Get stats
    total_veterans = conn.execute('SELECT COUNT(*) FROM veterans').fetchone()[0]
    total_inventory = conn.execute('SELECT COUNT(*) FROM inventory').fetchone()[0]
    low_stock = conn.execute('SELECT COUNT(*) FROM inventory WHERE quantity <= min_stock_level').fetchone()[0]
    pending_notifications = conn.execute('SELECT COUNT(*) FROM notifications WHERE status = "pending"').fetchone()[0]
    
    # Get recent notifications
    recent_notifications = conn.execute('''
        SELECT n.*, u.display_name as from_user_name 
        FROM notifications n 
        JOIN users u ON n.from_user_id = u.id 
        ORDER BY n.created_at DESC LIMIT 5
    ''').fetchall()
    
    conn.close()
    
    return render_template('dashboard.html',
                         total_veterans=total_veterans,
                         total_inventory=total_inventory,
                         low_stock=low_stock,
                         pending_notifications=pending_notifications,
                         recent_notifications=recent_notifications)

@app.route('/veterans')
@login_required
def veterans():
    conn = get_db_connection()
    veterans = conn.execute('SELECT * FROM veterans ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('veterans.html', veterans=veterans)

@app.route('/add_veteran', methods=['GET', 'POST'])
@login_required
def add_veteran():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        service_branch = request.form.get('service_branch')
        phone_number = request.form.get('phone_number')
        email = request.form.get('email')
        gender = request.form.get('gender')
        full_ssn = request.form.get('full_ssn')
        date_of_birth = request.form.get('date_of_birth')
        housing_status = request.form.get('housing_status')
        housing_notes = request.form.get('housing_notes')
        service_component = request.form.get('service_component')
        
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO veterans (first_name, last_name, service_branch, phone_number, email, gender, full_ssn, date_of_birth, housing_status, housing_notes, service_component) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (first_name, last_name, service_branch, phone_number, email, gender, full_ssn, date_of_birth, housing_status, housing_notes, service_component)
        )
        conn.commit()
        conn.close()
        
        flash('Veteran added successfully!', 'success')
        return redirect(url_for('veterans'))
    
    return render_template('add_veteran.html')

@app.route('/inventory')
@login_required
def inventory():
    conn = get_db_connection()
    items = conn.execute('SELECT * FROM inventory ORDER BY item_name').fetchall()
    conn.close()
    return render_template('inventory.html', items=items)

@app.route('/add_inventory', methods=['GET', 'POST'])
@login_required
def add_inventory():
    if request.method == 'POST':
        item_name = request.form.get('item_name')
        category = request.form.get('category')
        size = request.form.get('size')
        color = request.form.get('color')
        quantity = int(request.form.get('quantity', 0))
        min_stock_level = int(request.form.get('min_stock_level', 5))
        description = request.form.get('description')
        
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO inventory (item_name, category, size, color, quantity, min_stock_level, description) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (item_name, category, size, color, quantity, min_stock_level, description)
        )
        conn.commit()
        conn.close()
        
        flash('Inventory item added successfully!', 'success')
        return redirect(url_for('inventory'))
    
    return render_template('add_inventory.html')

@app.route('/notifications')
@login_required
def notifications():
    conn = get_db_connection()
    
    # Get all users for dropdown
    users = conn.execute('SELECT id, display_name FROM users WHERE id != ?', (current_user.id,)).fetchall()
    
    # Get sent notifications
    sent_notifications = conn.execute('''
        SELECT n.*, u.display_name as to_user_name 
        FROM notifications n 
        LEFT JOIN users u ON n.to_user_id = u.id 
        WHERE n.from_user_id = ?
        ORDER BY n.created_at DESC
    ''', (current_user.id,)).fetchall()
    
    # Get received notifications
    received_notifications = conn.execute('''
        SELECT n.*, u.display_name as from_user_name 
        FROM notifications n 
        JOIN users u ON n.from_user_id = u.id 
        WHERE n.to_user_id = ? OR n.to_user_id IS NULL
        ORDER BY n.created_at DESC
    ''', (current_user.id,)).fetchall()
    
    conn.close()
    
    return render_template('notifications.html', 
                         users=users,
                         sent_notifications=sent_notifications,
                         received_notifications=received_notifications)

@app.route('/send_notification', methods=['POST'])
@login_required
def send_notification():
    to_user_id = request.form.get('to_user_id')
    reason = request.form.get('reason')
    location = request.form.get('location')
    priority = request.form.get('priority', 'Normal')
    custom_reason = request.form.get('custom_reason', '')
    custom_location = request.form.get('custom_location', '')
    
    # Use custom fields if provided
    final_reason = custom_reason if reason == 'Other' else reason
    final_location = custom_location if location == 'Other' else location
    
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO notifications (from_user_id, to_user_id, message_type, reason, location, priority) VALUES (?, ?, ?, ?, ?, ?)',
        (current_user.id, to_user_id if to_user_id else None, 'help_request', final_reason, final_location, priority)
    )
    conn.commit()
    conn.close()
    
    flash('Notification sent successfully!', 'success')
    return redirect(url_for('notifications'))

@app.route('/respond_notification/<int:notification_id>', methods=['POST'])
@login_required
def respond_notification(notification_id):
    response = request.form.get('response')
    
    conn = get_db_connection()
    conn.execute(
        'UPDATE notifications SET status = "responded", response = ? WHERE id = ?',
        (response, notification_id)
    )
    conn.commit()
    conn.close()
    
    flash('Response sent!', 'success')
    return redirect(url_for('notifications'))

@app.route('/users')
@login_required
def users():
    if current_user.role != 'admin':
        flash('Access denied. Admin only.', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users ORDER BY role, display_name').fetchall()
    conn.close()
    return render_template('users.html', users=users)

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash('Access denied. Admin only.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        display_name = request.form.get('display_name')
        
        conn = get_db_connection()
        
        # Check if username exists
        existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if existing_user:
            flash('Username already exists', 'error')
            conn.close()
            return render_template('add_user.html')
        
        password_hash = generate_password_hash(password)
        
        conn.execute(
            'INSERT INTO users (username, email, password_hash, role, display_name) VALUES (?, ?, ?, ?, ?)',
            (username, email, password_hash, role, display_name)
        )
        conn.commit()
        conn.close()
        
        flash('User added successfully!', 'success')
        return redirect(url_for('users'))
    
    return render_template('add_user.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
