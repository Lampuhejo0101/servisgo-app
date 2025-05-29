from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, send_from_directory
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime, date
import secrets
from werkzeug.utils import secure_filename # Untuk mengamankan nama file yang diupload

app = Flask(__name__)

# --- Konfigurasi Aplikasi ---
# PENTING: GANTI INI DENGAN STRING ACAK YANG SANGAT KUAT UNTUK PRODUKSI!
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) # Sesi berakhir setelah 30 menit tidak aktif

# Konfigurasi nama database SQLite
DATABASE = 'booking_bengkel.db'

# Konfigurasi upload foto profil
UPLOAD_PROFILE_FOLDER = 'static/profile_pics' # Folder untuk menyimpan foto profil
UPLOAD_COVER_FOLDER = 'static/cover_pics' # Folder baru untuk foto sampul
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'} # Ekstensi file yang diizinkan
app.config['UPLOAD_PROFILE_FOLDER'] = UPLOAD_PROFILE_FOLDER
app.config['UPLOAD_COVER_FOLDER'] = UPLOAD_COVER_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 # Maksimal 10 MB

# Definisi hierarki peran (untuk otorisasi)
ROLES_HIERARCHY = {
    'user': 0,
    'mechanic': 1,
    'admin': 2,
    'master': 3
}

# --- Fungsi Pembantu untuk Upload ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# PASTIKAN FOLDER UPLOAD ADA SAAT APLIKASI DIMULAI
os.makedirs(app.config['UPLOAD_PROFILE_FOLDER'], exist_ok=True)
os.makedirs(app.config['UPLOAD_COVER_FOLDER'], exist_ok=True) 

# --- Fungsi Database ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row # Mengembalikan baris sebagai objek mirip dictionary
    return conn

# Fungsi untuk inisialisasi database (membuat tabel jika belum ada)
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Tabel users
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nama_lengkap TEXT NOT NULL,
            alamat TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            telepon TEXT NOT NULL,
            no_wa TEXT,
            jenis_kelamin TEXT,
            no_ktp TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user' NOT NULL,
            profile_picture TEXT DEFAULT 'default_profile.png',
            cover_picture TEXT DEFAULT 'default_cover.png',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user' NOT NULL")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN profile_picture TEXT DEFAULT 'default_profile.png'")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN cover_picture TEXT DEFAULT 'default_cover.png'")
    except sqlite3.OperationalError:
        pass

    # Tabel bookings
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            nama TEXT NOT NULL,
            email TEXT NOT NULL,
            telepon TEXT NOT NULL,
            layanan TEXT NOT NULL,
            lokasi_servis TEXT NOT NULL,
            alamat TEXT,
            tanggal DATE NOT NULL,
            jam TIME,
            keterangan TEXT,
            status TEXT DEFAULT 'Pending' NOT NULL,
            mechanic_id INTEGER,
            completed_at DATETIME,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (mechanic_id) REFERENCES users(id)
        )
    ''')
    try:
        cursor.execute("ALTER TABLE bookings ADD COLUMN status TEXT DEFAULT 'Pending' NOT NULL")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE bookings ADD COLUMN mechanic_id INTEGER")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE bookings ADD COLUMN completed_at DATETIME")
    except sqlite3.OperationalError:
        pass

    # Tabel services
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            price REAL NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    initial_services = [
        ('Servis Rutin', 'Pemeriksaan menyeluruh, pembersihan karburator/injeksi, penggantian busi, penyetelan rem, dan pengecekan komponen vital lainnya.', 50000),
        ('Ganti Oli', 'Penggantian oli mesin dengan oli berkualitas sesuai rekomendasi pabrikan. Termasuk pengecekan filter oli.', 40000),
        ('Perbaikan Mesin', 'Diagnosa dan perbaikan masalah mesin kompleks, seperti kebocoran oli, suara aneh, atau performa menurun.', 0),
        ('Ganti Ban', 'Penggantian ban motor dengan pilihan ban berkualitas. Termasuk balancing dan pengecekan tekanan angin.', 100000),
        ('Servis Rem', 'Pemeriksaan dan penggantian kampas rem, penyetelan rem, serta pengecekan minyak rem.', 30000),
        ('Pembersihan Karburator/Injeksi', 'Pembersihan komponen sistem bahan bakar untuk performa mesin yang optimal dan efisiensi bahan bakar.', 60000)
    ]
    for service_name, desc, price in initial_services:
        try:
            cursor.execute("INSERT OR IGNORE INTO services (name, description, price) VALUES (?, ?, ?)", (service_name, desc, price))
        except sqlite3.IntegrityError:
            pass

    # Tabel notifications
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            booking_id INTEGER,
            message TEXT NOT NULL,
            is_read INTEGER DEFAULT 0 NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (booking_id) REFERENCES bookings(id)
        )
    ''')
    try:
        cursor.execute("ALTER TABLE notifications ADD COLUMN is_read INTEGER DEFAULT 0 NOT NULL")
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()

init_db()

# --- Tambahkan data Master awal (Hanya jalankan sekali jika belum ada master!) ---
def create_initial_master():
    conn = get_db_connection()
    cursor = conn.cursor()
    master_exists = cursor.execute("SELECT 1 FROM users WHERE role = 'master' LIMIT 1").fetchone()
    if not master_exists:
        print("Membuat akun master awal...")
        master_username = 'master'
        master_password = 'masterpassword123' # PENTING: GANTI INI DENGAN PASSWORD MASTER YANG KUAT UNTUK PRODUKSI!
        hashed_master_password = generate_password_hash(master_password)
        try:
            cursor.execute('''
                INSERT INTO users (nama_lengkap, alamat, email, telepon, no_wa, jenis_kelamin, no_ktp, username, password_hash, role, profile_picture, cover_picture)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', ('Master Utama', 'Kantor Pusat ServisGo', 'master@servisgo.com', '081122334455', '', '', 'MASTERKTPOKE', master_username, hashed_master_password, 'master', 'default_profile.png', 'default_cover.png'))
            conn.commit()
            print(f"Akun master '{master_username}' dengan password '{master_password}' berhasil dibuat.")
            print("PENTING: GANTI PASSWORD INI SEGERA UNTUK KEAMANAN!")
        except sqlite3.IntegrityError as e:
            print(f"Gagal membuat akun master: {e} (mungkin username/email/ktp sudah ada)")
        except Exception as e:
            print(f"Error tidak terduga saat membuat master: {e}")
    conn.close()

create_initial_master() # Jalankan fungsi untuk membuat master awal

# --- Fungsi Pembantu untuk Membuat Notifikasi ---
def create_notification(user_id, message, booking_id=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO notifications (user_id, booking_id, message) VALUES (?, ?, ?)",
            (user_id, booking_id, message)
        )
        conn.commit()
    except Exception as e:
        print(f"Error creating notification for user {user_id}: {e}")
    finally:
        conn.close()


# --- DECORATOR UNTUK OTENTIKASI & OTORISASI ---
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Anda perlu login untuk mengakses halaman ini.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*allowed_roles):
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Anda perlu login untuk mengakses halaman ini.', 'danger')
                return redirect(url_for('login'))
            
            user_role = session.get('role')
            if not user_role:
                flash('Informasi peran tidak ditemukan. Silakan login ulang.', 'danger')
                return redirect(url_for('logout'))

            has_access = False
            for allowed_role in allowed_roles:
                if ROLES_HIERARCHY.get(user_role, -1) >= ROLES_HIERARCHY.get(allowed_role, 999):
                    has_access = True
                    break
            
            if has_access:
                return f(*args, **kwargs)
            else:
                flash(f'Anda tidak memiliki izin untuk mengakses halaman ini. Peran Anda adalah: {user_role}.', 'danger')
                if user_role == 'master':
                    return redirect(url_for('master_dashboard'))
                elif user_role == 'admin':
                    return redirect(url_for('admin_dashboard'))
                elif user_role == 'mechanic':
                    return redirect(url_for('mechanic_dashboard'))
                else:
                    return redirect(url_for('dashboard'))
        return decorated_function
    return decorator

# --- AKHIR BAGIAN DECORATOR ---


# --- Route Halaman Utama ---
@app.route('/')
def index():
    notifications = []
    # Hanya kirim notifikasi ke index.html jika user_id ada dan bukan halaman dashboard utama mereka
    if session.get('user_id') and session.get('role') == 'user': # Hanya untuk user biasa di index.html
        conn = get_db_connection()
        notifications = conn.execute(
            'SELECT id, message, created_at, is_read, booking_id FROM notifications WHERE user_id = ? ORDER BY created_at DESC',
            (session['user_id'],)
        ).fetchall()
        conn.close()
    
    return render_template('index.html', notifications=notifications)

# --- Route Halaman Booking ---
@app.route('/booking')
def booking_page():
    user_data = None
    if 'user_id' in session:
        conn = get_db_connection()
        user = conn.execute('SELECT nama_lengkap, email, telepon FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if user:
            user_data = dict(user)
        conn.close()
    else:
        flash('Anda disarankan login untuk melacak riwayat booking Anda.', 'info')
    
    conn = get_db_connection()
    services = conn.execute('SELECT name FROM services ORDER BY name ASC').fetchall()
    conn.close()
    return render_template('booking.html', services=services, user_data=user_data)

# --- Route Halaman Layanan ---
@app.route('/layanan')
def services_page():
    conn = get_db_connection()
    services = conn.execute('SELECT * FROM services ORDER BY name ASC').fetchall()
    conn.close()
    return render_template('services.html', services=services)

# --- Route Halaman Pendaftaran Pengguna Biasa ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        flash('Anda sudah login.', 'info')
        current_role = session.get('role')
        if current_role == 'master':
            return redirect(url_for('master_dashboard'))
        elif current_role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_role == 'mechanic':
            return redirect(url_for('mechanic_dashboard'))
        else:
            return redirect(url_for('dashboard'))

    if request.method == 'POST':
        data = request.form
        nama_lengkap = data.get('nama_lengkap')
        alamat = data.get('alamat')
        email = data.get('email')
        telepon = data.get('telepon')
        no_wa = data.get('no_wa')
        jenis_kelamin = data.get('jenis_kelamin')
        no_ktp = data.get('no_ktp')
        username = data.get('username')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        if not all([nama_lengkap, alamat, email, telepon, no_ktp, username, password, confirm_password]):
            flash('Harap lengkapi semua kolom yang wajib diisi.', 'danger')
            return render_template('register.html', data=data)

        if password != confirm_password:
            flash('Password dan konfirmasi password tidak cocok.', 'danger')
            return render_template('register.html', data=data)

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT INTO users (nama_lengkap, alamat, email, telepon, no_wa, jenis_kelamin, no_ktp, username, password_hash, role)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'user')
            ''', (nama_lengkap, alamat, email, telepon, no_wa, jenis_kelamin, no_ktp, username, hashed_password))
            conn.commit()
            conn.close()
            flash('Registrasi berhasil! Silakan login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError as e:
            conn.close()
            if "UNIQUE constraint failed: users.email" in str(e):
                flash('Email ini sudah terdaftar. Gunakan email lain.', 'danger')
            elif "UNIQUE constraint failed: users.no_ktp" in str(e):
                flash('Nomor KTP ini sudah terdaftar.', 'danger')
            elif "UNIQUE constraint failed: users.username" in str(e):
                flash('Username ini sudah digunakan. Pilih username lain.', 'danger')
            else:
                flash('Terjadi kesalahan saat pendaftaran. Silakan coba lagi.', 'danger')
            return render_template('register.html', data=data)
        except Exception as e:
            conn.close()
            flash(f'Terjadi kesalahan tidak terduga: {e}', 'danger')
            return render_template('register.html', data=data)
    
    return render_template('register.html')

# --- Route Halaman Login ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        flash('Anda sudah login.', 'info')
        current_role = session.get('role')
        if current_role == 'master':
            return redirect(url_for('master_dashboard'))
        elif current_role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_role == 'mechanic':
            return redirect(url_for('mechanic_dashboard'))
        else:
            return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session.permanent = True
            flash(f'Login berhasil sebagai {user["role"]}!', 'success')
            
            if user['role'] == 'master':
                return redirect(url_for('master_dashboard'))
            elif user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'mechanic':
                return redirect(url_for('mechanic_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Username atau password salah.', 'danger')
    
    return render_template('login.html')

# --- Route Logout ---
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    flash('Anda telah berhasil logout.', 'info')
    return redirect(url_for('index'))

# --- Route Dashboard Pengguna Biasa ---
@app.route('/dashboard')
@login_required
@role_required('user')
def dashboard():
    conn = get_db_connection()
    user_bookings = conn.execute('SELECT * FROM bookings WHERE user_id = ? ORDER BY timestamp DESC', (session['user_id'],)).fetchall()
    
    notifications = conn.execute(
        'SELECT id, message, created_at, is_read, booking_id FROM notifications WHERE user_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()
    
    user_info = conn.execute('SELECT profile_picture, cover_picture FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    profile_picture = user_info['profile_picture'] if user_info and user_info['profile_picture'] else 'default_profile.png'
    cover_picture = user_info['cover_picture'] if user_info and user_info['cover_picture'] else 'default_cover.png'

    conn.close()
    return render_template('dashboard.html', user_bookings=user_bookings, notifications=notifications, profile_picture=profile_picture, cover_picture=cover_picture)

# --- Route untuk mengupload foto profil ---
@app.route('/upload_profile_pic', methods=['POST'])
@login_required
def upload_profile_pic():
    if 'file' not in request.files:
        flash('Tidak ada bagian file di permintaan.', 'danger')
        current_role = session.get('role')
        if current_role == 'mechanic':
            return redirect(url_for('mechanic_dashboard'))
        elif current_role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_role == 'master':
            return redirect(url_for('master_dashboard'))
        else:
            return redirect(url_for('dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('Tidak ada file yang dipilih.', 'danger')
        current_role = session.get('role')
        if current_role == 'mechanic':
            return redirect(url_for('mechanic_dashboard'))
        elif current_role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_role == 'master':
            return redirect(url_for('master_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_extension = filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{session['user_id']}_{secrets.token_hex(8)}.{file_extension}"
        file_path = os.path.join(app.config['UPLOAD_PROFILE_FOLDER'], unique_filename)
        
        try:
            conn = get_db_connection()
            old_profile_pic = conn.execute("SELECT profile_picture FROM users WHERE id = ?", (session['user_id'],)).fetchone()
            if old_profile_pic and old_profile_pic['profile_picture'] != 'default_profile.png':
                old_file_path = os.path.join(app.config['UPLOAD_PROFILE_FOLDER'], old_profile_pic['profile_picture'])
                if os.path.exists(old_file_path):
                    os.remove(old_file_path)

            file.save(file_path)
            
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET profile_picture = ? WHERE id = ?", (unique_filename, session['user_id']))
            conn.commit()
            conn.close()
            flash('Foto profil berhasil diunggah!', 'success')
        except Exception as e:
            flash(f'Gagal mengunggah foto profil: {e}', 'danger')
            print(f"Error saving file or updating DB: {e}")
        
        current_role = session.get('role')
        if current_role == 'mechanic':
            return redirect(url_for('mechanic_dashboard'))
        elif current_role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_role == 'master':
            return redirect(url_for('master_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    else:
        flash('Format file tidak diizinkan atau ukuran file terlalu besar (max 10MB).', 'danger')
        current_role = session.get('role')
        if current_role == 'mechanic':
            return redirect(url_for('mechanic_dashboard'))
        elif current_role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_role == 'master':
            return redirect(url_for('master_dashboard'))
        else:
            return redirect(url_for('dashboard'))

# --- Route untuk mengupload foto sampul ---
@app.route('/upload_cover_pic', methods=['POST'])
@login_required
def upload_cover_pic():
    if 'file' not in request.files:
        flash('Tidak ada bagian file di permintaan.', 'danger')
        current_role = session.get('role')
        if current_role == 'mechanic':
            return redirect(url_for('mechanic_dashboard'))
        elif current_role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_role == 'master':
            return redirect(url_for('master_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    file = request.files['file']
    if file.filename == '':
        flash('Tidak ada file yang dipilih.', 'danger')
        current_role = session.get('role')
        if current_role == 'mechanic':
            return redirect(url_for('mechanic_dashboard'))
        elif current_role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_role == 'master':
            return redirect(url_for('master_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_extension = filename.rsplit('.', 1)[1].lower()
        unique_filename = f"cover_{session['user_id']}_{secrets.token_hex(8)}.{file_extension}"
        file_path = os.path.join(app.config['UPLOAD_COVER_FOLDER'], unique_filename)
        
        try:
            conn = get_db_connection()
            old_cover_pic = conn.execute("SELECT cover_picture FROM users WHERE id = ?", (session['user_id'],)).fetchone()
            if old_cover_pic and old_cover_pic['cover_picture'] != 'default_cover.png':
                # FIX: Menggunakan old_cover_pic['cover_picture'] untuk path lama
                old_file_path = os.path.join(app.config['UPLOAD_COVER_FOLDER'], old_cover_pic['cover_picture'])
                if os.path.exists(old_file_path):
                    os.remove(old_file_path)

            file.save(file_path)
            
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET cover_picture = ? WHERE id = ?", (unique_filename, session['user_id']))
            conn.commit()
            conn.close()
            flash('Foto sampul berhasil diunggah!', 'success')
        except Exception as e:
            flash(f'Gagal mengunggah foto sampul: {e}', 'danger')
            print(f"Error saving cover file or updating DB: {e}")
        
        current_role = session.get('role')
        if current_role == 'mechanic':
            return redirect(url_for('mechanic_dashboard'))
        elif current_role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_role == 'master':
            return redirect(url_for('master_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    else:
        flash('Format file tidak diizinkan atau ukuran file terlalu besar (max 10MB).', 'danger')
        current_role = session.get('role')
        if current_role == 'mechanic':
            return redirect(url_for('mechanic_dashboard'))
        elif current_role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_role == 'master':
            return redirect(url_for('master_dashboard'))
        else:
            return redirect(url_for('dashboard'))

# --- Route untuk menandai notifikasi sudah dibaca (via AJAX) ---
@app.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?",
                       (notification_id, session['user_id']))
        conn.commit()
        
        if cursor.rowcount == 0:
            return jsonify({'success': False, 'message': 'Notifikasi tidak ditemukan atau bukan milik Anda.'}), 404
            
        return jsonify({'success': True, 'message': 'Notifikasi ditandai sudah dibaca.'})
    except Exception as e:
        print(f"Error marking notification as read: {e}")
        return jsonify({'success': False, 'message': 'Gagal menandai notifikasi.'}), 500
    finally:
        conn.close()

# --- Route Mendapatkan Detail Booking dan Mekanik untuk Notifikasi (untuk Modal) ---
@app.route('/get_booking_mechanic_details/<int:booking_id>', methods=['GET'])
@login_required
def get_booking_mechanic_details(booking_id):
    conn = get_db_connection()
    try:
        booking = conn.execute("SELECT user_id, status, mechanic_id, layanan FROM bookings WHERE id = ?", (booking_id,)).fetchone()
        
        if not booking:
            return jsonify({'success': False, 'message': 'Booking tidak ditemukan.'}), 404
        
        if booking['user_id'] != session['user_id'] and session.get('role') == 'user':
            return jsonify({'success': False, 'message': 'Anda tidak memiliki izin untuk melihat detail booking ini.'}), 403

        mechanic_details = None
        if booking['mechanic_id']:
            mechanic_info = conn.execute("SELECT nama_lengkap, profile_picture FROM users WHERE id = ?", (booking['mechanic_id'],)).fetchone()
            if mechanic_info:
                mechanic_details = {
                    'nama_lengkap': mechanic_info['nama_lengkap'],
                    'profile_picture': mechanic_info['profile_picture'] if mechanic_info['profile_picture'] else 'default_profile.png'
                }
            else:
                mechanic_details = {'nama_lengkap': 'Mekanik Tidak Dikenal', 'profile_picture': 'default_profile.png'}
        
        instruction_message = ""
        if booking['status'] == 'Confirmed':
            instruction_message = "Booking Anda telah dikonfirmasi! Mekanik akan segera menanganinya. Mohon tunggu."
        elif booking['status'] == 'In Progress':
            instruction_message = "Booking Anda sedang dikerjakan. Mohon tunggu hingga selesai."
        elif booking['status'] == 'Completed':
            instruction_message = "Booking Anda telah selesai. Mohon hubungi kami jika ada pertanyaan."
        elif booking['status'] == 'Cancelled':
             instruction_message = "Booking Anda telah dibatalkan. Silakan hubungi kami untuk informasi lebih lanjut."

        return jsonify({
            'success': True,
            'booking_status': booking['status'],
            'layanan': booking['layanan'],
            'mechanic': mechanic_details,
            'instruction_message': instruction_message
        }), 200

    except Exception as e:
        print(f"Error fetching booking/mechanic details: {e}")
        return jsonify({'success': False, 'message': 'Terjadi kesalahan saat mengambil detail.'}), 500
    finally:
        conn.close()

# --- Route Dashboard Mekanik ---
@app.route('/mechanic_dashboard')
@login_required
@role_required('mechanic', 'admin', 'master')
def mechanic_dashboard():
    conn = get_db_connection()
    
    mechanic_id_current = session['user_id']

    pending_bookings_unassigned = conn.execute(
        "SELECT b.*, u.username, u.email FROM bookings b JOIN users u ON b.user_id = u.id WHERE b.status = 'Pending' AND b.mechanic_id IS NULL ORDER BY b.tanggal ASC, b.jam ASC"
    ).fetchall()
    
    assigned_and_in_progress_bookings = conn.execute(
        "SELECT b.*, u.username, u.email FROM bookings b JOIN users u ON b.user_id = u.id WHERE b.status IN ('Confirmed', 'In Progress') AND b.mechanic_id = ? ORDER BY b.tanggal ASC, b.jam ASC",
        (mechanic_id_current,)
    ).fetchall()
    
    notifications = conn.execute(
        'SELECT id, message, created_at, is_read, booking_id FROM notifications WHERE user_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()

    mechanic_info = conn.execute('SELECT profile_picture, cover_picture FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    profile_picture = mechanic_info['profile_picture'] if mechanic_info and mechanic_info['profile_picture'] else 'default_profile.png'
    cover_picture = mechanic_info['cover_picture'] if mechanic_info and mechanic_info['cover_picture'] else 'default_cover.png'

    conn.close()
    return render_template('mechanic_dashboard.html', 
                           pending_bookings_unassigned=pending_bookings_unassigned, 
                           assigned_and_in_progress_bookings=assigned_and_in_progress_bookings, 
                           notifications=notifications,
                           profile_picture=profile_picture,
                           cover_picture=cover_picture)

# --- Route untuk Riwayat Booking Mekanik ---
@app.route('/mechanic_history')
@login_required
@role_required('mechanic', 'admin', 'master')
def mechanic_history():
    conn = get_db_connection()
    completed_bookings = conn.execute(
        """
        SELECT b.*, u.username AS client_username, u.email AS client_email, 
               m.username AS mechanic_username, m.nama_lengkap AS mechanic_name
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        JOIN users m ON b.mechanic_id = m.id
        WHERE b.status = 'Completed' AND b.mechanic_id = ?
        ORDER BY b.completed_at DESC
        """, 
        (session['user_id'],)
    ).fetchall()
    conn.close()
    return render_template('mechanic_history.html', completed_bookings=completed_bookings)


# --- Fungsi pembantu untuk memfilter booking ---
def filter_bookings(filter_by, filter_value, conn):
    query = """
        SELECT b.*, u.username AS client_username, u.email AS client_email, 
               m.username AS mechanic_username, m.nama_lengkap AS mechanic_name
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        LEFT JOIN users m ON b.mechanic_id = m.id
    """
    params = []
    
    if filter_by == 'day':
        query += " WHERE SUBSTR(b.timestamp, 1, 10) = ?"
        params.append(filter_value)
    elif filter_by == 'month':
        query += " WHERE SUBSTR(b.timestamp, 1, 7) = ?"
        params.append(filter_value)
    elif filter_by == 'year':
        query += " WHERE SUBSTR(b.timestamp, 1, 4) = ?"
        params.append(filter_value)
    elif filter_by == 'week':
        try:
            start_date = datetime.strptime(filter_value, '%Y-%m-%d').date()
            end_date = start_date + timedelta(days=6)
            query += " WHERE b.tanggal BETWEEN ? AND ?"
            params.append(str(start_date))
            params.append(str(end_date))
        except ValueError:
            flash('Format tanggal minggu tidak valid. Gunakan YYYY-MM-DD untuk awal minggu.', 'danger')
            return []
    elif filter_by == 'hour':
        try:
            target_datetime = datetime.strptime(filter_value, '%Y-%m-%d-%H')
            start_of_hour = target_datetime.strftime('%Y-%m-%d %H:00:00')
            end_of_hour = (target_datetime + timedelta(hours=1) - timedelta(seconds=1)).strftime('%Y-%m-%d %H:%M:%S')
            query += " WHERE b.timestamp BETWEEN ? AND ?"
            params.append(start_of_hour)
            params.append(end_of_hour)
        except ValueError:
            flash('Format tanggal/jam tidak valid. Gunakan YYYY-MM-DD-HH untuk filter per jam.', 'danger')
            return []

    query += " ORDER BY b.timestamp DESC"
    
    return conn.execute(query, tuple(params)).fetchall()


# --- Route Dashboard Admin ---
@app.route('/admin_dashboard')
@login_required
@role_required('admin', 'master')
def admin_dashboard():
    conn = get_db_connection()
    
    filter_by = request.args.get('filter_by')
    filter_value = request.args.get('filter_value')
    
    if filter_by and filter_value:
        all_bookings = filter_bookings(filter_by, filter_value, conn)
        flash(f"Menampilkan booking per {filter_by}: {filter_value}", "info")
    else:
        all_bookings = conn.execute('SELECT b.*, u.username AS client_username, u.email AS client_email, m.username AS mechanic_username, m.nama_lengkap AS mechanic_name FROM bookings b JOIN users u ON b.user_id = u.id LEFT JOIN users m ON b.mechanic_id = m.id ORDER BY b.timestamp DESC').fetchall()
    
    notifications = conn.execute(
        'SELECT id, message, created_at, is_read, booking_id FROM notifications WHERE user_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()

    admin_info = conn.execute('SELECT profile_picture, cover_picture FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    profile_picture = admin_info['profile_picture'] if admin_info and admin_info['profile_picture'] else 'default_profile.png'
    cover_picture = admin_info['cover_picture'] if admin_info and admin_info['cover_picture'] else 'default_cover.png'

    conn.close()
    return render_template('admin_dashboard.html', all_bookings=all_bookings, notifications=notifications, 
                           current_filter_by=filter_by, current_filter_value=filter_value, 
                           profile_picture=profile_picture, cover_picture=cover_picture)

# --- Route Dashboard Master ---
@app.route('/master_dashboard')
@login_required
@role_required('master')
def master_dashboard():
    conn = get_db_connection()
    
    filter_by = request.args.get('filter_by')
    filter_value = request.args.get('filter_value')

    if filter_by and filter_value:
        all_bookings = filter_bookings(filter_by, filter_value, conn)
        flash(f"Menampilkan booking per {filter_by}: {filter_value}", "info")
    else:
        all_bookings = conn.execute('SELECT b.*, u.username AS client_username, u.email AS client_email, u.nama_lengkap AS client_name, m.username AS mechanic_username, m.nama_lengkap AS mechanic_name FROM bookings b JOIN users u ON b.user_id = u.id LEFT JOIN users m ON b.mechanic_id = m.id ORDER BY b.timestamp DESC').fetchall()
    
    all_users = conn.execute("SELECT id, nama_lengkap, email, telepon, role, profile_picture, cover_picture FROM users ORDER BY role DESC, username ASC").fetchall()
    
    notifications = conn.execute(
        'SELECT id, message, created_at, is_read, booking_id FROM notifications WHERE user_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()

    master_info = conn.execute('SELECT profile_picture, cover_picture FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    profile_picture = master_info['profile_picture'] if master_info and master_info['profile_picture'] else 'default_profile.png'
    cover_picture = master_info['cover_picture'] if master_info and master_info['cover_picture'] else 'default_cover.png'

    conn.close()
    return render_template('master_dashboard.html', all_users=all_users, all_bookings=all_bookings, notifications=notifications,
                           current_filter_by=filter_by, current_filter_value=filter_value, 
                           profile_picture=profile_picture, cover_picture=cover_picture)


# --- Route untuk Mendaftarkan Admin (GET untuk menampilkan form, POST untuk memproses) ---
@app.route('/register_admin', methods=['GET', 'POST'])
@login_required
@role_required('master')
def register_admin():
    if request.method == 'POST':
        data = request.form

        nama_lengkap = data.get('nama_lengkap')
        alamat = data.get('alamat')
        email = data.get('email')
        telepon = data.get('telepon')
        no_wa = data.get('no_wa')
        jenis_kelamin = data.get('jenis_kelamin')
        no_ktp = data.get('no_ktp')
        username = data.get('username')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        if not all([nama_lengkap, email, telepon, no_ktp, username, password, confirm_password]):
            flash('Harap lengkapi semua kolom wajib untuk admin (Nama, Email, Telepon, No KTP, Username, Password).', 'danger')
            return render_template('register_admin.html', data=data)

        if password != confirm_password:
            flash('Password dan konfirmasi password tidak cocok.', 'danger')
            return render_template('register_admin.html', data=data)

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT INTO users (nama_lengkap, alamat, email, telepon, no_wa, jenis_kelamin, no_ktp, username, password_hash, role)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'admin')
            ''', (nama_lengkap, alamat, email, telepon, no_wa, jenis_kelamin, no_ktp, username, hashed_password))
            conn.commit()
            conn.close()
            flash('Admin baru berhasil didaftarkan!', 'success')
            return redirect(url_for('master_dashboard'))
        except sqlite3.IntegrityError as e:
            conn.close()
            if "UNIQUE constraint failed: users.email" in str(e):
                flash('Email ini sudah terdaftar untuk pengguna lain.', 'danger')
            elif "UNIQUE constraint failed: users.no_ktp" in str(e):
                flash('Nomor KTP ini sudah terdaftar.', 'danger')
            elif "UNIQUE constraint failed: users.username" in str(e):
                flash('Username ini sudah digunakan. Pilih username lain.', 'danger')
            else:
                flash('Terjadi kesalahan saat pendaftaran admin. Silakan coba lagi.', 'danger')
            return render_template('register_admin.html', data=data)
        except Exception as e:
            conn.close()
            flash(f'Terjadi kesalahan tidak terduga saat mendaftarkan admin: {e}', 'danger')
            return render_template('register_admin.html', data=data)
            
    return render_template('register_admin.html')

# --- Route untuk Mendaftarkan Mekanik (GET untuk menampilkan form, POST untuk memproses) ---
@app.route('/register_mechanic', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'master')
def register_mechanic():
    if request.method == 'POST':
        data = request.form

        nama_lengkap = data.get('nama_lengkap')
        alamat = data.get('alamat')
        email = data.get('email')
        telepon = data.get('telepon')
        no_wa = data.get('no_wa')
        jenis_kelamin = data.get('jenis_kelamin')
        no_ktp = data.get('no_ktp')
        username = data.get('username')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        if not all([nama_lengkap, email, telepon, no_ktp, username, password, confirm_password]):
            flash('Harap lengkapi semua kolom wajib untuk mekanik (Nama, Email, Telepon, No KTP, Username, Password).', 'danger')
            return render_template('register_mechanic.html', data=data)

        if password != confirm_password:
            flash('Password dan konfirmasi password tidak cocok.', 'danger')
            return render_template('register_mechanic.html', data=data)

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT INTO users (nama_lengkap, alamat, email, telepon, no_wa, jenis_kelamin, no_ktp, username, password_hash, role)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'mechanic')
            ''', (nama_lengkap, alamat, email, telepon, no_wa, jenis_kelamin, no_ktp, username, hashed_password))
            conn.commit()
            conn.close()
            flash('Mekanik baru berhasil didaftarkan!', 'success')
            return redirect(url_for('admin_dashboard'))
        except sqlite3.IntegrityError as e:
            conn.close()
            if "UNIQUE constraint failed: users.email" in str(e):
                flash('Email ini sudah terdaftar untuk pengguna lain.', 'danger')
            elif "UNIQUE constraint failed: users.no_ktp" in str(e):
                flash('Nomor KTP ini sudah terdaftar.', 'danger')
            elif "UNIQUE constraint failed: users.username" in str(e):
                flash('Username ini sudah digunakan. Pilih username lain.', 'danger')
            else:
                flash('Terjadi kesalahan saat pendaftaran mekanik. Silakan coba lagi.', 'danger')
            return render_template('register_mechanic.html', data=data)
        except Exception as e:
            conn.close()
            flash(f'Terjadi kesalahan tidak terduga saat mendaftarkan mekanik: {e}', 'danger')
            return render_template('register_mechanic.html', data=data)
            
    return render_template('register_mechanic.html')


# --- Route untuk Manajemen Layanan (GET untuk menampilkan, POST untuk menambah) ---
@app.route('/manage_services', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'master')
def manage_services():
    conn = get_db_connection()
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')

        if not all([name, description, price]):
            flash('Nama, deskripsi, dan harga layanan wajib diisi.', 'danger')
            return redirect(url_for('manage_services'))
        
        try:
            price = float(price)
            if price < 0:
                flash('Harga tidak boleh negatif.', 'danger')
                return redirect(url_for('manage_services'))
        except ValueError:
            flash('Harga harus berupa angka.', 'danger')
            return redirect(url_for('manage_services'))

        try:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO services (name, description, price) VALUES (?, ?, ?)", (name, description, price))
            conn.commit()
            flash(f'Layanan "{name}" berhasil ditambahkan.', 'success')
        except sqlite3.IntegrityError:
            flash(f'Layanan dengan nama "{name}" sudah ada.', 'danger')
        except Exception as e:
            flash(f'Terjadi kesalahan saat menambahkan layanan: {e}', 'danger')
        return redirect(url_for('manage_services'))
    
    services = conn.execute('SELECT * FROM services ORDER BY name ASC').fetchall()
    conn.close()
    return render_template('manage_services.html', services=services)

# --- Route untuk Mengedit Layanan ---
@app.route('/edit_service/<int:service_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'master')
def edit_service(service_id):
    conn = get_db_connection()
    service = conn.execute('SELECT * FROM services WHERE id = ?', (service_id,)).fetchone()

    if not service:
        flash('Layanan tidak ditemukan.', 'danger')
        conn.close()
        return redirect(url_for('manage_services'))

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')

        if not all([name, description, price]):
            flash('Nama, deskripsi, dan harga layanan wajib diisi.', 'danger')
            conn.close()
            return render_template('edit_service.html', service=service)
        
        try:
            price = float(price)
            if price < 0:
                flash('Harga tidak boleh negatif.', 'danger')
                conn.close()
                return render_template('edit_service.html', service=service)
        except ValueError:
            flash('Harga harus berupa angka.', 'danger')
            conn.close()
            return render_template('edit_service.html', service=service)

        try:
            cursor = conn.cursor()
            cursor.execute("UPDATE services SET name = ?, description = ?, price = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                           (name, description, price, service_id))
            conn.commit()
            flash(f'Layanan "{name}" berhasil diperbarui.', 'success')
        except sqlite3.IntegrityError:
            flash(f'Layanan dengan nama "{name}" sudah ada.', 'danger')
        except Exception as e:
            flash(f'Terjadi kesalahan saat memperbarui layanan: {e}', 'danger')
        finally:
            conn.close()
        return redirect(url_for('manage_services'))
    
    conn.close()
    return render_template('edit_service.html', service=service)

# --- Route untuk Menghapus Layanan ---
@app.route('/delete_service/<int:service_id>', methods=['POST'])
@login_required
@role_required('admin', 'master')
def delete_service(service_id):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        bookings_with_service = conn.execute("SELECT COUNT(*) FROM bookings WHERE layanan = (SELECT name FROM services WHERE id = ?)", (service_id,)).fetchone()[0]
        if bookings_with_service > 0:
            flash(f'Layanan tidak bisa dihapus karena sudah ada {bookings_with_service} booking yang menggunakan layanan ini. Harap ubah booking terkait atau ganti nama layanan.', 'danger')
        else:
            cursor.execute("DELETE FROM services WHERE id = ?", (service_id,))
            conn.commit()
            flash('Layanan berhasil dihapus.', 'success')
    except Exception as e:
        flash(f'Terjadi kesalahan saat menghapus layanan: {e}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('manage_services'))


# --- Route untuk update status booking (hanya mekanik/admin/master) ---
@app.route('/update_booking_status/<int:booking_id>', methods=['POST'])
@login_required
@role_required('mechanic', 'admin', 'master')
def update_booking_status(booking_id):
    new_status = request.form.get('status')
    if not new_status:
        flash('Status baru tidak boleh kosong.', 'danger')
        current_role = session.get('role')
        if current_role == 'master':
            return redirect(url_for('master_dashboard'))
        elif current_role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('mechanic_dashboard'))

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        booking = conn.execute('SELECT user_id, layanan FROM bookings WHERE id = ?', (booking_id,)).fetchone()
        if not booking:
            flash('Booking tidak ditemukan.', 'danger')
            conn.close()
            return redirect(url_for('mechanic_dashboard')) 

        client_user_id = booking['user_id']
        layanan_name = booking['layanan']
        
        mechanic_id_session = session.get('user_id')
        mechanic_info = conn.execute('SELECT nama_lengkap FROM users WHERE id = ?', (mechanic_id_session,)).fetchone()
        mechanic_name = mechanic_info['nama_lengkap'] if mechanic_info else 'Mekanik Tidak Dikenal'
        
        update_mechanic_id_val = None
        update_completed_at_val = None
        notification_message = None

        if new_status == 'Completed':
            update_mechanic_id_val = mechanic_id_session
            update_completed_at_val = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            notification_message = f"Booking servis '{layanan_name}' Anda (ID: {booking_id}) telah SELESAI dikerjakan oleh {mechanic_name}."
        elif new_status == 'Confirmed':
            update_mechanic_id_val = mechanic_id_session
            notification_message = f"Booking servis '{layanan_name}' Anda (ID: {booking_id}) telah DIKONFIRMASI oleh {mechanic_name}! Mohon tunggu mekanik kami."
        elif new_status == 'In Progress':
            update_mechanic_id_val = mechanic_id_session
            notification_message = f"Booking servis '{layanan_name}' Anda (ID: {booking_id}) sedang DIKERJAKAN oleh {mechanic_name}."
        elif new_status == 'Cancelled':
            notification_message = f"Booking servis '{layanan_name}' Anda (ID: {booking_id}) telah DIBATALKAN oleh {mechanic_name}. Silakan hubungi kami untuk info lebih lanjut."
            update_mechanic_id_val = None
            update_completed_at_val = None
        
        set_clauses = ["status = ?"]
        params = [new_status]
        
        if new_status in ['Pending', 'Cancelled']:
            set_clauses.append("mechanic_id = NULL")
            set_clauses.append("completed_at = NULL")
        else:
            set_clauses.append("mechanic_id = ?")
            params.append(update_mechanic_id_val)
            if new_status == 'Completed':
                set_clauses.append("completed_at = ?")
                params.append(update_completed_at_val)
            else:
                set_clauses.append("completed_at = NULL")
            
        update_query = f"UPDATE bookings SET {', '.join(set_clauses)} WHERE id = ?"
        params.append(booking_id)

        cursor.execute(update_query, tuple(params))
        conn.commit()
        
        if notification_message:
            create_notification(client_user_id, notification_message, booking_id)
            
        flash(f'Status booking #{booking_id} berhasil diperbarui menjadi {new_status}.', 'success')
    except sqlite3.Error as e:
        print(f"Database error during status update: {e}")
        flash(f'Gagal memperbarui status booking: {e}', 'danger')
    except Exception as e:
        print(f"An unexpected error occurred during status update: {e}")
        flash(f'Terjadi kesalahan tidak terduga saat update status: {e}', 'danger')
    finally:
        conn.close()
    
    current_role = session.get('role')
    if current_role == 'master':
        return redirect(url_for('master_dashboard'))
    elif current_role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_role == 'mechanic':
        return redirect(url_for('mechanic_dashboard'))
    else:
        return redirect(url_for('dashboard'))


# --- Route untuk submit booking ---
@app.route('/submit-booking', methods=['POST'])
@login_required
@role_required('user', 'admin', 'master')
def submit_booking():
    user_id = session['user_id']

    if request.is_json:
        data = request.get_json()
    else:
        data = request.form

    required_fields = ['nama', 'email', 'telepon', 'layanan', 'lokasi_servis', 'tanggal']
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({'success': False, 'message': f'Field "{field}" is required.'}), 400

    nama = data['nama']
    email = data['email']
    telepon = data['telepon']
    layanan = data['layanan']
    lokasi_servis = data['lokasi_servis']
    alamat = data.get('alamat')
    tanggal = data['tanggal']
    jam = data.get('jam')
    keterangan = data.get('keterangan')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO bookings (user_id, nama, email, telepon, layanan, lokasi_servis, alamat, tanggal, jam, keterangan, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending')
        ''', (user_id, nama, email, telepon, layanan, lokasi_servis, alamat, tanggal, jam, keterangan))
        booking_id = cursor.lastrowid
        conn.commit()

        admin_mechanics = conn.execute("SELECT id FROM users WHERE role IN ('admin', 'master', 'mechanic')").fetchall()
        for am_user in admin_mechanics:
            create_notification(am_user['id'], f"Booking baru masuk dari {nama} (ID: {booking_id}) untuk layanan '{layanan}'.", booking_id)

        conn.close()
        return jsonify({'success': True, 'message': 'Booking berhasil disimpan!'}), 200
    except sqlite3.Error as e:
        print(f"Database error in submit_booking: {e}")
        return jsonify({'success': False, 'message': 'Terjadi kesalahan saat menyimpan booking ke database.'}), 500
    except Exception as e:
        print(f"An unexpected error occurred in submit_booking: {e}")
        return jsonify({'success': False, 'message': 'Terjadi kesalahan tidak terduga saat memproses booking.'}), 500

# Route opsional: Untuk melihat semua booking (hanya untuk debugging/admin, bisa dihapus)
@app.route('/bookings_all', methods=['GET'])
@login_required
@role_required('admin', 'master')
def get_all_bookings_json():
    conn = get_db_connection()
    bookings = conn.execute('SELECT b.*, u.username, u.role FROM bookings b JOIN users u ON b.user_id = u.id ORDER BY b.timestamp DESC').fetchall()
    conn.close()
    return jsonify([dict(booking) for booking in bookings])


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)