from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import Markup
import random
import string
import os
import re
import mysql.connector
from mysql.connector import Error

# Inisialisasi Flask
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Konfigurasi folder upload
UPLOAD_FOLDER = r'E:\PBL\e-passport\upload_file'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Menambahkan rute untuk mengakses file di folder upload_file
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    # Tentukan path folder tempat file disimpan
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Buat folder jika belum ada
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Fungsi untuk mendapatkan koneksi ke database
def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            database='e_passport'
        )
        if conn.is_connected():
            print("Berhasil terhubung ke database!")
        return conn
    except Error as e:
        print(f"Database Connection Error: {e}")
        return None

# Fungsi untuk hash password
def hashed_password(password):
    return generate_password_hash(password, method='pbkdf2:sha256')

# Fungsi untuk memeriksa file yang diunggah
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Fungsi untuk memastikan role pengguna yang benar
def check_role(expected_role):
    if 'role' not in session or session['role'] != expected_role:
        flash('Anda tidak memiliki akses ke halaman ini!', 'danger')
        return redirect(url_for('login_admin' if expected_role == 'admin' else 'login'))

# Halaman utama
@app.route('/')
def home():
    return render_template('index.html')

# Registrasi admin
@app.route('/register_admin', methods=['GET', 'POST'])
def register_admin():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        admin_token = request.form['admin_token']

        # Validasi token
        expected_token = "4dm1n!"
        if admin_token != expected_token:
            flash('Token tidak valid!', 'danger')
            return redirect(url_for('register_admin'))

        # Validasi input lainnya
        if not username or not password or not confirm_password:
            flash('Semua field harus diisi!', 'danger')
            return redirect(url_for('register_admin'))

        if password != confirm_password:
            flash('Password dan Konfirmasi Password tidak cocok!', 'danger')
            return redirect(url_for('register_admin'))

        password_pattern = re.compile(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$')
        if not password_pattern.match(password):
            flash('Password tidak memenuhi kriteria!', 'danger')
            return redirect(url_for('register_admin'))

        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        conn = get_db_connection()
        if conn is None:
            flash('Gagal menghubungkan ke database.', 'danger')
            return redirect(url_for('register_admin'))

        try:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO admins (username, password, role) VALUES (%s, %s, %s)',
                           (username, hashed_pw, 'admin'))
            conn.commit()
            flash('Registrasi admin berhasil! Silakan login.', 'success')
        except Error as e:
            flash(f'Kesalahan saat registrasi: {e}', 'danger')
        finally:
            cursor.close()
            conn.close()

        return redirect(url_for('login_admin'))

    return render_template('register_admin.html')

# Registrasi user
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validasi input kosong
        if not username or not password or not confirm_password:
            flash('Semua field harus diisi!', 'danger')
            return render_template('register.html', username=username)

        # Validasi password dan konfirmasi password
        if password != confirm_password:
            flash('Password dan Konfirmasi Password tidak cocok!', 'danger')
            return render_template('register.html', username=username)

        # Validasi password strength
        error_message = []
        if len(password) < 8:
            error_message.append('Password harus minimal 8 karakter!')

        if not re.search(r'[A-Z]', password):
            error_message.append('Password harus mengandung minimal 1 huruf besar!')

        if not re.search(r'[a-z]', password):
            error_message.append('Password harus mengandung minimal 1 huruf kecil!')

        if not re.search(r'\d', password):
            error_message.append('Password harus mengandung minimal 1 angka!')

        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            error_message.append('Password harus mengandung minimal 1 simbol!')

        if error_message:
            for msg in error_message:
                flash(msg, 'danger')
            return render_template('register.html', username=username)

        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        conn = get_db_connection()
        if conn is None:
            flash('Gagal menghubungkan ke database.', 'danger')
            return render_template('register.html', username=username)

        # Memproses penyimpanan ke database
        try:
            cursor = conn.cursor()

            # Memeriksa apakah username sudah ada
            cursor.execute('SELECT COUNT(*) FROM users WHERE username = %s', (username,))
            if cursor.fetchone()[0] > 0:
                flash('Username sudah digunakan, silakan gunakan username lain!', 'danger')
                return render_template('register.html', username=username, username_taken=True)

            # Insert data baru
            cursor.execute('INSERT INTO users (username, password, role) VALUES (%s, %s, %s)',
                           (username, hashed_pw, 'user'))
            conn.commit()
            flash('Registrasi berhasil! Silakan login.', 'success')
        except Error as e:
            flash(f'Terjadi kesalahan saat registrasi: {e}', 'danger')
        finally:
            cursor.close()
            conn.close()

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login_admin', methods=['GET', 'POST'])
def login_admin():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        # Validasi input
        if not username or not password:
            flash('Username dan password harus diisi!', 'danger')
            return redirect(url_for('login_admin'))

        conn = get_db_connection()
        if conn is None:
            flash('Gagal menghubungkan ke database.', 'danger')
            return redirect(url_for('login_admin'))

        try:
            cursor = conn.cursor(dictionary=True)
            # Mengambil data admin berdasarkan username
            cursor.execute('SELECT * FROM admins WHERE username = %s', (username,))
            admin = cursor.fetchone()

            if admin:
                # Memeriksa password hash
                if check_password_hash(admin['password'], password):
                    # Login berhasil
                    session['user_id'] = admin['id']
                    session['username'] = admin['username']
                    session['role'] = admin['role']
                    flash('Login admin berhasil!', 'success')
                    return redirect(url_for('admin_dashboard'))
                else:
                    flash('Password salah!', 'danger')
            else:
                flash('Username tidak ditemukan!', 'danger')
        except Error as e:
            flash(f'Terjadi kesalahan saat login: {e}', 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('login_admin.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        # Validasi input
        if not username or not password:
            flash('Username dan password harus diisi!', 'danger')
            return redirect(url_for('login'))

        conn = get_db_connection()
        if conn is None:
            flash('Gagal menghubungkan ke database.', 'danger')
            return redirect(url_for('login'))

        try:
            cursor = conn.cursor(dictionary=True)
            # Mengambil data user berdasarkan username
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()

            if user:
                # Memeriksa password hash
                if check_password_hash(user['password'], password):
                    # Login berhasil
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    flash('Login user berhasil!', 'success')
                    return redirect(url_for('form_pengajuan'))
                else:
                    flash('Password salah!', 'danger')
            else:
                flash('Username tidak ditemukan!', 'danger')
        except Error as e:
            flash(f'Terjadi kesalahan saat login: {e}', 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('login.html')

@app.route('/form_pengajuan', methods=['GET', 'POST'])
def form_pengajuan():
    if 'role' not in session or session['role'] != 'user':
        flash('Anda tidak memiliki akses ke halaman ini!', 'danger')
        return redirect(url_for('login'))

    user_id = session.get('user_id')  # Ambil ID atau username pengguna dari sesi

    # Periksa apakah pengguna sudah mengajukan sebelumnya
    conn = get_db_connection()
    if conn is None:
        flash('Gagal menghubungkan ke database.', 'danger')
        return redirect(url_for('form_pengajuan'))

    try:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM pengajuan WHERE user_id = %s', (user_id,))
        pengajuan_count = cursor.fetchone()[0]
        if pengajuan_count > 0:
            # Tampilkan halaman alert_redirect.html
            return render_template('alert_redirect.html', 
                                   message='Anda sudah pernah mengajukan form sebelumnya.', 
                                   redirect_url=url_for('tracking_pengajuan'))
    except Error as e:
        flash(f'Kesalahan saat memeriksa data: {e}', 'danger')
        return redirect(url_for('form_pengajuan'))
    finally:
        cursor.close()

    if request.method == 'POST':
        form_data = {key: request.form[key].strip() for key in request.form.keys()}
        ktp_file = request.files['ktp_file']

        if ktp_file and allowed_file(ktp_file.filename):
            # Ambil NIK dari form
            nik = form_data.get('nik')
            if not nik:
                flash('NIK tidak boleh kosong!', 'danger')
                return redirect(url_for('form_pengajuan'))

            # Ganti nama file sesuai format NIK_KTP
            file_extension = ktp_file.filename.rsplit('.', 1)[1].lower()
            new_filename = f"{nik}_KTP.{file_extension}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)

            # Simpan file
            ktp_file.save(file_path)
            form_data['ktp_file_path'] = file_path

            try:
                cursor = conn.cursor()
                cursor.execute(''' 
                    INSERT INTO pengajuan (user_id, nik, nama, jenis_kelamin, tempat_lahir, tanggal_lahir, agama, alamat, nomor_telepon, email, ktp_file_path, status) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (user_id, form_data['nik'], form_data['nama'], form_data['jenis_kelamin'], form_data['tempat_lahir'], 
                      form_data['tanggal_lahir'], form_data['agama'], form_data['alamat'], form_data['nomor_telepon'], 
                      form_data['email'], form_data['ktp_file_path'], 'Menunggu Verifikasi'))
                conn.commit()
                flash('Pengajuan berhasil diajukan.', 'success')
            except Error as e:
                flash(f'Kesalahan saat menyimpan data: {e}', 'danger')
            finally:
                cursor.close()
                conn.close()

            return redirect(url_for('tracking_pengajuan'))
        else:
            flash('File tidak valid atau tidak sesuai format.', 'danger')

    return render_template('form_pengajuan.html')

@app.route('/tracking_pengajuan', methods=['GET', 'POST'])
def tracking_pengajuan():
    if 'role' not in session or session['role'] != 'user':
        flash('Anda tidak memiliki akses ke halaman ini!', 'danger')
        return redirect(url_for('login'))

    pengajuan = None

    # Generate captcha jika belum ada
    if 'captcha' not in session:
        session['captcha'] = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

    if request.method == 'POST':
        nik = request.form['nik'].strip()  # Pastikan input NIK tidak kosong
        input_captcha = request.form['captcha'].strip()  # Input dari pengguna

        # Validasi NIK
        if not nik.isdigit() or len(nik) != 16:
            flash('NIK harus berupa 16 digit angka.', 'danger')
            session['captcha'] = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))  # Reset captcha
            return redirect(url_for('tracking_pengajuan'))

        # Validasi captcha
        if input_captcha != session['captcha']:
            flash('Captcha tidak sesuai. Silakan coba lagi!', 'danger')
            session['captcha'] = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))  # Reset captcha
            return redirect(url_for('tracking_pengajuan'))

        # Jika validasi input berhasil, lanjutkan ke pengecekan database
        conn = get_db_connection()
        if conn is None:
            flash('Gagal menghubungkan ke database.', 'danger')
            return redirect(url_for('tracking_pengajuan'))

        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT * FROM pengajuan WHERE nik = %s', (nik,))
            pengajuan = cursor.fetchone()
        except Error as e:
            flash(f'Kesalahan saat mengambil data: {e}', 'danger')
        finally:
            cursor.close()
            conn.close()

        if not pengajuan:
            flash('Data tidak ditemukan. Pastikan NIK yang Anda masukkan benar.', 'danger')

        # Reset captcha setelah setiap submit, baik berhasil atau gagal
        session['captcha'] = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

    return render_template('tracking_pengajuan.html', pengajuan=pengajuan, captcha=session['captcha'])

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'role' not in session or session['role'] != 'admin':
        flash('Anda tidak memiliki akses ke halaman ini!', 'danger')
        return redirect(url_for('login_admin'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # MengMengambil total pengajuan dan statistik lainnya
    cursor.execute('SELECT COUNT(*) AS total FROM pengajuan')
    total_pengajuan = cursor.fetchone()['total']

    cursor.execute('SELECT COUNT(*) AS menunggu FROM pengajuan WHERE status = %s', ('Menunggu Verifikasi',))
    menunggu_verifikasi = cursor.fetchone()['menunggu']

    cursor.execute('SELECT COUNT(*) AS diverifikasi FROM pengajuan WHERE status = %s', ('Telah Diverifikasi',))
    diverifikasi = cursor.fetchone()['diverifikasi']

    cursor.execute('SELECT COUNT(*) AS selesai FROM pengajuan WHERE status = %s', ('Selesai',))
    selesai = cursor.fetchone()['selesai']

    # MengMengambil daftar pengajuan untuk ditampilkan
    cursor.execute('SELECT * FROM pengajuan')
    daftar_pengajuan = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('admin_dashboard.html', 
                           total_pengajuan=total_pengajuan, 
                           menunggu_verifikasi=menunggu_verifikasi, 
                           diverifikasi=diverifikasi, 
                           selesai=selesai,
                           daftar_pengajuan=daftar_pengajuan)


@app.route('/admin/verifikasi/<int:id>', methods=['GET', 'POST'])
def verifikasi(id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Anda tidak memiliki akses ke halaman ini!', 'danger')
        return redirect(url_for('login_admin'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)  # Pastikan menggunakan dictionary=True

    # Jika metode adalah POST (untuk memperbarui status)
    if request.method == 'POST':
        # Mengupdate status menjadi "Telah Diverifikasi"
        cursor.execute('UPDATE pengajuan SET status = %s WHERE id = %s', ('Telah Diverifikasi', id))
        
        # Menambahkan tanggal jadwal foto (jika ada)
        tanggal_foto = request.form.get('tanggal_jadwal_foto')  # Dapatkan tanggal dari form
        if tanggal_foto:
            cursor.execute('UPDATE pengajuan SET tanggal_jadwal_foto = %s WHERE id = %s', (tanggal_foto, id))

        conn.commit()
        cursor.close()
        conn.close()

        flash('Status berhasil diperbarui!', 'success')
        return redirect(url_for('admin_dashboard'))

    # Jika menggunakan GET, ambil data pengajuan berdasarkan ID
    cursor.execute('SELECT * FROM pengajuan WHERE id = %s', (id,))
    pengajuan = cursor.fetchone()  # Mengambil satu hasil pengajuan sebagai dictionary
    cursor.close()
    conn.close()

    if not pengajuan:
        flash('Pengajuan tidak ditemukan!', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Jika file KTP diunggah, tampilkan path-nya
    ktp_file_path = pengajuan.get('ktp_file_path')  # Menggunakan .get() karena pengajuan adalah dictionary

    return render_template('verifikasi.html', pengajuan=pengajuan, ktp_file_path=ktp_file_path)

@app.route('/admin_dashboard/filter/<status>')
def admin_dashboard_filter(status):
    if 'role' not in session or session['role'] != 'admin':
        flash('Anda tidak memiliki akses ke halaman ini!', 'danger')
        return redirect(url_for('login_admin'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Mengambil total pengajuan dan statistik lainnya
    cursor.execute('SELECT COUNT(*) AS total FROM pengajuan')
    total_pengajuan = cursor.fetchone()['total']

    cursor.execute('SELECT COUNT(*) AS menunggu FROM pengajuan WHERE status = %s', ('Menunggu Verifikasi',))
    menunggu_verifikasi = cursor.fetchone()['menunggu']

    cursor.execute('SELECT COUNT(*) AS diverifikasi FROM pengajuan WHERE status = %s', ('Telah Diverifikasi',))
    diverifikasi = cursor.fetchone()['diverifikasi']

    cursor.execute('SELECT COUNT(*) AS selesai FROM pengajuan WHERE status = %s', ('Selesai',))
    selesai = cursor.fetchone()['selesai']

    # Mengambil daftar pengajuan berdasarkan filter status
    cursor.execute('SELECT * FROM pengajuan WHERE status = %s', (status,))
    daftar_pengajuan = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('admin_dashboard.html',
                           total_pengajuan=total_pengajuan,
                           menunggu_verifikasi=menunggu_verifikasi,
                           diverifikasi=diverifikasi,
                           selesai=selesai,
                           daftar_pengajuan=daftar_pengajuan,
                           filter_status=status)

@app.route('/admin_dashboard/filter/all')
def admin_dashboard_all():
    if 'role' not in session or session['role'] != 'admin':
        flash('Anda tidak memiliki akses ke halaman ini!', 'danger')
        return redirect(url_for('login_admin'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Mengambil total pengajuan dan statistik lainnya
    cursor.execute('SELECT COUNT(*) AS total FROM pengajuan')
    total_pengajuan = cursor.fetchone()['total']

    cursor.execute('SELECT COUNT(*) AS menunggu FROM pengajuan WHERE status = %s', ('Menunggu Verifikasi',))
    menunggu_verifikasi = cursor.fetchone()['menunggu']

    cursor.execute('SELECT COUNT(*) AS diverifikasi FROM pengajuan WHERE status = %s', ('Telah Diverifikasi',))
    diverifikasi = cursor.fetchone()['diverifikasi']

    cursor.execute('SELECT COUNT(*) AS selesai FROM pengajuan WHERE status = %s', ('Selesai',))
    selesai = cursor.fetchone()['selesai']

    # Mengambil semua daftar pengajuan tanpa filter
    cursor.execute('SELECT * FROM pengajuan')
    daftar_pengajuan = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('admin_dashboard.html',
                           total_pengajuan=total_pengajuan,
                           menunggu_verifikasi=menunggu_verifikasi,
                           diverifikasi=diverifikasi,
                           selesai=selesai,
                           daftar_pengajuan=daftar_pengajuan,
                           filter_status=None)  # Tidak ada filter

@app.route('/admin/detail_pengajuan/<int:id>', methods=['GET', 'POST'])
def detail_pengajuan(id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Anda tidak memiliki akses ke halaman ini!', 'danger')
        return redirect(url_for('login_admin'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Mengambil data pengajuan berdasarkan ID
    cursor.execute('SELECT * FROM pengajuan WHERE id = %s', (id,))
    pengajuan = cursor.fetchone()

    if not pengajuan:
        flash('Pengajuan tidak ditemukan!', 'danger')
        return redirect(url_for('admin_dashboard'))

    # URL untuk file KTP dengan proteksi
    secure_ktp_file_url = None
    if pengajuan.get('ktp_file_path'):
        filename = os.path.basename(pengajuan['ktp_file_path'])
        secure_ktp_file_url = url_for('secure_uploaded_file', filename=filename)

    if request.method == 'POST':
        status_baru = request.form['status']
        tanggal_foto = request.form.get('tanggal_jadwal_foto')

        cursor.execute('UPDATE pengajuan SET status = %s WHERE id = %s', (status_baru, id))
        if status_baru == 'Telah Diverifikasi' and tanggal_foto:
            cursor.execute('UPDATE pengajuan SET tanggal_jadwal_foto = %s WHERE id = %s', (tanggal_foto, id))

        conn.commit()
        flash('Status pengajuan berhasil diperbarui!', 'success')
        return redirect(url_for('admin_dashboard'))

    cursor.close()
    conn.close()

    return render_template(
        'detail_pengajuan.html',
        pengajuan=pengajuan,
        secure_ktp_file_url=secure_ktp_file_url
    )

@app.route('/secure_uploads/<filename>', methods=['GET', 'POST'])
def secure_uploaded_file(filename):
    # Periksa apakah admin sudah login
    if 'role' not in session or session['role'] != 'admin':
        flash('Anda tidak memiliki akses ke file ini!', 'danger')
        return redirect(url_for('login_admin'))

    message = None  # Variabel untuk menyimpan pesan kesalahan

    # Jika POST, verifikasi password admin
    if request.method == 'POST':
        password = request.form['password']

        conn = get_db_connection()
        if conn is None:
            flash('Gagal menghubungkan ke database.', 'danger')
            return redirect(url_for('login_admin'))

        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT * FROM admins WHERE id = %s', (session['user_id'],))
            admin = cursor.fetchone()
            if admin and check_password_hash(admin['password'], password):
                # Password benar, kirimkan file
                return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
            else:
                message = 'Password salah! Silakan coba lagi.'
        except Error as e:
            message = f'Kesalahan saat memverifikasi: {e}'
        finally:
            cursor.close()
            conn.close()

    # Jika GET atau password salah, tampilkan form login
    return render_template('confirm_password.html', filename=filename, message=message)

@app.route('/admin/selesai/<int:id>', methods=['GET', 'POST'])
def selesai(id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Anda tidak memiliki akses ke halaman ini!', 'danger')
        return redirect(url_for('login_admin'))

    # Jika menggunakan POST, update status menjadi 'Selesai'
    if request.method == 'POST':
        conn = get_db_connection()
        cursor = conn.cursor()

        # Update status menjadi "Selesai"
        cursor.execute('UPDATE pengajuan SET status = %s WHERE id = %s', ('Selesai', id))

        conn.commit()
        cursor.close()
        conn.close()

        flash('Pengajuan telah selesai!', 'success')
        return redirect(url_for('admin_dashboard_filter', status='Selesai'))

    # Jika menggunakan GET, ambil data pengajuan berdasarkan ID
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)  # Menambahkan dictionary=True untuk hasil yang berbentuk dictionary
    cursor.execute('SELECT * FROM pengajuan WHERE id = %s', (id,))
    pengajuan = cursor.fetchone()
    cursor.close()
    conn.close()

    if not pengajuan:
        flash('Pengajuan tidak ditemukan!', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Jika file KTP diunggah, tampilkan path-nya
    ktp_file_path = pengajuan.get('ktp_file_path')

    return render_template('selesai.html', pengajuan=pengajuan, ktp_file_path=ktp_file_path)

# Logout user
@app.route('/logout')
def logout():
    session.clear()
    flash('Anda berhasil logout.', 'success')
    return redirect(url_for('login'))

# Menu dinamis untuk header
@app.context_processor
def inject_menu():
    if 'role' not in session:
        menu = [
            {'name': 'Register', 'url': url_for('register')},
            {'name': 'Login', 'url': url_for('login')}
        ]
    elif session['role'] == 'user':
        menu = [
            {'name': 'Form Pengajuan', 'url': url_for('form_pengajuan')},
            {'name': 'Tracking Pengajuan', 'url': url_for('tracking_pengajuan')},
            {'name': 'Logout', 'url': url_for('logout')}
        ]
    elif session['role'] == 'admin':
        menu = [
            {'name': 'Admin Dashboard', 'url': url_for('admin_dashboard')},
            {'name': 'Logout', 'url': url_for('logout')}
        ]
    else:
        menu = []
    return {'menu': menu}

# Role-Based Access Control
def require_role(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'role' not in session or session['role'] != role:
                flash('Unauthorized access!', 'danger')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return wrapper
    return decorator

# Validasi dan Sanitasi Input
def sanitize_input(input_string):
    return Markup(input_string).striptags()

# Fungsi untuk menjalankan aplikasi
if __name__ == '__main__':
    app.run(debug=True)
