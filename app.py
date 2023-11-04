import pymysql
import re
import requests
import hashlib
import time
import smtplib
import random
import string
import subprocess
import sys
import os
import pytz
import logging
import pymysql.cursors
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory, send_file
from flask_socketio import SocketIO
from flask_session import Session
from datetime import datetime, timedelta
from flask_cors import CORS
from flask_sslify import SSLify
from flask_bcrypt import Bcrypt
from decouple import config
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
import base64
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage



app = Flask(__name__ )
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
app.permanent_session_lifetime = timedelta(minutes=2)  # Sesinya berakhir dalam 2 menit tidak aktif

load_dotenv()
app.secret_key = os.getenv("SECRET_KEY")
SECRET_KEY = config('SECRET_KEY')
app.config['DEBUG'] = True
ssl = SSLify(app)
socketio = SocketIO(app)
cors = CORS(app)
bcrypt = Bcrypt()

# Fungsi untuk memeriksa dan menginstal dependensi
def check_dependencies():
    try:
        import flask
    except ImportError:
        print("Flask belum terinstal. Menginstal Flask...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    else:
        print("Semua kebutuhan sudah terinstal.")

# Panggil fungsi untuk memeriksa dependensi
check_dependencies()



# Membuat folder logs jika belum ada
if not os.path.exists('logs'):
    os.makedirs('logs')


# Membuat folder logs/aktivitas_user jika belum ada
if not os.path.exists('logs/aktivitas_user'):
    os.makedirs('logs/aktivitas_user')

# Inisialisasi logger
log_folder = 'logs/visit_ip'
if not os.path.exists(log_folder):
    os.makedirs(log_folder)

log_file = os.path.join(log_folder, 'visit.log')
handler = RotatingFileHandler(log_file, maxBytes=100000, backupCount=1)  # Maksimum 100KB per file, maksimum 1 backup file
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

logger = logging.getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


# Koneksi ke database
conn = pymysql.connect(
    host=config('DB_HOST'),
    user=config('DB_USER'),
    password=config('DB_PASSWORD'),
    database=config('DB_NAME'),
    cursorclass=pymysql.cursors.DictCursor
)

def get_db_connection():
    connection = pymysql.connect(
        host=config('DB_HOST'),
        user=config('DB_USER'),
        password=config('DB_PASSWORD'),
        database=config('DB_NAME'),
        cursorclass=pymysql.cursors.DictCursor
    )
    return connection




    # Inisialisasi logger untuk log permintaan GET
get_logger = logging.getLogger('get_logger')
get_logger.setLevel(logging.INFO)
get_handler = logging.FileHandler('logs/get_logs/get_requests.log')
get_formatter = logging.Formatter('%(asctime)s - %(message)s')
get_handler.setFormatter(get_formatter)
get_logger.addHandler(get_handler)

# Inisialisasi logger untuk log aktivitas klaim point
claim_logger = logging.getLogger('claim_logger')
claim_logger.setLevel(logging.INFO)
claim_handler = logging.FileHandler('logs/aktivitas_user/claim_point.log')
claim_formatter = logging.Formatter('%(asctime)s - %(message)s')
claim_handler.setFormatter(claim_formatter)
claim_logger.addHandler(claim_handler)

# Inisialisasi logger untuk log aktivitas redeem point
redeem_logger = logging.getLogger('redeem_logger')
redeem_logger.setLevel(logging.INFO)
redeem_handler = logging.FileHandler('logs/aktivitas_user/redeem_point.log')
redeem_formatter = logging.Formatter('%(asctime)s - %(message)s')
redeem_handler.setFormatter(redeem_formatter)
redeem_logger.addHandler(redeem_handler)

# Fungsi untuk inisialisasi logger kunjungan
def init_visit_logger():
    visit_logger = logging.getLogger('visit_logger')
    visit_logger.setLevel(logging.INFO)
    visit_handler = logging.FileHandler('logs/visit_ip/visit.log')
    visit_formatter = logging.Formatter('%(asctime)s - IP: %(ip)s - %(message)s')
    visit_handler.setFormatter(visit_formatter)
    visit_logger.addHandler(visit_handler)
    return visit_logger

# Konfigurasi logger untuk menyimpan log ke file
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
tele_log = logging.getLogger('tele_log')
tele_log.setLevel(logging.INFO)
log_file = 'logs/tele_log/log_tele.log'
file_handler = logging.FileHandler(log_file)
file_handler.setFormatter(log_formatter)
tele_log.addHandler(file_handler)

visit_logger = init_visit_logger()

# Struktur data untuk melacak kunjungan dari setiap IP
visit_count = {}


@app.route('/log-visit', methods=['POST'])
def log_visit():
    data = request.get_json()
    user_ip = data.get('ip')
    visited_page = request.referrer  # Mendapatkan URL halaman sebelumnya yang dikunjungi oleh pengguna

    # Periksa apakah referrer ada dan tidak sama dengan halaman sebelumnya di session
    if visited_page and visited_page != session.get('previous_page'):
        # Format pesan log sesuai keinginan
        log_message = 'User dengan IP {} mengunjungi halaman {}'.format(user_ip, visited_page)
        
        # Catat log dengan format yang diinginkan
        visit_logger.info(log_message, extra={'ip': user_ip})
        
        # Simpan referrer sebagai halaman sebelumnya
        session['previous_page'] = visited_page

        # Periksa apakah IP sudah ada dalam daftar kunjungan
        if user_ip in visit_count:
            visit_count[user_ip] += 1
        else:
            visit_count[user_ip] = 1

    return 'Visit logged successfully'



@app.route('/get-visit-count')
def get_visit_count():
    # Kirim data kunjungan ke halaman admin
    return jsonify(visit_count)




# Fungsi untuk menangani kesalahan 404
@app.errorhandler(404)
def not_found(error):
    print(f"Error occurred: {error}")  # Menggunakan variabel error untuk mencetak informasi kesalahan
    return send_from_directory('static/404', '404.html'), 404

# Ini web pertama kali dimuat
@app.route('/')
def serve_index():
        # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    # Periksa apakah pengguna sudah login (gunakan session/cookie)
    if 'username' in session:
        # Jika pengguna sudah login, arahkan ke halaman dashboard
        return redirect(url_for('dashboard'))
    else:
        # Jika pengguna belum login, kirimkan file index.html dari folder 'home'

        return send_file('home/index.html')  # Mengirimkan file index.html


# Ini kalo permintaan /index.html akan kembali ke /
@app.route('/index.html')
def redirect_to_index():
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    return redirect(url_for('serve_index'))


# Fungsi untuk rute /about.html
@app.route('/about')
def serve_about():
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    if 'username' in session:
        return redirect(url_for('serve_index'))
    else:
        return send_file('home/about.html')  # Mengirimkan file login.html dari folder 'login'

# Fungsi untuk rute /privacy.html
@app.route('/privacy.html')
def serve_privacy():
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    if 'username' in session:
        return redirect(url_for('serve_index'))
    else:
        return send_file('home/privacy.html')  # Mengirimkan file privacy.html dari folder 'home'

# Fungsi untuk rute /dashboard.html
@app.route('/dashboard.html')
def serve_dashboard():
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    if 'username' in session:
        return render_template('main/dashboard.html')
    else:
        return redirect(url_for('serve_index'))

# Fungsi untuk rute /login.html
@app.route('/login.html')
def serve_login():
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    return render_template('login/login.html')

# Fungsi untuk rute /signup.html
@app.route('/signup.html')
def serve_signup():
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    return render_template('signup/signup.html')

# Fungsi untuk rute /redeem.html
@app.route('/redeem.html')
def serve_redeem():
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    if 'username' in session:
        return render_template('main/redeem.html')
    else:
        return render_template('login/login.html')


# Fungsi untuk rute /claim_point.html
@app.route('/claim_point.html')
def serve_claim_point():
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    if 'username' in session:
        return render_template('main/claim_point.html')
    else:
        return render_template('login/login.html')

# Fungsi untuk rute /logout.html
@app.route('/logout.html')
def serve_logout():
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    # Hapus session/cookie untuk menandakan pengguna sudah logout
    session.pop('username', None)
    # Arahkan pengguna kembali ke halaman utama
    return redirect(url_for('serve_index'))


# Fungsi untuk rute /forgot_password.html
@app.route('/forgot_password.html')
def serve_forgot_password():
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    return render_template('login/forgot_password.html')

# Tentukan direktori tempat file statis disimpan
static_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static')



# Fungsi untuk rute /forgot_password.html
@app.route('/forgot_username.html')
def serve_forgot_username():
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    return render_template('login/forgot_username.html')

# Tentukan direktori tempat file statis disimpan
static_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static')


# Route untuk file gambar di images/
@app.route('/static/images/<filename>')
def serve_images(filename):
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    file_path = os.path.join(static_dir, 'images', filename)
    if os.path.isfile(file_path):
        return send_from_directory(os.path.join(static_dir, 'images'), filename)
    else:
        return "File not found", 404

# Rute untuk menangani permintaan favicon.ico
@app.route('/favicon.ico')
def favicon():
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    # Mengirimkan favicon.ico dari direktori "images" di dalam direktori "static"
    return send_from_directory(os.path.join(static_dir, 'images/favicon'), 'ireload.ico', mimetype='image/vnd.microsoft.icon')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not request.form.get('agree_tnc'):
            flash('Harap setujui T&C sebelum melanjutkan.')
            return redirect(url_for('signup'))

        is_valid_username_result, username_message = is_valid_username(username)
        is_valid_password_result, password_message = is_valid_password(password)

        if not_a_valid_username(username):
            flash('Username tidak valid. Pastikan username dimulai dengan huruf besar dan hanya mengandung huruf besar, huruf kecil, dan angka.')
        if not is_valid_username_result:
            flash(username_message)
        elif not is_valid_password_result:
            flash(password_message)

        else:
            # Dapatkan koneksi dan objek cursor
            connection = get_db_connection()
            cursor = connection.cursor()

            cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
            existing_user = cursor.fetchone()

            if existing_user:
                flash(f'Username {username} sudah ada. Silakan pilih username lain.')
            else:
                # Validasi password
                if not is_valid_password(password):
                    flash('Password harus memiliki panjang antara 5 dan 11 karakter.')
                else:
                    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                    cursor.execute("INSERT INTO users (username, password, points) VALUES (%s, %s, %s)", (username, hashed_password, 500))
                    connection.commit()

                    user_id = cursor.lastrowid

                    points_earned = 500
                    transaction_type = 'Bonus Sign Up +'

                    cursor.execute("INSERT INTO point_history (user_id, points_change, transaction_type) VALUES (%s, %s, %s)", (user_id, points_earned, transaction_type))
                    connection.commit()

                    flash(f'Silahkan login menggunakan username Anda: {username} & password Anda.')

            # Tutup kursor dan koneksi saat selesai
            cursor.close()
            connection.close()

            return redirect(url_for('signup'))

    return render_template('signup/signup.html')



def is_valid_password(password):
    # Validasi panjang minimal 5 dan maksimal 11 karakter
    if not (5 <= len(password) <= 20):
        return False, "Password harus memiliki panjang antara 5 dan 11 karakter. Contoh :ReloadCell123@!@"
    # Validasi huruf besar
    if not any(char.isupper() for char in password):
        return False, "Password harus mengandung setidaknya satu huruf besar. Contoh :ReloadCell123@!@"
    # Validasi huruf kecil
    if not any(char.islower() for char in password):
        return False, "Password harus mengandung setidaknya satu huruf kecil. Contoh :ReloadCell123@!@"
    # Validasi angka
    if not any(char.isdigit() for char in password):
        return False, "Password harus mengandung setidaknya satu angka. Contoh :ReloadCell123@!@"
    # Validasi karakter khusus
    special_characters = "!@#$%^&*()_+={}|:;'<>,.?/"
    if not any(char in special_characters for char in password):
        return False, "Password harus mengandung setidaknya satu karakter khusus. Contoh :ReloadCell123@!@ "
    # Password valid
    return True, "Password valid."


def is_valid_username(username):
    # Ekspresi reguler untuk memeriksa validitas username
    pattern = r"^[a-zA-Z0-9_-]{5,20}$"
    # Validasi username tidak boleh mengandung spasi
    if " " in username:
        return False, "Username tidak boleh mengandung spasi. Contoh : ReloadCell0910"
    # Validasi username tidak boleh mengandung karakter yang tidak dapat ditampilkan
    if not username.isprintable():
        return False, "Username harus hanya mengandung karakter yang dapat ditampilkan. Contoh : ReloadCell0910"
    # Validasi username tidak boleh mengandung karakter yang dapat digunakan untuk serangan SQL injection
    if re.search(r"[;'`]", username):
        return False, "Username tidak boleh mengandung karakter khusus seperti ';`. Contoh : ReloadCell0910"
    # Validasi menggunakan ekspresi reguler
    if not re.match(pattern, username):
        return False, "Username harus terdiri dari 5-20 karakter, hanya huruf besar, huruf kecil, angka, '_', dan '-'. Contoh : ReloadCell0910"
    # Username valid, cetak ke konsol aplikasi
    return True, "Username valid."


def not_a_valid_username(username):
    is_valid, message = is_valid_username(username)
    if not is_valid:
        print(f"Input username: {username} Tidak Valid. Alasan: {message}")
    return not is_valid


# Fungsi untuk mengirim email konfirmasi login
def send_login_confirmation_email(username, email):
    subject = 'Login Confirmation'
    template_path = 'templates/login_confirmation/login_confirmation.html'

    # Mendapatkan alamat IP pengunjung
    ip_address = request.remote_addr

    # Mendapatkan informasi lokasi berdasarkan alamat IP
    location_info = get_location_info(ip_address)

    # Membaca template HTML
    with open(template_path, 'r') as file:
        html_template = file.read()

    # Mengganti placeholders dalam template dengan nilai yang sesuai
    html_template = html_template.replace('{{ username }}', username)
    html_template = html_template.replace('{{ ip_address }}', location_info)

    # Membuat pesan email
    msg = MIMEMultipart()
    msg['From'] = os.getenv('SENDER_EMAIL')
    msg['To'] = email
    msg['Subject'] = subject

    # Melampirkan versi HTML dari email
    msg.attach(MIMEText(html_template, 'html'))

    # Membaca gambar/logo dan melampirkannya
    with open('templates/lupa_username/logo_1.png', 'rb') as image_file:
        logo_image = MIMEImage(image_file.read())
        logo_image.add_header('Content-ID', '<logo>')
        msg.attach(logo_image)

    # Mengirim email melalui SMTP server
    server = smtplib.SMTP(os.getenv('SMTP_SERVER'), int(os.getenv('SMTP_PORT')))
    server.starttls()
    server.login(os.getenv('SENDER_EMAIL'), os.getenv('SENDER_PASSWORD'))
    server.sendmail(os.getenv('SENDER_EMAIL'), email, msg.as_string())
    server.quit()


# Fungsi untuk mendapatkan alamat email pengguna berdasarkan user_id
def get_user_email(user_id):
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM users_profile WHERE user_id=%s", (user_id,))
    result = cursor.fetchone()
    return result['email'] if result else None


#login users
@app.route('/login', methods=['GET', 'POST'])
def login():
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()

        if user:
            if user['status'] == 'active':
                hashed_password = user['password']  # Ambil kata sandi yang telah di-hash dari database
                if bcrypt.check_password_hash(hashed_password, password):
                    session['username'] = user['username']
                    session['loggedin'] = True  # Tandai pengguna telah login

                    # Kirim email konfirmasi login
                    email = get_user_email(user['id'])
                    send_login_confirmation_email(username, email)

                    # Catat alamat IP, lokasi, dan waktu login
                    ip_address = request.remote_addr
                    location_info = get_location_info(ip_address)
                    login_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    log_message = f"User '{username}' logged in from IP: {ip_address}, Location: {location_info}, Time: {login_time}"

                    # Tampilkan pesan Login Berhasil anda akan diarahkan ke halaman dashboard dalam hitungan mundur dari 5 dengan dinamis
                    flash('Login Berhasil! Anda akan diarahkan ke halaman dashboard dalam hitungan mundur dari 5 detik.', 'success')

                    # Redirect ke halaman login untuk menampilkan pesan login berhasil dengan hitungan mundur
                    return redirect(url_for('login'))
                else:
                    error_message = 'Username atau password salah. Periksa kembali username dan password Anda.'
            else:
                error_message = 'Akun Anda tidak aktif. Hubungi administrator.'
        else:
            error_message = 'Username atau password salah. Periksa kembali username dan password Anda.'

        flash(error_message, 'error')  # Gunakan flash untuk menyimpan pesan kesalahan
        return render_template('login/login.html')

    return render_template('login/login.html')

# Fungsi untuk mendapatkan informasi lokasi berdasarkan alamat IP
def get_location_info(ip_address):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)  # Timeout set to 5 seconds
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                location_info = f"{data['city']}, {data['regionName']}, {data['country']}"
                return location_info
            else:
                return 'Unknown'
        else:
            return 'Unknown'
    except Exception as e:
        return 'Unknown'





# Fungsi untuk generate reset token
def generate_reset_token(length=8):
    characters = string.ascii_letters + string.digits
    reset_token = ''.join(random.choice(characters) for i in range(length))
    return reset_token



reset_tokens = {}  # Dictionary to store reset tokens and their expiration time

# Fungsi untuk send token dengan template HTML, logo, dan link
@app.route('/send-token', methods=['POST'])
def send_token():
    data = request.get_json()
    email = data.get('email')

    if email:
        # Memeriksa apakah pengguna sudah memiliki token reset yang aktif
        if email in reset_tokens and reset_tokens[email]['expiration_time'] > datetime.now():
            return jsonify(success=False, message='Anda sudah memiliki permintaan reset password yang aktif. Cek email Anda untuk petunjuk lebih lanjut.')
        
        # Mendapatkan koneksi ke database
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                # Cari email dalam tabel users_profile
                sql = "SELECT email, full_name FROM users_profile WHERE email = %s"
                cursor.execute(sql, (email,))
                user = cursor.fetchone()
                if user:
                    reset_token = generate_reset_token()
                    reset_tokens[email] = {
                        'token': reset_token,
                        'expiration_time': datetime.now() + timedelta(minutes=1)  # Token kedaluwarsa dalam 1 jam
                    }

                    # URL untuk mereset password
                    expires = int((datetime.now() + timedelta(minutes=1)).timestamp())
                    reset_link = f'http://localhost:5000/forgot_password.html?token={reset_token}&email={email}&expires={expires}'

                    # Kirim reset token ke email pengguna dengan template HTML, logo, dan link
                    subject = f'Berikut Kode Verifikasi Anda : {reset_token}'
                    template_path = 'templates/lupa_password/reset_token.html'
                    logo_path = 'templates/lupa_username/logo_1.png'  # Path file logo
                    replacements = {
                        'full_name': user['full_name'],
                        'reset_token': reset_token,
                        'reset_link': reset_link
                    }

                    if send_email_token_with_template_and_logo_and_link(subject, email, template_path, replacements, logo_path, reset_link):
                        return jsonify(success=True, message='Email dengan petunjuk pengaturan ulang password telah dikirim.')
                    else:
                        return jsonify(success=False, message='Terjadi kesalahan saat mengirim email. Silakan coba lagi nanti.')
                else:
                    return jsonify(success=False, message='Email tidak ditemukan. Pastikan Anda memasukkan email yang benar.')
        except Exception as e:
            print(f"Error: {e}")
            return jsonify(success=False, message='Terjadi kesalahan saat mengirim email. Silakan coba lagi nanti.')
        finally:
            # Tutup koneksi setelah penggunaan
            connection.close()

    return jsonify(success=False, message='Terjadi kesalahan. Pastikan email valid.')









# Fungsi untuk mendapatkan full_name berdasarkan email dari basis data
def get_full_name_by_email(email):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            sql_get_full_name = "SELECT full_name FROM users_profile WHERE email = %s"
            cursor.execute(sql_get_full_name, (email,))
            result = cursor.fetchone()
            if result:
                return result['full_name']
            else:
                return None
    except Exception as e:
        print(f"Error: {e}")
        return None
    finally:
        # Tutup koneksi setelah penggunaan
        connection.close()


# Fungsi untuk reset password
@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    token = data.get('token')
    new_password = data.get('new_password')

    if email and token and new_password:
        # Periksa apakah token cocok dengan yang ada dalam dictionary reset_tokens
        if email in reset_tokens and reset_tokens[email]['token'] == token:
            # Periksa apakah token masih berlaku
            if reset_tokens[email]['expiration_time'] > datetime.now():
                # Hash password baru
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

                # Dapatkan user_id berdasarkan email dari tabel users_profile
                connection = get_db_connection()
                try:
                    with connection.cursor() as cursor:
                        sql_get_user_id = "SELECT user_id FROM users_profile WHERE email = %s"
                        cursor.execute(sql_get_user_id, (email,))
                        user_id = cursor.fetchone()

                        # Update password pengguna dengan password yang dihash
                        if user_id:
                            sql_update_password = "UPDATE users SET password = %s WHERE id = %s"
                            cursor.execute(sql_update_password, (hashed_password, user_id['user_id']))
                            connection.commit()
                            del reset_tokens[email]  # Hapus token yang sudah digunakan

                            # Panggil fungsi untuk mengirim email konfirmasi
                            full_name = get_full_name_by_email(email)
                            if full_name:
                                send_password_changed_email(email, full_name)
                            else:
                                return jsonify(success=False, message='Eror.')

                            return jsonify(success=True, message='Selamat {{username}} Password Anda berhasil direset.')
                        else:
                            return jsonify(success=False, message='Email tidak valid.')
                except Exception as e:
                    print(f"Error: {e}")
                    return jsonify(success=False, message='Terjadi kesalahan saat mereset password. Silakan coba lagi nanti.')
                finally:
                    # Tutup koneksi setelah penggunaan
                    connection.close()
            else:
                return jsonify(success=False, message='Kode telah kedaluwarsa. Silakan minta Kode reset ulang.')
        else:
            return jsonify(success=False, message='Kode tidak valid. Silakan periksa kembali atau minta Kode reset ulang.')
    else:
        return jsonify(success=False, message='Permintaan tidak valid. Pastikan semua data terisi dengan benar.')





# Endpoint untuk forgot-username
@app.route('/forgot-username', methods=['POST'])
def forgot_username():
    try:
        # Ambil data email dari request
        data = request.get_json()
        email = data['email']

        # Query database untuk mendapatkan username berdasarkan email dari tabel users_profile
        connection = get_db_connection()
        with connection.cursor() as cursor:
            sql = "SELECT user_id, full_name FROM users_profile WHERE email = %s"
            cursor.execute(sql, email)
            result = cursor.fetchone()

        if result:
            user_id = result['user_id']
            full_name = result['full_name']

            # Cari username berdasarkan user_id di tabel users
            with connection.cursor() as cursor:
                sql = "SELECT username FROM users WHERE id = %s"
                cursor.execute(sql, user_id)
                username_result = cursor.fetchone()

            if username_result:
                username = username_result['username']

                # Kirim email username ke alamat email pengguna
                send_username_email(email, username, full_name)

                # Respon sukses
                response = {'message': 'Email berhasil dikirim,Silakan cek pada folder spam /inbox'}
                return jsonify(response), 200
            else:
                # Respon jika username tidak ditemukan
                response = {'error': 'Username tidak ditemukan,Kamu belum mendaftar'}
                return jsonify(response), 404
        else:
            # Respon jika email tidak ditemukan di tabel users_profile
            response = {'error': 'Email tidak terdaftar,Kamu belum mengedit profil'}
            return jsonify(response), 404
    except Exception as e:
        # Respon jika terjadi error
        response = {'error': f'Gagal mengirim email : {str(e)}'}
        return jsonify(response), 500








# Fungsi untuk send email dengan template HTML, logo, dan link
def send_email_token_with_template_and_logo_and_link(subject, to_email, template_path, replacements, logo_path, reset_link):
    try:
        # Pengaturan informasi email pengirim dari file .env
        sender_email = os.getenv('SENDER_EMAIL')
        sender_password = os.getenv('SENDER_PASSWORD')
        smtp_server = os.getenv('SMTP_SERVER')  # Alamat SMTP server
        smtp_port = int(os.getenv('SMTP_PORT'))  # Port SMTP server

        # Membaca template HTML dari file
        with open(template_path, 'r') as template_file:
            template_content = template_file.read()

        # Mengganti placeholder dalam template dengan nilai yang sesuai
        for key, value in replacements.items():
            template_content = template_content.replace(f'{{{{ {key} }}}}', value)

        # Membuat pesan email dengan template HTML, menyisipkan logo, dan menyertakan link
        msg = MIMEMultipart('related')
        msg['From'] = f'I Reload Cell <{sender_email}>'  # Tambahkan Display Name di sini
        msg['To'] = to_email
        msg['Subject'] = subject

        # Menyisipkan versi HTML dari pesan email dengan link
        template_content_with_link = template_content.replace('{{ reset_link }}', reset_link)
        msg.attach(MIMEText(template_content_with_link, 'html'))

        # Menyisipkan logo sebagai gambar dalam pesan email
        with open(logo_path, 'rb') as image_file:
            logo_image = MIMEImage(image_file.read())
            logo_image.add_header('Content-ID', '<logo>')
            msg.attach(logo_image)

        # Mengirim email melalui SMTP server
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Menggunakan TLS (Transport Layer Security) untuk keamanan
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, to_email, msg.as_string())
        server.quit()

        return True
    except Exception as e:
        print(f"Email gagal dikirim: {e}")
        return False    



# Fungsi untuk kirim email dengan template HTML dan teks
def send_username_email(email, username, full_name):
    # Set sender email information from environment variables
    sender_email = os.getenv('SENDER_EMAIL')
    sender_password = os.getenv('SENDER_PASSWORD')
    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = int(os.getenv('SMTP_PORT'))

    # Load HTML and text templates from the 'templates' folder
    with open('templates/lupa_username/content.html', 'r') as html_file:
        html_template = html_file.read()
    with open('templates/lupa_username/content.txt', 'r') as text_file:
        text_template = text_file.read()

    # Replace placeholders in templates with actual data
    html_body = html_template.replace('{{ full_name }}', full_name).replace('{{ username }}', username)
    text_body = text_template.replace('{{ full_name }}', full_name).replace('{{ username }}', username)

    try:
        # Create email message
        msg = MIMEMultipart('alternative')
        msg['From'] = f'I Reload Cell <{sender_email}>'  # Tambahkan Display Name di sini
        msg['To'] = email
        msg['Subject'] = ' Info Penting ! : Username Kamu Telah Ditemukan Nih! Cekidot! '

        # Attach HTML version of the email
        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))

        # Attach logo image
        with open('templates/lupa_username/logo_1.png', 'rb') as image_file:
            logo_image = MIMEImage(image_file.read())
            logo_image.add_header('Content-ID', '<logo>')
            msg.attach(logo_image)

        # Send the email via the SMTP server
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, msg.as_string())
        server.quit()

        print("Email berhasil dikirim")
        return True
    except Exception as e:
        print(f"Email gagal dikirim: {e}")
        return False



# Fungsi untuk mengirim email konfirmasi reset password
def send_password_changed_email(email, full_name):
    subject = 'Your Password Change Completed'
    template_path = 'templates/password_changed/password_changed.html'
    replacements = {
        'full_name': full_name
    }

    return send_email_with_template(subject, email, template_path, replacements)

# Fungsi untuk mengirim email menggunakan template HTML
def send_email_with_template(subject, to_email, template_path, replacements):
    try:
        # Pengaturan informasi email pengirim dari file .env
        sender_email = os.getenv('SENDER_EMAIL')
        sender_password = os.getenv('SENDER_PASSWORD')
        smtp_server = os.getenv('SMTP_SERVER')
        smtp_port = int(os.getenv('SMTP_PORT'))

        # Membaca template HTML
        with open(template_path, 'r') as file:
            html_template = file.read()

        # Mengganti placeholders dalam template dengan nilai yang sesuai
        for key, value in replacements.items():
            html_template = html_template.replace('{{ ' + key + ' }}', value)

        # Membuat pesan email
        msg = MIMEMultipart()
        msg['From'] = f'I Reload Cell <{sender_email}>'  # Tambahkan Display Name di sini
        msg['To'] = to_email
        msg['Subject'] = subject

        # Melampirkan versi HTML dari email
        msg.attach(MIMEText(html_template, 'html'))

        # Membaca gambar/logo
        with open('templates/lupa_username/logo_1.png', 'rb') as image_file:
            logo_image = MIMEImage(image_file.read())
            logo_image.add_header('Content-ID', '<logo>')
            msg.attach(logo_image)

        # Mengirim email melalui SMTP server
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, to_email, msg.as_string())
        server.quit()

        return True
    except Exception as e:
        print(f"Email gagal dikirim: {e}")
        return False



# Endpoint untuk mengirim email konfirmasi setelah password diubah
@app.route('/send-password-changed-email', methods=['POST'])
def send_password_changed_email_endpoint():
    data = request.get_json()
    email = data.get('email')
    full_name = data.get('full_name')

    if email and full_name:
        success = send_password_changed_email(email, full_name)
        if success:
            return jsonify(success=True, message='Email konfirmasi perubahan password berhasil dikirim.')
        else:
            return jsonify(success=False, message='Terjadi kesalahan saat mengirim email konfirmasi perubahan password.')
    else:
        return jsonify(success=False, message='Permintaan tidak valid. Pastikan semua data terisi dengan benar.')



@app.route('/dashboard')
def dashboard():
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    # Dapatkan koneksi dan objek cursor
    connection = get_db_connection()
    cursor = connection.cursor()

    if 'loggedin' not in session:
        # Jika 'loggedin' tidak ada dalam session, arahkan pengguna ke halaman login
        return redirect(url_for('login'))
    
    username = session['username']
    
    userHasEditedProfile = session.get('userHasEditedProfile', False)
    
    # Dapatkan waktu lokal Pekalongan
    local_time = get_local_time()
    # Tentukan sapaan berdasarkan waktu
    current_hour = local_time.hour
    greeting = "Selamat Malam"
    if 5 <= current_hour < 12:
        greeting = "Selamat Pagi"
    elif 12 <= current_hour < 18:
        greeting = "Selamat Siang"
    elif 18 <= current_hour < 24 or 0 <= current_hour < 5:
        greeting = "Selamat Sore/Malam"
    
    cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
    user_data_from_db = cursor.fetchone()

    if user_data_from_db:
        user = {
            'id': user_data_from_db['id'],
            'username': user_data_from_db['username'],
            'password': user_data_from_db['password'],
            'points': user_data_from_db['points'],
            'tanggal_mendapatkan_point': user_data_from_db['tanggal_mendapatkan_point'],
            'tanggal_registrasi_user': user_data_from_db['tanggal_registrasi_user'],
            'timezone': user_data_from_db['timezone']
        }

        # Konversi poin ke IDR dan format sebagai string sesuai format 'RpXXX.XXX'
        points_in_idr = "Rp{:,.0f}".format(user['points']).replace(',', '.')

        cursor.execute("SELECT * FROM point_history WHERE user_id=%s ORDER BY transaction_date DESC", (user['id'],))
        point_history_data = cursor.fetchall()
        earned_points_history = []
        redeemed_points_history = []

        for row in point_history_data:
            history_entry = {
                'id': row['id'],
                'user_id': row['user_id'],
                'points_change': row['points_change'],
                'transaction_type': row['transaction_type'],
                'transaction_date': datetime.strftime(row['transaction_date'], '%d/%m/%y'),
                'product_name': row['product_name']
            }
            if row['points_change'] is not None and row['points_change'] > 0:
                earned_points_history.append(history_entry)
            else:
                redeemed_points_history.append(history_entry)

        latest_earned_points = earned_points_history[:5]
        latest_redeemed_points = redeemed_points_history[:5]

        # Pastikan kursor dan koneksi ditutup saat selesai menggunakannya
        cursor.close()
        connection.close()
        return render_template('/main/dashboard.html', greeting=greeting, username=username, user=user, earned_points_history=latest_earned_points, redeemed_points_history=latest_redeemed_points, points_in_idr=points_in_idr, userHasEditedProfile=userHasEditedProfile)
    else:
        # Pastikan kursor dan koneksi ditutup saat selesai menggunakannya
        cursor.close()
        connection.close()
        return redirect(url_for('login'))
    
    

# Fungsi untuk mengirim pesan ke Telegram
def send_telegram_message(message):
    bot_token = '6108836783:AAGBeqBoPTPr4qH-TutjcH5HafV89bvFl3A'
    chat_id = '6688399488'
    api_url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
    params = {
        'chat_id': chat_id,
        'text': message
    }
    response = requests.post(api_url, params=params)
    tele_log.info(f'Pesan Telegram terkirim: {message}')  # Log pesan yang dikirim
    return response.json()






# Fungsi filter format untuk memformat angka dengan titik (.) sebagai pemisah ribuan
def format(value):
    return "{:,.0f}".format(value).replace(',', '.')

# Menambahkan filter format ke Flask
app.add_template_filter(format, 'format')


# Fungsi untuk mendapatkan waktu lokal Pekalongan
def get_local_time():
    pekalongan_tz = pytz.timezone('Asia/Jakarta')  # Atur zona waktu Pekalongan
    local_time = datetime.now(pytz.utc).astimezone(pekalongan_tz)
    return local_time


@app.route('/redeem_product', methods=['POST'])
def redeem_product():
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    else:
        username = session['username']
        product_id = request.json.get('product_id')
        point_cost = int(request.json.get('point_cost'))

        # Dapatkan koneksi dan objek cursor
        connection = get_db_connection()
        cursor = connection.cursor()

        # Ambil data pengguna dari database
        cursor.execute("SELECT id, points FROM users WHERE username=%s", (username,))
        user_data = cursor.fetchone()

        if user_data:
            user_id, user_points = user_data['id'], user_data['points']

            # Ambil informasi produk yang akan diredeem
            cursor.execute("SELECT name_product FROM products WHERE id=%s", (product_id,))
            product_name = cursor.fetchone()

            if product_name:
                product_name = product_name['name_product']

                # Periksa apakah pengguna memiliki cukup poin untuk menukarkan produk
                if user_points >= point_cost:
                    # Kurangi poin pengguna
                    new_points = user_points - point_cost
                    cursor.execute("UPDATE users SET points = %s, total_redeemed_products = total_redeemed_products + 1 WHERE id = %s", (new_points, user_id))
                    connection.commit()

                    # Tambahkan entri ke tabel point_history untuk menandai penggunaan poin (redeemed)
                    cursor.execute("INSERT INTO point_history (user_id, points_change, transaction_type, product_name) VALUES (%s, %s, %s, %s)",
                                   (user_id, -point_cost, 'redeemed', product_name))
                    connection.commit()

                    # Mengirim notifikasi ke Telegram
                    send_telegram_message(f"Wow, {username}! Produk {product_name}seharga {point_cost} poin telah berhasil ditukarkan. Mohon untuk diberikan hadiah dalam waktu 24 jam.")

                    # Setelah mengupdate basis data dengan riwayat poin baru, kirimkan pembaruan poin ke pengguna melalui Socket.IO
                    socketio.emit('update_points', {'points_change': -point_cost}, room=session['username'])
                    
                    # Merekam aktivitas menukarkan produk ke log
                    log_message = f"Pengguna {username} menukarkan produk {product_name} seharga {point_cost} poin pada waktu :  {datetime.now()}"
                    redeem_logger.info(log_message)
                    # Pastikan untuk menutup cursor dan koneksi saat selesai
                    cursor.close()
                    connection.close()

                    return jsonify(success=True, message=f"Selamat {username}!! Anda telah menukar {product_name}. Admin akan segera menghubungi Anda.")
                else:
                    # Pastikan untuk menutup cursor dan koneksi saat selesai
                    cursor.close()
                    connection.close()
                    
                    # Merekam aktivitas menukarkan produk ke log
                    log_message = f"Pengguna {username} mencoba menukarkan poin yang tidak cukup pada waktu :  {datetime.now()}"
                    redeem_logger.info(log_message)
                    return jsonify(success=False, message=f"Maaf {username}, poin Anda tidak mencukupi untuk melakukan penukaran {product_name}. Silakan kumpulkan lebih banyak poin untuk mendapatkan {product_name} yang diinginkan. Terima kasih atas partisipasi Anda!")







# Initialize the request_logs dictionary with an empty dictionary for each hour
request_logs = {hour: {} for hour in range(24)}

@app.route('/claim_point', methods=['GET', 'POST'])
def claim_point():
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user_ip = request.remote_addr

    if request.method == 'POST':
        # Batasi jumlah request code per pengguna dalam satu jam
        current_hour = datetime.now().hour

        if user_ip not in request_logs[current_hour]:
            request_logs[current_hour][user_ip] = 1
        else:
            request_count = request_logs[current_hour][user_ip]
            if request_count >= 3:
                # Merekam aktivitas menukarkan input code claim ke log
                log_message = f"Pengguna {username} telah memasukan code terlalu banyak pada waktu : {datetime.now()}"
                claim_logger.info(log_message)
                return jsonify(success=False, message='Anda telah memasukkan terlalu banyak kode klaim yang salah. Coba lagi dalam 24 Jam.')
            else:
                request_logs[current_hour][user_ip] += 1

        claim_code = request.form['claim_code']
        cursor = conn.cursor()

        # Periksa apakah kode klaim ada dalam database
        cursor.execute("SELECT * FROM claim_codes1 WHERE code = %s", (claim_code,))
        claim_data = cursor.fetchone()

        if claim_data:
            # Periksa apakah kode klaim sudah kadaluwarsa
            if claim_data['status'] == 'kadaluwarsa':
                log_message = f"Pengguna {username} memasukan kode yang sudah kadaluwarsa pada waktu : {datetime.now()}"
                claim_logger.info(log_message)
                return jsonify(success=False, message='Kode tersebut sudah kadaluwarsa.')

            # Periksa apakah kode klaim sudah digunakan
            if claim_data['status'] == 'sudah klaim':
                log_message = f"Pengguna {username} memasukan kode yang sudah digunakan oleh pengguna lain pada waktu : {datetime.now()}"
                claim_logger.info(log_message)
                return jsonify(success=False, message='Kode tersebut sudah digunakan oleh pengguna lain.')

            # Dapatkan user_id berdasarkan username
            username = session['username']

            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            user_id = cursor.fetchone()['id']

            jumlah_point = claim_data['jumlah_point']
            tanggal_claim_users = datetime.now()

            # Tambahkan poin ke akun pengguna
            cursor.execute("UPDATE users SET points = points + %s, total_claimed_codes = total_claimed_codes + 1 WHERE id = %s", (jumlah_point, user_id))
            conn.commit()

            # Update status kode klaim yang telah digunakan
            cursor.execute("UPDATE claim_codes1 SET status = 'sudah klaim' WHERE id = %s", (claim_data['id'],))
            conn.commit()

            tanggal_claim_users = datetime.now()

            # Sekarang setel tanggal_claim_users ke nilai datetime.now()
            cursor.execute("UPDATE claim_codes1 SET tanggal_claim_users = %s WHERE id = %s", (datetime.now(), claim_data['id']))
            conn.commit()

            # Tambahkan entri ke tabel point_history
            transaction_type = 'Mendapatkan sejumlah poin + '
            cursor.execute("INSERT INTO point_history (user_id, points_change, transaction_type, transaction_date) VALUES (%s, %s, %s, %s)", (user_id, jumlah_point, transaction_type, tanggal_claim_users))
            conn.commit()
            # Merekam aktivitas menukarkan input code claim ke log
            log_message = f"Pengguna {username} telah Berhasil mendapatkan sejumlah + {jumlah_point} pada waktu : {datetime.now()}"
            claim_logger.info(log_message)
            return jsonify(success=True, message=f'Selamat! Anda berhasil mendapatkan {jumlah_point} poin.')

        # Merekam aktivitas menukarkan input code claim ke log
        log_message = f"Pengguna {username} Memasukan kode klaim yang tidak valid pada waktu : {datetime.now()}"
        claim_logger.info(log_message)
        return jsonify(success=False,message='Kode yang Anda masukkan tidak valid. Silakan masukkan kode yang benar.',)

    # Jika metode request adalah GET, tampilkan halaman claim_point.html (jika perlu)
    return render_template('main/claim_point.html')



# Web route halaman redeem
@app.route('/redeem')
def redeem():
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    # Periksa apakah pengguna sudah login (gunakan session/cookie)
    if 'loggedin' not in session:
        # Jika pengguna belum login, arahkan ke halaman login
        return redirect(url_for('login'))

    # Dapatkan koneksi dan objek cursor
    connection = get_db_connection()
    cursor = connection.cursor()

    # Ambil daftar produk yang bisa diredeem dari database
    cursor.execute("SELECT id, name_product, description, point_cost, image_url FROM products")
    products_from_db = cursor.fetchall()

    # Kirim data produk ke template redeem.html
    products = []
    for product in products_from_db:
        product_data = {
            'id': product['id'],
            'name_product': product['name_product'],
            'description': product['description'],
            'point_cost': product['point_cost'],
            'image_url': product['image_url']
        }
        products.append(product_data)

    # Pastikan untuk menutup cursor dan koneksi saat selesai
    cursor.close()
    connection.close()

    return render_template('main/redeem.html', products=products)


@app.route('/edit_profile')
def edit_profile():
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    # Check if the user is logged in
    if 'loggedin' not in session:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('login'))  # Assuming you have a 'login' route defined

    username = session['username']
    session['loggedin'] = True  # Tandai pengguna telah login
            

    # Get user data from users_profile table
    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users_profile WHERE user_id IN (SELECT id FROM users WHERE username = %s)", (username,))
        user_profile = cursor.fetchone()

    # Render the edit profile HTML template with user data
    return render_template('main/edit_profile.html', user_profile=user_profile)



# Fungsi untuk memperbarui profil pengguna melalui API
@app.route('/api/update_profile', methods=['PUT'])
def update_profile_api():
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    try:
        data = request.get_json()
        full_name = data.get('fullName')
        email = data.get('email')
        phone = data.get('phone')

        if not full_name or not email or not phone:
            raise ValueError('Semua kolom harus diisi')

        if 'loggedin' not in session:
            raise ValueError('Cannot Get')

        username = session.get('username')

        # Dapatkan ID pengguna dari tabel users
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            user_id = cursor.fetchone()

            if user_id is None:
                raise ValueError('Pengguna tidak ditemukan')

            user_id = user_id['id']

            # Periksa apakah data profil pengguna sudah ada
            cursor.execute("SELECT * FROM users_profile WHERE user_id = %s", (user_id,))
            existing_profile = cursor.fetchone()

            if existing_profile:
                # Jika data profil pengguna sudah ada, perbarui data
                update_query = "UPDATE users_profile SET full_name=%s, email=%s, phone=%s WHERE user_id=%s"
                cursor.execute(update_query, (full_name, email, phone, user_id))
            else:
                # Jika belum ada data profil pengguna, buat data baru
                insert_query = "INSERT INTO users_profile (user_id, full_name, email, phone) VALUES (%s, %s, %s, %s)"
                cursor.execute(insert_query, (user_id, full_name, email, phone))

            connection.commit()

            response = {
                'message': 'Terima Kasih! Telah memperbarui Profil',
                'redirect': '/dashboard'
            }

        return jsonify(response), 200

    except Exception as e:
        response = {
            'error': 'Terjadi kesalahan saat memperbarui profil: ' + str(e)
        }
        return jsonify(response), 500

# logout users
@app.route('/logout')
def logout():
            # Menyimpan informasi permintaan GET ke file log
    log_message = f"Received GET request from {request.remote_addr} for {request.url}"
    get_logger.info(log_message)
    # Periksa apakah pengguna sudah login (gunakan session/cookie)
    if 'loggedin' in session:

        session.pop('loggedin', None)
        session.pop('username', None)
        session.pop('email', None)
        return redirect(url_for('serve_index'))
    else:
        # Jika pengguna belum login, langsung redirect ke halaman login
        return redirect(url_for('serve_index'))


# Fungsi untuk menambahkan admin baru ke database dengan password yang di-hash
@app.route('/api/admin_register', methods=['POST'])
def admin_register():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        # Check if the username already exists in the database
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM maganize_users WHERE username=%s", (username,))
        existing_user = cursor.fetchone()
        cursor.close()

        if existing_user:
            # Username already exists, send an error response
            return jsonify({'success': False, 'message': 'Username already exists'}), 400

        # Register the new admin
        register_admin(username, password)

        # Send a success response
        return jsonify({'success': True}), 200

    except Exception as e:
        # Handle any other exceptions that might occur during the process
        return jsonify({'success': False, 'message': 'An error occurred while processing your request'}), 500

def register_admin(username, password):
    try:
        # Menghash password sebelum disimpan ke database
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Pastikan menggunakan koneksi ke database yang aman
        connection = get_db_connection()
        cursor = connection.cursor()

        # Menyimpan username dan password yang di-hash ke database
        cursor.execute("INSERT INTO maganize_users (username, password) VALUES (%s, %s)", (username, hashed_password))
        connection.commit()

        # Pastikan untuk menutup kursor dan koneksi setelah selesai menggunakannya
        cursor.close()
        connection.close()

    except Exception as e:
        print("Error:", e)
        # Mengembalikan pesan error jika terjadi kesalahan saat mengakses database
        return str(e)


@app.route('/api/admin_login', methods=['POST'])
def admin_login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        # Connect to the database and retrieve the hashed password for the provided username
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT password FROM maganize_users WHERE username=%s", (username,))
        result = cursor.fetchone()
        cursor.close()

        if result is None:
            # Username not found
            return jsonify({'success': False, 'message': 'Invalid username or password'}), 401

        hashed_password_from_db = result['password']

        if bcrypt.check_password_hash(hashed_password_from_db, password):
            # Password is correct, set the session and send a success response
            session['admin_username'] = username
            session['login_admin'] = True  # Set login_admin to True in the session
            return jsonify({'success': True}), 200
        else:
            # Password is incorrect
            return jsonify({'success': False, 'message': 'Invalid username or password'}), 401

    except Exception as e:
        # Handle any other exceptions that might occur during the process
        return jsonify({'success': False, 'message': 'An error occurred while processing your request'}), 500





# Endpoint untuk menambahkan pengguna baru ke dalam database
@app.route('/admin/api/add_users', methods=['POST'])
def create_user():
    # Memeriksa otorisasi admin
    if 'admin_username' not in session or not session['login_admin']:
        return jsonify({"error": "Unauthorized"}), 401

    # Mengambil data pengguna dari permintaan POST
    data = request.json
    username = data.get('username')
    password = data.get('password')
    points = data.get('points')
    timezone = data.get('timezone', 'Asia/Jakarta')

    # Memeriksa apakah username dan password telah diberikan
    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    # Mengenkripsi password menggunakan hash bcrypt
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Menghubungkan ke database
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Memeriksa apakah username sudah ada di database
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            existing_user = cursor.fetchone()
            if existing_user:
                return jsonify({"error": "Username already exists."}), 400

            # Mengambil zona waktu yang diinginkan oleh pengguna
            try:
                tz = pytz.timezone(timezone)
                local_time = datetime.now(tz)
            except pytz.exceptions.UnknownTimeZoneError:
                return jsonify({"error": "Invalid timezone."}), 400

            # Menyimpan data pengguna ke dalam tabel users
            sql = "INSERT INTO users (username, password, points, tanggal_mendapatkan_point, tanggal_registrasi_user, timezone) VALUES (%s, %s, %s, %s, %s, %s)"
            cursor.execute(sql, (username, hashed_password, points, local_time, local_time, timezone))
            connection.commit()

            # Mendapatkan ID pengguna yang baru saja ditambahkan
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            user_id = cursor.fetchone()['id']

            # Tambahkan entri ke tabel point_history
            transaction_type = 'Bonus poin dari I Reload Cell + '
            cursor.execute("INSERT INTO point_history (user_id, points_change, transaction_type, transaction_date) VALUES (%s, %s, %s, %s)", (user_id, points, transaction_type, local_time))
            connection.commit()

            # Mengembalikan respons yang berhasil
            return jsonify({"message": "User created successfully."}), 201

    except Exception as e:
        # Mengatasi kesalahan dan menutup koneksi ke database jika terjadi kesalahan
        print("Error:", e)
        connection.rollback()  # Mengembalikan transaksi jika terjadi kesalahan
        return jsonify({"error": "Error occurred."}), 500

    finally:
        # Menutup koneksi ke database
        connection.close()


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'admin_username' in session and session['login_admin']:
        # Admin sudah login, arahkan ke halaman admin.html
        return redirect(url_for('admin_admin'))
    
    if request.method == 'POST':
        # Memanggil fungsi admin_login untuk memverifikasi login admin
        response, status_code = admin_login()

        if response['success']:
            # Jika login berhasil, redirect ke halaman admin.html
            return redirect(url_for('admin_admin')), status_code
        else:
            # Jika login gagal, tampilkan pesan kesalahan pada halaman admin/index.html
            error_message = response['message']
            return render_template('admin/index.html', error_message=error_message), status_code

    return render_template('admin/index.html'), 200



@app.route('/api/create-code', methods=['POST'])
def create_code_voc():
    try:
        # Mengambil data dari formulir JSON
        data = request.get_json()
        code = data.get('code')
        points = int(data.get('points'))
        enable_expiry_date = data.get('enable_expiry_date')
        expiration_date = data.get('expiration_date')
        claim_status = data.get('claim_status')

        # Cek apakah enable_expiry_date diaktifkan
        if not enable_expiry_date:
            return jsonify(message="Tolong Aktifkan Tanggal Kedaluwarsa!")

        # Cek apakah code sudah ada di database
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM claim_codes1 WHERE code = %s", (code,))
        existing_code = cursor.fetchone()

        # Jika code sudah ada
        if existing_code:
            cursor.close()
            connection.close()
            return jsonify(message="Code Tersebut Sudah Ada!")

        # Jika code belum ada, masukkan ke database
        cursor.execute("INSERT INTO claim_codes1 (code, jumlah_point, status, tanggal_admin_add_code_voc, tanggal_kedaluwarsa) VALUES (%s, %s, %s, CURRENT_TIMESTAMP, %s)", (code, points, claim_status, expiration_date))
        connection.commit()

        # Update status code VOC menjadi AKTIF
        cursor.execute("UPDATE claim_codes1 SET status = 'aktif' WHERE code = %s", (code,))
        connection.commit()

        cursor.close()
        connection.close()

        return jsonify(message="Pembuatan Code Berhasil!", code=code, points=points, claim_status=claim_status, expiration_date=expiration_date)

    except Exception as e:
        print(str(e))
        return jsonify(message="Oops!, Ada yang error nih.")
    


@app.route('/api/get-codes', methods=['GET'])
def get_codes():
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            # Mendapatkan data code dari database
            query = "SELECT * FROM claim_codes1 LIMIT %s OFFSET %s"
            codes_per_page = 5
            offset = (int(request.args.get('page')) - 1) * codes_per_page
            cursor.execute(query, (codes_per_page, offset))
            codes = cursor.fetchall()
            return jsonify(codes)
    except Exception as e:
        return jsonify(message=str(e)), 500
    finally:
        connection.close()





# Endpoint API untuk halaman users
@app.route('/admin/api/users', methods=['GET'])
def api_users():
    # Memeriksa apakah pengguna sudah login
    if 'admin_username' not in session or not session['login_admin']:
        return jsonify({"error": "Unauthorized"}), 401

    # Mengambil koneksi ke database
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Mengambil data pengguna dari tabel users
            sql = "SELECT * FROM users"
            cursor.execute(sql)
            users_data = cursor.fetchall()

            # Mengambil data profil pengguna dari tabel users_profile
            sql = "SELECT * FROM users_profile"
            cursor.execute(sql)
            users_profile_data = cursor.fetchall()

        # Menutup koneksi ke database
        connection.close()

        # Menggabungkan data pengguna dan profil pengguna
        users_combined = []
        for user in users_data:
            user_profile = next((profile for profile in users_profile_data if profile['user_id'] == user['id']), {})
            user_combined = {**user, **user_profile}
            # Menyembunyikan sebagian karakter pada username
            user_combined['masked_username'] = mask_username(user['username'])
            users_combined.append(user_combined)

        # Mengambil parameter halaman dan ukuran halaman dari permintaan
        page = int(request.args.get('page', 1))
        page_size = 5  # Jumlah pengguna per halaman

        # Menghitung indeks awal dan akhir data yang akan ditampilkan
        start_index = (page - 1) * page_size
        end_index = start_index + page_size

        # Mengambil data pengguna yang sesuai dengan halaman yang diminta
        users_page = users_combined[start_index:end_index]

        # Mengirim data pengguna yang sesuai dalam format JSON
        return jsonify(users_page)

    except Exception as e:
        # Mengatasi kesalahan dan menutup koneksi ke database jika terjadi kesalahan
        print("Error:", e)
        connection.close()
        return jsonify({"error": "Error occurred."})

def mask_username(username):
    # Menyembunyikan sebagian karakter pada username
    masked_username = username[:3] + '*' * (len(username) - 3)
    return masked_username





# Fungsi untuk memeriksa token akses
def verify_token_akses(token_akses):
    try:
        # Memisahkan token akses menjadi header, payload, dan signature
        header, payload, signature = token_akses.split(".")

        # Dekripsi payload menggunakan base64
        decoded_payload = base64.urlsafe_b64decode(payload + '==').decode('utf-8')

        # Parsing payload sebagai JSON
        payload_data = json.loads(decoded_payload)

        # Mendapatkan waktu kedaluwarsa dari payload
        expires = datetime.datetime.utcfromtimestamp(payload_data['exp'])

        # Memeriksa apakah token akses masih valid
        now = datetime.datetime.utcnow()
        if now < expires:
            return True

    except Exception as e:
        print("Error:", e)

    return False



def get_user_stats():
    connection = get_db_connection()
    cursor = connection.cursor(pymysql.cursors.DictCursor)  # Gunakan DictCursor untuk menghasilkan data dalam bentuk dictionary

    # Query untuk menghitung total_claimed_codes dan total_redeemed_products
    query = "SELECT SUM(total_claimed_codes) as total_claimed_codes, SUM(total_redeemed_products) as total_redeemed_products FROM users"

    cursor.execute(query)
    user_stats = cursor.fetchone()

    cursor.close()
    connection.close()

    return user_stats

def get_total_active_users():
    connection = get_db_connection()
    cursor = connection.cursor(pymysql.cursors.DictCursor)

    # Query untuk menghitung total pengguna yang aktif
    query = "SELECT COUNT(*) AS total_active_users FROM users WHERE status = 'active'"

    cursor.execute(query)
    total_active_users = cursor.fetchone()['total_active_users']

    cursor.close()
    connection.close()

    return total_active_users


                                                                                # All Rute halaman admin

# Route untuk halaman admin.html
@app.route('/admin/admin.html')
def admin_admin():
    if 'admin_username' in session and session['login_admin']:
        # Admin sudah login, dapatkan statistik pengguna dan arahkan ke halaman admin.html
        user_stats = get_user_stats()
        total_claimed_codes = user_stats['total_claimed_codes']
        total_redeemed_products = user_stats['total_redeemed_products']
        
        # Dapatkan total pengguna aktif
        total_active_users = get_total_active_users()
        
        return render_template('admin/admin.html', total_claimed_codes=total_claimed_codes, total_redeemed_products=total_redeemed_products, total_active_users=total_active_users)
    else:
        # Admin belum login atau tidak memiliki izin, arahkan ke halaman login
        return redirect(url_for('admin'))


# Endpoint untuk halaman create user
@app.route('/admin/create-user.html')
def create_user_page():
    if 'admin_username' in session and session['login_admin']:
        return render_template('/admin/create-user.html')
    else:
        return redirect(url_for('admin'))
    
# Route untuk halaman registrasi admin
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Memanggil fungsi register_admin untuk menambahkan admin baru
        register_admin(username, password)

        # Redirect ke halaman login setelah registrasi berhasil
        return redirect(url_for('admin'))

    return render_template('admin/register.html')

# Route untuk halaman /admin/users.html
@app.route('/admin/users.html')
def users_page():
    if 'admin_username' in session and session['login_admin']:
        return render_template('/admin/users.html')
    else:
        return redirect(url_for('admin'))

# Rute untuk halaman create_code.html admin
@app.route('/admin/create_code.html')
def create_code():
    if 'admin_username' in session and session['login_admin']:
        return render_template('admin/create_code.html')
    else:
        return redirect(url_for('admin'))

# Rute untuk halaman list_code.html admin
@app.route('/admin/list_code.html')
def list_code():
    if 'admin_username' in session and session['login_admin']:
        return render_template('admin/list_code.html')
    else:
        return redirect(url_for('admin'))

# Rute untuk halaman add_product_redeem.html admin
@app.route('/admin/add_product_redeem.html')
def add_product_redeem():
    if 'admin_username' in session and session['login_admin']:
        return render_template('admin/add_product_redeem.html')
    else:
        return redirect(url_for('admin'))

# Rute untuk halaman list_product_redeem.html admin
@app.route('/admin/list_product_redeem.html')
def list_product_redeem():
    if 'admin_username' in session and session['login_admin']:
        return render_template('admin/list_product_redeem.html')
    else:
        return redirect(url_for('admin'))


# Route untuk logout admin
@app.route('/logout_admin')
def logout_admin():
    # Menghapus sesi pengguna saat logout
    session.pop('admin_username', None)
    session.pop('login_admin', None)
    # Redirect ke halaman login admin setelah logout
    return redirect(url_for('admin'))


                                            # API FETCH ALL





@app.route('/api/tambah_produk', methods=['POST'])
def add_product():
    try:
        data = request.form
        judul = data.get('judul')
        name_product = data.get('name_product')
        description = data.get('description')
        point_cost = data.get('point_cost')
        image_url = data.get('image_url')

        # Pastikan semua data yang dibutuhkan ada dan sesuai tipe datanya
        if judul and name_product and description and point_cost and image_url:
            # Ubah point_cost menjadi integer
            try:
                point_cost = int(point_cost)
            except ValueError:
                # Jika point_cost tidak dapat diubah menjadi integer, kirim pesan error
                return jsonify(success=False, error='Point cost harus berupa angka.')

            cursor = conn.cursor()
            # Tambahkan produk ke database
            cursor.execute("INSERT INTO products (judul, name_product, description, point_cost, image_url) VALUES (%s, %s, %s, %s, %s)",
                           (judul, name_product, description, point_cost, image_url))
            conn.commit()

            # Produk berhasil ditambahkan, kirim pesan sukses
            return jsonify(success=True, message='Produk berhasil ditambahkan.')
        else:
            # Jika data tidak lengkap, kirim pesan error
            return jsonify(success=False, error='Semua kolom harus diisi.')

    except Exception as e:
        # Jika terjadi kesalahan, kirim pesan error
        return jsonify(success=False, error=str(e))
    finally:
        cursor.close()  # Pastikan untuk menutup cursor setelah penggunaan




@app.route('/api/products', methods=['GET'])
def get_products():
    try:
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT * FROM products")
        products = cursor.fetchall()
        return jsonify(products)
    except Exception as e:
        return jsonify(error=str(e))

@app.route('/api/products/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    try:
        cursor = conn.cursor()
        # Hapus produk dari database berdasarkan ID
        cursor.execute("DELETE FROM products WHERE id=%s", (product_id,))
        conn.commit()
        return jsonify(success=True, message='Produk berhasil dihapus.')
    except Exception as e:
        return jsonify(success=False, error=str(e))

# Endpoint untuk menambahkan kode klaim baru
@app.route('/api/claim_codes', methods=['POST'])
def add_claim_code():
    try:
        code = request.form['code']
        jumlah_point = int(request.form['jumlah_point'])
        tanggal_kedaluwarsa = request.form['tanggal_kedaluwarsa']
        
        cursor = conn.cursor()
        # Dapatkan timestamp saat ini
        tanggal_admin_add_code_voc = datetime.now()

        # Tambahkan kode klaim ke database
        cursor.execute("INSERT INTO claim_codes1 (code, jumlah_point, tanggal_admin_add_code_voc, tanggal_kedaluwarsa) VALUES (%s, %s, %s, %s)",
                       (code, jumlah_point, tanggal_admin_add_code_voc, tanggal_kedaluwarsa))
        conn.commit()

        return jsonify(success=True, message='Kode klaim berhasil ditambahkan.')
    except Exception as e:
        return jsonify(success=False, error=str(e))

# Endpoint untuk mengambil total pengguna dari MySQL
@app.route('/api/total_users')
def total_users():
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(id) FROM users")
            result = cursor.fetchone()
            total_users = result['COUNT(id)']
            return jsonify(totalUsers=total_users)

    except Exception as e:
        return jsonify(error=str(e)), 500
    finally:
        if connection:
            connection.close()

# Daftar alamat IP bot yang diketahui
with open('known_bots.txt', 'r') as f:
    known_bots = f.read().splitlines()

def is_bot(request):
    """
    Mengembalikan True jika pengunjung adalah bot, False jika pengunjung bukan bot.
    """
    user_agent = request.headers.get('User-Agent')

    # Periksa apakah User-Agent mengindikasikan bot
    if 'bot' in user_agent.lower() or 'crawler' in user_agent.lower():
        # Catat aktivitas deteksi bot
        logging.info(f'Bot dengan User-Agent {user_agent} mendeteksi pada {datetime.now()}')
        return True

    # Periksa apakah pengunjung melakukan aktivitas yang mencurigakan
    if request.method == 'GET' and request.path == '/' and request.headers['Referer'] is None:
        # Catat aktivitas aktivitas mencurigakan
        logging.info(f'Aktivitas mencurigakan dari alamat IP {request.remote_addr} pada {datetime.now()}')
        return True

    # Periksa apakah alamat IP pengunjung ada di daftar
    if request.remote_addr in known_bots:
        # Catat aktivitas alamat IP bot yang diketahui
        logging.info(f'Bot dengan alamat IP {request.remote_addr} mendeteksi pada {datetime.now()}')
        return True

    # Pengunjung bukan bot
    return False




# Endpoint untuk mengambil total kode voucher dari MySQL
@app.route('/api/total_vouchers')
def total_vouchers():
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(id) FROM claim_codes1")
            result = cursor.fetchone()
            total_vouchers = result['COUNT(id)']
            return jsonify(totalVouchers=total_vouchers)

    except Exception as e:
        return jsonify(error=str(e)), 500
    finally:
        if connection:
            connection.close()

@app.errorhandler(Exception)
def handle_error(error):
    response = jsonify({"error": str(error)})
    response.status_code = 500
    return response




# akan melakukan debug dari semua script diatas
if __name__ == '__main__':

# Untuk Mengaktifkan log debug
# True = iya False = tidak
    app.run(debug=True) 
