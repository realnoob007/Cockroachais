import logging
from flask import Flask, request, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user
from werkzeug.security import generate_password_hash, check_password_hash
from captcha.image import ImageCaptcha
from email_validator import validate_email, EmailNotValidError
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr
import random
import config
import redis
from flask import send_file
from io import BytesIO
from PIL import Image
import numpy as np
import string
import base64


# 设置日志记录
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.config.from_object(config)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

try:
    db = SQLAlchemy(app)
    login_manager = LoginManager()
    login_manager.init_app(app)

    r = redis.Redis(
        host=app.config['REDIS_HOST'],
        port=app.config['REDIS_PORT'],
        db=app.config['REDIS_DB'],
        password=app.config['REDIS_PASSWORD']
    )
    # 尝试连接 Redis
    r.ping()
except Exception as e:
    logging.error("Error connecting to database or Redis: %s", e)
    exit(1)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

def make_header_string(text):
    """对包含非ASCII字符的文本进行base64编码"""
    if any(ord(char) > 127 for char in text):
        # 非ASCII字符，使用base64编码
        return '=?UTF-8?B?' + base64.b64encode(text.encode()).decode() + '?='
    else:
        # ASCII字符，不需要编码
        return text
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        code = data.get('code')

        if not username or not email or not password or not code:
            return jsonify({'message': 'Missing data'}), 400

        # 验证电子邮件格式
        try:
            valid = validate_email(email)
            email = valid.email  # 格式化邮件
        except EmailNotValidError as e:
            return jsonify({'message': 'Invalid email format'}), 400
        
        # 检查用户名和电子邮件是否已存在
        if User.query.filter_by(username=username).first():
            return jsonify({'message': 'Username already exists'}), 400
        if User.query.filter_by(email=email).first():
            return jsonify({'message': 'Email already exists'}), 400

        if config.REGISTRATION_METHOD == "captcha":
            captcha_value = r.get(username)
            if not captcha_value:
                logging.info(f"Captcha for {username} not found or expired.")
                return jsonify({'message': 'Captcha expired or not found'}), 400

            if code.lower() != captcha_value.decode().lower():
                logging.info(f"Invalid captcha for {username}. Expected: {captcha_value.decode()}, Received: {code}")
                return jsonify({'message': 'Invalid captcha'}), 400
            
            logging.info(f"Captcha for {username} validated successfully.")
            
        elif config.REGISTRATION_METHOD == "email":
            email_code = r.get(email) 
            if not email_code:
                logging.info(f"Email code for {email} not found or expired.")
                return jsonify({'message': 'Email code expired or not found'}), 400

            if code != email_code.decode():
                logging.info(f"Invalid email code for {email}. Expected: {email_code.decode()}, Received: {code}")
                return jsonify({'message': 'Invalid email code'}), 400
                
            logging.info(f"Email code for {email} validated successfully.")

            new_user = User(username=username, email=email)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()

            return jsonify({'message': 'User registered successfully'}), 201


        # 创建并保存新用户
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'User registered successfully'}), 201

    except Exception as e:
        logging.error(f"Error in registration: {e}")
        return jsonify({'message': 'Internal server error'}), 500

def gen_captcha_text_and_image():
    image = ImageCaptcha()
    captcha_text = random_captcha_text()
    captcha_text = ''.join(captcha_text)
    captcha = image.generate(captcha_text)
    captcha_image = Image.open(captcha)

    return captcha_text, captcha_image

def random_captcha_text(char_set=config.CHAR_SET, captcha_size=4):
    return random.choices(char_set, k=captcha_size)

@app.route('/send_email_code', methods=['POST'])
def send_email_code():
    data = request.json
    email = data.get('email')
    if not email:
        return jsonify({'message': 'Missing email'}), 400

    try:
        valid = validate_email(email)
        email = valid.email
    except EmailNotValidError as e:
        return jsonify({'message': str(e)}), 400

    code = get_random_str()
    logging.info(f"Generated email code for {email}: {code}")  # 打印生成的验证码

    if send_email(email, code):
        r.set(email, code)
        r.expire(email, 600)  # 设置验证码有效期为10分钟
        return jsonify({'message': 'Email code sent successfully'}), 200
    else:
        return jsonify({'message': 'Failed to send email'}), 500


def get_random_str():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

def send_email(receiver, code):
    sender_email = app.config['SMTP_EMAIL']
    sender_name = app.config['SMTP_NICKNAME']
    subject = app.config['EMAIL_SUBJECT']
    content = app.config['EMAIL_CONTENT'] % code

    msg = MIMEText(content, 'plain', 'utf-8')
    msg['From'] = formataddr((Header(sender_name, 'utf-8').encode(), sender_email))
    msg['To'] = formataddr((Header('尊敬的客户', 'utf-8').encode(), receiver))
    msg['Subject'] = Header(subject, 'utf-8')

    try:
        server = smtplib.SMTP_SSL(app.config['SMTP_SERVER'], app.config['SMTP_PORT'])
        server.login(app.config['SMTP_EMAIL'], app.config['SMTP_PASSWORD'])
        server.sendmail(sender_email, [receiver], msg.as_string())
        server.quit()
    except smtplib.SMTPException as e:
        logging.error(f"Error sending email: {e}")
        return False
    return True



@app.route('/get_captcha/<username>')
def get_captcha(username):
    captcha_text, captcha_image = gen_captcha_text_and_image()
    r.set(username, captcha_text)
    r.expire(username, 300)  # 验证码有效期5分钟

    print(f"Generated captcha for {username}: {captcha_text}")  # 打印生成的验证码

    # 将图像转换为字节流以便发送
    img_io = BytesIO()
    captcha_image.save(img_io, 'PNG')
    img_io.seek(0)
    print(f"Setting captcha for {username} in Redis: {captcha_text}")
    return send_file(img_io, mimetype='image/png')

if __name__ == '__main__':
    try:
        with app.app_context():
            db.create_all()  # 创建数据库表
        app.run(debug=True)
    except Exception as e:
        logging.error("Error starting the application: %s", e)
        exit(1)
