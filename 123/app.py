from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import hashlib
import os
import random
import string

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Замените на случайный ключ

# Файл для хранения пользователей
USERS_FILE = 'users.txt'

# ==================== АВТОРИЗАЦИЯ ====================

def hash_password(password):
    """Хеширование пароля"""
    return hashlib.sha256(password.encode()).hexdigest()

def read_users():
    """Чтение пользователей из файла"""
    users = {}
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    username, password_hash = line.strip().split(':')
                    users[username] = password_hash
    return users

def write_user(username, password_hash):
    """Запись нового пользователя в файл"""
    with open(USERS_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{username}:{password_hash}\n")

def user_exists(username):
    """Проверка существования пользователя"""
    users = read_users()
    return username in users

def verify_password(username, password):
    """Проверка пароля"""
    users = read_users()
    if username in users:
        return users[username] == hash_password(password)
    return False

# ==================== ГЕНЕРАТОР ПАРОЛЕЙ ====================

def generate_password(length=12, use_uppercase=True, use_numbers=True, use_special=True):
    """
    Генерирует случайный пароль на основе заданных параметров.
    """
    characters = string.ascii_lowercase
    
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_numbers:
        characters += string.digits
    if use_special:
        characters += string.punctuation
    
    if not characters:
        characters = string.ascii_lowercase
    
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def check_password_strength(password):
    """
    Проверяет сложность пароля и возвращает оценку.
    """
    score = 0
    feedback = []
    
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
        feedback.append("Используйте пароль длиной не менее 12 символов")
    else:
        feedback.append("Пароль слишком короткий")
    
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Добавьте заглавные буквы")
    
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Добавьте строчные буквы")
    
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Добавьте цифры")
    
    if any(c in string.punctuation for c in password):
        score += 1
    else:
        feedback.append("Добавьте специальные символы")
    
    if score >= 5:
        strength = "Очень сильный"
    elif score >= 4:
        strength = "Сильный"
    elif score >= 3:
        strength = "Средний"
    else:
        strength = "Слабый"
    
    return {
        'score': score,
        'strength': strength,
        'feedback': feedback
    }

# ==================== МАРШРУТЫ ====================

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if verify_password(username, password):
            session['username'] = username
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if not username or not password:
            flash('Заполните все поля', 'error')
        elif password != confirm_password:
            flash('Пароли не совпадают', 'error')
        elif user_exists(username):
            flash('Пользователь с таким именем уже существует', 'error')
        else:
            password_hash = hash_password(password)
            write_user(username, password_hash)
            flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', username=session['username'])

@app.route('/password-generator')
def password_generator():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    return render_template('index.html', username=session['username'])

@app.route('/generate', methods=['POST'])
def generate():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Требуется авторизация'})
    
    try:
        data = request.json
        
        length = int(data.get('length', 12))
        use_uppercase = data.get('uppercase', True)
        use_numbers = data.get('numbers', True)
        use_special = data.get('special', True)
        
        if length < 4:
            return jsonify({
                'success': False,
                'error': 'Длина пароля должна быть не менее 4 символов'
            })
        
        if length > 50:
            return jsonify({
                'success': False,
                'error': 'Длина пароля не должна превышать 50 символов'
            })
        
        password = generate_password(length, use_uppercase, use_numbers, use_special)
        
        return jsonify({
            'success': True,
            'password': password
        })
        
    except ValueError:
        return jsonify({
            'success': False,
            'error': 'Неверный формат длины пароля'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Произошла ошибка: {str(e)}'
        })

@app.route('/generate-advanced', methods=['POST'])
def generate_advanced():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Требуется авторизация'})
    
    try:
        data = request.json
        
        length = int(data.get('length', 12))
        use_uppercase = data.get('uppercase', True)
        use_numbers = data.get('numbers', True)
        use_special = data.get('special', True)
        
        if length < 4 or length > 50:
            return jsonify({
                'success': False,
                'error': 'Длина пароля должна быть от 4 до 50 символов'
            })
        
        password = generate_password(length, use_uppercase, use_numbers, use_special)
        strength_analysis = check_password_strength(password)
        
        return jsonify({
            'success': True,
            'password': password,
            'strength': strength_analysis['strength'],
            'score': strength_analysis['score'],
            'feedback': strength_analysis['feedback']
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Вы вышли из системы', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)