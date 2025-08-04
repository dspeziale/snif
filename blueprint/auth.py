from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import json
import os
from datetime import datetime, timedelta
import secrets
import re

auth = Blueprint('auth', __name__)

# Configurazione per la gestione utenti
USERS_FILE = 'users.json'
SESSIONS_FILE = 'sessions.json'


def load_users():
    """Carica gli utenti dal file JSON"""
    try:
        users_path = os.path.join(current_app.root_path, USERS_FILE)
        with open(users_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        current_app.logger.warning("File users.json non trovato, creando utenti di default")
        return create_default_users()
    except json.JSONDecodeError:
        current_app.logger.error("Errore nel parsing di users.json")
        return create_default_users()


def save_users(users):
    """Salva gli utenti nel file JSON"""
    try:
        users_path = os.path.join(current_app.root_path, USERS_FILE)
        with open(users_path, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        current_app.logger.error(f"Errore nel salvataggio degli utenti: {str(e)}")
        return False


def create_default_users():
    """Crea utenti di default"""
    default_users = {
        "users": [
            {
                "id": 1,
                "username": "admin",
                "email": "admin@example.com",
                "password": generate_password_hash("admin123"),
                "first_name": "Alexander",
                "last_name": "Pierce",
                "role": "admin",
                "avatar": "/static/assets/img/user2-160x160.jpg",
                "created_at": datetime.now().isoformat(),
                "last_login": None,
                "is_active": True,
                "permissions": ["read", "write", "delete", "admin"],
                "profile": {
                    "bio": "Web Developer & System Administrator",
                    "phone": "+1 234 567 8900",
                    "location": "New York, USA",
                    "website": "https://example.com",
                    "join_date": "Nov. 2023"
                }
            },
            {
                "id": 2,
                "username": "user",
                "email": "user@example.com",
                "password": generate_password_hash("user123"),
                "first_name": "Sarah",
                "last_name": "Bullock",
                "role": "user",
                "avatar": "/static/assets/img/user3-128x128.jpg",
                "created_at": datetime.now().isoformat(),
                "last_login": None,
                "is_active": True,
                "permissions": ["read", "write"],
                "profile": {
                    "bio": "Marketing Specialist",
                    "phone": "+1 234 567 8901",
                    "location": "Los Angeles, USA",
                    "website": None,
                    "join_date": "Dec. 2023"
                }
            }
        ]
    }
    save_users(default_users)
    return default_users


def load_sessions():
    """Carica le sessioni attive dal file JSON"""
    try:
        sessions_path = os.path.join(current_app.root_path, SESSIONS_FILE)
        with open(sessions_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"sessions": []}


def save_sessions(sessions):
    """Salva le sessioni nel file JSON"""
    try:
        sessions_path = os.path.join(current_app.root_path, SESSIONS_FILE)
        with open(sessions_path, 'w', encoding='utf-8') as f:
            json.dump(sessions, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        current_app.logger.error(f"Errore nel salvataggio delle sessioni: {str(e)}")
        return False


def get_user_by_username(username):
    """Ottiene un utente per username"""
    users_data = load_users()
    for user in users_data.get('users', []):
        if user['username'] == username:
            return user
    return None


def get_user_by_email(email):
    """Ottiene un utente per email"""
    users_data = load_users()
    for user in users_data.get('users', []):
        if user['email'] == email:
            return user
    return None


def get_user_by_id(user_id):
    """Ottiene un utente per ID"""
    users_data = load_users()
    for user in users_data.get('users', []):
        if user['id'] == user_id:
            return user
    return None


def validate_email(email):
    """Valida il formato email"""
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None


def validate_password(password):
    """Valida la password (almeno 6 caratteri)"""
    return len(password) >= 6


def create_session(user_id):
    """Crea una nuova sessione per l'utente"""
    session_token = secrets.token_urlsafe(32)
    expire_time = datetime.now() + timedelta(hours=24)

    sessions_data = load_sessions()
    new_session = {
        "token": session_token,
        "user_id": user_id,
        "created_at": datetime.now().isoformat(),
        "expires_at": expire_time.isoformat(),
        "ip_address": request.remote_addr,
        "user_agent": request.headers.get('User-Agent', '')
    }

    sessions_data["sessions"].append(new_session)
    save_sessions(sessions_data)

    return session_token


def validate_session(session_token):
    """Valida una sessione"""
    sessions_data = load_sessions()
    current_time = datetime.now()

    for session_info in sessions_data["sessions"]:
        if session_info["token"] == session_token:
            expire_time = datetime.fromisoformat(session_info["expires_at"])
            if current_time < expire_time:
                return session_info["user_id"]
            else:
                # Sessione scaduta, rimuovila
                sessions_data["sessions"].remove(session_info)
                save_sessions(sessions_data)
                return None
    return None


def remove_session(session_token):
    """Rimuove una sessione"""
    sessions_data = load_sessions()
    sessions_data["sessions"] = [
        s for s in sessions_data["sessions"]
        if s["token"] != session_token
    ]
    save_sessions(sessions_data)


def login_required(f):
    """Decorator per richiedere l'autenticazione"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))

        # Valida la sessione se presente
        session_token = session.get('session_token')
        if session_token:
            user_id = validate_session(session_token)
            if not user_id:
                session.clear()
                flash('Sessione scaduta, effettua nuovamente il login', 'warning')
                return redirect(url_for('auth.login'))

        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    """Decorator per richiedere privilegi di amministratore"""

    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        user = get_user_by_id(session['user_id'])
        if not user or user['role'] != 'admin':
            flash('Accesso negato: privilegi di amministratore richiesti', 'error')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)

    return decorated_function


# Routes per l'autenticazione

@auth.route('/login', methods=['GET', 'POST'])
def login():
    """Pagina di login"""
    if request.method == 'POST':
        username_or_email = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember_me = bool(request.form.get('remember_me'))

        if not username_or_email or not password:
            flash('Username/Email e password sono obbligatori', 'error')
            return render_template('auth/login.html')

        # Cerca l'utente per username o email
        user = get_user_by_username(username_or_email)
        if not user:
            user = get_user_by_email(username_or_email)

        if user and user['is_active'] and check_password_hash(user['password'], password):
            # Login riuscito
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']

            # Crea sessione se "Ricordami" è selezionato
            if remember_me:
                session_token = create_session(user['id'])
                session['session_token'] = session_token
                session.permanent = True

            # Aggiorna ultimo login
            users_data = load_users()
            for u in users_data['users']:
                if u['id'] == user['id']:
                    u['last_login'] = datetime.now().isoformat()
                    break
            save_users(users_data)

            flash(f'Benvenuto, {user["first_name"]}!', 'success')

            # Redirect alla pagina richiesta o dashboard
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('main.index'))
        else:
            flash('Username/Email o password non validi', 'error')

    return render_template('auth/login.html')


@auth.route('/logout')
def logout():
    """Logout dell'utente"""
    session_token = session.get('session_token')
    if session_token:
        remove_session(session_token)

    session.clear()
    flash('Logout effettuato con successo', 'info')
    return redirect(url_for('auth.login'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    """Registrazione nuovo utente"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validazioni
        errors = []

        if not username or len(username) < 3:
            errors.append('Username deve essere di almeno 3 caratteri')

        if not email or not validate_email(email):
            errors.append('Email non valida')

        if not first_name:
            errors.append('Nome è obbligatorio')

        if not last_name:
            errors.append('Cognome è obbligatorio')

        if not validate_password(password):
            errors.append('Password deve essere di almeno 6 caratteri')

        if password != confirm_password:
            errors.append('Le password non coincidono')

        # Controlla se username o email esistono già
        if get_user_by_username(username):
            errors.append('Username già esistente')

        if get_user_by_email(email):
            errors.append('Email già registrata')

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth/register.html')

        # Crea nuovo utente
        users_data = load_users()
        new_user_id = max([u['id'] for u in users_data['users']], default=0) + 1

        new_user = {
            "id": new_user_id,
            "username": username,
            "email": email,
            "password": generate_password_hash(password),
            "first_name": first_name,
            "last_name": last_name,
            "role": "user",
            "avatar": "/static/assets/img/user-default.jpg",
            "created_at": datetime.now().isoformat(),
            "last_login": None,
            "is_active": True,
            "permissions": ["read", "write"],
            "profile": {
                "bio": "",
                "phone": "",
                "location": "",
                "website": "",
                "join_date": datetime.now().strftime("%b. %Y")
            }
        }

        users_data['users'].append(new_user)

        if save_users(users_data):
            flash('Registrazione completata con successo! Puoi ora effettuare il login.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Errore durante la registrazione. Riprova.', 'error')

    return render_template('auth/register.html')


@auth.route('/profile')
@login_required
def profile():
    """Profilo utente"""
    user = get_user_by_id(session['user_id'])
    if not user:
        flash('Utente non trovato', 'error')
        return redirect(url_for('main.index'))

    return render_template('auth/profile.html', user=user)


@auth.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Modifica profilo utente"""
    user = get_user_by_id(session['user_id'])
    if not user:
        flash('Utente non trovato', 'error')
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip()
        bio = request.form.get('bio', '').strip()
        phone = request.form.get('phone', '').strip()
        location = request.form.get('location', '').strip()
        website = request.form.get('website', '').strip()

        # Validazioni
        errors = []

        if not first_name:
            errors.append('Nome è obbligatorio')

        if not last_name:
            errors.append('Cognome è obbligatorio')

        if not email or not validate_email(email):
            errors.append('Email non valida')

        # Controlla se email è già usata da un altro utente
        existing_user = get_user_by_email(email)
        if existing_user and existing_user['id'] != user['id']:
            errors.append('Email già utilizzata da un altro utente')

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth/edit_profile.html', user=user)

        # Aggiorna utente
        users_data = load_users()
        for u in users_data['users']:
            if u['id'] == user['id']:
                u['first_name'] = first_name
                u['last_name'] = last_name
                u['email'] = email
                u['profile']['bio'] = bio
                u['profile']['phone'] = phone
                u['profile']['location'] = location
                u['profile']['website'] = website if website else None
                break

        if save_users(users_data):
            flash('Profilo aggiornato con successo', 'success')
            return redirect(url_for('auth.profile'))
        else:
            flash('Errore durante l\'aggiornamento del profilo', 'error')

    return render_template('auth/edit_profile.html', user=user)


@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Cambia password"""
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        user = get_user_by_id(session['user_id'])
        if not user:
            flash('Utente non trovato', 'error')
            return redirect(url_for('main.index'))

        # Validazioni
        errors = []

        if not check_password_hash(user['password'], current_password):
            errors.append('Password attuale non corretta')

        if not validate_password(new_password):
            errors.append('La nuova password deve essere di almeno 6 caratteri')

        if new_password != confirm_password:
            errors.append('Le nuove password non coincidono')

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth/change_password.html')

        # Aggiorna password
        users_data = load_users()
        for u in users_data['users']:
            if u['id'] == user['id']:
                u['password'] = generate_password_hash(new_password)
                break

        if save_users(users_data):
            # Rimuovi tutte le sessioni dell'utente per forzare nuovo login
            sessions_data = load_sessions()
            sessions_data["sessions"] = [
                s for s in sessions_data["sessions"]
                if s["user_id"] != user['id']
            ]
            save_sessions(sessions_data)

            session.clear()
            flash('Password cambiata con successo. Effettua nuovamente il login.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Errore durante il cambio password', 'error')

    return render_template('auth/change_password.html')


# API Routes

@auth.route('/api/auth/check')
def check_auth():
    """Controlla se l'utente è autenticato"""
    if 'user_id' in session:
        user = get_user_by_id(session['user_id'])
        if user:
            return jsonify({
                'authenticated': True,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'first_name': user['first_name'],
                    'last_name': user['last_name'],
                    'role': user['role'],
                    'avatar': user['avatar']
                }
            })

    return jsonify({'authenticated': False})


@auth.route('/api/auth/sessions')
@login_required
def get_user_sessions():
    """Ottiene le sessioni attive dell'utente"""
    user_id = session['user_id']
    sessions_data = load_sessions()
    user_sessions = []

    current_time = datetime.now()

    for session_info in sessions_data["sessions"]:
        if session_info["user_id"] == user_id:
            expire_time = datetime.fromisoformat(session_info["expires_at"])
            if current_time < expire_time:
                user_sessions.append({
                    'token': session_info['token'][:10] + '...',  # Mostra solo parte del token
                    'created_at': session_info['created_at'],
                    'expires_at': session_info['expires_at'],
                    'ip_address': session_info['ip_address'],
                    'user_agent': session_info['user_agent'][:50] + '...' if len(session_info['user_agent']) > 50 else
                    session_info['user_agent'],
                    'is_current': session_info['token'] == session.get('session_token')
                })

    return jsonify({
        'success': True,
        'sessions': user_sessions
    })


# Context processor per l'autenticazione
@auth.app_context_processor
def inject_auth_data():
    """Inietta i dati di autenticazione nei template"""
    if 'user_id' in session:
        user = get_user_by_id(session['user_id'])
        if user:
            return {
                'current_user': {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'name': f"{user['first_name']} {user['last_name']}",
                    'first_name': user['first_name'],
                    'last_name': user['last_name'],
                    'role': user['role'],
                    'avatar': user['avatar'],
                    'join_date': user['profile']['join_date'],
                    'permissions': user['permissions']
                },
                'is_authenticated': True,
                'is_admin': user['role'] == 'admin'
            }

    return {
        'current_user': None,
        'is_authenticated': False,
        'is_admin': False
    }