import time
from functools import wraps
from flask import Blueprint, request, jsonify, g
from datetime import datetime
from .models import session, User, Chat, Message

bp = Blueprint('routes', __name__)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_token = request.headers.get('Authorization')
        if not auth_token:
            return jsonify({"error": "Brak tokenu autoryzacji"}), 401

        user_id = auth_token.split(' ')[1] if len(auth_token.split(' ')) > 1 else None
        user = session.query(User).get(user_id)

        if not user:
            return jsonify({"error": "test"}), 401
        if not user.is_active:
            return jsonify({"error": "Nieautoryzowany dostęp"}), 401

        g.current_user = user
        return f(*args, **kwargs)

    return decorated_function


@bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if session.query(User).filter_by(username=username).first():
        return jsonify({"error": "Użytkownik już istnieje"}), 400
    if session.query(User).filter_by(email=email).first():
        return jsonify({"error": "Email jest już używany"}), 400

    new_user = User(username=username, email=email)
    new_user.set_password(password)
    session.add(new_user)
    session.commit()

    return jsonify({
        "message": "Rejestracja zakończona sukcesem",
        "user_id": new_user.id,
        "token": str(new_user.id)
    })


@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = session.query(User).filter_by(username=username).first()
    if user and user.check_password(password):
        user.is_active = True
        session.commit()
        return jsonify({
            "message": "Zalogowano pomyślnie",
            "user_id": user.id,
            "token": str(user.id)
        })
    else:
        return jsonify({"error": "Nieprawidłowa nazwa użytkownika lub hasło"}), 401


@bp.route('/logout', methods=['POST'])
@login_required
def logout():
    current_user = g.current_user
    current_user.is_active = False
    session.commit()
    return jsonify({"message": "Wylogowano pomyślnie"})


@bp.route('/protected', methods=['GET'])
@login_required
def protected():
    return jsonify({
        "message": f"Witaj {g.current_user.username}! To jest chroniona trasa.",
        "user_data": {
            "id": g.current_user.id,
            "username": g.current_user.username,
            "email": g.current_user.email
        }
    })


@bp.route('/getUsers', methods=['GET'])
def getUsers():
    users = session.query(User).all()
    users_list = []

    for user in users:
        user_data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_active': user.is_active,
            'last_seen': user.last_seen.isoformat() if user.last_seen else None
        }
        users_list.append(user_data)

    return jsonify(users_list)


@bp.route('/getActivity', methods=['GET'])
def getActivity():
    data = request.get_json()
    user_id = data.get('user_id')
    user = session.query(User).get(user_id)
    return jsonify({'isActive': user.is_active})


@bp.route('/createChat', methods=['POST'])
@login_required
def createChat():
    data = request.get_json()
    second_user_id = data.get('second_user_id')
    new_chat = Chat(first_user=g.current_user.id, second_user=second_user_id)
    session.add(new_chat)
    try:
        session.commit()
        return jsonify({"message": "Stworzenie czatu zakończonę sukcesem", "chat_id": new_chat.id})
    except:
        return jsonify({"error": "Tworzenie czatu nie powiodło się"}), 400


@bp.route('/getChats', methods=['GET'])
def getChats():
    chats = session.query(Chat).all()
    chat_list = []

    for chat in chats:
        chat_data = {
            'chat_id': chat.id,
            'first_user': chat.first_user,
            'second_user': chat.second_user,
        }
        chat_list.append(chat_data)

    return jsonify(chat_list)


@bp.route('/sendMessage', methods=['POST'])
@login_required
def sendMessage():
    data = request.get_json()
    chat_id = data.get('chat_id')
    message = data.get('message')
    new_message = Message(chat_id=chat_id, message=message, author_id=g.current_user.id)
    session.add(new_message)
    try:
        session.commit()
        return jsonify({"message": "Wysyłano wiadomość", "chat_id": chat_id})
    except:
        return jsonify({"error": "Wysyłanie wiadomości nie powiodło się"}), 400


@bp.route('/CreateGroupChat', methods=['POST'])
@login_required
def createGroupChat():
    data = request.get_json()
    chat_id = data.get('chat_id')