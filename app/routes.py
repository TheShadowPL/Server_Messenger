from datetime import datetime
from flask import Blueprint, request, jsonify
from .models import session, User, Chat, Message

bp = Blueprint('routes', __name__)


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

    return jsonify({"message": "Rejestracja zakończona sukcesem", "user_id": new_user.id})


@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = session.query(User).filter_by(username=username).first()
    if user and user.check_password(password):
        user.is_active = True
        session.commit()
        return jsonify({"message": "Zalogowano pomyślnie", "user_id": user.id})
    else:
        return jsonify({"error": "Nieprawidłowa nazwa użytkownika lub hasło"}), 401


@bp.route('/logout', methods=['POST'])
def logout():
    data = request.get_json()
    user_id = data.get('user_id')

    user = session.query(User).get(user_id)
    if user:
        user.is_active = False
        session.commit()
        return jsonify({"message": "Wylogowano pomyślnie"})
    else:
        return jsonify({"error": "Użytkownik nie znaleziony"}), 404

@bp.route('/heartbeat', methods=['POST'])
def heartbeat():
    data = request.get_json()
    user_id = data.get('user_id')

    user = session.query(User).get(user_id)
    if user:
        user.last_seen = datetime.utcnow()
        user.is_active = True
        session.commit()
        return jsonify({"message": "otrzymano ping"})
    else:
        return jsonify({"error": "Użytkownik nie znaleziony"}), 404
    
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
def createChat():
    data = request.get_json()
    first_user_id = data.get('first_user_id')
    second_user_id = data.get('second_user_id')
    new_chat = Chat(first_user=first_user_id, second_user=second_user_id)
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
def sendMessage():
    data = request.get_json()
    chat_id = data.get('chat_id')
    message = data.get('message')
    new_message = Message(chat_id=chat_id, message=message)


@bp.route('/CreateGroupChat', methods=['POST'])
def createGroupChat():
    data = request.get_json()
    chat_id = data.get('chat_id')

