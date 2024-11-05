import json
import time
from functools import wraps
from flask import Blueprint, request, jsonify, g
from datetime import datetime
from .models import session, User, Chat, Message, GroupChat, GroupMessages
from .models import session, User, Chat, Message
import secrets

bp = Blueprint('routes', __name__)

def generate_token():
    return secrets.token_hex(32)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_token = request.headers.get('Authorization')
        print(auth_token)
        if not auth_token:
            return jsonify({"error": "Brak tokenu autoryzacji"}), 401

        user = session.query(User).filter_by(token=auth_token).first()
        if not user:
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
        "user_id": new_user.id
    })


@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = session.query(User).filter_by(username=username).first()
    if user and user.check_password(password):
        user.token = generate_token()
        user.is_active = True
        session.commit()

        return jsonify({
            "message": "Zalogowano pomyślnie",
            "user_id": user.id,
            "token": user.token
        })
    else:
        return jsonify({"error": "Nieprawidłowa nazwa użytkownika lub hasło"}), 401


@bp.route('/logout', methods=['POST'])
@login_required
def logout():
    current_user = g.current_user
    current_user.is_active = False
    current_user.token = None
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
    except Exception as e:
        print(e)
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

@bp.route('/sendActivity', methods=['POST'])
@login_required
def sendActivity():
    user = session.query(User).get(g.current_user.id)
    user.set_activity(True)
    try:
        session.commit()
        return jsonify({"message": "Pomyślnie wysłano aktywność do serwera"})
    except Exception as e:
        print(e)
        return jsonify({"message": "Wysłanie aktywności nie powiodło się"})

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
    members = data.get('members')

    if not members or not isinstance(members, list):
        return jsonify({"error": "Lista członków jest wymagana i powinna być typu list"}), 400

    if g.current_user.id not in members:
        members.append(g.current_user.id)

    new_group_chat = GroupChat(members=json.dumps(members))
    session.add(new_group_chat)
    session.commit()

    return jsonify({
        "message": "Czat grupowy został pomyślnie utworzony",
        "group_chat_id": new_group_chat.id
    }), 201


@bp.route('/sendGroupMessage', methods=['POST'])
@login_required
def sendGroupMessage():
    data = request.get_json()
    group_chat_id = data.get('group_chat_id')
    content = data.get('content')

    if not group_chat_id or not content:
        return jsonify({"error": "group_chat_id i treść wiadomości są wymagane"}), 400

    group_chat = session.query(GroupChat).filter_by(id=group_chat_id).first()
    if not group_chat:
        return jsonify({"error": "Czat grupowy nie istnieje"}), 404

    new_message = GroupMessages(
        group_chat_id=group_chat_id,
        sender_id=g.current_user.id,
        content=content
    )
    session.add(new_message)
    session.commit()

    return jsonify({"message": "Wiadomość grupowa została wysłana", "sender_id": g.current_user.id}), 201

@bp.route('/inviteToGroupChat', methods=['POST'])
@login_required
def invite_to_group_chat():
    data = request.get_json()
    group_chat_id = data.get('group_chat_id')
    user_id = data.get('user_id')
    print(group_chat_id, user_id)
    if not group_chat_id or not user_id:
        return jsonify({"error": "group_chat_id i user_id są wymagane"}), 400

    group_chat = session.query(GroupChat).filter_by(id=group_chat_id).first()
    if not group_chat:
        return jsonify({"error": "Czat grupowy nie istnieje"}), 404

    members = json.loads(group_chat.members)
    if user_id in members:
        return jsonify({"error": "Użytkownik jest już członkiem czatu grupowego"}), 400

    members.append(user_id)
    group_chat.members = json.dumps(members)
    session.commit()

    return jsonify({"message": "Użytkownik został pomyślnie zaproszony do czatu grupowego"}), 200

@bp.route('/getGroupMessages', methods=['GET'])
@login_required
def get_group_messages():
    group_chat_id = request.args.get('group_chat_id')

    if not group_chat_id:
        return jsonify({"error": "group_chat_id jest wymagane"}), 400

    group_chat = session.query(GroupChat).filter_by(id=group_chat_id).first()
    if not group_chat:
        return jsonify({"error": "Czat grupowy nie istnieje"}), 404

    messages = session.query(GroupMessages).filter_by(group_chat_id=group_chat_id).all()
    messages_list = [
        {
            "id": message.id,
            "sender_id": message.sender_id,
            "content": message.content,
            "timestamp": message.timestamp.isoformat()
        }
        for message in messages
    ]

    return jsonify(messages_list), 200