import json
from datetime import datetime
from functools import wraps
from flask import Blueprint, request, jsonify, g
from .models import session, User, Chat, Message, GroupChat, GroupMessages
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import secrets

bp = Blueprint('routes', __name__)

def serialize_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

def deserialize_public_key(pem_str):
    pem = pem_str.encode('utf-8')
    public_key = serialization.load_pem_public_key(
        pem,
        backend=default_backend()
    )
    return public_key

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def decrypt_message(ciphertext, private_key):
    plaintext = private_key.decrypt(
        base64.b64decode(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

def generate_token():
    return secrets.token_hex(32)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Brak tokenu autoryzacji"}), 401

        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
        else:
            return jsonify({"error": "Nieprawidłowy format tokenu"}), 401

        user = session.query(User).filter_by(token=token).first()
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
    public_key = data.get('public_key')

    if not username or not email or not password or not public_key:
        return jsonify({"error": "Wszystkie pola (username, email, password, public_key) są wymagane"}), 400
    if session.query(User).filter_by(username=username).first():
        return jsonify({"error": "Użytkownik już istnieje"}), 400
    if session.query(User).filter_by(email=email).first():
        return jsonify({"error": "Email jest już używany"}), 400

    try:
        serialization.load_pem_public_key(public_key.encode())
    except ValueError:
        return jsonify({"error": "Klucz publiczny ma nieprawidłowy format"}), 400

    new_user = User(
        username=username,
        email=email,
        public_key=public_key
    )
    new_user.set_password(password)
    session.add(new_user)
    session.commit()

    token = secrets.token_hex(32)
    new_user.token = token
    session.commit()

    return jsonify({
        "message": "Rejestracja zakończona sukcesem",
        "user_id": new_user.id,
        "token": token
    })

def serialize_public_key(public_key):
    """Serializuje klucz publiczny do formatu PEM"""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')


@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = session.query(User).filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Nieprawidłowe dane logowania"}), 401

    user.token = secrets.token_hex(32)
    session.commit()

    return jsonify({
        "user_id": user.id,
        "token": user.token
    })

@bp.route('/logout', methods=['POST'])
@login_required
def logout():
    current_user = g.current_user
    current_user.is_active = False
    current_user.token = None
    session.commit()
    return jsonify({"message": "Wylogowano pomyślnie"})


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
    user_id = request.args.get('user_id')
    user = session.query(User).get(user_id)
    return jsonify({'isActive': user.is_active})


@bp.route('/createChat', methods=['POST'])
@login_required
def createChat():
    data = request.get_json()
    second_user_id = data.get('second_user_id')

    second_user = session.query(User).filter_by(id=second_user_id).first()
    if not second_user:
        return jsonify({"error": "Użytkownik o podanym ID nie istnieje"}), 404

    existing_chat = session.query(Chat).filter(
        (Chat.first_user_id == g.current_user.id) & (Chat.second_user_id == second_user_id) |
        (Chat.first_user_id == second_user_id) & (Chat.second_user_id == g.current_user.id)
    ).first()
    if existing_chat:
        return jsonify({"error": "Czat z tym użytkownikiem już istnieje", "chat_id": existing_chat.id}), 409

    new_chat = Chat(first_user_id=g.current_user.id, second_user_id=second_user_id)
    session.add(new_chat)
    try:
        session.commit()
        return jsonify({"message": "Stworzenie czatu zakończone sukcesem", "chat_id": new_chat.id})
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
            'first_user': chat.first_user_id,
            'second_user': chat.second_user_id,
        }
        chat_list.append(chat_data)

    return jsonify(chat_list)

@bp.route('/sendActivity', methods=['POST'])
@login_required
def sendActivity():
    user = session.query(User).get(g.current_user.id)
    user.set_activity(True)
    user.set_last_seen = datetime.utcnow()
    try:
        session.commit()
        return jsonify({"message": "Pomyślnie wysłano aktywność do serwera"})
    except Exception as e:
        print(e)
        return jsonify({"message": "Wysłanie aktywności nie powiodło się"})

@bp.route('/getPublicKey', methods=['GET'])
@login_required
def getPublicKey():
    print("Żądanie klucza publicznego dla użytkownika ID:", request.args.get("user_id"))
    user_id = request.args.get('user_id')

    user = session.query(User).filter_by(id=user_id).first()
    if not user or not user.public_key:
        return jsonify({"error": "Nie znaleziono klucza publicznego"}), 404

    return jsonify({"public_key": user.public_key})

@bp.route('/sendMessage', methods=['POST'])
@login_required
def sendMessage():
    try:
        data = request.get_json()
        chat_id = data.get('chat_id')
        encrypted_message = data.get('message')

        if not chat_id or not encrypted_message:
            return jsonify({"error": "chat_id i zaszyfrowana wiadomość są wymagane"}), 400

        chat = session.query(Chat).filter_by(id=chat_id).first()
        if not chat:
            return jsonify({"error": "Czat nie istnieje"}), 404

        if g.current_user.id not in [chat.first_user_id, chat.second_user_id]:
            return jsonify({"error": "Brak dostępu do tego czatu"}), 403

        new_message = Message(
            chat_id=chat_id,
            message=encrypted_message,
            author_id=g.current_user.id
        )
        session.add(new_message)
        session.commit()

        return jsonify({
            "message": "Wiadomość została wysłana",
            "chat_id": chat_id,
            "message_id": new_message.id
        }), 201

    except Exception as e:
        session.rollback()
        return jsonify({"error": f"Błąd podczas wysyłania wiadomości: {str(e)}"}), 500
@bp.route('/getMessages', methods=['GET'])
@login_required
def get_messages():
    try:
        chat_id = request.args.get('chat_id')
        if not chat_id:
            return jsonify({"error": "Nie podano chat_id"}), 400

        chat = session.query(Chat).filter_by(id=chat_id).first()
        if not chat:
            return jsonify({"error": "Chat nie istnieje"}), 404

        if g.current_user.id not in [chat.first_user_id, chat.second_user_id]:
            return jsonify({"error": "Brak dostępu do czatu"}), 403

        messages = session.query(Message).filter_by(chat_id=chat.id).order_by(Message.timestamp.asc()).all()
        messages_list = []

        for message in messages:
            message_data = {
                'message_id': message.id,
                'author_id': message.author_id,
                'message': message.message,
                'timestamp': message.timestamp.isoformat() if message.timestamp else None,
            }
            messages_list.append(message_data)

        return jsonify(messages_list)

    except Exception as e:
        return jsonify({"error": f"Błąd podczas pobierania wiadomości: {str(e)}"}), 500

@bp.route('/createGroupChat', methods=['POST'])
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


@bp.route('/getGroupChats', methods=['GET'])
@login_required
def get_group_chats():
    group_chats = session.query(GroupChat).all()

    chats_data = []
    for chat in group_chats:
        try:
            members = json.loads(chat.members)
            if g.current_user.id in members:
                chats_data.append({
                    'id': chat.id,
                    'members': members,
                })
        except json.JSONDecodeError:
            print("Problem podczas parsowania JSON'a w krotce " + chat.id)
            continue

    return chats_data, 200