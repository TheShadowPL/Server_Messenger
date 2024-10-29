from datetime import datetime
from flask import Blueprint, request, jsonify
from .models import session, User

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