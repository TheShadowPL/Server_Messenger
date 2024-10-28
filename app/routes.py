from flask import Blueprint, request, jsonify
from .models import session, User

bp = Blueprint('routes', __name__)


@bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if session.query(User).filter_by(username=username).first():
        return jsonify({"error": "Użytkownik już istnieje"}), 400

    new_user = User(username=username)
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
        return jsonify({"message": "Zalogowano pomyślnie", "user_id": user.id})
    else:
        return jsonify({"error": "Nieprawidłowa nazwa użytkownika lub hasło"}), 401