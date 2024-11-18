import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os
import requests
import threading
import time
from datetime import datetime
import os


BASE_URL = "http://localhost:5001"

session_info = {
    "current_user": None,
}


def generate_rsa_keys():
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        return private_key, public_key
    except Exception as e:
        print(f"Błąd podczas generowania kluczy RSA: {e}")

def save_private_key(username, private_key):
    try:
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(f"{username}_private_key.pem", "wb") as f:
            f.write(pem)
        print(f"Klucz prywatny zapisany dla użytkownika: {username}")
    except Exception as e:
        print(f"Błąd przy zapisywaniu klucza prywatnego: {e}")

def load_private_key(username):
    try:
        with open(f"{username}_private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        print(f"Klucz prywatny wczytany dla użytkownika: {username}")
        return private_key
    except Exception as e:
        print(f"Błąd przy wczytywaniu klucza prywatnego: {e}")

def encrypt_message(message, recipient_public_key_pem):
    try:
        public_key = serialization.load_pem_public_key(recipient_public_key_pem.encode())
        encrypted = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Wiadomość zaszyfrowana: {message}")
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        print(f"Błąd podczas szyfrowania wiadomości: {e}")
        return None

def decrypt_message(encrypted_message, private_key):
    try:
        decrypted = private_key.decrypt(
            base64.b64decode(encrypted_message),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Wiadomość odszyfrowana: {decrypted.decode()}")
        return decrypted.decode()
    except Exception as e:
        print(f"Błąd podczas odszyfrowywania wiadomości: {e}")
        return None

def register_user(username, password, email):
    private_key, public_key = generate_rsa_keys()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    with open(f"{username}_private_key.pem", "w") as f:
        f.write(private_key_pem)

    url = f"{BASE_URL}/register"
    response = requests.post(url, json={"username": username, "email": email, "password": password, "public_key": public_key_pem})
    return response.json()


def get_headers():
    if session_info.get("current_user"):
        return {"Authorization": f"{session_info['current_user']['token']}"}
    return {}

def register_user(username, password, email):
    try:
        private_key, public_key = generate_rsa_keys()
        save_private_key(username, private_key)

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        url = f"{BASE_URL}/register"
        response = requests.post(url, json={
            "username": username,
            "email": email,
            "password": password,
            "public_key": public_key_pem
        })
        response.raise_for_status()
        data = response.json()
        print("Rejestracja zakończona:", data)
        return data
    except requests.exceptions.RequestException as e:
        print(f"Błąd rejestracji użytkownika: {e}")
        return {"error": "Nie udało się zarejestrować użytkownika"}

def login_user(username, password):
    url = f"{BASE_URL}/login"
    response = requests.post(url, json={"username": username, "password": password})
    data = response.json()
    if "user_id" in data:
        session_info["current_user"] = {"username": username, "user_id": data["user_id"], "token": data["token"]}
        #threading.Thread(target=send_heartbeat, daemon=True).start()
    return data

def send_heartbeat():
    while session_info["current_user"]:
        url = f"{BASE_URL}/heartbeat"
        try:
            response = requests.post(url, json={"user_id": session_info["current_user"]["user_id"]})
            print("wysłano pinga:", response.json())
        except requests.exceptions.RequestException as e:
            print("Błąd przy wysyłaniu pinga:", e)

        time.sleep(58)

def create_chat(first_user_id, second_user_id):
    url = f"{BASE_URL}/createChat"
    headers = get_headers()
    try:
        response = requests.post(url, json={"first_user_id": first_user_id, "second_user_id": second_user_id}, headers=headers)
        print(response.json())
    except requests.exceptions.RequestException as e:
        print("Nie mozna bylo utworzyc czatu", e)


def get_recipient_public_key(recipient_id):
    try:
        if not session_info.get("current_user") or not session_info["current_user"].get("token"):
            print("Błąd: Użytkownik nie jest zalogowany lub brak tokenu")
            return None

        token = session_info["current_user"]["token"]
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{BASE_URL}/getPublicKey?user_id={recipient_id}"

        print("Nagłówki żądania:", headers)
        print("Adres URL żądania:", url)

        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        print("Pobrano klucz publiczny odbiorcy:", data)
        return data.get("public_key")
    except requests.exceptions.HTTPError as http_err:
        print(f"Błąd HTTP: {http_err.response.status_code} - {http_err.response.text}")
    except requests.exceptions.RequestException as req_err:
        print(f"Błąd przy pobieraniu klucza publicznego: {req_err}")
    return None

def send_message(chat_id, recipient_id, message):
    try:
        recipient_public_key = get_recipient_public_key(recipient_id)
        if not recipient_public_key:
            print("Nie można pobrać klucza publicznego odbiorcy")
            return {"error": "Brak klucza publicznego odbiorcy"}

        encrypted_message = encrypt_message(message, recipient_public_key)
        headers = {"Authorization": f"Bearer {session_info['current_user']['token']}"}

        url = f"{BASE_URL}/sendMessage"
        response = requests.post(url, json={
            "chat_id": chat_id,
            "message": encrypted_message
        }, headers=headers)
        response.raise_for_status()
        data = response.json()
        print("Wiadomość wysłana:", data)
        return data
    except requests.exceptions.RequestException as e:
        print(f"Błąd przy wysyłaniu wiadomości: {e}")
        return {"error": "Nie udało się wysłać wiadomości"}

def get_messages(chat_id):
    try:
        headers = {"Authorization": f"Bearer {session_info['current_user']['token']}"}
        url = f"{BASE_URL}/getMessages?chat_id={chat_id}"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        messages = response.json()

        private_key = load_private_key(session_info["current_user"]["username"])
        print("\n--- Wiadomości w czacie ---")
        for msg in messages:
            try:
                decrypted_message = decrypt_message(msg["message"], private_key)
                print(f"ID Nadawcy: {msg['author_id']}, Czas: {msg['timestamp']}")
                print(f"Wiadomość: {decrypted_message}\n")
            except Exception as e:
                print(f"Błąd podczas odszyfrowywania wiadomości (ID: {msg['message_id']}): {e}")
    except requests.exceptions.RequestException as e:
        print(f"Błąd przy pobieraniu wiadomości: {e}")

def send_group_message(group_chat_id, content):
    if not session_info.get("current_user"):
        print("Musisz być zalogowany, aby wysyłać wiadomości.")
        return

    url = f"{BASE_URL}/sendGroupMessage"
    headers = get_headers()

    try:
        response = requests.post(
            url,
            json={"group_chat_id": group_chat_id, "content": content},
            headers=headers
        )
        data = response.json()
        if response.status_code == 201:
            print("Wiadomość wysłana pomyślnie:", data)
        else:
            print("Błąd przy wysyłaniu wiadomości:", data.get("error"))
    except requests.exceptions.RequestException as e:
        print("Błąd połączenia:", e)


def create_group_chat(members):
    if not session_info.get("current_user"):
        print("Musisz być zalogowany, aby tworzyć czaty grupowe.")
        return

    url = f"{BASE_URL}/CreateGroupChat"
    headers = get_headers()

    try:
        response = requests.post(
            url,
            json={"members": members},
            headers=headers
        )
        data = response.json()
        if response.status_code == 201:
            print("Czat grupowy utworzony pomyślnie:", data)
        else:
            print("Błąd przy tworzeniu czatu grupowego:", data.get("error"))
    except requests.exceptions.RequestException as e:
        print("Błąd połączenia:", e)

def get_users():
    url = f"{BASE_URL}/getUsers"
    headers = get_headers()
    try:
        response = requests.get(url, headers=headers)
        users = response.json()
        return users
    except requests.exceptions.RequestException as e:
        print("Błąd przy pobieraniu listy użytkowników:", e)

def get_activity(userId):
    url = f"{BASE_URL}/getActivity"
    headers = get_headers()
    try:
        response = requests.get(url, json={"user_id": userId}, headers=headers)
        return response.json()
    except requests.exceptions.RequestException as e:
        print("Błąd przy sprawdzaniu aktywności:", e)


def invite_to_group_chat(group_chat_id, user_id):
    if not session_info.get("current_user"):
        print("Musisz być zalogowany, aby zapraszać użytkowników do czatu grupowego.")
        return

    url = f"{BASE_URL}/inviteToGroupChat"
    headers = get_headers()

    try:
        response = requests.post(
            url,
            json={"group_chat_id": group_chat_id, "user_id": user_id},
            headers=headers
        )
        data = response.json()
        if response.status_code == 200:
            print("Użytkownik zaproszony pomyślnie:", data)
        else:
            print("Błąd przy zapraszaniu użytkownika:", data.get("error"))
    except requests.exceptions.RequestException as e:
        print("Błąd połączenia:", e)


def get_group_messages(group_chat_id):
    if not session_info.get("current_user"):
        print("Musisz być zalogowany, aby przeglądać wiadomości.")
        return

    url = f"{BASE_URL}/getGroupMessages?group_chat_id={group_chat_id}"
    headers = get_headers()

    try:
        response = requests.get(url, headers=headers)
        messages = response.json()

        if response.status_code == 200:
            print("\n--- Wiadomości w czacie grupowym ---")
            for message in messages:
                print(f"ID Nadawcy: {message['sender_id']} | Czas: {message['timestamp']}")
                print(f"Wiadomość: {message['content']}\n")
        else:
            print("Błąd przy pobieraniu wiadomości:", messages.get("error"))
    except requests.exceptions.RequestException as e:
        print("Błąd połączenia:", e)


def get_chats():
    url = f"{BASE_URL}/getChats"
    headers = get_headers()
    try:
        response = requests.get(url, headers=headers)
        print(response.json())
    except requests.exceptions.RequestException as e:
        print("Nie mozna bylo uzyskac czatow", e)


def get_messages(chat_id):
    try:
        headers = {"Authorization": f"Bearer {session_info['current_user']['token']}"}
        url = f"{BASE_URL}/getMessages?chat_id={chat_id}"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        messages = response.json()

        private_key = load_private_key(session_info["current_user"]["username"])
        print("\n--- Wiadomości w czacie ---")
        for msg in messages:
            try:
                decrypted_message = decrypt_message(msg["message"], private_key)
                print(f"ID Nadawcy: {msg['author_id']}, Wiadomość: {decrypted_message}")
            except Exception as e:
                print(f"Błąd podczas odszyfrowywania wiadomości: {e}")
    except requests.exceptions.RequestException as e:
        print(f"Błąd przy pobieraniu wiadomości: {e}")


def select_chat(chat_id):
    print('Wybrany chat :' + str(chat_id))

def menu():
    print("\n--- Menu ---")
    print("1. Rejestracja użytkownika")
    print("2. Logowanie użytkownika")
    print("3. Utwórz czat")
    print("4. Wyślij wiadomość")
    print("5 Utwórz chat grupowy")
    print("6 Wyślij wiadomość grupową")
    print("7 Zaproś do chatu")
    print("8 Pobierz wiadomosci z chatu grupowego")
    #print("8. Pobierz listę użytkowników")
    print("9. Pobierz listę czatów")
    print("10. Pobierz wiadomości z bieżącego czatu")
    print("11. Wybierz czat")
    print("12. Pokaż informacje o sesji")
    print("13. Czy użytkownik jest aktywny")
    print("14. Wyjście")
    return input("Wybierz opcję: ")


def main():
    while True:
        choice = menu()

        if choice == "1":
            username = input("Podaj nazwę użytkownika: ")
            password = input("Podaj hasło: ")
            email = input("Podaj email: ")
            print(register_user(username, password, email))

        elif choice == "2":
            username = input("Podaj nazwę użytkownika: ")
            password = input("Podaj hasło: ")
            print(login_user(username, password))

        elif choice == "3":
            first_user_id = input("Podaj id pierwszego uzytkownika: ")
            second_user_id = input("Podaj id drugiego uzytkownika: ")
            print(create_chat(first_user_id, second_user_id))

        elif choice == "4":
            chat_id = input("Podaj ID czatu: ")
            recipient_id = input("Podaj ID odbiorcy: ")
            message = input("Podaj treść wiadomości: ")
            print(send_message(chat_id, recipient_id, message))

        elif choice == "5":
            members = input("Podaj listę ID członków (oddzielone przecinkami): ").split(",")
            members = [int(member.strip()) for member in members]
            create_group_chat(members)

        elif choice == "6":
            group_chat_id = input("Podaj ID czatu grupowego: ")
            content = input("Podaj treść wiadomości: ")
            send_group_message(group_chat_id, content)

        elif choice == "7":
            group_chat_id = input("Podaj ID czatu grupowego: ")
            user_id = input("Podaj ID użytkownika do zaproszenia: ")
            invite_to_group_chat(group_chat_id, user_id)

        elif choice == "8":
            group_chat_id = input("Podaj ID czatu grupowego, którego wiadomości chcesz zobaczyć: ")
            get_group_messages(group_chat_id)
        elif choice == "10":
            caht_id = input("Podaj ID czatu:")
            get_messages(caht_id)

        elif choice == "11":
            chat_id = int(input("Podaj ID czatu, który chcesz wybrać: "))
            print(select_chat(chat_id))

        elif choice == "12":
            print("\n--- Informacje o sesji ---")
            print(f"Zalogowany użytkownik: {session_info['current_user']}")
            print(f"Dostępne czaty: []")
            print(f"Bieżący czat: Brak")

        elif choice == "13":
            print("\n--- Czy użytkownik jest aktywny ---")
            userId = input("Wprowadź id usera do sprawdzenia: ")
            print(get_activity(userId))

        elif choice == "14":
            print("Zamykanie klienta...")
            session_info["current_user"] = None
            break

        else:
            print("Niepoprawny wybór. Spróbuj ponownie.")


if __name__ == "__main__":
    main()