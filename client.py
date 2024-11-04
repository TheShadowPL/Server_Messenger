import requests
import threading
import time
from datetime import datetime

BASE_URL = "http://localhost:5001"

session_info = {
    "current_user": None,
}

def get_headers():
    if session_info.get("current_user"):
        return {"Authorization": f"{session_info['current_user']['token']}"}
    return {}

def register_user(username, password, email):
    url = f"{BASE_URL}/register"
    try:
        response = requests.post(url, json={"username": username, "email": email, "password": password})
        response.raise_for_status()
        data = response.json()
        if "user_id" in data:
            session_info["current_user"] = {"username": username, "user_id": data["user_id"], "email": email, "hasło": password}
        return data
    except requests.exceptions.JSONDecodeError:
        print("Błąd dekodowania JSON z odpowiedzi serwera. Odpowiedź:")
        print(response.text)
        return {"error": "Nie udało się zdekodować odpowiedzi JSON"}
    except requests.exceptions.RequestException as e:
        print(f"Błąd zapytania: {e}")
        print("Treść odpowiedzi serwera:")
        print(response.text)
        return {"error": "Błąd połączenia lub zapytania"}

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

def send_message(content):
    print('Wysłano wiadomosc : ' + content)


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


def get_messages():
    print('Wiadomosci :')


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
            content = input("Podaj treść wiadomości: ")
            print(send_message(content))

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