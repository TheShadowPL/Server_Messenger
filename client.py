import requests
import threading
import time
from datetime import datetime

BASE_URL = "http://localhost:5001"

session_info = {
    "current_user": None,
}


def register_user(username, password, email):
    url = f"{BASE_URL}/register"
    try:
        response = requests.post(url, json={"username": username, "email": email, "password": password})
        response.raise_for_status()
        data = response.json()
        if "user_id" in data:
            session_info["current_user"] = {"username": username, "user_id": data["user_id"], "email": email, "hasło":password}
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
        session_info["current_user"] = {"username": username, "user_id": data["user_id"]}
        threading.Thread(target=send_heartbeat, daemon=True).start()
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


def create_chat(name):
    print("Stworzono Chat : " + name)


def send_message(content):
    print('Wysłano wiadomosc : ' + content)


def get_users():
    url = f"{BASE_URL}/getUsers"
    try:
        response = requests.get(url)
        users = response.json()
        return users
    except requests.exceptions.RequestException as e:
        print("Błąd przy pobieraniu listy użytkowników:", e)

def get_activity(userId):
    url = f"{BASE_URL}/getActivity"
    try:
        response = requests.get(url, json={"user_id": userId})
        return response.json()
    except requests.exceptions.RequestException as e:
        print("Błąd przy sprawdzaniu aktywności:", e)

def get_chats():
    print('Chaty :')


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
    print("5. Pobierz listę użytkowników")
    print("6. Pobierz listę czatów")
    print("7. Pobierz wiadomości z bieżącego czatu")
    print("8. Wybierz czat")
    print("9. Pokaż informacje o sesji")
    print("10. Czy użytkownik jest aktywny")
    print("11. Wyjście")
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
            chat_name = input("Podaj nazwę czatu: ")
            print(create_chat(chat_name))

        elif choice == "4":
            content = input("Podaj treść wiadomości: ")
            print(send_message(content))

        elif choice == "5":
            print(get_users())

        elif choice == "6":
            print(get_chats())

        elif choice == "7":
            print(get_messages())

        elif choice == "8":
            chat_id = int(input("Podaj ID czatu, który chcesz wybrać: "))
            print(select_chat(chat_id))

        elif choice == "9":
            print("\n--- Informacje o sesji ---")
            print(f"Zalogowany użytkownik: {session_info['current_user']}")
            print(f"Dostępne czaty: []")
            print(f"Bieżący czat: Brak")

        elif choice == "10":
            print("\n--- Czy użytkownik jest aktywny ---")
            userId = input("Wprowadź id usera do sprawdzenia: ")
            print(get_activity(userId))

        elif choice == "11":
            print("Zamykanie klienta...")
            session_info["current_user"] = None
            break

        else:
            print("Niepoprawny wybór. Spróbuj ponownie.")


if __name__ == "__main__":
    main()