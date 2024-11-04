from threading import Thread
from time import sleep
from datetime import datetime, timedelta, timezone
from app import create_app
from app.models import session, User

app = create_app()


def check_user_activity():
    while True:
        threshold_time = datetime.now(timezone.utc) - timedelta(seconds=60)
        inactive_users = session.query(User).filter(User.is_active == True, User.last_seen < threshold_time).all()

        for user in inactive_users:
            user.is_active = False
            session.commit()
            print(f"Użytkownik {user.username} został ustawiony jako offline z powodu braku aktywności.")

        sleep(60)


# Thread(target=check_user_activity, daemon=True).start()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)