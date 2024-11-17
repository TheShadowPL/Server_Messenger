from threading import Thread
from time import sleep
from flask_cors import CORS
from datetime import datetime, timedelta, timezone
from app import create_app
from app.models import session, User
from sqlalchemy import and_

app = create_app()
CORS(app)

def check_user_activity():
    while True:
        threshold_time = datetime.now(timezone.utc) - timedelta(seconds=60)
        inactive_users = session.query(User).filter(User.is_active == True, User.last_seen < threshold_time).all()

        for user in inactive_users:
            user.is_active = False
            session.commit()
            print(f"Użytkownik {user.username} został ustawiony jako offline z powodu braku aktywności.")

        sleep(60)


Thread(target=check_user_activity, daemon=True).start()

def cleanup_inactive_tokens():
    while True:
        try:
            threshold_time = datetime.now(timezone.utc) - timedelta(weeks=2)

            inactive_users = session.query(User).filter(
                and_(
                    User.is_active == False,
                    User.last_seen < threshold_time,
                    User.token != None
                )
            ).all()

            for user in inactive_users:
                try:
                    user.token = None
                    session.commit()
                    print(f"Zresetowano token użytkownika {user.username} z powodu długiej nieaktywności.")
                except Exception as user_error:
                    print(f"Błąd podczas resetowania tokena dla użytkownika {user.username}: {str(user_error)}")
                    session.rollback()

        except Exception as e:
            print(f"Błąd w funkcji cleanup_inactive_tokens: {str(e)}")
            session.rollback()

        finally:
            sleep(60)


Thread(target=cleanup_inactive_tokens, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)