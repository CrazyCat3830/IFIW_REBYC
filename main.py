"""
הקובץ main.py הוא הקובץ ממנו מריצים את כל המערכת.
תחילה קורא ל-login_mainloop שאחראית על מסך ההתחברות ל-firebase.
אם ההתחברות נכשלת - התוכנית נעצרת.
אחרת, נוצר רכיב ה-Orchestrator שאחראי לתיאום הפעילות בין רכיבי המערכת:
(ניטור, זיהוי מתקפות, מסד הנתונים וממשק המשתמש).
"""

from orchestrator import Orchestrator
from login_poc import login_mainloop
from dashboard import start_dashboard


def main():
    ok, uid, token = login_mainloop()  # starts login screen, returns login_success, current_user_uid, current_user_token
    if not ok:
        return

    orch = Orchestrator(
        db_path="DB.db",
        firebase_uid=uid,
        firebase_token=token
    )

    start_dashboard(orch, db_path="DB.db")  # main screen of the program


if __name__ == "__main__":
    main()
