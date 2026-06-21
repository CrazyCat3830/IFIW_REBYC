"""
קובץ זה אחראי על תהליך ההזדהות של המשתמש מול Firebase Authentication.

הקובץ מציג חלון התחברות והרשמה באמצעות Tkinter, שולח את פרטי המשתמש
ל-Firebase באמצעות REST API, ומקבל בחזרה מזהה משתמש ייחודי (UID) ואסימון התחברות (Token).

ה-UID וה-Token מוחזרים ל-main.py ומשמשים בהמשך לגישה מאובטחת להתראות השייכות למשתמש המחובר בלבד.
"""
import os  # for getenv
from tkinter import messagebox, Tk, Label, Entry, Button, StringVar  # login screen
import requests  # http requests to firebase
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("FIREBASE_API_KEY")  # gets API key from .env file, in a variable named FIREBASE_API_KEY
IDT_BASE = "https://identitytoolkit.googleapis.com/v1"  # Firebase Identity Toolkit address

current_user_uid = None
current_user_token = None
login_root = None
login_success = False


def signin_email_password():
    """
    Authenticates an existing user using Firebase Authentication.

    On success, stores the user's UID and authentication token
    and closes the login window.
    """
    global login_success, login_root
    global current_user_uid, current_user_token

    email = email_var.get()
    password = passw_var.get()

    if not email or not password:
        messagebox.showwarning("Missing info", "Please enter both email and password.")
        return

    try:
        url = f"{IDT_BASE}/accounts:signInWithPassword?key={API_KEY}"
        payload = {"email": email, "password": password, "returnSecureToken": True}
        r = requests.post(url, json=payload, timeout=15)
        r.raise_for_status()

        data = r.json()

        current_user_uid = data.get("localId")
        current_user_token = data.get("idToken")

        login_success = True
        messagebox.showinfo("Login successful", f"Welcome {email}")
        login_root.destroy()

    except requests.exceptions.HTTPError:
        msg = extract_firebase_error(r)
        messagebox.showerror("Login failed", msg)
    except requests.exceptions.RequestException as e:
        messagebox.showerror("Network error", str(e))


def signup_email_password():
    """
    Creates a new Firebase Authentication account using
    the email and password entered by the user.
    """
    email = email_var.get()
    password = passw_var.get()

    if not email or not password:
        messagebox.showwarning("Missing info", "Please enter both email and password.")
        return

    try:
        url = f"{IDT_BASE}/accounts:signUp?key={API_KEY}"
        payload = {"email": email, "password": password, "returnSecureToken": True}
        r = requests.post(url, json=payload, timeout=15)
        r.raise_for_status()

        messagebox.showinfo("Success", "Account created successfully!")

    except requests.exceptions.HTTPError:
        msg = extract_firebase_error(r)
        messagebox.showerror("Sign up failed", msg)
    except requests.exceptions.RequestException as e:
        messagebox.showerror("Network error", str(e))


def extract_firebase_error(response):
    """
    Extracts the detailed error message returned by Firebase.

    Firebase often returns useful error codes inside the JSON response,
    such as INVALID_LOGIN_CREDENTIALS or EMAIL_EXISTS.
    This function makes sure the user sees the real Firebase error
    instead of only a generic HTTP 400 error.
    """
    try:
        error_data = response.json()
        return error_data["error"]["message"]
    except Exception:
        return response.text or "Unknown Firebase error"


def login_mainloop():
    """
    Creates and displays the login window.

    Returns:
        (login_success, user_uid, user_token)
    """
    global email_var, passw_var, login_root, login_success
    global current_user_uid, current_user_token

    login_success = False
    current_user_uid = None
    current_user_token = None

    login_root = Tk()
    login_root.title("Login")

    email_var = StringVar()
    passw_var = StringVar()

    Label(login_root, text="Email").grid(row=0, column=0)
    Entry(login_root, textvariable=email_var).grid(row=0, column=1)

    Label(login_root, text="Password").grid(row=1, column=0)
    Entry(login_root, textvariable=passw_var, show="*").grid(row=1, column=1)

    Button(login_root, text="Login", command=signin_email_password).grid(row=2, column=1)
    Button(login_root, text="Sign Up", command=signup_email_password).grid(row=3, column=1)

    login_root.mainloop()

    return login_success, current_user_uid, current_user_token
