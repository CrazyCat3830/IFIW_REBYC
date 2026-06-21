"""
קובץ זה אחראי על התקשורת בין המערכת לבין Firebase Realtime Database.

הקובץ מאפשר שמירת התראות (Alerts) וטעינת התראות של המשתמש המחובר.
הגישה לנתונים מתבצעת באמצעות ה-UID וה-Authentication Token שהתקבלו
בתהליך ההתחברות ל-Firebase.
"""
import requests
import os
from dotenv import load_dotenv

load_dotenv()

FIREBASE_DB_URL = os.getenv("FIREBASE_DB_URL")


def save_alert(uid, token, alert_id, alert_data):
    """
    Saves an alert to Firebase Realtime Database
    under the currently authenticated user.
    """
    if not uid or not token:
        return

    url = f"{FIREBASE_DB_URL}/alerts/{uid}/{alert_id}.json?auth={token}"
    r = requests.put(url, json=alert_data, timeout=10)  # http put request

    if r.status_code != 200:
        print("Firebase save error:", r.text)


def load_alerts(uid, token):
    """
    Loads all alerts that belong to the
    currently authenticated user.
    """
    if not uid or not token:
        return {}

    url = f"{FIREBASE_DB_URL}/alerts/{uid}.json?auth={token}"
    r = requests.get(url, timeout=10)  # http get request

    if r.status_code == 200 and r.json():
        return r.json()

    return {}
