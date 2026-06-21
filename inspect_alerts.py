"""
Utility script for inspecting alerts stored in the local database.

Used during development and debugging to display recently detected
alerts without launching the full dashboard.
"""
from database import Database


def main():
    """
    Prints the most recent alerts stored in the database.
    """
    db = Database("DB.db")
    alerts = db.get_recent_alerts(limit=50)
    for a in alerts:
        print(
            f"#{a['alert_id']} | {a['timestamp']} | {a['alert_type']} | sev={a['severity']} | "
            f"{a['description']} | pcap={a.get('pcap_path')}"
        )
    db.close()


if __name__ == "__main__":
    main()


"""
זה כלי Debug קטן שנועד לבדוק במהירות אילו Alerts נשמרו במסד הנתונים, בלי להפעיל את כל המערכת וה־Dashboard.
"""
