"""
קובץ זה אחראי על זיהוי מיקום גיאוגרפי של כתובת IP.

אם קיימים הספרייה geoip2 וקובץ מסד הנתונים GeoLite2-City.mmdb,
הקובץ מחזיר מדינה, עיר וקואורדינטות עבור כתובת IP.

זהו פיצ'ר אופציונלי: אם הקובץ או הספרייה לא קיימים,
המערכת ממשיכה לעבוד ללא מידע גיאוגרפי.
"""
from __future__ import annotations
import os

try:
    import geoip2.database
except Exception:
    geoip2 = None

reader = None
_db_path = "GeoLite2-City.mmdb"
if geoip2 is not None and os.path.exists(_db_path):
    try:
        reader = geoip2.database.Reader(_db_path)
    except Exception:
        reader = None


def lookup_ip(ip: str):
    """
    Looks up geographic information for an IP address.

    Returns country, city, latitude and longitude if available.
    Returns None if GeoIP is not configured or lookup fails.
    """
    if not reader or not ip:
        return None
    try:
        r = reader.city(ip)
        return {
            "country": r.country.name,  # Country name associated with the IP address
            "city": r.city.name,  # City associated with the IP address
            "latitude": r.location.latitude,  # Geographic latitude (north-south position on Earth)
            "longitude": r.location.longitude,  # Geographic longitude (east-west position on Earth)
        }
    except Exception:
        return None
