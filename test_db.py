import sqlite3
from pathlib import Path
import os

# Mocking some parts of app.py to test the query logic
DATA_DIR = Path(os.environ.get("LOCALAPPDATA", ".")) / "CyberProxyDefender"
DATABASE = DATA_DIR / "users.db"

def test_query():
    try:
        db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        
        # Test get_traffic_data query
        traffic_feed_rows = db.execute(
            """
            SELECT
                username, client_ip, proxy_ip, url, website_domain, target_ip,
                method, protocol, status, threat_level, bandwidth_kb, requested_at,
                strftime('%H:%M:%S', requested_at) AS request_time
            FROM logs
            ORDER BY requested_at DESC
            LIMIT 10
            """
        ).fetchall()
        
        print(f"Fetched {len(traffic_feed_rows)} rows")
        for row in traffic_feed_rows:
            d = dict(row)
            print(f"Row serialized: {d['url']}")
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    test_query()
