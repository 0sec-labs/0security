import os

DB_PATH = os.environ.get("REPORTS_DB", "reports.db")
SNAPSHOT_LIMIT = 256 * 1024
