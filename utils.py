from datetime import datetime, timezone

def timestamp() -> float:
    return datetime.now(timezone.utc).timestamp()

