import sqlite3


class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable dict-like access
        return conn
    
    def execute_query(self, query: str, params: tuple = (), fetch_one: bool = False):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            if fetch_one:
                return cursor.fetchone()
            return cursor.fetchall()
    
    def execute_insert(self, query: str, params: tuple = ()) -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor.lastrowid

