from typing import Optional
from posts import Post
from threads import Thread
from users import UserManager, User
from boards import BoardManager
from database import DatabaseManager
from web_interface import WebInterface


class Forum:
    """Main Forum class that orchestrates all components."""
    
    def __init__(self, database_connection_string: str = ""):
        self.user_manager = UserManager()
        self.board_manager = BoardManager()
        self.database = DatabaseManager(database_connection_string)
        self.web_interface = WebInterface(self)
        
        # Create default admin user
        admin = self.user_manager.create_user("admin", "admin@forum.com", "admin_hash")
        if admin:
            self.user_manager.make_admin(admin.user_id)
    
    def get_user_manager(self) -> UserManager:
        return self.user_manager
    
    def get_board_manager(self) -> BoardManager:
        return self.board_manager
    
    def get_database(self) -> DatabaseManager:
        return self.database
    
    def get_web_interface(self) -> WebInterface:
        return self.web_interface
    
    # High-level forum operations
    def create_user(self, username: str, email: str, password: str = "") -> Optional[User]:
        """Create a new user account."""
        user = self.user_manager.create_user(username, email, password)
        if user:
            self.database.save_user(user)
        return user
    
    def create_board(self, name: str, description: str, creator_id: int) -> bool:
        """Create a new board."""
        success = self.board_manager.add_board(name, description, creator_id)
        if success:
            board = self.board_manager.boards[name]
            self.database.save_board(board)
        return success
    
    def post_message(self, board_name: str, user_id: int, title: str, content: str) -> Optional[Thread]:
        """Create a new thread in a board."""
        # Check if user is banned
        user = self.user_manager.get_user(user_id)
        if not user or user.is_banned:
            return None
            
        thread = self.board_manager.create_thread(board_name, user_id, title, content)
        if thread:
            self.user_manager.increment_post_count(user_id)
            self.user_manager.update_activity(user_id)
            self.database.save_thread(thread)
        return thread
    
    def reply_to_thread(self, board_name: str, thread_id: int, user_id: int, content: str) -> Optional[Post]:
        """Reply to an existing thread."""
        # Check if user is banned
        user = self.user_manager.get_user(user_id)
        if not user or user.is_banned:
            return None
            
        tm = self.board_manager.get_thread_manager(board_name)
        if not tm:
            return None
            
        reply = tm.add_reply(thread_id, user_id, content)
        if reply:
            self.user_manager.increment_post_count(user_id)
            self.user_manager.update_activity(user_id)
            self.database.save_post(reply)
        return reply
    
    def moderate_post(self, board_name: str, thread_id: int, post_id: int, moderator_id: int, action: str) -> bool:
        """Moderate a post (delete/restore)."""
        # Check if user is moderator or admin
        user = self.user_manager.get_user(moderator_id)
        if not user:
            return False
            
        is_mod = self.board_manager.is_moderator(board_name, moderator_id)
        if not (user.is_admin or is_mod):
            return False
            
        tm = self.board_manager.get_thread_manager(board_name)
        if not tm:
            return False
            
        if action == "delete":
            return tm.del_post(thread_id, post_id)
        elif action == "restore":
            return tm.restore_post(thread_id, post_id)
        return False
    
    def start_web_server(self, host: str = "localhost", port: int = 8000) -> bool:
        """Start the web interface."""
        self.web_interface.host = host
        self.web_interface.port = port
        return self.web_interface.start_server()
    
    def stop_web_server(self) -> bool:
        """Stop the web interface."""
        return self.web_interface.stop_server()
