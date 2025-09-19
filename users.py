from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass(slots=True)
class User:
    user_id: int
    username: str
    email: str
    password_hash: str = ""
    is_admin: bool = False
    is_banned: bool = False
    join_date: float = field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    last_activity: float = field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    post_count: int = 0
    avatar_url: str = ""

    def __str__(self) -> str:
        admin_marker = " [ADMIN]" if self.is_admin else ""
        banned_marker = " [BANNED]" if self.is_banned else ""
        return f"User {self.user_id}: {self.username}{admin_marker}{banned_marker}"


class UserManager:
    def __init__(self) -> None:
        self.user_count: int = 0
        self.users: dict[int, User] = {}
        self.username_to_id: dict[str, int] = {}

    def create_user(self, username: str, email: str, password_hash: str = "") -> Optional[User]:
        """Create a new user."""
        if username in self.username_to_id:
            return None  # Username already exists
        
        user = User(self.user_count, username, email, password_hash)
        self.users[self.user_count] = user
        self.username_to_id[username] = self.user_count
        self.user_count += 1
        return user

    def get_user(self, user_id: int) -> Optional[User]:
        return self.users.get(user_id)

    def get_user_by_username(self, username: str) -> Optional[User]:
        user_id = self.username_to_id.get(username)
        if user_id is not None:
            return self.users.get(user_id)
        return None

    def ban_user(self, user_id: int) -> bool:
        user = self.users.get(user_id)
        if user:
            user.is_banned = True
            return True
        return False

    def unban_user(self, user_id: int) -> bool:
        user = self.users.get(user_id)
        if user:
            user.is_banned = False
            return True
        return False

    def make_admin(self, user_id: int) -> bool:
        user = self.users.get(user_id)
        if user:
            user.is_admin = True
            return True
        return False

    def remove_admin(self, user_id: int) -> bool:
        user = self.users.get(user_id)
        if user:
            user.is_admin = False
            return True
        return False

    def update_activity(self, user_id: int) -> bool:
        user = self.users.get(user_id)
        if user:
            user.last_activity = datetime.now(timezone.utc).timestamp()
            return True
        return False

    def increment_post_count(self, user_id: int) -> bool:
        user = self.users.get(user_id)
        if user:
            user.post_count += 1
            return True
        return False

