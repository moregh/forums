from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional


@dataclass(slots=True)
class Post:
    post_id: int
    thread_id: int
    user_id: int
    content: str
    deleted: bool = False
    timestamp: float = field(default_factory=lambda: datetime.now(timezone.utc).timestamp())

    def __str__(self) -> str:
        deleted_marker = " [DELETED]" if self.deleted else ""
        return f"Post {self.post_id}: {self.content[:50]}...{deleted_marker}"


class PostManager:
    def __init__(self) -> None:
        self.post_count: int = 0
        self.posts: dict[int, Post] = {}

    def create_post(self, thread_id: int, user_id: int, content: str) -> Post:
        """Create and register a new post."""
        post = Post(self.post_count, thread_id, user_id, content)
        self.posts[self.post_count] = post
        self.post_count += 1
        return post

    def get_post(self, post_id: int) -> Optional[Post]:
        return self.posts.get(post_id)

    def delete_post(self, post_id: int) -> bool:
        if post_id in self.posts:
            self.posts[post_id].deleted = True
            return True
        return False

    def restore_post(self, post_id: int) -> bool:
        """Restore a deleted post."""
        if post_id in self.posts:
            self.posts[post_id].deleted = False
            return True
        return False