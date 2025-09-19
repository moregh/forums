from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from posts import Post, PostManager


@dataclass(slots=True)
class Thread:
    thread_id: int
    user_id: int
    title: str
    posts: dict[int, Post] = field(default_factory=dict)
    deleted: bool = False
    sticky: bool = False
    timestamp: float = field(default_factory=lambda: datetime.now(timezone.utc).timestamp())

    def __str__(self) -> str:
        deleted_marker = " [DELETED]" if self.deleted else ""
        sticky_marker = " [STICKY]" if self.sticky else ""
        return f"Thread {self.thread_id}: {self.title}{sticky_marker}{deleted_marker}"


class ThreadManager:
    def __init__(self) -> None:
        self.thread_count: int = 0
        self.threads: dict[int, Thread] = {}
        self.pm = PostManager()

    def new_thread(self, user_id: int, title: str, content: str) -> Thread:
        """Create a new thread with its initial post."""
        thread_id = self.thread_count
        self.thread_count += 1

        thread = Thread(thread_id, user_id, title)
        initial_post = self.pm.create_post(thread_id, user_id, content)
        thread.posts[initial_post.post_id] = initial_post

        self.threads[thread_id] = thread
        return thread

    def get_thread(self, thread_id: int) -> Optional[Thread]:
        return self.threads.get(thread_id)

    def delete_thread(self, thread_id: int) -> bool:
        if thread_id in self.threads:
            self.threads[thread_id].deleted = True
            return True
        return False

    def restore_thread(self, thread_id: int) -> bool:
        """Restore a deleted thread."""
        if thread_id in self.threads:
            self.threads[thread_id].deleted = False
            return True
        return False

    def set_sticky(self, thread_id: int, sticky: bool = True) -> bool:
        """Set or unset sticky status for a thread."""
        if thread_id in self.threads:
            self.threads[thread_id].sticky = sticky
            return True
        return False

    def add_reply(self, thread_id: int, user_id: int, content: str) -> Optional[Post]:
        """Add a reply to a thread if it exists and isn't deleted."""
        thread = self.threads.get(thread_id)
        if not thread or thread.deleted:
            return None
        reply = self.pm.create_post(thread_id, user_id, content)
        thread.posts[reply.post_id] = reply
        return reply

    def get_visible_posts(self, thread_id: int) -> list[Post]:
        """Return all non-deleted posts from a thread in order."""
        thread = self.threads.get(thread_id)
        if not thread:
            return []
        return [p for _, p in sorted(thread.posts.items()) if not p.deleted]

    def get_all_posts(self, thread_id: int) -> list[Post]:
        """Return all posts from a thread (including deleted) in order."""
        thread = self.threads.get(thread_id)
        if not thread:
            return []
        return [p for _, p in sorted(thread.posts.items())]

    def del_post(self, thread_id: int, post_id: int) -> bool:
        """Delete a specific post from a thread."""
        thread = self.threads.get(thread_id)
        if not thread or thread.deleted:
            return False
        if post_id in thread.posts:
            return self.pm.delete_post(post_id)
        return False

    def restore_post(self, thread_id: int, post_id: int) -> bool:
        """Restore a specific post in a thread."""
        thread = self.threads.get(thread_id)
        if not thread or thread.deleted:
            return False
        if post_id in thread.posts:
            return self.pm.restore_post(post_id)
        return False

    def get_post_manager(self) -> PostManager:
        """Get the post manager instance."""
        return self.pm

    def get_visible_threads(self) -> list[Thread]:
        """Return all non-deleted threads."""
        return [thread for thread in self.threads.values() if not thread.deleted]

