from dataclasses import dataclass, field
from typing import Optional
from threads import ThreadManager, Thread


@dataclass(slots=True)
class Board:
    name: str
    description: str
    creator: int
    deleted: bool = False
    moderators: set[int] = field(default_factory=set)

    def __str__(self) -> str:
        deleted_marker = " [DELETED]" if self.deleted else ""
        return f"Board '{self.name}': {self.description}{deleted_marker}"


class BoardManager:
    def __init__(self) -> None:
        self.boards: dict[str, Board] = {}
        self.thread_managers: dict[str, ThreadManager] = {}

    def add_board(self, name: str, description: str, creator: int) -> bool:
        if name in self.boards:
            return False
        board = Board(name, description, creator)
        board.moderators.add(creator)  # creator is first mod
        self.boards[name] = board
        self.thread_managers[name] = ThreadManager()
        return True

    def del_board(self, name: str) -> bool:
        if name in self.boards:
            self.boards[name].deleted = True
            return True
        return False

    def restore_board(self, name: str) -> bool:
        if name in self.boards:
            self.boards[name].deleted = False
            return True
        return False

    def get_boards(self) -> list[Board]:
        return [board for board in self.boards.values() if not board.deleted]

    def get_thread_manager(self, board_name: str) -> Optional[ThreadManager]:
        return self.thread_managers.get(board_name)

    def add_moderator(self, board_name: str, user_id: int) -> bool:
        board = self.boards.get(board_name)
        if board and not board.deleted:
            board.moderators.add(user_id)
            return True
        return False

    def remove_moderator(self, board_name: str, user_id: int) -> bool:
        board = self.boards.get(board_name)
        if board and not board.deleted and user_id in board.moderators:
            board.moderators.remove(user_id)
            return True
        return False

    def is_moderator(self, board_name: str, user_id: int) -> bool:
        board = self.boards.get(board_name)
        return board is not None and user_id in board.moderators

    # Convenience methods for thread operations
    def create_thread(self, board_name: str, user_id: int, title: str, content: str) -> Optional[Thread]:
        tm = self.get_thread_manager(board_name)
        if tm:
            return tm.new_thread(user_id, title, content)
        return None

    def delete_thread(self, board_name: str, thread_id: int) -> bool:
        tm = self.get_thread_manager(board_name)
        return tm.delete_thread(thread_id) if tm else False

    def delete_post(self, board_name: str, thread_id: int, post_id: int) -> bool:
        tm = self.get_thread_manager(board_name)
        return tm.del_post(thread_id, post_id) if tm else False
