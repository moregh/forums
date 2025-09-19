#!/usr/bin/env python3












# forum.py
from forum import Forum


# main.py
if __name__ == "__main__":
    # Initialize the forum
    forum = Forum()
    
    # Create some test users
    alice = forum.create_user("alice", "alice@example.com", "alice_hash")
    bob = forum.create_user("bob", "bob@example.com", "bob_hash")
    charlie = forum.create_user("charlie", "charlie@example.com", "charlie_hash")
    
    print("Users created:")
    print(f"- {alice}")
    print(f"- {bob}")
    print(f"- {charlie}")
    
    # Create a board
    if alice:
        forum.create_board("tech", "Technology discussions", alice.user_id)
        print("\nBoard created: tech")
    
    # Create a thread
    if bob:
        thread = forum.post_message("tech", bob.user_id, "Python vs Rust", "Which is better?")
        print(f"\nThread created: {thread}")
        
        # Add replies
        if charlie:
            reply1 = forum.reply_to_thread("tech", thread.thread_id, charlie.user_id, "Rust is faster!")
            print(f"Reply added: {reply1}")
            
            reply2 = forum.reply_to_thread("tech", thread.thread_id, alice.user_id, "Python development is faster!")
            print(f"Reply added: {reply2}")
            
            reply3 = forum.reply_to_thread("tech", thread.thread_id, bob.user_id, "What about Haskell?")
            print(f"Reply added: {reply3}")
            
            reply4 = forum.reply_to_thread("tech", thread.thread_id, charlie.user_id, "Bring in the banhammer")
            print(f"Reply added: {reply4}")
            
            # Moderate a post (delete it)
            if alice and reply4:
                success = forum.moderate_post("tech", thread.thread_id, reply4.post_id, alice.user_id, "delete")
                print(f"Post moderated (deleted): {success}")
                
            # Add another reply
            reply5 = forum.reply_to_thread("tech", thread.thread_id, bob.user_id, "It's gone!")
            print(f"Reply added: {reply5}")
            
            # Get visible posts
            tm = forum.board_manager.get_thread_manager("tech")
            if tm:
                posts = tm.get_visible_posts(thread.thread_id)
                print(f"\nVisible posts in thread:")
                for post in posts:
                    user = forum.user_manager.get_user(post.user_id)
                    username = user.username if user else f"User {post.user_id}"
                    print(f"  - {username}: {post.content}")
    
    print(f"\nForum statistics:")
    print(f"- Total users: {forum.user_manager.user_count}")
    print(f"- Total boards: {len(forum.board_manager.get_boards())}")
    
    # Demonstrate web server (stub)
    print(f"\nStarting web server...")
    forum.start_web_server("localhost", 8080)