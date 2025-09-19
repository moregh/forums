// Frontend Architecture for Forum System
// Static HTML/CSS/JS that consumes the REST API

// =============================================================================
// CRYPTO UTILITIES FOR SECURE PASSWORD HANDLING
// =============================================================================



// =============================================================================
// API CLIENT CONFIGURATION
// =============================================================================



// =============================================================================
// APPLICATION STATE MANAGEMENT
// =============================================================================



// =============================================================================
// ROUTER FOR SINGLE PAGE APPLICATION
// =============================================================================



// =============================================================================
// UI COMPONENTS
// =============================================================================



// =============================================================================
// MAIN APPLICATION CLASS
// =============================================================================

class ForumApp {
    constructor() {
        this.api = new ForumAPI();
        this.state = new ForumState();
        this.router = new Router();
        this.setupRoutes();
        this.setupEventListeners();
        this.init();
    }

    setupRoutes() {
        this.router.register('/', () => this.showHome());
        this.router.register('/login', () => this.showLogin());
        this.router.register('/register', () => this.showRegister());
        this.router.register('/admin', () => this.showAdmin());
        this.router.register('/boards/:id', (params) => this.showBoard(params.id));
        this.router.register('/threads/:id', (params) => this.showThread(params.id));
    }

    setupEventListeners() {
        // State change listeners
        this.state.subscribe('userChanged', (user) => this.updateNavigation(user));
        this.state.subscribe('loadingChanged', (loading) => UIComponents.showLoading(loading));
        this.state.subscribe('errorChanged', (error) => {
            if (error) UIComponents.showError(error);
        });
    }

    async init() {
        // Check if user is logged in
        if (this.api.token && this.api.user) {
            this.state.setState({ user: this.api.user });
            
            // Try to refresh token to ensure it's still valid
            try {
                await this.api.refreshToken();
                this.state.setState({ user: this.api.user });
            } catch (error) {
                this.api.clearAuth();
                this.state.setState({ user: null });
            }
        }
        this.updateNavigation(this.api.user);

        // Load initial data
        await this.loadBoards();
    }

    async loadBoards() {
        try {
            this.state.setState({ loading: true, error: null });
            const boards = await this.api.getBoards();
            this.state.setState({ boards, loading: false });
        } catch (error) {
            this.state.setState({ 
                error: error.message, 
                loading: false 
            });
        }
    }

    updateNavigation(user) {
        const navElement = document.querySelector('#navigation .nav-right');
        if (!navElement) return;

        if (user) {
            navElement.innerHTML = `
                <div class="nav-left">
                    <a href="/" onclick="forum.router.navigate('/'); return false;">Forum Home</a>
                    ${user.is_admin ? `
                        <a href="/admin" onclick="forum.router.navigate('/admin'); return false;">Admin Panel</a>
                    ` : ''}
                </div>
                <div class="nav-right">
                    <span>Welcome, ${UIComponents.escapeHtml(user.username)}</span>
                    <button onclick="forum.logout()">Logout</button>
                </div>
            `;
        } else {
            navElement.innerHTML = `
                <div class="nav-left">
                    <a href="/" onclick="forum.router.navigate('/'); return false;">Forum Home</a>
                </div>
                <div class="nav-right">
                    <a href="/login" onclick="forum.router.navigate('/login'); return false;">Login</a>
                    <a href="/register" onclick="forum.router.navigate('/register'); return false;">Register</a>
                </div>
            `;
        }
    }

    // Route handlers
    showHome() {
        const content = document.getElementById('content');
        const { boards } = this.state.getState();
        
        content.innerHTML = `
            <div class="page-header">
                <h1>Forum Boards</h1>
                ${this.state.getState().user?.is_admin ? `
                    <button onclick="forum.showCreateBoardForm()">Create Board</button>
                ` : ''}
            </div>
            <div class="boards-list">
                ${UIComponents.renderBoards(boards)}
            </div>
        `;
    }

    showLogin() {
        const content = document.getElementById('content');
        content.innerHTML = `
            <div class="auth-form">
                <h2>Login</h2>
                <form onsubmit="forum.handleLogin(event)">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Login</button>
                </form>
                <p><a href="/register" onclick="forum.router.navigate('/register'); return false;">Need an account? Register here</a></p>
            </div>
        `;
    }

    showRegister() {
        const content = document.getElementById('content');
        content.innerHTML = `
            <div class="auth-form">
                <h2>Register</h2>
                <form onsubmit="forum.handleRegister(event)">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="email" name="email" placeholder="Email" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Register</button>
                </form>
                <p><a href="/login" onclick="forum.router.navigate('/login'); return false;">Already have an account? Login here</a></p>
            </div>
        `;
    }

    async showAdmin() {
        const currentUser = this.state.getState().user;
        if (!currentUser || !currentUser.is_admin) {
            this.router.navigate('/');
            return;
        }

        try {
            this.state.setState({ loading: true, error: null });
            // In a real app, you'd have an API endpoint to get all users
            // For now, we'll show a placeholder
            const content = document.getElementById('content');
            content.innerHTML = `
                <div class="page-header">
                    <h1>Admin Panel</h1>
                </div>
                <div class="admin-content">
                    <p>Admin functionality would be implemented here.</p>
                    <p>This would include user management, moderation tools, etc.</p>
                </div>
            `;
            this.state.setState({ loading: false });
        } catch (error) {
            this.state.setState({ 
                error: error.message, 
                loading: false 
            });
        }
    }

    async showBoard(boardId) {
        try {
            this.state.setState({ loading: true, error: null });
            const threads = await this.api.getThreads(boardId);
            const { boards } = this.state.getState();
            const board = boards.find(b => b.board_id == boardId);
            const currentUser = this.state.getState().user;
            
            const content = document.getElementById('content');
            content.innerHTML = `
                <div class="page-header">
                    <h1>${board ? UIComponents.escapeHtml(board.name) : 'Board'}</h1>
                    ${currentUser ? `
                        <button onclick="forum.showCreateThreadForm(${boardId})">New Thread</button>
                    ` : ''}
                </div>
                <div class="threads-list">
                    ${UIComponents.renderThreads(threads, currentUser)}
                </div>
            `;
            
            this.state.setState({ 
                currentBoard: board, 
                threads, 
                loading: false 
            });
        } catch (error) {
            this.state.setState({ 
                error: error.message, 
                loading: false 
            });
        }
    }

    async showThread(threadId) {
        try {
            this.state.setState({ loading: true, error: null });
            const posts = await this.api.getPosts(threadId);
            const currentUser = this.state.getState().user;
            
            const content = document.getElementById('content');
            content.innerHTML = `
                <div class="page-header">
                    <h1>Thread</h1>
                    ${currentUser ? `
                        <button onclick="forum.showReplyForm(${threadId})">Reply</button>
                    ` : ''}
                </div>
                <div class="posts-list">
                    ${UIComponents.renderPosts(posts, currentUser)}
                </div>
            `;
            
            this.state.setState({ 
                currentThread: { thread_id: threadId }, 
                posts, 
                loading: false 
            });
        } catch (error) {
            this.state.setState({ 
                error: error.message, 
                loading: false 
            });
        }
    }

    // Event handlers
    async handleLogin(event) {
        event.preventDefault();
        const formData = new FormData(event.target);
        const username = formData.get('username');
        const password = formData.get('password');

        try {
            this.state.setState({ loading: true, error: null });
            await this.api.login(username, password);
            this.state.setState({ user: this.api.user, loading: false });
            UIComponents.showSuccess('Login successful!');
            this.router.navigate('/');
        } catch (error) {
            this.state.setState({ 
                error: error.message, 
                loading: false 
            });
        }
    }

    async handleRegister(event) {
        event.preventDefault();
        const formData = new FormData(event.target);
        const username = formData.get('username');
        const email = formData.get('email');
        const password = formData.get('password');

        try {
            this.state.setState({ loading: true, error: null });
            await this.api.register(username, email, password);
            this.state.setState({ user: this.api.user, loading: false });
            UIComponents.showSuccess('Registration successful!');
            this.router.navigate('/');
        } catch (error) {
            this.state.setState({ 
                error: error.message, 
                loading: false 
            });
        }
    }

    async logout() {
        this.api.logout();
        this.state.setState({ user: null });
        UIComponents.showSuccess('Logged out successfully');
        this.router.navigate('/');
    }

    // Post and thread management
    async editPost(postId) {
        const post = this.state.getState().posts.find(p => p.post_id === postId);
        if (!post) return;

        const modal = this.createModal(`
            <h3>Edit Post</h3>
            <form onsubmit="forum.handleEditPost(event, ${postId})">
                <textarea name="content" rows="6" required>${UIComponents.escapeHtml(post.content)}</textarea>
                <button type="submit">Update Post</button>
            </form>
        `);
    }

    async handleEditPost(event, postId) {
        event.preventDefault();
        const formData = new FormData(event.target);
        const content = formData.get('content');

        try {
            await this.api.editPost(postId, content);
            UIComponents.showSuccess('Post updated successfully!');
            event.target.closest('.modal').remove();
            
            // Update the post content in the DOM
            const postContentElement = document.getElementById(`post-content-${postId}`);
            if (postContentElement) {
                postContentElement.innerHTML = UIComponents.escapeHtml(content).replace(/\n/g, '<br>');
            }
            
            // Refresh the current thread
            const currentThread = this.state.getState().currentThread;
            if (currentThread) {
                this.showThread(currentThread.thread_id);
            }
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    async deletePost(postId) {
        if (!confirm('Are you sure you want to delete this post?')) {
            return;
        }

        try {
            await this.api.deletePost(postId);
            UIComponents.showSuccess('Post deleted successfully!');
            
            // Remove the post from the DOM
            const postElement = document.getElementById(`post-${postId}`);
            if (postElement) {
                postElement.style.opacity = '0.5';
                postElement.innerHTML += '<div class="deleted-overlay">This post has been deleted</div>';
            }
            
            // Refresh the current thread
            const currentThread = this.state.getState().currentThread;
            if (currentThread) {
                setTimeout(() => this.showThread(currentThread.thread_id), 1000);
            }
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    async deleteThread(threadId) {
        if (!confirm('Are you sure you want to delete this thread?')) {
            return;
        }

        try {
            await this.api.deleteThread(threadId);
            UIComponents.showSuccess('Thread deleted successfully!');
            
            // Navigate back to the board
            const currentBoard = this.state.getState().currentBoard;
            if (currentBoard) {
                this.router.navigate(`/boards/${currentBoard.board_id}`);
            } else {
                this.router.navigate('/');
            }
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    async toggleThreadLock(threadId, locked) {
        try {
            await this.api.lockThread(threadId, locked);
            UIComponents.showSuccess(`Thread ${locked ? 'locked' : 'unlocked'} successfully!`);
            
            // Refresh the current board view
            const currentBoard = this.state.getState().currentBoard;
            if (currentBoard) {
                this.showBoard(currentBoard.board_id);
            }
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    async toggleThreadSticky(threadId, sticky) {
        try {
            await this.api.stickyThread(threadId, sticky);
            UIComponents.showSuccess(`Thread ${sticky ? 'stickied' : 'unstickied'} successfully!`);
            
            // Refresh the current board view
            const currentBoard = this.state.getState().currentBoard;
            if (currentBoard) {
                this.showBoard(currentBoard.board_id);
            }
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    // Admin functions
    async banUser(userId) {
        if (!confirm('Are you sure you want to ban this user?')) {
            return;
        }

        try {
            await this.api.banUser(userId);
            UIComponents.showSuccess('User banned successfully!');
            this.showAdmin(); // Refresh admin panel
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    async unbanUser(userId) {
        try {
            await this.api.unbanUser(userId);
            UIComponents.showSuccess('User unbanned successfully!');
            this.showAdmin(); // Refresh admin panel
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    async makeUserAdmin(userId) {
        if (!confirm('Are you sure you want to make this user an admin?')) {
            return;
        }

        try {
            await this.api.makeUserAdmin(userId);
            UIComponents.showSuccess('User promoted to admin successfully!');
            this.showAdmin(); // Refresh admin panel
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    async removeUserAdmin(userId) {
        if (!confirm('Are you sure you want to remove admin privileges from this user?')) {
            return;
        }

        try {
            await this.api.removeUserAdmin(userId);
            UIComponents.showSuccess('Admin privileges removed successfully!');
            this.showAdmin(); // Refresh admin panel
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    // Modal forms
    showCreateBoardForm() {
        const modal = this.createModal(`
            <h3>Create New Board</h3>
            <form onsubmit="forum.handleCreateBoard(event)">
                <input type="text" name="name" placeholder="Board Name" required>
                <textarea name="description" placeholder="Board Description" rows="4" required></textarea>
                <button type="submit">Create Board</button>
            </form>
        `);
    }

    showCreateThreadForm(boardId) {
        const modal = this.createModal(`
            <h3>Create New Thread</h3>
            <form onsubmit="forum.handleCreateThread(event, ${boardId})">
                <input type="text" name="title" placeholder="Thread Title" required>
                <textarea name="content" placeholder="Thread Content" rows="6" required></textarea>
                <button type="submit">Create Thread</button>
            </form>
        `);
    }

    showReplyForm(threadId) {
        const modal = this.createModal(`
            <h3>Reply to Thread</h3>
            <form onsubmit="forum.handleCreatePost(event, ${threadId})">
                <textarea name="content" placeholder="Your Reply" rows="6" required></textarea>
                <button type="submit">Post Reply</button>
            </form>
        `);
    }

    createModal(content) {
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-content">
                <span class="close" onclick="this.parentNode.parentNode.remove()">&times;</span>
                ${content}
            </div>
        `;
        
        // Close modal when clicking outside
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.remove();
            }
        });
        
        // Close modal on escape key
        const escapeHandler = (e) => {
            if (e.key === 'Escape') {
                modal.remove();
                document.removeEventListener('keydown', escapeHandler);
            }
        };
        document.addEventListener('keydown', escapeHandler);
        
        document.body.appendChild(modal);
        return modal;
    }

    async handleCreateBoard(event) {
        event.preventDefault();
        const formData = new FormData(event.target);
        const name = formData.get('name');
        const description = formData.get('description');

        try {
            await this.api.createBoard(name, description);
            UIComponents.showSuccess('Board created successfully!');
            event.target.closest('.modal').remove();
            await this.loadBoards(); // Refresh boards list
            this.router.navigate('/'); // Go back to home
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    async handleCreateThread(event, boardId) {
        event.preventDefault();
        const formData = new FormData(event.target);
        const title = formData.get('title');
        const content = formData.get('content');

        try {
            const thread = await this.api.createThread(boardId, title, content);
            UIComponents.showSuccess('Thread created successfully!');
            event.target.closest('.modal').remove();
            this.router.navigate(`/threads/${thread.thread_id}`); // Navigate to new thread
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    async handleCreatePost(event, threadId) {
        event.preventDefault();
        const formData = new FormData(event.target);
        const content = formData.get('content');

        try {
            await this.api.createPost(threadId, content);
            UIComponents.showSuccess('Reply posted successfully!');
            event.target.closest('.modal').remove();
            this.showThread(threadId); // Refresh the thread
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    // Utility methods
    confirmAction(message, callback) {
        const modal = this.createModal(`
            <h3>Confirm Action</h3>
            <p>${message}</p>
            <div class="modal-actions">
                <button onclick="this.closest('.modal').remove()" class="btn-secondary">Cancel</button>
                <button onclick="${callback}; this.closest('.modal').remove()" class="btn-danger">Confirm</button>
            </div>
        `);
    }

    // Keyboard shortcuts
    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl/Cmd + Enter to submit forms
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                const activeForm = document.querySelector('.modal form');
                if (activeForm) {
                    activeForm.requestSubmit();
                }
            }
            
            // ESC to close modals (already handled in createModal)
            
            // Alt + H to go home
            if (e.altKey && e.key === 'h') {
                e.preventDefault();
                this.router.navigate('/');
            }
            
            // Alt + L to go to login (if not logged in)
            if (e.altKey && e.key === 'l' && !this.state.getState().user) {
                e.preventDefault();
                this.router.navigate('/login');
            }
        });
    }

    // Enhanced error handling
    handleNetworkError() {
        UIComponents.showError('Network error. Please check your connection and try again.');
    }

    handleAuthError() {
        this.api.clearAuth();
        this.state.setState({ user: null });
        UIComponents.showError('Your session has expired. Please log in again.');
        this.router.navigate('/login');
    }

    // Auto-save for forms (draft functionality)
    setupAutoSave() {
        let autoSaveTimer;
        
        document.addEventListener('input', (e) => {
            if (e.target.tagName === 'TEXTAREA' && e.target.closest('.modal')) {
                clearTimeout(autoSaveTimer);
                autoSaveTimer = setTimeout(() => {
                    const formId = e.target.closest('form').getAttribute('data-form-id') || 'draft';
                    localStorage.setItem(`forum_draft_${formId}`, e.target.value);
                }, 1000);
            }
        });
    }

    // Load saved drafts
    loadDraft(formId) {
        return localStorage.getItem(`forum_draft_${formId}`) || '';
    }

    // Clear saved drafts
    clearDraft(formId) {
        localStorage.removeItem(`forum_draft_${formId}`);
    }

    // Theme management
    setTheme(theme) {
        document.body.className = `theme-${theme}`;
        localStorage.setItem('forum_theme', theme);
    }

    loadTheme() {
        const savedTheme = localStorage.getItem('forum_theme') || 'default';
        this.setTheme(savedTheme);
    }

    // Notification system
    setupNotifications() {
        // Request notification permission
        if ('Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission();
        }
    }

    showNotification(title, body, icon = '/favicon.ico') {
        if ('Notification' in window && Notification.permission === 'granted') {
            new Notification(title, { body, icon });
        }
    }

    // Initialize additional features
    initializeEnhancements() {
        this.setupKeyboardShortcuts();
        this.setupAutoSave();
        this.loadTheme();
        this.setupNotifications();
        
        // Setup periodic token refresh
        setInterval(() => {
            if (this.api.token) {
                this.api.refreshToken().catch(() => {
                    // Token refresh failed, user will be logged out on next request
                });
            }
        }, 25 * 60 * 1000); // Refresh every 25 minutes (token expires in 30)
    }
}

// =============================================================================
// APPLICATION INITIALIZATION
// =============================================================================

// Initialize the application when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.forum = new ForumApp();
    window.forum.initializeEnhancements();
});