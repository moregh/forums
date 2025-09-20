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
        this.router.register('/threads/:id', (params) => this.showThread(params.id, 1, params.threadData));
    }

    setupEventListeners() {
        this.state.subscribe('userChanged', (user) => this.updateNavigation(user));
        this.state.subscribe('loadingChanged', (loading) => UIComponents.showLoading(loading));
        this.state.subscribe('errorChanged', (error) => {
            if (error) UIComponents.showError(error);
        });
    }

    async init() {
        if (this.api.token && this.api.user) {
            this.state.setState({ user: this.api.user });
            try {
                await this.api.refreshToken();
                this.state.setState({ user: this.api.user });
            } catch (error) {
                this.api.clearAuth();
                this.state.setState({ user: null });
            }
        }
        this.updateNavigation(this.api.user);

        await this.loadBoards();
        this.router.handleRoute();
    }

    async loadBoards() {
        try {
            this.state.setState({ loading: true, error: null });
            const boards = await this.api.getBoards();
            this.state.setState({ boards, loading: false });
        } catch (error) {
            this.state.setState({ error: error.message, loading: false });
        }
    }

    updateNavigation(user) {
        const navElement = document.querySelector('#navigation .nav-right');
        if (!navElement) return;
        navElement.innerHTML = user 
            ? Templates.navigationLoggedIn(user) 
            : Templates.navigationLoggedOut();
    }

    // Route handlers
    showHome() {
        const content = document.getElementById('content');
        const { boards, user } = this.state.getState();
        content.innerHTML = Templates.home(boards, user);
    }

    showLogin() {
        document.getElementById('content').innerHTML = Templates.login();
    }

    showRegister() {
        document.getElementById('content').innerHTML = Templates.register();
    }

    async showAdmin() {
        const currentUser = this.state.getState().user;
        if (!currentUser || !currentUser.is_admin) {
            this.router.navigate('/');
            return;
        }
        try {
            this.state.setState({ loading: true, error: null });
            document.getElementById('content').innerHTML = Templates.admin();
            this.state.setState({ loading: false });
        } catch (error) {
            this.state.setState({ error: error.message, loading: false });
        }
    }

    async showBoard(boardId, page = 1) {
        try {
            this.state.setState({ loading: true, error: null });
            const threads = await this.api.getThreads(boardId, page);
            const { boards, user } = this.state.getState();
            const board = boards.find(b => b.board_id == boardId);

            const totalThreads = board?.thread_count || 25; // todo: get rid of this hardcoded value
            const totalPages = Math.ceil(totalThreads / 20);  // todo: get rid of this hardcoded value

            document.getElementById('content').innerHTML =
                Templates.board(board, threads, user, page, totalPages);

            this.state.setState({ 
                currentBoard: board, 
                threads, 
                currentPage: page,
                totalPages,
                loading: false 
            });
        } catch (error) {
            this.state.setState({ error: error.message, loading: false });
        }
    }

    // Replace the entire showThread method in app.js with this version
// This eliminates ALL redundant API calls and fixes the flickering

async showThread(threadId, page = 1, threadData = null) {
    try {
        this.state.setState({ loading: true, error: null });
        
        console.log('Loading thread:', threadId, 'page:', page);
        
        // ONLY make the 2 necessary API calls
        let posts, threadInfo;
        
        if (threadData) {
            // If we already have thread data (from clicking in board view), use it
            posts = await this.api.getPosts(threadId, page);
            threadInfo = threadData;
            console.log('Using provided thread data');
        } else {
            // Make both calls in parallel for efficiency
            [posts, threadInfo] = await Promise.all([
                this.api.getPosts(threadId, page),
                this.api.getThreadInfo(threadId)
            ]);
            console.log('Fetched thread data from API');
        }
        
        console.log('Posts loaded:', posts?.length || 0);
        console.log('Thread info:', threadInfo);
        
        const user = this.state.getState().user;
        
        // Calculate pagination from thread reply_count (NO additional API calls)
        const totalPosts = (threadInfo?.reply_count || 0) + 1; // +1 for original post
        const totalPages = Math.ceil(totalPosts / 20);
        
        console.log('Total posts calculated:', totalPosts, 'Total pages:', totalPages);
        
        // Ensure we have valid thread info with comprehensive fallbacks
        const safeThreadInfo = {
            thread_id: parseInt(threadId),
            title: threadInfo?.title || `Thread ${threadId}`,
            locked: Boolean(threadInfo?.locked),
            sticky: Boolean(threadInfo?.sticky),
            reply_count: threadInfo?.reply_count || 0,
            view_count: threadInfo?.view_count || 0,
            user_id: threadInfo?.user_id || threadInfo?.author_id || 0,
            username: threadInfo?.username || threadInfo?.author_name || 'Unknown',
            timestamp: threadInfo?.timestamp || threadInfo?.created_at || Date.now() / 1000,
            board_id: threadInfo?.board_id || 0,
            last_post_at: threadInfo?.last_post_at || null,
            last_post_username: threadInfo?.last_post_username || null
        };
        
        console.log('Safe thread info created:', safeThreadInfo);
        
        // Validate posts array
        const safePosts = Array.isArray(posts) ? posts : [];
        console.log('Safe posts array length:', safePosts.length);
        
        // Generate HTML template
        const content = document.getElementById('content');
        if (!content) {
            throw new Error('Content element not found');
        }
        
        const threadHTML = Templates.thread(safeThreadInfo, safePosts, user, page, totalPages);
        console.log('Generated HTML length:', threadHTML?.length || 0);
        
        if (!threadHTML || threadHTML.length < 100) {
            throw new Error('Generated HTML is too short, likely template error');
        }
        
        // Set the content
        content.innerHTML = threadHTML;
        console.log('HTML set successfully');

        // Update state
        this.state.setState({ 
            currentThread: safeThreadInfo, 
            posts: safePosts, 
            currentPage: page,
            totalPages: totalPages,
            loading: false 
        });
        
        console.log('State updated, thread rendered successfully');
        
    } catch (error) {
        console.error('Error in showThread:', error);
        console.error('Stack trace:', error.stack);
        
        // Show error state instead of blank screen
        const content = document.getElementById('content');
        if (content) {
            content.innerHTML = `
                <div class="error-state">
                    <h3>Error Loading Thread</h3>
                    <p>There was a problem loading this thread. Please try again.</p>
                    <button onclick="forum.router.navigate('/')">Return to Home</button>
                </div>
            `;
        }
        
        this.state.setState({ 
            error: `Failed to load thread: ${error.message}`, 
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
            this.state.setState({ error: error.message, loading: false });
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
            this.state.setState({ error: error.message, loading: false });
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
        if (post) this.createModal(Templates.modals.editPost(post, postId));
    }

    async handleEditPost(event, postId) {
        event.preventDefault();
        const formData = new FormData(event.target);
        const content = formData.get('content');

        try {
            await this.api.editPost(postId, content);
            UIComponents.showSuccess('Post updated successfully!');
            event.target.closest('.modal').remove();

            const currentThread = this.state.getState().currentThread;
            if (currentThread) {
                this.showThread(currentThread.thread_id, this.state.getState().currentPage || 1);
            }
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    async deletePost(postId) {
        if (!confirm('Are you sure you want to delete this post?')) return;

        try {
            await this.api.deletePost(postId);
            UIComponents.showSuccess('Post deleted successfully!');
            const currentThread = this.state.getState().currentThread;
            if (currentThread) {
                setTimeout(() => this.showThread(currentThread.thread_id, this.state.getState().currentPage || 1), 1000);
            }
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    async deleteThread(threadId) {
        if (!confirm('Are you sure you want to delete this thread?')) return;

        try {
            await this.api.deleteThread(threadId);
            UIComponents.showSuccess('Thread deleted successfully!');
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
            const currentBoard = this.state.getState().currentBoard;
            if (currentBoard) this.showBoard(currentBoard.board_id, this.state.getState().currentPage || 1);
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    async toggleThreadSticky(threadId, sticky) {
        try {
            await this.api.stickyThread(threadId, sticky);
            UIComponents.showSuccess(`Thread ${sticky ? 'stickied' : 'unstickied'} successfully!`);
            const currentBoard = this.state.getState().currentBoard;
            if (currentBoard) this.showBoard(currentBoard.board_id, this.state.getState().currentPage || 1);
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    // Admin functions
    async banUser(userId) {
        if (!confirm('Are you sure you want to ban this user?')) return;
        try {
            await this.api.banUser(userId);
            UIComponents.showSuccess('User banned successfully!');
            this.showAdmin();
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    async unbanUser(userId) {
        try {
            await this.api.unbanUser(userId);
            UIComponents.showSuccess('User unbanned successfully!');
            this.showAdmin();
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    async makeUserAdmin(userId) {
        if (!confirm('Are you sure you want to make this user an admin?')) return;
        try {
            await this.api.makeUserAdmin(userId);
            UIComponents.showSuccess('User promoted to admin successfully!');
            this.showAdmin();
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    async removeUserAdmin(userId) {
        if (!confirm('Are you sure you want to remove admin privileges from this user?')) return;
        try {
            await this.api.removeUserAdmin(userId);
            UIComponents.showSuccess('Admin privileges removed successfully!');
            this.showAdmin();
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    // Modal forms
    showCreateBoardForm() {
        this.createModal(Templates.modals.createBoard());
    }
    showCreateThreadForm(boardId) {
        this.createModal(Templates.modals.createThread(boardId));
    }
    showReplyForm(threadId) {
        this.createModal(Templates.modals.reply(threadId));
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
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.remove();
        });
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
            await this.loadBoards();
            this.router.navigate('/');
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
            this.router.navigate(`/threads/${thread.thread_id}`);
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

            const totalPosts = 1; 
            const lastPage = Math.ceil(totalPosts / 20);  // todo: get rid of magic number
            this.showThread(threadId, lastPage);
        } catch (error) {
            UIComponents.showError(error.message);
        }
    }

    // Utilities
    confirmAction(message, callback) {
        this.createModal(`
            <h3>Confirm Action</h3>
            <p>${message}</p>
            <div class="modal-actions">
                <button onclick="this.closest('.modal').remove()" class="btn-secondary">Cancel</button>
                <button onclick="${callback}; this.closest('.modal').remove()" class="btn-danger">Confirm</button>
            </div>
        `);
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                const activeForm = document.querySelector('.modal form');
                if (activeForm) activeForm.requestSubmit();
            }
            if (e.altKey && e.key === 'h') {
                e.preventDefault();
                this.router.navigate('/');
            }
            if (e.altKey && e.key === 'l' && !this.state.getState().user) {
                e.preventDefault();
                this.router.navigate('/login');
            }
        });
    }

    handleNetworkError() {
        UIComponents.showError('Network error. Please check your connection and try again.');
    }

    handleAuthError() {
        this.api.clearAuth();
        this.state.setState({ user: null });
        UIComponents.showError('Your session has expired. Please log in again.');
        this.router.navigate('/login');
    }

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

    loadDraft(formId) {
        return localStorage.getItem(`forum_draft_${formId}`) || '';
    }

    clearDraft(formId) {
        localStorage.removeItem(`forum_draft_${formId}`);
    }

    setTheme(theme) {
        document.body.className = `theme-${theme}`;
        localStorage.setItem('forum_theme', theme);
    }

    loadTheme() {
        const savedTheme = localStorage.getItem('forum_theme') || 'default';
        this.setTheme(savedTheme);
    }

    setupNotifications() {
        // Only request notification permission when user explicitly wants it
        // Remove automatic permission request to fix the warning
    }

    showNotification(title, body, icon = '/favicon.ico') {
        if ('Notification' in window && Notification.permission === 'granted') {
            new Notification(title, { body, icon });
        }
    }

    requestNotificationPermission() {
        // Call this only in response to user action
        if ('Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission();
        }
    }

    initializeEnhancements() {
        this.setupKeyboardShortcuts();
        this.setupAutoSave();
        this.loadTheme();
        // Removed automatic notification setup

        setInterval(() => {
            if (this.api.token) {
                this.api.refreshToken().catch(() => {});
            }
        }, 25 * 60 * 1000);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.forum = new ForumApp();
    window.forum.initializeEnhancements();
});