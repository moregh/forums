class ForumApp {
    constructor() {
        this.api = new ForumAPI();
        this.state = new ForumState();
        this.router = new Router();
        this.navigationLock = false;
        this.tempThreadData = null;
        this.setupRoutes();
        this.setupEventListeners();
        this.setupEventDelegation();
        this.init();
    }

    setupRoutes() {
        this.router.register('/', () => this.showHome());
        this.router.register('/login', () => this.showLogin());
        this.router.register('/register', () => this.showRegister());
        this.router.register('/admin', () => this.showAdmin());
        this.router.register('/boards/:id', (params) => this.showBoard(params.id));
        this.router.register('/threads/:id', (params) => {
            const threadData = this.tempThreadData;
            this.tempThreadData = null;
            this.showThread(params.id, 1, threadData);
        });
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
         window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    showLogin() {
        document.getElementById('content').innerHTML = Templates.login();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    showRegister() {
        document.getElementById('content').innerHTML = Templates.register();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }
    async navigateToThread(threadId, threadData = null) {
        if (this.navigationLock) {
            return;
        }

        this.navigationLock = true;

        try {
            // Store thread data temporarily if provided
            if (threadData) {
                this.tempThreadData = threadData;
            }

            this.router.navigate(`/threads/${threadId}`, true);

        } catch (error) {
            UIComponents.showError(`Navigation error: ${error}`);
            console.error('Navigation error:', error);
            this.state.setState({ error: error.message });
        } finally {
            // Clear navigation lock after a short delay to prevent rapid clicks
            setTimeout(() => {
                this.navigationLock = false;
            }, 250); 
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
            window.scrollTo({ top: 0, behavior: 'smooth' });
        } catch (error) {
            this.state.setState({ error: error.message, loading: false });
        }
    }

    async showThread(threadId, page = 1, threadData = null) {
        try {
            this.state.setState({ loading: true, error: null });
            let posts, threadInfo;

            if (threadData) {
                posts = await this.api.getPosts(threadId, page);
                threadInfo = threadData;
            } else {
                [posts, threadInfo] = await Promise.all([
                    this.api.getPosts(threadId, page),
                    this.api.getThreadInfo(threadId)
                ]);
            }
            
            if (!threadInfo || !threadInfo.thread_id) {
                throw new Error('Invalid thread info received from API');
            }

            if (!Array.isArray(posts)) {
                console.warn('Posts is not an array, converting:', posts);
                posts = [];
            }

            const user = this.state.getState().user;
            const { boards } = this.state.getState();

            // Get board information
            let boardInfo = null;
            if (threadInfo.board_id && boards && boards.length > 0) {
                boardInfo = boards.find(b => b.board_id == threadInfo.board_id);
            }

            const totalPosts = Math.max((threadInfo.reply_count || 0) + 1, posts.length);
            const postsPerPage = 20;
            const totalPages = Math.ceil(totalPosts / postsPerPage);

            const cleanThreadInfo = {
                thread_id: parseInt(threadId),
                title: threadInfo.title || `Thread ${threadId}`,
                locked: Boolean(threadInfo.locked),
                sticky: Boolean(threadInfo.sticky),
                reply_count: threadInfo.reply_count || 0,
                view_count: threadInfo.view_count || 0,
                user_id: threadInfo.user_id || threadInfo.author_id || 0,
                username: threadInfo.username || threadInfo.author_name || 'Unknown',
                timestamp: threadInfo.timestamp || threadInfo.created_at || Date.now() / 1000,
                board_id: threadInfo.board_id || 0,
                board_name: boardInfo ? boardInfo.name : 'Unknown Board',
                last_post_at: threadInfo.last_post_at || null,
                last_post_username: threadInfo.last_post_username || null
            };

            const content = document.getElementById('content');
            if (!content) {
                throw new Error('Content element not found');
            }

            const threadHTML = Templates.thread(cleanThreadInfo, posts, user, page, totalPages);

            if (!threadHTML || threadHTML.includes('Error')) {
                throw new Error('Template rendering failed');
            }

            content.innerHTML = threadHTML;

            this.state.setState({
                currentThread: cleanThreadInfo,
                posts: posts,
                currentPage: page,
                totalPages: totalPages,
                loading: false
            });
            window.scrollTo({ top: 0, behavior: 'smooth' });
        } catch (error) {
            UIComponents.showError(`Error in showThread: ${error}`);
            console.error('Error in showThread:', error);

            const content = document.getElementById('content');
            if (content) {
                content.innerHTML = `
                <div class="error-state">
                    <h3>Error Loading Thread</h3>
                    <p>Failed to load thread: ${error.message}</p>
                    <button onclick="forum.router.navigate('/')" class="btn-primary">Return to Home</button>
                    <button onclick="location.reload()" class="btn-secondary">Retry</button>
                </div>
            `;
            }

            this.state.setState({
                error: `Failed to load thread: ${error.message}`,
                loading: false
            });
        }
    }
    setupEventDelegation() {
        document.addEventListener('click', (e) => {
            const threadRow = e.target.closest('.thread-row[data-thread-id]');
            if (threadRow && !e.target.closest('.thread-actions')) {
                e.preventDefault();
                e.stopPropagation();

                const threadId = threadRow.dataset.threadId;

                if (threadId && !this.navigationLock) {
                    // Instead of parsing JSON from data attribute, just use the thread ID
                    // The thread data will be fetched from the API if needed
                    this.navigateToThread(parseInt(threadId), null);
                }
            }
        });
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
        const reason = prompt('Reason for ban (required):');
        if (reason === null) {
            UIComponents.showInfo('Cancelled ban user')
            return;
        }

        try {
            await this.api.banUser(userId, reason);
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
    async showAdmin() {
        const currentUser = this.state.getState().user;
        if (!currentUser || !currentUser.is_admin) {
            this.router.navigate('/');
            return;
        }

        try {
            this.state.setState({ loading: true, error: null });

            const [users, stats, moderationLog] = await Promise.all([
                this.api.request('/api/admin/users?page=1&per_page=50').catch(() => []),
                this.api.request('/api/stats').catch(() => ({})),
                this.api.request('/api/admin/moderation-log?page=1&per_page=20').catch(() => [])
            ]);

            const content = document.getElementById('content');
            content.innerHTML = `
            <div class="page-header">
                <h1>Admin Panel</h1>
            </div>
            
            <div class="admin-content">
                <div class="admin-section">
                    <h2>Forum Statistics</h2>
                    <div class="stats-grid">
                        <div class="stat-card">
                            <h3>${stats.total_users || 0}</h3>
                            <p>Total Users</p>
                        </div>
                        <div class="stat-card">
                            <h3>${stats.total_threads || 0}</h3>
                            <p>Total Threads</p>
                        </div>
                        <div class="stat-card">
                            <h3>${stats.total_posts || 0}</h3>
                            <p>Total Posts</p>
                        </div>
                        <div class="stat-card">
                            <h3>${stats.users_online || 0}</h3>
                            <p>Users Online</p>
                        </div>
                    </div>
                </div>
                
                <div class="admin-section">
                    <h2>User Management</h2>
                    <div class="user-management">
                        ${this.renderUserList(users)}
                    </div>
                </div>
                
                <div class="admin-section">
                    <h2>Recent Moderation Actions</h2>
                    <div class="moderation-log">
                        ${this.renderModerationLog(moderationLog)}
                    </div>
                </div>
            </div>
        `;

            this.state.setState({ loading: false });
            window.scrollTo({ top: 0, behavior: 'smooth' });

        } catch (error) {
            UIComponents.showError(`Error loading admin panel: ${error}`);
            console.error('Error loading admin panel:', error);
            this.state.setState({ error: error.message, loading: false });
        }
    }

    renderUserList(users) {
        if (!Array.isArray(users) || users.length === 0) {
            return '<p>No users found.</p>';
        }

        return `
        <div class="user-list">
            ${users.map(user => `
                <div class="admin-user-row" data-user-id="${user.user_id}">
                    <div class="user-info">
                        <strong>${UIComponents.escapeHtml(user.username)}</strong>
                        <span class="user-email">${UIComponents.escapeHtml(user.email)}</span>
                        ${user.is_admin ? '<span class="admin-badge">Admin</span>' : ''}
                        ${user.is_banned ? '<span class="banned-badge">Banned</span>' : ''}
                        <div class="user-stats">
                            Joined: ${UIComponents.formatDate(user.join_date)} | 
                            Posts: ${user.post_count || 0} | 
                            Last seen: ${UIComponents.formatDate(user.last_activity)}
                        </div>
                    </div>
                    <div class="user-actions">
                        ${!user.is_banned ? `
                            <button onclick="forum.banUser(${user.user_id})" class="btn-small btn-danger">Ban</button>
                        ` : `
                            <button onclick="forum.unbanUser(${user.user_id})" class="btn-small btn-success">Unban</button>
                        `}
                        ${!user.is_admin ? `
                            <button onclick="forum.makeUserAdmin(${user.user_id})" class="btn-small btn-warning">Make Admin</button>
                        ` : `
                            <button onclick="forum.removeUserAdmin(${user.user_id})" class="btn-small btn-secondary">Remove Admin</button>
                        `}
                    </div>
                </div>
            `).join('')}
        </div>
    `;
    }

    renderModerationLog(logs) {
        if (!Array.isArray(logs) || logs.length === 0) {
            return '<p>No recent moderation actions.</p>';
        }

        return `
        <div class="moderation-entries">
            ${logs.map(log => `
                <div class="moderation-entry">
                    <div class="mod-header">
                        <strong>${UIComponents.escapeHtml(log.moderator_name || 'Unknown')}</strong>
                        <span class="action-type">${log.action}</span>
                        <span class="mod-date">${UIComponents.formatDate(log.timestamp)}</span>
                    </div>
                    <div class="mod-details">
                        Target: ${log.target_type} #${log.target_id}
                        ${log.reason ? `<br>Reason: ${UIComponents.escapeHtml(log.reason)}` : ''}
                    </div>
                </div>
            `).join('')}
        </div>
    `;
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

        // Validate content
        if (!content || content.trim().length === 0) {
            UIComponents.showError('Post content cannot be empty');
            return;
        }

        if (content.length > 50000) {
            UIComponents.showError('Post content is too long (maximum 50,000 characters)');
            return;
        }

        try {
            // Show loading state
            this.state.setState({ loading: true, error: null });
            
            // Create the post
            const newPost = await this.api.createPost(threadId, content);
            
            if (!newPost) {
                throw new Error('Failed to create post - no response from server');
            }

            // Get current thread info to calculate proper pagination
            const currentThread = this.state.getState().currentThread;
            let targetPage = 1;

            if (currentThread) {
                // Calculate the page where the new post will appear
                // Total posts = original post + existing replies + new post
                const totalPosts = (currentThread.reply_count || 0) + 2; // +1 for original post, +1 for new post
                const postsPerPage = 20;
                targetPage = Math.ceil(totalPosts / postsPerPage);
            } else {
                // Fallback: try to get thread info from API
                try {
                    const threadInfo = await this.api.getThreadInfo(threadId);
                    if (threadInfo) {
                        const totalPosts = (threadInfo.reply_count || 0) + 2;
                        const postsPerPage = 20;
                        targetPage = Math.ceil(totalPosts / postsPerPage);
                    }
                } catch (error) {
                    console.warn('Could not get thread info for pagination, using page 1:', error);
                    targetPage = 1;
                }
            }

            // Close the modal
            const modal = event.target.closest('.modal');
            if (modal) {
                modal.remove();
            }

            // Clear any draft content
            this.clearDraft(`reply_${threadId}`);

            // Show success message
            UIComponents.showSuccess('Reply posted successfully!');

            // Navigate to the correct page where the new post appears
            // Add a small delay to ensure the post is fully processed server-side
            setTimeout(() => {
                this.showThread(threadId, targetPage);
                
                // Scroll to the new post after the page loads
                setTimeout(() => {
                    const posts = document.querySelectorAll('.post');
                    if (posts.length > 0) {
                        const lastPost = posts[posts.length - 1];
                        lastPost.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        
                        // Add a subtle highlight effect to the new post
                        lastPost.style.border = '2px solid var(--primary)';
                        setTimeout(() => {
                            lastPost.style.border = '1px solid var(--border)';
                        }, 3000);
                    }
                }, 500);
            }, 100);

        } catch (error) {
            console.error('Error creating post:', error);
            
            // Show user-friendly error message
            let errorMessage = 'Failed to create post. Please try again.';
            
            if (error.message) {
                if (error.message.includes('rate limit')) {
                    errorMessage = 'You are posting too frequently. Please wait a moment and try again.';
                } else if (error.message.includes('locked')) {
                    errorMessage = 'This thread is locked and cannot accept new posts.';
                } else if (error.message.includes('not found')) {
                    errorMessage = 'Thread not found. It may have been deleted.';
                } else if (error.message.includes('authentication') || error.message.includes('unauthorized')) {
                    errorMessage = 'You need to log in to post replies.';
                    // Redirect to login if not authenticated
                    this.router.navigate('/login');
                    return;
                }
            }
            
            UIComponents.showError(errorMessage);
            this.state.setState({ error: error.message, loading: false });
        } finally {
            // Always clear loading state
            this.state.setState({ loading: false });
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
                this.api.refreshToken().catch(() => { });
            }
        }, 25 * 60 * 1000);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.forum = new ForumApp();
    window.forum.initializeEnhancements();
});
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
    UIComponents.showError('An unexpected error occurred. Please refresh the page.');
});

window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    UIComponents.showError('Network error. Please check your connection.');
});