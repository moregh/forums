// Frontend Architecture for Forum System
// Static HTML/CSS/JS that consumes the REST API

// =============================================================================
// API CLIENT CONFIGURATION
// =============================================================================

class ForumAPI {
    constructor(baseURL = 'http://localhost:8000') {
        this.baseURL = baseURL;
        this.token = localStorage.getItem('auth_token');
        this.user = JSON.parse(localStorage.getItem('user') || 'null');
    }

    // Set authentication token
    setAuth(token, user) {
        this.token = token;
        this.user = user;
        localStorage.setItem('auth_token', token);
        localStorage.setItem('user', JSON.stringify(user));
    }

    // Clear authentication
    clearAuth() {
        this.token = null;
        this.user = null;
        localStorage.removeItem('auth_token');
        localStorage.removeItem('user');
    }

    // Make authenticated request
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };

        // Add authorization header if token exists
        if (this.token) {
            config.headers.Authorization = `Bearer ${this.token}`;
        }

        try {
            const response = await fetch(url, config);
            
            // Handle authentication errors
            if (response.status === 401) {
                this.clearAuth();
                window.location.href = '/login.html';
                return;
            }

            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Request failed');
            }

            return data;
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    }

    // Authentication methods
    async register(username, email, password) {
        const response = await this.request('/api/auth/register', {
            method: 'POST',
            body: JSON.stringify({ username, email, password })
        });
        
        this.setAuth(response.access_token, response.user);
        return response;
    }

    async login(username, password) {
        const response = await this.request('/api/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });
        
        this.setAuth(response.access_token, response.user);
        return response;
    }

    async logout() {
        this.clearAuth();
    }

    async refreshToken() {
        const response = await this.request('/api/auth/refresh', {
            method: 'POST'
        });
        
        this.setAuth(response.access_token, response.user);
        return response;
    }

    // Board methods
    async getBoards() {
        return this.request('/api/boards');
    }

    async createBoard(name, description) {
        return this.request('/api/boards', {
            method: 'POST',
            body: JSON.stringify({ name, description })
        });
    }

    // Thread methods
    async getThreads(boardId, page = 1, perPage = 20) {
        return this.request(`/api/boards/${boardId}/threads?page=${page}&per_page=${perPage}`);
    }

    async createThread(boardId, title, content) {
        return this.request(`/api/boards/${boardId}/threads`, {
            method: 'POST',
            body: JSON.stringify({ title, content })
        });
    }

    // Post methods
    async getPosts(threadId, page = 1, perPage = 20) {
        return this.request(`/api/threads/${threadId}/posts?page=${page}&per_page=${perPage}`);
    }

    async createPost(threadId, content) {
        return this.request(`/api/threads/${threadId}/posts`, {
            method: 'POST',
            body: JSON.stringify({ content })
        });
    }
}

// =============================================================================
// APPLICATION STATE MANAGEMENT
// =============================================================================

class ForumState {
    constructor() {
        this.listeners = {};
        this.state = {
            user: null,
            boards: [],
            currentBoard: null,
            currentThread: null,
            threads: [],
            posts: [],
            loading: false,
            error: null
        };
    }

    // Subscribe to state changes
    subscribe(event, callback) {
        if (!this.listeners[event]) {
            this.listeners[event] = [];
        }
        this.listeners[event].push(callback);
    }

    // Emit state change
    emit(event, data) {
        if (this.listeners[event]) {
            this.listeners[event].forEach(callback => callback(data));
        }
    }

    // Update state
    setState(updates) {
        const oldState = { ...this.state };
        this.state = { ...this.state, ...updates };
        
        // Emit specific change events
        Object.keys(updates).forEach(key => {
            if (oldState[key] !== this.state[key]) {
                this.emit(`${key}Changed`, this.state[key]);
            }
        });
        
        this.emit('stateChanged', this.state);
    }

    getState() {
        return this.state;
    }
}

// =============================================================================
// ROUTER FOR SINGLE PAGE APPLICATION
// =============================================================================

class Router {
    constructor() {
        this.routes = {};
        this.currentRoute = null;
        this.isNavigating = false;
        
        // Listen for browser navigation
        window.addEventListener('popstate', () => this.handleRoute());
        
        // Handle initial route
        this.handleRoute();
    }

    // Register route handler
    register(path, handler) {
        this.routes[path] = handler;
    }

    // Navigate to route
    navigate(path, pushState = true) {
        if (this.isNavigating) return; // Prevent recursion
        
        if (pushState) {
            history.pushState({}, '', path);
        }
        this.handleRoute();
    }

    // Handle current route
    handleRoute() {
        if (this.isNavigating) return; // Prevent recursion
        this.isNavigating = true;
        
        const path = window.location.pathname;
        this.currentRoute = path;

        // Find matching route
        let routeFound = false;
        for (const routePath in this.routes) {
            const regex = new RegExp('^' + routePath.replace(/:\w+/g, '([^/]+)') + '$');
            const match = path.match(regex);
            
            if (match) {
                // Extract parameters
                const params = {};
                const paramNames = routePath.match(/:(\w+)/g) || [];
                paramNames.forEach((param, index) => {
                    const paramName = param.substring(1);
                    params[paramName] = match[index + 1];
                });
                
                this.routes[routePath](params);
                routeFound = true;
                break;
            }
        }
        
        // If no route found and not already on home, redirect to home
        if (!routeFound && path !== '/') {
            history.replaceState({}, '', '/');
            if (this.routes['/']) {
                this.routes['/']({});
            }
        }
        
        this.isNavigating = false;
    }
}

// =============================================================================
// UI COMPONENTS
// =============================================================================

class UIComponents {
    static showLoading(show = true) {
        const loader = document.getElementById('loading');
        if (loader) {
            loader.style.display = show ? 'block' : 'none';
        }
    }

    static showError(message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.textContent = message;
        errorDiv.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #dc3545;
            color: white;
            padding: 15px;
            border-radius: 5px;
            z-index: 1000;
            max-width: 300px;
        `;
        
        document.body.appendChild(errorDiv);
        
        setTimeout(() => {
            if (errorDiv.parentNode) {
                errorDiv.parentNode.removeChild(errorDiv);
            }
        }, 5000);
    }

    static showSuccess(message) {
        const successDiv = document.createElement('div');
        successDiv.className = 'success-message';
        successDiv.textContent = message;
        successDiv.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #28a745;
            color: white;
            padding: 15px;
            border-radius: 5px;
            z-index: 1000;
            max-width: 300px;
        `;
        
        document.body.appendChild(successDiv);
        
        setTimeout(() => {
            if (successDiv.parentNode) {
                successDiv.parentNode.removeChild(successDiv);
            }
        }, 3000);
    }

    static formatDate(timestamp) {
        return new Date(timestamp * 1000).toLocaleString();
    }

    static escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    static renderBoards(boards) {
        return boards.map(board => `
            <div class="board-card" onclick="forum.router.navigate('/boards/${board.board_id}')">
                <h3>${this.escapeHtml(board.name)}</h3>
                <p>${this.escapeHtml(board.description)}</p>
                <div class="board-stats">
                    <span>${board.thread_count} threads</span>
                    <span>${board.post_count} posts</span>
                    ${board.last_post_username ? `
                        <span>Last: ${this.escapeHtml(board.last_post_username)}</span>
                    ` : ''}
                </div>
            </div>
        `).join('');
    }

    static renderThreads(threads) {
        return threads.map(thread => `
            <div class="thread-row ${thread.sticky ? 'sticky' : ''}" 
                 onclick="forum.router.navigate('/threads/${thread.thread_id}')">
                <div class="thread-info">
                    <h4>${this.escapeHtml(thread.title)}</h4>
                    <span class="thread-meta">
                        by ${this.escapeHtml(thread.username)} • 
                        ${this.formatDate(thread.timestamp)}
                        ${thread.sticky ? ' • <span class="sticky-badge">Sticky</span>' : ''}
                        ${thread.locked ? ' • <span class="locked-badge">Locked</span>' : ''}
                    </span>
                </div>
                <div class="thread-stats">
                    <span>${thread.reply_count} replies</span>
                    <span>${thread.view_count} views</span>
                    ${thread.last_post_username ? `
                        <div class="last-post">
                            Last: ${this.escapeHtml(thread.last_post_username)}<br>
                            ${this.formatDate(thread.last_post_at)}
                        </div>
                    ` : ''}
                </div>
            </div>
        `).join('');
    }

    static renderPosts(posts) {
        return posts.map(post => `
            <div class="post" id="post-${post.post_id}">
                <div class="post-header">
                    <span class="post-author">${this.escapeHtml(post.username)}</span>
                    <span class="post-date">${this.formatDate(post.timestamp)}</span>
                    ${post.edited ? '<span class="edited-badge">Edited</span>' : ''}
                </div>
                <div class="post-content">
                    ${this.escapeHtml(post.content).replace(/\n/g, '<br>')}
                </div>
            </div>
        `).join('');
    }
}

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

    async showBoard(boardId) {
        try {
            this.state.setState({ loading: true, error: null });
            const threads = await this.api.getThreads(boardId);
            const { boards } = this.state.getState();
            const board = boards.find(b => b.board_id == boardId);
            
            const content = document.getElementById('content');
            content.innerHTML = `
                <div class="page-header">
                    <h1>${board ? UIComponents.escapeHtml(board.name) : 'Board'}</h1>
                    ${this.state.getState().user ? `
                        <button onclick="forum.showCreateThreadForm(${boardId})">New Thread</button>
                    ` : ''}
                </div>
                <div class="threads-list">
                    ${UIComponents.renderThreads(threads)}
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
            
            const content = document.getElementById('content');
            content.innerHTML = `
                <div class="page-header">
                    <h1>Thread</h1>
                    ${this.state.getState().user ? `
                        <button onclick="forum.showReplyForm(${threadId})">Reply</button>
                    ` : ''}
                </div>
                <div class="posts-list">
                    ${UIComponents.renderPosts(posts)}
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

    // Modal forms
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
        document.body.appendChild(modal);
        return modal;
    }

    async handleCreateThread(event, boardId) {
        event.preventDefault();
        const formData = new FormData(event.target);
        const title = formData.get('title');
        const content = formData.get('content');

        try {
            await this.api.createThread(boardId, title, content);
            UIComponents.showSuccess('Thread created successfully!');
            event.target.closest('.modal').remove();
            this.showBoard(boardId); // Refresh the board
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
}

// =============================================================================
// APPLICATION INITIALIZATION
// =============================================================================

// Initialize the application when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.forum = new ForumApp();
});