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
        // Hash password on client side before sending
        const { hash, salt } = await CryptoUtils.hashPassword(password);
        const passwordHash = `${hash}:${salt}`; // Store hash and salt together
        
        const response = await this.request('/api/auth/register', {
            method: 'POST',
            body: JSON.stringify({ username, email, password: passwordHash })
        });
        
        this.setAuth(response.access_token, response.user);
        return response;
    }

    async login(username, password) {
        // For login, we need to get the user's salt first, then hash with that salt
        // This is a simplified approach - in production, you might want a different flow
        const { hash, salt } = await CryptoUtils.hashPassword(password);
        const passwordHash = `${hash}:${salt}`;
        
        const response = await this.request('/api/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password: passwordHash })
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

    async deleteThread(threadId) {
        return this.request(`/api/threads/${threadId}`, {
            method: 'DELETE'
        });
    }

    async lockThread(threadId, locked = true) {
        return this.request(`/api/threads/${threadId}/lock`, {
            method: 'PATCH',
            body: JSON.stringify({ locked })
        });
    }

    async stickyThread(threadId, sticky = true) {
        return this.request(`/api/threads/${threadId}/sticky`, {
            method: 'PATCH',
            body: JSON.stringify({ sticky })
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

    async editPost(postId, content) {
        return this.request(`/api/posts/${postId}`, {
            method: 'PATCH',
            body: JSON.stringify({ content })
        });
    }

    async deletePost(postId) {
        return this.request(`/api/posts/${postId}`, {
            method: 'DELETE'
        });
    }

    async restorePost(postId) {
        return this.request(`/api/posts/${postId}/restore`, {
            method: 'PATCH'
        });
    }

    // Admin methods
    async banUser(userId) {
        return this.request(`/api/admin/users/${userId}/ban`, {
            method: 'POST'
        });
    }

    async unbanUser(userId) {
        return this.request(`/api/admin/users/${userId}/unban`, {
            method: 'POST'
        });
    }

    async makeUserAdmin(userId) {
        return this.request(`/api/admin/users/${userId}/promote`, {
            method: 'POST'
        });
    }

    async removeUserAdmin(userId) {
        return this.request(`/api/admin/users/${userId}/demote`, {
            method: 'POST'
        });
    }
}