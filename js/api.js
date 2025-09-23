class ForumAPI {
    constructor(baseURL = 'http://10.0.1.251:8000') {
        this.baseURL = baseURL;
        this.token = localStorage.getItem('auth_token');
        this.user = JSON.parse(localStorage.getItem('user') || 'null');
        this.csrfToken = localStorage.getItem('csrf_token');
    }

    setAuth(token, user, csrfToken = null) {
        this.token = token;
        this.user = user;
        this.csrfToken = csrfToken;
        localStorage.setItem('auth_token', token);
        localStorage.setItem('user', JSON.stringify(user));
        if (csrfToken) {
            localStorage.setItem('csrf_token', csrfToken);
        }
    }

    clearAuth() {
        this.token = null;
        this.user = null;
        this.csrfToken = null;
        localStorage.removeItem('auth_token');
        localStorage.removeItem('user');
        localStorage.removeItem('csrf_token');
    }

    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            credentials: 'include',
            ...options
        };

        if (this.token) {
            config.headers.Authorization = `Bearer ${this.token}`;
        }

        if (this.csrfToken && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(options.method?.toUpperCase())) {
            config.headers['X-CSRF-Token'] = this.csrfToken;
        }

        try {
            const response = await fetch(url, config);
            
            if (response.status === 401) {
                this.clearAuth();
                if (window.forum) {
                    window.forum.handleAuthError();
                }
                return null;
            }

            if (response.status === 404) {
                const errorData = await response.json().catch(() => ({ message: 'Not found' }));
                throw new Error(errorData.message || 'Resource not found');
            }

            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || `Request failed with status ${response.status}`);
            }

            return data;
        } catch (error) {
            console.error('API request failed:', error);
            UIComponents.showError(`API request failed: ${error}`);
            throw error;
        }
    }

    async register(username, email, password) {
        const response = await this.request('/api/auth/register', {
            method: 'POST',
            body: JSON.stringify({ username, email, password })
        });
        
        if (response) {
            this.setAuth(response.access_token, response.user, response.csrf_token);
        }
        return response;
    }

    async login(username, password) {
        const response = await this.request('/api/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });
        
        if (response) {
            this.setAuth(response.access_token, response.user, response.csrf_token);
        }
        return response;
    }

    async logout() {
        this.clearAuth();
    }

    async refreshToken() {
        const response = await this.request('/api/auth/refresh', {
            method: 'POST'
        });
        
        if (response) {
            this.setAuth(response.access_token, response.user, response.csrf_token);
        }
        return response;
    }

    async getBoards() {
        return this.request('/api/boards');
    }

    async createBoard(name, description) {
        return this.request('/api/boards', {
            method: 'POST',
            body: JSON.stringify({ name, description })
        });
    }

    async getThreads(boardId, page = 1, perPage = 20) {
        return this.request(`/api/boards/${boardId}/threads?page=${page}&per_page=${perPage}`);
    }

    async getThreadInfo(threadId) {
        try {
            return await this.request(`/api/threads/${threadId}`);
        } catch (error) {
            console.warn(`Failed to get thread info for ${threadId}:`, error);
            return {
                thread_id: threadId,
                title: `Thread ${threadId}`,
                locked: false,
                sticky: false,
                reply_count: 0,
                view_count: 0,
                user_id: 0,
                username: 'Unknown',
                timestamp: Date.now() / 1000
            };
        }
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

    async getPosts(threadId, page = 1, perPage = 20) {
        return this.request(`/api/threads/${threadId}/posts?page=${page}&per_page=${perPage}`);
    }

    async createPost(threadId, content) {
        return this.request(`/api/threads/${threadId}/posts`, {
            method: 'POST',
            body: JSON.stringify({ content })
        });
    }

    async getPost(postId) {
        return this.request(`/api/posts/${postId}`);
    }

    async getPostEditHistory(postId) {
        return this.request(`/api/posts/${postId}/history`);
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


    async banUser(userId, reason = null) {
        return this.request(`/api/admin/users/${userId}/ban`, {
            method: 'POST',
            body: JSON.stringify({ 
                reason: reason || "No reason provided" 
            })
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

    async getPublicUserInfo(userId) {
        return this.request(`/api/users/${userId}/public`);
    }
}