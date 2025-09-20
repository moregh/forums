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
                if (window.forum) {
                    window.forum.handleAuthError();
                }
                return null;
            }

            // Handle 404 errors gracefully
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
            throw error;
        }
    }

    // Authentication methods
    async register(username, email, password) {
        const response = await this.request('/api/auth/register', {
            method: 'POST',
            body: JSON.stringify({ username, email, password })
        });
        
        if (response) {
            this.setAuth(response.access_token, response.user);
        }
        return response;
    }

    async login(username, password) {
        const response = await this.request('/api/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });
        
        if (response) {
            this.setAuth(response.access_token, response.user);
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
            this.setAuth(response.access_token, response.user);
        }
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

    async getThreadsCount(boardId) {
        // Get a reasonable estimate by checking multiple pages
        try {
            let totalCount = 0;
            let page = 1;
            const perPage = 100;
            
            while (page <= 10) { // Limit to 10 pages max to avoid infinite loops
                const threads = await this.request(`/api/boards/${boardId}/threads?page=${page}&per_page=${perPage}`);
                if (!threads || threads.length === 0) break;
                
                totalCount += threads.length;
                if (threads.length < perPage) break; // Last page
                page++;
            }
            
            return totalCount;
        } catch (error) {
            console.warn('Failed to get threads count:', error);
            return 20; // Return a default count
        }
    }

    async getThreadInfo(threadId) {
        try {
            return await this.request(`/api/threads/${threadId}`);
        } catch (error) {
            console.warn(`Failed to get thread info for ${threadId}:`, error);
            // Return a fallback object
            return {
                thread_id: threadId,
                title: `Thread ${threadId}`,
                locked: false,
                sticky: false
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

    // Post methods
    async getPosts(threadId, page = 1, perPage = 20) {
        return this.request(`/api/threads/${threadId}/posts?page=${page}&per_page=${perPage}`);
    }

    async getPostsCount(threadId) {
        try {
            let totalCount = 0;
            let page = 1;
            const perPage = 100;
            
            while (page <= 10) { // Limit to 10 pages max
                const posts = await this.request(`/api/threads/${threadId}/posts?page=${page}&per_page=${perPage}`);
                if (!posts || posts.length === 0) break;
                
                totalCount += posts.length;
                if (posts.length < perPage) break; // Last page
                page++;
            }
            
            return totalCount;
        } catch (error) {
            console.warn('Failed to get posts count:', error);
            return 20; // Return a default count
        }
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