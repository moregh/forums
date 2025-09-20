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

    // Thread methods - SIMPLIFIED
    async getThreads(boardId, page = 1, perPage = 20) {
        return this.request(`/api/boards/${boardId}/threads?page=${page}&per_page=${perPage}`);
    }

    // // REMOVED: Complex getThreadsCount method - we'll get this info from the API response headers or board stats
    // async getThreadsCount(boardId) {
    //     // Instead of making multiple API calls, we'll use the board stats
    //     try {
    //         const boards = await this.getBoards();
    //         const board = boards.find(b => b.board_id == boardId);
    //         return board ? board.thread_count : 20; // Fallback to reasonable default
    //     } catch (error) {
    //         console.warn('Failed to get threads count:', error);
    //         return 20; // Fallback
    //     }
    // }

    async getThreadInfo(threadId) {
        try {
            return await this.request(`/api/threads/${threadId}`);
        } catch (error) {
            console.warn(`Failed to get thread info for ${threadId}:`, error);
            // Return a fallback object with minimal info
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

    // Post methods - SIMPLIFIED
    async getPosts(threadId, page = 1, perPage = 20) {
        return this.request(`/api/threads/${threadId}/posts?page=${page}&per_page=${perPage}`);
    }

    // // REMOVED: Complex getPostsCount method - we'll calculate this differently
    // async getPostsCount(threadId) {
    //     // Instead of making API calls to estimate, we'll use the thread's reply_count + 1
    //     try {
    //         const threadInfo = await this.getThreadInfo(threadId);
    //         return (threadInfo.reply_count || 0) + 1; // +1 for the original post
    //     } catch (error) {
    //         console.warn('Failed to get posts count:', error);
    //         return 20; // Fallback
    //     }
    // }

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

    // REMOVED: Duplicate methods that don't exist

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