class UserService {
    constructor(api, modalManager, notifications) {
        this.api = api;
        this.modalManager = modalManager;
        this.notifications = notifications;
        this.userInfoCache = new Map();
        this.cacheTimeout = 5 * 60 * 1000; // 5 minutes
    }

    /**
     * Show user info popup for a given user ID
     * @param {number} userId - The user ID to show info for
     */
    async showUserInfo(userId) {
        try {
            const userInfo = await this.getUserInfo(userId);
            this.createUserInfoModal(userInfo);
        } catch (error) {
            console.error('Failed to load user info:', error);
            this.notifications.show('Failed to load user information', 'error');
        }
    }

    /**
     * Get user info with caching
     * @param {number} userId - The user ID
     * @returns {Promise<Object>} User info object
     */
    async getUserInfo(userId, forceRefresh = false) {
        const cacheKey = `user_${userId}`;
        const now = Date.now();

        if (!forceRefresh && this.userInfoCache.has(cacheKey)) {
            const cached = this.userInfoCache.get(cacheKey);
            if (now - cached.timestamp < this.cacheTimeout) {
                return cached.data;
            }
        }

        const userInfo = await this.api.getPublicUserInfo(userId);
        this.userInfoCache.set(cacheKey, {
            data: userInfo,
            timestamp: now
        });

        return userInfo;
    }

    /**
     * Create and show user info modal
     * @param {Object} userInfo - User info object
     */
    createUserInfoModal(userInfo) {
        const activityStatusClass = this.getActivityStatusClass(userInfo.activity_status);
        const rankClass = this.getRankClass(userInfo.user_rank);

        const joinDate = new Date(userInfo.join_date * 1000).toLocaleDateString();
        const lastActivity = this.formatLastActivity(userInfo.last_activity);

        const recentPostsHtml = this.formatRecentPosts(userInfo.recent_posts);

        const avatarContent = this.getAvatarContent(userInfo);

        const content = `
            <div class="modal-header">
                <h3 id="user-info-title">User Information</h3>
            </div>
            <div class="modal-body user-info-modal">
                <div class="user-info-header">
                    <div class="user-avatar">
                        ${avatarContent}
                    </div>
                    <div class="user-basic-info">
                        <h4 class="username">
                            ${UIComponents.escapeHtml(userInfo.username)}
                            ${userInfo.is_admin ? '<span class="admin-badge">Admin</span>' : ''}
                            ${userInfo.is_banned ? '<span class="banned-badge">Banned</span>' : ''}
                        </h4>
                        <div class="user-rank ${rankClass}">
                            <span class="rank-icon">★</span>
                            ${userInfo.rank_description}
                        </div>
                        <div class="activity-status ${activityStatusClass}">
                            <span class="status-indicator"></span>
                            ${this.getActivityStatusText(userInfo.activity_status)}
                        </div>
                    </div>
                </div>

                <div class="user-stats">
                    <div class="stat-card">
                        <div class="stat-number">${userInfo.post_count}</div>
                        <div class="stat-label">Posts</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${userInfo.thread_count}</div>
                        <div class="stat-label">Threads</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${userInfo.posts_per_day}</div>
                        <div class="stat-label">Posts/Day</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${userInfo.days_since_join}</div>
                        <div class="stat-label">Days Joined</div>
                    </div>
                </div>

                <div class="user-details">
                    <div class="detail-row">
                        <span class="detail-label">Joined:</span>
                        <span class="detail-value">${joinDate}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Last Activity:</span>
                        <span class="detail-value">${lastActivity}</span>
                    </div>
                </div>

                ${recentPostsHtml}
            </div>
        `;

        this.modalManager.createModal(content, {
            className: 'modal user-info-modal-container',
            width: '500px',
            closeButton: true
        });
    }

    /**
     * Get avatar content with proper fallback handling
     * @param {Object} userInfo - User info object
     * @returns {string} HTML string for avatar
     */
    getAvatarContent(userInfo) {
        if (!userInfo.avatar_url ||
            userInfo.avatar_url === '/static/default-avatar.png' ||
            userInfo.avatar_url === 'default-avatar.png' ||
            userInfo.avatar_url === '' ||
            userInfo.avatar_url === null) {

            const initials = this.getUserInitials(userInfo.username);
            return `<div class="avatar-initials">${initials}</div>`;
        }

        const avatarId = `avatar-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

        return `<img id="${avatarId}"
                     src="${this.escapeHtml(userInfo.avatar_url)}"
                     alt="${this.escapeHtml(userInfo.username)}'s avatar"
                     onload="this.style.display='block'; this.nextElementSibling?.remove();"
                     onerror="this.style.display='none'; this.nextElementSibling.style.display='block';">
                <div class="avatar-initials" style="display: none;">${this.getUserInitials(userInfo.username)}</div>`;
    }

    /**
     * Get user initials from username
     * @param {string} username - Username
     * @returns {string} User initials (1-2 characters)
     */
    getUserInitials(username) {
        if (!username) return '?';

        const cleaned = username.trim().toUpperCase();
        if (cleaned.length === 1) return cleaned;

        const parts = cleaned.split(/[\s_-]+/).filter(part => part.length > 0);
        if (parts.length >= 2) {
            return parts[0].charAt(0) + parts[parts.length - 1].charAt(0);
        }

        return cleaned.length >= 2 ? cleaned.substring(0, 2) : cleaned.charAt(0);
    }

    /**
     * Format recent posts for display
     * @param {Array} recentPosts - Array of recent post objects
     * @returns {string} HTML string for recent posts
     */
    formatRecentPosts(recentPosts) {
        if (!recentPosts || recentPosts.length === 0) {
            return `
                <div class="recent-posts">
                    <h5>Recent Posts</h5>
                    <div class="no-posts">No recent posts</div>
                </div>
            `;
        }

        const postsHtml = recentPosts.map(post => {
            const postDate = new Date(post.timestamp * 1000);
            const relativeTime = this.getRelativeTime(postDate);

            return `
                <div class="recent-post-item" data-thread-id="${post.thread_id}" onclick="window.userService?.navigateToThread(${post.thread_id}) || window.forum?.navigateToThreadFromUserInfo(${post.thread_id})" title="Click to view thread">
                    <div class="post-thread">
                        <span class="thread-link-icon">→</span>
                        ${this.escapeHtml(post.thread_title)}
                    </div>
                    <div class="post-time">${relativeTime}</div>
                </div>
            `;
        }).join('');

        return `
            <div class="recent-posts">
                <h5>Recent Posts <span class="recent-posts-count">(${recentPosts.length})</span></h5>
                <div class="recent-posts-list">
                    ${postsHtml}
                </div>
            </div>
        `;
    }

    /**
     * Get CSS class for activity status
     * @param {string} status - Activity status
     * @returns {string} CSS class name
     */
    getActivityStatusClass(status) {
        switch (status) {
            case 'online': return 'status-online';
            case 'recently_active': return 'status-recent';
            default: return 'status-offline';
        }
    }

    /**
     * Get display text for activity status
     * @param {string} status - Activity status
     * @returns {string} Display text
     */
    getActivityStatusText(status) {
        switch (status) {
            case 'online': return 'Online';
            case 'recently_active': return 'Recently Active';
            default: return 'Offline';
        }
    }

    /**
     * Get CSS class for user rank
     * @param {string} rank - User rank
     * @returns {string} CSS class name
     */
    getRankClass(rank) {
        switch (rank) {
            case 'veteran': return 'rank-veteran';
            case 'active': return 'rank-active';
            case 'regular': return 'rank-regular';
            case 'member': return 'rank-member';
            default: return 'rank-newcomer';
        }
    }

    /**
     * Format last activity time
     * @param {number} timestamp - Last activity timestamp
     * @returns {string} Formatted time string
     */
    formatLastActivity(timestamp) {
        const date = new Date(timestamp * 1000);
        const now = new Date();
        const diffMs = now - date;
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

        if (diffDays === 0) {
            return 'Today';
        } else if (diffDays === 1) {
            return 'Yesterday';
        } else if (diffDays < 7) {
            return `${diffDays} days ago`;
        } else {
            return date.toLocaleDateString();
        }
    }

    /**
     * Get relative time string
     * @param {Date} date - Date object
     * @returns {string} Relative time string
     */
    getRelativeTime(date) {
        const now = new Date();
        const diffMs = now - date;
        const diffMinutes = Math.floor(diffMs / (1000 * 60));
        const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

        if (diffMinutes < 1) {
            return 'Just now';
        } else if (diffMinutes < 60) {
            return `${diffMinutes}m ago`;
        } else if (diffHours < 24) {
            return `${diffHours}h ago`;
        } else if (diffDays < 7) {
            return `${diffDays}d ago`;
        } else {
            return date.toLocaleDateString();
        }
    }

    /**
     * Escape HTML to prevent XSS
     * @param {string} text - Text to escape
     * @returns {string} Escaped text
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Clear user info cache
     */
    clearCache() {
        this.userInfoCache.clear();
    }

    /**
     * Navigate to a thread (used by recent posts)
     * @param {number} threadId - The thread ID to navigate to
     */
    navigateToThread(threadId) {
        this.modalManager.closeAllModals();

        if (window.forum && window.forum.router) {
            window.forum.router.navigate(`/threads/${threadId}`);
        } else if (window.location) {
            window.location.hash = `#/threads/${threadId}`;
            window.location.reload();
        }
    }

    /**
     * Set up click handlers for usernames
     * @param {HTMLElement} container - Container element to search for usernames
     */
    setupUsernameClickHandlers(container = document) {
        const usernameElements = container.querySelectorAll('[data-user-id], .username[data-user-id], .post-author[data-user-id]');

        usernameElements.forEach(element => {
            const userId = element.getAttribute('data-user-id');
            if (userId && !element.hasAttribute('data-user-info-handler')) {
                element.style.cursor = 'pointer';
                element.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    this.showUserInfo(parseInt(userId));
                });
                element.setAttribute('data-user-info-handler', 'true');
            }
        });
    }
}