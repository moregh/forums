class AdminService {
    constructor(api, notifications) {
        this.api = api;
        this.notifications = notifications;
    }

    async getUsers(page = 1, perPage = 50) {
        try {
            const users = await this.api.request(`/api/admin/users?page=${page}&per_page=${perPage}`);
            return Array.isArray(users) ? users.map(user => this.sanitizeUser(user)) : [];
        } catch (error) {
            if (error.message.includes('403') || error.message.includes('admin')) {
                throw new Error('Admin privileges required');
            }
            throw new Error(`Failed to load users: ${error.message}`);
        }
    }

    async getForumStats() {
        try {
            const stats = await this.api.request('/api/stats');
            return this.sanitizeStats(stats);
        } catch (error) {
            throw new Error(`Failed to load forum statistics: ${error.message}`);
        }
    }

    async getModerationLog(page = 1, perPage = 20) {
        try {
            const logs = await this.api.request(`/api/admin/moderation-log?page=${page}&per_page=${perPage}`);
            return Array.isArray(logs) ? logs : [];
        } catch (error) {
            if (error.message.includes('403') || error.message.includes('admin')) {
                throw new Error('Admin privileges required');
            }
            throw new Error(`Failed to load moderation log: ${error.message}`);
        }
    }

    async banUser(userId, reason) {
        const validation = Validation.validateBanReason(reason);
        if (!validation.isValid) {
            const error = new Error('Validation failed');
            error.name = 'ValidationError';
            error.details = { reason: validation.errors };
            throw error;
        }

        try {
            await this.api.banUser(userId, reason);
            return true;
        } catch (error) {
            if (error.message.includes('admin')) {
                throw new Error('Cannot ban admin users');
            }
            if (error.message.includes('not found')) {
                throw new Error('User not found');
            }
            if (error.message.includes('permission')) {
                throw new Error('Admin privileges required');
            }
            throw error;
        }
    }

    async unbanUser(userId) {
        try {
            await this.api.unbanUser(userId);
            return true;
        } catch (error) {
            if (error.message.includes('not found')) {
                throw new Error('User not found');
            }
            if (error.message.includes('permission')) {
                throw new Error('Admin privileges required');
            }
            throw error;
        }
    }

    async promoteUser(userId) {
        try {
            await this.api.makeUserAdmin(userId);
            return true;
        } catch (error) {
            if (error.message.includes('already admin')) {
                throw new Error('User is already an admin');
            }
            if (error.message.includes('not found')) {
                throw new Error('User not found');
            }
            if (error.message.includes('permission')) {
                throw new Error('Admin privileges required');
            }
            throw error;
        }
    }

    async demoteUser(userId) {
        try {
            await this.api.removeUserAdmin(userId);
            return true;
        } catch (error) {
            if (error.message.includes('not admin')) {
                throw new Error('User is not an admin');
            }
            if (error.message.includes('yourself')) {
                throw new Error('Cannot demote yourself');
            }
            if (error.message.includes('not found')) {
                throw new Error('User not found');
            }
            if (error.message.includes('permission')) {
                throw new Error('Admin privileges required');
            }
            throw error;
        }
    }

    sanitizeUser(user) {
        return {
            user_id: user.user_id,
            username: user.username || 'Unknown',
            email: user.email || '',
            is_admin: Boolean(user.is_admin),
            is_banned: Boolean(user.is_banned),
            join_date: user.join_date || 0,
            last_activity: user.last_activity || 0,
            post_count: user.post_count || 0,
            thread_count: user.thread_count || 0
        };
    }

    sanitizeStats(stats) {
        return {
            total_users: stats.total_users || 0,
            total_threads: stats.total_threads || 0,
            total_posts: stats.total_posts || 0,
            total_boards: stats.total_boards || 0,
            users_online: stats.users_online || 0,
            posts_today: stats.posts_today || 0,
            top_posters: Array.isArray(stats.top_posters) ? stats.top_posters : []
        };
    }

    formatUserForDisplay(user) {
        return {
            ...user,
            formattedJoinDate: UIComponents.formatDate(user.join_date),
            formattedLastActivity: UIComponents.formatDate(user.last_activity),
            membershipDuration: this.calculateMembershipDuration(user.join_date),
            activityLevel: this.calculateUserActivityLevel(user),
            isNewUser: this.isNewUser(user),
            isActiveUser: this.isActiveUser(user)
        };
    }

    formatUsersForDisplay(users) {
        return users.map(user => this.formatUserForDisplay(user));
    }

    calculateMembershipDuration(joinDate) {
        const now = Date.now() / 1000;
        const duration = now - joinDate;
        const days = Math.floor(duration / (24 * 60 * 60));
        const months = Math.floor(days / 30);
        const years = Math.floor(days / 365);

        if (years > 0) {
            return years === 1 ? '1 year' : `${years} years`;
        } else if (months > 0) {
            return months === 1 ? '1 month' : `${months} months`;
        } else {
            return days === 1 ? '1 day' : `${days} days`;
        }
    }

    calculateUserActivityLevel(user) {
        const totalActivity = (user.post_count || 0) + (user.thread_count || 0);
        const membershipDays = Math.max(1, Math.floor((Date.now() / 1000 - user.join_date) / (24 * 60 * 60)));
        const activityPerDay = totalActivity / membershipDays;

        if (activityPerDay >= 5) return 'very-active';
        if (activityPerDay >= 2) return 'active';
        if (activityPerDay >= 0.5) return 'moderate';
        if (activityPerDay > 0) return 'low';
        return 'inactive';
    }

    isNewUser(user) {
        const weekAgo = Date.now() / 1000 - (7 * 24 * 60 * 60);
        return user.join_date > weekAgo;
    }

    isActiveUser(user) {
        const weekAgo = Date.now() / 1000 - (7 * 24 * 60 * 60);
        return user.last_activity > weekAgo;
    }

    sortUsers(users, sortBy = 'username') {
        const sortedUsers = [...users];

        switch (sortBy) {
            case 'username':
                return sortedUsers.sort((a, b) => a.username.localeCompare(b.username));
            case 'join_date':
                return sortedUsers.sort((a, b) => b.join_date - a.join_date);
            case 'last_activity':
                return sortedUsers.sort((a, b) => b.last_activity - a.last_activity);
            case 'post_count':
                return sortedUsers.sort((a, b) => (b.post_count || 0) - (a.post_count || 0));
            case 'thread_count':
                return sortedUsers.sort((a, b) => (b.thread_count || 0) - (a.thread_count || 0));
            case 'activity_level':
                return sortedUsers.sort((a, b) => {
                    const levelOrder = { 'very-active': 4, 'active': 3, 'moderate': 2, 'low': 1, 'inactive': 0 };
                    const aLevel = levelOrder[this.calculateUserActivityLevel(a)] || 0;
                    const bLevel = levelOrder[this.calculateUserActivityLevel(b)] || 0;
                    return bLevel - aLevel;
                });
            default:
                return sortedUsers.sort((a, b) => a.username.localeCompare(b.username));
        }
    }

    filterUsers(users, filter = {}) {
        let filtered = [...users];

        if (filter.search) {
            const searchTerm = filter.search.toLowerCase();
            filtered = filtered.filter(user =>
                user.username.toLowerCase().includes(searchTerm) ||
                user.email.toLowerCase().includes(searchTerm)
            );
        }

        if (filter.status === 'admin') {
            filtered = filtered.filter(user => user.is_admin);
        } else if (filter.status === 'banned') {
            filtered = filtered.filter(user => user.is_banned);
        } else if (filter.status === 'regular') {
            filtered = filtered.filter(user => !user.is_admin && !user.is_banned);
        }

        if (filter.activityLevel) {
            filtered = filtered.filter(user =>
                this.calculateUserActivityLevel(user) === filter.activityLevel
            );
        }

        if (filter.newUsers) {
            filtered = filtered.filter(user => this.isNewUser(user));
        }

        if (filter.activeUsers) {
            filtered = filtered.filter(user => this.isActiveUser(user));
        }

        if (filter.minPosts !== undefined) {
            filtered = filtered.filter(user => (user.post_count || 0) >= filter.minPosts);
        }

        if (filter.joinDateRange) {
            const { start, end } = filter.joinDateRange;
            filtered = filtered.filter(user => 
                user.join_date >= start && user.join_date <= end
            );
        }

        return filtered;
    }

    getUserStats(users) {
        const total = users.length;
        const admins = users.filter(u => u.is_admin).length;
        const banned = users.filter(u => u.is_banned).length;
        const active = users.filter(u => this.isActiveUser(u)).length;
        const newUsers = users.filter(u => this.isNewUser(u)).length;

        const totalPosts = users.reduce((sum, u) => sum + (u.post_count || 0), 0);
        const totalThreads = users.reduce((sum, u) => sum + (u.thread_count || 0), 0);

        const topPoster = users.length > 0
            ? users.reduce((max, user) => 
                (user.post_count || 0) > (max.post_count || 0) ? user : max
              )
            : null;

        const averagePostsPerUser = total > 0 ? Math.round(totalPosts / total) : 0;

        return {
            total,
            admins,
            banned,
            regular: total - admins - banned,
            active,
            inactive: total - active,
            newUsers,
            totalPosts,
            totalThreads,
            averagePostsPerUser,
            topPoster,
            adminPercentage: total > 0 ? Math.round((admins / total) * 100) : 0,
            bannedPercentage: total > 0 ? Math.round((banned / total) * 100) : 0,
            activePercentage: total > 0 ? Math.round((active / total) * 100) : 0
        };
    }

    canPerformAction(action, targetUser, currentUser) {
        if (!currentUser || !currentUser.is_admin) {
            return { allowed: false, reason: 'Admin privileges required' };
        }

        if (!targetUser) {
            return { allowed: false, reason: 'Target user not found' };
        }

        switch (action) {
            case 'ban':
                if (targetUser.is_admin) {
                    return { allowed: false, reason: 'Cannot ban admin users' };
                }
                if (targetUser.is_banned) {
                    return { allowed: false, reason: 'User is already banned' };
                }
                break;

            case 'unban':
                if (!targetUser.is_banned) {
                    return { allowed: false, reason: 'User is not banned' };
                }
                break;

            case 'promote':
                if (targetUser.is_admin) {
                    return { allowed: false, reason: 'User is already an admin' };
                }
                break;

            case 'demote':
                if (!targetUser.is_admin) {
                    return { allowed: false, reason: 'User is not an admin' };
                }
                if (targetUser.user_id === currentUser.user_id) {
                    return { allowed: false, reason: 'Cannot demote yourself' };
                }
                break;

            default:
                return { allowed: false, reason: 'Unknown action' };
        }

        return { allowed: true };
    }

    async searchUsers(query, options = {}) {
        const { page = 1, perPage = 50, filters = {} } = options;

        const validation = Validation.validateSearchQuery(query);
        if (!validation.isValid) {
            throw new Error(validation.errors[0]);
        }

        try {
            const users = await this.getUsers(page, perPage);
            const searchTerm = query.toLowerCase();

            let results = users.filter(user =>
                user.username.toLowerCase().includes(searchTerm) ||
                user.email.toLowerCase().includes(searchTerm)
            );

            if (Object.keys(filters).length > 0) {
                results = this.filterUsers(results, filters);
            }

            return results;
        } catch (error) {
            throw new Error(`User search failed: ${error.message}`);
        }
    }

    formatModerationAction(action) {
        return {
            ...action,
            formattedDate: UIComponents.formatDate(action.timestamp),
            actionText: this.getActionText(action.action),
            targetText: this.getTargetText(action.target_type, action.target_id),
            severityLevel: this.getActionSeverity(action.action)
        };
    }

    getActionText(action) {
        const actionMap = {
            'ban': 'Banned user',
            'unban': 'Unbanned user',
            'promote_admin': 'Promoted to admin',
            'demote_admin': 'Removed admin privileges',
            'delete_post': 'Deleted post',
            'delete_thread': 'Deleted thread',
            'lock_thread': 'Locked thread',
            'unlock_thread': 'Unlocked thread',
            'sticky_thread': 'Made thread sticky',
            'unsticky_thread': 'Removed thread sticky',
            'restore_post': 'Restored post'
        };

        return actionMap[action] || action;
    }

    getTargetText(targetType, targetId) {
        const typeMap = {
            'user': 'User',
            'post': 'Post',
            'thread': 'Thread',
            'board': 'Board'
        };

        return `${typeMap[targetType] || targetType} #${targetId}`;
    }

    getActionSeverity(action) {
        const severityMap = {
            'ban': 'high',
            'delete_thread': 'high',
            'promote_admin': 'high',
            'demote_admin': 'high',
            'unban': 'medium',
            'delete_post': 'medium',
            'lock_thread': 'medium',
            'restore_post': 'low',
            'unlock_thread': 'low',
            'sticky_thread': 'low',
            'unsticky_thread': 'low'
        };

        return severityMap[action] || 'medium';
    }

    getDashboardData() {
        return {
            userManagement: true,
            moderationLog: true,
            forumStats: true,
            contentModeration: true
        };
    }

    getQuickActions() {
        return [
            { id: 'view_users', text: 'View All Users', icon: '👥' },
            { id: 'view_reports', text: 'View Reports', icon: '🚨' },
            { id: 'moderation_log', text: 'Moderation Log', icon: '📋' },
            { id: 'forum_stats', text: 'Forum Statistics', icon: '📊' },
            { id: 'system_settings', text: 'System Settings', icon: '⚙️' }
        ];
    }

    async exportUserData(format = 'csv') {
        try {
            const users = await this.getUsers(1, 1000);
            
            if (format === 'csv') {
                return this.exportUsersToCSV(users);
            } else if (format === 'json') {
                return this.exportUsersToJSON(users);
            } else {
                throw new Error('Unsupported export format');
            }
        } catch (error) {
            throw new Error(`Export failed: ${error.message}`);
        }
    }

    exportUsersToCSV(users) {
        const headers = ['Username', 'Email', 'Join Date', 'Last Activity', 'Posts', 'Threads', 'Admin', 'Banned'];
        const rows = users.map(user => [
            user.username,
            user.email,
            new Date(user.join_date * 1000).toISOString(),
            new Date(user.last_activity * 1000).toISOString(),
            user.post_count || 0,
            user.thread_count || 0,
            user.is_admin ? 'Yes' : 'No',
            user.is_banned ? 'Yes' : 'No'
        ]);

        return [headers, ...rows].map(row => 
            row.map(cell => `"${cell}"`).join(',')
        ).join('\n');
    }

    exportUsersToJSON(users) {
        return JSON.stringify(users, null, 2);
    }
}