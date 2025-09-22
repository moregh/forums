class AdminController {
    constructor(adminService, formHandler, notifications, modalManager, router, state) {
        this.adminService = adminService;
        this.formHandler = formHandler;
        this.notifications = notifications;
        this.modalManager = modalManager;
        this.router = router;
        this.state = state;
        this.currentView = 'dashboard';
        this.currentFilters = {};
    }

    async showAdmin() {
        const currentUser = this.state.getState().user;
        if (!currentUser || !currentUser.is_admin) {
            this.notifications.showError('Admin privileges required');
            this.router.navigate('/');
            return;
        }

        try {
            this.state.setState({ loading: true, error: null });
            
            const [users, stats, moderationLog] = await Promise.all([
                this.adminService.getUsers(1, 50).catch(() => []),
                this.adminService.getForumStats().catch(() => ({})),
                this.adminService.getModerationLog(1, 20).catch(() => [])
            ]);

            const content = document.getElementById('content');
            content.innerHTML = this.renderAdminPanel(users, stats, moderationLog);
            
            this.setupAdminInteractions();
            this.state.setState({ loading: false });
            setTimeout(() => {
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }, 0);

        } catch (error) {
            this.state.setState({ error: error.message, loading: false });
            this.showErrorState(error.message);
        }
    }

    renderAdminPanel(users, stats, moderationLog) {
        return `
            <div class="admin-header">
                <h1>Admin Panel</h1>
                <div class="admin-nav-tabs">
                    ${this.renderAdminNavigation()}
                </div>
            </div>
            
            <div class="admin-layout">
                <div class="admin-sidebar">
                    ${this.renderAdminSidebar(stats)}
                </div>
                
                <div class="admin-main-content" id="admin-main-content">
                    ${this.renderDashboard(users, stats, moderationLog)}
                </div>
            </div>
        `;
    }

    renderAdminNavigation() {
        const items = [
            { id: 'dashboard', text: 'Dashboard', icon: '📊' },
            { id: 'users', text: 'Users', icon: '👥' },
            { id: 'moderation', text: 'Moderation', icon: '🛡️' },
            { id: 'content', text: 'Content', icon: '📝' },
            { id: 'settings', text: 'Settings', icon: '⚙️' }
        ];

        return items.map(item => `
            <button class="admin-tab ${this.currentView === item.id ? 'active' : ''}" 
                    onclick="adminController.switchView('${item.id}')">
                <span class="tab-icon">${item.icon}</span>
                <span class="tab-text">${item.text}</span>
            </button>
        `).join('');
    }

    renderAdminSidebar(stats) {
        return `
            <div class="sidebar-section">
                <h3>Quick Actions</h3>
                <div class="quick-actions-grid">
                    <button class="quick-action-card" onclick="adminController.handleQuickAction('view_users')">
                        <div class="action-icon">👥</div>
                        <div class="action-text">Manage Users</div>
                        <div class="action-count">${stats.total_users || 0}</div>
                    </button>
                    <button class="quick-action-card" onclick="adminController.handleQuickAction('view_reports')">
                        <div class="action-icon">🚨</div>
                        <div class="action-text">View Reports</div>
                        <div class="action-count">0</div>
                    </button>
                    <button class="quick-action-card" onclick="adminController.handleQuickAction('moderation_log')">
                        <div class="action-icon">📋</div>
                        <div class="action-text">Mod Log</div>
                        <div class="action-count">Latest</div>
                    </button>
                    <button class="quick-action-card" onclick="adminController.handleQuickAction('forum_stats')">
                        <div class="action-icon">📊</div>
                        <div class="action-text">Statistics</div>
                        <div class="action-count">${stats.total_posts || 0}</div>
                    </button>
                </div>
            </div>
            
            <div class="sidebar-section">
                <h3>System Status</h3>
                <div class="status-indicators">
                    <div class="status-item healthy">
                        <div class="status-dot"></div>
                        <div class="status-info">
                            <div class="status-label">Forum Status</div>
                            <div class="status-value">Online</div>
                        </div>
                    </div>
                    <div class="status-item healthy">
                        <div class="status-dot"></div>
                        <div class="status-info">
                            <div class="status-label">Users Online</div>
                            <div class="status-value">${stats.users_online || 0}</div>
                        </div>
                    </div>
                    <div class="status-item healthy">
                        <div class="status-dot"></div>
                        <div class="status-info">
                            <div class="status-label">System Load</div>
                            <div class="status-value">Normal</div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    renderDashboard(users, stats, moderationLog) {
        return `
            <div class="dashboard-overview">
                ${this.renderStatsCards(stats)}
            </div>
            
            <div class="dashboard-content-grid">
                <div class="dashboard-panel">
                    <div class="panel-header">
                        <h3>Recent User Activity</h3>
                        <button onclick="adminController.switchView('users')" class="btn-text">View All</button>
                    </div>
                    <div class="panel-content">
                        ${this.renderRecentUsers(users.slice(0, 8))}
                    </div>
                </div>
                
                <div class="dashboard-panel">
                    <div class="panel-header">
                        <h3>Recent Moderation Actions</h3>
                        <button onclick="adminController.switchView('moderation')" class="btn-text">View All</button>
                    </div>
                    <div class="panel-content">
                        ${this.renderRecentModerationLog(moderationLog.slice(0, 8))}
                    </div>
                </div>
                
                <div class="dashboard-panel full-width">
                    <div class="panel-header">
                        <h3>System Overview</h3>
                    </div>
                    <div class="panel-content">
                        ${this.renderSystemOverview(stats)}
                    </div>
                </div>
            </div>
        `;
    }

    renderStatsCards(stats) {
        const cards = [
            { title: 'Total Users', value: stats.total_users || 0, icon: '👥', color: 'blue', trend: '+12%' },
            { title: 'Total Threads', value: stats.total_threads || 0, icon: '💬', color: 'green', trend: '+8%' },
            { title: 'Total Posts', value: stats.total_posts || 0, icon: '📝', color: 'purple', trend: '+15%' },
            { title: 'Users Online', value: stats.users_online || 0, icon: '🟢', color: 'orange', trend: 'Now' },
            { title: 'Posts Today', value: stats.posts_today || 0, icon: '📈', color: 'red', trend: 'Today' },
            { title: 'Total Boards', value: stats.total_boards || 0, icon: '📋', color: 'teal', trend: 'Active' }
        ];

        return `
            <div class="stats-cards-grid">
                ${cards.map(card => `
                    <div class="stat-card ${card.color}">
                        <div class="stat-header">
                            <div class="stat-icon">${card.icon}</div>
                            <div class="stat-trend ${card.color}">${card.trend}</div>
                        </div>
                        <div class="stat-body">
                            <div class="stat-value">${card.value.toLocaleString()}</div>
                            <div class="stat-title">${UIComponents.escapeHtml(card.title)}</div>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    renderUserManagement(users) {
        const formattedUsers = this.adminService.formatUsersForDisplay(users);
        const userStats = this.adminService.getUserStats(users);

        return `
            <div class="users-management">
                <div class="section-header">
                    <h2>User Management</h2>
                    <div class="section-actions">
                        <button onclick="adminController.showUserFilters()" class="btn-secondary">
                            <span>🔍</span> Filters
                        </button>
                        <button onclick="adminController.exportUsers()" class="btn-secondary">
                            <span>📤</span> Export
                        </button>
                    </div>
                </div>
                
                <div class="user-stats-overview">
                    ${this.renderUserStatsCards(userStats)}
                </div>
                
                <div class="user-controls-bar">
                    <div class="search-section">
                        <input type="text" id="user-search" placeholder="Search users..." 
                               onkeyup="adminController.handleUserSearch(this.value)">
                    </div>
                    <div class="filter-section">
                        <select id="user-status-filter" onchange="adminController.handleUserFilter('status', this.value)">
                            <option value="">All Users</option>
                            <option value="admin">Admins Only</option>
                            <option value="banned">Banned Users</option>
                            <option value="regular">Regular Users</option>
                        </select>
                        <select id="user-sort" onchange="adminController.handleUserSort(this.value)">
                            <option value="username">Sort by Username</option>
                            <option value="join_date">Sort by Join Date</option>
                            <option value="last_activity">Sort by Activity</option>
                            <option value="post_count">Sort by Posts</option>
                        </select>
                    </div>
                </div>
                
                <div class="users-table-container" id="user-list-container">
                    ${this.renderUserTable(formattedUsers)}
                </div>
            </div>
        `;
    }

    renderUserTable(users) {
        if (!users || users.length === 0) {
            return '<div class="empty-state"><p>No users found.</p></div>';
        }

        return `
            <div class="users-table">
                <div class="table-header">
                    <div class="col-user">User Information</div>
                    <div class="col-activity">Activity Level</div>
                    <div class="col-stats">Statistics</div>
                    <div class="col-dates">Dates</div>
                    <div class="col-actions">Actions</div>
                </div>
                <div class="table-body">
                    ${users.map(user => this.renderUserRow(user)).join('')}
                </div>
            </div>
        `;
    }

    renderUserRow(user) {
        const currentUser = this.state.getState().user;
        const activityInfo = this.getActivityLevelInfo(user.activityLevel);
        
        return `
            <div class="user-row" data-user-id="${user.user_id}">
                <div class="col-user">
                    <div class="user-profile">
                        <div class="user-avatar">${UIComponents.escapeHtml(user.username.charAt(0).toUpperCase())}</div>
                        <div class="user-details">
                            <div class="user-name">${UIComponents.escapeHtml(user.username)}</div>
                            <div class="user-email">${UIComponents.escapeHtml(user.email)}</div>
                            <div class="user-badges">
                                ${user.is_admin ? '<span class="badge admin">Admin</span>' : ''}
                                ${user.is_banned ? '<span class="badge banned">Banned</span>' : ''}
                                ${user.isNewUser ? '<span class="badge new">New User</span>' : ''}
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-activity">
                    <div class="activity-indicator">
                        <div class="activity-level ${user.activityLevel}">
                            <div class="activity-dot"></div>
                            <div class="activity-text">
                                <div class="activity-label">${activityInfo.label}</div>
                                <div class="activity-desc">${UIComponents.escapeHtml(activityInfo.description)}</div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-stats">
                    <div class="user-stats-grid">
                        <div class="stat-item">
                            <div class="stat-number">${user.post_count || 0}</div>
                            <div class="stat-label">Posts</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-number">${user.thread_count || 0}</div>
                            <div class="stat-label">Threads</div>
                        </div>
                    </div>
                </div>
                <div class="col-dates">
                    <div class="date-info">
                        <div class="date-item">
                            <div class="date-label">Joined</div>
                            <div class="date-value">${user.formattedJoinDate}</div>
                        </div>
                        <div class="date-item">
                            <div class="date-label">Last Active</div>
                            <div class="date-value">${user.formattedLastActivity}</div>
                        </div>
                    </div>
                </div>
                <div class="col-actions">
                    ${this.renderUserActions(user, currentUser)}
                </div>
            </div>
        `;
    }

    getActivityLevelInfo(activityLevel) {
        const levels = {
            'very-active': { label: 'Very Active', description: '5+ posts/day' },
            'active': { label: 'Active', description: '2-5 posts/day' },
            'moderate': { label: 'Moderate', description: '0.5-2 posts/day' },
            'low': { label: 'Low Activity', description: 'Few posts/week' },
            'inactive': { label: 'Inactive', description: 'No recent activity' }
        };
        return levels[activityLevel] || { label: 'Unknown', description: 'Activity level unknown' };
    }

    renderUserActions(user, currentUser) {
        const actions = [];
        
        if (!user.is_banned) {
            const banAction = this.adminService.canPerformAction('ban', user, currentUser);
            if (banAction && banAction.allowed) {
                actions.push(`<button onclick="adminController.banUser(${user.user_id})" class="action-btn ban">Ban</button>`);
            }
        } else {
            const unbanAction = this.adminService.canPerformAction('unban', user, currentUser);
            if (unbanAction && unbanAction.allowed) {
                actions.push(`<button onclick="adminController.unbanUser(${user.user_id})" class="action-btn unban">Unban</button>`);
            }
        }

        if (!user.is_admin) {
            const promoteAction = this.adminService.canPerformAction('promote', user, currentUser);
            if (promoteAction && promoteAction.allowed) {
                actions.push(`<button onclick="adminController.promoteUser(${user.user_id})" class="action-btn promote">Make Admin</button>`);
            }
        } else {
            const demoteAction = this.adminService.canPerformAction('demote', user, currentUser);
            if (demoteAction && demoteAction.allowed) {
                actions.push(`<button onclick="adminController.demoteUser(${user.user_id})" class="action-btn demote">Remove Admin</button>`);
            }
        }

        return `<div class="user-actions-grid">${actions.join('')}</div>`;
    }

    renderUserStatsCards(stats) {
        const cards = [
            { title: 'Total Users', value: stats.total, color: 'blue', icon: '👥' },
            { title: 'Active Users', value: stats.active, color: 'green', icon: '🟢' },
            { title: 'Administrators', value: stats.admins, color: 'purple', icon: '👑' },
            { title: 'Banned Users', value: stats.banned, color: 'red', icon: '🚫' },
            { title: 'New This Week', value: stats.newUsers, color: 'orange', icon: '✨' }
        ];

        return `
            <div class="mini-stats-grid">
                ${cards.map(card => `
                    <div class="mini-stat-card ${card.color}">
                        <div class="mini-stat-icon">${card.icon}</div>
                        <div class="mini-stat-content">
                            <div class="mini-stat-value">${card.value}</div>
                            <div class="mini-stat-title">${UIComponents.escapeHtml(card.title)}</div>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    renderRecentUsers(users) {
        if (!users || users.length === 0) {
            return '<div class="empty-panel">No recent user activity.</div>';
        }

        return `
            <div class="recent-users-list">
                ${users.map(user => `
                    <div class="recent-user-item">
                        <div class="user-avatar small">${UIComponents.escapeHtml(user.username.charAt(0).toUpperCase())}</div>
                        <div class="user-info">
                            <div class="user-name">${UIComponents.escapeHtml(user.username)}</div>
                            <div class="user-activity">Last active: ${UIComponents.formatDate(user.last_activity)}</div>
                        </div>
                        <div class="user-status ${user.is_admin ? 'admin' : user.is_banned ? 'banned' : 'user'}">
                            ${user.is_admin ? 'Admin' : user.is_banned ? 'Banned' : 'User'}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    renderRecentModerationLog(logs) {
        if (!logs || logs.length === 0) {
            return '<div class="empty-panel">No recent moderation actions.</div>';
        }

        return `
            <div class="moderation-log-list">
                ${logs.map(log => {
                    const formatted = this.adminService.formatModerationAction(log);
                    return `
                        <div class="moderation-item severity-${formatted.severityLevel}">
                            <div class="mod-icon severity-${formatted.severityLevel}">
                                ${this.getModerationIcon(formatted.severityLevel)}
                            </div>
                            <div class="mod-content">
                                <div class="mod-action">${formatted.actionText}</div>
                                <div class="mod-details">${formatted.targetText}</div>
                                <div class="mod-meta">
                                    <span class="mod-user">${UIComponents.escapeHtml(formatted.moderator_name || 'Unknown')}</span>
                                    <span class="mod-date">${formatted.formattedDate}</span>
                                </div>
                            </div>
                        </div>
                    `;
                }).join('')}
            </div>
        `;
    }

    getModerationIcon(severity) {
        const icons = {
            high: '🚨',
            medium: '⚠️',
            low: 'ℹ️'
        };
        return icons[severity] || 'ℹ️';
    }

    renderSystemOverview(stats) {
        return `
            <div class="system-overview-grid">
                <div class="overview-metric">
                    <div class="metric-label">Average Posts per User</div>
                    <div class="metric-value">${Math.round((stats.total_posts || 0) / Math.max(1, stats.total_users || 1))}</div>
                </div>
                <div class="overview-metric">
                    <div class="metric-label">Average Threads per User</div>
                    <div class="metric-value">${Math.round((stats.total_threads || 0) / Math.max(1, stats.total_users || 1))}</div>
                </div>
                <div class="overview-metric">
                    <div class="metric-label">Top Poster</div>
                    <div class="metric-value">${stats.top_posters?.[0]?.username ? UIComponents.escapeHtml(stats.top_posters[0].username) : 'N/A'}</div>
                </div>
                <div class="overview-metric">
                    <div class="metric-label">Forum Activity</div>
                    <div class="metric-value">High</div>
                </div>
            </div>
        `;
    }

    async switchView(viewId) {
        this.currentView = viewId;
        
        try {
            this.state.setState({ loading: true });
            
            let content = '';
            switch (viewId) {
                case 'users':
                    const users = await this.adminService.getUsers(1, 100);
                    content = this.renderUserManagement(users);
                    break;
                case 'moderation':
                    const logs = await this.adminService.getModerationLog(1, 50);
                    content = this.renderModerationView(logs);
                    break;
                case 'content':
                    content = this.renderContentManagement();
                    break;
                case 'settings':
                    content = this.renderSystemSettings();
                    break;
                default:
                    const [dashUsers, stats, modLogs] = await Promise.all([
                        this.adminService.getUsers(1, 50),
                        this.adminService.getForumStats(),
                        this.adminService.getModerationLog(1, 20)
                    ]);
                    content = this.renderDashboard(dashUsers, stats, modLogs);
            }
            
            document.getElementById('admin-main-content').innerHTML = content;
            this.updateNavigation();
            this.state.setState({ loading: false });
            
        } catch (error) {
            this.notifications.showError(`Failed to load ${viewId}: ${error.message}`);
            this.state.setState({ loading: false });
        }
    }

    updateNavigation() {
        document.querySelectorAll('.admin-tab').forEach(item => {
            item.classList.remove('active');
        });
        
        const activeItem = document.querySelector(`[onclick*="'${this.currentView}'"]`);
        if (activeItem) {
            activeItem.classList.add('active');
        }
    }

    async banUser(userId) {
        this.modalManager.createFormModal(
            'Ban User',
            `<textarea name="reason" placeholder="Reason for ban (required)" rows="4" required></textarea>
             <div class="ban-warning">
                <strong>⚠️ Warning:</strong> This will immediately ban the user and prevent them from accessing the forum.
             </div>`,
            async (formData) => {
                await this.adminService.banUser(userId, formData.reason);
                this.notifications.showSuccess('User banned successfully!');
                await this.refreshCurrentView();
            },
            {
                validation: (data) => Validation.validateForm(data, { reason: 'banReason' }),
                confirmClass: 'btn-danger',
                submitText: 'Ban User'
            }
        );
    }

    async unbanUser(userId) {
        this.modalManager.createConfirmationModal(
            'Unban User',
            'Are you sure you want to unban this user? They will regain access to the forum.',
            async () => {
                await this.adminService.unbanUser(userId);
                this.notifications.showSuccess('User unbanned successfully!');
                await this.refreshCurrentView();
            }
        );
    }

    async promoteUser(userId) {
        this.modalManager.createConfirmationModal(
            'Promote to Admin',
            'Are you sure you want to give this user administrator privileges? Admins have full access to the forum.',
            async () => {
                await this.adminService.promoteUser(userId);
                this.notifications.showSuccess('User promoted to admin successfully!');
                await this.refreshCurrentView();
            },
            { confirmClass: 'btn-warning' }
        );
    }

    async demoteUser(userId) {
        this.modalManager.createConfirmationModal(
            'Remove Admin Privileges',
            'Are you sure you want to remove administrator privileges from this user?',
            async () => {
                await this.adminService.demoteUser(userId);
                this.notifications.showSuccess('Admin privileges removed successfully!');
                await this.refreshCurrentView();
            }
        );
    }

    async handleUserSearch(query) {
        if (query.length < 3 && query.length > 0) return;
        
        try {
            const users = query.length === 0 
                ? await this.adminService.getUsers(1, 100)
                : await this.adminService.searchUsers(query);
                
            const container = document.getElementById('user-list-container');
            container.innerHTML = this.renderUserTable(this.adminService.formatUsersForDisplay(users));
        } catch (error) {
            this.notifications.showError('Search failed: ' + error.message);
        }
    }

    async handleUserFilter(filterType, value) {
        this.currentFilters[filterType] = value;
        await this.applyFilters();
    }

    async handleUserSort(sortBy) {
        try {
            const users = await this.adminService.getUsers(1, 100);
            const sortedUsers = this.adminService.sortUsers(users, sortBy);
            
            const container = document.getElementById('user-list-container');
            container.innerHTML = this.renderUserTable(this.adminService.formatUsersForDisplay(sortedUsers));
        } catch (error) {
            this.notifications.showError('Sort failed: ' + error.message);
        }
    }

    async applyFilters() {
        try {
            const users = await this.adminService.getUsers(1, 100);
            const filteredUsers = this.adminService.filterUsers(users, this.currentFilters);
            
            const container = document.getElementById('user-list-container');
            container.innerHTML = this.renderUserTable(this.adminService.formatUsersForDisplay(filteredUsers));
        } catch (error) {
            this.notifications.showError('Filter failed: ' + error.message);
        }
    }

    async exportUsers() {
        try {
            const csvData = await this.adminService.exportUserData('csv');
            this.downloadFile(csvData, 'forum-users.csv', 'text/csv');
            this.notifications.showSuccess('User data exported successfully!');
        } catch (error) {
            this.notifications.showError('Export failed: ' + error.message);
        }
    }

    downloadFile(content, filename, contentType) {
        const blob = new Blob([content], { type: contentType });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
    }

    renderModerationView(logs) {
        return `
            <div class="moderation-management">
                <div class="section-header">
                    <h2>Moderation Log</h2>
                    <div class="section-actions">
                        <select onchange="adminController.filterModerationLog(this.value)">
                            <option value="">All Actions</option>
                            <option value="ban">Bans</option>
                            <option value="delete">Deletions</option>
                            <option value="edit">Edits</option>
                        </select>
                    </div>
                </div>
                <div class="moderation-log-detailed">
                    ${this.renderDetailedModerationLog(logs)}
                </div>
            </div>
        `;
    }

    renderDetailedModerationLog(logs) {
        if (!logs || logs.length === 0) {
            return '<div class="empty-state">No moderation actions found.</div>';
        }

        return `
            <div class="detailed-moderation-list">
                ${logs.map(log => {
                    const formatted = this.adminService.formatModerationAction(log);
                    return `
                        <div class="detailed-mod-entry severity-${formatted.severityLevel}">
                            <div class="mod-entry-header">
                                <div class="mod-info">
                                    <span class="moderator">${UIComponents.escapeHtml(formatted.moderator_name)}</span>
                                    <span class="action severity-${formatted.severityLevel}">${formatted.actionText}</span>
                                </div>
                                <span class="timestamp">${formatted.formattedDate}</span>
                            </div>
                            <div class="mod-entry-details">
                                <div class="target-info">Target: ${formatted.targetText}</div>
                                ${log.reason ? `<div class="reason-info">Reason: ${UIComponents.escapeHtml(log.reason)}</div>` : ''}
                            </div>
                        </div>
                    `;
                }).join('')}
            </div>
        `;
    }

    renderContentManagement() {
        return `
            <div class="content-management">
                <div class="section-header">
                    <h2>Content Management</h2>
                </div>
                <div class="content-tools-grid">
                    <div class="tool-card">
                        <div class="tool-icon">🗑️</div>
                        <div class="tool-info">
                            <h4>Bulk Delete</h4>
                            <p>Remove multiple posts or threads</p>
                            <button onclick="adminController.bulkContentAction('delete')" class="btn-danger">Start</button>
                        </div>
                    </div>
                    <div class="tool-card">
                        <div class="tool-icon">📊</div>
                        <div class="tool-info">
                            <h4>Content Analytics</h4>
                            <p>View detailed content statistics</p>
                            <button onclick="adminController.contentAnalytics()" class="btn-secondary">View</button>
                        </div>
                    </div>
                    <div class="tool-card">
                        <div class="tool-icon">🔍</div>
                        <div class="tool-info">
                            <h4>Content Search</h4>
                            <p>Search and filter all content</p>
                            <button onclick="adminController.showContentSearch()" class="btn-secondary">Search</button>
                        </div>
                    </div>
                </div>
                <div class="placeholder-message">
                    <p>Content management tools will be fully implemented in a future update.</p>
                </div>
            </div>
        `;
    }

    renderSystemSettings() {
        return `
            <div class="system-settings">
                <div class="section-header">
                    <h2>System Settings</h2>
                </div>
                <div class="settings-grid">
                    <div class="settings-section">
                        <div class="settings-header">
                            <h3>General Settings</h3>
                            <p>Configure basic forum settings</p>
                        </div>
                        <div class="settings-content">
                            <div class="setting-item">
                                <label>Forum Name</label>
                                <input type="text" value="Forum" readonly>
                            </div>
                            <div class="setting-item">
                                <label>Registration Enabled</label>
                                <input type="checkbox" checked disabled>
                            </div>
                        </div>
                    </div>
                    <div class="settings-section">
                        <div class="settings-header">
                            <h3>Security Settings</h3>
                            <p>Manage security and authentication</p>
                        </div>
                        <div class="settings-content">
                            <div class="setting-item">
                                <label>Require Email Verification</label>
                                <input type="checkbox" disabled>
                            </div>
                            <div class="setting-item">
                                <label>Max Login Attempts</label>
                                <input type="number" value="5" readonly>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="placeholder-message">
                    <p>System settings will be fully configurable in a future update.</p>
                </div>
            </div>
        `;
    }

    setupAdminInteractions() {
    }

    async refreshCurrentView() {
        await this.switchView(this.currentView);
    }

    handleQuickAction(actionId) {
        switch (actionId) {
            case 'view_users':
                this.switchView('users');
                break;
            case 'moderation_log':
                this.switchView('moderation');
                break;
            case 'view_reports':
                this.notifications.showInfo('Reports feature coming soon');
                break;
            case 'forum_stats':
                this.switchView('dashboard');
                break;
            case 'system_settings':
                this.switchView('settings');
                break;
            default:
                this.notifications.showInfo(`Quick action: ${actionId} - Feature coming soon`);
        }
    }

    showErrorState(message) {
        const content = document.getElementById('content');
        content.innerHTML = `
            <div class="error-state">
                <h3>Error Loading Admin Panel</h3>
                <p>${UIComponents.escapeHtml(message)}</p>
                <div class="error-actions">
                    <button onclick="location.reload()" class="btn-primary">Retry</button>
                    <button onclick="adminController.router.navigate('/')" class="btn-secondary">Return to Home</button>
                </div>
            </div>
        `;
    }

    bulkContentAction(action) {
        this.notifications.showInfo(`Bulk ${action} feature will be implemented soon`);
    }

    contentAnalytics() {
        this.notifications.showInfo('Content analytics feature will be implemented soon');
    }

    showContentSearch() {
        this.notifications.showInfo('Content search feature will be implemented soon');
    }

    filterModerationLog(filter) {
        this.notifications.showInfo(`Filtering by: ${filter || 'all actions'}`);
    }

    showUserFilters() {
        this.notifications.showInfo('Advanced user filters will be implemented soon');
    }

    destroy() {
    }
}