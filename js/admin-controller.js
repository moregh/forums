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
            window.scrollTo({ top: 0, behavior: 'smooth' });

        } catch (error) {
            this.state.setState({ error: error.message, loading: false });
            this.showErrorState(error.message);
        }
    }

    renderAdminPanel(users, stats, moderationLog) {
        return `
            <div class="page-header">
                <h1>Admin Panel</h1>
                <div class="admin-nav">
                    ${this.renderAdminNavigation()}
                </div>
            </div>
            
            <div class="admin-content">
                <div class="admin-sidebar">
                    ${this.renderAdminSidebar()}
                </div>
                
                <div class="admin-main" id="admin-main-content">
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
            <button class="admin-nav-item ${this.currentView === item.id ? 'active' : ''}" 
                    onclick="adminController.switchView('${item.id}')">
                <span class="nav-icon">${item.icon}</span>
                <span class="nav-text">${item.text}</span>
            </button>
        `).join('');
    }

    renderAdminSidebar() {
        const quickActions = this.adminService.getQuickActions();
        
        return `
            <div class="sidebar-section">
                <h3>Quick Actions</h3>
                <div class="quick-actions">
                    ${quickActions.map(action => `
                        <button class="quick-action-btn" onclick="adminController.handleQuickAction('${action.id}')">
                            <span class="action-icon">${action.icon}</span>
                            <span class="action-text">${action.text}</span>
                        </button>
                    `).join('')}
                </div>
            </div>
            
            <div class="sidebar-section">
                <h3>System Status</h3>
                <div class="system-status">
                    <div class="status-item">
                        <span class="status-indicator online"></span>
                        <span>Forum Online</span>
                    </div>
                    <div class="status-item">
                        <span class="status-indicator"></span>
                        <span>All Systems Normal</span>
                    </div>
                </div>
            </div>
        `;
    }

    renderDashboard(users, stats, moderationLog) {
        return `
            <div class="dashboard-content">
                <div class="stats-overview">
                    ${this.renderStatsCards(stats)}
                </div>
                
                <div class="dashboard-grid">
                    <div class="dashboard-panel">
                        <h3>Recent User Activity</h3>
                        ${this.renderRecentUsers(users.slice(0, 10))}
                    </div>
                    
                    <div class="dashboard-panel">
                        <h3>Recent Moderation Actions</h3>
                        ${this.renderRecentModerationLog(moderationLog.slice(0, 10))}
                    </div>
                    
                    <div class="dashboard-panel">
                        <h3>System Overview</h3>
                        ${this.renderSystemOverview(stats)}
                    </div>
                </div>
            </div>
        `;
    }

    renderStatsCards(stats) {
        const cards = [
            { title: 'Total Users', value: stats.total_users || 0, icon: '👥', color: 'blue' },
            { title: 'Total Threads', value: stats.total_threads || 0, icon: '💬', color: 'green' },
            { title: 'Total Posts', value: stats.total_posts || 0, icon: '📝', color: 'purple' },
            { title: 'Users Online', value: stats.users_online || 0, icon: '🟢', color: 'orange' },
            { title: 'Posts Today', value: stats.posts_today || 0, icon: '📈', color: 'red' },
            { title: 'Total Boards', value: stats.total_boards || 0, icon: '📋', color: 'teal' }
        ];

        return `
            <div class="stats-grid">
                ${cards.map(card => `
                    <div class="stat-card ${card.color}">
                        <div class="stat-icon">${card.icon}</div>
                        <div class="stat-content">
                            <div class="stat-value">${card.value.toLocaleString()}</div>
                            <div class="stat-title">${card.title}</div>
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
            <div class="user-management">
                <div class="section-header">
                    <h2>User Management</h2>
                    <div class="section-actions">
                        <button onclick="adminController.showUserFilters()" class="btn-secondary">Filters</button>
                        <button onclick="adminController.exportUsers()" class="btn-secondary">Export</button>
                    </div>
                </div>
                
                <div class="user-stats-summary">
                    ${this.renderUserStatsCards(userStats)}
                </div>
                
                <div class="user-controls">
                    <div class="search-box">
                        <input type="text" id="user-search" placeholder="Search users..." 
                               onkeyup="adminController.handleUserSearch(this.value)">
                    </div>
                    <div class="filter-controls">
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
                
                <div class="user-list" id="user-list-container">
                    ${this.renderUserList(formattedUsers)}
                </div>
            </div>
        `;
    }

    renderUserList(users) {
        if (!users || users.length === 0) {
            return '<div class="empty-state"><p>No users found.</p></div>';
        }

        return `
            <div class="user-table">
                <div class="user-table-header">
                    <div class="col-user">User</div>
                    <div class="col-status">Status</div>
                    <div class="col-activity">Activity</div>
                    <div class="col-stats">Stats</div>
                    <div class="col-actions">Actions</div>
                </div>
                ${users.map(user => this.renderUserRow(user)).join('')}
            </div>
        `;
    }

    renderUserRow(user) {
        const currentUser = this.state.getState().user;
        
        return `
            <div class="user-row" data-user-id="${user.user_id}">
                <div class="col-user">
                    <div class="user-info">
                        <strong>${UIComponents.escapeHtml(user.username)}</strong>
                        <div class="user-email">${UIComponents.escapeHtml(user.email)}</div>
                        <div class="user-badges">
                            ${user.is_admin ? '<span class="badge admin">Admin</span>' : ''}
                            ${user.is_banned ? '<span class="badge banned">Banned</span>' : ''}
                            ${user.isNewUser ? '<span class="badge new">New</span>' : ''}
                        </div>
                    </div>
                </div>
                <div class="col-status">
                    <div class="activity-indicator ${user.activityLevel}"></div>
                    <span class="activity-text">${user.activityLevel.replace('-', ' ')}</span>
                </div>
                <div class="col-activity">
                    <div class="activity-info">
                        <div>Joined: ${user.formattedJoinDate}</div>
                        <div>Last seen: ${user.formattedLastActivity}</div>
                        <div>Member for: ${user.membershipDuration}</div>
                    </div>
                </div>
                <div class="col-stats">
                    <div class="user-stats">
                        <div>${user.post_count || 0} posts</div>
                        <div>${user.thread_count || 0} threads</div>
                    </div>
                </div>
                <div class="col-actions">
                    ${this.renderUserActions(user, currentUser)}
                </div>
            </div>
        `;
    }

    renderUserActions(user, currentUser) {
        const actions = [];
        
        if (!user.is_banned) {
            const banAction = this.adminService.canPerformAction('ban', user, currentUser);
            if (banAction.allowed) {
                actions.push(`<button onclick="adminController.banUser(${user.user_id})" class="btn-small btn-danger">Ban</button>`);
            }
        } else {
            const unbanAction = this.adminService.canPerformAction('unban', user, currentUser);
            if (unbanAction.allowed) {
                actions.push(`<button onclick="adminController.unbanUser(${user.user_id})" class="btn-small btn-success">Unban</button>`);
            }
        }

        if (!user.is_admin) {
            const promoteAction = this.adminService.canPerformAction('promote', user, currentUser);
            if (promoteAction.allowed) {
                actions.push(`<button onclick="adminController.promoteUser(${user.user_id})" class="btn-small btn-warning">Make Admin</button>`);
            }
        } else {
            const demoteAction = this.adminService.canPerformAction('demote', user, currentUser);
            if (demoteAction.allowed) {
                actions.push(`<button onclick="adminController.demoteUser(${user.user_id})" class="btn-small btn-secondary">Remove Admin</button>`);
            }
        }

        return `<div class="user-actions">${actions.join('')}</div>`;
    }

    renderUserStatsCards(stats) {
        const cards = [
            { title: 'Total Users', value: stats.total, color: 'blue' },
            { title: 'Active Users', value: stats.active, color: 'green' },
            { title: 'Admins', value: stats.admins, color: 'purple' },
            { title: 'Banned Users', value: stats.banned, color: 'red' },
            { title: 'New Users', value: stats.newUsers, color: 'orange' }
        ];

        return cards.map(card => `
            <div class="mini-stat-card ${card.color}">
                <div class="mini-stat-value">${card.value}</div>
                <div class="mini-stat-title">${card.title}</div>
            </div>
        `).join('');
    }

    renderRecentUsers(users) {
        if (!users || users.length === 0) {
            return '<p>No recent user activity.</p>';
        }

        return `
            <div class="recent-users">
                ${users.map(user => `
                    <div class="recent-user-item">
                        <div class="user-avatar">${user.username.charAt(0).toUpperCase()}</div>
                        <div class="user-details">
                            <strong>${UIComponents.escapeHtml(user.username)}</strong>
                            <div class="user-meta">Last active: ${UIComponents.formatDate(user.last_activity)}</div>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    renderRecentModerationLog(logs) {
        if (!logs || logs.length === 0) {
            return '<p>No recent moderation actions.</p>';
        }

        return `
            <div class="moderation-entries">
                ${logs.map(log => {
                    const formatted = this.adminService.formatModerationAction(log);
                    return `
                        <div class="moderation-entry severity-${formatted.severityLevel}">
                            <div class="mod-header">
                                <strong>${UIComponents.escapeHtml(formatted.moderator_name || 'Unknown')}</strong>
                                <span class="action-badge ${formatted.severityLevel}">${formatted.actionText}</span>
                                <span class="mod-date">${formatted.formattedDate}</span>
                            </div>
                            <div class="mod-details">
                                ${formatted.targetText}
                                ${log.reason ? `<br><em>Reason: ${UIComponents.escapeHtml(log.reason)}</em>` : ''}
                            </div>
                        </div>
                    `;
                }).join('')}
            </div>
        `;
    }

    renderSystemOverview(stats) {
        return `
            <div class="system-overview">
                <div class="overview-item">
                    <span class="overview-label">Average Posts per User:</span>
                    <span class="overview-value">${Math.round((stats.total_posts || 0) / Math.max(1, stats.total_users || 1))}</span>
                </div>
                <div class="overview-item">
                    <span class="overview-label">Average Threads per User:</span>
                    <span class="overview-value">${Math.round((stats.total_threads || 0) / Math.max(1, stats.total_users || 1))}</span>
                </div>
                <div class="overview-item">
                    <span class="overview-label">Top Poster:</span>
                    <span class="overview-value">${stats.top_posters?.[0]?.username || 'N/A'}</span>
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
        document.querySelectorAll('.admin-nav-item').forEach(item => {
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
                <strong>Warning:</strong> This will immediately ban the user and prevent them from accessing the forum.
             </div>`,
            async (formData) => {
                await this.adminService.banUser(userId, formData.reason);
                this.notifications.showSuccess('User banned successfully!');
                await this.refreshCurrentView();
            },
            {
                validation: (data) => this.adminService.validateBanReason ? 
                    { isValid: true, errors: {} } : 
                    Validation.validateForm(data, { reason: 'banReason' }),
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
            container.innerHTML = this.renderUserList(this.adminService.formatUsersForDisplay(users));
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
            container.innerHTML = this.renderUserList(this.adminService.formatUsersForDisplay(sortedUsers));
        } catch (error) {
            this.notifications.showError('Sort failed: ' + error.message);
        }
    }

    async applyFilters() {
        try {
            const users = await this.adminService.getUsers(1, 100);
            const filteredUsers = this.adminService.filterUsers(users, this.currentFilters);
            
            const container = document.getElementById('user-list-container');
            container.innerHTML = this.renderUserList(this.adminService.formatUsersForDisplay(filteredUsers));
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
            <div class="moderation-view">
                <h2>Moderation Log</h2>
                <div class="moderation-controls">
                    <select onchange="adminController.filterModerationLog(this.value)">
                        <option value="">All Actions</option>
                        <option value="ban">Bans</option>
                        <option value="delete">Deletions</option>
                        <option value="edit">Edits</option>
                    </select>
                </div>
                <div class="moderation-log-detailed">
                    ${this.renderDetailedModerationLog(logs)}
                </div>
            </div>
        `;
    }

    renderDetailedModerationLog(logs) {
        return logs.map(log => {
            const formatted = this.adminService.formatModerationAction(log);
            return `
                <div class="detailed-mod-entry">
                    <div class="mod-entry-header">
                        <span class="moderator">${UIComponents.escapeHtml(formatted.moderator_name)}</span>
                        <span class="action ${formatted.severityLevel}">${formatted.actionText}</span>
                        <span class="timestamp">${formatted.formattedDate}</span>
                    </div>
                    <div class="mod-entry-details">
                        <div>Target: ${formatted.targetText}</div>
                        ${log.reason ? `<div>Reason: ${UIComponents.escapeHtml(log.reason)}</div>` : ''}
                    </div>
                </div>
            `;
        }).join('');
    }

    renderContentManagement() {
        return `
            <div class="content-management">
                <h2>Content Management</h2>
                <div class="content-tools">
                    <button onclick="adminController.bulkContentAction('delete')" class="btn-danger">Bulk Delete</button>
                    <button onclick="adminController.contentAnalytics()" class="btn-secondary">Analytics</button>
                </div>
                <p>Content management tools will be implemented here.</p>
            </div>
        `;
    }

    renderSystemSettings() {
        return `
            <div class="system-settings">
                <h2>System Settings</h2>
                <div class="settings-sections">
                    <div class="settings-section">
                        <h3>General Settings</h3>
                        <p>General forum configuration options.</p>
                    </div>
                    <div class="settings-section">
                        <h3>Security Settings</h3>
                        <p>Security and authentication configuration.</p>
                    </div>
                </div>
            </div>
        `;
    }

    setupAdminInteractions() {
        // Additional setup for admin-specific interactions
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
            default:
                this.notifications.showInfo(`Quick action: ${actionId}`);
        }
    }

    showErrorState(message) {
        const content = document.getElementById('content');
        content.innerHTML = `
            <div class="error-state">
                <h3>Error Loading Admin Panel</h3>
                <p>${UIComponents.escapeHtml(message)}</p>
                <button onclick="location.reload()" class="btn-primary">Retry</button>
                <button onclick="adminController.router.navigate('/')" class="btn-secondary">Return to Home</button>
            </div>
        `;
    }

    destroy() {
        // Cleanup if needed
    }
}