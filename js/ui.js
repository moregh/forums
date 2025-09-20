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

    static canEditPost(post, currentUser) {
        if (!currentUser) return false;
        // Users can edit their own posts, admins can edit any post
        return post.user_id === currentUser.user_id || currentUser.is_admin;
    }

    static canDeletePost(post, currentUser) {
        if (!currentUser) return false;
        // Users can delete their own posts, admins can delete any post
        return post.user_id === currentUser.user_id || currentUser.is_admin;
    }

    static canModerateThread(currentUser) {
        return currentUser && currentUser.is_admin;
    }

    static renderPagination(currentPage, totalPages, onPageChange) {
        if (totalPages <= 1 && currentPage === 1) return '';
        
        let pagination = '<div class="pagination">';
        
        // Previous button
        if (currentPage > 1) {
            pagination += `<button onclick="${onPageChange(currentPage - 1)}" class="pagination-btn">« Previous</button>`;
        }
        
        // Current page indicator
        pagination += `<span class="pagination-info">Page ${currentPage}</span>`;
        
        // Next button - show if we think there might be more pages
        if (currentPage < totalPages) {
            pagination += `<button onclick="${onPageChange(currentPage + 1)}" class="pagination-btn">Next »</button>`;
        }
        
        pagination += '</div>';
        return pagination;
    }

    static renderBoards(boards) {
        if (!boards || boards.length === 0) {
            return '<div class="empty-state"><h3>No boards available</h3><p>No boards have been created yet.</p></div>';
        }
        
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

    static renderThreads(threads, currentUser) {
    if (!threads || threads.length === 0) {
        return '<div class="empty-state"><h3>No threads</h3><p>No threads have been created in this board yet.</p></div>';
    }
    
    return threads.map(thread => `
        <div class="thread-row ${thread.sticky ? 'sticky' : ''}" 
             onclick="forum.showThread(${thread.thread_id}); forum.router.navigate('/threads/${thread.thread_id}', false);">
            <div class="thread-info">
                <h4>${this.escapeHtml(thread.title)}</h4>
                <span class="thread-meta">
                    by ${this.escapeHtml(thread.username)} • 
                    ${this.formatDate(thread.timestamp)}
                    ${thread.sticky ? ' • <span class="sticky-badge">Sticky</span>' : ''}
                    ${thread.locked ? ' • <span class="locked-badge">Locked</span>' : ''}
                </span>
                ${this.canModerateThread(currentUser) ? `
                    <div class="thread-actions" onclick="event.stopPropagation()">
                        <button onclick="forum.toggleThreadSticky(${thread.thread_id}, ${!thread.sticky})" 
                                class="btn-small ${thread.sticky ? 'btn-warning' : 'btn-secondary'}">
                            ${thread.sticky ? 'Unsticky' : 'Sticky'}
                        </button>
                        <button onclick="forum.toggleThreadLock(${thread.thread_id}, ${!thread.locked})" 
                                class="btn-small ${thread.locked ? 'btn-success' : 'btn-warning'}">
                            ${thread.locked ? 'Unlock' : 'Lock'}
                        </button>
                        <button onclick="forum.deleteThread(${thread.thread_id})" 
                                class="btn-small btn-danger">Delete</button>
                    </div>
                ` : ''}
            </div>
            <div class="thread-stats">
                <span>${thread.reply_count || 0} replies</span>
                <span>${thread.view_count || 0} views</span>
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

    static renderPosts(posts, currentUser) {
        if (!posts || posts.length === 0) {
            return '<div class="empty-state"><h3>No posts</h3><p>No posts found in this thread.</p></div>';
        }
        
        return posts.map(post => `
            <div class="post" id="post-${post.post_id}">
                <div class="post-header">
                    <span class="post-author">${this.escapeHtml(post.username)}</span>
                    <span class="post-date">${this.formatDate(post.timestamp)}</span>
                    ${post.edited ? '<span class="edited-badge">Edited</span>' : ''}
                    ${currentUser ? `
                        <div class="post-actions">
                            ${this.canEditPost(post, currentUser) ? `
                                <button onclick="forum.editPost(${post.post_id})" class="btn-small btn-secondary">Edit</button>
                            ` : ''}
                            ${this.canDeletePost(post, currentUser) ? `
                                <button onclick="forum.deletePost(${post.post_id})" class="btn-small btn-danger">Delete</button>
                            ` : ''}
                        </div>
                    ` : ''}
                </div>
                <div class="post-content" id="post-content-${post.post_id}">
                    ${this.escapeHtml(post.content).replace(/\n/g, '<br>')}
                </div>
            </div>
        `).join('');
    }

    static renderAdminPanel(users) {
        return `
            <div class="admin-panel">
                <h3>User Management</h3>
                <div class="admin-users">
                    ${users.map(user => `
                        <div class="admin-user-row">
                            <span class="user-info">
                                ${this.escapeHtml(user.username)} 
                                ${user.is_admin ? '<span class="admin-badge">Admin</span>' : ''}
                                ${user.is_banned ? '<span class="banned-badge">Banned</span>' : ''}
                            </span>
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
            </div>
        `;
    }
}