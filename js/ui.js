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

    static showInfo(message) {
        const infoDiv = document.createElement('div');
        infoDiv.className = 'info-message';
        infoDiv.textContent = message;
        infoDiv.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #2e71bdff;
            color: white;
            padding: 15px;
            border-radius: 5px;
            z-index: 1000;
            max-width: 300px;
        `;
        setTimeout(() => {
            if (infoDiv.parentNode) {
                infoDiv.parentNode.removeChild(infoDiv);
            }
        }, 3000);
    }

    static formatDate(timestamp) {
        return new Date(timestamp * 1000).toLocaleString();
    }

    static escapeHtml(text) {
        if (!text) return '';
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
        if (totalPages <= 1) return '';
        
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

    static renderThreads(threads, currentUser) {
        if (!threads || threads.length === 0) {
            return '<div class="empty-state"><h3>No threads</h3><p>No threads have been created in this board yet.</p></div>';
        }
        
        return threads.map(thread => {
            const safeThread = {
                thread_id: thread.thread_id,
                title: thread.title || 'Untitled Thread',
                username: thread.username || thread.author_name || 'Unknown',
                timestamp: thread.timestamp || thread.created_at || 0,
                sticky: Boolean(thread.sticky),
                locked: Boolean(thread.locked),
                reply_count: thread.reply_count || 0,
                view_count: thread.view_count || 0,
                last_post_username: thread.last_post_username || null,
                last_post_at: thread.last_post_at || null,
                user_id: thread.user_id || thread.author_id || 0
            };
            
            return `
                <div class="thread-row ${safeThread.sticky ? 'sticky' : ''}" 
                     data-thread-id="${safeThread.thread_id}">
                    <div class="thread-info">
                        <h4>${UIComponents.escapeHtml(safeThread.title)}</h4>
                        <span class="thread-meta">
                            by ${UIComponents.escapeHtml(safeThread.username)} • 
                            ${UIComponents.formatDate(safeThread.timestamp)}
                            ${safeThread.sticky ? ' • <span class="sticky-badge">Sticky</span>' : ''}
                            ${safeThread.locked ? ' • <span class="locked-badge">Locked</span>' : ''}
                        </span>
                        ${UIComponents.canModerateThread(currentUser) ? `
                            <div class="thread-actions">
                                <button onclick="event.stopPropagation(); forum.toggleThreadSticky(${safeThread.thread_id}, ${!safeThread.sticky})" 
                                        class="btn-small ${safeThread.sticky ? 'btn-warning' : 'btn-secondary'}">
                                    ${safeThread.sticky ? 'Unsticky' : 'Sticky'}
                                </button>
                                <button onclick="event.stopPropagation(); forum.toggleThreadLock(${safeThread.thread_id}, ${!safeThread.locked})" 
                                        class="btn-small ${safeThread.locked ? 'btn-success' : 'btn-warning'}">
                                    ${safeThread.locked ? 'Unlock' : 'Lock'}
                                </button>
                                <button onclick="event.stopPropagation(); forum.deleteThread(${safeThread.thread_id})" 
                                        class="btn-small btn-danger">Delete</button>
                            </div>
                        ` : ''}
                    </div>
                    <div class="thread-stats">
                        <span>${safeThread.reply_count} replies</span>
                        <span>${safeThread.view_count} views</span>
                        ${safeThread.last_post_username ? `
                            <div class="last-post">
                                Last: ${UIComponents.escapeHtml(safeThread.last_post_username)}<br>
                                ${UIComponents.formatDate(safeThread.last_post_at)}
                            </div>
                        ` : ''}
                    </div>
                </div>
            `;
        }).join('');
    }
    
    static renderBoards(boards) {
    if (!boards || boards.length === 0) {
        return '<div class="empty-state"><h3>No boards available</h3><p>No boards have been created yet.</p></div>';
    }
    
    return boards.map(board => `
        <div class="board-card" onclick="forum.router.navigate('/boards/${board.board_id}')">
            <h3>${UIComponents.escapeHtml(board.name)}</h3>
            <p>${UIComponents.escapeHtml(board.description)}</p>
            <div class="board-stats">
                <span>${board.thread_count} threads</span>
                <span>${board.post_count} posts</span>
                ${board.last_post_username ? `
                    <span>Last: ${UIComponents.escapeHtml(board.last_post_username)}</span>
                ` : ''}
            </div>
        </div>
    `).join('');
}
    static renderPosts(posts, currentUser) {
        if (!posts || posts.length === 0) {
            return '<div class="empty-state"><h3>No posts</h3><p>No posts found in this thread.</p></div>';
        }
        
        return posts.map(post => {
            // Ensure we have all required post properties with safe defaults
            const safePost = {
                post_id: post.post_id,
                user_id: post.user_id,
                username: post.username || 'Unknown',
                content: post.content || '',
                timestamp: post.timestamp || 0,
                edited: post.edited || false
            };
            
            return `
                <div class="post" id="post-${safePost.post_id}">
                    <div class="post-header">
                        <span class="post-author">${this.escapeHtml(safePost.username)}</span>
                        <span class="post-date">${this.formatDate(safePost.timestamp)}</span>
                        ${safePost.edited ? '<span class="edited-badge">Edited</span>' : ''}
                        ${currentUser ? `
                            <div class="post-actions">
                                ${this.canEditPost(safePost, currentUser) ? `
                                    <button onclick="forum.editPost(${safePost.post_id})" class="btn-small btn-secondary">Edit</button>
                                ` : ''}
                                ${this.canDeletePost(safePost, currentUser) ? `
                                    <button onclick="forum.deletePost(${safePost.post_id})" class="btn-small btn-danger">Delete</button>
                                ` : ''}
                            </div>
                        ` : ''}
                    </div>
                    <div class="post-content" id="post-content-${safePost.post_id}">
                        ${this.escapeHtml(safePost.content).replace(/\n/g, '<br>')}
                    </div>
                </div>
            `;
        }).join('');
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