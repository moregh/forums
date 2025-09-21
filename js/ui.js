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
        
        document.body.appendChild(infoDiv);
        
        setTimeout(() => {
            if (infoDiv.parentNode) {
                infoDiv.parentNode.removeChild(infoDiv);
            }
        }, 3000);
    }

    static formatDate(timestamp) {
        if (!timestamp) return 'Never';
        const date = new Date(timestamp * 1000);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);

        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        if (diffDays < 7) return `${diffDays}d ago`;
        
        return date.toLocaleDateString();
    }

    static escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    static canEditPost(post, currentUser) {
        if (!currentUser) return false;
        return post.user_id === currentUser.user_id || currentUser.is_admin;
    }

    static canDeletePost(post, currentUser) {
        if (!currentUser) return false;
        return post.user_id === currentUser.user_id || currentUser.is_admin;
    }

    static canModerateThread(currentUser) {
        return currentUser && currentUser.is_admin;
    }

    static renderPagination(currentPage, totalPages, onPageChange) {
        if (totalPages <= 1) return '';

        let pagination = '<div class="pagination">';

        if (currentPage > 1) {
            pagination += `<button onclick="${onPageChange(currentPage - 1)}" class="pagination-btn">« Previous</button>`;
        }

        pagination += `<span class="pagination-info">Page ${currentPage}</span>`;

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

    static truncateText(text, maxLength = 100) {
        if (!text || text.length <= maxLength) return text;
        return text.substring(0, maxLength) + '...';
    }

    static createLoadingSpinner(size = 'medium') {
        const sizes = {
            small: '20px',
            medium: '40px',
            large: '60px'
        };
        
        const spinner = document.createElement('div');
        spinner.className = 'spinner';
        spinner.style.width = sizes[size] || sizes.medium;
        spinner.style.height = sizes[size] || sizes.medium;
        
        return spinner;
    }

    static formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    static debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    static copyToClipboard(text) {
        if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(() => {
                this.showSuccess('Copied to clipboard');
            }).catch(() => {
                this.fallbackCopyToClipboard(text);
            });
        } else {
            this.fallbackCopyToClipboard(text);
        }
    }

    static fallbackCopyToClipboard(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            document.execCommand('copy');
            this.showSuccess('Copied to clipboard');
        } catch (err) {
            this.showError('Failed to copy to clipboard');
        }
        
        document.body.removeChild(textArea);
    }

    static highlightText(text, searchTerm) {
        if (!searchTerm || !text) return text;
        const regex = new RegExp(`(${this.escapeRegex(searchTerm)})`, 'gi');
        return text.replace(regex, '<mark>$1</mark>');
    }

    static escapeRegex(string) {
        return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    static createConfirmDialog(message, onConfirm, onCancel = null) {
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-content">
                <h3>Confirm Action</h3>
                <p>${this.escapeHtml(message)}</p>
                <div class="modal-actions">
                    <button class="btn-secondary" data-action="cancel">Cancel</button>
                    <button class="btn-danger" data-action="confirm">Confirm</button>
                </div>
            </div>
        `;

        modal.addEventListener('click', (e) => {
            if (e.target === modal || e.target.dataset.action === 'cancel') {
                modal.remove();
                if (onCancel) onCancel();
            } else if (e.target.dataset.action === 'confirm') {
                modal.remove();
                onConfirm();
            }
        });

        document.body.appendChild(modal);
        return modal;
    }

    static smoothScrollTo(element, offset = 0) {
        const elementPosition = element.offsetTop;
        const offsetPosition = elementPosition - offset;

        window.scrollTo({
            top: offsetPosition,
            behavior: 'smooth'
        });
    }

    static isElementInViewport(element) {
        const rect = element.getBoundingClientRect();
        return (
            rect.top >= 0 &&
            rect.left >= 0 &&
            rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
            rect.right <= (window.innerWidth || document.documentElement.clientWidth)
        );
    }

    static getTimeAgo(timestamp) {
        const now = Date.now();
        const diff = now - (timestamp * 1000);
        const seconds = Math.floor(diff / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);
        const weeks = Math.floor(days / 7);
        const months = Math.floor(days / 30);
        const years = Math.floor(days / 365);

        if (years > 0) return `${years} year${years > 1 ? 's' : ''} ago`;
        if (months > 0) return `${months} month${months > 1 ? 's' : ''} ago`;
        if (weeks > 0) return `${weeks} week${weeks > 1 ? 's' : ''} ago`;
        if (days > 0) return `${days} day${days > 1 ? 's' : ''} ago`;
        if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
        if (minutes > 0) return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
        return 'Just now';
    }

    static pluralize(count, singular, plural = null) {
        if (count === 1) return `${count} ${singular}`;
        return `${count} ${plural || singular + 's'}`;
    }

    static sanitizeHtml(html) {
        const temp = document.createElement('div');
        temp.textContent = html;
        return temp.innerHTML;
    }

    static parseMarkdown(text) {
        return text
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/`(.*?)`/g, '<code>$1</code>')
            .replace(/\n/g, '<br>');
    }
}