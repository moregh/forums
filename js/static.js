// static.js
const Templates = {
    navigationLoggedIn: (user) => `
        <div class="nav-left">
            <a href="/" onclick="forum.router.navigate('/'); return false;">Forum Home</a>
            ${user.is_admin ? `
                <a href="/admin" onclick="forum.router.navigate('/admin'); return false;">Admin Panel</a>
            ` : ''}
        </div>
        <div class="nav-right">
            <span>Welcome, ${UIComponents.escapeHtml(user.username)}</span>
            <button onclick="forum.logout()">Logout</button>
        </div>
    `,

    navigationLoggedOut: () => `
        <div class="nav-left">
            <a href="/" onclick="forum.router.navigate('/'); return false;">Forum Home</a>
        </div>
        <div class="nav-right">
            <a href="/login" onclick="forum.router.navigate('/login'); return false;">Login</a>
            <a href="/register" onclick="forum.router.navigate('/register'); return false;">Register</a>
        </div>
    `,

    home: (boards, user) => `
        <div class="page-header">
            <h1>Forum Boards</h1>
            ${user?.is_admin ? `<button class="btn-primary" onclick="forum.showCreateBoardForm()">Create Board</button>` : ''}
        </div>
        <div class="boards-list">
            ${UIComponents.renderBoards(boards)}
        </div>
    `,

    login: () => `
        <div class="auth-form">
            <h2>Login</h2>
            <form onsubmit="forum.handleLogin(event)">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            <p><a href="/register" onclick="forum.router.navigate('/register'); return false;">Need an account? Register here</a></p>
        </div>
    `,

    register: () => `
        <div class="auth-form">
            <h2>Register</h2>
            <form onsubmit="forum.handleRegister(event)">
                <input type="text" name="username" placeholder="Username" required>
                <input type="email" name="email" placeholder="Email" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Register</button>
            </form>
            <p><a href="/login" onclick="forum.router.navigate('/login'); return false;">Already have an account? Login here</a></p>
        </div>
    `,

    admin: () => `
        <div class="page-header">
            <h1>Admin Panel</h1>
        </div>
        <div class="admin-content">
            <p>Admin functionality would be implemented here.</p>
            <p>This would include user management, moderation tools, etc.</p>
        </div>
    `,

    board: (board, threads, currentUser, page, totalPages) => `
        <div class="page-header">
            <h1>${board ? UIComponents.escapeHtml(board.name) : 'Board'}</h1>
            ${currentUser ? `<button class="btn-primary" onclick="forum.showCreateThreadForm(${board.board_id})">New Thread</button>` : ''}
        </div>
        <div class="threads-list">
            ${UIComponents.renderThreads(threads, currentUser)}
        </div>
        ${UIComponents.renderPagination(page, totalPages, (newPage) =>
            `forum.showBoard(${board.board_id}, ${newPage})`
        )}
    `,

    thread: (threadInfo, posts, currentUser, page, totalPages) => {
        // Ensure we have valid data
        if (!threadInfo || !Array.isArray(posts)) {
            console.error('Invalid thread data:', { threadInfo, posts });
            return `
                <div class="error-state">
                    <h3>Error Loading Thread</h3>
                    <p>Invalid thread data received from server.</p>
                    <button onclick="forum.router.navigate('/')">Return to Home</button>
                </div>
            `;
        }

        try {
            const safeThreadInfo = {
                thread_id: parseInt(threadInfo.thread_id) || 0,
                title: threadInfo.title || 'Unknown Thread',
                locked: Boolean(threadInfo.locked),
                sticky: Boolean(threadInfo.sticky),
                reply_count: threadInfo.reply_count || 0,
                view_count: threadInfo.view_count || 0,
                user_id: threadInfo.user_id || threadInfo.author_id || 0,
                username: threadInfo.username || threadInfo.author_name || 'Unknown',
                timestamp: threadInfo.timestamp || threadInfo.created_at || Date.now() / 1000,
                board_id: threadInfo.board_id || 0,
                board_name: threadInfo.board_name || 'Unknown Board'
            };

            const threadHTML = `
                <div class="breadcrumb-nav">
                    <a href="/" onclick="forum.router.navigate('/'); return false;">📋 Forum</a>
                    <span class="breadcrumb-separator">›</span>
                    <a href="/boards/${safeThreadInfo.board_id}" onclick="forum.router.navigate('/boards/${safeThreadInfo.board_id}'); return false;">${UIComponents.escapeHtml(safeThreadInfo.board_name)}</a>
                    <span class="breadcrumb-separator">›</span>
                    <span class="breadcrumb-current">${UIComponents.escapeHtml(safeThreadInfo.title)}</span>
                </div>
                <div class="page-header">
                    <div>
                        <h1>${UIComponents.escapeHtml(safeThreadInfo.title)}</h1>
                        <div class="thread-meta">
                            <span>by ${UIComponents.escapeHtml(safeThreadInfo.username)} • ${UIComponents.formatDate(safeThreadInfo.timestamp)}</span>
                            ${safeThreadInfo.sticky ? ' • <span class="sticky-badge">Sticky</span>' : ''}
                            ${safeThreadInfo.locked ? ' • <span class="locked-badge">Locked</span>' : ''}
                            <span> • ${safeThreadInfo.reply_count} replies • ${safeThreadInfo.view_count} views</span>
                        </div>
                    </div>
                    <div class="page-actions">
                        <button onclick="forum.router.navigate('/boards/${safeThreadInfo.board_id}')" class="btn-secondary">
                            ← Back to ${UIComponents.escapeHtml(safeThreadInfo.board_name)}
                        </button>
                        ${currentUser && !safeThreadInfo.locked ? `<button onclick="forum.showReplyForm(${safeThreadInfo.thread_id})" class="btn-primary">Reply</button>` : ''}
                        ${UIComponents.canModerateThread(currentUser) ? `
                            <div class="admin-actions">
                                <button onclick="forum.toggleThreadLock(${safeThreadInfo.thread_id}, ${!safeThreadInfo.locked})" 
                                        class="btn-small ${safeThreadInfo.locked ? 'btn-success' : 'btn-warning'}">
                                    ${safeThreadInfo.locked ? 'Unlock' : 'Lock'}
                                </button>
                                <button onclick="forum.toggleThreadSticky(${safeThreadInfo.thread_id}, ${!safeThreadInfo.sticky})" 
                                        class="btn-small ${safeThreadInfo.sticky ? 'btn-warning' : 'btn-secondary'}">
                                    ${safeThreadInfo.sticky ? 'Unsticky' : 'Sticky'}
                                </button>
                                <button onclick="forum.deleteThread(${safeThreadInfo.thread_id})" class="btn-small btn-danger">Delete</button>
                            </div>
                        ` : ''}
                    </div>
                </div>
                <div class="posts-list">
                    ${UIComponents.renderPosts(posts, currentUser)}
                </div>
                ${totalPages > 1 ? UIComponents.renderPagination(page, totalPages, (newPage) =>
                    `forum.showThread(${safeThreadInfo.thread_id}, ${newPage})`
                ) : ''}
            `;

            return threadHTML;
        } catch (error) {
            console.error('Error rendering thread template:', error);
            return `
                <div class="error-state">
                    <h3>Template Error</h3>
                    <p>Failed to render thread. Please try refreshing the page.</p>
                    <button onclick="forum.router.navigate('/')">Return to Home</button>
                </div>
            `;
        }
    },

    modals: {
        createBoard: () => `
            <h3>Create New Board</h3>
            <form onsubmit="forum.handleCreateBoard(event)">
                <input type="text" name="name" placeholder="Board Name" required>
                <textarea name="description" placeholder="Board Description" rows="4" required></textarea>
                <button type="submit">Create Board</button>
            </form>
        `,
        createThread: (boardId) => `
            <h3>Create New Thread</h3>
            <form onsubmit="forum.handleCreateThread(event, ${boardId})">
                <input type="text" name="title" placeholder="Thread Title" required>
                <textarea name="content" placeholder="Thread Content" rows="6" required></textarea>
                <button type="submit">Create Thread</button>
            </form>
        `,
        reply: (threadId) => `
            <h3>Reply to Thread</h3>
            <form onsubmit="forum.handleCreatePost(event, ${threadId})">
                <textarea name="content" placeholder="Your Reply" rows="6" required></textarea>
                <button type="submit">Post Reply</button>
            </form>
        `,
        editPost: (post, postId) => `
            <h3>Edit Post</h3>
            <form onsubmit="forum.handleEditPost(event, ${postId})">
                <textarea name="content" rows="6" required>${UIComponents.escapeHtml(post.content)}</textarea>
                <button type="submit">Update Post</button>
            </form>
        `,
        postHistory: (history, postId) => `
            <h3>Post Edit History</h3>
            <div class="post-history">
                ${history.length === 0 ? '<p>No edit history available.</p>' : 
                    history.map(edit => `
                        <div class="history-item">
                            <div class="history-header">
                                <strong>Edited by ${UIComponents.escapeHtml(edit.editor_name)}</strong>
                                <span class="history-date">${UIComponents.formatDate(edit.timestamp)}</span>
                            </div>
                            <div class="history-content">
                                <h4>Previous content:</h4>
                                <div class="history-old-content">${UIComponents.escapeHtml(edit.old_content).replace(/\n/g, '<br>')}</div>
                                <h4>Updated to:</h4>
                                <div class="history-new-content">${UIComponents.escapeHtml(edit.new_content).replace(/\n/g, '<br>')}</div>
                            </div>
                        </div>
                    `).join('')
                }
            </div>
        `
    }
};