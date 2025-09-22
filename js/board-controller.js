class BoardController {
    constructor(boardService, threadService, formHandler, notifications, modalManager, router, state) {
        this.boardService = boardService;
        this.threadService = threadService;
        this.formHandler = formHandler;
        this.notifications = notifications;
        this.modalManager = modalManager;
        this.router = router;
        this.state = state;
    }

    async showHome() {
        try {
            this.state.setState({ loading: true, error: null });
            
            const boards = await this.boardService.getBoards();
            const user = this.state.getState().user;
            
            const content = document.getElementById('content');
            content.innerHTML = this.renderHomePage(boards, user);
            
            this.state.setState({ boards, loading: false });

            this.setupBoardInteractions();

            // Ensure scroll happens after DOM updates
            setTimeout(() => {
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }, 0);
            
        } catch (error) {
            this.state.setState({ error: error.message, loading: false });
            this.showErrorState(error.message);
        }
    }

    async showBoard(boardId, page = 1) {
        try {
            this.state.setState({ loading: true, error: null });
            
            const [board, threads] = await Promise.all([
                this.boardService.getBoard(boardId),
                this.threadService.getThreads(boardId, page)
            ]);
            
            const user = this.state.getState().user;
            const totalThreads = board.thread_count || 25;
            const totalPages = Math.ceil(totalThreads / 20);

            const content = document.getElementById('content');
            content.innerHTML = this.renderBoardPage(board, threads, user, page, totalPages);

            this.state.setState({
                currentBoard: board,
                threads,
                currentPage: page,
                totalPages,
                loading: false
            });

            this.setupBoardInteractions();

            // Only scroll on initial load (page 1) to avoid pagination scroll conflicts
            if (page === 1) {
                setTimeout(() => {
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                }, 0);
            }

        } catch (error) {
            this.state.setState({ error: error.message, loading: false });
            this.showErrorState(error.message);
        }
    }

    renderHomePage(boards, user) {
        const formattedBoards = this.boardService.formatBoardsForDisplay(boards);
        const boardStats = this.boardService.getBoardStats(boards);
        
        return `
            <div class="page-header">
                <div>
                    <h1>Forum Boards</h1>
                    <div class="forum-stats">
                        <span>${boardStats.total} boards</span>
                        <span>${boardStats.totalThreads} threads</span>
                        <span>${boardStats.totalPosts} posts</span>
                    </div>
                </div>
                ${user?.is_admin ? `<button class="btn-primary" onclick="boardController.showCreateBoardForm()">Create Board</button>` : ''}
            </div>
            
            ${this.renderBoardFilters()}
            
            <div class="boards-list" id="boards-container">
                ${this.renderBoards(formattedBoards)}
            </div>
            
            ${boardStats.total === 0 ? this.renderEmptyBoardsState() : ''}
        `;
    }

    renderBoardPage(board, threads, user, page, totalPages) {
        const formattedThreads = this.threadService.formatThreadsForDisplay(threads);
        const breadcrumbs = this.boardService.getBoardBreadcrumbs(board);
        
        return `
            ${this.renderBreadcrumbs(breadcrumbs)}
            
            <div class="page-header">
                <div>
                    <h1>${UIComponents.escapeHtml(board.name)}</h1>
                    <p class="board-description">${UIComponents.escapeHtml(board.description)}</p>
                    <div class="board-stats">
                        <span>${board.thread_count} threads</span>
                        <span>${board.post_count} posts</span>
                    </div>
                </div>
                <div class="page-actions">
                    <button onclick="boardController.router.navigate('/')" class="btn-secondary">← Back to Forums</button>
                    ${user && !this.isThreadCreationDisabled(board) ? 
                        `<button onclick="boardController.showCreateThreadForm(${board.board_id})" class="btn-primary">New Thread</button>` : ''}
                </div>
            </div>
            
            ${this.renderThreadFilters(board.board_id)}
            
            <div class="threads-list">
                ${this.renderThreads(formattedThreads, user)}
            </div>
            
            ${totalPages > 1 ? this.renderPagination(page, totalPages, board.board_id) : ''}
            
            ${threads.length === 0 ? this.renderEmptyThreadsState(board, user) : ''}
        `;
    }

    renderBoards(boards) {
        if (!boards || boards.length === 0) {
            return this.renderEmptyBoardsState();
        }

        return boards.map(board => `
            <div class="board-card ${board.isEmpty ? 'board-empty' : ''}" onclick="boardController.showBoard(${board.board_id})">
                <div class="board-header">
                    <h3>${UIComponents.escapeHtml(board.name)}</h3>
                    <div class="board-activity ${board.activityLevel}"></div>
                </div>
                <p class="board-description">${UIComponents.escapeHtml(board.description)}</p>
                <div class="board-stats">
                    <span class="stat-item">
                        <strong>${board.thread_count}</strong>
                        <small>${board.threadText}</small>
                    </span>
                    <span class="stat-item">
                        <strong>${board.post_count}</strong>
                        <small>${board.postText}</small>
                    </span>
                    ${board.last_post_username ? `
                        <span class="stat-item last-post">
                            <small>Last: <span data-user-id="${board.last_post_user_id || ''}">${UIComponents.escapeHtml(board.last_post_username)}</span></small>
                            <small>${board.formattedLastPost}</small>
                        </span>
                    ` : '<span class="stat-item"><small>No recent activity</small></span>'}
                </div>
            </div>
        `).join('');
    }

    renderThreads(threads, user) {
        if (!threads || threads.length === 0) {
            return '';
        }

        return threads.map(thread => `
            <div class="thread-row ${thread.sticky ? 'sticky' : ''}" data-thread-id="${thread.thread_id}" onclick="boardController.navigateToThread(${thread.thread_id})">
                <div class="thread-info">
                    <h4>${UIComponents.escapeHtml(thread.title)}</h4>
                    <div class="thread-meta">
                        by <span class="thread-author" data-user-id="${thread.user_id}">${UIComponents.escapeHtml(thread.username)}</span> • ${thread.formattedDate}
                        ${thread.sticky ? ' • <span class="sticky-badge">Sticky</span>' : ''}
                        ${thread.locked ? ' • <span class="locked-badge">Locked</span>' : ''}
                    </div>
                    ${this.canUserModerateThread(user) ? this.renderThreadActions(thread) : ''}
                </div>
                <div class="thread-stats">
                    <div class="stat-group">
                        <span class="stat-number">${thread.reply_count}</span>
                        <span class="stat-label">replies</span>
                    </div>
                    <div class="stat-group">
                        <span class="stat-number">${thread.view_count}</span>
                        <span class="stat-label">views</span>
                    </div>
                    ${thread.last_post_username ? `
                        <div class="last-post">
                            <div class="last-post-user" data-user-id="${thread.last_post_user_id || ''}">${UIComponents.escapeHtml(thread.last_post_username)}</div>
                            <div class="last-post-time">${UIComponents.formatDate(thread.last_post_at)}</div>
                        </div>
                    ` : ''}
                </div>
            </div>
        `).join('');
    }

    renderThreadActions(thread) {
        return `
            <div class="thread-actions">
                <button onclick="event.stopPropagation(); boardController.toggleThreadSticky(${thread.thread_id}, ${!thread.sticky})" 
                        class="btn-small ${thread.sticky ? 'btn-warning' : 'btn-secondary'}">
                    ${thread.sticky ? 'Unsticky' : 'Sticky'}
                </button>
                <button onclick="event.stopPropagation(); boardController.toggleThreadLock(${thread.thread_id}, ${!thread.locked})" 
                        class="btn-small ${thread.locked ? 'btn-success' : 'btn-warning'}">
                    ${thread.locked ? 'Unlock' : 'Lock'}
                </button>
                <button onclick="event.stopPropagation(); boardController.deleteThread(${thread.thread_id})" 
                        class="btn-small btn-danger">Delete</button>
            </div>
        `;
    }

    renderBreadcrumbs(breadcrumbs) {
        return `
            <div class="breadcrumb-nav">
                ${breadcrumbs.map(crumb => 
                    crumb.current 
                        ? `<span class="breadcrumb-current">${UIComponents.escapeHtml(crumb.text)}</span>`
                        : `<a href="${crumb.url}" onclick="boardController.router.navigate('${crumb.url}'); return false;">${crumb.text}</a>`
                ).join('<span class="breadcrumb-separator">›</span>')}
            </div>
        `;
    }

    renderBoardFilters() {
        return `
            <div class="filter-controls">
                <div class="search-box">
                    <input type="text" id="board-search" placeholder="Search boards..." onkeyup="boardController.handleBoardSearch(this.value)">
                </div>
                <div class="sort-controls">
                    <select id="board-sort" onchange="boardController.handleBoardSort(this.value)">
                        <option value="name">Sort by Name</option>
                        <option value="activity">Sort by Activity</option>
                        <option value="threads">Sort by Threads</option>
                        <option value="posts">Sort by Posts</option>
                        <option value="last_activity">Sort by Recent Activity</option>
                    </select>
                </div>
            </div>
        `;
    }

    renderThreadFilters(boardId) {
        return `
            <div class="filter-controls">
                <div class="search-box">
                    <input type="text" id="thread-search" placeholder="Search threads..." onkeyup="boardController.handleThreadSearch(this.value, ${boardId})">
                </div>
                <div class="sort-controls">
                    <select id="thread-sort" onchange="boardController.handleThreadSort(this.value, ${boardId})">
                        <option value="default">Default Order</option>
                        <option value="newest">Newest First</option>
                        <option value="oldest">Oldest First</option>
                        <option value="most_replies">Most Replies</option>
                        <option value="most_views">Most Views</option>
                        <option value="last_activity">Recent Activity</option>
                    </select>
                </div>
            </div>
        `;
    }

    renderPagination(currentPage, totalPages, boardId) {
        const pagination = PaginationHelper.calculatePagination(currentPage, totalPages * 20, 20);
        const containerId = `pagination-board-${boardId}`;

        // Set up event delegation after render
        setTimeout(() => {
            PaginationHelper.setupEventDelegation(containerId, (page) => {
                this.showBoard(boardId, page);
            });
        }, 0);

        return PaginationHelper.renderPagination(pagination, containerId);
    }

    renderEmptyBoardsState() {
        return `
            <div class="empty-state">
                <h3>No boards available</h3>
                <p>No boards have been created yet. Check back later or contact an administrator.</p>
            </div>
        `;
    }

    renderEmptyThreadsState(board, user) {
        return `
            <div class="empty-state">
                <h3>No threads yet</h3>
                <p>Be the first to start a discussion in ${UIComponents.escapeHtml(board.name)}!</p>
                ${user ? `<button onclick="boardController.showCreateThreadForm(${board.board_id})" class="btn-primary">Create First Thread</button>` : ''}
            </div>
        `;
    }

    showCreateBoardForm() {
        this.modalManager.createFormModal(
            'Create New Board',
            `<input type="text" name="name" placeholder="Board Name" required maxlength="100">
             <textarea name="description" placeholder="Board Description" rows="4" required maxlength="1000"></textarea>`,
            async (formData) => {
                const board = await this.boardService.createBoard(formData.name, formData.description);
                await this.refreshBoards();
                this.router.navigate(`/boards/${board.board_id}`);
            },
            {
                validation: (data) => this.boardService.validateBoardData(data)
            }
        );
    }

    showCreateThreadForm(boardId) {
        this.modalManager.createFormModal(
            'Create New Thread',
            `<input type="text" name="title" placeholder="Thread Title" required maxlength="255">
             <textarea name="content" placeholder="Thread Content" rows="8" required></textarea>`,
            async (formData) => {
                const thread = await this.threadService.createThread(boardId, formData.title, formData.content);
                this.router.navigate(`/threads/${thread.thread_id}`);
            },
            {
                validation: (data) => this.threadService.validateThreadData(data)
            }
        );
    }

    async toggleThreadSticky(threadId, sticky) {
        try {
            await this.threadService.stickyThread(threadId, sticky);
            this.notifications.showSuccess(`Thread ${sticky ? 'stickied' : 'unstickied'} successfully!`);
            await this.refreshCurrentBoard();
        } catch (error) {
            this.notifications.showError(error.message);
        }
    }

    async toggleThreadLock(threadId, locked) {
        try {
            await this.threadService.lockThread(threadId, locked);
            this.notifications.showSuccess(`Thread ${locked ? 'locked' : 'unlocked'} successfully!`);
            await this.refreshCurrentBoard();
        } catch (error) {
            this.notifications.showError(error.message);
        }
    }

    async deleteThread(threadId) {
        this.modalManager.createConfirmationModal(
            'Delete Thread',
            'Are you sure you want to delete this thread? This action cannot be undone.',
            async () => {
                try {
                    await this.threadService.deleteThread(threadId);
                    this.notifications.showSuccess('Thread deleted successfully!');
                    await this.refreshCurrentBoard();
                } catch (error) {
                    this.notifications.showError(error.message);
                }
            },
            { confirmClass: 'btn-danger' }
        );
    }

    async handleBoardSearch(query) {
        if (query.length < 3 && query.length > 0) return;
        
        try {
            const boards = query.length === 0 
                ? await this.boardService.getBoards()
                : await this.boardService.searchBoards(query);
                
            const container = document.getElementById('boards-container');
            container.innerHTML = this.renderBoards(this.boardService.formatBoardsForDisplay(boards));
        } catch (error) {
            this.notifications.showError('Search failed: ' + error.message);
        }
    }

    async handleBoardSort(sortBy) {
        try {
            const boards = await this.boardService.getBoards();
            const sortedBoards = this.boardService.sortBoards(boards, sortBy);
            
            const container = document.getElementById('boards-container');
            container.innerHTML = this.renderBoards(this.boardService.formatBoardsForDisplay(sortedBoards));
        } catch (error) {
            this.notifications.showError('Sort failed: ' + error.message);
        }
    }

    async handleThreadSearch(query, boardId) {
        if (query.length < 3 && query.length > 0) return;
        
        try {
            const threads = query.length === 0
                ? await this.threadService.getThreads(boardId)
                : await this.threadService.searchThreads(boardId, query);
                
            this.updateThreadsList(threads);
        } catch (error) {
            this.notifications.showError('Search failed: ' + error.message);
        }
    }

    async handleThreadSort(sortBy, boardId) {
        try {
            const threads = await this.threadService.getThreads(boardId);
            const sortedThreads = this.threadService.sortThreads(threads, sortBy);
            this.updateThreadsList(sortedThreads);
        } catch (error) {
            this.notifications.showError('Sort failed: ' + error.message);
        }
    }

    updateThreadsList(threads) {
        const container = document.querySelector('.threads-list');
        const user = this.state.getState().user;
        container.innerHTML = this.renderThreads(this.threadService.formatThreadsForDisplay(threads), user);
    }

    async refreshBoards() {
        try {
            const boards = await this.boardService.getBoards(true);
            this.state.setState({ boards });
        } catch (error) {
            this.notifications.showError('Failed to refresh boards');
        }
    }

    async refreshCurrentBoard() {
        const currentBoard = this.state.getState().currentBoard;
        const currentPage = this.state.getState().currentPage || 1;
        
        if (currentBoard) {
            await this.showBoard(currentBoard.board_id, currentPage);
        }
    }

    showErrorState(message) {
        const content = document.getElementById('content');
        content.innerHTML = `
            <div class="error-state">
                <h3>Error Loading Content</h3>
                <p>${UIComponents.escapeHtml(message)}</p>
                <button onclick="location.reload()" class="btn-primary">Retry</button>
                <button onclick="boardController.router.navigate('/')" class="btn-secondary">Return to Home</button>
            </div>
        `;
    }

    canUserModerateThread(user) {
        return user && user.is_admin;
    }

    isThreadCreationDisabled(board) {
        return false;
    }

    navigateToThread(threadId, threadData = null) {
        this.router.navigate(`/threads/${threadId}`);
    }

    setupBoardInteractions() {
        // Set up thread row click handlers
        const threadRows = document.querySelectorAll('.thread-row');
        threadRows.forEach(row => {
            if (!row.hasAttribute('data-click-handler')) {
                row.style.cursor = 'pointer';
                row.setAttribute('data-click-handler', 'true');
            }
        });
    }

    destroy() {
        // Cleanup if needed
    }
}