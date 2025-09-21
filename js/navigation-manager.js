class NavigationManager {
    constructor(router, state, notifications) {
        this.router = router;
        this.state = state;
        this.notifications = notifications;
        this.navigationLock = false;
        this.tempThreadData = null;
        this.setupEventDelegation();
        this.setupKeyboardShortcuts();
    }

    async navigateToThread(threadId, threadData = null) {
        if (this.navigationLock) return;

        this.navigationLock = true;

        try {
            if (threadData) {
                this.tempThreadData = threadData;
            }

            this.router.navigate(`/threads/${threadId}`, true);

        } catch (error) {
            this.notifications.showError(`Navigation error: ${error.message}`);
            console.error('Navigation error:', error);
        } finally {
            setTimeout(() => {
                this.navigationLock = false;
            }, 250);
        }
    }

    navigateToBoard(boardId) {
        this.router.navigate(`/boards/${boardId}`);
    }

    navigateToHome() {
        this.router.navigate('/');
    }

    navigateToLogin(redirectPath = null) {
        const loginUrl = redirectPath 
            ? `/login?redirect=${encodeURIComponent(redirectPath)}`
            : '/login';
        this.router.navigate(loginUrl);
    }

    navigateToRegister() {
        this.router.navigate('/register');
    }

    navigateToAdmin() {
        const user = this.state.getState().user;
        if (!user || !user.is_admin) {
            this.notifications.showError('Admin privileges required');
            this.navigateToHome();
            return;
        }
        this.router.navigate('/admin');
    }

    setupEventDelegation() {
        document.addEventListener('click', (e) => {
            this.handleThreadNavigation(e);
            this.handleBoardNavigation(e);
            this.handleGeneralNavigation(e);
        });
    }

    handleThreadNavigation(e) {
        const threadRow = e.target.closest('.thread-row[data-thread-id]');
        if (threadRow && !e.target.closest('.thread-actions')) {
            e.preventDefault();
            e.stopPropagation();

            const threadId = threadRow.dataset.threadId;
            if (threadId && !this.navigationLock) {
                this.navigateToThread(parseInt(threadId), null);
            }
        }
    }

    handleBoardNavigation(e) {
        const boardCard = e.target.closest('.board-card[onclick]');
        if (boardCard) {
            e.preventDefault();
            e.stopPropagation();

            const onclickAttr = boardCard.getAttribute('onclick');
            const boardIdMatch = onclickAttr.match(/showBoard\((\d+)\)/);
            if (boardIdMatch) {
                const boardId = parseInt(boardIdMatch[1]);
                this.navigateToBoard(boardId);
            }
        }
    }

    handleGeneralNavigation(e) {
        const link = e.target.closest('a[href]');
        if (link && this.isInternalLink(link.href)) {
            const preventDefault = link.getAttribute('onclick')?.includes('return false');
            if (preventDefault) {
                e.preventDefault();
                const url = new URL(link.href);
                this.router.navigate(url.pathname + url.search + url.hash);
            }
        }
    }

    isInternalLink(href) {
        try {
            const url = new URL(href);
            return url.origin === window.location.origin;
        } catch {
            return href.startsWith('/');
        }
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
                return;
            }

            const { ctrlKey, metaKey, altKey, key } = e;
            const modKey = ctrlKey || metaKey;

            if (altKey && key === 'h') {
                e.preventDefault();
                this.navigateToHome();
            }

            if (altKey && key === 'l' && !this.state.getState().user) {
                e.preventDefault();
                this.navigateToLogin();
            }

            if (altKey && key === 'a' && this.state.getState().user?.is_admin) {
                e.preventDefault();
                this.navigateToAdmin();
            }

            if (modKey && key === 'k') {
                e.preventDefault();
                this.showQuickNavigation();
            }

            if (key === 'Escape') {
                this.closeActiveModals();
            }

            if (key === 'ArrowUp' && modKey) {
                e.preventDefault();
                this.navigateToParent();
            }

            if (key === 'ArrowLeft' && modKey) {
                e.preventDefault();
                this.navigateBack();
            }

            if (key === 'ArrowRight' && modKey) {
                e.preventDefault();
                this.navigateForward();
            }
        });
    }

    showQuickNavigation() {
        const user = this.state.getState().user;
        const boards = this.state.getState().boards || [];
        
        const quickNavItems = [
            { text: '🏠 Home', action: () => this.navigateToHome() },
            ...boards.slice(0, 10).map(board => ({
                text: `📋 ${board.name}`,
                action: () => this.navigateToBoard(board.board_id)
            }))
        ];

        if (user?.is_admin) {
            quickNavItems.push({ text: '⚙️ Admin Panel', action: () => this.navigateToAdmin() });
        }

        if (!user) {
            quickNavItems.push(
                { text: '🔑 Login', action: () => this.navigateToLogin() },
                { text: '📝 Register', action: () => this.navigateToRegister() }
            );
        }

        this.showQuickNavModal(quickNavItems);
    }

    showQuickNavModal(items) {
        const modal = document.createElement('div');
        modal.className = 'quick-nav-modal';
        modal.innerHTML = `
            <div class="quick-nav-content">
                <div class="quick-nav-header">
                    <h3>Quick Navigation</h3>
                    <span class="quick-nav-close">&times;</span>
                </div>
                <div class="quick-nav-search">
                    <input type="text" placeholder="Search..." id="quick-nav-search">
                </div>
                <div class="quick-nav-items" id="quick-nav-items">
                    ${items.map((item, index) => `
                        <div class="quick-nav-item" data-index="${index}">
                            ${item.text}
                        </div>
                    `).join('')}
                </div>
                <div class="quick-nav-help">
                    Use ↑↓ arrows to navigate, Enter to select, Esc to close
                </div>
            </div>
        `;

        let selectedIndex = 0;
        const selectItem = (index) => {
            modal.querySelectorAll('.quick-nav-item').forEach((item, i) => {
                item.classList.toggle('selected', i === index);
            });
            selectedIndex = index;
        };

        const executeAction = () => {
            if (items[selectedIndex]) {
                items[selectedIndex].action();
                modal.remove();
            }
        };

        modal.addEventListener('click', (e) => {
            if (e.target === modal || e.target.classList.contains('quick-nav-close')) {
                modal.remove();
            }
            
            const item = e.target.closest('.quick-nav-item');
            if (item) {
                const index = parseInt(item.dataset.index);
                executeAction(index);
            }
        });

        modal.addEventListener('keydown', (e) => {
            switch (e.key) {
                case 'ArrowUp':
                    e.preventDefault();
                    selectItem(Math.max(0, selectedIndex - 1));
                    break;
                case 'ArrowDown':
                    e.preventDefault();
                    selectItem(Math.min(items.length - 1, selectedIndex + 1));
                    break;
                case 'Enter':
                    e.preventDefault();
                    executeAction();
                    break;
                case 'Escape':
                    e.preventDefault();
                    modal.remove();
                    break;
            }
        });

        const searchInput = modal.querySelector('#quick-nav-search');
        searchInput.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            const itemElements = modal.querySelectorAll('.quick-nav-item');
            
            itemElements.forEach((element, index) => {
                const text = items[index].text.toLowerCase();
                const visible = text.includes(query);
                element.style.display = visible ? 'block' : 'none';
            });
        });

        document.body.appendChild(modal);
        selectItem(0);
        searchInput.focus();
    }

    navigateToParent() {
        const currentPath = window.location.pathname;
        
        if (currentPath.startsWith('/threads/')) {
            const thread = this.state.getState().currentThread;
            if (thread?.board_id) {
                this.navigateToBoard(thread.board_id);
            } else {
                this.navigateToHome();
            }
        } else if (currentPath.startsWith('/boards/')) {
            this.navigateToHome();
        } else if (currentPath !== '/') {
            this.navigateToHome();
        }
    }

    navigateBack() {
        if (window.history.length > 1) {
            window.history.back();
        }
    }

    navigateForward() {
        window.history.forward();
    }

    closeActiveModals() {
        const modals = document.querySelectorAll('.modal, .quick-nav-modal');
        modals.forEach(modal => modal.remove());
    }

    updateBrowserTitle(title) {
        document.title = title ? `${title} - Forum` : 'Forum';
    }

    updateNavigation(user) {
        const navElement = document.querySelector('#navigation .nav-right');
        if (!navElement) return;

        navElement.innerHTML = user
            ? this.renderLoggedInNavigation(user)
            : this.renderLoggedOutNavigation();
    }

    renderLoggedInNavigation(user) {
        return `
            <div class="nav-left">
                <a href="/" onclick="navigationManager.navigateToHome(); return false;">Forum Home</a>
                ${user.is_admin ? `
                    <a href="/admin" onclick="navigationManager.navigateToAdmin(); return false;">Admin Panel</a>
                ` : ''}
            </div>
            <div class="nav-right">
                <span class="nav-user">Welcome, ${UIComponents.escapeHtml(user.username)}</span>
                <button onclick="forum.logout()" class="nav-logout">Logout</button>
            </div>
        `;
    }

    renderLoggedOutNavigation() {
        return `
            <div class="nav-left">
                <a href="/" onclick="navigationManager.navigateToHome(); return false;">Forum Home</a>
            </div>
            <div class="nav-right">
                <a href="/login" onclick="navigationManager.navigateToLogin(); return false;">Login</a>
                <a href="/register" onclick="navigationManager.navigateToRegister(); return false;">Register</a>
            </div>
        `;
    }

    getCurrentPath() {
        return window.location.pathname;
    }

    getCurrentParams() {
        return new URLSearchParams(window.location.search);
    }

    getCurrentHash() {
        return window.location.hash;
    }

    addToHistory(path, state = {}) {
        window.history.pushState(state, '', path);
    }

    replaceInHistory(path, state = {}) {
        window.history.replaceState(state, '', path);
    }

    buildUrl(path, params = {}, hash = '') {
        const url = new URL(path, window.location.origin);
        
        Object.entries(params).forEach(([key, value]) => {
            if (value !== null && value !== undefined) {
                url.searchParams.set(key, value);
            }
        });

        if (hash) {
            url.hash = hash.startsWith('#') ? hash : `#${hash}`;
        }

        return url.pathname + url.search + url.hash;
    }

    parseCurrentRoute() {
        const path = this.getCurrentPath();
        const params = this.getCurrentParams();
        const hash = this.getCurrentHash();

        let routeType = 'unknown';
        let routeParams = {};

        if (path === '/') {
            routeType = 'home';
        } else if (path === '/login') {
            routeType = 'login';
        } else if (path === '/register') {
            routeType = 'register';
        } else if (path === '/admin') {
            routeType = 'admin';
        } else if (path.startsWith('/boards/')) {
            routeType = 'board';
            const boardId = path.split('/')[2];
            routeParams.boardId = parseInt(boardId);
        } else if (path.startsWith('/threads/')) {
            routeType = 'thread';
            const threadId = path.split('/')[2];
            routeParams.threadId = parseInt(threadId);
            
            if (hash.startsWith('#post-')) {
                routeParams.postId = parseInt(hash.substring(6));
            }
        }

        return {
            type: routeType,
            path,
            params: Object.fromEntries(params.entries()),
            hash,
            routeParams
        };
    }

    isCurrentRoute(path) {
        return this.getCurrentPath() === path;
    }

    requireAuth(redirectPath = null) {
        const user = this.state.getState().user;
        if (!user) {
            const redirect = redirectPath || this.getCurrentPath();
            this.navigateToLogin(redirect);
            return false;
        }
        return true;
    }

    requireAdmin() {
        const user = this.state.getState().user;
        if (!user) {
            this.navigateToLogin(this.getCurrentPath());
            return false;
        }
        if (!user.is_admin) {
            this.notifications.showError('Admin privileges required');
            this.navigateToHome();
            return false;
        }
        return true;
    }

    handleRouteChange(route) {
        this.updateBrowserTitle(this.getPageTitle(route));
        this.updateActiveNavigation(route);
    }

    getPageTitle(route) {
        switch (route.type) {
            case 'home':
                return null;
            case 'login':
                return 'Login';
            case 'register':
                return 'Register';
            case 'admin':
                return 'Admin Panel';
            case 'board':
                const board = this.state.getState().currentBoard;
                return board ? board.name : 'Board';
            case 'thread':
                const thread = this.state.getState().currentThread;
                return thread ? thread.title : 'Thread';
            default:
                return 'Page';
        }
    }

    updateActiveNavigation(route) {
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });

        const activeSelector = this.getActiveNavSelector(route);
        if (activeSelector) {
            const activeItem = document.querySelector(activeSelector);
            if (activeItem) {
                activeItem.classList.add('active');
            }
        }
    }

    getActiveNavSelector(route) {
        switch (route.type) {
            case 'home':
                return 'a[href="/"]';
            case 'admin':
                return 'a[href="/admin"]';
            default:
                return null;
        }
    }

    getTempThreadData() {
        const data = this.tempThreadData;
        this.tempThreadData = null;
        return data;
    }

    setTempThreadData(data) {
        this.tempThreadData = data;
    }

    getNavigationLock() {
        return this.navigationLock;
    }

    setNavigationLock(locked) {
        this.navigationLock = locked;
        if (locked) {
            setTimeout(() => {
                this.navigationLock = false;
            }, 250);
        }
    }

    destroy() {
        // Remove event listeners if needed
    }
}