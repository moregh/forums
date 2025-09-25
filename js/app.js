class ForumApp {
    constructor() {
        this.api = new ForumAPI();
        this.state = new ForumState();
        this.router = new Router();
        
        this.notifications = new NotificationManager();
        this.modalManager = new ModalManager();
        this.formHandler = new FormHandler(this.api, this.notifications);
        this.navigationManager = new NavigationManager(this.router, this.state, this.notifications);
        
        this.boardService = new BoardService(this.api, this.notifications);
        this.threadService = new ThreadService(this.api, this.notifications, this.boardService);
        this.postService = new PostService(this.api, this.notifications);
        this.adminService = new AdminService(this.api, this.notifications);
        this.userService = new UserService(this.api, this.modalManager, this.notifications);
        
        this.authController = new AuthController(
            this.api, this.formHandler, this.notifications, 
            this.modalManager, this.router, this.state
        );
        this.boardController = new BoardController(
            this.boardService, this.threadService, this.formHandler,
            this.notifications, this.modalManager, this.router, this.state
        );
        this.threadController = new ThreadController(
            this.threadService, this.postService, this.boardService,
            this.formHandler, this.notifications, this.modalManager, this.router, this.state
        );
        this.adminController = new AdminController(
            this.adminService, this.formHandler, this.notifications,
            this.modalManager, this.router, this.state
        );

        this.setupRoutes();
        this.setupEventListeners();
        this.init();
    }

    setupRoutes() {
        this.router.register('/', () => this.boardController.showHome());
        this.router.register('/login', () => this.authController.showLogin());
        this.router.register('/register', () => this.authController.showRegister());
        this.router.register('/admin', () => this.adminController.showAdmin());
        this.router.register('/boards/:id', (params) => this.boardController.showBoard(params.id));
        this.router.register('/threads/:id', (params) => {
            const threadData = this.navigationManager.getTempThreadData();
            this.threadController.showThread(params.id, 1, threadData);
        });
    }

    setupEventListeners() {
        this.state.subscribe('userChanged', (user) => this.navigationManager.updateNavigation(user));
        this.state.subscribe('loadingChanged', (loading) => UIComponents.showLoading(loading));
        this.state.subscribe('errorChanged', (error) => {
            if (error) this.notifications.showError(error);
        });

        this.router.register('routeChanged', (route) => {
            this.navigationManager.handleRouteChange(route);
        });
    }

    async init() {
        if (this.api.token && this.api.user) {
            this.state.setState({ user: this.api.user });
            try {
                await this.authController.refreshToken();
            } catch (error) {
                this.authController.handleAuthError();
            }
        }

        this.navigationManager.updateNavigation(this.api.user);
        
        this.authController.setupAuthRefresh();
        
        await this.loadInitialData();
        
        this.router.handleRoute();
        
        this.setupGlobalReferences();
        
        this.initializeEnhancements();

        this.initializeUsernameHandlers();
    }

    async loadInitialData() {
        try {
            this.state.setState({ loading: true, error: null });
            const boards = await this.boardService.getBoards();
            this.state.setState({ boards, loading: false });
        } catch (error) {
            this.state.setState({ error: error.message, loading: false });
        }
    }

    setupGlobalReferences() {
        window.authController = this.authController;
        window.boardController = this.boardController;
        window.threadController = this.threadController;
        window.adminController = this.adminController;
        window.navigationManager = this.navigationManager;
        window.notificationManager = this.notifications;
        window.userService = this.userService;
        
        window.forum = {
            router: this.router,
            state: this.state,
            api: this.api,
            
            logout: () => this.authController.logout(),
            handleLogin: (event) => this.authController.handleLogin(event),
            handleRegister: (event) => this.authController.handleRegister(event),
            handleAuthError: () => this.authController.handleAuthError(),
            
            navigateToThread: (threadId, threadData) => this.navigationManager.navigateToThread(threadId, threadData),
            navigateToBoard: (boardId) => this.navigationManager.navigateToBoard(boardId),
            
            showHome: () => this.boardController.showHome(),
            showBoard: (boardId, page) => this.boardController.showBoard(boardId, page),
            showCreateBoardForm: () => this.boardController.showCreateBoardForm(),
            handleCreateBoard: (event) => this.formHandler.handleSubmit(
                event.target,
                (formData) => this.boardService.createBoard(formData.name, formData.description),
                { successMessage: 'Board created successfully!' }
            ),
            
            showThread: (threadId, page, threadData) => this.threadController.showThread(threadId, page, threadData),
            showCreateThreadForm: (boardId) => this.boardController.showCreateThreadForm(boardId),
            handleCreateThread: (event, boardId) => this.formHandler.handleSubmit(
                event.target,
                (formData) => this.threadService.createThread(boardId, formData.title, formData.content),
                { successMessage: 'Thread created successfully!' }
            ),
            deleteThread: (threadId) => this.threadController.deleteThread(threadId),
            toggleThreadLock: (threadId, locked) => this.threadController.toggleThreadLock(threadId, locked),
            toggleThreadSticky: (threadId, sticky) => this.threadController.toggleThreadSticky(threadId, sticky),
            
            showReplyForm: (threadId) => this.threadController.showReplyForm(threadId),
            handleCreatePost: (event, threadId) => this.threadController.handleQuickReply(event, threadId),
            editPost: (postId) => this.threadController.editPost(postId),
            handleEditPost: (event, postId) => this.threadController.updatePost(postId, new FormData(event.target).get('content')),
            deletePost: (postId) => this.threadController.deletePost(postId),
            
            showAdmin: () => this.adminController.showAdmin(),
            banUser: (userId) => this.adminController.banUser(userId),
            unbanUser: (userId) => this.adminController.unbanUser(userId),
            makeUserAdmin: (userId) => this.adminController.promoteUser(userId),
            removeUserAdmin: (userId) => this.adminController.demoteUser(userId),
            
            showUserInfo: (userId) => this.userService.showUserInfo(userId),
            navigateToThreadFromUserInfo: (threadId) => this.userService.navigateToThread(threadId),

            createModal: (content) => this.modalManager.createModal(content),
            showError: (message) => this.notifications.showError(message),
            showSuccess: (message) => this.notifications.showSuccess(message),
            showInfo: (message) => this.notifications.showInfo(message)
        };
    }

    initializeEnhancements() {
        this.setupKeyboardShortcuts();
        this.setupAutoSave();
        this.loadTheme();
        this.setupPeriodicTasks();
    }

    initializeUsernameHandlers() {
        this.userService.setupUsernameClickHandlers();

        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList') {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            this.userService.setupUsernameClickHandlers(node);
                        }
                    });
                }
            });
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });

        this._usernameObserver = observer;
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
                return;
            }

            const { ctrlKey, metaKey, altKey, key } = e;
            const modKey = ctrlKey || metaKey;

            if (modKey && key === 'Enter') {
                const activeForm = document.querySelector('.modal form');
                if (activeForm) {
                    activeForm.requestSubmit();
                }
            }

            if (altKey && key === 'h') {
                e.preventDefault();
                this.navigationManager.navigateToHome();
            }

            if (altKey && key === 'l' && !this.state.getState().user) {
                e.preventDefault();
                this.navigationManager.navigateToLogin();
            }

            if (altKey && key === 'a' && this.state.getState().user?.is_admin) {
                e.preventDefault();
                this.navigationManager.navigateToAdmin();
            }

            if (key === 'Escape') {
                this.navigationManager.closeActiveModals();
            }
        });
    }

    setupAutoSave() {
        let autoSaveTimer;
        document.addEventListener('input', (e) => {
            if (e.target.tagName === 'TEXTAREA' && e.target.closest('.modal')) {
                clearTimeout(autoSaveTimer);
                autoSaveTimer = setTimeout(() => {
                    const formId = e.target.closest('form').getAttribute('data-form-id') || 'draft';
                    localStorage.setItem(`forum_draft_${formId}`, e.target.value);
                }, ForumConfig.timing.autoSaveDelay);
            }
        });
    }

    loadTheme() {
        const savedTheme = localStorage.getItem('forum_theme') || 'default';
        this.setTheme(savedTheme);
    }

    setTheme(theme) {
        document.body.className = `theme-${theme}`;
        localStorage.setItem('forum_theme', theme);
    }

    setupPeriodicTasks() {
        setInterval(() => {
            if (this.api.token && this.state.getState().user) {
                this.authController.refreshToken().catch(() => {
                    console.warn('Token refresh failed');
                });
            }
        }, ForumConfig.cache.sessionRefreshInterval);

        setInterval(() => {
            this.cleanupOldDrafts();
        }, ForumConfig.cache.draftCleanupInterval);
    }

    cleanupOldDrafts() {
        const maxAge = ForumConfig.cache.maxDraftAge;
        const now = Date.now();
        
        Object.keys(localStorage).forEach(key => {
            if (key.startsWith('forum_draft_')) {
                try {
                    const timestamp = localStorage.getItem(`${key}_timestamp`);
                    if (timestamp && (now - parseInt(timestamp)) > maxAge) {
                        localStorage.removeItem(key);
                        localStorage.removeItem(`${key}_timestamp`);
                    }
                } catch (error) {
                    localStorage.removeItem(key);
                }
            }
        });
    }

    handleNetworkError() {
        this.notifications.showError('Network error. Please check your connection and try again.');
    }

    getCurrentUser() {
        return this.state.getState().user;
    }

    isLoggedIn() {
        return !!this.getCurrentUser();
    }

    isAdmin() {
        const user = this.getCurrentUser();
        return user && user.is_admin;
    }

    refreshCurrentView() {
        const route = this.navigationManager.parseCurrentRoute();
        
        switch (route.type) {
            case 'home':
                this.boardController.showHome();
                break;
            case 'board':
                if (route.routeParams.boardId) {
                    this.boardController.showBoard(route.routeParams.boardId);
                }
                break;
            case 'thread':
                if (route.routeParams.threadId) {
                    this.threadController.showThread(route.routeParams.threadId);
                }
                break;
            case 'admin':
                this.adminController.showAdmin();
                break;
            default:
                this.boardController.showHome();
        }
    }

    destroy() {
        if (this.authController) this.authController.destroy();
        if (this.boardController) this.boardController.destroy();
        if (this.threadController) this.threadController.destroy();
        if (this.adminController) this.adminController.destroy();
        if (this.navigationManager) this.navigationManager.destroy();
        if (this.modalManager) this.modalManager.destroy();
        if (this.notifications) this.notifications.destroy();
        if (this.formHandler) this.formHandler.destroy();

        if (this._usernameObserver) {
            this._usernameObserver.disconnect();
        }

        delete window.authController;
        delete window.boardController;
        delete window.threadController;
        delete window.adminController;
        delete window.navigationManager;
        delete window.notificationManager;
        delete window.userService;
        delete window.forum;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.forum = new ForumApp();
});

window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
    if (window.notificationManager) {
        window.notificationManager.showError('An unexpected error occurred. Please refresh the page.');
    }
});

window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    if (window.notificationManager) {
        window.notificationManager.showError('Network error. Please check your connection.');
    }
});