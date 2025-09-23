const ForumConfig = {
    // API Configuration
    api: {
        baseURL: 'http://10.0.1.251:8000'
    },

    // Pagination Settings
    pagination: {
        defaultPerPage: 20,
        adminUsersPerPage: 50,
        threadsPerPage: 20,
        postsPerPage: 20,
        defaultPage: 1
    },

    // Cache Settings (in milliseconds)
    cache: {
        userServiceTimeout: 5 * 60 * 1000,    // 5 minutes
        boardServiceTimeout: 5 * 60 * 1000,   // 5 minutes
        sessionRefreshInterval: 25 * 60 * 1000, // 25 minutes
        draftCleanupInterval: 60 * 60 * 1000,  // 1 hour
        maxDraftAge: 7 * 24 * 60 * 60 * 1000  // 7 days
    },

    // Timing Constants (in milliseconds)
    timing: {
        animationDelay: 10,
        shortDelay: 100,
        mediumDelay: 300,
        longDelay: 500,
        scrollDelay: 1000,
        autoSaveDelay: 1000,
        refreshDelay: 1000,
        navigationLockDelay: 1000,
        fadeOutDelay: 300
    },

    // Notification Settings (in milliseconds)
    notifications: {
        defaultDuration: 8000,
        toastDuration: 3000,
        progressHideDelay: 1000,
        durations: {
            success: 4000,
            error: 6000,
            warning: 5000,
            info: 4000,
            loading: 0
        },
        zIndex: 10000
    },

    // UI Constants
    ui: {
        zIndexModal: 10000,
        scrollBehavior: 'smooth',
        scrollTop: 0
    },

    // HTTP Status Codes
    httpStatus: {
        unauthorized: 401,
        notFound: 404,
        forbidden: 403
    },

    // Validation Constants
    validation: {
        passwordMinLength: 10,
        banReasonMaxLength: 500,
        defaultValidationDelay: 1000
    },

    // Board Activity Thresholds
    boardActivity: {
        lowActivityThreshold: 10,
        mediumActivityThreshold: 50,
        highActivityThreshold: 200
    },

    // Popular Content Limits
    limits: {
        popularBoardsDefault: 5,
        recentlyActiveBoardsDefault: 5
    },

    // Form Constants
    forms: {
        textareaRows: {
            description: 4,
            content: 6,
            reply: 6
        }
    },

    // Misc Constants
    misc: {
        paginationMultiplier: 20,
        percentageMax: 100,
        emptyCount: 0,
        singleItem: 1,
        firstIndex: 0,
        secondIndex: 1,
        increment: 1,
        decrement: -1
    },

    // Time Constants (in seconds)
    timeConstants: {
        hour: 60 * 60,
        day: 24 * 60 * 60,
        week: 7 * 24 * 60 * 60,
        dayAgo: 24 * 60 * 60
    }
};

// Make it available globally
window.ForumConfig = ForumConfig;