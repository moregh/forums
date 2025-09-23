class BoardService {
    constructor(api, notifications) {
        this.api = api;
        this.notifications = notifications;
        this.cachedBoards = null;
        this.lastFetch = 0;
        this.cacheTimeout = 5 * 60 * 1000; // 5 minutes
    }

    async getBoards(forceRefresh = false) {
        const now = Date.now();
        
        if (!forceRefresh && this.cachedBoards && (now - this.lastFetch) < this.cacheTimeout) {
            return this.cachedBoards;
        }

        try {
            const boards = await this.api.getBoards();
            this.cachedBoards = Array.isArray(boards) ? boards.map(board => this.sanitizeBoard(board)) : [];
            this.lastFetch = now;
            return this.cachedBoards;
        } catch (error) {
            throw new Error(`Failed to load boards: ${error.message}`);
        }
    }

    async getBoard(boardId) {
        try {
            console.log('Looking for board ID:', boardId, 'type:', typeof boardId);

            // First try to find in cached boards
            const boards = await this.getBoards();
            console.log('Available boards:', boards.map(b => ({ id: b.board_id, name: b.name })));
            let board = boards.find(b => b.board_id == boardId);

            // If not found, force refresh cache and try again
            if (!board) {
                console.log('Board not found in cache, refreshing...');
                const refreshedBoards = await this.getBoards(true);
                console.log('Refreshed boards:', refreshedBoards.map(b => ({ id: b.board_id, name: b.name })));
                board = refreshedBoards.find(b => b.board_id == boardId);
            }

            if (!board) {
                console.error('Board still not found after refresh');
                throw new Error('Board not found');
            }

            console.log('Found board:', board.name);
            return board;
        } catch (error) {
            console.error('getBoard error:', error);
            throw new Error(`Failed to load board: ${error.message}`);
        }
    }

    async createBoard(name, description) {
        const validation = Validation.validateForm({ name, description }, {
            name: 'boardName',
            description: 'boardDescription'
        });

        if (!validation.isValid) {
            const error = new Error('Validation failed');
            error.name = 'ValidationError';
            error.details = validation.errors;
            throw error;
        }

        try {
            const board = await this.api.createBoard(name, description);
            if (!board) {
                throw new Error('Failed to create board - no response from server');
            }

            this.invalidateCache();
            return this.sanitizeBoard(board);
        } catch (error) {
            if (error.message.includes('already exists')) {
                throw new Error('A board with this name already exists');
            }
            if (error.message.includes('permission') || error.message.includes('admin')) {
                throw new Error('You do not have permission to create boards');
            }
            throw error;
        }
    }

    sanitizeBoard(board) {
        return {
            board_id: board.board_id,
            name: board.name || 'Unnamed Board',
            description: board.description || '',
            creator_id: board.creator_id || 0,
            creator_name: board.creator_name || 'Unknown',
            thread_count: board.thread_count || 0,
            post_count: board.post_count || 0,
            last_post_at: board.last_post_at || null,
            last_post_username: board.last_post_username || null
        };
    }

    formatBoardForDisplay(board) {
        return {
            ...board,
            formattedLastPost: board.last_post_at 
                ? UIComponents.formatDate(board.last_post_at)
                : 'No posts yet',
            threadText: board.thread_count === 1 ? '1 thread' : `${board.thread_count} threads`,
            postText: board.post_count === 1 ? '1 post' : `${board.post_count} posts`,
            activityLevel: this.calculateActivityLevel(board),
            isEmpty: board.thread_count === 0 && board.post_count === 0
        };
    }

    formatBoardsForDisplay(boards) {
        return boards.map(board => this.formatBoardForDisplay(board));
    }

    calculateActivityLevel(board) {
        const totalActivity = (board.thread_count || 0) + (board.post_count || 0);
        
        if (totalActivity === 0) return 'inactive';
        if (totalActivity < 10) return 'low';
        if (totalActivity < 50) return 'medium';
        if (totalActivity < 200) return 'high';
        return 'very-high';
    }

    sortBoards(boards, sortBy = 'name') {
        const sortedBoards = [...boards];

        switch (sortBy) {
            case 'name':
                return sortedBoards.sort((a, b) => a.name.localeCompare(b.name));
            case 'activity':
                return sortedBoards.sort((a, b) => 
                    ((b.thread_count || 0) + (b.post_count || 0)) - 
                    ((a.thread_count || 0) + (a.post_count || 0))
                );
            case 'threads':
                return sortedBoards.sort((a, b) => (b.thread_count || 0) - (a.thread_count || 0));
            case 'posts':
                return sortedBoards.sort((a, b) => (b.post_count || 0) - (a.post_count || 0));
            case 'newest':
                return sortedBoards.sort((a, b) => b.board_id - a.board_id);
            case 'oldest':
                return sortedBoards.sort((a, b) => a.board_id - b.board_id);
            case 'last_activity':
                return sortedBoards.sort((a, b) => {
                    const aTime = a.last_post_at || 0;
                    const bTime = b.last_post_at || 0;
                    return bTime - aTime;
                });
            default:
                return sortedBoards.sort((a, b) => a.name.localeCompare(b.name));
        }
    }

    filterBoards(boards, filter = {}) {
        let filtered = [...boards];

        if (filter.search) {
            const searchTerm = filter.search.toLowerCase();
            filtered = filtered.filter(board =>
                board.name.toLowerCase().includes(searchTerm) ||
                board.description.toLowerCase().includes(searchTerm)
            );
        }

        if (filter.creator) {
            filtered = filtered.filter(board =>
                board.creator_name.toLowerCase().includes(filter.creator.toLowerCase())
            );
        }

        if (filter.activityLevel) {
            filtered = filtered.filter(board =>
                this.calculateActivityLevel(board) === filter.activityLevel
            );
        }

        if (filter.hasActivity !== undefined) {
            filtered = filtered.filter(board => {
                const hasActivity = (board.thread_count || 0) > 0 || (board.post_count || 0) > 0;
                return hasActivity === filter.hasActivity;
            });
        }

        if (filter.minThreads !== undefined) {
            filtered = filtered.filter(board => (board.thread_count || 0) >= filter.minThreads);
        }

        if (filter.minPosts !== undefined) {
            filtered = filtered.filter(board => (board.post_count || 0) >= filter.minPosts);
        }

        return filtered;
    }

    getBoardStats(boards) {
        const total = boards.length;
        const totalThreads = boards.reduce((sum, b) => sum + (b.thread_count || 0), 0);
        const totalPosts = boards.reduce((sum, b) => sum + (b.post_count || 0), 0);
        const activeBoards = boards.filter(b => (b.thread_count || 0) > 0 || (b.post_count || 0) > 0).length;
        
        const creators = new Set(boards.map(b => b.creator_name)).size;
        
        const mostActive = boards.length > 0
            ? boards.reduce((max, board) => {
                const maxActivity = (max.thread_count || 0) + (max.post_count || 0);
                const boardActivity = (board.thread_count || 0) + (board.post_count || 0);
                return boardActivity > maxActivity ? board : max;
              })
            : null;

        const recentlyActive = boards.filter(board => {
            if (!board.last_post_at) return false;
            const dayAgo = Date.now() / 1000 - (24 * 60 * 60);
            return board.last_post_at > dayAgo;
        }).length;

        return {
            total,
            active: activeBoards,
            inactive: total - activeBoards,
            totalThreads,
            totalPosts,
            uniqueCreators: creators,
            averageThreadsPerBoard: total > 0 ? Math.round(totalThreads / total) : 0,
            averagePostsPerBoard: total > 0 ? Math.round(totalPosts / total) : 0,
            mostActiveBoard: mostActive,
            recentlyActive
        };
    }

    validateBoardData(data) {
        const errors = {};

        if (!data.name || data.name.trim().length === 0) {
            errors.name = ['Board name is required'];
        } else {
            const nameValidation = Validation.validateBoardName(data.name);
            if (!nameValidation.isValid) {
                errors.name = nameValidation.errors;
            }
        }

        if (!data.description || data.description.trim().length === 0) {
            errors.description = ['Board description is required'];
        } else {
            const descValidation = Validation.validateBoardDescription(data.description);
            if (!descValidation.isValid) {
                errors.description = descValidation.errors;
            }
        }

        return {
            isValid: Object.keys(errors).length === 0,
            errors
        };
    }

    canUserCreateBoard(user) {
        return user && user.is_admin;
    }

    canUserModerateBoard(board, user) {
        if (!user) return false;
        return user.is_admin || board.creator_id === user.user_id;
    }

    getBoardActivityIndicator(board) {
        const now = Date.now() / 1000;
        const hour = 60 * 60;
        const day = 24 * hour;
        const week = 7 * day;

        if (!board.last_post_at) {
            return { level: 'none', text: 'No activity', class: 'activity-none' };
        }

        const timeSince = now - board.last_post_at;

        if (timeSince < hour) {
            return { level: 'very-recent', text: 'Active now', class: 'activity-very-recent' };
        } else if (timeSince < day) {
            return { level: 'recent', text: 'Active today', class: 'activity-recent' };
        } else if (timeSince < week) {
            return { level: 'moderate', text: 'Active this week', class: 'activity-moderate' };
        } else {
            return { level: 'old', text: 'Quiet recently', class: 'activity-old' };
        }
    }

    groupBoardsByActivity(boards) {
        const groups = {
            'very-active': [],
            'active': [],
            'moderate': [],
            'quiet': [],
            'inactive': []
        };

        boards.forEach(board => {
            const activity = this.calculateActivityLevel(board);
            const indicator = this.getBoardActivityIndicator(board);

            if (activity === 'very-high' && indicator.level === 'very-recent') {
                groups['very-active'].push(board);
            } else if (activity === 'high' || indicator.level === 'recent') {
                groups['active'].push(board);
            } else if (activity === 'medium' || indicator.level === 'moderate') {
                groups['moderate'].push(board);
            } else if (activity === 'low') {
                groups['quiet'].push(board);
            } else {
                groups['inactive'].push(board);
            }
        });

        return groups;
    }

    async searchBoards(query, options = {}) {
        const {
            includeInactive = true,
            sortBy = 'relevance'
        } = options;

        const validation = Validation.validateSearchQuery(query);
        if (!validation.isValid) {
            throw new Error(validation.errors[0]);
        }

        try {
            const boards = await this.getBoards();
            const searchTerm = query.toLowerCase();
            
            let results = boards.filter(board =>
                board.name.toLowerCase().includes(searchTerm) ||
                board.description.toLowerCase().includes(searchTerm) ||
                board.creator_name.toLowerCase().includes(searchTerm)
            );

            if (!includeInactive) {
                results = results.filter(board => 
                    (board.thread_count || 0) > 0 || (board.post_count || 0) > 0
                );
            }

            if (sortBy === 'relevance') {
                results.sort((a, b) => {
                    const aNameMatch = a.name.toLowerCase().includes(searchTerm);
                    const bNameMatch = b.name.toLowerCase().includes(searchTerm);
                    
                    if (aNameMatch && !bNameMatch) return -1;
                    if (!aNameMatch && bNameMatch) return 1;
                    
                    const aActivity = (a.thread_count || 0) + (a.post_count || 0);
                    const bActivity = (b.thread_count || 0) + (b.post_count || 0);
                    return bActivity - aActivity;
                });
            } else {
                results = this.sortBoards(results, sortBy);
            }

            return results;
        } catch (error) {
            throw new Error(`Board search failed: ${error.message}`);
        }
    }

    getBoardUrl(boardId) {
        return `/boards/${boardId}`;
    }

    getBoardCreateUrl() {
        return '/boards/create';
    }

    generateBoardSlug(name) {
        return name
            .toLowerCase()
            .replace(/[^a-z0-9\s-]/g, '')
            .replace(/\s+/g, '-')
            .replace(/-+/g, '-')
            .trim('-');
    }

    invalidateCache() {
        this.cachedBoards = null;
        this.lastFetch = 0;
    }

    getCachedBoards() {
        return this.cachedBoards;
    }

    isCacheValid() {
        const now = Date.now();
        return this.cachedBoards && (now - this.lastFetch) < this.cacheTimeout;
    }

    getCacheAge() {
        return Date.now() - this.lastFetch;
    }

    async refreshCache() {
        return this.getBoards(true);
    }

    getBoardBreadcrumbs(board) {
        return [
            { text: '📋 Forum', url: '/' },
            { text: board.name, url: this.getBoardUrl(board.board_id), current: true }
        ];
    }

    getPopularBoards(boards, limit = 5) {
        return this.sortBoards(boards, 'activity').slice(0, limit);
    }

    getRecentlyActiveBoards(boards, limit = 5) {
        return this.sortBoards(boards, 'last_activity').slice(0, limit);
    }

    getEmptyBoards(boards) {
        return boards.filter(board => 
            (board.thread_count || 0) === 0 && (board.post_count || 0) === 0
        );
    }
}