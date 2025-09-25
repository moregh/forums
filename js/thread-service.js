class ThreadService {
    constructor(api, notifications, boardService = null) {
        this.api = api;
        this.notifications = notifications;
        this.boardService = boardService;
    }

    async getThread(threadId, page = 1) {
        try {
            const [posts, threadInfo] = await Promise.all([
                this.api.getPosts(threadId, page),
                this.api.getThreadInfo(threadId)
            ]);

            if (!threadInfo || !threadInfo.thread_id) {
                throw new Error('Thread not found');
            }

            let sanitizedThreadInfo = this.sanitizeThreadInfo(threadInfo, threadId);

            // If board name is missing and we have board service, try to fetch it
            if ((!sanitizedThreadInfo.board_name || sanitizedThreadInfo.board_name === 'Unknown Board') &&
                this.boardService && sanitizedThreadInfo.board_id) {
                try {
                    const board = await this.boardService.getBoard(sanitizedThreadInfo.board_id);
                    sanitizedThreadInfo.board_name = board.name || 'Unknown Board';
                } catch (error) {
                    console.warn('Failed to fetch board name for thread:', error);
                }
            }
            const sanitizedPosts = Array.isArray(posts) ? posts : [];

            return {
                thread: sanitizedThreadInfo,
                posts: sanitizedPosts,
                pagination: this.calculateThreadPagination(sanitizedThreadInfo, posts.length, page)
            };
        } catch (error) {
            throw new Error(`Failed to load thread: ${error.message}`);
        }
    }

    async getThreads(boardId, page = 1, perPage = 20) {
        try {
            const threads = await this.api.getThreads(boardId, page, perPage);
            return Array.isArray(threads) ? threads : [];
        } catch (error) {
            throw new Error(`Failed to load threads: ${error.message}`);
        }
    }

    async createThread(boardId, title, content) {
        const validation = Validation.validateForm({ title, content }, {
            title: 'threadTitle',
            content: 'postContent'
        });

        if (!validation.isValid) {
            const error = new Error('Validation failed');
            error.name = 'ValidationError';
            error.details = validation.errors;
            throw error;
        }

        try {
            const thread = await this.api.createThread(boardId, title, content);
            if (!thread) {
                throw new Error('Failed to create thread - no response from server');
            }
            return thread;
        } catch (error) {
            if (error.message.includes('rate limit')) {
                throw new Error('You are creating threads too frequently. Please wait a moment.');
            }
            throw error;
        }
    }

    async deleteThread(threadId) {
        try {
            await this.api.deleteThread(threadId);
            return true;
        } catch (error) {
            if (error.message.includes('not found')) {
                throw new Error('Thread not found or already deleted');
            }
            if (error.message.includes('permission')) {
                throw new Error('You do not have permission to delete this thread');
            }
            throw error;
        }
    }

    async lockThread(threadId, locked = true) {
        try {
            await this.api.lockThread(threadId, locked);
            return locked;
        } catch (error) {
            throw new Error(`Failed to ${locked ? 'lock' : 'unlock'} thread: ${error.message}`);
        }
    }

    async stickyThread(threadId, sticky = true) {
        try {
            await this.api.stickyThread(threadId, sticky);
            return sticky;
        } catch (error) {
            throw new Error(`Failed to ${sticky ? 'sticky' : 'unsticky'} thread: ${error.message}`);
        }
    }

    sanitizeThreadInfo(threadInfo, threadId) {
        return {
            thread_id: parseInt(threadId),
            title: threadInfo.title || `Thread ${threadId}`,
            locked: Boolean(threadInfo.locked),
            sticky: Boolean(threadInfo.sticky),
            reply_count: threadInfo.reply_count || 0,
            view_count: threadInfo.view_count || 0,
            user_id: threadInfo.user_id || threadInfo.author_id || 0,
            username: threadInfo.username || threadInfo.author_name || 'Unknown',
            timestamp: threadInfo.timestamp || threadInfo.created_at || Date.now() / 1000,
            board_id: threadInfo.board_id || 0,
            board_name: threadInfo.board_name || 'Unknown Board',
            last_post_at: threadInfo.last_post_at || null,
            last_post_username: threadInfo.last_post_username || null
        };
    }

    calculateThreadPagination(threadInfo, postsLoaded, currentPage) {
        const totalPosts = Math.max((threadInfo.reply_count || 0) + 1, postsLoaded);
        const postsPerPage = 20;
        
        return PaginationHelper.calculatePagination(currentPage, totalPosts, postsPerPage);
    }

    getPageForNewReply(threadInfo) {
        const totalPosts = (threadInfo.reply_count || 0) + 2;
        return PaginationHelper.getLastPageForNewItem(totalPosts, 20);
    }

    canUserEditThread(thread, user) {
        if (!user) return false;
        return thread.user_id === user.user_id || user.is_admin;
    }

    canUserDeleteThread(thread, user) {
        if (!user) return false;
        return thread.user_id === user.user_id || user.is_admin;
    }

    canUserModerateThread(user) {
        return user && user.is_admin;
    }

    isThreadLocked(thread) {
        return Boolean(thread.locked);
    }

    isThreadSticky(thread) {
        return Boolean(thread.sticky);
    }

    formatThreadForDisplay(thread) {
        return {
            ...thread,
            formattedDate: UIComponents.formatDate(thread.timestamp),
            formattedLastPost: thread.last_post_at 
                ? UIComponents.formatDate(thread.last_post_at)
                : null,
            replyText: thread.reply_count === 1 ? '1 reply' : `${thread.reply_count} replies`,
            viewText: thread.view_count === 1 ? '1 view' : `${thread.view_count} views`
        };
    }

    formatThreadsForDisplay(threads) {
        return threads.map(thread => this.formatThreadForDisplay(thread));
    }

    sortThreads(threads, sortBy = 'default') {
        const sortedThreads = [...threads];
        
        switch (sortBy) {
            case 'newest':
                return sortedThreads.sort((a, b) => b.timestamp - a.timestamp);
            case 'oldest':
                return sortedThreads.sort((a, b) => a.timestamp - b.timestamp);
            case 'most_replies':
                return sortedThreads.sort((a, b) => b.reply_count - a.reply_count);
            case 'most_views':
                return sortedThreads.sort((a, b) => b.view_count - a.view_count);
            case 'title':
                return sortedThreads.sort((a, b) => a.title.localeCompare(b.title));
            case 'last_activity':
                return sortedThreads.sort((a, b) => (b.last_post_at || b.timestamp) - (a.last_post_at || a.timestamp));
            default:
                return sortedThreads.sort((a, b) => {
                    if (a.sticky !== b.sticky) {
                        return b.sticky - a.sticky;
                    }
                    return (b.last_post_at || b.timestamp) - (a.last_post_at || a.timestamp);
                });
        }
    }

    filterThreads(threads, filter = {}) {
        let filtered = [...threads];

        if (filter.locked !== undefined) {
            filtered = filtered.filter(thread => Boolean(thread.locked) === filter.locked);
        }

        if (filter.sticky !== undefined) {
            filtered = filtered.filter(thread => Boolean(thread.sticky) === filter.sticky);
        }

        if (filter.author) {
            filtered = filtered.filter(thread => 
                thread.username.toLowerCase().includes(filter.author.toLowerCase())
            );
        }

        if (filter.search) {
            const searchTerm = filter.search.toLowerCase();
            filtered = filtered.filter(thread =>
                thread.title.toLowerCase().includes(searchTerm)
            );
        }

        if (filter.minReplies !== undefined) {
            filtered = filtered.filter(thread => thread.reply_count >= filter.minReplies);
        }

        if (filter.dateRange) {
            const { start, end } = filter.dateRange;
            filtered = filtered.filter(thread => {
                const threadDate = thread.timestamp;
                return threadDate >= start && threadDate <= end;
            });
        }

        return filtered;
    }

    getThreadStats(threads) {
        const total = threads.length;
        const locked = threads.filter(t => t.locked).length;
        const sticky = threads.filter(t => t.sticky).length;
        const totalReplies = threads.reduce((sum, t) => sum + (t.reply_count || 0), 0);
        const totalViews = threads.reduce((sum, t) => sum + (t.view_count || 0), 0);
        
        const authors = new Set(threads.map(t => t.username)).size;
        
        const mostActive = threads.length > 0 
            ? threads.reduce((max, thread) => 
                (thread.reply_count || 0) > (max.reply_count || 0) ? thread : max
              )
            : null;

        return {
            total,
            locked,
            sticky,
            totalReplies,
            totalViews,
            uniqueAuthors: authors,
            averageReplies: total > 0 ? Math.round(totalReplies / total) : 0,
            averageViews: total > 0 ? Math.round(totalViews / total) : 0,
            mostActiveThread: mostActive
        };
    }

    validateThreadData(data) {
        const errors = {};

        if (!data.title || data.title.trim().length === 0) {
            errors.title = ['Thread title is required'];
        } else {
            const titleValidation = Validation.validateThreadTitle(data.title);
            if (!titleValidation.isValid) {
                errors.title = titleValidation.errors;
            }
        }

        if (!data.content || data.content.trim().length === 0) {
            errors.content = ['Thread content is required'];
        } else {
            const contentValidation = Validation.validatePostContent(data.content);
            if (!contentValidation.isValid) {
                errors.content = contentValidation.errors;
            }
        }

        return {
            isValid: Object.keys(errors).length === 0,
            errors
        };
    }

    async searchThreads(boardId, query, options = {}) {
        const {
            page = 1,
            perPage = 20,
            sortBy = 'relevance'
        } = options;

        const validation = Validation.validateSearchQuery(query);
        if (!validation.isValid) {
            throw new Error(validation.errors[0]);
        }

        try {
            const results = await this.api.request(`/api/search?q=${encodeURIComponent(query)}&type=threads&board_id=${boardId}&page=${page}&per_page=${perPage}`);
            return results.threads || [];
        } catch (error) {
            throw new Error(`Search failed: ${error.message}`);
        }
    }

    getBreadcrumbs(thread, boards) {
        const breadcrumbs = [
            { text: '📋 Forum', url: '/' }
        ];

        if (thread.board_id && boards) {
            const board = boards.find(b => b.board_id === thread.board_id);
            if (board) {
                breadcrumbs.push({
                    text: board.name,
                    url: `/boards/${board.board_id}`
                });
            }
        }

        breadcrumbs.push({
            text: thread.title,
            url: `/threads/${thread.thread_id}`,
            current: true
        });

        return breadcrumbs;
    }
}