class ThreadController {
    constructor(threadService, postService, boardService, formHandler, notifications, modalManager, router, state) {
        this.threadService = threadService;
        this.postService = postService;
        this.boardService = boardService;
        this.formHandler = formHandler;
        this.notifications = notifications;
        this.modalManager = modalManager;
        this.router = router;
        this.state = state;
        this.navigationLock = false;
    }

    async showThread(threadId, page = 1, threadData = null) {
        if (this.navigationLock) return;
        
        try {
            this.state.setState({ loading: true, error: null });
            
            let threadResult;
            if (threadData) {
                const posts = await this.postService.getPosts(threadId, page);
                threadResult = {
                    thread: threadData,
                    posts,
                    pagination: this.threadService.calculateThreadPagination(threadData, posts.length, page)
                };
            } else {
                threadResult = await this.threadService.getThread(threadId, page);
            }

            const { thread, posts, pagination } = threadResult;
            const user = this.state.getState().user;
            const boards = this.state.getState().boards;

            const content = document.getElementById('content');
            content.innerHTML = this.renderThreadPage(thread, posts, user, boards, pagination);

            this.state.setState({
                currentThread: thread,
                posts,
                currentPage: page,
                totalPages: pagination.totalPages,
                loading: false
            });

            this.setupThreadInteractions();

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

    renderThreadPage(thread, posts, user, boards, pagination) {
        const breadcrumbs = this.threadService.getBreadcrumbs(thread, boards);
        const formattedPosts = this.postService.formatPostsForDisplay(posts);

        return `
            ${this.renderBreadcrumbs(breadcrumbs)}
            
            <div class="page-header">
                <div class="thread-header">
                    <h1>${UIComponents.escapeHtml(thread.title)}</h1>
                    <div class="thread-meta">
                        <span>by <span class="thread-author" data-user-id="${thread.user_id}">${UIComponents.escapeHtml(thread.username)}</span> • ${UIComponents.formatDate(thread.timestamp)}</span>
                        ${thread.sticky ? ' • <span class="sticky-badge">Sticky</span>' : ''}
                        ${thread.locked ? ' • <span class="locked-badge">Locked</span>' : ''}
                        <span> • ${thread.reply_count} replies • ${thread.view_count} views</span>
                    </div>
                </div>
                <div class="page-actions">
                    <button onclick="threadController.router.navigate('/boards/${thread.board_id}')" class="btn-secondary">
                        ← Back to ${UIComponents.escapeHtml(thread.board_name)}
                    </button>
                    ${user && !thread.locked ? `<button onclick="threadController.showReplyForm(${thread.thread_id})" class="btn-primary">Reply</button>` : ''}
                    ${this.canUserModerateThread(thread, user) ? this.renderModeratorActions(thread) : ''}
                </div>
            </div>

            ${this.renderThreadControls(thread, user)}
            
            <div class="posts-list" id="posts-container">
                ${this.renderPosts(formattedPosts, user)}
            </div>
            
            ${pagination.totalPages > 1 ? this.renderPagination(pagination, thread.thread_id) : ''}
            
            ${user && !thread.locked ? this.renderQuickReply(thread.thread_id) : ''}
        `;
    }

    renderPosts(posts, user) {
        if (!posts || posts.length === 0) {
            return this.renderEmptyPostsState();
        }

        return posts.map((post, index) => `
            <div class="post" id="post-${post.post_id}" data-post-number="${index + 1}">
                <div class="post-header">
                    <div class="post-author-info">
                        <span class="post-author" data-user-id="${post.user_id}">${UIComponents.escapeHtml(post.username)}</span>
                        <span class="post-number">#${index + 1}</span>
                    </div>
                    <div class="post-meta">
                        <span class="post-date">${post.formattedDate}</span>
                        ${post.isEdited ? `<span class="edited-badge" title="${post.editInfo?.text || 'Edited'}">Edited</span>` : ''}
                        <a href="#post-${post.post_id}" class="post-link">#</a>
                    </div>
                    ${this.renderPostActions(post, user)}
                </div>
                <div class="post-content" id="post-content-${post.post_id}">
                    ${post.formattedContent}
                </div>
                ${post.editInfo ? `<div class="post-edit-info">${UIComponents.escapeHtml(post.editInfo.text)}</div>` : ''}
            </div>
        `).join('');
    }

    renderPostActions(post, user) {
        if (!user) return '';

        const actions = [];

        if (this.postService.canUserEditPost(post, user)) {
            actions.push(`<button onclick="threadController.editPost(${post.post_id})" class="btn-small btn-secondary">Edit</button>`);
        }

        if (this.postService.canUserDeletePost(post, user)) {
            actions.push(`<button onclick="threadController.deletePost(${post.post_id})" class="btn-small btn-danger">Delete</button>`);
        }

        if (this.postService.canUserViewEditHistory(post, user) && post.isEdited) {
            actions.push(`<button onclick="threadController.showPostHistory(${post.post_id})" class="btn-small btn-secondary">History</button>`);
        }

        actions.push(`<button onclick="threadController.quotePost(${post.post_id})" class="btn-small btn-secondary">Quote</button>`);

        return actions.length > 0 ? `<div class="post-actions">${actions.join('')}</div>` : '';
    }

    renderModeratorActions(thread) {
        return `
            <div class="admin-actions">
                <button onclick="threadController.toggleThreadLock(${thread.thread_id}, ${!thread.locked})" 
                        class="btn-small ${thread.locked ? 'btn-success' : 'btn-warning'}">
                    ${thread.locked ? 'Unlock' : 'Lock'}
                </button>
                <button onclick="threadController.toggleThreadSticky(${thread.thread_id}, ${!thread.sticky})" 
                        class="btn-small ${thread.sticky ? 'btn-warning' : 'btn-secondary'}">
                    ${thread.sticky ? 'Unsticky' : 'Sticky'}
                </button>
                <button onclick="threadController.deleteThread(${thread.thread_id})" class="btn-small btn-danger">Delete</button>
            </div>
        `;
    }

    renderThreadControls(thread, user) {
        return `
            <div class="thread-controls">
                <div class="view-controls">
                    <button onclick="threadController.jumpToPost('first')" class="btn-small">First Post</button>
                    <button onclick="threadController.jumpToPost('last')" class="btn-small">Last Post</button>
                </div>
                <div class="sort-controls">
                    <select onchange="threadController.handlePostSort(this.value)" id="post-sort">
                        <option value="chronological">Chronological Order</option>
                        <option value="reverse_chronological">Newest First</option>
                        <option value="author">By Author</option>
                    </select>
                </div>
            </div>
        `;
    }

    renderQuickReply(threadId) {
        return `
            <div class="quick-reply">
                <h4>Quick Reply</h4>
                <form id="quick-reply-form" onsubmit="threadController.handleQuickReply(event, ${threadId})">
                    <textarea name="content" placeholder="Write your reply..." rows="4" required></textarea>
                    <div class="quick-reply-actions">
                        <button type="button" onclick="threadController.showReplyForm(${threadId})" class="btn-secondary">Full Editor</button>
                        <button type="submit" class="btn-primary">Post Reply</button>
                    </div>
                </form>
            </div>
        `;
    }

    renderBreadcrumbs(breadcrumbs) {
        return `
            <div class="breadcrumb-nav">
                ${breadcrumbs.map(crumb => 
                    crumb.current 
                        ? `<span class="breadcrumb-current">${UIComponents.escapeHtml(crumb.text)}</span>`
                        : `<a href="${crumb.url}" onclick="threadController.router.navigate('${crumb.url}'); return false;">${UIComponents.escapeHtml(crumb.text)}</a>`
                ).join('<span class="breadcrumb-separator">›</span>')}
            </div>
        `;
    }

    renderPagination(pagination, threadId) {
        const containerId = `pagination-thread-${threadId}`;

        setTimeout(() => {
            PaginationHelper.setupEventDelegation(containerId, (page) => {
                this.showThread(threadId, page);
            });
        }, 0);

        return PaginationHelper.renderPagination(pagination, containerId);
    }

    renderEmptyPostsState() {
        return `
            <div class="empty-state">
                <h3>No posts found</h3>
                <p>This thread appears to be empty.</p>
            </div>
        `;
    }

    showReplyForm(threadId) {
        this.modalManager.createFormModal(
            'Reply to Thread',
            `<textarea name="content" placeholder="Write your reply..." rows="8" required data-autosave="true"></textarea>
             <div class="formatting-help">
                <small>**bold** *italic* \`code\` for basic formatting</small>
             </div>`,
            async (formData) => {
                await this.createPost(threadId, formData.content);
            },
            {
                validation: (data) => this.postService.validatePostData(data)
            }
        );
    }

    async handleQuickReply(event, threadId) {
        event.preventDefault();
        const form = event.target;
        const formData = new FormData(form);
        
        try {
            await this.createPost(threadId, formData.get('content'));
            form.reset();
        } catch (error) {
        }
    }

    async createPost(threadId, content) {
        try {
            const newPost = await this.postService.createPost(threadId, content);
            const currentThread = this.state.getState().currentThread;
            
            if (currentThread) {
                const targetPage = this.threadService.getPageForNewReply(currentThread);
                
                this.notifications.showSuccess('Reply posted successfully!');
                
                setTimeout(() => {
                    this.showThread(threadId, targetPage).then(() => {
                        setTimeout(() => {
                            const posts = document.querySelectorAll('.post');
                            if (posts.length > 0) {
                                const lastPost = posts[posts.length - 1];
                                lastPost.scrollIntoView({ behavior: 'smooth', block: 'center' });
                                lastPost.style.border = '2px solid var(--primary)';
                                setTimeout(() => {
                                    lastPost.style.border = '1px solid var(--border)';
                                }, 3000);
                            }
                        }, 500);
                    });
                }, 100);
            }
            
        } catch (error) {
            this.notifications.showError(error.message);
        }
    }

    async editPost(postId) {
        try {
            const post = await this.postService.getPost(postId);
            
            this.modalManager.createFormModal(
                'Edit Post',
                `<textarea name="content" rows="8" required>${UIComponents.escapeHtml(post.content)}</textarea>`,
                async (formData) => {
                    await this.updatePost(postId, formData.content);
                },
                {
                    validation: (data) => this.postService.validatePostData(data)
                }
            );
        } catch (error) {
            this.notifications.showError(error.message);
        }
    }

    async updatePost(postId, content) {
        try {
            await this.postService.editPost(postId, content);
            this.notifications.showSuccess('Post updated successfully!');
            await this.refreshCurrentThread();
        } catch (error) {
            this.notifications.showError(error.message);
        }
    }

    async deletePost(postId) {
        this.modalManager.createConfirmationModal(
            'Delete Post',
            'Are you sure you want to delete this post? This action cannot be undone.',
            async () => {
                try {
                    await this.postService.deletePost(postId);
                    this.notifications.showSuccess('Post deleted successfully!');
                    setTimeout(() => this.refreshCurrentThread(), 1000);
                } catch (error) {
                    this.notifications.showError(error.message);
                }
            },
            { confirmClass: 'btn-danger' }
        );
    }

    async showPostHistory(postId) {
        try {
            const history = await this.postService.getPostEditHistory(postId);
            
            const historyHtml = history.length === 0 ? '<p>No edit history available.</p>' : 
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
                `).join('');

            this.modalManager.createModal(`
                <h3>Post Edit History</h3>
                <div class="post-history">${historyHtml}</div>
            `);
            
        } catch (error) {
            this.notifications.showError(error.message);
        }
    }

    async quotePost(postId) {
        try {
            const post = await this.postService.getPost(postId);
            const quoteText = this.postService.getQuoteText(post);
            const currentThread = this.state.getState().currentThread;
            
            this.modalManager.createFormModal(
                'Reply with Quote',
                `<textarea name="content" rows="8" required>${quoteText}</textarea>`,
                async (formData) => {
                    await this.createPost(currentThread.thread_id, formData.content);
                },
                {
                    validation: (data) => this.postService.validatePostData(data)
                }
            );
        } catch (error) {
            this.notifications.showError(error.message);
        }
    }

    async toggleThreadLock(threadId, locked) {
        try {
            await this.threadService.lockThread(threadId, locked);
            this.notifications.showSuccess(`Thread ${locked ? 'locked' : 'unlocked'} successfully!`);
            await this.refreshCurrentThread();
        } catch (error) {
            this.notifications.showError(error.message);
        }
    }

    async toggleThreadSticky(threadId, sticky) {
        try {
            await this.threadService.stickyThread(threadId, sticky);
            this.notifications.showSuccess(`Thread ${sticky ? 'stickied' : 'unstickied'} successfully!`);
            await this.refreshCurrentThread();
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
                    
                    const currentThread = this.state.getState().currentThread;
                    if (currentThread && currentThread.board_id) {
                        this.router.navigate(`/boards/${currentThread.board_id}`);
                    } else {
                        this.router.navigate('/');
                    }
                } catch (error) {
                    this.notifications.showError(error.message);
                }
            },
            { confirmClass: 'btn-danger' }
        );
    }

    jumpToPost(position) {
        const posts = document.querySelectorAll('.post');
        if (posts.length === 0) return;

        let targetPost;
        switch (position) {
            case 'first':
                targetPost = posts[0];
                break;
            case 'last':
                targetPost = posts[posts.length - 1];
                break;
            default:
                return;
        }

        targetPost.scrollIntoView({ behavior: 'smooth', block: 'start' });
        targetPost.style.background = 'var(--primary-light)';
        setTimeout(() => {
            targetPost.style.background = '';
        }, 2000);
    }

    async handlePostSort(sortBy) {
        try {
            const posts = this.state.getState().posts;
            const sortedPosts = this.postService.sortPosts(posts, sortBy);
            this.updatePostsList(sortedPosts);
        } catch (error) {
            this.notifications.showError('Sort failed: ' + error.message);
        }
    }

    updatePostsList(posts) {
        const container = document.getElementById('posts-container');
        const user = this.state.getState().user;
        container.innerHTML = this.renderPosts(this.postService.formatPostsForDisplay(posts), user);
    }

    setupThreadInteractions() {
        document.addEventListener('click', (e) => {
            const postLink = e.target.closest('.post-link');
            if (postLink) {
                e.preventDefault();
                const postId = postLink.getAttribute('href').substring(1);
                const post = document.getElementById(postId);
                if (post) {
                    post.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }
            }
        });

        const hash = window.location.hash;
        if (hash.startsWith('#post-')) {
            setTimeout(() => {
                const post = document.querySelector(hash);
                if (post) {
                    post.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }
            }, 500);
        }
    }

    async refreshCurrentThread() {
        const currentThread = this.state.getState().currentThread;
        const currentPage = this.state.getState().currentPage || 1;
        
        if (currentThread) {
            await this.showThread(currentThread.thread_id, currentPage);
        }
    }

    canUserModerateThread(thread, user) {
        return this.threadService.canUserModerateThread(user);
    }

    showErrorState(message) {
        const content = document.getElementById('content');
        content.innerHTML = `
            <div class="error-state">
                <h3>Error Loading Thread</h3>
                <p>${UIComponents.escapeHtml(message)}</p>
                <button onclick="location.reload()" class="btn-primary">Retry</button>
                <button onclick="threadController.router.navigate('/')" class="btn-secondary">Return to Home</button>
            </div>
        `;
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
    }
}