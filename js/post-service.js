class PostService {
    constructor(api, notifications) {
        this.api = api;
        this.notifications = notifications;
    }

    async getPost(postId) {
        try {
            const post = await this.api.getPost(postId);
            if (!post) {
                throw new Error('Post not found');
            }
            return this.sanitizePost(post);
        } catch (error) {
            throw new Error(`Failed to load post: ${error.message}`);
        }
    }

    async getPosts(threadId, page = 1, perPage = 20) {
        try {
            const posts = await this.api.getPosts(threadId, page, perPage);
            return Array.isArray(posts) ? posts.map(post => this.sanitizePost(post)) : [];
        } catch (error) {
            throw new Error(`Failed to load posts: ${error.message}`);
        }
    }

    async createPost(threadId, content) {
        const validation = Validation.validatePostContent(content);
        if (!validation.isValid) {
            const error = new Error('Validation failed');
            error.name = 'ValidationError';
            error.details = { content: validation.errors };
            throw error;
        }

        try {
            const post = await this.api.createPost(threadId, content);
            if (!post) {
                throw new Error('Failed to create post - no response from server');
            }
            return this.sanitizePost(post);
        } catch (error) {
            if (error.message.includes('rate limit')) {
                throw new Error('You are posting too frequently. Please wait a moment.');
            }
            if (error.message.includes('locked')) {
                throw new Error('This thread is locked and cannot accept new posts.');
            }
            if (error.message.includes('not found')) {
                throw new Error('Thread not found. It may have been deleted.');
            }
            throw error;
        }
    }

    async editPost(postId, content) {
        const validation = Validation.validatePostContent(content);
        if (!validation.isValid) {
            const error = new Error('Validation failed');
            error.name = 'ValidationError';
            error.details = { content: validation.errors };
            throw error;
        }

        try {
            const post = await this.api.editPost(postId, content);
            if (!post) {
                throw new Error('Failed to update post');
            }
            return this.sanitizePost(post);
        } catch (error) {
            if (error.message.includes('permission') || error.message.includes('forbidden')) {
                throw new Error('You do not have permission to edit this post');
            }
            if (error.message.includes('locked')) {
                throw new Error('Cannot edit posts in locked thread');
            }
            if (error.message.includes('not found')) {
                throw new Error('Post not found or has been deleted');
            }
            throw error;
        }
    }

    async deletePost(postId) {
        try {
            await this.api.deletePost(postId);
            return true;
        } catch (error) {
            if (error.message.includes('permission') || error.message.includes('forbidden')) {
                throw new Error('You do not have permission to delete this post');
            }
            if (error.message.includes('locked')) {
                throw new Error('Cannot delete posts in locked thread');
            }
            if (error.message.includes('not found')) {
                throw new Error('Post not found or already deleted');
            }
            if (error.message.includes('already been deleted')) {
                throw new Error('Post has already been deleted');
            }
            throw error;
        }
    }

    async restorePost(postId) {
        try {
            await this.api.restorePost(postId);
            return true;
        } catch (error) {
            if (error.message.includes('permission')) {
                throw new Error('You do not have permission to restore this post');
            }
            if (error.message.includes('not found')) {
                throw new Error('Deleted post not found or cannot be restored');
            }
            throw error;
        }
    }

    async getPostEditHistory(postId) {
        try {
            const history = await this.api.getPostEditHistory(postId);
            return Array.isArray(history) ? history : [];
        } catch (error) {
            if (error.message.includes('permission')) {
                throw new Error('You do not have permission to view edit history');
            }
            throw new Error(`Failed to load edit history: ${error.message}`);
        }
    }

    sanitizePost(post) {
        return {
            post_id: post.post_id,
            thread_id: post.thread_id,
            user_id: post.user_id,
            username: post.username || 'Unknown',
            content: post.content || '',
            timestamp: post.timestamp || 0,
            edited: Boolean(post.edited),
            edit_count: post.edit_count || 0,
            edited_at: post.edited_at || null,
            edited_by: post.edited_by || null
        };
    }

    canUserEditPost(post, user) {
        if (!user) return false;
        return post.user_id === user.user_id || user.is_admin;
    }

    canUserDeletePost(post, user) {
        if (!user) return false;
        return post.user_id === user.user_id || user.is_admin;
    }

    canUserViewEditHistory(post, user) {
        if (!user) return false;
        return post.user_id === user.user_id || user.is_admin;
    }

    formatPostForDisplay(post) {
        return {
            ...post,
            formattedDate: UIComponents.formatDate(post.timestamp),
            formattedEditDate: post.edited_at ? UIComponents.formatDate(post.edited_at) : null,
            formattedContent: this.formatPostContent(post.content),
            isEdited: Boolean(post.edited),
            editInfo: post.edited ? this.getEditInfo(post) : null
        };
    }

    formatPostsForDisplay(posts) {
        return posts.map(post => this.formatPostForDisplay(post));
    }

    formatPostContent(content) {
        if (!content) return '';
        
        return UIComponents.escapeHtml(content)
            .replace(/\n/g, '<br>')
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/`(.*?)`/g, '<code>$1</code>')
            .replace(/https?:\/\/[^\s]+/g, '<a href="$&" target="_blank" rel="noopener">$&</a>');
    }

    getEditInfo(post) {
        if (!post.edited) return null;

        const info = {
            count: post.edit_count || 1,
            lastEditDate: post.edited_at
        };

        if (post.edit_count === 1) {
            info.text = 'Edited once';
        } else {
            info.text = `Edited ${post.edit_count} times`;
        }

        if (post.edited_at) {
            info.text += ` • Last edited ${UIComponents.formatDate(post.edited_at)}`;
        }

        return info;
    }

    validatePostData(data) {
        const errors = {};

        if (!data.content || data.content.trim().length === 0) {
            errors.content = ['Post content is required'];
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

    getPostMetrics(posts) {
        const total = posts.length;
        const edited = posts.filter(p => p.edited).length;
        const totalEdits = posts.reduce((sum, p) => sum + (p.edit_count || 0), 0);
        
        const authors = new Set(posts.map(p => p.username)).size;
        const averageLength = total > 0 
            ? Math.round(posts.reduce((sum, p) => sum + (p.content?.length || 0), 0) / total)
            : 0;

        return {
            total,
            edited,
            totalEdits,
            uniqueAuthors: authors,
            averageLength,
            editPercentage: total > 0 ? Math.round((edited / total) * 100) : 0
        };
    }

    sortPosts(posts, sortBy = 'chronological') {
        const sortedPosts = [...posts];

        switch (sortBy) {
            case 'chronological':
                return sortedPosts.sort((a, b) => a.timestamp - b.timestamp);
            case 'reverse_chronological':
                return sortedPosts.sort((a, b) => b.timestamp - a.timestamp);
            case 'author':
                return sortedPosts.sort((a, b) => a.username.localeCompare(b.username));
            case 'length':
                return sortedPosts.sort((a, b) => (b.content?.length || 0) - (a.content?.length || 0));
            case 'most_edited':
                return sortedPosts.sort((a, b) => (b.edit_count || 0) - (a.edit_count || 0));
            default:
                return sortedPosts.sort((a, b) => a.timestamp - b.timestamp);
        }
    }

    filterPosts(posts, filter = {}) {
        let filtered = [...posts];

        if (filter.author) {
            filtered = filtered.filter(post =>
                post.username.toLowerCase().includes(filter.author.toLowerCase())
            );
        }

        if (filter.search) {
            const searchTerm = filter.search.toLowerCase();
            filtered = filtered.filter(post =>
                post.content.toLowerCase().includes(searchTerm)
            );
        }

        if (filter.edited !== undefined) {
            filtered = filtered.filter(post => Boolean(post.edited) === filter.edited);
        }

        if (filter.dateRange) {
            const { start, end } = filter.dateRange;
            filtered = filtered.filter(post => {
                const postDate = post.timestamp;
                return postDate >= start && postDate <= end;
            });
        }

        if (filter.minLength !== undefined) {
            filtered = filtered.filter(post => (post.content?.length || 0) >= filter.minLength);
        }

        if (filter.maxLength !== undefined) {
            filtered = filtered.filter(post => (post.content?.length || 0) <= filter.maxLength);
        }

        return filtered;
    }

    async searchPosts(query, options = {}) {
        const {
            threadId = null,
            page = 1,
            perPage = 20,
            sortBy = 'relevance'
        } = options;

        const validation = Validation.validateSearchQuery(query);
        if (!validation.isValid) {
            throw new Error(validation.errors[0]);
        }

        try {
            let searchUrl = `/api/search?q=${encodeURIComponent(query)}&type=posts&page=${page}&per_page=${perPage}`;
            if (threadId) {
                searchUrl += `&thread_id=${threadId}`;
            }

            const results = await this.api.request(searchUrl);
            return results.posts || [];
        } catch (error) {
            throw new Error(`Search failed: ${error.message}`);
        }
    }

    getQuoteText(post) {
        const author = post.username || 'Unknown';
        const date = UIComponents.formatDate(post.timestamp);
        const content = post.content.split('\n').map(line => `> ${line}`).join('\n');
        
        return `**${author}** wrote on ${date}:\n${content}\n\n`;
    }

    detectMentions(content) {
        const mentionRegex = /@(\w+)/g;
        const mentions = [];
        let match;

        while ((match = mentionRegex.exec(content)) !== null) {
            mentions.push({
                username: match[1],
                position: match.index,
                length: match[0].length
            });
        }

        return mentions;
    }

    highlightMentions(content, currentUser) {
        const mentionRegex = /@(\w+)/g;
        
        return content.replace(mentionRegex, (match, username) => {
            const isCurrentUser = currentUser && username.toLowerCase() === currentUser.username.toLowerCase();
            const className = isCurrentUser ? 'mention mention-self' : 'mention';
            return `<span class="${className}">${match}</span>`;
        });
    }

    calculateReadingTime(content) {
        const wordsPerMinute = 200;
        const words = content.trim().split(/\s+/).length;
        const minutes = Math.ceil(words / wordsPerMinute);
        
        return {
            words,
            minutes,
            text: minutes === 1 ? '1 min read' : `${minutes} min read`
        };
    }

    getPostAnchor(postId) {
        return `#post-${postId}`;
    }

    generatePostPermalink(threadId, postId) {
        return `/threads/${threadId}${this.getPostAnchor(postId)}`;
    }

    truncateContent(content, maxLength = 200) {
        if (!content || content.length <= maxLength) {
            return content;
        }

        const truncated = content.substring(0, maxLength);
        const lastSpace = truncated.lastIndexOf(' ');
        
        return lastSpace > 0 
            ? truncated.substring(0, lastSpace) + '...'
            : truncated + '...';
    }

    async getPostContext(postId) {
        try {
            const post = await this.getPost(postId);
            const allPosts = await this.getPosts(post.thread_id);
            
            const postIndex = allPosts.findIndex(p => p.post_id === postId);
            const previousPost = postIndex > 0 ? allPosts[postIndex - 1] : null;
            const nextPost = postIndex < allPosts.length - 1 ? allPosts[postIndex + 1] : null;

            return {
                post,
                previous: previousPost,
                next: nextPost,
                position: postIndex + 1,
                total: allPosts.length
            };
        } catch (error) {
            throw new Error(`Failed to get post context: ${error.message}`);
        }
    }
}