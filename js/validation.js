/**
 * Client-side validation utilities for the forum application
 * Provides consistent validation rules matching the backend models
 */
class Validation {
    /**
     * Validate username according to forum rules
     * @param {string} username - The username to validate
     * @returns {Object} {isValid: boolean, errors: string[]}
     */
    static validateUsername(username) {
        const errors = [];
        
        if (!username || typeof username !== 'string') {
            errors.push('Username is required');
            return { isValid: false, errors };
        }
        
        const trimmed = username.trim();
        
        if (trimmed.length < 3) {
            errors.push('Username must be at least 3 characters long');
        }
        
        if (trimmed.length > 50) {
            errors.push('Username must be no more than 50 characters long');
        }
        
        // Check for valid characters (letters, numbers, hyphens, underscores)
        if (!/^[a-zA-Z0-9_-]+$/.test(trimmed)) {
            errors.push('Username can only contain letters, numbers, hyphens, and underscores');
        }
        
        return {
            isValid: errors.length === 0,
            errors
        };
    }
    
    /**
     * Validate email address
     * @param {string} email - The email to validate
     * @returns {Object} {isValid: boolean, errors: string[]}
     */
    static validateEmail(email) {
        const errors = [];
        
        if (!email || typeof email !== 'string') {
            errors.push('Email is required');
            return { isValid: false, errors };
        }
        
        const trimmed = email.trim();
        
        // Basic email regex (not perfect but good enough for client-side)
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        
        if (!emailRegex.test(trimmed)) {
            errors.push('Please enter a valid email address');
        }
        
        if (trimmed.length > 255) {
            errors.push('Email address is too long');
        }
        
        return {
            isValid: errors.length === 0,
            errors
        };
    }
    
    /**
     * Validate password according to security requirements
     * @param {string} password - The password to validate
     * @returns {Object} {isValid: boolean, errors: string[]}
     */
    static validatePassword(password) {
        const errors = [];
        
        if (!password || typeof password !== 'string') {
            errors.push('Password is required');
            return { isValid: false, errors };
        }
        
        if (password.length < 10) {
            errors.push('Password must be at least 10 characters long');
        }
        
        if (!/[A-Z]/.test(password)) {
            errors.push('Password must contain at least one uppercase letter');
        }
        
        if (!/[a-z]/.test(password)) {
            errors.push('Password must contain at least one lowercase letter');
        }
        
        if (!/\d/.test(password)) {
            errors.push('Password must contain at least one number');
        }
        
        if (!/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)) {
            errors.push('Password must contain at least one special character');
        }
        
        return {
            isValid: errors.length === 0,
            errors
        };
    }
    
    /**
     * Validate board name
     * @param {string} name - The board name to validate
     * @returns {Object} {isValid: boolean, errors: string[]}
     */
    static validateBoardName(name) {
        const errors = [];
        
        if (!name || typeof name !== 'string') {
            errors.push('Board name is required');
            return { isValid: false, errors };
        }
        
        const trimmed = name.trim();
        
        if (trimmed.length < 2) {
            errors.push('Board name must be at least 2 characters long');
        }
        
        if (trimmed.length > 100) {
            errors.push('Board name must be no more than 100 characters long');
        }
        
        return {
            isValid: errors.length === 0,
            errors
        };
    }
    
    /**
     * Validate board description
     * @param {string} description - The board description to validate
     * @returns {Object} {isValid: boolean, errors: string[]}
     */
    static validateBoardDescription(description) {
        const errors = [];
        
        if (!description || typeof description !== 'string') {
            errors.push('Board description is required');
            return { isValid: false, errors };
        }
        
        const trimmed = description.trim();
        
        if (trimmed.length < 1) {
            errors.push('Board description cannot be empty');
        }
        
        if (trimmed.length > 1000) {
            errors.push('Board description is too long (maximum 1000 characters)');
        }
        
        return {
            isValid: errors.length === 0,
            errors
        };
    }
    
    /**
     * Validate thread title
     * @param {string} title - The thread title to validate
     * @returns {Object} {isValid: boolean, errors: string[]}
     */
    static validateThreadTitle(title) {
        const errors = [];
        
        if (!title || typeof title !== 'string') {
            errors.push('Thread title is required');
            return { isValid: false, errors };
        }
        
        const trimmed = title.trim();
        
        if (trimmed.length < 3) {
            errors.push('Thread title must be at least 3 characters long');
        }
        
        if (trimmed.length > 255) {
            errors.push('Thread title must be no more than 255 characters long');
        }
        
        return {
            isValid: errors.length === 0,
            errors
        };
    }
    
    /**
     * Validate post content (for both thread content and reply content)
     * @param {string} content - The content to validate
     * @returns {Object} {isValid: boolean, errors: string[]}
     */
    static validatePostContent(content) {
        const errors = [];
        
        if (!content || typeof content !== 'string') {
            errors.push('Content is required');
            return { isValid: false, errors };
        }
        
        const trimmed = content.trim();
        
        if (trimmed.length < 1) {
            errors.push('Content cannot be empty');
        }
        
        if (trimmed.length > 50000) {
            errors.push('Content is too long (maximum 50,000 characters)');
        }
        
        return {
            isValid: errors.length === 0,
            errors
        };
    }
    
    /**
     * Validate search query
     * @param {string} query - The search query to validate
     * @returns {Object} {isValid: boolean, errors: string[]}
     */
    static validateSearchQuery(query) {
        const errors = [];
        
        if (!query || typeof query !== 'string') {
            errors.push('Search query is required');
            return { isValid: false, errors };
        }
        
        const trimmed = query.trim();
        
        if (trimmed.length < 3) {
            errors.push('Search query must be at least 3 characters long');
        }
        
        if (trimmed.length > 100) {
            errors.push('Search query is too long (maximum 100 characters)');
        }
        
        return {
            isValid: errors.length === 0,
            errors
        };
    }
    
    /**
     * Validate ban reason
     * @param {string} reason - The ban reason to validate
     * @returns {Object} {isValid: boolean, errors: string[]}
     */
    static validateBanReason(reason) {
        const errors = [];
        
        if (!reason || typeof reason !== 'string') {
            errors.push('Ban reason is required');
            return { isValid: false, errors };
        }
        
        const trimmed = reason.trim();
        
        if (trimmed.length < 3) {
            errors.push('Ban reason must be at least 3 characters long');
        }
        
        if (trimmed.length > 500) {
            errors.push('Ban reason is too long (maximum 500 characters)');
        }
        
        return {
            isValid: errors.length === 0,
            errors
        };
    }
    
    /**
     * Validate a form with multiple fields
     * @param {Object} formData - Object containing field names and values
     * @param {Object} rules - Object mapping field names to validation function names
     * @returns {Object} {isValid: boolean, errors: Object}
     */
    static validateForm(formData, rules) {
        const allErrors = {};
        let hasErrors = false;
        
        for (const [fieldName, validationRule] of Object.entries(rules)) {
            const value = formData[fieldName];
            let result;
            
            switch (validationRule) {
                case 'username':
                    result = this.validateUsername(value);
                    break;
                case 'email':
                    result = this.validateEmail(value);
                    break;
                case 'password':
                    result = this.validatePassword(value);
                    break;
                case 'boardName':
                    result = this.validateBoardName(value);
                    break;
                case 'boardDescription':
                    result = this.validateBoardDescription(value);
                    break;
                case 'threadTitle':
                    result = this.validateThreadTitle(value);
                    break;
                case 'postContent':
                    result = this.validatePostContent(value);
                    break;
                case 'searchQuery':
                    result = this.validateSearchQuery(value);
                    break;
                case 'banReason':
                    result = this.validateBanReason(value);
                    break;
                default:
                    result = { isValid: true, errors: [] };
            }
            
            if (!result.isValid) {
                allErrors[fieldName] = result.errors;
                hasErrors = true;
            }
        }
        
        return {
            isValid: !hasErrors,
            errors: allErrors
        };
    }
    
    /**
     * Sanitize content for display (basic XSS prevention)
     * @param {string} content - The content to sanitize
     * @returns {string} Sanitized content
     */
    static sanitizeContent(content) {
        if (!content || typeof content !== 'string') {
            return '';
        }
        
        return content
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
    }
    
    /**
     * Check if a string contains only safe characters for URLs
     * @param {string} input - The input to check
     * @returns {boolean} True if safe for URL use
     */
    static isSafeForUrl(input) {
        if (!input || typeof input !== 'string') {
            return false;
        }
        
        return /^[a-zA-Z0-9_-]+$/.test(input);
    }
    
    /**
     * Validate pagination parameters
     * @param {number} page - Page number
     * @param {number} perPage - Items per page
     * @returns {Object} {isValid: boolean, errors: string[], sanitized: Object}
     */
    static validatePagination(page, perPage) {
        const errors = [];
        let sanitizedPage = 1;
        let sanitizedPerPage = 20;
        
        // Validate page number
        if (page !== undefined && page !== null) {
            const pageNum = parseInt(page, 10);
            if (isNaN(pageNum) || pageNum < 1) {
                errors.push('Page number must be a positive integer');
            } else if (pageNum > 1000) {
                errors.push('Page number is too large');
            } else {
                sanitizedPage = pageNum;
            }
        }
        
        // Validate per page
        if (perPage !== undefined && perPage !== null) {
            const perPageNum = parseInt(perPage, 10);
            if (isNaN(perPageNum) || perPageNum < 1) {
                errors.push('Items per page must be a positive integer');
            } else if (perPageNum > 100) {
                errors.push('Items per page cannot exceed 100');
            } else {
                sanitizedPerPage = perPageNum;
            }
        }
        
        return {
            isValid: errors.length === 0,
            errors,
            sanitized: {
                page: sanitizedPage,
                perPage: sanitizedPerPage
            }
        };
    }
}