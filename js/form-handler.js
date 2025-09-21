/**
 * Form Handler for the forum application
 * Provides generic form submission, validation, and state management
 */
class FormHandler {
    constructor(api, notificationManager) {
        this.api = api;
        this.notifications = notificationManager;
        this.activeForms = new Map();
        this.setupAutoSave();
    }

    /**
     * Handle form submission with validation and error handling
     * @param {HTMLFormElement} form - Form element
     * @param {Function} submitCallback - Function to handle form submission
     * @param {Object} options - Configuration options
     * @returns {Promise} Submission promise
     */
    async handleSubmit(form, submitCallback, options = {}) {
        const {
            validation = null,
            successMessage = 'Operation completed successfully',
            loadingMessage = 'Processing...',
            autoClose = true,
            preventDuplicates = true,
            clearOnSuccess = false
        } = options;

        // Prevent duplicate submissions
        if (preventDuplicates && this.isFormSubmitting(form)) {
            return;
        }

        try {
            // Mark form as submitting
            this.setFormSubmitting(form, true);
            
            // Get form data
            const formData = new FormData(form);
            const formObject = this.formDataToObject(formData);

            // Run client-side validation
            if (validation) {
                const validationResult = validation(formObject);
                if (!validationResult.isValid) {
                    this.showFormErrors(form, validationResult.errors);
                    return false;
                }
            }

            // Clear existing errors
            this.clearFormErrors(form);

            // Set loading state
            this.setFormLoading(form, true, loadingMessage);

            // Call submission handler
            const result = await submitCallback(formObject, formData, form);

            // Handle success
            if (result !== false) {
                this.notifications.showSuccess(successMessage);
                
                if (clearOnSuccess) {
                    this.clearForm(form);
                }
                
                if (autoClose) {
                    this.closeFormModal(form);
                }
                
                this.clearDraft(form.id);
            }

            return result;

        } catch (error) {
            console.error('Form submission error:', error);
            
            // Handle different error types
            if (error.name === 'ValidationError' && error.details) {
                this.showFormErrors(form, error.details);
            } else {
                this.showFormErrors(form, { 
                    general: [error.message || 'An error occurred while processing your request'] 
                });
            }
            
            return false;

        } finally {
            this.setFormLoading(form, false);
            this.setFormSubmitting(form, false);
        }
    }

    /**
     * Handle authentication forms (login/register)
     * @param {HTMLFormElement} form - Form element
     * @param {string} type - 'login' or 'register'
     * @param {Function} onSuccess - Success callback
     * @returns {Promise} Submission promise
     */
    async handleAuthForm(form, type, onSuccess) {
        const validationRules = type === 'login' 
            ? { username: 'username', password: 'password' }
            : { username: 'username', email: 'email', password: 'password' };

        return this.handleSubmit(form, async (formData) => {
            let result;
            if (type === 'login') {
                result = await this.api.login(formData.username, formData.password);
            } else {
                result = await this.api.register(formData.username, formData.email, formData.password);
            }
            
            if (onSuccess) {
                onSuccess(result);
            }
            
            return result;
        }, {
            validation: (data) => Validation.validateForm(data, validationRules),
            successMessage: type === 'login' ? 'Login successful!' : 'Registration successful!',
            autoClose: false
        });
    }

    /**
     * Handle content creation forms (threads, posts, boards)
     * @param {HTMLFormElement} form - Form element
     * @param {string} type - 'thread', 'post', or 'board'
     * @param {Object} params - Additional parameters
     * @param {Function} onSuccess - Success callback
     * @returns {Promise} Submission promise
     */
    async handleContentForm(form, type, params = {}, onSuccess) {
        const validationRules = this.getContentValidationRules(type);
        
        return this.handleSubmit(form, async (formData) => {
            let result;
            
            switch (type) {
                case 'thread':
                    result = await this.api.createThread(params.boardId, formData.title, formData.content);
                    break;
                case 'post':
                    result = await this.api.createPost(params.threadId, formData.content);
                    break;
                case 'board':
                    result = await this.api.createBoard(formData.name, formData.description);
                    break;
                case 'editPost':
                    result = await this.api.editPost(params.postId, formData.content);
                    break;
                default:
                    throw new Error(`Unknown content type: ${type}`);
            }
            
            if (onSuccess) {
                onSuccess(result);
            }
            
            return result;
        }, {
            validation: (data) => Validation.validateForm(data, validationRules),
            successMessage: this.getContentSuccessMessage(type)
        });
    }

    /**
     * Handle admin action forms (ban, promote, etc.)
     * @param {HTMLFormElement} form - Form element
     * @param {string} action - Admin action type
     * @param {Object} params - Action parameters
     * @param {Function} onSuccess - Success callback
     * @returns {Promise} Submission promise
     */
    async handleAdminForm(form, action, params = {}, onSuccess) {
        return this.handleSubmit(form, async (formData) => {
            let result;
            
            switch (action) {
                case 'ban':
                    result = await this.api.banUser(params.userId, formData.reason);
                    break;
                case 'unban':
                    result = await this.api.unbanUser(params.userId);
                    break;
                case 'promote':
                    result = await this.api.makeUserAdmin(params.userId);
                    break;
                case 'demote':
                    result = await this.api.removeUserAdmin(params.userId);
                    break;
                default:
                    throw new Error(`Unknown admin action: ${action}`);
            }
            
            if (onSuccess) {
                onSuccess(result);
            }
            
            return result;
        }, {
            validation: action === 'ban' ? (data) => Validation.validateForm(data, { reason: 'banReason' }) : null,
            successMessage: this.getAdminSuccessMessage(action)
        });
    }

    /**
     * Convert FormData to plain object
     * @param {FormData} formData - FormData object
     * @returns {Object} Plain object
     */
    formDataToObject(formData) {
        const object = {};
        for (const [key, value] of formData.entries()) {
            if (object[key]) {
                // Handle multiple values for same key
                if (Array.isArray(object[key])) {
                    object[key].push(value);
                } else {
                    object[key] = [object[key], value];
                }
            } else {
                object[key] = value;
            }
        }
        return object;
    }

    /**
     * Show form validation errors
     * @param {HTMLFormElement} form - Form element
     * @param {Object} errors - Error object
     */
    showFormErrors(form, errors) {
        this.clearFormErrors(form);

        Object.entries(errors).forEach(([fieldName, fieldErrors]) => {
            const field = form.querySelector(`[name="${fieldName}"]`);
            
            if (field) {
                field.classList.add('error');
                const errorContainer = this.createErrorContainer(fieldErrors);
                this.insertErrorAfterField(field, errorContainer);
            } else if (fieldName === 'general') {
                const generalError = this.createErrorContainer(fieldErrors, 'general-error');
                form.insertBefore(generalError, form.firstChild);
            }
        });

        // Focus first error field
        const firstErrorField = form.querySelector('.error');
        if (firstErrorField) {
            firstErrorField.focus();
        }
    }

    /**
     * Clear form validation errors
     * @param {HTMLFormElement} form - Form element
     */
    clearFormErrors(form) {
        form.querySelectorAll('.error').forEach(el => el.classList.remove('error'));
        form.querySelectorAll('.error-container, .general-error').forEach(el => el.remove());
    }

    /**
     * Set form loading state
     * @param {HTMLFormElement} form - Form element
     * @param {boolean} loading - Loading state
     * @param {string} message - Loading message
     */
    setFormLoading(form, loading, message = 'Loading...') {
        const submitBtn = form.querySelector('button[type="submit"]');
        const inputs = form.querySelectorAll('input, textarea, select, button');

        if (loading) {
            inputs.forEach(input => input.disabled = true);
            if (submitBtn) {
                submitBtn._originalText = submitBtn.textContent;
                submitBtn.textContent = message;
                submitBtn.classList.add('loading');
            }
        } else {
            inputs.forEach(input => input.disabled = false);
            if (submitBtn) {
                if (submitBtn._originalText) {
                    submitBtn.textContent = submitBtn._originalText;
                }
                submitBtn.classList.remove('loading');
            }
        }
    }

    /**
     * Mark form as submitting to prevent duplicates
     * @param {HTMLFormElement} form - Form element
     * @param {boolean} submitting - Submitting state
     */
    setFormSubmitting(form, submitting) {
        if (submitting) {
            this.activeForms.set(form, Date.now());
        } else {
            this.activeForms.delete(form);
        }
    }

    /**
     * Check if form is currently submitting
     * @param {HTMLFormElement} form - Form element
     * @returns {boolean} True if submitting
     */
    isFormSubmitting(form) {
        return this.activeForms.has(form);
    }

    /**
     * Clear form fields
     * @param {HTMLFormElement} form - Form element
     */
    clearForm(form) {
        form.reset();
        this.clearFormErrors(form);
    }

    /**
     * Close modal containing the form
     * @param {HTMLFormElement} form - Form element
     */
    closeFormModal(form) {
        const modal = form.closest('.modal');
        if (modal) {
            modal.remove();
        }
    }

    /**
     * Create error container element
     * @param {Array|string} errors - Error messages
     * @param {string} className - CSS class
     * @returns {HTMLElement} Error container
     */
    createErrorContainer(errors, className = 'error-container') {
        const container = document.createElement('div');
        container.className = className;
        
        const errorArray = Array.isArray(errors) ? errors : [errors];
        errorArray.forEach(error => {
            const errorEl = document.createElement('div');
            errorEl.className = 'error-message';
            errorEl.textContent = error;
            container.appendChild(errorEl);
        });

        return container;
    }

    /**
     * Insert error container after form field
     * @param {HTMLElement} field - Form field
     * @param {HTMLElement} errorContainer - Error container
     */
    insertErrorAfterField(field, errorContainer) {
        const wrapper = field.parentElement;
        if (wrapper.nextSibling) {
            wrapper.parentNode.insertBefore(errorContainer, wrapper.nextSibling);
        } else {
            wrapper.parentNode.appendChild(errorContainer);
        }
    }

    /**
     * Get validation rules for content types
     * @param {string} type - Content type
     * @returns {Object} Validation rules
     */
    getContentValidationRules(type) {
        switch (type) {
            case 'thread':
                return { title: 'threadTitle', content: 'postContent' };
            case 'post':
            case 'editPost':
                return { content: 'postContent' };
            case 'board':
                return { name: 'boardName', description: 'boardDescription' };
            default:
                return {};
        }
    }

    /**
     * Get success message for content types
     * @param {string} type - Content type
     * @returns {string} Success message
     */
    getContentSuccessMessage(type) {
        switch (type) {
            case 'thread':
                return 'Thread created successfully!';
            case 'post':
                return 'Reply posted successfully!';
            case 'editPost':
                return 'Post updated successfully!';
            case 'board':
                return 'Board created successfully!';
            default:
                return 'Operation completed successfully!';
        }
    }

    /**
     * Get success message for admin actions
     * @param {string} action - Admin action
     * @returns {string} Success message
     */
    getAdminSuccessMessage(action) {
        switch (action) {
            case 'ban':
                return 'User banned successfully!';
            case 'unban':
                return 'User unbanned successfully!';
            case 'promote':
                return 'User promoted to admin successfully!';
            case 'demote':
                return 'Admin privileges removed successfully!';
            default:
                return 'Admin action completed successfully!';
        }
    }

    /**
     * Setup auto-save functionality
     */
    setupAutoSave() {
        let autoSaveTimer;
        
        document.addEventListener('input', (e) => {
            if (e.target.matches('textarea[data-autosave], input[data-autosave]')) {
                clearTimeout(autoSaveTimer);
                autoSaveTimer = setTimeout(() => {
                    this.saveDraft(e.target);
                }, 1000);
            }
        });
    }

    /**
     * Save form field value as draft
     * @param {HTMLElement} field - Form field
     */
    saveDraft(field) {
        const form = field.closest('form');
        if (!form || !form.id) return;

        const draftKey = `${form.id}_${field.name}`;
        localStorage.setItem(`forum_draft_${draftKey}`, field.value);
    }

    /**
     * Load draft value for form field
     * @param {string} formId - Form ID
     * @param {string} fieldName - Field name
     * @returns {string} Draft value
     */
    loadDraft(formId, fieldName) {
        const draftKey = `${formId}_${fieldName}`;
        return localStorage.getItem(`forum_draft_${draftKey}`) || '';
    }

    /**
     * Clear all drafts for a form
     * @param {string} formId - Form ID
     */
    clearDraft(formId) {
        if (!formId) return;
        
        Object.keys(localStorage).forEach(key => {
            if (key.startsWith(`forum_draft_${formId}_`)) {
                localStorage.removeItem(key);
            }
        });
    }

    /**
     * Setup form with auto-save and draft loading
     * @param {HTMLFormElement} form - Form element
     */
    setupAutoSaveForm(form) {
        if (!form.id) {
            form.id = `form_${Date.now()}`;
        }

        // Load drafts for existing fields
        const fields = form.querySelectorAll('textarea, input[type="text"]');
        fields.forEach(field => {
            if (field.name) {
                const draft = this.loadDraft(form.id, field.name);
                if (draft && !field.value) {
                    field.value = draft;
                }
                field.setAttribute('data-autosave', 'true');
            }
        });
    }

    /**
     * Cleanup form handler
     */
    destroy() {
        this.activeForms.clear();
    }
}