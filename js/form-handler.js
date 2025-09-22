class FormHandler {
    constructor(api, notificationManager) {
        this.api = api;
        this.notifications = notificationManager;
        this.activeForms = new Map();
        this.setupAutoSave();
    }

    async handleSubmit(form, submitCallback, options = {}) {
        const {
            validation = null,
            successMessage = 'Operation completed successfully',
            loadingMessage = 'Processing...',
            autoClose = true,
            preventDuplicates = true,
            clearOnSuccess = false
        } = options;

        if (preventDuplicates && this.isFormSubmitting(form)) {
            return;
        }

        try {
            this.setFormSubmitting(form, true);
            
            const formData = new FormData(form);
            const formObject = this.formDataToObject(formData);

            if (validation) {
                const validationResult = validation(formObject);
                if (!validationResult.isValid) {
                    this.showFormErrors(form, validationResult.errors);
                    return false;
                }
            }

            this.clearFormErrors(form);

            this.setFormLoading(form, true, loadingMessage);

            const result = await submitCallback(formObject, formData, form);

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

    formDataToObject(formData) {
        const object = {};
        for (const [key, value] of formData.entries()) {
            if (object[key]) {
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

        const firstErrorField = form.querySelector('.error');
        if (firstErrorField) {
            firstErrorField.focus();
        }
    }

    clearFormErrors(form) {
        form.querySelectorAll('.error').forEach(el => el.classList.remove('error'));
        form.querySelectorAll('.error-container, .general-error').forEach(el => el.remove());
    }

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

    setFormSubmitting(form, submitting) {
        if (submitting) {
            this.activeForms.set(form, Date.now());
        } else {
            this.activeForms.delete(form);
        }
    }

    isFormSubmitting(form) {
        return this.activeForms.has(form);
    }

    clearForm(form) {
        form.reset();
        this.clearFormErrors(form);
    }

    closeFormModal(form) {
        const modal = form.closest('.modal');
        if (modal) {
            modal.remove();
        }
    }

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

    insertErrorAfterField(field, errorContainer) {
        const wrapper = field.parentElement;
        if (wrapper.nextSibling) {
            wrapper.parentNode.insertBefore(errorContainer, wrapper.nextSibling);
        } else {
            wrapper.parentNode.appendChild(errorContainer);
        }
    }

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

    saveDraft(field) {
        const form = field.closest('form');
        if (!form || !form.id) return;

        const draftKey = `${form.id}_${field.name}`;
        localStorage.setItem(`forum_draft_${draftKey}`, field.value);
    }

    loadDraft(formId, fieldName) {
        const draftKey = `${formId}_${fieldName}`;
        return localStorage.getItem(`forum_draft_${draftKey}`) || '';
    }

    clearDraft(formId) {
        if (!formId) return;
        
        Object.keys(localStorage).forEach(key => {
            if (key.startsWith(`forum_draft_${formId}_`)) {
                localStorage.removeItem(key);
            }
        });
    }

    setupAutoSaveForm(form) {
        if (!form.id) {
            form.id = `form_${Date.now()}`;
        }

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

    destroy() {
        this.activeForms.clear();
    }
}