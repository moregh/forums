/**
 * Modal Manager for the forum application
 * Provides centralized modal creation, management, and lifecycle handling
 */
class ModalManager {
    constructor() {
        this.activeModals = new Set();
        this.modalCounter = 0;
        this.setupGlobalEventListeners();
        this.setupKeyboardHandlers();
    }

    /**
     * Create a basic modal with custom content
     * @param {string} content - HTML content for the modal
     * @param {Object} options - Configuration options
     * @returns {HTMLElement} The modal element
     */
    createModal(content, options = {}) {
        const {
            className = 'modal',
            backdrop = true,
            keyboard = true,
            focus = true,
            width = 'auto',
            height = 'auto',
            closeButton = true,
            onShow = null,
            onHide = null,
            onDestroy = null
        } = options;

        const modalId = `modal-${++this.modalCounter}`;
        
        // Create modal structure
        const modal = document.createElement('div');
        modal.className = className;
        modal.id = modalId;
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-labelledby', `${modalId}-title`);

        const modalContent = document.createElement('div');
        modalContent.className = 'modal-content';
        
        if (width !== 'auto') modalContent.style.width = width;
        if (height !== 'auto') modalContent.style.height = height;

        // Add close button if requested
        if (closeButton) {
            const closeBtn = document.createElement('span');
            closeBtn.className = 'close';
            closeBtn.innerHTML = '&times;';
            closeBtn.setAttribute('aria-label', 'Close modal');
            closeBtn.addEventListener('click', () => this.closeModal(modal));
            modalContent.appendChild(closeBtn);
        }

        // Add content
        const contentContainer = document.createElement('div');
        contentContainer.innerHTML = content;
        modalContent.appendChild(contentContainer);

        modal.appendChild(modalContent);

        // Store modal configuration
        modal._modalConfig = {
            backdrop,
            keyboard,
            onShow,
            onHide,
            onDestroy
        };

        // Set up backdrop click handling
        if (backdrop) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    this.closeModal(modal);
                }
            });
        }

        // Add to active modals tracking
        this.activeModals.add(modal);

        // Show the modal
        this.showModal(modal, focus);

        // Call onShow callback
        if (onShow) {
            onShow(modal);
        }

        return modal;
    }

    /**
     * Create a form modal with validation and submission handling
     * @param {string} title - Modal title
     * @param {string} formContent - HTML content for the form
     * @param {Function} onSubmit - Form submission handler
     * @param {Object} options - Configuration options
     * @returns {HTMLElement} The modal element
     */
    createFormModal(title, formContent, onSubmit, options = {}) {
        const {
            submitText = 'Submit',
            cancelText = 'Cancel',
            submitClass = 'btn-primary',
            cancelClass = 'btn-secondary',
            validation = null,
            autoClose = true,
            ...modalOptions
        } = options;

        const formId = `form-${this.modalCounter + 1}`;
        
        const content = `
            <div class="modal-header">
                <h3 id="modal-${this.modalCounter + 1}-title">${title}</h3>
            </div>
            <form id="${formId}" class="modal-form">
                ${formContent}
                <div class="modal-actions">
                    <button type="button" class="btn ${cancelClass}" data-action="cancel">
                        ${cancelText}
                    </button>
                    <button type="submit" class="btn ${submitClass}">
                        ${submitText}
                    </button>
                </div>
            </form>
        `;

        const modal = this.createModal(content, modalOptions);
        const form = modal.querySelector(`#${formId}`);
        const cancelBtn = modal.querySelector('[data-action="cancel"]');

        // Handle form submission
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(form);
            const formObject = Object.fromEntries(formData.entries());

            // Run validation if provided
            if (validation) {
                const validationResult = validation(formObject);
                if (!validationResult.isValid) {
                    this.showFormErrors(form, validationResult.errors);
                    return;
                }
            }

            // Clear any existing errors
            this.clearFormErrors(form);

            try {
                // Disable form during submission
                this.setFormLoading(form, true);
                
                const result = await onSubmit(formObject, form, modal);
                
                if (result !== false && autoClose) {
                    this.closeModal(modal);
                }
            } catch (error) {
                this.showFormErrors(form, { general: [error.message] });
            } finally {
                this.setFormLoading(form, false);
            }
        });

        // Handle cancel button
        cancelBtn.addEventListener('click', () => {
            this.closeModal(modal);
        });

        // Focus first input
        const firstInput = form.querySelector('input, textarea, select');
        if (firstInput) {
            setTimeout(() => firstInput.focus(), 100);
        }

        return modal;
    }

    /**
     * Create a confirmation modal
     * @param {string} title - Modal title
     * @param {string} message - Confirmation message
     * @param {Function} onConfirm - Confirmation handler
     * @param {Object} options - Configuration options
     * @returns {HTMLElement} The modal element
     */
    createConfirmationModal(title, message, onConfirm, options = {}) {
        const {
            confirmText = 'Confirm',
            cancelText = 'Cancel',
            confirmClass = 'btn-danger',
            cancelClass = 'btn-secondary',
            icon = null,
            autoClose = true,
            ...modalOptions
        } = options;

        const iconHtml = icon ? `<div class="modal-icon">${icon}</div>` : '';
        
        const content = `
            <div class="modal-header">
                <h3 id="modal-${this.modalCounter + 1}-title">${title}</h3>
            </div>
            <div class="modal-body">
                ${iconHtml}
                <p>${message}</p>
            </div>
            <div class="modal-actions">
                <button type="button" class="btn ${cancelClass}" data-action="cancel">
                    ${cancelText}
                </button>
                <button type="button" class="btn ${confirmClass}" data-action="confirm">
                    ${confirmText}
                </button>
            </div>
        `;

        const modal = this.createModal(content, modalOptions);
        const confirmBtn = modal.querySelector('[data-action="confirm"]');
        const cancelBtn = modal.querySelector('[data-action="cancel"]');

        // Handle confirmation
        confirmBtn.addEventListener('click', async () => {
            try {
                confirmBtn.disabled = true;
                confirmBtn.textContent = 'Processing...';
                
                const result = await onConfirm(modal);
                
                if (result !== false && autoClose) {
                    this.closeModal(modal);
                }
            } catch (error) {
                console.error('Confirmation error:', error);
                // Could show error in modal or close it
            } finally {
                confirmBtn.disabled = false;
                confirmBtn.textContent = confirmText;
            }
        });

        // Handle cancel
        cancelBtn.addEventListener('click', () => {
            this.closeModal(modal);
        });

        // Focus confirm button by default
        setTimeout(() => confirmBtn.focus(), 100);

        return modal;
    }

    /**
     * Create an alert modal (information only)
     * @param {string} title - Modal title
     * @param {string} message - Alert message
     * @param {Object} options - Configuration options
     * @returns {HTMLElement} The modal element
     */
    createAlertModal(title, message, options = {}) {
        const {
            okText = 'OK',
            okClass = 'btn-primary',
            icon = null,
            ...modalOptions
        } = options;

        const iconHtml = icon ? `<div class="modal-icon">${icon}</div>` : '';
        
        const content = `
            <div class="modal-header">
                <h3 id="modal-${this.modalCounter + 1}-title">${title}</h3>
            </div>
            <div class="modal-body">
                ${iconHtml}
                <p>${message}</p>
            </div>
            <div class="modal-actions">
                <button type="button" class="btn ${okClass}" data-action="ok">
                    ${okText}
                </button>
            </div>
        `;

        const modal = this.createModal(content, modalOptions);
        const okBtn = modal.querySelector('[data-action="ok"]');

        okBtn.addEventListener('click', () => {
            this.closeModal(modal);
        });

        // Focus OK button
        setTimeout(() => okBtn.focus(), 100);

        return modal;
    }

    /**
     * Create a loading modal
     * @param {string} message - Loading message
     * @param {Object} options - Configuration options
     * @returns {HTMLElement} The modal element
     */
    createLoadingModal(message = 'Loading...', options = {}) {
        const {
            spinner = true,
            backdrop = false,
            keyboard = false,
            closeButton = false,
            ...modalOptions
        } = options;

        const spinnerHtml = spinner ? '<div class="loading-spinner"></div>' : '';
        
        const content = `
            <div class="modal-body loading-modal">
                ${spinnerHtml}
                <p>${message}</p>
            </div>
        `;

        return this.createModal(content, {
            backdrop,
            keyboard,
            closeButton,
            ...modalOptions
        });
    }

    /**
     * Show a modal
     * @param {HTMLElement} modal - Modal element
     * @param {boolean} focus - Whether to focus the modal
     */
    showModal(modal, focus = true) {
        // Add to DOM
        document.body.appendChild(modal);
        
        // Force reflow to ensure CSS transition works
        modal.offsetHeight;
        
        // Add visible class for CSS transitions
        modal.classList.add('modal-visible');
        
        // Prevent body scroll
        document.body.style.overflow = 'hidden';
        
        // Set focus if requested
        if (focus) {
            modal.setAttribute('tabindex', '-1');
            modal.focus();
        }

        // Trap focus within modal
        this.trapFocus(modal);
    }

    /**
     * Close a modal
     * @param {HTMLElement} modal - Modal element to close
     */
    closeModal(modal) {
        if (!modal || !modal.parentNode) return;

        const config = modal._modalConfig || {};

        // Call onHide callback
        if (config.onHide) {
            config.onHide(modal);
        }

        // Remove visible class for CSS transition
        modal.classList.remove('modal-visible');

        // Remove from tracking
        this.activeModals.delete(modal);

        // Restore body scroll if no other modals
        if (this.activeModals.size === 0) {
            document.body.style.overflow = '';
        }

        // Remove from DOM after transition
        setTimeout(() => {
            if (modal.parentNode) {
                modal.parentNode.removeChild(modal);
            }

            // Call onDestroy callback
            if (config.onDestroy) {
                config.onDestroy(modal);
            }
        }, 300); // Match CSS transition duration
    }

    /**
     * Close all active modals
     */
    closeAllModals() {
        const modals = Array.from(this.activeModals);
        modals.forEach(modal => this.closeModal(modal));
    }

    /**
     * Show form validation errors
     * @param {HTMLElement} form - Form element
     * @param {Object} errors - Error object with field names as keys
     */
    showFormErrors(form, errors) {
        this.clearFormErrors(form);

        Object.entries(errors).forEach(([fieldName, fieldErrors]) => {
            const field = form.querySelector(`[name="${fieldName}"]`);
            const errorContainer = this.createErrorContainer(fieldErrors);

            if (field) {
                field.classList.add('error');
                field.parentNode.appendChild(errorContainer);
            } else if (fieldName === 'general') {
                // Show general errors at the top of the form
                const generalError = this.createErrorContainer(fieldErrors, 'general-error');
                form.insertBefore(generalError, form.firstChild);
            }
        });
    }

    /**
     * Clear form validation errors
     * @param {HTMLElement} form - Form element
     */
    clearFormErrors(form) {
        // Remove error classes
        form.querySelectorAll('.error').forEach(el => {
            el.classList.remove('error');
        });

        // Remove error containers
        form.querySelectorAll('.error-container, .general-error').forEach(el => {
            el.remove();
        });
    }

    /**
     * Set form loading state
     * @param {HTMLElement} form - Form element
     * @param {boolean} loading - Whether form is loading
     */
    setFormLoading(form, loading) {
        const submitBtn = form.querySelector('button[type="submit"]');
        const inputs = form.querySelectorAll('input, textarea, select, button');

        if (loading) {
            inputs.forEach(input => input.disabled = true);
            if (submitBtn) {
                submitBtn._originalText = submitBtn.textContent;
                submitBtn.textContent = 'Loading...';
            }
        } else {
            inputs.forEach(input => input.disabled = false);
            if (submitBtn && submitBtn._originalText) {
                submitBtn.textContent = submitBtn._originalText;
            }
        }
    }

    /**
     * Create error container element
     * @param {Array} errors - Array of error messages
     * @param {string} className - CSS class name
     * @returns {HTMLElement} Error container element
     */
    createErrorContainer(errors, className = 'error-container') {
        const container = document.createElement('div');
        container.className = className;
        
        if (Array.isArray(errors)) {
            errors.forEach(error => {
                const errorEl = document.createElement('div');
                errorEl.className = 'error-message';
                errorEl.textContent = error;
                container.appendChild(errorEl);
            });
        } else {
            const errorEl = document.createElement('div');
            errorEl.className = 'error-message';
            errorEl.textContent = errors;
            container.appendChild(errorEl);
        }

        return container;
    }

    /**
     * Trap focus within modal
     * @param {HTMLElement} modal - Modal element
     */
    trapFocus(modal) {
        const focusableElements = modal.querySelectorAll(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        
        if (focusableElements.length === 0) return;

        const firstFocusable = focusableElements[0];
        const lastFocusable = focusableElements[focusableElements.length - 1];

        modal.addEventListener('keydown', (e) => {
            if (e.key === 'Tab') {
                if (e.shiftKey) {
                    if (document.activeElement === firstFocusable) {
                        e.preventDefault();
                        lastFocusable.focus();
                    }
                } else {
                    if (document.activeElement === lastFocusable) {
                        e.preventDefault();
                        firstFocusable.focus();
                    }
                }
            }
        });
    }

    /**
     * Set up global event listeners
     */
    setupGlobalEventListeners() {
        // Handle browser back button
        window.addEventListener('popstate', () => {
            this.closeAllModals();
        });

        // Handle window resize
        window.addEventListener('resize', () => {
            this.activeModals.forEach(modal => {
                this.repositionModal(modal);
            });
        });
    }

    /**
     * Set up keyboard handlers
     */
    setupKeyboardHandlers() {
        document.addEventListener('keydown', (e) => {
            if (this.activeModals.size === 0) return;

            const topModal = Array.from(this.activeModals).pop();
            const config = topModal._modalConfig || {};

            if (e.key === 'Escape' && config.keyboard !== false) {
                e.preventDefault();
                this.closeModal(topModal);
            }
        });
    }

    /**
     * Reposition modal (for responsive design)
     * @param {HTMLElement} modal - Modal element
     */
    repositionModal(modal) {
        const content = modal.querySelector('.modal-content');
        if (!content) return;

        // Reset any previous positioning
        content.style.marginTop = '';
        content.style.marginBottom = '';

        // Center vertically if modal is smaller than viewport
        const modalHeight = content.offsetHeight;
        const viewportHeight = window.innerHeight;

        if (modalHeight < viewportHeight * 0.9) {
            const topMargin = Math.max(20, (viewportHeight - modalHeight) / 2);
            content.style.marginTop = `${topMargin}px`;
        }
    }

    /**
     * Get the currently active modal (topmost)
     * @returns {HTMLElement|null} Active modal or null
     */
    getActiveModal() {
        return this.activeModals.size > 0 ? Array.from(this.activeModals).pop() : null;
    }

    /**
     * Check if any modal is currently open
     * @returns {boolean} True if any modal is open
     */
    hasActiveModal() {
        return this.activeModals.size > 0;
    }

    /**
     * Destroy the modal manager and clean up
     */
    destroy() {
        this.closeAllModals();
        // Remove event listeners would go here if we stored references
        this.activeModals.clear();
    }
}