class NotificationManager {
    constructor() {
        this.notifications = new Map();
        this.counter = 0;
        this.container = this.createContainer();
    }

    createContainer() {
        const container = document.createElement('div');
        container.className = 'notification-container';
        container.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 10000;
            pointer-events: none;
        `;
        document.body.appendChild(container);
        this.setupEventHandlers(container);
        return container;
    }

    show(message, type = 'info', options = {}) {
        const {
            duration = this.getDefaultDuration(type),
            title = null,
            icon = null,
            actions = [],
            persistent = false,
            className = ''
        } = options;

        const id = `notification-${++this.counter}`;
        const notification = this.createNotification(id, message, type, {
            title,
            icon,
            actions,
            className
        });

        this.notifications.set(id, {
            element: notification,
            timer: persistent ? null : setTimeout(() => this.hide(id), duration)
        });

        this.container.appendChild(notification);
        
        setTimeout(() => notification.classList.add('show'), ForumConfig.timing.animationDelay);

        return id;
    }

    showSuccess(message, options = {}) {
        return this.show(message, 'success', options);
    }

    showError(message, options = {}) {
        return this.show(message, 'error', { 
            duration: ForumConfig.notifications.defaultDuration,
            ...options 
        });
    }

    showWarning(message, options = {}) {
        return this.show(message, 'warning', options);
    }

    showInfo(message, options = {}) {
        return this.show(message, 'info', options);
    }

    showLoading(message, options = {}) {
        return this.show(message, 'loading', {
            persistent: true,
            icon: '<div class="spinner"></div>',
            ...options
        });
    }

    hide(id) {
        const notification = this.notifications.get(id);
        if (!notification) return;

        if (notification.timer) {
            clearTimeout(notification.timer);
        }

        notification.element.classList.add('hide');
        
        setTimeout(() => {
            if (notification.element.parentNode) {
                notification.element.parentNode.removeChild(notification.element);
            }
            this.notifications.delete(id);
        }, ForumConfig.timing.mediumDelay);
    }

    hideAll() {
        Array.from(this.notifications.keys()).forEach(id => this.hide(id));
    }

    createNotification(id, message, type, options) {
        const { title, icon, actions, className } = options;
        
        const notification = document.createElement('div');
        notification.className = `notification notification-${type} ${className}`;
        notification.style.cssText = `
            pointer-events: auto;
            margin-bottom: 10px;
            padding: 15px 20px;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
            max-width: 400px;
            transform: translateX(100%);
            opacity: 0;
            transition: all 0.3s ease;
            ${this.getTypeStyles(type)}
        `;

        let content = '';

        if (icon) {
            content += `<div class="notification-icon">${UIComponents.escapeHtml(icon)}</div>`;
        }

        content += '<div class="notification-content">';
        
        if (title) {
            content += `<div class="notification-title">${UIComponents.escapeHtml(title)}</div>`;
        }
        
        content += `<div class="notification-message">${UIComponents.escapeHtml(message)}</div>`;

        if (actions.length > 0) {
            content += '<div class="notification-actions">';
            actions.forEach(action => {
                content += `<button class="notification-btn" data-callback="${UIComponents.escapeHtml(action.callback)}">${UIComponents.escapeHtml(action.text)}</button>`;
            });
            content += '</div>';
        }

        content += '</div>';

        if (type !== 'loading') {
            content += `<button class="notification-close" data-notification-id="${id}">&times;</button>`;
        }

        notification.innerHTML = content;

        return notification;
    }

    getTypeStyles(type) {
        const styles = {
            success: 'background: linear-gradient(135deg, #27ae60, #229954); color: white;',
            error: 'background: linear-gradient(135deg, #e74c3c, #c0392b); color: white;',
            warning: 'background: linear-gradient(135deg, #f39c12, #d68910); color: white;',
            info: 'background: linear-gradient(135deg, #3498db, #2980b9); color: white;',
            loading: 'background: linear-gradient(135deg, #95a5a6, #7f8c8d); color: white;'
        };
        return styles[type] || styles.info;
    }

    setupEventHandlers(container) {
        container.addEventListener('click', (e) => {
            if (e.target.classList.contains('notification-close')) {
                const notificationId = e.target.getAttribute('data-notification-id');
                if (notificationId) {
                    this.hide(notificationId);
                }
            } else if (e.target.classList.contains('notification-btn')) {
                const callback = e.target.getAttribute('data-callback');
                if (callback) {
                    try {
                        // Safely evaluate the callback
                        const func = new Function('return ' + callback)();
                        if (typeof func === 'function') {
                            func();
                        }
                    } catch (error) {
                        console.error('Notification callback error:', error);
                    }
                }
            }
        });
    }

    getDefaultDuration(type) {
        const durations = ForumConfig.notifications.durations;
        return durations[type] || ForumConfig.notifications.durations.info;
    }

    showProgress(message, currentValue, maxValue, options = {}) {
        const percentage = Math.round((currentValue / maxValue) * 100);
        const progressHtml = `
            <div class="progress-bar">
                <div class="progress-fill" style="width: ${percentage}%"></div>
            </div>
            <div class="progress-text">${message} (${percentage}%)</div>
        `;
        
        return this.show(progressHtml, 'info', {
            persistent: true,
            ...options
        });
    }

    updateProgress(id, currentValue, maxValue, message = null) {
        const notification = this.notifications.get(id);
        if (!notification) return;

        const percentage = Math.round((currentValue / maxValue) * 100);
        const progressFill = notification.element.querySelector('.progress-fill');
        const progressText = notification.element.querySelector('.progress-text');

        if (progressFill) {
            progressFill.style.width = `${percentage}%`;
        }

        if (progressText && message) {
            progressText.textContent = `${message} (${percentage}%)`;
        }

        if (percentage >= 100) {
            setTimeout(() => this.hide(id), ForumConfig.notifications.progressHideDelay);
        }
    }

    showConfirmation(message, onConfirm, onCancel = null, options = {}) {
        const actions = [
            {
                text: options.confirmText || 'Confirm',
                callback: `notificationManager.handleConfirmAction('${this.counter + 1}', true)`
            },
            {
                text: options.cancelText || 'Cancel',
                callback: `notificationManager.handleConfirmAction('${this.counter + 1}', false)`
            }
        ];

        const id = this.show(message, 'warning', {
            persistent: true,
            actions,
            title: options.title || 'Confirmation Required',
            ...options
        });

        this.notifications.get(id).onConfirm = onConfirm;
        this.notifications.get(id).onCancel = onCancel;

        return id;
    }

    handleConfirmAction(id, confirmed) {
        const notification = this.notifications.get(id);
        if (!notification) return;

        if (confirmed && notification.onConfirm) {
            notification.onConfirm();
        } else if (!confirmed && notification.onCancel) {
            notification.onCancel();
        }

        this.hide(id);
    }

    showRetry(message, retryCallback, options = {}) {
        const actions = [
            {
                text: options.retryText || 'Retry',
                callback: `notificationManager.handleRetryAction('${this.counter + 1}')`
            }
        ];

        const id = this.show(message, 'error', {
            persistent: true,
            actions,
            title: options.title || 'Operation Failed',
            ...options
        });

        this.notifications.get(id).retryCallback = retryCallback;

        return id;
    }

    handleRetryAction(id) {
        const notification = this.notifications.get(id);
        if (!notification || !notification.retryCallback) return;

        this.hide(id);
        notification.retryCallback();
    }

    showToast(message, type = 'info', duration = ForumConfig.notifications.toastDuration) {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        toast.style.cssText = `
            position: fixed;
            bottom: 20px;
            left: 50%;
            transform: translateX(-50%) translateY(100px);
            padding: 12px 24px;
            border-radius: 25px;
            font-size: 14px;
            font-weight: 500;
            z-index: ${ForumConfig.notifications.zIndex};
            transition: transform 0.3s ease;
            ${this.getTypeStyles(type)}
        `;

        document.body.appendChild(toast);

        setTimeout(() => {
            toast.style.transform = 'translateX(-50%) translateY(0)';
        }, ForumConfig.timing.animationDelay);

        setTimeout(() => {
            toast.style.transform = 'translateX(-50%) translateY(100px)';
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, ForumConfig.timing.mediumDelay);
        }, duration);
    }

    count() {
        return this.notifications.size;
    }

    getAll() {
        return Array.from(this.notifications.values()).map(n => n.element);
    }

    destroy() {
        this.hideAll();
        if (this.container.parentNode) {
            this.container.parentNode.removeChild(this.container);
        }
    }
}