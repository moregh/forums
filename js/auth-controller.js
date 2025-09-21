class AuthController {
    constructor(api, formHandler, notifications, modalManager, router, state) {
        this.api = api;
        this.formHandler = formHandler;
        this.notifications = notifications;
        this.modalManager = modalManager;
        this.router = router;
        this.state = state;
    }

    showLogin() {
        const content = document.getElementById('content');
        content.innerHTML = this.renderLoginPage();
        this.setupLoginForm();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    showRegister() {
        const content = document.getElementById('content');
        content.innerHTML = this.renderRegisterPage();
        this.setupRegisterForm();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    renderLoginPage() {
        return `
            <div class="auth-form">
                <h2>Login</h2>
                <form id="login-form">
                    <input type="text" name="username" placeholder="Username" required autocomplete="username">
                    <input type="password" name="password" placeholder="Password" required autocomplete="current-password">
                    <button type="submit">Login</button>
                </form>
                <p><a href="/register" onclick="forum.router.navigate('/register'); return false;">Need an account? Register here</a></p>
                <div class="auth-help">
                    <a href="#" onclick="authController.showForgotPassword(); return false;">Forgot your password?</a>
                </div>
            </div>
        `;
    }

    renderRegisterPage() {
        return `
            <div class="auth-form">
                <h2>Register</h2>
                <form id="register-form">
                    <input type="text" name="username" placeholder="Username" required autocomplete="username">
                    <input type="email" name="email" placeholder="Email" required autocomplete="email">
                    <input type="password" name="password" placeholder="Password" required autocomplete="new-password">
                    <div class="password-requirements">
                        <small>Password must be at least 10 characters with uppercase, lowercase, number, and special character</small>
                    </div>
                    <button type="submit">Register</button>
                </form>
                <p><a href="/login" onclick="forum.router.navigate('/login'); return false;">Already have an account? Login here</a></p>
            </div>
        `;
    }

    setupLoginForm() {
        const form = document.getElementById('login-form');
        if (!form) return;

        form.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin(form);
        });

        this.addFormEnhancements(form);
    }

    setupRegisterForm() {
        const form = document.getElementById('register-form');
        if (!form) return;

        form.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleRegister(form);
        });

        this.addFormEnhancements(form);
        this.addPasswordValidation(form);
    }

    async handleLogin(form) {
        await this.formHandler.handleSubmit(form, async (formData) => {
            const result = await this.api.login(formData.username, formData.password);
            
            this.state.setState({ user: this.api.user });
            this.onAuthSuccess('login');
            
            return result;
        }, {
            validation: (data) => this.validateLoginData(data),
            successMessage: 'Login successful!',
            autoClose: false
        });
    }

    async handleRegister(form) {
        await this.formHandler.handleSubmit(form, async (formData) => {
            const result = await this.api.register(formData.username, formData.email, formData.password);
            
            this.state.setState({ user: this.api.user });
            this.onAuthSuccess('register');
            
            return result;
        }, {
            validation: (data) => this.validateRegisterData(data),
            successMessage: 'Registration successful! Welcome to the forum!',
            autoClose: false
        });
    }

    async logout() {
        try {
            await this.api.logout();
            this.state.setState({ user: null });
            this.notifications.showSuccess('Logged out successfully');
            this.router.navigate('/');
        } catch (error) {
            this.notifications.showError('Logout failed. Please try again.');
        }
    }

    showForgotPassword() {
        this.modalManager.createFormModal(
            'Reset Password',
            `<input type="email" name="email" placeholder="Enter your email address" required>
             <p class="form-help">We'll send you a link to reset your password.</p>`,
            async (formData) => {
                await this.handleForgotPassword(formData.email);
            },
            {
                submitText: 'Send Reset Link',
                validation: (data) => this.validateEmail(data.email)
            }
        );
    }

    async handleForgotPassword(email) {
        try {
            await this.api.request('/api/auth/forgot-password', {
                method: 'POST',
                body: JSON.stringify({ email })
            });
            
            this.notifications.showSuccess('Password reset link sent to your email');
            return true;
        } catch (error) {
            throw new Error('Failed to send reset link. Please check your email address.');
        }
    }

    showChangePassword() {
        this.modalManager.createFormModal(
            'Change Password',
            `<input type="password" name="currentPassword" placeholder="Current Password" required autocomplete="current-password">
             <input type="password" name="newPassword" placeholder="New Password" required autocomplete="new-password">
             <input type="password" name="confirmPassword" placeholder="Confirm New Password" required autocomplete="new-password">`,
            async (formData) => {
                await this.handleChangePassword(formData);
            },
            {
                submitText: 'Change Password',
                validation: (data) => this.validateChangePasswordData(data)
            }
        );
    }

    async handleChangePassword(formData) {
        try {
            await this.api.request('/api/auth/change-password', {
                method: 'POST',
                body: JSON.stringify({
                    current_password: formData.currentPassword,
                    new_password: formData.newPassword
                })
            });
            
            this.notifications.showSuccess('Password changed successfully');
            return true;
        } catch (error) {
            if (error.message.includes('current password')) {
                throw new Error('Current password is incorrect');
            }
            throw new Error('Failed to change password. Please try again.');
        }
    }

    validateLoginData(data) {
        const errors = {};

        if (!data.username || data.username.trim().length === 0) {
            errors.username = ['Username is required'];
        }

        if (!data.password || data.password.length === 0) {
            errors.password = ['Password is required'];
        }

        return {
            isValid: Object.keys(errors).length === 0,
            errors
        };
    }

    validateRegisterData(data) {
        return Validation.validateForm(data, {
            username: 'username',
            email: 'email',
            password: 'password'
        });
    }

    validateChangePasswordData(data) {
        const errors = {};

        if (!data.currentPassword) {
            errors.currentPassword = ['Current password is required'];
        }

        if (!data.newPassword) {
            errors.newPassword = ['New password is required'];
        } else {
            const passwordValidation = Validation.validatePassword(data.newPassword);
            if (!passwordValidation.isValid) {
                errors.newPassword = passwordValidation.errors;
            }
        }

        if (!data.confirmPassword) {
            errors.confirmPassword = ['Please confirm your new password'];
        } else if (data.newPassword !== data.confirmPassword) {
            errors.confirmPassword = ['Passwords do not match'];
        }

        return {
            isValid: Object.keys(errors).length === 0,
            errors
        };
    }

    validateEmail(email) {
        const validation = Validation.validateEmail(email);
        return {
            isValid: validation.isValid,
            errors: validation.isValid ? {} : { email: validation.errors }
        };
    }

    addFormEnhancements(form) {
        const inputs = form.querySelectorAll('input');
        inputs.forEach(input => {
            input.addEventListener('blur', () => this.validateField(input));
            input.addEventListener('input', () => this.clearFieldError(input));
        });

        form.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && e.target.tagName === 'INPUT') {
                const inputs = Array.from(form.querySelectorAll('input'));
                const currentIndex = inputs.indexOf(e.target);
                const nextInput = inputs[currentIndex + 1];
                
                if (nextInput) {
                    nextInput.focus();
                } else {
                    form.requestSubmit();
                }
            }
        });
    }

    addPasswordValidation(form) {
        const passwordInput = form.querySelector('input[name="password"]');
        if (!passwordInput) return;

        const requirementsEl = form.querySelector('.password-requirements');
        if (!requirementsEl) return;

        passwordInput.addEventListener('input', () => {
            const password = passwordInput.value;
            const requirements = this.getPasswordRequirements(password);
            requirementsEl.innerHTML = this.renderPasswordRequirements(requirements);
        });
    }

    getPasswordRequirements(password) {
        return [
            { text: 'At least 10 characters', met: password.length >= 10 },
            { text: 'Contains uppercase letter', met: /[A-Z]/.test(password) },
            { text: 'Contains lowercase letter', met: /[a-z]/.test(password) },
            { text: 'Contains number', met: /\d/.test(password) },
            { text: 'Contains special character', met: /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password) }
        ];
    }

    renderPasswordRequirements(requirements) {
        return requirements.map(req => 
            `<div class="requirement ${req.met ? 'met' : 'unmet'}">
                ${req.met ? '✓' : '✗'} ${req.text}
            </div>`
        ).join('');
    }

    validateField(input) {
        const name = input.name;
        const value = input.value;

        let validation;
        switch (name) {
            case 'username':
                validation = Validation.validateUsername(value);
                break;
            case 'email':
                validation = Validation.validateEmail(value);
                break;
            case 'password':
                validation = Validation.validatePassword(value);
                break;
            default:
                return;
        }

        if (!validation.isValid) {
            this.showFieldError(input, validation.errors[0]);
        } else {
            this.clearFieldError(input);
        }
    }

    showFieldError(input, message) {
        this.clearFieldError(input);
        
        input.classList.add('error');
        const errorEl = document.createElement('div');
        errorEl.className = 'field-error';
        errorEl.textContent = message;
        input.parentNode.insertBefore(errorEl, input.nextSibling);
    }

    clearFieldError(input) {
        input.classList.remove('error');
        const errorEl = input.parentNode.querySelector('.field-error');
        if (errorEl) {
            errorEl.remove();
        }
    }

    onAuthSuccess(type) {
        const redirectPath = this.getRedirectPath();
        
        setTimeout(() => {
            this.router.navigate(redirectPath);
        }, 1000);
    }

    getRedirectPath() {
        const urlParams = new URLSearchParams(window.location.search);
        const redirect = urlParams.get('redirect');
        
        if (redirect && this.isValidRedirectPath(redirect)) {
            return redirect;
        }
        
        return '/';
    }

    isValidRedirectPath(path) {
        try {
            const url = new URL(path, window.location.origin);
            return url.origin === window.location.origin;
        } catch {
            return path.startsWith('/') && !path.startsWith('//');
        }
    }

    requireAuth(callback) {
        const user = this.state.getState().user;
        
        if (!user) {
            this.notifications.showError('Please log in to continue');
            this.router.navigate('/login?redirect=' + encodeURIComponent(window.location.pathname));
            return false;
        }
        
        if (callback) {
            callback(user);
        }
        
        return true;
    }

    requireAdmin(callback) {
        const user = this.state.getState().user;
        
        if (!user) {
            this.notifications.showError('Please log in to continue');
            this.router.navigate('/login');
            return false;
        }
        
        if (!user.is_admin) {
            this.notifications.showError('Admin privileges required');
            this.router.navigate('/');
            return false;
        }
        
        if (callback) {
            callback(user);
        }
        
        return true;
    }

    async refreshToken() {
        try {
            const result = await this.api.refreshToken();
            this.state.setState({ user: this.api.user });
            return result;
        } catch (error) {
            this.handleAuthError();
            return null;
        }
    }

    handleAuthError() {
        this.api.clearAuth();
        this.state.setState({ user: null });
        
        const currentPath = window.location.pathname;
        if (currentPath !== '/login' && currentPath !== '/register' && currentPath !== '/') {
            this.notifications.showError('Your session has expired. Please log in again.');
            this.router.navigate('/login?redirect=' + encodeURIComponent(currentPath));
        }
    }

    isLoggedIn() {
        return !!this.state.getState().user;
    }

    getCurrentUser() {
        return this.state.getState().user;
    }

    hasRole(role) {
        const user = this.getCurrentUser();
        if (!user) return false;
        
        switch (role) {
            case 'admin':
                return user.is_admin;
            case 'user':
                return !user.is_banned;
            default:
                return false;
        }
    }

    getAuthStatus() {
        const user = this.getCurrentUser();
        
        if (!user) {
            return { status: 'guest', user: null };
        }
        
        if (user.is_banned) {
            return { status: 'banned', user };
        }
        
        if (user.is_admin) {
            return { status: 'admin', user };
        }
        
        return { status: 'user', user };
    }

    setupAuthRefresh() {
        if (!this.isLoggedIn()) return;
        
        setInterval(async () => {
            if (this.isLoggedIn()) {
                try {
                    await this.refreshToken();
                } catch (error) {
                    console.warn('Token refresh failed:', error);
                }
            }
        }, 25 * 60 * 1000); // 25 minutes
    }

    destroy() {
        // Cleanup if needed
    }
}