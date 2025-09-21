class Router {
    constructor() {
        this.routes = {};
        this.currentRoute = null;
        this.isNavigating = false;
        this.initialized = false;
        
        // Listen for browser navigation
        window.addEventListener('popstate', () => this.handleRoute());
    }

    // Register route handler
    register(path, handler) {
        this.routes[path] = handler;
    }

    navigate(path, pushState = true) {
        if (this.isNavigating) return; // Prevent recursion

        // Don't push state if we're already on this path
        if (pushState && path !== window.location.pathname) {
            history.pushState({}, '', path);
        }

        // Only handle route if the path actually changed
        if (path !== this.currentRoute) {
            this.handleRoute();
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }
    }

    // Handle current route
    handleRoute() {
        if (this.isNavigating) return; // Prevent recursion
        this.isNavigating = true;
        
        const path = window.location.pathname;
        this.currentRoute = path;

        // Find matching route
        let routeFound = false;
        for (const routePath in this.routes) {
            const regex = new RegExp('^' + routePath.replace(/:\w+/g, '([^/]+)') + '$');
            const match = path.match(regex);
            
            if (match) {
                // Extract parameters
                const params = {};
                const paramNames = routePath.match(/:(\w+)/g) || [];
                paramNames.forEach((param, index) => {
                    const paramName = param.substring(1);
                    params[paramName] = match[index + 1];
                });
                
                this.routes[routePath](params);
                routeFound = true;
                break;
            }
        }
        
        // If no route found and not already on home, redirect to home
        if (!routeFound && path !== '/') {
            history.replaceState({}, '', '/');
            if (this.routes['/']) {
                this.routes['/']({});
            }
        } else if (!routeFound && path === '/') {
            // Handle home route explicitly
            if (this.routes['/']) {
                this.routes['/']({});
            }
        }
        
        this.isNavigating = false;
        this.initialized = true;
    }

    // Initialize router after all routes are registered
    init() {
        if (!this.initialized) {
            this.handleRoute();
        }
    }
}