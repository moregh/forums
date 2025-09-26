class Router {
    constructor() {
        this.routes = {};
        this.currentRoute = null;
        this.isNavigating = false;
        this.initialized = false;
        
        window.addEventListener('popstate', () => this.handleRoute());
    }

    register(path, handler) {
        this.routes[path] = handler;
    }

    navigate(path, pushState = true) {
        if (this.isNavigating) return; // Prevent recursion

        if (pushState && path !== window.location.pathname) {
            history.pushState({}, '', path);
        }

        // Always handle route to ensure navigation works
        this.handleRoute();
    }

    handleRoute() {
        if (this.isNavigating) return; // Prevent recursion
        this.isNavigating = true;

        try {
            const path = window.location.pathname;
            this.currentRoute = path;

            let routeFound = false;
            for (const routePath in this.routes) {
                const regex = new RegExp('^' + routePath.replace(/:\w+/g, '([^/]+)') + '$');
                const match = path.match(regex);

                if (match) {
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

            if (!routeFound && path !== '/') {
                history.replaceState({}, '', '/');
                if (this.routes['/']) {
                    this.routes['/']({});
                }
            } else if (!routeFound && path === '/') {
                if (this.routes['/']) {
                    this.routes['/']({});
                }
            }
        } catch (error) {
            console.error('Router error:', error);
        } finally {
            this.isNavigating = false;
            this.initialized = true;
        }
    }

    init() {
        if (!this.initialized) {
            this.handleRoute();
        }
    }
}